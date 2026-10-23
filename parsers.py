#!/usr/bin/env python3
"""
Telegram 消息与文件解析器模块 (parsers.py)
从公开频道非结构化消息与各类测速附件中精准提取节点与指标，全面解耦数据提取与业务调度：
  1. 通用代理匹配：标准 URL 格式 (socks5/http/https/turn)、tg://socks 链接转换、发现开放代理通报（带防污染隔离）。
  2. 频道单条优选：解析测速通报卡片中的 IP、端口、TLS、网络延迟、下载速度、colo、落地地区等指标。
  3. 测速附件解析：解析 DanFeng 命名规范 CSV 与 OTC 优选测速扫描 TXT，根据 ASN 与厂商智能清洗归类。
  4. 代理附件解析：识别并提取各类文本代理附件文件中的有效节点。
"""

from __future__ import annotations

import csv
import ipaddress
import logging
import os
import re
from urllib.parse import parse_qs

from providers import (
    KNOWN_CLOUD_PROVIDERS,
    ASN_TO_PROVIDER,
    SORTED_CLOUD_PROVIDER_KEYS,
    format_asn_isp,
    load_ip_cache,
    normalize_timestamp,
    resolve_ip_asn,
)

log = logging.getLogger("parsers")

# 通用代理匹配正则表达式
ANNOUNCE_PROXY_RE = re.compile(
    r"\[发现开放\s*(?P<proto>HTTP|SOCKS5|HTTPS|TURNS?|SSTP)\s*(?:代理|服务)?\]\s*(?:(?:https?|socks5|turns?|sstp)://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
)
TG_SOCKS_RE = re.compile(
    r"(?:tg://socks|https?://(?:t\.me|telegram\.me)/socks)\?(?P<query>[^\s#]+)"
)
PROXY_URL_RE = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turns?|sstp)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
    re.IGNORECASE,
)


RE_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$")


def is_valid_ip(val: str) -> bool:
    """严格校验是否为有效 IPv4 或 IPv6 地址"""
    if not val:
        return False
    clean = str(val).strip().strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except Exception:
        return False


def is_valid_host(host: str) -> bool:
    """验证主机名是否为有效 IPv4 地址或域名 (RFC 1035 / RFC 1123)"""
    if not host or len(host) > 253:
        return False
    parts = host.split(".")
    if len(parts) == 4 and all(p.isascii() and p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    if len(parts) >= 2 and parts[-1].isalpha() and len(parts[-1]) >= 2:
        return all(0 < len(part) <= 63 and bool(RE_DOMAIN_LABEL.match(part)) for part in parts)
    return False


def extract_proxies(text: str) -> list[tuple[str, str]]:
    """从纯文本中提取代理节点 URL 与去重键 (ip:port)"""
    results = []
    lines = text.splitlines()
    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        ann_m = ANNOUNCE_PROXY_RE.search(line_s)
        if ann_m:
            proto = ann_m.group("proto").lower()
            ip = ann_m.group("ip")
            port = ann_m.group("port")
            if is_valid_host(ip) and 1 <= int(port) <= 65535:
                results.append((f"{proto}://{ip}:{port}", f"{ip}:{port}"))
            continue

        for m in TG_SOCKS_RE.finditer(line_s):
            qs = parse_qs(m.group("query"))
            server = qs.get("server", [""])[0].strip()
            port = qs.get("port", [""])[0].strip()
            user = qs.get("user", [""])[0].strip()
            password = qs.get("pass", [""])[0].strip()
            if server and port and is_valid_host(server) and port.isdigit() and 1 <= int(port) <= 65535:
                url = f"socks5://{user}:{password}@{server}:{port}" if (user or password) else f"socks5://{server}:{port}"
                results.append((url, f"{server}:{port}"))

        for m in PROXY_URL_RE.finditer(line_s):
            host = m.group("host")
            port = m.group("port")
            if is_valid_host(host) and 1 <= int(port) <= 65535:
                results.append((m.group("url"), f"{host}:{port}"))

    return results


RE_CF_IP = re.compile(r"IP地址[:：]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
RE_CF_PORT = re.compile(r"端口[:：]\s*(\d{1,5})")
RE_CF_TLS = re.compile(r"TLS[:：]\s*(true|false)", re.IGNORECASE)
RE_CF_ASN = re.compile(r"ASN编号[:：]\s*([^\r\n]+)")
RE_CF_ISP = re.compile(r"运营商[:：]\s*([^\r\n]+)")
RE_CF_COLO = re.compile(r"数据中心[:：]\s*([A-Za-z0-9]+)")
RE_CF_LOC = re.compile(r"CF落地位置[:：].*?🌐\s*([^\r\n]+)", re.DOTALL)
RE_CF_DELAY = re.compile(r"网络延迟[:：]\s*(\d+(?:\.\d+)?)\s*ms")
RE_CF_SPEED = re.compile(r"(?:下载)?速度(?:\s*[\(\[（]\s*([a-zA-Z/]+)\s*[\)\]）])?[:：]\s*(\d+(?:\.\d+)?)\s*([a-zA-Z/]+)?")
RE_CF_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
RE_CF_SOURCE = re.compile(r"IP来源[:：]\s*([@\w]+)")
RE_AS_CODE = re.compile(r"(AS\d+)", re.IGNORECASE)
RE_SPEED_EXTRACT = re.compile(r"(\d+(?:\.\d+)?)\s*([a-zA-Z/]+)?")


def parse_speed_to_kbs(
    val_or_str: str | float | int,
    unit: str = "",
    *,
    mb_hint: bool = False,
) -> str | int:
    """
    统一将各种格式的测速值统一转换为 kB/s 整数：
    - 支持单位: GB/s, Gbps, MB/s, Mbps, kB/s, kbps, B/s, bps 等
    - 支持无单位时根据数值范围或列头提示 (mb_hint) 自动判定
    - 无法解析或非法值返回空字符串 ""
    """
    if val_or_str is None or val_or_str == "":
        return ""

    if isinstance(val_or_str, str) and not unit:
        m = RE_SPEED_EXTRACT.search(val_or_str.strip())
        if m:
            val_or_str = m.group(1)
            unit = m.group(2) or ""

    try:
        val = float(val_or_str)
    except (ValueError, TypeError):
        return ""

    unit = (unit or "").lower().strip()
    if not unit:
        if mb_hint:
            unit = "mb/s"
        else:
            # 缺乏单位时启发式判定：主流 CF 测速工具（如 CloudflareST）小数值 (< 50) 通常为 MB/s，大数值通常为 kB/s
            unit = "mb/s" if val < 50 else "kb/s"

    if "gbps" in unit or "gb/s" in unit:
        val *= (1024 * 1024) / 8 if "bps" in unit else (1024 * 1024)
    elif "gb" in unit or unit == "g":
        val *= 1024 * 1024
    elif "mbps" in unit or "mb/s" in unit:
        val *= (1024 / 8) if "bps" in unit else 1024
    elif "mb" in unit or unit == "m":
        val *= 1024
    elif "kbps" in unit or "kb/s" in unit:
        val = (val / 8) if "bps" in unit else val
    elif "kb" in unit or unit == "k":
        pass
    elif "bps" in unit:
        val /= (1024 * 8)
    elif "b/s" in unit or "byte" in unit or unit == "b":
        val /= 1024

    return max(0, int(val))


def resolve_and_clean_asn(ip: str, raw_asn: str = "", raw_isp: str = "") -> tuple[str, str]:
    """
    统一解析与补全 (asn, isp)：
    1. 从 raw_asn 中正则提取标准 AS\d+ 编号（严格遵循 RFC 7607 排除非路由保留编号 AS0）；
    2. 兼容 ASN/ISP 列反转（如 raw_asn 全为组织名称）；
    3. 若缺少有效 ASN，查持久化库、本地 IP 缓存 (ip_cache) 或在线反查补全；
    4. 返回 (asn_code, isp_name)。
    """
    raw_asn = (raw_asn or "").strip()
    raw_isp = (raw_isp or "").strip()

    asn_clean = ""
    if raw_asn:
        m_asn = RE_AS_CODE.search(raw_asn)
        if m_asn:
            code_str = m_asn.group(1).upper()
            if code_str != "AS0":
                asn_clean = code_str
            if not raw_isp:
                rem_isp = raw_asn[m_asn.end():].strip().strip("-").strip()
                if rem_isp:
                    raw_isp = rem_isp
        else:
            if raw_asn.isdigit():
                num = int(raw_asn)
                if num > 0:
                    asn_clean = f"AS{num}"
            elif not raw_isp and raw_asn not in ("-", "UNKNOWN", "AS_UNKNOWN", "AS0", "0"):
                raw_isp = raw_asn

    # 优先查验本地 IP 缓存：若当前 IP 已有确凿真实的 BGP ASN，且当前标记为空/未知/或误标为 Cloudflare (AS13335)，坚决以 IP 真实 ASN 为准
    if ip and ip not in ("AS_UNKNOWN", "unknown", "127.0.0.1"):
        try:
            cache = load_ip_cache()
            if ip in cache and cache[ip].get("asn"):
                cached_asn = cache[ip]["asn"]
                if cached_asn and cached_asn.upper() not in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
                    if not asn_clean or asn_clean in ("AS0", "AS_UNKNOWN", "UNKNOWN") or (asn_clean == "AS13335" and cached_asn != "AS13335"):
                        asn_clean = cached_asn
                        cached_isp = cache[ip].get("isp") or ASN_TO_PROVIDER.get(cached_asn, "")
                        if cached_isp:
                            raw_isp = cached_isp
        except Exception:
            pass

    if not asn_clean or asn_clean in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
        found_asn, found_isp = resolve_ip_asn(ip, raw_isp)
        if found_asn and found_asn.upper() not in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
            asn_clean = found_asn
            if not raw_isp and found_isp:
                raw_isp = found_isp

    if asn_clean and asn_clean in ASN_TO_PROVIDER:
        std_isp = ASN_TO_PROVIDER[asn_clean]
        if not raw_isp or len(raw_isp.strip()) <= 2 or re.search(r'(?i)^(?:sa|beafort|ht|dc|unknown|none|null|n/a)$', raw_isp.strip()):
            raw_isp = std_isp

    return asn_clean or "", raw_isp


def parse_cf_ip(text: str, default_channel: str = "") -> dict | None:
    """从单条优选 IP 消息卡片中提取结构化字段"""
    ip_m = RE_CF_IP.search(text)
    port_m = RE_CF_PORT.search(text)
    if not ip_m or not port_m:
        return None

    ip = ip_m.group(1).strip()
    port = port_m.group(1).strip()
    if not is_valid_host(ip) or not (1 <= int(port) <= 65535):
        return None

    tls_m = RE_CF_TLS.search(text)
    asn_m = RE_CF_ASN.search(text)
    isp_m = RE_CF_ISP.search(text)
    colo_m = RE_CF_COLO.search(text)
    cf_loc_m = RE_CF_LOC.search(text)
    delay_m = RE_CF_DELAY.search(text)
    speed_m = RE_CF_SPEED.search(text)
    speed_kbs = ""
    if speed_m:
        val = speed_m.group(2)
        unit = speed_m.group(1) or speed_m.group(3) or ""
        speed_kbs = parse_speed_to_kbs(val, unit)

    time_m = RE_CF_TIME.search(text)
    source_m = RE_CF_SOURCE.search(text)

    raw_asn = asn_m.group(1).replace("`", "").strip() if asn_m else ""
    raw_isp = isp_m.group(1).replace("`", "").strip() if isp_m else ""

    asn_val, raw_isp = resolve_and_clean_asn(ip, raw_asn, raw_isp)
    final_asn = format_asn_isp(asn_val, raw_isp)

    return {
        "ip": ip,
        "port": str(port),
        "tls": tls_m.group(1).lower() if tls_m else "unknown",
        "delay_ms": int(float(delay_m.group(1))) if delay_m else "",
        "speed_kbs": speed_kbs,
        "colo": colo_m.group(1).replace("`", "").strip() if colo_m else "",
        "cf_location": cf_loc_m.group(1).replace("`", "").strip() if cf_loc_m else "",
        "isp": raw_isp,
        "asn": final_asn,
        "raw_asn": asn_val,
        "first_seen": normalize_timestamp(time_m.group(1).strip() if time_m else ""),
        "channel": source_m.group(1).strip() if source_m else default_channel,
        "fail_count": 0,
    }


def parse_cf_csv_content(
    text: str,
    default_channel: str = "@danfeng_chat",
    filename: str = "",
    dt_str: str = "",
) -> list[dict]:
    """解析 Cloudflare 优选测速与反代 ProxyIP CSV 格式内容（支持 DanFeng、CheckProxyIP、云厂商测速等）"""
    fn_asn = ""
    fn_isp = ""
    fn_port = ""
    fn_time = dt_str

    if filename:
        fn_lower = filename.lower()
        # 1. 优先从文件名正则匹配 AS 编号与 ISP (支持 DanFeng 命名规范，如 AS45102_CNNICALIBABACNNETAP_20260906_190653.csv, AS61112_AkileCloud_Network_20260831_012345.csv)
        base_fn = os.path.basename(filename.replace("\\", "/"))
        m_fn = re.search(r"(?i)(?P<asn>AS\d+)_(?P<isp>.+?)(?:_(?P<date>\d{8})_(?P<time>\d{6}))?\.(?:csv|txt)$", base_fn)
        if m_fn:
            fn_asn = m_fn.group("asn").upper()
            raw_captured_isp = m_fn.group("isp").replace("-", " ").replace("_", " ")
            fn_isp = re.sub(r"\.(?:csv|txt)$", "", raw_captured_isp, flags=re.IGNORECASE).strip()
            if m_fn.group("date") and m_fn.group("time") and not fn_time:
                d = m_fn.group("date")
                t = m_fn.group("time")
                fn_time = f"{d[:4]}-{d[4:6]}-{d[6:8]} {t[:2]}:{t[2:4]}:{t[4:6]}"
        elif not any(bad in fn_lower for bad in ("nsb", "results", "speedtest", "benchmark", "warp", "tunnel", "anti", "proxyip", "反代")):
            # 2. 从常见云服务器/VPS文件名推断 ASN 与 ISP (如 Aliyun.csv, Tencent.csv, DMIT.csv, Akile.csv 等)
            for key in SORTED_CLOUD_PROVIDER_KEYS:
                pattern = rf"(?i)(?:^|[^a-z0-9]){re.escape(key)}(?:[^a-z0-9]|$)"
                if re.search(pattern, fn_lower) or (len(key) >= 4 and key in fn_lower):
                    fn_asn, fn_isp = KNOWN_CLOUD_PROVIDERS[key]
                    break

        m_port = re.search(r"proxyip[-_](\d{2,5})", filename, re.IGNORECASE)
        if m_port:
            fn_port = m_port.group(1)

    results = []
    clean_text = text.lstrip("\ufeff").strip()
    if not clean_text:
        return results

    try:
        lines = clean_text.splitlines()
        first_line = lines[0].strip() if lines else ""
        if not first_line:
            return results

        # 智能探测分隔符与首行是否为无标题数据行 (例如首列直接是 IP 地址)
        delimiter = "\t" if ("\t" in first_line and "," not in first_line) else ","
        first_parts = [p.strip().strip('"') for p in first_line.split(delimiter)]
        is_headerless = False
        if first_parts and (is_valid_host(first_parts[0]) or ":" in first_parts[0]):
            is_headerless = True

        if is_headerless:
            reader_rows = csv.reader(lines, delimiter=delimiter)
            for row in reader_rows:
                if not row or not row[0].strip():
                    continue
                raw_ip = row[0].strip()
                raw_port = ""
                raw_delay = ""
                if ":" in raw_ip:
                    ip_c, p_c = raw_ip.split(":", 1)
                    if is_valid_host(ip_c) and p_c.isdigit():
                        raw_ip, raw_port = ip_c, p_c

                if len(row) == 1:
                    raw_port = raw_port or fn_port
                elif len(row) == 2:
                    val = row[1].strip()
                    if fn_port:
                        # 文件名已显式指定端口（如 proxyip-443.csv），第二列为延迟数值，端口继承自文件名端口
                        raw_port = raw_port or fn_port
                        raw_delay = val
                    else:
                        # 文件名未指定端口时，若第二列为合法的端口数值范围 (1-65535)，优先作为端口；否则作为延迟
                        if val.isdigit() and 1 <= int(val) <= 65535:
                            raw_port = val
                        else:
                            raw_port = raw_port or fn_port
                            raw_delay = val
                elif len(row) >= 3:
                    raw_port = raw_port or row[1].strip() or fn_port
                    raw_delay = row[2].strip()

                if not raw_port and fn_port:
                    raw_port = fn_port

                if not raw_ip or not raw_port or not is_valid_host(raw_ip) or not raw_port.isdigit():
                    continue
                port = int(raw_port)
                if not (1 <= port <= 65535):
                    continue
                delay_ms = ""
                m_delay = re.search(r"(\d+(?:\.\d+)?)", raw_delay)
                if m_delay:
                    delay_ms = int(float(m_delay.group(1)))

                row_asn, row_isp = resolve_and_clean_asn(raw_ip, fn_asn, fn_isp)

                results.append({
                    "ip": raw_ip,
                    "port": str(port),
                    "tls": "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false",
                    "delay_ms": delay_ms,
                    "speed_kbs": "",
                    "colo": "",
                    "cf_location": "",
                    "isp": row_isp,
                    "asn": format_asn_isp(row_asn, row_isp),
                    "raw_asn": row_asn,
                    "first_seen": fn_time,
                    "channel": default_channel,
                    "fail_count": 0,
                    "exit_ip": "",
                })
            return results

        reader = csv.DictReader(lines, delimiter=delimiter)
        if not reader.fieldnames:
            return results

        field_map = {}
        speed_unit_is_mb = False
        for col in reader.fieldnames:
            if not col:
                continue
            c_clean = col.strip().lower().replace(" ", "").replace("_", "")

            # 1. 优先精准提取出口/出站 IP 字段 (严格排除 类型/位置/协议 等干扰属性列)
            if (
                c_clean in ("出站ip", "出口ip", "egressip", "exitip", "clientip", "出站", "出口", "egress", "exit")
                or (
                    any(k in c_clean for k in ("出站ip", "出口ip", "egressip", "exitip", "clientip"))
                    and not any(k in c_clean for k in ("类型", "位置", "地区", "国家", "城市", "type", "loc", "status", "asn", "org", "协议"))
                )
            ):
                field_map["exit_ip"] = col
                continue

            # 2. 捕获出站地理位置 (如 出站IP位置, 出口IP位置, 兼容部分表头中将国家列误标为出站IP位置的变体)
            if any(k in c_clean for k in ("出站ip位置", "出口ip位置", "出站位置", "出口位置", "出站国家", "出口国家")):
                field_map["exit_loc"] = col
                continue

            # 2.5 捕获出站 ASN 与出站 ISP (如 出站ASN, 出口ASN, 出站组织, 出口运营商)
            if any(k in c_clean for k in ("出站as", "出口as", "egressas", "exitas")):
                field_map["exit_asn"] = col
                continue
            if any(k in c_clean for k in ("出站运营商", "出口运营商", "出站组织", "出口组织", "egressisp", "exitisp", "egressorg", "exitorg", "出站isp", "出口isp")):
                field_map["exit_isp"] = col
                continue

            # 3. 忽略其余出站属性列与隧道/网关标记列，防止污染后续指标提取
            if any(k in c_clean for k in ("出站", "出口", "egress", "tunnel", "warp", "gateway", "rbi")):
                continue

            # 3. 频道/数据来源匹配 (如 IP数据来源, 渠道, source)
            if any(k in c_clean for k in ("ip数据来源", "数据来源", "来源", "渠道", "channel", "source")):
                field_map["channel"] = col

            # 4. 入口 IP 匹配 (严密排除包含出站/出口字样的干扰列)
            elif (
                (any(k in c_clean for k in ("ip地址", "ipaddress", "proxyip", "节点ip", "入口ip")) or c_clean == "ip")
                and not any(k in c_clean for k in ("出站", "出口", "exit", "egress"))
            ):
                field_map["ip"] = col

            # 5. 端口匹配
            elif any(k in c_clean for k in ("端口", "port")):
                field_map["port"] = col

            # 6. TLS 开关匹配 (严密排除 TLS版本/TLS协议 等版本信息列)
            elif (
                c_clean in ("tls", "istls", "ssl", "is_tls")
                or (
                    any(k in c_clean for k in ("tls", "istls", "ssl"))
                    and not any(k in c_clean for k in ("版本", "version", "ver", "协议", "proto"))
                )
            ):
                field_map["tls"] = col

            # 7. 延迟匹配
            elif any(k in c_clean for k in ("延迟", "delay", "latency", "connectms")):
                field_map["delay"] = col

            # 8. 速度/带宽匹配
            elif any(k in c_clean for k in ("速度", "speed", "带宽", "bandwidth")):
                field_map["speed"] = col
                if "mb" in c_clean:
                    speed_unit_is_mb = True

            # 9. 机房/数据中心代码匹配
            elif any(k in c_clean for k in ("数据中心", "机房", "colo", "dc", "地区码", "城市码", "机场码")):
                field_map["colo"] = col


            # 10. 地理位置多维精细识别 (优先区分中文地理层级与英文/标准地理字段)
            elif any(k in c_clean for k in ("地区(中文)", "大洲(中文)", "地区中文", "大洲中文", "洲(中文)", "continentcn", "regioncn")):
                field_map["region_cn"] = col
            elif any(k in c_clean for k in ("国家(中文)", "国家中文", "countrycn")) or c_clean == "国家":
                field_map["country_cn"] = col
            elif any(k in c_clean for k in ("城市(中文)", "城市中文", "citycn")):
                field_map["city_cn"] = col
            elif c_clean in ("ip位置", "位置", "location") or any(k in c_clean for k in ("country", "国家代码")):
                field_map["loc"] = col
            elif any(k in c_clean for k in ("地区", "省份", "region", "province", "continent")):
                field_map["region"] = col
            elif any(k in c_clean for k in ("城市", "city")):
                field_map["city"] = col

            # 11. 自治系统 (ASN) 编号与组织匹配
            elif (
                c_clean in ("asn", "as", "asnumber", "asnum", "asn_id", "asnid")
                or any(k in c_clean for k in ("as编号", "as号码", "as号", "as_number", "asn编号", "asn号码", "asn号", "asn_number"))
                or (c_clean.startswith("asn") and not any(k in c_clean for k in ("组织", "org", "isp", "name", "名称")))
            ):
                field_map["asn"] = col
            elif any(k in c_clean for k in ("运营商", "组织", "org", "isp", "company", "asn组织", "as组织", "asn名称")):
                field_map["isp"] = col

            # 12. 时间戳与测试时间匹配
            elif any(k in c_clean for k in ("时间戳", "时间", "timestamp", "time", "date")):
                field_map["time"] = col

        for row in reader:
            raw_ip = row.get(field_map.get("ip", ""), "").strip()
            raw_port = row.get(field_map.get("port", ""), "").strip()
            if not raw_port and fn_port:
                raw_port = fn_port
            if ":" in raw_ip:
                ip_cand, port_cand = raw_ip.split(":", 1)
                if is_valid_host(ip_cand) and port_cand.isdigit():
                    raw_ip = ip_cand
                    raw_port = port_cand
            if not raw_ip or not raw_port or not is_valid_host(raw_ip) or not raw_port.isdigit():
                continue
            port = int(raw_port)
            if not (1 <= port <= 65535):
                continue

            raw_tls = row.get(field_map.get("tls", ""), "").strip().lower()
            tls = "true" if raw_tls in ("true", "1", "yes") else ("false" if raw_tls in ("false", "0", "no") else "unknown")
            if tls == "unknown" and port in (443, 8443, 2053, 2083, 2087, 2096):
                tls = "true"

            raw_delay = row.get(field_map.get("delay", ""), "").strip()
            delay_ms = ""
            m_delay = re.search(r"(\d+(?:\.\d+)?)", raw_delay)
            if m_delay:
                delay_ms = int(float(m_delay.group(1)))

            raw_speed = row.get(field_map.get("speed", ""), "").strip()
            speed_kbs = parse_speed_to_kbs(raw_speed, mb_hint=speed_unit_is_mb)

            colo = row.get(field_map.get("colo", ""), "").strip()

            # 智能拼接地理信息：优先中文完整层级 (大洲/地区 · 国家 · 城市)，若无国家则使用 exit_loc 兜底
            loc_parts = []
            has_cn_loc = any(field_map.get(k) for k in ("region_cn", "country_cn", "exit_loc", "city_cn"))
            if has_cn_loc:
                country_key = "country_cn" if field_map.get("country_cn") else "exit_loc"
                for key in ("region_cn", country_key, "city_cn"):
                    val = row.get(field_map.get(key, ""), "").strip()
                    if val and val.upper() not in ("-", "N/A", "NULL", "NONE") and val not in loc_parts:
                        loc_parts.append(val)
            if not loc_parts:
                for key in ("region", "country", "city", "loc"):
                    val = row.get(field_map.get(key, ""), "").strip()
                    if val and val.upper() not in ("-", "N/A", "NULL", "NONE") and val not in loc_parts:
                        loc_parts.append(val)
            cf_location = " · ".join(loc_parts)

            # 真实出口 IP 提取与校验
            raw_exit_ip = row.get(field_map.get("exit_ip", ""), "").strip()
            exit_ip = raw_exit_ip if is_valid_ip(raw_exit_ip) else ""

            # 来源频道提取与格式清洗 (如 TG@danfeng_chat -> @danfeng_chat)
            raw_channel = row.get(field_map.get("channel", ""), "").strip()
            row_channel = default_channel
            if raw_channel:
                ch_clean = re.sub(r"^(?:tg:?//|telegram:?//|tg:?|telegram:?)", "", raw_channel, flags=re.IGNORECASE).strip()
                if ch_clean:
                    if not ch_clean.startswith("@"):
                        ch_clean = f"@{ch_clean}"
                    row_channel = ch_clean

            raw_exit_asn = row.get(field_map.get("exit_asn", ""), "").strip()
            raw_exit_isp = row.get(field_map.get("exit_isp", ""), "").strip()

            raw_asn = row.get(field_map.get("asn", ""), "").replace("`", "").strip()
            if not raw_asn or raw_asn in ("-", "0", "AS0", "AS_UNKNOWN", "UNKNOWN"):
                raw_asn = fn_asn
            elif raw_asn.isdigit():
                num = int(raw_asn)
                raw_asn = f"AS{num}" if num > 0 else fn_asn

            raw_isp = row.get(field_map.get("isp", ""), "").replace("`", "").strip()
            if not raw_isp or raw_isp in ("-", "UNKNOWN", "AS_UNKNOWN"):
                raw_isp = fn_isp

            asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_asn, raw_isp)
            # 仅当入口 ASN 完全缺失且本地 IP 缓存未收录时，才允许使用 exit_asn 兜底
            if (not asn_val or asn_val in ("AS0", "AS_UNKNOWN", "UNKNOWN")) and raw_exit_asn:
                asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_exit_asn, raw_exit_isp or raw_isp)

            raw_time = row.get(field_map.get("time", ""), "").strip()
            first_seen = normalize_timestamp(raw_time, fn_time)

            results.append({
                "ip": raw_ip,
                "port": str(port),
                "tls": tls,
                "delay_ms": delay_ms,
                "speed_kbs": speed_kbs,
                "colo": colo,
                "cf_location": cf_location,
                "isp": raw_isp,
                "asn": format_asn_isp(asn_val, raw_isp),
                "raw_asn": asn_val,
                "first_seen": first_seen,
                "channel": row_channel,
                "fail_count": 0,
                "exit_ip": exit_ip,
                "exit_asn": raw_exit_asn,
                "exit_isp": raw_exit_isp,
            })
    except Exception as e:
        log.warning("解析 CSV 优选/ProxyIP 数据异常: %s", e)

    return results


def parse_otc_scan_content(
    text: str,
    default_channel: str = "@otcfxq",
    filename: str = "",
    dt_str: str = ""
) -> list[dict]:
    """解析 OTC 优选扫描或测速导出的文本/CSV文件内容 (OTC_SCAN_YX_*.txt, 纯 IP:Port 列表等)"""
    fn_asn = ""
    fn_port = ""
    if filename:
        m_fn = re.search(r"(AS\d+)", filename, re.IGNORECASE)
        if m_fn:
            fn_asn = m_fn.group(1).upper()
        m_port = re.search(r"[-_](\d{2,5})(?:\.|$)", filename)
        if m_port and (1 <= int(m_port.group(1)) <= 65535):
            fn_port = m_port.group(1)

    results = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # 提取行内可能携带的 # 备注 (如 1.2.3.4:443#NRT 日本东京)
        line_remark = ""
        if "#" in line:
            parts_hash = line.split("#", 1)
            line = parts_hash[0].strip()
            line_remark = parts_hash[1].strip()
            if not line:
                continue

        # 智能切分：优先使用逗号，其次使用制表符，最后使用多空格
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
        elif "\t" in line:
            parts = [p.strip() for p in line.split("\t") if p.strip()]
        elif " " in line:
            parts = [p.strip() for p in line.split() if p.strip()]
        else:
            parts = [line]

        if not parts:
            continue

        first_token = parts[0]
        ip = ""
        port = 0
        rem_parts = parts[1:]

        # 1. 检测首项是否携带端口 (如 1.2.3.4:443 或 [2001:db8::1]:443)
        if ":" in first_token:
            c_host, _, c_port = first_token.rpartition(":")
            if c_host and c_port.isdigit() and is_valid_host(c_host):
                ip = c_host
                port = int(c_port)
            elif is_valid_host(first_token):
                ip = first_token
        elif is_valid_host(first_token):
            ip = first_token

        # 若首项未解析出有效 IP，跳过（可能是 CSV 表头或说明行）
        if not ip or not is_valid_host(ip):
            continue

        # 2. 若尚未确定端口，依次尝试从 rem_parts[0]、文件名端口或默认 443 获取
        if port <= 0:
            if rem_parts and rem_parts[0].isdigit() and 1 <= int(rem_parts[0]) <= 65535:
                port = int(rem_parts[0])
                rem_parts = rem_parts[1:]
            elif fn_port:
                port = int(fn_port)
            else:
                port = 443

        if not (1 <= port <= 65535):
            continue

        asn = ""
        isp = ""
        colo = ""
        loc = ""
        delay_ms = ""
        speed_kbs = ""
        exit_ip = ""

        # 特征探测：判断是否为标准的 OTC 7 列优选测速扫描格式
        # 标准格式: {ip:port},{country},{asn},{isp/org},{colo(loc)},{exit_ip},{ip_stack}
        is_otc_7col = False
        if len(parts) >= 6:
            last_token = parts[-1].strip()
            if "ipv" in last_token.lower() or "双栈" in last_token:
                is_otc_7col = True
            elif len(parts) >= 7 and is_valid_ip(parts[5]):
                is_otc_7col = True

        if is_otc_7col:
            # 模式 A：精准定长 7 字段解析，杜绝字段错位与误吞 (兼容 IP:Port 与 IP,Port 独立分列变体)
            sub_parts = parts[2:] if (":" not in first_token and len(parts) > 1 and parts[1].strip().isdigit()) else parts[1:]
            c_country = sub_parts[0].strip() if len(sub_parts) > 0 else ""
            c_asn = sub_parts[1].strip() if len(sub_parts) > 1 else ""
            c_isp = sub_parts[2].strip() if len(sub_parts) > 2 else ""
            c_colo_loc = sub_parts[3].strip() if len(sub_parts) > 3 else ""
            c_exit = sub_parts[4].strip() if len(sub_parts) > 4 else ""

            # 1. 提取 ASN (格式如 AS139659)
            if c_asn:
                m_a = re.search(r"\b(AS\d+)\b", c_asn, re.IGNORECASE)
                if m_a:
                    asn = m_a.group(1).upper()

            # 2. 提取 ISP (排除纯数字或 IP 字符串)
            if c_isp and not is_valid_ip(c_isp) and not c_isp.isdigit():
                isp = c_isp

            # 3. 提取机房代号与位置 (如 HKG (中国-香港))
            if c_colo_loc:
                m_cl = re.match(r"^([A-Z]{3})\s*\((.*?)\)", c_colo_loc)
                if m_cl:
                    colo = m_cl.group(1).upper()
                    loc = m_cl.group(2).strip()
                elif len(c_colo_loc) == 3 and c_colo_loc.isupper():
                    colo = c_colo_loc.upper()
                else:
                    loc = c_colo_loc.strip("()")

            if not loc and c_country:
                loc = c_country

            # 4. 提取真实出口 IP
            if is_valid_ip(c_exit):
                exit_ip = c_exit
        else:
            # 模式 B：通用自适应启发式解析（兼容 DanFeng 变体、纯 IP 文本、带测速指标文本等）
            merged_parts = []
            i = 0
            while i < len(rem_parts):
                p_cur = rem_parts[i]
                if i + 1 < len(rem_parts) and p_cur.isupper() and len(p_cur) == 3 and rem_parts[i + 1].startswith("("):
                    merged_parts.append(p_cur + " " + rem_parts[i + 1])
                    i += 2
                elif p_cur.startswith("(") and not p_cur.endswith(")") and i + 1 < len(rem_parts):
                    merged_parts.append(p_cur + " " + rem_parts[i + 1])
                    i += 2
                else:
                    merged_parts.append(p_cur)
                    i += 1

            for p_val in merged_parts:
                if not p_val or p_val.upper() in ("N/A", "-", "NULL", "NONE"):
                    continue

                # 1. 优先匹配带 AS 前缀的编号 (如 AS210644, AS906)
                m_a = re.search(r"\b(AS\d+)\b", p_val, re.IGNORECASE)
                if m_a and not asn:
                    asn = m_a.group(1).upper()
                    continue

                # 2. 匹配测速下载带宽 (如 12.5MB/s, 1024KB/s, 100Mbps)
                m_spd = re.search(r"^(\d+(?:\.\d+)?)\s*([kKmMgG]?[bB]/s|[kKmMgG]?bps)$", p_val, re.IGNORECASE)
                if m_spd and not speed_kbs:
                    speed_kbs = parse_speed_to_kbs(p_val)
                    continue

                # 3. 匹配显式带 ms 结尾的延迟数值 (如 145ms, 145.5ms)
                m_del = re.search(r"^(\d+(?:\.\d+)?)\s*ms$", p_val, re.IGNORECASE)
                if m_del and not delay_ms:
                    delay_ms = int(float(m_del.group(1)))
                    continue

                # 4. 匹配机房位置字段 (如 HKG (中国-香港), FRA (德国-法兰克福), (中国-香港))
                if "(" in p_val and ")" in p_val and not loc:
                    m_cl = re.match(r"^([A-Z]{3})\s*\((.*?)\)", p_val)
                    if m_cl:
                        colo = m_cl.group(1)
                        loc = m_cl.group(2)
                    else:
                        loc = p_val.strip("()")
                    continue

                # 5. 独立匹配纯三位大写 IATA 机房码 (如 HKG, SJC, NRT, FRA)
                if p_val.isupper() and len(p_val) == 3 and not colo:
                    colo = p_val
                    continue

                # 6. 识别纯数字：延迟 vs 纯数字 ASN 启发式区分
                if p_val.isdigit():
                    val_int = int(p_val)
                    if not delay_ms and val_int < 3000:
                        delay_ms = val_int
                    elif not asn and val_int >= 1000:
                        asn = f"AS{val_int}"
                    continue

                # 7. 识别独立出口 IP（合法 IPv4/IPv6 且非当前入口 IP）
                if not exit_ip and is_valid_ip(p_val) and p_val != ip:
                    exit_ip = p_val
                    continue

                # 8. 识别 ISP 运营商名称 (严密排除 IPv6、公网 IP、机房位置括号、纯数字及短国家码)
                if not isp and ":" not in p_val and "(" not in p_val and not p_val.isdigit():
                    if len(p_val) > 2 and not p_val.startswith("仅") and not is_valid_ip(p_val) and not is_valid_host(p_val):
                        isp = p_val

        # 核心 ASN 优先级规则：
        # 1. 优先使用行内真实提取出的合法 ASN；
        # 2. 行内无 ASN 时，若文件名明确指定了目标 ASN（如 OTC_SCAN_YX_AS210644.txt），采用文件名 ASN 兜底；
        # 3. 否则交由 resolve_and_clean_asn 根据 IP 权威反查。
        if not asn or asn in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
            if fn_asn:
                asn = fn_asn

        if not isp and asn and asn not in ("AS0", "AS_UNKNOWN") and asn in ASN_TO_PROVIDER:
            isp = ASN_TO_PROVIDER[asn]

        if not colo and line_remark:
            m_iata = re.search(r"\b([A-Z]{3})\b", line_remark)
            if m_iata:
                colo = m_iata.group(1)
        if not loc and line_remark:
            loc = line_remark

        clean_asn_code, isp = resolve_and_clean_asn(ip, asn, isp)

        tls = "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false"

        results.append({
            "ip": ip,
            "port": str(port),
            "tls": tls,
            "delay_ms": delay_ms,
            "speed_kbs": speed_kbs,
            "colo": colo,
            "cf_location": loc,
            "isp": isp,
            "asn": format_asn_isp(clean_asn_code, isp),
            "raw_asn": clean_asn_code,
            "first_seen": dt_str,
            "channel": default_channel,
            "fail_count": 0,
            "exit_ip": exit_ip,
            "exit_asn": clean_asn_code,
            "exit_isp": isp,
        })
    return results


RE_ATTACHMENT_PROXY_1 = re.compile(
    r"^(?P<url>(?P<proto>socks5|http|https|turns?|sstp)://(?:[^\s#@]+@[^@\s#]+@|[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
    re.IGNORECASE,
)
RE_ATTACHMENT_PROXY_2 = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turns?|sstp)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
    re.IGNORECASE,
)
RE_ATTACHMENT_PROXY_RAW = re.compile(
    r"^((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(\d{1,5})(?:@([a-zA-Z0-9]+))?"
)


def parse_proxy_attachment_content(text: str) -> list[tuple[str, str]]:
    """解析频道代理附件内容 (如 http_proxies.txt, https_proxies.txt, turn_proxies.txt 等)"""
    results = []
    seen = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # 1. 优先匹配行首标准代理格式（提取最真实的认证与节点信息，忽略后续 PTR 别名和中文评注）
        m = RE_ATTACHMENT_PROXY_1.match(line)
        if m:
            host = m.group("host")
            port = m.group("port")
            if is_valid_host(host) and 1 <= int(port) <= 65535:
                url = m.group("url")
                key = f"{host}:{port}"
                if key not in seen:
                    seen.add(key)
                    results.append((url, key))
                continue

        # 2. 回退普通提取（容错）
        m_any = RE_ATTACHMENT_PROXY_2.search(line)
        if m_any:
            host = m_any.group("host")
            port = m_any.group("port")
            if is_valid_host(host) and 1 <= int(port) <= 65535:
                url = m_any.group("url")
                key = f"{host}:{port}"
                if key not in seen:
                    seen.add(key)
                    results.append((url, key))
                continue

        # 3. 支持无 URL 协议头纯 IP:Port 或 IP:Port@proto 格式 (如 1.1.1.1:8080 或 2.2.2.2:1080@socks5)
        m_raw = RE_ATTACHMENT_PROXY_RAW.match(line)
        if m_raw:
            host = m_raw.group(1)
            port = m_raw.group(2)
            proto = (m_raw.group(3) or "socks5").lower()
            if is_valid_host(host) and 1 <= int(port) <= 65535:
                url = f"{proto}://{host}:{port}"
                key = f"{host}:{port}"
                if key not in seen:
                    seen.add(key)
                    results.append((url, key))

    return results
