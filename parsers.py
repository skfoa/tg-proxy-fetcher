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
from urllib.parse import parse_qs, urlparse

from providers import (
    KNOWN_CLOUD_PROVIDERS,
    ASN_TO_PROVIDER,
    SORTED_CLOUD_PROVIDER_KEYS,
    _extract_asn_code,
    format_asn_isp,
    is_valid_public_ip,
    load_ip_cache,
    normalize_timestamp,
    resolve_authoritative_cache_asn,
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


def is_valid_ipv4(val: str) -> bool:
    """严格校验是否为有效 IPv4 地址"""
    if not val:
        return False
    clean = str(val).strip().strip("[]")
    try:
        return ipaddress.ip_address(clean).version == 4
    except Exception:
        return False


def is_valid_ipv6(val: str) -> bool:
    """严格校验是否为有效 IPv6 地址"""
    if not val:
        return False
    clean = str(val).strip().strip("[]")
    try:
        return ipaddress.ip_address(clean).version == 6
    except Exception:
        return False


def extract_ips(val) -> list[str]:
    """从任意输入（单串、列表、逗号/分号/斜杠/空格分隔）中提取所有合法 IP 地址（IPv4 与 IPv6），保持顺序并去重"""
    if not val:
        return []
    if isinstance(val, (list, tuple, set)):
        raw_items = [str(x) for x in val]
    else:
        raw_items = re.split(r"[,;\s/|]+", str(val).strip())
    res = []
    seen = set()
    for item in raw_items:
        clean = item.strip().strip("[]'\"")
        if clean and is_valid_ip(clean) and clean not in seen:
            seen.add(clean)
            res.append(clean)
    return res


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


def resolve_and_clean_asn(
    ip: str,
    raw_asn: str = "",
    raw_isp: str = "",
    ip_cache: dict[str, dict] | None = None,
) -> tuple[str, str]:
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

    cache = ip_cache
    # 权威本地 IP 缓存：若 ip_cache 持有真实非占位 BGP ASN，且当前标记缺失/占位/与缓存冲突（含非 Cloudflare 错标），坚决以缓存为准
    if ip and ip not in ("AS_UNKNOWN", "unknown", "127.0.0.1"):
        try:
            if cache is None:
                cache = load_ip_cache()
            cached_asn, cached_isp = resolve_authoritative_cache_asn(cache, ip)
            if cached_asn:
                if (
                    not asn_clean
                    or asn_clean in ("AS0", "AS_UNKNOWN", "UNKNOWN")
                    or cached_asn != asn_clean
                ):
                    asn_clean = cached_asn
                    raw_isp = cached_isp
                elif cached_isp and not raw_isp:
                    raw_isp = cached_isp
        except Exception:
            pass

    if not asn_clean or asn_clean in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
        found_asn, found_isp = resolve_ip_asn(ip, raw_isp, ip_cache=cache)
        if found_asn and found_asn.upper() not in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
            asn_clean = found_asn
            if not raw_isp and found_isp:
                raw_isp = found_isp

    if asn_clean and asn_clean in ASN_TO_PROVIDER:
        std_isp = ASN_TO_PROVIDER[asn_clean]
        if not raw_isp or len(raw_isp.strip()) <= 2 or re.search(r'(?i)^(?:sa|beafort|ht|dc|unknown|none|null|n/a)$', raw_isp.strip()):
            raw_isp = std_isp

    return asn_clean or "", raw_isp


def parse_cf_ip(
    text: str,
    default_channel: str = "",
    ip_cache: dict[str, dict] | None = None,
) -> dict | None:
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

    asn_val, raw_isp = resolve_and_clean_asn(ip, raw_asn, raw_isp, ip_cache=ip_cache)
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
    ip_cache: dict[str, dict] | None = None,
) -> list[dict]:
    """解析 Cloudflare 优选测速与反代 ProxyIP CSV 格式内容（支持 DanFeng、CheckProxyIP、云厂商测速等）"""
    fn_asn = ""
    fn_isp = ""
    fn_port = ""
    fn_time = dt_str

    if filename:
        fn_lower = filename.lower()
        base_fn = os.path.basename(filename.replace("\\", "/"))
        # OTC 优选扫描导出文件 (OTC_SCAN_*) 交由专属 parse_otc_scan_content 解析，避免被无表头 CSV 模式误吞截断字段
        if base_fn.lower().startswith("otc_scan"):
            return []
        # 1. 优先从文件名正则匹配 AS 编号与 ISP (支持 DanFeng 命名规范，如 AS45102_CNNICALIBABACNNETAP_20260906_190653.csv, AS61112_AkileCloud_Network_20260831_012345.csv)
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

    local_cache = ip_cache

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
            # 防误吞守卫：若无表头行携带显式 AS\d+ 列或 OTC 多列扫描特征（国家/ASN/ISP/机房/出口IP/栈类型），交由 parse_otc_scan_content 处理
            if any(re.match(r"^AS\d+$", p, re.IGNORECASE) for p in first_parts[1:]) or (
                len(first_parts) >= 6
                and (
                    "ipv" in first_parts[-1].lower()
                    or "双栈" in first_parts[-1]
                    or is_valid_ip(first_parts[-2])
                )
            ):
                return []

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
                if raw_delay and not re.match(r"^AS\d+\b", raw_delay.strip(), re.IGNORECASE):
                    m_delay = re.search(r"(\d+(?:\.\d+)?)", raw_delay)
                    if m_delay:
                        delay_ms = int(float(m_delay.group(1)))

                if local_cache is None:
                    local_cache = load_ip_cache()
                # Step 2: fn_asn / fn_isp 降级为无冲突 hint，解析阶段不写入 raw_asn / isp，避免阻断后续在线反查
                row_asn, row_isp = resolve_and_clean_asn(raw_ip, "", "", ip_cache=local_cache)
                if not row_asn:
                    row_isp = ""

                row_item = {
                    "ip": raw_ip,
                    "port": str(port),
                    "tls": "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false",
                    "delay_ms": delay_ms,
                    "speed_kbs": "",
                    "colo": "",
                    "cf_location": "",
                    "isp": row_isp,
                    "asn": format_asn_isp(row_asn, row_isp) if row_asn else "",
                    "raw_asn": row_asn,
                    "first_seen": fn_time,
                    "channel": default_channel,
                    "fail_count": 0,
                    "exit_ip": "",
                    "exit_ipv6": "",
                }
                if not row_asn and fn_asn:
                    row_item["asn_hint"] = fn_asn
                    if fn_isp:
                        row_item["isp_hint"] = fn_isp
                results.append(row_item)
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

            # 1. 优先精准提取出口/出站 IP 字段 (含 IPv4 / IPv6 细分与解耦列)
            if any(k in c_clean for k in ("出站ipv6", "出口ipv6", "egressipv6", "exitipv6", "clientipv6", "出站v6", "出口v6")):
                field_map["exit_ipv6"] = col
                continue
            if any(k in c_clean for k in ("出站ipv4", "出口ipv4", "egressipv4", "exitipv4", "clientipv4", "出站v4", "出口v4")):
                field_map["exit_ipv4"] = col
                continue
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

            # 真实出口 IP 提取与校验（原生支持单/多出口与 IPv4/IPv6 双栈解耦）
            raw_exit_ip = row.get(field_map.get("exit_ip", ""), "").strip()
            raw_exit_v4 = row.get(field_map.get("exit_ipv4", ""), "").strip()
            raw_exit_v6 = row.get(field_map.get("exit_ipv6", ""), "").strip()
            cand_exit_ips = extract_ips([raw_exit_ip, raw_exit_v4, raw_exit_v6])
            v4_exits = [cip for cip in cand_exit_ips if is_valid_ipv4(cip)]
            v6_exits = [cip for cip in cand_exit_ips if is_valid_ipv6(cip)]
            exit_v4 = v4_exits[0] if v4_exits else ""
            exit_v6 = v6_exits[0] if v6_exits else ""
            exit_ip = exit_v4 or exit_v6
            exit_ipv6 = exit_v6

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
                raw_asn = ""
            elif raw_asn.isdigit():
                num = int(raw_asn)
                raw_asn = f"AS{num}" if num > 0 else ""

            raw_isp = row.get(field_map.get("isp", ""), "").replace("`", "").strip()
            if not raw_isp or raw_isp in ("-", "UNKNOWN", "AS_UNKNOWN"):
                raw_isp = ""

            if local_cache is None:
                local_cache = load_ip_cache()
            has_separate_exit = bool(exit_ip and is_valid_ip(exit_ip) and exit_ip != raw_ip)
            ex_asn_code = _extract_asn_code(raw_exit_asn, raw_exit_isp)
            if has_separate_exit:
                # 出入口严格解耦：存在独立 exit_ip 时，绝不用 exit_asn 污染入口；
                # 若入口未缓存且行内 asn 与 exit_asn 相同（疑似出口反写污染），置空交由后续在线反查独立验证
                cached_ing_code, _ = resolve_authoritative_cache_asn(local_cache, raw_ip)
                ing_asn_code = _extract_asn_code(raw_asn, raw_isp)
                if (not cached_ing_code) and ing_asn_code and ex_asn_code and ing_asn_code == ex_asn_code:
                    asn_val, raw_isp = resolve_and_clean_asn(raw_ip, "", "", ip_cache=local_cache)
                else:
                    asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_asn, raw_isp, ip_cache=local_cache)
                resolved_ex_code, resolved_ex_isp = resolve_and_clean_asn(
                    exit_ip, raw_exit_asn, raw_exit_isp, ip_cache=local_cache
                )
                if resolved_ex_code:
                    raw_exit_asn = resolved_ex_code
                    if not raw_exit_isp:
                        raw_exit_isp = resolved_ex_isp
            else:
                asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_asn, raw_isp, ip_cache=local_cache)
                # 仅同出口/单 IP 场景且入口 ASN 缺失时，才允许使用 exit_asn 兜底；
                # 文件名 fn_asn / fn_isp 绝不写入 raw_asn / isp，仅作 asn_hint / isp_hint 留待在线反查失败后兜底
                if (not asn_val or asn_val in ("AS0", "AS_UNKNOWN", "UNKNOWN")) and raw_exit_asn:
                    asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_exit_asn, raw_exit_isp or raw_isp, ip_cache=local_cache)

            raw_time = row.get(field_map.get("time", ""), "").strip()
            first_seen = normalize_timestamp(raw_time, fn_time)

            row_item = {
                "ip": raw_ip,
                "port": str(port),
                "tls": tls,
                "delay_ms": delay_ms,
                "speed_kbs": speed_kbs,
                "colo": colo,
                "cf_location": cf_location,
                "isp": raw_isp,
                "asn": format_asn_isp(asn_val, raw_isp) if asn_val else "",
                "raw_asn": asn_val,
                "first_seen": first_seen,
                "channel": row_channel,
                "fail_count": 0,
                "exit_ip": exit_ip,
                "exit_ipv6": exit_ipv6,
                "exit_asn": raw_exit_asn,
                "exit_isp": raw_exit_isp,
            }
            if not asn_val and fn_asn and not (exit_ip and exit_ip != raw_ip):
                row_item["asn_hint"] = fn_asn
                if fn_isp:
                    row_item["isp_hint"] = fn_isp
            results.append(row_item)
    except Exception as e:
        log.warning("解析 CSV 优选/ProxyIP 数据异常: %s", e)

    return results


_CORP_SUFFIX_3 = frozenset({
    "LTD", "PTE", "LLC", "INC", "PLC", "PVT", "GMB", "COR", "LLP", "SPA", "SRL", "SAS", "OOO", "JSC",
})


def parse_otc_scan_content(
    text: str,
    default_channel: str = "@otcjlq",
    filename: str = "",
    dt_str: str = "",
    ip_cache: dict[str, dict] | None = None,
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

    local_cache = ip_cache
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
        # rem_parts 已剥离首列 IP (及独立端口列)，通过右锚定 ip_stack / exit_ip 兼容 ISP 内含未引号逗号的拆分场景
        is_otc_7col = False
        has_stack_col = False
        if len(rem_parts) >= 5:
            last_token = rem_parts[-1].strip()
            if "ipv" in last_token.lower() or "双栈" in last_token:
                is_otc_7col = True
                has_stack_col = True
            elif is_valid_ip(last_token):
                is_otc_7col = True

        if is_otc_7col:
            # 模式 A：左锚定 country/asn + 右锚定 colo_loc/exit_ip[/ip_stack]，中间多段逗号碎片以 ", " 重组为完整 ISP
            c_country = rem_parts[0].strip() if len(rem_parts) > 0 else ""
            c_asn = rem_parts[1].strip() if len(rem_parts) > 1 else ""
            if has_stack_col:
                if len(rem_parts) >= 6:
                    c_exit = rem_parts[-2].strip()
                    c_colo_loc = rem_parts[-3].strip()
                    isp_parts = rem_parts[2:-3]
                else:
                    c_exit = ""
                    c_colo_loc = rem_parts[-2].strip()
                    isp_parts = rem_parts[2:-2]
            else:
                c_exit = rem_parts[-1].strip()
                c_colo_loc = rem_parts[-2].strip()
                isp_parts = rem_parts[2:-2]
            c_isp = ", ".join(p.strip() for p in isp_parts if p and p.strip())

            # 1. 提取 ASN (格式如 AS139659)
            if c_asn:
                m_a = re.search(r"\b(AS\d+)\b", c_asn, re.IGNORECASE)
                if m_a:
                    asn = m_a.group(1).upper()

            # 2. 提取 ISP (排除纯数字或 IP 字符串)
            if c_isp and not is_valid_ip(c_isp) and not c_isp.isdigit():
                isp = c_isp

            # 3. 提取机房代号与位置 (如 HKG (中国-香港)，严防公司后缀 LTD/PTE/LLC 误判为 IATA 码)
            if c_colo_loc:
                m_cl = re.match(r"^([A-Z]{3})\s*\((.*?)\)", c_colo_loc)
                if m_cl:
                    cand_colo = m_cl.group(1).upper()
                    if cand_colo not in _CORP_SUFFIX_3:
                        colo = cand_colo
                    loc = m_cl.group(2).strip()
                elif len(c_colo_loc) == 3 and c_colo_loc.isupper() and c_colo_loc.upper() not in _CORP_SUFFIX_3:
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
                        if m_cl.group(1).upper() not in _CORP_SUFFIX_3:
                            colo = m_cl.group(1).upper()
                        loc = m_cl.group(2)
                    else:
                        loc = p_val.strip("()")
                    continue

                # 5. 独立匹配纯三位大写 IATA 机房码 (如 HKG, SJC, NRT, FRA，排除公司后缀 PTE/LLC/LTD 等)
                if p_val.isupper() and len(p_val) == 3 and p_val not in _CORP_SUFFIX_3 and not colo:
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

        if not colo and line_remark:
            m_iata = re.search(r"\b([A-Z]{3})\b", line_remark)
            if m_iata and m_iata.group(1) not in _CORP_SUFFIX_3:
                colo = m_iata.group(1)
        if not loc and line_remark:
            loc = line_remark

        if local_cache is None:
            local_cache = load_ip_cache()

        has_separate_exit = bool(exit_ip and is_valid_ip(exit_ip) and exit_ip != ip)
        if has_separate_exit:
            # 出入口严格解耦：行内 ASN/ISP 仅归属出口 exit_ip (绝不用 fn_asn 填出口)；
            # 入口仅查独立 ip_cache / 离线 BGP 反查，未命中则留空交由后续批量在线反查补全，杜绝出口属性污染入口
            exit_asn_code, exit_isp_val = resolve_and_clean_asn(exit_ip, asn, isp, ip_cache=local_cache)
            if not exit_isp_val and exit_asn_code and exit_asn_code in ASN_TO_PROVIDER:
                exit_isp_val = ASN_TO_PROVIDER[exit_asn_code]
            clean_asn_code, ingress_isp_val = resolve_and_clean_asn(ip, "", "", ip_cache=local_cache)
            if not ingress_isp_val and clean_asn_code and clean_asn_code in ASN_TO_PROVIDER:
                ingress_isp_val = ASN_TO_PROVIDER[clean_asn_code]
        else:
            # 同出口或单 IP 场景：fn_asn 降级为仅记录在 asn_hint 中的无冲突 hint（仅在线反查失败或预算耗尽后兜底）
            if not asn or asn in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
                clean_asn_code, ingress_isp_val = resolve_and_clean_asn(ip, "", isp, ip_cache=local_cache)
            else:
                if not isp and asn in ASN_TO_PROVIDER:
                    isp = ASN_TO_PROVIDER[asn]
                clean_asn_code, ingress_isp_val = resolve_and_clean_asn(ip, asn, isp, ip_cache=local_cache)
            exit_asn_code = clean_asn_code
            exit_isp_val = ingress_isp_val

        tls = "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false"

        row_item = {
            "ip": ip,
            "port": str(port),
            "tls": tls,
            "delay_ms": delay_ms,
            "speed_kbs": speed_kbs,
            "colo": colo,
            "cf_location": loc,
            "isp": ingress_isp_val,
            "asn": format_asn_isp(clean_asn_code, ingress_isp_val) if clean_asn_code else "",
            "raw_asn": clean_asn_code,
            "first_seen": dt_str,
            "channel": default_channel,
            "fail_count": 0,
            "exit_ip": exit_ip,
            "exit_ipv6": exit_ip if is_valid_ipv6(exit_ip) else "",
            "exit_asn": exit_asn_code,
            "exit_isp": exit_isp_val,
        }
        if not has_separate_exit and not clean_asn_code and fn_asn:
            row_item["asn_hint"] = fn_asn
            hint_isp = ASN_TO_PROVIDER.get(fn_asn, "")
            if hint_isp:
                row_item["isp_hint"] = hint_isp
        results.append(row_item)
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


RE_IPV6_PORT = re.compile(r"^\[([0-9a-fA-F:]+)\]:(\d{1,5})$")
RE_IPV4_PORT = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$")


def parse_proxyip_domain_spec(spec: str, default_port: int = 443) -> tuple[str, int] | None:
    """
    解析 ProxyIP 域名配置条目（如 'kr.william.us.ci' 或 'example.com:8443'），
    返回规范化的 (domain, default_port)；非法或纯 IP 输入返回 None。
    """
    raw = str(spec or "").strip().split("#", 1)[0].strip()
    if not raw or not (1 <= default_port <= 65535):
        return None

    domain = ""
    port = default_port
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            domain = (parsed.hostname or "").strip().rstrip(".").lower()
            if parsed.port is not None:
                port = parsed.port
        except Exception:
            return None
    else:
        raw_clean = raw.strip("[]")
        if ":" in raw_clean:
            host_part, port_part = raw_clean.rsplit(":", 1)
            if not port_part.isdigit():
                return None
            port = int(port_part)
            domain = host_part.strip().rstrip(".").lower()
        else:
            domain = raw_clean.strip().rstrip(".").lower()

    if not domain or not (1 <= port <= 65535):
        return None
    if not is_valid_host(domain) or is_valid_ip(domain):
        return None
    return domain, port


def parse_proxyip_txt_endpoints(
    txt_records: list[str] | str,
    default_port: int = 443,
    allow_bare_ip: bool = False,
) -> list[tuple[str, int]]:
    """
    从 DNS TXT 记录文本中提取所有有效的 ProxyIP (ip, port) 端点，
    支持逗号/分号/空白分隔、IPv4:Port、[IPv6]:Port、无端口裸 IP（回退 default_port）及 # 备注过滤。
    """
    if not txt_records:
        return []
    raw_list = [txt_records] if isinstance(txt_records, str) else list(txt_records)
    endpoints: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    for raw_txt in raw_list:
        text = str(raw_txt or "").strip()
        if not text:
            continue
        for seg in re.split(r"[,;\r\n]+", text):
            seg_clean = seg.split("#", 1)[0].strip()
            if not seg_clean:
                continue
            for tok in seg_clean.split():
                clean_tok = tok.split("#", 1)[0].strip().strip("'\"")
                if not clean_tok:
                    continue

                ip_val = ""
                port_val = 0
                m6 = RE_IPV6_PORT.match(clean_tok)
                if m6:
                    ip_val = m6.group(1).strip()
                    port_val = int(m6.group(2))
                else:
                    m4 = RE_IPV4_PORT.match(clean_tok)
                    if m4:
                        ip_val = m4.group(1).strip()
                        port_val = int(m4.group(2))
                    elif allow_bare_ip:
                        bare = clean_tok.strip("[]")
                        if is_valid_ip(bare) and 1 <= default_port <= 65535:
                            ip_val = bare
                            port_val = default_port

                if ip_val and (1 <= port_val <= 65535) and is_valid_public_ip(ip_val):
                    pair = (ip_val, port_val)
                    if pair not in seen:
                        seen.add(pair)
                        endpoints.append(pair)

    return endpoints
