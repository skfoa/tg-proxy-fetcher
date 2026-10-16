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
import logging
import os
import re
from urllib.parse import parse_qs

from providers import (
    KNOWN_CLOUD_PROVIDERS,
    ASN_TO_PROVIDER,
    SORTED_CLOUD_PROVIDER_KEYS,
    format_asn_isp,
    normalize_timestamp,
    resolve_ip_asn,
)

log = logging.getLogger("parsers")

# 通用代理匹配正则表达式
ANNOUNCE_PROXY_RE = re.compile(
    r"\[发现开放\s*(?P<proto>HTTP|SOCKS5|HTTPS|TURN|SSTP)\s*(?:代理|服务)?\]\s*(?:(?:https?|socks5|turn|sstp)://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
)
TG_SOCKS_RE = re.compile(
    r"(?:tg://socks|https?://(?:t\.me|telegram\.me)/socks)\?(?P<query>[^\s#]+)"
)
PROXY_URL_RE = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turn|sstp)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
    re.IGNORECASE,
)


RE_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$")


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
    1. 从 raw_asn 中正则提取标准 AS\d+ 编号；
    2. 兼容 ASN/ISP 列反转（如 raw_asn 全为组织名称）；
    3. 若缺少有效 ASN，查持久化库或在线反查 (resolve_ip_asn) 补全；
    4. 返回 (asn_code, isp_name)。
    """
    raw_asn = (raw_asn or "").strip()
    raw_isp = (raw_isp or "").strip()

    asn_clean = ""
    if raw_asn:
        m_asn = RE_AS_CODE.search(raw_asn)
        if m_asn:
            asn_clean = m_asn.group(1).upper()
            if not raw_isp:
                rem_isp = raw_asn[m_asn.end():].strip().strip("-").strip()
                if rem_isp:
                    raw_isp = rem_isp
        else:
            if not raw_isp and raw_asn != "-":
                raw_isp = raw_asn

    if not asn_clean or asn_clean == "AS_UNKNOWN":
        found_asn, found_isp = resolve_ip_asn(ip, raw_isp)
        if found_asn:
            asn_clean = found_asn
            if not raw_isp and found_isp:
                raw_isp = found_isp

    return asn_clean or raw_asn, raw_isp


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
        base_fn = os.path.basename(filename)
        m_fn = re.search(r"(?i)(?P<asn>AS\d+)_(?P<isp>.+?)(?:_(?P<date>\d{8})_(?P<time>\d{6}))?\.(?:csv|txt)$", base_fn)
        if m_fn:
            fn_asn = m_fn.group("asn").upper()
            raw_captured_isp = m_fn.group("isp").replace("-", " ").replace("_", " ")
            fn_isp = re.sub(r"\.(?:csv|txt)$", "", raw_captured_isp, flags=re.IGNORECASE).strip()
            if m_fn.group("date") and m_fn.group("time") and not fn_time:
                d = m_fn.group("date")
                t = m_fn.group("time")
                fn_time = f"{d[:4]}-{d[4:6]}-{d[6:8]} {t[:2]}:{t[2:4]}:{t[4:6]}"
        elif not any(bad in fn_lower for bad in ("nsb", "results", "speedtest", "benchmark", "warp", "tunnel")):
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
                    "first_seen": fn_time,
                    "channel": default_channel,
                    "fail_count": 0,
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
            if any(k in c_clean for k in ("出站", "egress", "tunnel", "warp", "gateway")):
                continue
            if any(k in c_clean for k in ("ip地址", "ipaddress", "proxyip")) or c_clean == "ip":
                field_map["ip"] = col
            elif any(k in c_clean for k in ("端口", "port")):
                field_map["port"] = col
            elif any(k in c_clean for k in ("tls", "istls", "ssl")):
                field_map["tls"] = col
            elif any(k in c_clean for k in ("延迟", "delay", "latency", "connectms")):
                field_map["delay"] = col
            elif any(k in c_clean for k in ("速度", "speed", "带宽", "bandwidth")):
                field_map["speed"] = col
                if "mb" in c_clean:
                    speed_unit_is_mb = True
            elif any(k in c_clean for k in ("数据中心", "机房", "colo")):
                field_map["colo"] = col
            elif any(k in c_clean for k in ("位置", "location", "country", "国家")):
                field_map["loc"] = col
            elif any(k in c_clean for k in ("地区", "省份", "region", "province")):
                field_map["region"] = col
            elif any(k in c_clean for k in ("城市", "city")):
                field_map["city"] = col
            elif c_clean in ("asn", "as", "asnumber", "asnum") or any(k in c_clean for k in ("as编号", "as号码", "as_number")):
                field_map["asn"] = col
            elif any(k in c_clean for k in ("运营商", "组织", "org", "isp", "company")):
                field_map["isp"] = col
            elif any(k in c_clean for k in ("时间", "time", "date")):
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

            loc_parts = []
            for key in ("region", "city", "loc"):
                val = row.get(field_map.get(key, ""), "").strip()
                if val and val != "-" and val not in loc_parts:
                    loc_parts.append(val)
            cf_location = " · ".join(loc_parts)

            raw_asn = row.get(field_map.get("asn", ""), "").replace("`", "").strip()
            if not raw_asn or raw_asn == "-":
                raw_asn = fn_asn

            raw_isp = row.get(field_map.get("isp", ""), "").replace("`", "").strip()
            if not raw_isp or raw_isp == "-":
                raw_isp = fn_isp

            asn_val, raw_isp = resolve_and_clean_asn(raw_ip, raw_asn, raw_isp)

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
                "first_seen": first_seen,
                "channel": default_channel,
                "fail_count": 0,
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

        # 0. 预处理 rem_parts：若存在被空格切散的 IATA 航线机房码与括号备注（如 HKG (中国-香港)），或括号内部包含空格，予以合并
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

        # 依次探测 ASN 编号 (ASxxxx 或纯数字)、Colo位置、延时、速度与 ISP
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
                # 典型网络延迟大多分布在 1-3000ms 之间，若尚未提取到延迟则优先填补延迟
                if not delay_ms and val_int < 3000:
                    delay_ms = val_int
                elif not asn and val_int >= 1000:
                    asn = f"AS{val_int}"
                continue

            # 7. 识别 ISP 运营商名称 (排除 IPv6、机房位置括号、纯数字及短国家码)
            if not isp and ":" not in p_val and "(" not in p_val and not p_val.isdigit():
                if len(p_val) > 2 and not p_val.startswith("仅"):
                    isp = p_val

        # 核心 ASN 判定规则：
        # 1. 若文件名明确指定了目标 ASN（如 OTC_SCAN_YX_AS210644.txt），全文件统一以文件名中目标 ASN 为准；
        # 2. 若文件名没有 ASN（如混合文件 OTC_SCAN_YX_杂.txt），则直接以该行数据中具体的 ASN 与 ISP 为准；
        if fn_asn:
            asn = fn_asn
        elif not asn:
            asn = "AS_UNKNOWN"

        if not isp and asn and asn != "AS_UNKNOWN" and asn in ASN_TO_PROVIDER:
            isp = ASN_TO_PROVIDER[asn]

        if not colo and line_remark:
            m_iata = re.search(r"\b([A-Z]{3})\b", line_remark)
            if m_iata:
                colo = m_iata.group(1)
        if not loc and line_remark:
            loc = line_remark

        asn, isp = resolve_and_clean_asn(ip, asn, isp)

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
            "asn": format_asn_isp(asn, isp),
            "first_seen": dt_str,
            "channel": default_channel,
            "fail_count": 0,
        })
    return results


RE_ATTACHMENT_PROXY_1 = re.compile(
    r"^(?P<url>(?P<proto>socks5|http|https|turn|sstp)://(?:[^\s#@]+@[^@\s#]+@|[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
    re.IGNORECASE,
)
RE_ATTACHMENT_PROXY_2 = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turn|sstp)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
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
