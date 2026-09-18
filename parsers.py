#!/usr/bin/env python3
"""
Telegram 消息与文件解析器模块 (parsers.py)
从公开频道非结构化消息与各类测速附件中精准提取节点与指标，全面解耦数据提取与业务调度：
  1. 通用代理匹配：标准 URL 格式 (socks5/http/https/turn)、tg://socks 链接转换、发现开放代理通报（带防污染隔离）。
  2. 频道单条优选：解析测速通报卡片中的 IP、端口、TLS、网络延迟、下载速度、colo、落地地区等指标。
  3. 测速附件解析：解析 DanFeng 命名规范 CSV 与 OTC 优选测速扫描 TXT，根据 ASN 与厂商智能清洗归类。
  4. 代理附件解析：识别并提取各类文本代理附件文件中的有效节点。
"""

import csv
import logging
import os
import re
from urllib.parse import parse_qs

from providers import KNOWN_CLOUD_PROVIDERS, ASN_TO_PROVIDER

log = logging.getLogger("parsers")

# 通用代理匹配正则表达式
ANNOUNCE_PROXY_RE = re.compile(
    r"\[发现开放\s*(?P<proto>HTTP|SOCKS5|SOCKS4|HTTPS|TURN)\s*(?:代理|服务)?\]\s*(?:(?:https?|socks5|socks4|turn)://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
)
TG_SOCKS_RE = re.compile(
    r"(?:tg://socks|https?://(?:t\.me|telegram\.me)/socks)\?(?P<query>[^\s#]+)"
)
PROXY_URL_RE = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turn)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))"
)


def is_valid_host(host: str) -> bool:
    """验证主机名是否为有效 IPv4 地址或域名"""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    if len(parts) >= 2 and parts[-1].isalpha() and len(parts[-1]) >= 2:
        return all(bool(re.match(r"^[a-zA-Z0-9-]+$", part)) for part in parts)
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


def parse_cf_ip(text: str, default_channel: str = "") -> dict | None:
    """从单条优选 IP 消息卡片中提取结构化字段"""
    ip_m = re.search(r"IP地址[:：]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
    port_m = re.search(r"端口[:：]\s*(\d{1,5})", text)
    if not ip_m or not port_m:
        return None

    ip = ip_m.group(1).strip()
    port = port_m.group(1).strip()
    if not is_valid_host(ip) or not (1 <= int(port) <= 65535):
        return None

    tls_m = re.search(r"TLS[:：]\s*(true|false)", text, re.IGNORECASE)
    asn_m = re.search(r"ASN编号[:：]\s*([^\r\n]+)", text)
    isp_m = re.search(r"运营商[:：]\s*([^\r\n]+)", text)
    colo_m = re.search(r"数据中心[:：]\s*([A-Za-z0-9]+)", text)
    cf_loc_m = re.search(r"CF落地位置[:：].*?🌐\s*([^\r\n]+)", text, re.DOTALL)
    delay_m = re.search(r"网络延迟[:：]\s*(\d+(?:\.\d+)?)\s*ms", text)
    speed_m = re.search(r"下载速度[:：]\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?[bB]/s)?", text)
    speed_kbs = ""
    if speed_m:
        val = float(speed_m.group(1))
        unit = (speed_m.group(2) or "kB/s").lower()
        if "m" in unit:
            val *= 1024
        elif "g" in unit:
            val *= 1024 * 1024
        speed_kbs = int(val)

    time_m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", text)
    source_m = re.search(r"IP来源[:：]\s*([@\w]+)", text)

    return {
        "ip": ip,
        "port": port,
        "tls": tls_m.group(1).lower() if tls_m else "unknown",
        "delay_ms": int(float(delay_m.group(1))) if delay_m else "",
        "speed_kbs": speed_kbs,
        "colo": colo_m.group(1).strip() if colo_m else "",
        "cf_location": cf_loc_m.group(1).strip() if cf_loc_m else "",
        "isp": isp_m.group(1).strip() if isp_m else "",
        "asn": asn_m.group(1).strip() if asn_m else "",
        "tested_at": time_m.group(1).strip() if time_m else "",
        "channel": source_m.group(1).strip() if source_m else default_channel,
        "fail_count": 0,
    }


def parse_cf_csv_content(
    text: str,
    default_channel: str = "@danfeng2",
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
            for key in sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True):
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

        # 检测首行是否为无标题数据行 (例如首列直接是 IP 地址)
        first_parts = [p.strip().strip('"') for p in first_line.split(",")]
        is_headerless = False
        if first_parts and (is_valid_host(first_parts[0]) or ":" in first_parts[0]):
            is_headerless = True

        if is_headerless:
            reader_rows = csv.reader(lines)
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
                    # 只有两列 [IP, 第二列]: 若文件名已指定端口(如 ProxyIP-8443)，则第二列通常是延迟
                    if fn_port:
                        raw_port = raw_port or fn_port
                        raw_delay = row[1].strip()
                    else:
                        val = row[1].strip()
                        # 常见端口优先作为端口，否则作为延迟
                        if val.isdigit() and int(val) in (80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 1080):
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

                results.append({
                    "ip": raw_ip,
                    "port": str(port),
                    "tls": "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false",
                    "delay_ms": delay_ms,
                    "speed_kbs": "",
                    "colo": "",
                    "cf_location": "",
                    "isp": fn_isp,
                    "asn": fn_asn or "AS_UNKNOWN",
                    "tested_at": fn_time,
                    "channel": default_channel,
                })
            return results

        reader = csv.DictReader(lines)
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
            elif any(k in c_clean for k in ("asn", "as编号", "as号码")):
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
            speed_kbs = ""
            m_speed = re.search(r"(\d+(?:\.\d+)?)\s*([kKmMgG]?[bB]/s)?", raw_speed)
            if m_speed:
                val = float(m_speed.group(1))
                unit = (m_speed.group(2) or "").lower()
                if "m" in unit or (not unit and speed_unit_is_mb):
                    val *= 1024
                elif "g" in unit:
                    val *= 1024 * 1024
                speed_kbs = int(val)

            colo = row.get(field_map.get("colo", ""), "").strip()

            loc_parts = []
            for key in ("region", "city", "loc"):
                val = row.get(field_map.get(key, ""), "").strip()
                if val and val != "-" and val not in loc_parts:
                    loc_parts.append(val)
            cf_location = " · ".join(loc_parts)

            raw_asn = row.get(field_map.get("asn", ""), "").strip()
            if not raw_asn or raw_asn == "-":
                raw_asn = fn_asn
            m_asn = re.search(r"(AS\d+)", raw_asn, re.IGNORECASE)
            asn_clean = m_asn.group(1).upper() if m_asn else (raw_asn if raw_asn and raw_asn != "-" else "")

            raw_isp = row.get(field_map.get("isp", ""), "").strip()
            if not raw_isp or raw_isp == "-":
                raw_isp = fn_isp

            # 智能补全：若数据行缺少 ASN，但 ISP 匹配已知服务商，自动推断补全 ASN
            if (not asn_clean or asn_clean == "AS_UNKNOWN") and raw_isp:
                isp_lower = raw_isp.lower()
                for key in sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True):
                    if key in isp_lower:
                        asn_clean, default_isp = KNOWN_CLOUD_PROVIDERS[key]
                        if not raw_isp:
                            raw_isp = default_isp
                        break

            # 智能补全：若已有 ASN 但缺少 ISP，从 ASN 反查知名服务商名称
            if asn_clean and asn_clean != "AS_UNKNOWN" and not raw_isp:
                if asn_clean in ASN_TO_PROVIDER:
                    raw_isp = ASN_TO_PROVIDER[asn_clean]

            tested_at = row.get(field_map.get("time", ""), "").strip() or fn_time

            results.append({
                "ip": raw_ip,
                "port": str(port),
                "tls": tls,
                "delay_ms": delay_ms,
                "speed_kbs": speed_kbs,
                "colo": colo,
                "cf_location": cf_location,
                "isp": raw_isp,
                "asn": asn_clean or "AS_UNKNOWN",
                "tested_at": tested_at,
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
    """解析 OTC 优选扫描导出的 CSV 格式文件内容 (OTC_SCAN_YX_*.txt)"""
    fn_asn = ""
    if filename:
        m_fn = re.search(r"(AS\d+)", filename, re.IGNORECASE)
        if m_fn:
            fn_asn = m_fn.group(1).upper()

    results = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        ip = parts[0]
        port_str = parts[1]
        if not is_valid_host(ip) or not port_str.isdigit():
            continue
        port = int(port_str)
        if not (1 <= port <= 65535):
            continue

        asn = ""
        isp = ""
        colo_loc = ""
        # 依次探测 ASN 编号 (ASxxxx 或纯数字)、Colo位置与 ISP
        for idx in range(2, len(parts)):
            p_val = parts[idx]
            if not p_val or p_val.upper() in ("N/A", "-", "NULL", "NONE"):
                continue

            # 1. 优先匹配带 AS 前缀的编号 (如 AS210644, AS906)
            m_a = re.search(r"\b(AS\d+)\b", p_val, re.IGNORECASE)
            if m_a and not asn:
                asn = m_a.group(1).upper()
                continue

            # 2. 匹配纯数字 ASN (如 210644, 212336，扫描器常省略 AS 前缀)
            if p_val.isdigit() and not asn:
                val_int = int(p_val)
                if 1 <= val_int <= 4294967295:
                    asn = f"AS{val_int}"
                    continue

            # 3. 匹配机房位置字段 (如 HKG (中国-香港), FRA (德国-法兰克福))
            if "(" in p_val and ")" in p_val and not colo_loc:
                colo_loc = p_val
                continue

            # 4. 识别 ISP 运营商名称 (排除 IPv6、机房位置括号、纯数字及短国家码)
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

        colo = ""
        loc = colo_loc
        m = re.match(r"^([A-Z]{3})\s*\((.*?)\)", colo_loc)
        if m:
            colo = m.group(1)
            loc = m.group(2)

        tls = "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false"

        results.append({
            "ip": ip,
            "port": str(port),
            "tls": tls,
            "delay_ms": "",
            "speed_kbs": "",
            "colo": colo,
            "cf_location": loc,
            "isp": isp,
            "asn": asn,
            "tested_at": dt_str,
            "channel": default_channel,
            "fail_count": 0,
        })
    return results


def parse_proxy_attachment_content(text: str) -> list[tuple[str, str]]:
    """解析频道代理附件内容 (如 http_proxies.txt, https_proxies.txt, turn_proxies.txt 等)"""
    results = []
    seen = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # 1. 优先匹配行首标准代理格式（提取最真实的认证与节点信息，忽略后续 PTR 别名和中文评注）
        m = re.match(
            r"^(?P<url>(?P<proto>socks5|http|https|turn)://(?:[^\s#@]+@[^@\s#]+@|[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
            line,
            re.IGNORECASE,
        )
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
        m_any = re.search(
            r"(?P<url>(?P<proto>socks5|http|https|turn)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))",
            line,
            re.IGNORECASE,
        )
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
        m_raw = re.match(r"^((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(\d{1,5})(?:@([a-zA-Z0-9]+))?", line)
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
