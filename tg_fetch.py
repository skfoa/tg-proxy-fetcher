#!/usr/bin/env python3
"""
TG 频道代理与 Cloudflare 优选 IP 同步工具
核心特性：
1. 【永久增量持久化】：历史抓取到的节点与优选 IP 全量保留，只增不减，绝不草率淘汰！
2. 【智能更新去重】：同一 host:port 或 ip:port 再次出现时，自动以最新配置与测速数据覆盖刷新。
3. 【双模驱动】：
   - 免登录 Web 模式（默认）：直接抓取公开频道预览，无需任何 Telegram API 密钥或账号登录。
   - 官方 API 模式（可选）：配置 TG_API_ID / TG_SESSION_STR 后自动启用 Telethon MTProto 客户端。
"""

import os
import time
import re
import csv
import sys
import json
import html
import shutil
import logging
import asyncio
import subprocess
import urllib.request
from collections import defaultdict
from urllib.parse import parse_qs
from datetime import datetime, timedelta, timezone

# Windows 事件循环策略
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

START_TIME = time.time()

# ================= 配置区域 =================
TG_API_ID = os.getenv("TG_API_ID") or ""
TG_API_HASH = os.getenv("TG_API_HASH") or ""
TG_SESSION_STR = os.getenv("TG_SESSION_STR") or ""
FETCH_DAYS = int(os.getenv("FETCH_DAYS") or "3")
PROXY = os.getenv("PROXY") or os.getenv("ALL_PROXY") or os.getenv("HTTPS_PROXY") or ""

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""

PROXY_CHANNELS = ["@otcfxq"]
CF_IP_CHANNELS = ["@otcfxq", "@danfeng2"]

OUTPUT_PROXY_FILE = "socks5.txt"
OUTPUT_CF_FILE = "cf_ips.csv"
OUTPUT_CF_TXT = "cf_ips.txt"

# 扫描文件/附件提取的批量优选 IP 独立保存文件（与单条 IP 隔离，按 ASN 分组）
OUTPUT_SCAN_FILE = "scan_ips.csv"
OUTPUT_SCAN_TXT = "scan_ips.txt"
OUTPUT_SCAN_DIR = "scan_ips"

# 反代 ProxyIP 专属保存文件（独立反代池，供 edgetunnel / Workers 等使用）
OUTPUT_PROXYIP_FILE = "proxyip.csv"
OUTPUT_PROXYIP_TXT = "proxyip.txt"
# ============================================

ANNOUNCE_PROXY_RE = re.compile(
    r"\[发现开放\s*(?P<proto>HTTP|SOCKS5|SOCKS4|HTTPS|TURN)\s*(?:代理|服务)?\]\s*(?:(?:https?|socks5|socks4|turn)://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
)
TG_SOCKS_RE = re.compile(
    r"(?:tg://socks|https?://(?:t\.me|telegram\.me)/socks)\?(?P<query>[^\s#]+)"
)
PROXY_URL_RE = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turn)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))"
)

CF_CSV_FIELDS = [
    "ip",
    "port",
    "tls",
    "delay_ms",
    "speed_kbs",
    "colo",
    "cf_location",
    "isp",
    "asn",
    "tested_at",
    "channel",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("tg-fetch")


def get_system_proxy() -> str:
    """自动获取代理：优先环境变量，Windows 下自动探测系统代理"""
    if PROXY:
        return PROXY
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if enabled:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    if server:
                        if "10808" in server:
                            return f"socks5h://{server}"
                        elif not server.startswith("http"):
                            return f"http://{server}"
                        return server
        except Exception:
            pass
    return ""


def is_valid_host(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    if len(parts) >= 2 and parts[-1].isalpha() and len(parts[-1]) >= 2:
        return all(bool(re.match(r"^[a-zA-Z0-9-]+$", part)) for part in parts)
    return False


def extract_proxies(text: str) -> list:
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
    }


KNOWN_CLOUD_PROVIDERS = {
    # 头部公有云与 CDN 服务
    "cloudflare": ("AS13335", "Cloudflare"),
    "cf": ("AS13335", "Cloudflare"),
    "fastly": ("AS54113", "Fastly"),
    "aliyun": ("AS45102", "Alibaba Cloud"),
    "alibaba": ("AS45102", "Alibaba Cloud"),
    "alicloud": ("AS45102", "Alibaba Cloud"),
    "tencent": ("AS132203", "Tencent Cloud"),
    "qcloud": ("AS132203", "Tencent Cloud"),
    "hwcloud": ("AS136907", "Huawei Cloud"),
    "huawei": ("AS136907", "Huawei Cloud"),
    "huaweicloud": ("AS136907", "Huawei Cloud"),
    "ucloud": ("AS138915", "UCloud"),
    "baidu": ("AS38365", "Baidu Cloud"),
    "bce": ("AS38365", "Baidu Cloud"),
    "volcengine": ("AS138699", "ByteDance Volcengine"),
    "bytedance": ("AS138699", "ByteDance Volcengine"),
    "jdcloud": ("AS44907", "JD Cloud"),
    "jcloud": ("AS44907", "JD Cloud"),
    "ksyun": ("AS45062", "Kingsoft Cloud"),
    "kingsoft": ("AS45062", "Kingsoft Cloud"),
    "qiniu": ("AS136907", "Qiniu Cloud"),

    # 国际主流公有云
    "aws": ("AS16509", "Amazon AWS"),
    "amazon": ("AS16509", "Amazon AWS"),
    "lightsail": ("AS16509", "Amazon Lightsail"),
    "azure": ("AS8075", "Microsoft Azure"),
    "microsoft": ("AS8075", "Microsoft Azure"),
    "gcp": ("AS15169", "Google Cloud"),
    "google": ("AS15169", "Google Cloud"),
    "oracle": ("AS31898", "Oracle Cloud"),
    "oci": ("AS31898", "Oracle Cloud"),
    "digitalocean": ("AS14061", "DigitalOcean"),
    "vultr": ("AS20473", "Vultr"),
    "choopa": ("AS20473", "Vultr"),
    "linode": ("AS63949", "Linode Akamai"),
    "akamai": ("AS63949", "Linode Akamai"),
    "hetzner": ("AS24940", "Hetzner"),
    "ovh": ("AS16276", "OVH"),
    "scaleway": ("AS12876", "Scaleway"),
    "leaseweb": ("AS60781", "Leaseweb"),
    "kamatera": ("AS35838", "Kamatera"),

    # 热门 VPS / 优选反代服务商 (圈内高频出现)
    "akile": ("AS61112", "AkileCloud"),
    "akilecloud": ("AS61112", "AkileCloud"),
    "dmit": ("AS906", "DMIT"),
    "bandwagon": ("AS25820", "BandwagonHost"),
    "bwg": ("AS25820", "BandwagonHost"),
    "it7": ("AS25820", "BandwagonHost"),
    "claw": ("AS45102", "Claw Cloud"),
    "clawcloud": ("AS45102", "Claw Cloud"),
    "vmiss": ("AS147049", "VMISS"),
    "contabo": ("AS51167", "Contabo"),
    "netcup": ("AS197540", "Netcup"),
    "racknerd": ("AS36352", "RackNerd"),
    "buyvm": ("AS53667", "BuyVM FranTech"),
    "frantech": ("AS53667", "BuyVM FranTech"),
    "hostdare": ("AS397373", "HostDare"),
    "misaka": ("AS54600", "Misaka"),
    "kurun": ("AS13768", "Kurun Cloud"),
    "spartan": ("AS201106", "SpartanHost"),
    "spartanhost": ("AS201106", "SpartanHost"),
    "wap": ("AS149798", "WAP.ac"),
    "bagevm": ("AS14061", "BageVM"),
    "netlab": ("AS979", "NetLab"),
    "zenlayer": ("AS21859", "Zenlayer"),
    "hostinger": ("AS47583", "Hostinger"),
    "m247": ("AS9009", "M247"),
    "datacamp": ("AS60068", "Datacamp Limited"),
    "aeza": ("AS210644", "Aeza"),
    "bytevirt": ("AS212336", "ByteVirt"),
    "starry": ("AS134835", "Starry Network"),
    "cyberverse": ("AS216211", "Cyberverse"),
    "isif": ("AS209554", "ISIF"),

    # 运营商骨干与出海线路
    "hinet": ("AS3462", "Chunghwa Telecom HiNet"),
    "cmi": ("AS58453", "China Mobile CMI"),
    "chinamobile": ("AS58453", "China Mobile CMI"),
    "cug": ("AS10099", "China Unicom CUG"),
    "chinaunicom": ("AS10099", "China Unicom CUG"),
    "ctg": ("AS4134", "China Telecom CTG"),
    "chinatelecom": ("AS4134", "China Telecom 163"),
    "cn2": ("AS4809", "China Telecom CN2"),
    "9929": ("AS9929", "China Unicom 9929"),
    "cmin2": ("AS58807", "China Mobile CMIN2"),
}

# ASN 到标准服务商名称反查表
ASN_TO_PROVIDER = {}
for _k, (_asn, _isp) in KNOWN_CLOUD_PROVIDERS.items():
    if _asn not in ASN_TO_PROVIDER:
        ASN_TO_PROVIDER[_asn] = _isp


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
        else:
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


def get_telegram_download_dirs() -> list[str]:
    """获取常见 Telegram Desktop 下载目录，支持直接读取客户端已下载的测速与代理文件"""
    dirs = []
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Downloads", "Telegram Desktop"),
        os.path.join(home, "Documents", "Telegram Desktop"),
        r"C:\Users\ASUS\Downloads\Telegram Desktop",
        r"C:\Users\ASUS\Documents\Telegram Desktop",
        r"D:\Users\ASUS\Downloads\Telegram Desktop",
        r"D:\Users\ASUS\Documents\Telegram Desktop",
    ]
    for p in candidates:
        if os.path.isdir(p) and p not in dirs:
            dirs.append(p)
    return dirs


def load_local_import_proxies(import_dir: str = "import_proxies") -> dict:
    """扫描本地 import_proxies 目录、Telegram 下载目录或项目根目录下的各类代理 txt 文件并自动解析导入"""
    imported = {}
    files_to_check = set()

    scan_dirs = [import_dir] + get_telegram_download_dirs()
    for d in scan_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                fname_lower = fname.lower()
                if fname_lower.endswith(".txt") and (d == import_dir or any(k in fname_lower for k in ("proxy", "proxies", "http", "turn", "socks"))):
                    files_to_check.add(os.path.join(d, fname))

    for fname in os.listdir("."):
        fname_lower = fname.lower()
        if fname_lower.endswith(".txt") and not fname_lower.startswith("otc_scan") and any(k in fname_lower for k in ("proxy", "proxies", "http", "turn", "socks")):
            if fname not in (OUTPUT_PROXY_FILE, OUTPUT_CF_TXT, OUTPUT_SCAN_TXT):
                files_to_check.add(fname)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            items = parse_proxy_attachment_content(content)
            for url, key in items:
                imported[key] = url
            if items:
                log.info("从本地代理文件 %s 中导入 %d 个节点", fpath, len(items))
        except Exception as e:
            log.warning("读取本地代理文件 %s 失败: %s", fpath, e)

    return imported


def load_local_import_proxyips(import_dir: str = "import_proxyip") -> dict:
    """扫描本地 import_proxyip 目录、Telegram 下载目录或项目根目录下的 proxyip 文件（支持 .txt 与 .csv）并自动解析导入"""
    imported = {}
    files_to_check = set()

    scan_dirs = [import_dir] + get_telegram_download_dirs()
    for d in scan_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                fname_lower = fname.lower()
                if "proxyip" in fname_lower and (fname_lower.endswith(".txt") or fname_lower.endswith(".csv")):
                    files_to_check.add(os.path.join(d, fname))
                elif d == import_dir and (fname_lower.endswith(".txt") or fname_lower.endswith(".csv")):
                    files_to_check.add(os.path.join(d, fname))

    for fname in os.listdir("."):
        fname_lower = fname.lower()
        if "proxyip" in fname_lower and (fname_lower.endswith(".txt") or fname_lower.endswith(".csv")):
            if fname not in (OUTPUT_PROXYIP_FILE, OUTPUT_PROXYIP_TXT, OUTPUT_PROXY_FILE, OUTPUT_CF_TXT, OUTPUT_SCAN_TXT):
                files_to_check.add(fname)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), timezone.utc)
            mtime_bjt = mtime.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
            base_fname = os.path.basename(fpath)
            if base_fname.lower().endswith(".csv"):
                items = parse_cf_csv_content(content, default_channel="@danfeng2", filename=base_fname, dt_str=mtime_bjt)
            else:
                items = []
                m_port = re.search(r"proxyip[-_](\d{2,5})", base_fname, re.IGNORECASE)
                default_p = m_port.group(1) if m_port else "443"
                for line in content.splitlines():
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue
                    if ":" in line_s:
                        ip_p, port_p = line_s.split(":", 1)
                        if is_valid_host(ip_p) and port_p.isdigit() and 1 <= int(port_p) <= 65535:
                            items.append({
                                "ip": ip_p, "port": port_p, "tls": "true", "delay_ms": "", "speed_kbs": "",
                                "colo": "", "cf_location": "", "isp": "", "asn": "", "tested_at": mtime_bjt, "channel": "@danfeng2"
                            })
                    elif is_valid_host(line_s):
                        items.append({
                            "ip": line_s, "port": default_p, "tls": "true", "delay_ms": "", "speed_kbs": "",
                            "colo": "", "cf_location": "", "isp": "", "asn": "", "tested_at": mtime_bjt, "channel": "@danfeng2"
                        })
            for item in items:
                key = f"{item['ip']}:{item['port']}"
                imported[key] = item
            if items:
                log.info("从本地反代文件 %s 中导入 %d 条 ProxyIP 记录", fpath, len(items))
        except Exception as e:
            log.warning("读取本地反代文件 %s 失败: %s", fpath, e)

    return imported


def load_local_import_ips(import_dir: str = "import_ips") -> dict:
    """扫描本地 import_ips 目录、Telegram 下载目录或项目根目录下的优选测速文件（自动识别云厂商测速）并自动解析导入"""
    imported = {}
    files_to_check = set()

    # 1. 检查 import_ips 及 Telegram 客户端下载文件夹（自动过滤 proxyip 专属文件）
    scan_dirs = [import_dir] + get_telegram_download_dirs()
    for d in scan_dirs:
        if os.path.isdir(d):
            for fname in os.listdir(d):
                fname_lower = fname.lower()
                if "proxyip" in fname_lower:
                    continue
                if d == import_dir and (fname_lower.endswith(".txt") or fname_lower.endswith(".csv")):
                    files_to_check.add(os.path.join(d, fname))
                elif fname_lower.endswith(".csv") or (fname_lower.startswith("otc_scan") and fname_lower.endswith(".txt")):
                    # 识别来自 Telegram 下载的测速文件 (如 AS*.csv, OTC_SCAN*.txt, 或已知云厂商/VPS测速)
                    if fname_lower.startswith("as") or fname_lower.startswith("otc_scan") or any(k in fname_lower for k in KNOWN_CLOUD_PROVIDERS.keys()):
                        files_to_check.add(os.path.join(d, fname))

    # 2. 检查根目录下匹配的优选文件（如 OTC_SCAN*.txt、AS*.csv、云服务器测速 *.csv 等，过滤 proxyip 文件）
    for fname in os.listdir("."):
        fname_lower = fname.lower()
        if "proxyip" in fname_lower:
            continue
        if fname in (OUTPUT_CF_FILE, OUTPUT_SCAN_FILE, OUTPUT_PROXYIP_FILE, OUTPUT_CF_TXT, OUTPUT_SCAN_TXT, OUTPUT_PROXYIP_TXT, OUTPUT_PROXY_FILE):
            continue
        if (fname.startswith("OTC_SCAN") and fname_lower.endswith(".txt")) or \
           fname_lower.endswith(".csv"):
            files_to_check.add(fname)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), timezone.utc)
            mtime_bjt = mtime.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
            base_fname = os.path.basename(fpath)
            if base_fname.lower().endswith(".csv"):
                items = parse_cf_csv_content(content, default_channel="@danfeng2", filename=base_fname, dt_str=mtime_bjt)
            else:
                items = parse_otc_scan_content(content, default_channel="@otcfxq", filename=base_fname, dt_str=mtime_bjt)
            for item in items:
                key = f"{item['ip']}:{item['port']}"
                imported[key] = item
            if items:
                log.info("从本地优选文件 %s 中导入 %d 条优选 IP 记录", fpath, len(items))
        except Exception as e:
            log.warning("读取本地优选文件 %s 失败: %s", fpath, e)

    return imported


def load_existing_proxies(filepath: str = OUTPUT_PROXY_FILE) -> dict:
    """读取本地已保存的代理列表，保留历史累积节点（只增不减）"""
    existing = {}
    if not os.path.exists(filepath):
        return existing
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line_s = line.strip()
                if not line_s or line_s.startswith("#"):
                    continue
                for url, key in extract_proxies(line_s):
                    existing[key] = url
        log.info("已加载本地已存代理节点: %d 个（历史节点全部保留）", len(existing))
    except Exception as e:
        log.warning("读取已有代理文件失败: %s", e)
    return existing


def load_existing_cf_ips(filepath: str = OUTPUT_CF_FILE) -> dict:
    """读取本地已保存的优选 IP，保留历史累积数据（只增不减）"""
    existing = {}
    if not os.path.exists(filepath):
        return existing
    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip", "").strip()
                port = row.get("port", "").strip()
                if ip and port:
                    existing[f"{ip}:{port}"] = row
        log.info("已加载本地已存优选 IP 记录: %d 条（历史记录全部保留）", len(existing))
    except Exception as e:
        log.warning("读取已有优选 IP 文件失败: %s", e)
    return existing


def send_tg_notification(
    proxies_count: int,
    cf_ips_count: int,
    scan_ips_count: int = 0,
    asn_count: int = 0,
    proxyips_count: int = 0,
    new_proxies: int = 0,
    updated_proxies: int = 0,
    new_cf: int = 0,
    updated_cf: int = 0,
    new_scan: int = 0,
    updated_scan: int = 0,
    new_proxyips: int = 0,
    updated_proxyips: int = 0,
    top_providers: list = None,
    elapsed_seconds: float = 0.0,
):
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过机器人消息推送")
        return

    bjt = datetime.now(timezone(timedelta(hours=8)))
    date_str = bjt.strftime("%Y-%m-%d %H:%M:%S")

    def format_diff(new_c: int, upd_c: int) -> str:
        parts = []
        if new_c > 0:
            parts.append(f"🟢 <b>+{new_c}</b> 新增")
        if upd_c > 0:
            parts.append(f"🔄 {upd_c} 刷新")
        if not parts:
            return "保持最新"
        return " · ".join(parts)

    total_new = new_proxies + new_cf + new_scan + new_proxyips
    total_updated = updated_proxies + updated_cf + updated_scan + updated_proxyips

    if total_new > 0:
        header = f"🚀 <b>节点与优选 IP 同步完成</b> (🟢 发现 <b>+{total_new}</b> 条新数据)"
    elif total_updated > 0:
        header = f"🚀 <b>节点与优选 IP 同步完成</b> (🔄 刷新 {total_updated} 条数据)"
    else:
        header = "⚡ <b>节点与优选 IP 同步完成</b> (数据已全部为最新)"

    div = "━━━━━━━━━━━━━━━━━━━━"

    scan_line = ""
    if scan_ips_count > 0:
        asn_suffix = f" · {asn_count} 个 ASN" if asn_count > 0 else ""
        scan_diff = format_diff(new_scan, updated_scan)
        scan_line = f"📁 <b>扫描优选</b>：<code>{scan_ips_count}</code> 条 ({scan_diff}{asn_suffix})\n"
        if top_providers:
            prov_preview = ", ".join(top_providers[:4])
            if len(top_providers) > 4:
                prov_preview += " 等"
            scan_line += f"   └ <i>涵盖: {prov_preview}</i>\n"

    proxyip_line = ""
    if proxyips_count > 0:
        proxyip_diff = format_diff(new_proxyips, updated_proxyips)
        proxyip_line = f"🛡️ <b>反代 ProxyIP</b>：<code>{proxyips_count}</code> 条 ({proxyip_diff})\n"

    all_channels = []
    for ch in PROXY_CHANNELS + CF_IP_CHANNELS:
        if ch not in all_channels:
            all_channels.append(ch)
    channels_str = ", ".join(all_channels)

    # 识别 GitHub Actions 运行时环境链接
    github_server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_run_id = os.getenv("GITHUB_RUN_ID")
    github_run_number = os.getenv("GITHUB_RUN_NUMBER")

    footer_parts = []
    if elapsed_seconds > 0:
        footer_parts.append(f"⚡ <b>耗时</b>: {elapsed_seconds:.1f}s")
    if github_repo:
        repo_url = f"{github_server}/{github_repo}"
        if github_run_id:
            run_label = f"Action #{github_run_number}" if github_run_number else "Action 日志"
            footer_parts.append(f'🔗 <a href="{repo_url}/actions/runs/{github_run_id}">{run_label}</a>')
        footer_parts.append(f'📦 <a href="{repo_url}">产物仓库</a>')

    footer_line = f"\n{div}\n" + " · ".join(footer_parts) if footer_parts else ""

    message = (
        f"{header}\n"
        f"{div}\n"
        f"📅 <b>时间</b>：{date_str} (北京时间)\n"
        f"📫 <b>可用代理</b>：<code>{proxies_count}</code> 个 ({format_diff(new_proxies, updated_proxies)})\n"
        f"🌐 <b>单条优选</b>：<code>{cf_ips_count}</code> 条 ({format_diff(new_cf, updated_cf)})\n"
        f"{scan_line}"
        f"{proxyip_line}"
        f"📡 <b>频道来源</b>：{channels_str}"
        f"{footer_line}"
    )

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                log.info("TG 机器人通知发送成功")
            else:
                log.warning("TG 机器人通知发送失败: %s", data.get("description", "未知错误"))
    except Exception as e:
        log.warning("发送 TG 机器人通知网络异常: %s", e)


def fetch_web_page(url: str, proxy: str = "") -> str:
    """获取网页 HTML 内容，支持 curl 与 urllib.request 优雅降级"""
    if shutil.which("curl"):
        cmd = [
            "curl", "-sL",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        if proxy:
            cmd.extend(["-x", proxy])
        cmd.extend([url, "--max-time", "15"])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=20)
            if res.returncode == 0 and res.stdout:
                return res.stdout
        except Exception as e:
            log.debug("curl 请求失败: %s，降级至 urllib", e)

    handlers = []
    if proxy and not proxy.startswith("socks"):
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    )
    with opener.open(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def scrape_channel_web(channel: str, cutoff: datetime, proxy: str = "") -> tuple[list[tuple[str, str]], list[dict]]:
    clean_channel = channel.lstrip("@")
    base_url = f"https://t.me/s/{clean_channel}"
    
    proxies_found = []
    cf_ips_found = []
    
    url = base_url
    page_num = 1
    max_pages = 25

    while url and page_num <= max_pages:
        log.info("频道 %s 正在抓取第 %d 页: %s", channel, page_num, url)
        try:
            html_content = fetch_web_page(url, proxy=proxy)
        except Exception as e:
            log.warning("频道 %s 第 %d 页抓取网络错误: %s", channel, page_num, e)
            break

        if not html_content or "tgme_widget_message_wrap" not in html_content:
            log.warning("频道 %s 未获取到公开消息卡片（可能不支持 Web 预览或为群组/私密频道）", channel)
            break

        chunks = re.split(r'<div class="tgme_widget_message_wrap[^"]*"', html_content)[1:]
        if not chunks:
            break

        earliest_id = None
        reached_cutoff = False

        for chunk in reversed(chunks):
            p_m = re.search(r'data-post="([^"]+)"', chunk)
            if p_m:
                try:
                    m_id = int(p_m.group(1).split("/")[1])
                    if earliest_id is None or m_id < earliest_id:
                        earliest_id = m_id
                except Exception:
                    pass

            t_m = re.search(r'<time[^>]*datetime="([^"]+)"', chunk)
            dt = None
            if t_m:
                try:
                    dt = datetime.fromisoformat(t_m.group(1).replace("Z", "+00:00"))
                    if dt < cutoff:
                        reached_cutoff = True
                except Exception:
                    pass

            txt_m = re.search(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', chunk, re.DOTALL)
            if not txt_m:
                continue

            raw_text = txt_m.group(1)
            cleaned_text = re.sub(r'<br\s*/?>', '\n', raw_text)
            cleaned_text = re.sub(r'<[^>]+>', '', cleaned_text)
            cleaned_text = html.unescape(cleaned_text).strip()

            for p_url, key in extract_proxies(cleaned_text):
                proxies_found.append((p_url, key))

            cf_data = parse_cf_ip(cleaned_text, default_channel=channel)
            if cf_data:
                if not cf_data["tested_at"] and dt:
                    cf_data["tested_at"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                cf_ips_found.append(cf_data)

        if reached_cutoff or not earliest_id:
            log.info("频道 %s 已到达时间截止点 (%s)，停止向后翻页", channel, cutoff.strftime("%Y-%m-%d %H:%M:%S UTC"))
            break

        page_num += 1
        url = f"{base_url}?before={earliest_id}"

    return proxies_found, cf_ips_found


def save_and_notify(
    final_proxies: dict,
    final_cf_ips: dict,
    final_scan_ips: dict = None,
    final_proxyips: dict = None,
    new_proxies_count: int = 0,
    updated_proxies_count: int = 0,
    new_cf_count: int = 0,
    updated_cf_count: int = 0,
    new_scan_count: int = 0,
    updated_scan_count: int = 0,
    new_proxyips_count: int = 0,
    updated_proxyips_count: int = 0,
):
    # 1. 保存代理节点
    with open(OUTPUT_PROXY_FILE, "w", encoding="utf-8") as f:
        for node in final_proxies.values():
            f.write(node + "\n")
    log.info("已保存代理文件: %s (%d 个全量累积节点)", OUTPUT_PROXY_FILE, len(final_proxies))

    # 2. 保存单条优选 IP
    sorted_cf_ips = sorted(
        final_cf_ips.values(),
        key=lambda item: item.get("tested_at", ""),
        reverse=True,
    )
    with open(OUTPUT_CF_FILE, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS)
        writer.writeheader()
        for row in sorted_cf_ips:
            writer.writerow(row)
    log.info("已保存单条优选IP文件: %s (%d 条全量累积记录)", OUTPUT_CF_FILE, len(sorted_cf_ips))

    with open(OUTPUT_CF_TXT, "w", encoding="utf-8") as f:
        for row in sorted_cf_ips:
            f.write(f"{row['ip']}:{row['port']}\n")
    log.info("已保存单条优选IP纯文本: %s (%d 行 IP:Port)", OUTPUT_CF_TXT, len(sorted_cf_ips))

    # 3. 保存文件/扫描优选 IP（按 ASN 智能去重、分组归类与独立拆分）
    scan_ips_total = 0
    asn_groups_total = 0
    if final_scan_ips:
        os.makedirs(OUTPUT_SCAN_DIR, exist_ok=True)

        asn_groups = defaultdict(list)
        for row in final_scan_ips.values():
            raw_asn = (row.get("asn") or "").strip()
            m = re.search(r"(AS\d+)", raw_asn, re.IGNORECASE)
            if m:
                asn_clean = m.group(1).upper()
            else:
                asn_clean = ""
                r_low = (raw_asn + " " + (row.get("isp") or "")).lower()
                for k in sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True):
                    if k in r_low:
                        asn_clean, _ = KNOWN_CLOUD_PROVIDERS[k]
                        break
                if not asn_clean:
                    m_d = re.search(r"\b(\d{3,7})\b", raw_asn)
                    if m_d:
                        asn_clean = f"AS{m_d.group(1)}"
                    else:
                        asn_clean = "AS_UNKNOWN"
            row["asn"] = asn_clean
            asn_groups[asn_clean].append(row)

        asn_groups_total = len(asn_groups)

        all_sorted_scan_rows = []
        for asn_name in sorted(asn_groups.keys()):
            group_rows = sorted(asn_groups[asn_name], key=lambda x: x.get("tested_at", ""), reverse=True)
            all_sorted_scan_rows.extend(group_rows)

        with open(OUTPUT_SCAN_FILE, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS)
            writer.writeheader()
            for row in all_sorted_scan_rows:
                writer.writerow(row)
        log.info("已保存扫描优选IP表格: %s (%d 条全量累积记录)", OUTPUT_SCAN_FILE, len(all_sorted_scan_rows))

        with open(OUTPUT_SCAN_TXT, "w", encoding="utf-8") as f:
            for asn_name in sorted(asn_groups.keys()):
                group = asn_groups[asn_name]
                isp_name = ASN_TO_PROVIDER.get(asn_name, "")
                if not isp_name:
                    isp_name = next((r.get("isp") for r in group if r.get("isp")), "")
                header = f"# {asn_name}" + (f" ({isp_name})" if isp_name else "") + f" - {len(group)} 个"
                f.write(f"{header}\n")
                for r in sorted(group, key=lambda x: (x.get("ip", ""), int(x.get("port", 0)))):
                    f.write(f"{r['ip']}:{r['port']}\n")
                f.write("\n")
        log.info("已保存扫描优选IP汇总文本: %s (共 %d 个 ASN 分组，%d 行 IP:Port)", OUTPUT_SCAN_TXT, asn_groups_total, len(all_sorted_scan_rows))

        active_files = set()
        for asn_name, group in asn_groups.items():
            isp_name = ASN_TO_PROVIDER.get(asn_name, "")
            if not isp_name:
                isp_name = next((r.get("isp") for r in group if r.get("isp")), "")
            clean_isp = re.sub(r'[^a-zA-Z0-9]', '', isp_name) if isp_name else ""
            fname = f"{asn_name}_{clean_isp}.txt" if clean_isp else f"{asn_name}.txt"
            asn_file = os.path.join(OUTPUT_SCAN_DIR, fname)
            with open(asn_file, "w", encoding="utf-8") as f:
                for r in sorted(group, key=lambda x: (x.get("ip", ""), int(x.get("port", 0)))):
                    f.write(f"{r['ip']}:{r['port']}\n")
            active_files.add(fname)

        # 清理已不存在或旧命名格式的分组文件
        for old_f in os.listdir(OUTPUT_SCAN_DIR):
            if old_f.endswith(".txt") and old_f not in active_files:
                try:
                    os.remove(os.path.join(OUTPUT_SCAN_DIR, old_f))
                except OSError:
                    pass
        log.info("已在 %s/ 目录下生成 %d 个独立 ASN 纯文本列表", OUTPUT_SCAN_DIR, len(active_files))

        scan_ips_total = len(all_sorted_scan_rows)

    # 4. 保存反代 ProxyIP 独立池
    proxyip_total = 0
    if final_proxyips:
        sorted_proxyips = sorted(
            final_proxyips.values(),
            key=lambda x: (x.get("tested_at", ""), -int(x.get("delay_ms") or 99999)),
            reverse=True,
        )
        with open(OUTPUT_PROXYIP_FILE, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS)
            writer.writeheader()
            for row in sorted_proxyips:
                writer.writerow(row)
        log.info("已保存反代 ProxyIP 表格: %s (%d 条全量累积记录)", OUTPUT_PROXYIP_FILE, len(sorted_proxyips))

        with open(OUTPUT_PROXYIP_TXT, "w", encoding="utf-8") as f:
            for row in sorted_proxyips:
                f.write(f"{row['ip']}:{row['port']}\n")
        log.info("已保存反代 ProxyIP 纯文本: %s (%d 行 IP:Port)", OUTPUT_PROXYIP_TXT, len(sorted_proxyips))

        proxyip_total = len(sorted_proxyips)

    top_providers = []
    if final_scan_ips and 'asn_groups' in locals() and asn_groups:
        sorted_groups = sorted(asn_groups.items(), key=lambda item: len(item[1]), reverse=True)
        seen_names = set()
        for asn_name, group in sorted_groups:
            isp_name = ASN_TO_PROVIDER.get(asn_name, "")
            if not isp_name:
                isp_name = next((r.get("isp") for r in group if r.get("isp")), "")
            raw_name = isp_name if isp_name else asn_name
            clean_name = re.sub(r'\b(LLC|Inc|Limited|Ltd|OU|GmbH|Co)\b\.?', '', raw_name, flags=re.IGNORECASE).strip()
            name = clean_name if clean_name else raw_name
            if name and name not in seen_names:
                seen_names.add(name)
                top_providers.append(name)

    elapsed_sec = time.time() - START_TIME if 'START_TIME' in globals() else 0.0

    send_tg_notification(
        len(final_proxies),
        len(sorted_cf_ips),
        scan_ips_count=scan_ips_total,
        asn_count=asn_groups_total,
        proxyips_count=proxyip_total,
        new_proxies=new_proxies_count,
        updated_proxies=updated_proxies_count,
        new_cf=new_cf_count,
        updated_cf=updated_cf_count,
        new_scan=new_scan_count,
        updated_scan=updated_scan_count,
        new_proxyips=new_proxyips_count,
        updated_proxyips=updated_proxyips_count,
        top_providers=top_providers,
        elapsed_seconds=elapsed_sec,
    )

    log.info("=" * 50)
    log.info("抓取、增量合并、保存与通知任务全部顺利完成！")


def run_web_scraper():
    log.info("=" * 50)
    log.info("模式: 【免登录 Web 抓取模式】（公开 Web 频道预览，无需 API ID / 会话密钥）")
    log.info("本次增量回溯: 最近 %d 天", FETCH_DAYS)
    log.info("代理抓取频道: %s", ", ".join(PROXY_CHANNELS))
    log.info("优选 IP 抓取频道: %s", ", ".join(CF_IP_CHANNELS))
    
    proxy = get_system_proxy()
    if proxy:
        log.info("网络连接: 本地代理 (%s)", proxy)
    else:
        log.info("网络连接: 直连 (Direct)")

    # 1. 预先加载本地已保存的历史节点（永久保留，单条、扫描与反代独立存放）
    existing_proxies = load_existing_proxies(OUTPUT_PROXY_FILE)
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE)
    existing_scan_ips = load_existing_cf_ips(OUTPUT_SCAN_FILE)
    existing_proxyips = load_existing_cf_ips(OUTPUT_PROXYIP_FILE)

    cutoff = datetime.now(timezone.utc) - timedelta(days=FETCH_DAYS)
    all_channels = sorted(list(set(PROXY_CHANNELS + CF_IP_CHANNELS)))

    scraped_proxies = {}
    scraped_cf_ips = {}

    for channel in all_channels:
        is_proxy_target = channel in PROXY_CHANNELS
        is_cf_target = channel in CF_IP_CHANNELS

        log.info("-" * 50)
        log.info("开始处理频道: %s (代理: %s, 优选IP: %s)", channel, is_proxy_target, is_cf_target)

        raw_proxies, raw_cf_ips = scrape_channel_web(channel, cutoff, proxy=proxy)

        if is_proxy_target:
            p_cnt = 0
            for url, key in raw_proxies:
                if key not in scraped_proxies:
                    scraped_proxies[key] = url
                    p_cnt += 1
            log.info("频道 %s 提取去重代理节点: %d 个", channel, p_cnt)

        if is_cf_target:
            cf_cnt = 0
            for item in raw_cf_ips:
                key = f"{item['ip']}:{item['port']}"
                if key not in scraped_cf_ips:
                    scraped_cf_ips[key] = item
                    cf_cnt += 1
            log.info("频道 %s 提取单条优选 IP: %d 条", channel, cf_cnt)

    # 1.4 加载本地代理待导入文件（若有 http/https/turn/socks 等代理 txt）
    local_imported_proxies = load_local_import_proxies()
    for k, v in local_imported_proxies.items():
        if k not in scraped_proxies:
            scraped_proxies[k] = v

    # 1.5 加载本地待导入文件（若有 OTC_SCAN*.txt 或 AS*.csv 等，放入独立扫描 IP 集合）
    scraped_scan_ips = load_local_import_ips()

    # 1.6 加载本地反代待导入文件（若有 Global-proxyip*.csv 等，放入独立 ProxyIP 集合）
    scraped_proxyips = load_local_import_proxyips()

    # 2. 智能增量合并：历史保留，重复更新，新增追加
    new_proxy_cnt = sum(1 for k in scraped_proxies if k not in existing_proxies)
    updated_proxy_cnt = sum(1 for k in scraped_proxies if k in existing_proxies)
    
    new_cf_cnt = sum(1 for k in scraped_cf_ips if k not in existing_cf_ips)
    updated_cf_cnt = sum(1 for k in scraped_cf_ips if k in existing_cf_ips)

    new_scan_cnt = sum(1 for k in scraped_scan_ips if k not in existing_scan_ips)
    updated_scan_cnt = sum(1 for k in scraped_scan_ips if k in existing_scan_ips)

    new_proxyip_cnt = sum(1 for k in scraped_proxyips if k not in existing_proxyips)
    updated_proxyip_cnt = sum(1 for k in scraped_proxyips if k in existing_proxyips)

    final_proxies = {**existing_proxies, **scraped_proxies}
    final_cf_ips = {**existing_cf_ips, **scraped_cf_ips}
    final_scan_ips = {**existing_scan_ips, **scraped_scan_ips}
    final_proxyips = {**existing_proxyips, **scraped_proxyips}

    log.info("=" * 50)
    log.info("代理节点增量合并: 历史保留 %d 个, 本次新增 %d 个, 本次更新 %d 个 -> 全量总计 %d 个", 
             len(existing_proxies) - updated_proxy_cnt, new_proxy_cnt, updated_proxy_cnt, len(final_proxies))
    log.info("单条优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
             len(existing_cf_ips) - updated_cf_cnt, new_cf_cnt, updated_cf_cnt, len(final_cf_ips))
    if final_scan_ips:
        log.info("扫描优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                 len(existing_scan_ips) - updated_scan_cnt, new_scan_cnt, updated_scan_cnt, len(final_scan_ips))
    if final_proxyips:
        log.info("反代 ProxyIP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                 len(existing_proxyips) - updated_proxyip_cnt, new_proxyip_cnt, updated_proxyip_cnt, len(final_proxyips))

    save_and_notify(
        final_proxies,
        final_cf_ips,
        final_scan_ips=final_scan_ips,
        final_proxyips=final_proxyips,
        new_proxies_count=new_proxy_cnt,
        updated_proxies_count=updated_proxy_cnt,
        new_cf_count=new_cf_cnt,
        updated_cf_count=updated_cf_cnt,
        new_scan_count=new_scan_cnt,
        updated_scan_count=updated_scan_cnt,
        new_proxyips_count=new_proxyip_cnt,
        updated_proxyips_count=updated_proxyip_cnt,
    )

async def run_telethon():
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.errors import FloodWaitError

    log.info("=" * 50)
    log.info("模式: 【Telegram 官方 API 模式】（Telethon MTProto）")
    log.info("本次增量回溯: 最近 %d 天", FETCH_DAYS)
    log.info("代理抓取频道: %s", ", ".join(PROXY_CHANNELS))
    log.info("优选 IP 抓取频道: %s", ", ".join(CF_IP_CHANNELS))

    # 1. 预先加载本地已保存的历史节点（永久保留，单条、扫描与反代独立存放）
    existing_proxies = load_existing_proxies(OUTPUT_PROXY_FILE)
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE)
    existing_scan_ips = load_existing_cf_ips(OUTPUT_SCAN_FILE)
    existing_proxyips = load_existing_cf_ips(OUTPUT_PROXYIP_FILE)

    client = TelegramClient(
        StringSession(TG_SESSION_STR), int(TG_API_ID), TG_API_HASH
    )

    all_channels = sorted(list(set(PROXY_CHANNELS + CF_IP_CHANNELS)))
    scraped_proxies = {}
    scraped_cf_ips = {}
    scraped_scan_ips = {}
    scraped_proxyips = {}

    try:
        await client.connect()
        if not await client.is_user_authorized():
            log.error("TG 会话已失效，请更新 TG_SESSION_STR")
            sys.exit(1)

        cutoff = datetime.now(timezone.utc) - timedelta(days=FETCH_DAYS)

        for channel_name in all_channels:
            is_proxy_target = channel_name in PROXY_CHANNELS
            is_cf_target = channel_name in CF_IP_CHANNELS

            log.info("-" * 50)
            log.info("开始处理频道: %s (代理: %s, 优选IP: %s)", channel_name, is_proxy_target, is_cf_target)

            try:
                entity = await client.get_entity(channel_name)
                channel_title = getattr(entity, "title", channel_name)
                log.info("已成功连接频道: %s (%s)", channel_title, channel_name)
            except Exception as e:
                log.warning("无法获取频道 %s 的实体信息: %s，跳过该频道", channel_name, e)
                continue

            msg_count = 0
            proxy_count = 0
            cf_count = 0
            scan_count = 0
            proxyip_count = 0

            try:
                async for msg in client.iter_messages(entity):
                    msg_count += 1
                    if msg.date and msg.date < cutoff:
                        log.info("已到达时间截止点 (%s)，终止该频道扫描", cutoff.strftime("%Y-%m-%d %H:%M:%S UTC"))
                        break

                    # 提取代理（包含 socks5, http, https, turn, 通报格式, 以及 tg://socks 直连链接）
                    if is_proxy_target:
                        if msg.text:
                            for url, key in extract_proxies(msg.text):
                                if key not in scraped_proxies:
                                    scraped_proxies[key] = url
                                    proxy_count += 1

                        # 支持自动下载并解析代理文件附件 (如 http_proxies.txt, https_proxies.txt, turn_proxies.txt 等)
                        if msg.file and msg.file.name and msg.file.name.lower().endswith(".txt"):
                            fname_lower = msg.file.name.lower()
                            if not fname_lower.startswith("otc_scan") and any(k in fname_lower for k in ("proxy", "proxies", "http", "turn", "socks")):
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_proxies = parse_proxy_attachment_content(doc_text)
                                        doc_added = 0
                                        for url, key in doc_proxies:
                                            if key not in scraped_proxies:
                                                scraped_proxies[key] = url
                                                proxy_count += 1
                                                doc_added += 1
                                        log.info("从频道 %s 附件 %s 中提取 %d 个代理节点", channel_name, msg.file.name, doc_added)
                                except Exception as e:
                                    log.warning("下载/解析频道 %s 代理附件 %s 失败: %s", channel_name, msg.file.name, e)

                    if is_cf_target:
                        if msg.text:
                            cf_data = parse_cf_ip(msg.text, default_channel=channel_name)
                            if cf_data:
                                cf_key = f"{cf_data['ip']}:{cf_data['port']}"
                                if cf_key not in scraped_cf_ips:
                                    if not cf_data["tested_at"] and msg.date:
                                        cf_data["tested_at"] = msg.date.strftime("%Y-%m-%d %H:%M:%S")
                                    scraped_cf_ips[cf_key] = cf_data
                                    cf_count += 1

                        # 支持自动下载并解析优选扫描附件与反代 ProxyIP 附件 (独立归入各自集合)
                        if msg.file and msg.file.name:
                            fname_lower = msg.file.name.lower()
                            # 1. 反代 ProxyIP 文件 (如 Global-proxyip-443.csv, Global-proxyip-8443.csv 等)
                            if "proxyip" in fname_lower and (fname_lower.endswith(".csv") or fname_lower.endswith(".txt")):
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_date_str = msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_cf_csv_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if cf_key not in scraped_proxyips:
                                                scraped_proxyips[cf_key] = cf_item
                                                proxyip_count += 1
                                                doc_added += 1
                                        log.info("从频道 %s ProxyIP 附件 %s 中提取 %d 条反代 IP", channel_name, msg.file.name, doc_added)
                                except Exception as e:
                                    log.warning("下载/解析频道 %s ProxyIP 附件 %s 失败: %s", channel_name, msg.file.name, e)
                            # 2. 扫描优选 CSV (如 DanFeng AS45102_*.csv)
                            elif fname_lower.endswith(".csv"):
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_date_str = msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_cf_csv_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if cf_key not in scraped_scan_ips:
                                                scraped_scan_ips[cf_key] = cf_item
                                                scan_count += 1
                                                doc_added += 1
                                        log.info("从频道 %s CSV 附件 %s 中提取 %d 条扫描优选 IP", channel_name, msg.file.name, doc_added)
                                except Exception as e:
                                    log.warning("下载/解析频道 %s CSV 附件 %s 失败: %s", channel_name, msg.file.name, e)
                            # 3. 扫描优选 TXT (如 OTC_SCAN_YX_*.txt)
                            elif fname_lower.endswith(".txt") and "otc_scan" in fname_lower:
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_date_str = msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_otc_scan_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if cf_key not in scraped_scan_ips:
                                                scraped_scan_ips[cf_key] = cf_item
                                                scan_count += 1
                                                doc_added += 1
                                        log.info("从频道 %s TXT 附件 %s 中提取 %d 条扫描优选 IP", channel_name, msg.file.name, doc_added)
                                except Exception as e:
                                    log.warning("下载/解析频道 %s TXT 附件 %s 失败: %s", channel_name, msg.file.name, e)
            except FloodWaitError as e:
                log.warning("频道 %s 扫描时触发 Telegram 频控限制 (等待 %d 秒): %s", channel_name, e.seconds, e)

            log.info("频道 %s 扫描完毕: 消息 %d 条, 新增代理 %d 个, 单条优选IP %d 个, 扫描优选IP %d 个, 反代ProxyIP %d 个", 
                     channel_name, msg_count, proxy_count, cf_count, scan_count, proxyip_count)

        # 1.4 加载本地代理待导入文件（若有 http/https/turn/socks 等代理 txt）
        local_imported_proxies = load_local_import_proxies()
        for k, v in local_imported_proxies.items():
            if k not in scraped_proxies:
                scraped_proxies[k] = v

        # 1.5 加载本地待导入文件（若有 OTC_SCAN*.txt 或 AS*.csv 等，放入独立扫描 IP 集合）
        local_imported_ips = load_local_import_ips()
        if local_imported_ips:
            scraped_scan_ips = {**scraped_scan_ips, **local_imported_ips}

        # 1.6 加载本地反代待导入文件（若有 Global-proxyip*.csv 等，放入独立 ProxyIP 集合）
        local_imported_proxyips = load_local_import_proxyips()
        if local_imported_proxyips:
            scraped_proxyips = {**scraped_proxyips, **local_imported_proxyips}

        # 2. 智能增量合并
        new_proxy_cnt = sum(1 for k in scraped_proxies if k not in existing_proxies)
        updated_proxy_cnt = sum(1 for k in scraped_proxies if k in existing_proxies)
        
        new_cf_cnt = sum(1 for k in scraped_cf_ips if k not in existing_cf_ips)
        updated_cf_cnt = sum(1 for k in scraped_cf_ips if k in existing_cf_ips)

        new_scan_cnt = sum(1 for k in scraped_scan_ips if k not in existing_scan_ips)
        updated_scan_cnt = sum(1 for k in scraped_scan_ips if k in existing_scan_ips)

        new_proxyip_cnt = sum(1 for k in scraped_proxyips if k not in existing_proxyips)
        updated_proxyip_cnt = sum(1 for k in scraped_proxyips if k in existing_proxyips)

        final_proxies = {**existing_proxies, **scraped_proxies}
        final_cf_ips = {**existing_cf_ips, **scraped_cf_ips}
        final_scan_ips = {**existing_scan_ips, **scraped_scan_ips}
        final_proxyips = {**existing_proxyips, **scraped_proxyips}

        log.info("=" * 50)
        log.info("代理节点增量合并: 历史保留 %d 个, 本次新增 %d 个, 本次更新 %d 个 -> 全量总计 %d 个", 
                 len(existing_proxies) - updated_proxy_cnt, new_proxy_cnt, updated_proxy_cnt, len(final_proxies))
        log.info("单条优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                 len(existing_cf_ips) - updated_cf_cnt, new_cf_cnt, updated_cf_cnt, len(final_cf_ips))
        if final_scan_ips:
            log.info("扫描优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                     len(existing_scan_ips) - updated_scan_cnt, new_scan_cnt, updated_scan_cnt, len(final_scan_ips))
        if final_proxyips:
            log.info("反代 ProxyIP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                     len(existing_proxyips) - updated_proxyip_cnt, new_proxyip_cnt, updated_proxyip_cnt, len(final_proxyips))

        save_and_notify(
            final_proxies,
            final_cf_ips,
            final_scan_ips=final_scan_ips,
            final_proxyips=final_proxyips,
            new_proxies_count=new_proxy_cnt,
            updated_proxies_count=updated_proxy_cnt,
            new_cf_count=new_cf_cnt,
            updated_cf_count=updated_cf_cnt,
            new_scan_count=new_scan_cnt,
            updated_scan_count=updated_scan_cnt,
            new_proxyips_count=new_proxyip_cnt,
            updated_proxyips_count=updated_proxyip_cnt,
        )

    finally:
        await client.disconnect()

def main():
    if TG_API_ID and TG_API_HASH and TG_SESSION_STR:
        try:
            import telethon
            asyncio.run(run_telethon())
            return
        except ImportError:
            log.warning("检测到已配置 TG_API 凭据，但当前 Python 环境未安装 telethon，自动降级为【免登录 Web 模式】")

    run_web_scraper()


if __name__ == "__main__":
    main()
