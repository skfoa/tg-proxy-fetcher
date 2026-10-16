#!/usr/bin/env python3
"""
TG 频道代理与 Cloudflare 优选 IP 同步工具 (tg_fetch.py)

核心特性：
  1. 【增量持久化】：历史抓取的有效节点与优选 IP 全量保留并自动去重，交由后续质检引擎执行缓冲淘汰。
  2. 【时效覆盖刷新】：同一 host:port 或 ip:port 再次出现时，自动以最新配置与测速数据覆盖刷新。
  3. 【双模驱动架构】：
     - 免登录 Web 模式（默认）：直接抓取公开频道网页预览，无需任何 Telegram API 密钥或账号登录。
     - 官方 API 模式（可选）：配置 TG_API_ID / TG_SESSION_STR 后激活 Telethon MTProto 客户端，解锁频道测速附件与反代池附件自动下载。
  4. 【未收录 ASN 动态发现（模式 A）】：
     自动巡检本次新增节点，遇未在权威对照表中收录的新自治系统时，动态生成 Telegram 卡片提醒并支持一键入库。
"""

from __future__ import annotations

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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
TZ_BJT = timezone(timedelta(hours=8))

# ================= 配置区域 =================
import providers
from providers import (
    load_dotenv,
    safe_int,
    clean_asn,
    format_asn_isp,
    send_tg_message,
    ASN_TO_PROVIDER,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    format_proxyip_txt,
    format_scan_ips_txt,
    format_proxies_txt,
    save_proxyip_by_country,
    save_proxies_by_protocol,
    save_proxies_csv,
    save_scan_ips_by_asn,
    format_diff,
    classify_asn,
    is_asn_recorded,
    _extract_asn_code,
    normalize_timestamp,
    load_tombstone,
    prune_tombstone,
    is_tombstoned,
    LEGACY_DEFAULT_FIRST_SEEN,
    AUTHORITATIVE_CLOUD_ASNS,
    load_asn_database,
    save_asn_database,
    resolve_asn_online,
    atomic_writer,
    atomic_write_text,
    atomic_write_json,
)
from parsers import (
    extract_proxies,
    parse_cf_ip,
    parse_cf_csv_content,
    parse_otc_scan_content,
    parse_proxy_attachment_content,
    is_valid_host,
)

# 确保本地 .env 加载
load_dotenv()

TG_API_ID = os.getenv("TG_API_ID") or ""
TG_API_HASH = os.getenv("TG_API_HASH") or ""
TG_SESSION_STR = os.getenv("TG_SESSION_STR") or ""
FETCH_DAYS = int(os.getenv("FETCH_DAYS") or "3")
PROXY = os.getenv("PROXY") or os.getenv("ALL_PROXY") or os.getenv("HTTPS_PROXY") or ""

def _parse_channels(env_name: str, default: list[str]) -> list[str]:
    """
    解析环境变量中的频道列表。
    向后兼容说明：若专属变量（如 PROXY_CHANNELS / CF_IP_CHANNELS）未配置，
    将自动回退至全局 CHANNELS 环境变量；若仍未配置，则使用内置 default 列表。
    """
    raw_val = (os.getenv(env_name) or "").strip()
    if not raw_val and env_name in ("PROXY_CHANNELS", "CF_IP_CHANNELS"):
        raw_val = (os.getenv("CHANNELS") or "").strip()
    if not raw_val:
        return default
    channels = []
    for item in re.split(r"[,;\s]+", raw_val):
        item = item.strip()
        if not item:
            continue
        # 兼容处理各种频道链接形态：https://t.me/s/xxx, https://t.me/xxx, t.me/xxx, @xxx, xxx (L3)
        m = re.match(r"^(?:https?://)?(?:t\.me/)?(?:s/)?@?([A-Za-z0-9_]+)/?$", item)
        if m:
            item = f"@{m.group(1)}"
        elif not item.startswith("@") and not item.startswith("https://"):
            item = f"@{item}"
        if item not in channels:
            channels.append(item)
    return channels if channels else default


PROXY_CHANNELS = _parse_channels("PROXY_CHANNELS", ["@otcfxq", "@danfeng_chat"])
CF_IP_CHANNELS = _parse_channels("CF_IP_CHANNELS", ["@otcfxq", "@danfeng_chat"])

DEFAULT_SUB_URLS = [
    "https://sub.cmliussss.net/vpngate",
]


def _parse_sub_urls() -> list[str]:
    raw_val = (os.getenv("SUB_URLS") or "").strip()
    if raw_val.lower() in ("none", "off", "disable", "false", "0"):
        return []
    if not raw_val:
        return list(DEFAULT_SUB_URLS)
    urls = []
    for item in re.split(r"[,;\s]+", raw_val):
        item = item.strip()
        if item and item.startswith("http"):
            urls.append(item)
    return urls if urls else list(DEFAULT_SUB_URLS)


SUB_URLS = _parse_sub_urls()

DEFAULT_EDT_PROXY_URLS = {
    "https": [
        "https://github.090227.xyz/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json",
        "https://github.cmliussss.net/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json",
        "https://github.cmliussss.com/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json",
        "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json",
    ],
    "http": [
        "https://github.090227.xyz/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json",
        "https://github.cmliussss.net/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json",
        "https://github.cmliussss.com/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json",
        "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json",
    ],
    "socks5": [
        "https://github.090227.xyz/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json",
        "https://github.cmliussss.net/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json",
        "https://github.cmliussss.com/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json",
        "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json",
    ],
}

DEFAULT_EDT_HTTPS_URLS = DEFAULT_EDT_PROXY_URLS["https"]
DEFAULT_EDT_HTTP_URLS = DEFAULT_EDT_PROXY_URLS["http"]
DEFAULT_EDT_SOCKS5_URLS = DEFAULT_EDT_PROXY_URLS["socks5"]


def _parse_edt_mirrors() -> list[str]:
    """从环境变量解析用户配置的镜像加速前缀列表（支持 EDT_MIRRORS / GITHUB_MIRRORS）"""
    raw_val = (os.getenv("EDT_MIRRORS") or os.getenv("GITHUB_MIRRORS") or "").strip()
    if not raw_val or raw_val.lower() in ("none", "off", "disable", "false", "0"):
        return []
    mirrors = []
    for item in re.split(r"[,;\s]+", raw_val):
        item = item.strip().rstrip("/")
        if item and (item.startswith("http://") or item.startswith("https://")):
            mirrors.append(item)
    return mirrors


def _parse_edt_urls_for_proto(proto: str) -> list[str]:
    """
    按协议解析镜像 URL 候选列表，优先采用环境变量输入：
    1. 协议专属完整 URL: EDT_HTTPS_URLS / EDT_HTTP_URLS / EDT_SOCKS5_URLS
    2. 全局通用 URL 列表: EDT_URLS / EDT_PROXY_URLS
    3. 用户自建基址环境变量: EDT_BASE_URLS / EDT_BASE_URL (如 Worker / CDN)
    4. 用户输入的镜像前缀: EDT_MIRRORS / GITHUB_MIRRORS (动态生成多源候选)
    5. 默认开箱即用候选镜像源 (DEFAULT_EDT_PROXY_URLS)
    """
    proto_lower = proto.strip().lower()
    proto_file = f"{proto_lower}.json"
    env_key = f"EDT_{proto_lower.upper()}_URLS"
    raw_val = (os.getenv(env_key) or "").strip()
    if raw_val.lower() in ("none", "off", "disable", "false", "0"):
        return []

    # 1. 协议专属环境变量完整 URL
    if raw_val:
        urls = [item.strip() for item in re.split(r"[,;\s]+", raw_val) if item.strip().startswith("http")]
        if urls:
            return urls

    # 2. 全局通用 URL 列表 (EDT_URLS / EDT_PROXY_URLS)
    global_urls_val = (os.getenv("EDT_URLS") or os.getenv("EDT_PROXY_URLS") or "").strip()
    if global_urls_val and global_urls_val.lower() not in ("none", "off", "disable", "false", "0"):
        matched_urls = []
        for item in re.split(r"[,;\s]+", global_urls_val):
            item = item.strip()
            if item.startswith("http") and proto_file in item.lower():
                matched_urls.append(item)
        if matched_urls:
            return matched_urls

    # 3. 用户自建基址环境变量 (EDT_BASE_URLS / EDT_BASE_URL)
    base_val = (os.getenv("EDT_BASE_URLS") or os.getenv("EDT_BASE_URL") or "").strip()
    if base_val and base_val.lower() not in ("none", "off", "disable", "false", "0"):
        base_urls = []
        for item in re.split(r"[,;\s]+", base_val):
            item = item.strip().rstrip("/")
            if item.startswith("http"):
                base_urls.append(f"{item}/{proto_file}")
        if base_urls:
            return base_urls

    # 4. 用户配置的镜像加速前缀环境变量 (EDT_MIRRORS / GITHUB_MIRRORS)
    user_mirrors = _parse_edt_mirrors()
    if user_mirrors:
        built_urls = []
        for m in user_mirrors:
            if "raw.githubusercontent.com" in m:
                built_urls.append(f"{m}/EDT-Pages/Proxy-List/main/data/{proto_file}")
            else:
                built_urls.append(f"{m}/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/{proto_file}")
        official_url = f"https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/{proto_file}"
        if official_url not in built_urls:
            built_urls.append(official_url)
        return built_urls

    # 5. 默认开箱即用候选源
    return list(DEFAULT_EDT_PROXY_URLS.get(proto_lower, []))


def _parse_edt_https_urls() -> list[str]:
    return _parse_edt_urls_for_proto("https")


def _parse_edt_http_urls() -> list[str]:
    return _parse_edt_urls_for_proto("http")


def _parse_edt_socks5_urls() -> list[str]:
    return _parse_edt_urls_for_proto("socks5")


EDT_HTTPS_URLS = _parse_edt_https_urls()
EDT_HTTP_URLS = _parse_edt_http_urls()
EDT_SOCKS5_URLS = _parse_edt_socks5_urls()

DEFAULT_PROXYIP_ZIP_URLS = [
    "https://zip.cm.edu.kg.cmliussss.net/all.json",
]


def _parse_proxyip_zip_urls() -> list[str]:
    raw_val = (os.getenv("PROXYIP_ZIP_URLS") or os.getenv("PROXYIP_ZIP_URL") or "").strip()
    if raw_val:
        if raw_val.lower() in ("none", "off", "disable", "false", "0"):
            return []
        return [u.strip() for u in re.split(r"[,;\s]+", raw_val) if u.strip().startswith("http")]
    return list(DEFAULT_PROXYIP_ZIP_URLS)


PROXYIP_ZIP_URLS = _parse_proxyip_zip_urls()

DATA_DIR = "data"
OUTPUT_PROXY_FILE = os.path.join(DATA_DIR, "proxies.txt")
OUTPUT_PROXIES_CSV = os.path.join(DATA_DIR, "proxies.csv")
OUTPUT_PROXIES_DIR = os.path.join(DATA_DIR, "proxies")
OUTPUT_CF_FILE = os.path.join(DATA_DIR, "cf_ips.csv")
OUTPUT_CF_TXT = os.path.join(DATA_DIR, "cf_ips.txt")

# 扫描文件/附件提取的批量优选 IP 独立保存文件（与单条 IP 隔离，按 ASN 分组）
OUTPUT_SCAN_FILE = os.path.join(DATA_DIR, "scan_ips.csv")
OUTPUT_SCAN_TXT = os.path.join(DATA_DIR, "scan_ips.txt")
OUTPUT_SCAN_DIR = os.path.join(DATA_DIR, "scan_ips")

# 反代 ProxyIP 专属保存文件（独立反代池，供 edgetunnel / Workers 等使用）
OUTPUT_PROXYIP_FILE = os.path.join(DATA_DIR, "proxyip.csv")
OUTPUT_PROXYIP_TXT = os.path.join(DATA_DIR, "proxyip.txt")
OUTPUT_PROXYIP_DIR = os.path.join(DATA_DIR, "proxyip")
FETCH_STATS_FILE = os.path.join(DATA_DIR, ".fetch_stats.json")
# ============================================



CF_CSV_FIELDS = [
    "ip",
    "port",
    "tls",
    "delay_ms",
    "speed_kbs",
    "colo",
    "cf_location",
    "asn",
    "isp",
    "first_seen",
    "channel",
    "fail_count",
]
PROXYIP_CSV_FIELDS = CF_CSV_FIELDS + ["net_type"]

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

# 核心解析函数 (is_valid_host, extract_proxies, parse_cf_ip, parse_cf_csv_content,
# parse_otc_scan_content, parse_proxy_attachment_content) 已提取至 parsers.py 维护


def load_existing_proxies(
    filepath: str = OUTPUT_PROXY_FILE,
    csv_path: str = OUTPUT_PROXIES_CSV,
) -> dict:
    """读取本地已保存的代理列表，保留历史累积有效节点及其首次收录时间与质检元数据"""
    existing = {}
    csv_meta_by_url = {}
    csv_meta_by_key = {}
    if os.path.isfile(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    u = (r.get("url") or "").strip()
                    if not u:
                        continue
                    meta = {
                        "url": u,
                        "first_seen": (r.get("first_seen") or "").strip() or LEGACY_DEFAULT_FIRST_SEEN,
                        "fail_count": safe_int(r.get("fail_count"), 0),
                        "delay_ms": safe_int(r.get("delay_ms"), 0),
                        "status": r.get("status", "pending"),
                        "colo": r.get("colo", ""),
                        "country": r.get("country", ""),
                        "egress_ip": r.get("egress_ip", ""),
                        "asn": r.get("asn", ""),
                        "isp": r.get("isp", ""),
                        "net_type": r.get("net_type", ""),
                        "source": (r.get("source") or "").strip(),
                    }
                    csv_meta_by_url[u] = meta
                    for _, key in extract_proxies(u):
                        # 若同 key 在 CSV 中存在多行历史记录，优选健康度更高 (fail_count 更低) 或更新 (first_seen 更近) 的记录
                        if key not in csv_meta_by_key:
                            csv_meta_by_key[key] = meta
                        else:
                            old = csv_meta_by_key[key]
                            if meta["fail_count"] < old["fail_count"] or (
                                meta["fail_count"] == old["fail_count"] and meta["first_seen"] > old["first_seen"]
                            ):
                                csv_meta_by_key[key] = meta
        except Exception as e:
            log.warning("读取已有代理 CSV 失败: %s", e)

    # 1. 优先加载墓碑黑名单
    tombstone = load_tombstone()

    # 2. 兜底回填：若 proxies.txt 缺失但 proxies.csv 存在，直接从 CSV 索引反解并严格过滤墓地
    if not os.path.exists(filepath):
        if csv_meta_by_key:
            for key, meta in csv_meta_by_key.items():
                if not is_tombstoned(key, tombstone):
                    existing[key] = {
                        "url": meta["url"],
                        "first_seen": meta.get("first_seen", LEGACY_DEFAULT_FIRST_SEEN),
                        "fail_count": meta.get("fail_count", 0),
                        "delay_ms": meta.get("delay_ms", 0),
                        "status": meta.get("status", "pending"),
                        "colo": meta.get("colo", ""),
                        "country": meta.get("country", ""),
                        "egress_ip": meta.get("egress_ip", ""),
                        "asn": meta.get("asn", ""),
                        "isp": meta.get("isp", ""),
                        "net_type": meta.get("net_type", ""),
                        "source": meta.get("source", ""),
                    }
            if not existing and csv_meta_by_url:
                log.warning(
                    "本地 %s 缺失，且 %s 中读取的 %d 条记录全部命中墓碑或未匹配到有效 host:port (可能含未识别格式/IPv6)",
                    filepath, csv_path, len(csv_meta_by_url)
                )
            else:
                log.info("本地 %s 缺失，已从 %s 兜底恢复有效代理节点: %d 个 (已执行墓碑过滤)", filepath, csv_path, len(existing))
        return existing

    # 3. 正常读取 proxies.txt，优先按 canonical key (host:port) 关联 CSV 质检元数据
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line_s = line.strip()
                if not line_s or line_s.startswith("#"):
                    continue
                for url, key in extract_proxies(line_s):
                    if not is_tombstoned(key, tombstone):
                        meta = csv_meta_by_key.get(key) or csv_meta_by_url.get(url, {})
                        existing[key] = {
                            "url": url,
                            "first_seen": meta.get("first_seen", LEGACY_DEFAULT_FIRST_SEEN),
                            "fail_count": meta.get("fail_count", 0),
                            "delay_ms": meta.get("delay_ms", 0),
                            "status": meta.get("status", "pending"),
                            "colo": meta.get("colo", ""),
                            "country": meta.get("country", ""),
                            "egress_ip": meta.get("egress_ip", ""),
                            "asn": meta.get("asn", ""),
                            "isp": meta.get("isp", ""),
                            "net_type": meta.get("net_type", ""),
                            "source": meta.get("source", ""),
                        }
        log.info("已加载本地已存代理节点: %d 个（历史有效节点全部保留）", len(existing))
    except Exception as e:
        log.warning("读取已有代理文件失败: %s", e)
    return existing


def load_existing_cf_ips(filepath: str = OUTPUT_CF_FILE, label: str = "优选 IP") -> dict:
    """读取本地已保存的优选 IP，保留历史累积数据（已淘汰进入墓地的节点跳过）"""
    existing = {}
    if not os.path.exists(filepath):
        return existing
    tombstone = load_tombstone()
    try:
        with open(filepath, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip", "").strip()
                port = row.get("port", "").strip()
                if ip and port:
                    key = f"{ip}:{port}"
                    if not is_tombstoned(key, tombstone):
                        row["fail_count"] = safe_int(row.get("fail_count"), 0)
                        row["first_seen"] = normalize_timestamp(str(row.get("first_seen") or row.get("tested_at") or ""))
                        raw_asn = row.get("asn", "").replace("`", "").strip()
                        raw_isp = row.get("isp", "").replace("`", "").strip()
                        row["asn"] = format_asn_isp(raw_asn, raw_isp)
                        row["isp"] = raw_isp
                        row["colo"] = row.get("colo", "").replace("`", "").strip()
                        row["cf_location"] = row.get("cf_location", "").replace("`", "").strip()
                        existing[key] = row
        log.info("已加载本地已存%s记录: %d 条（历史有效记录全部保留）", label, len(existing))
    except Exception as e:
        log.warning("读取已有%s文件失败: %s", label, e)
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
    top_providers: list | None = None,
    elapsed_seconds: float = 0.0,
    unrecorded_asns: list | None = None,
):
    # 若设置了 DEFER_NOTIFY=1（如在 GitHub Actions 完整流水线中），则将抓取统计暂存至 .fetch_stats.json，由后续的 cf_verify 生成联合卡片
    if os.getenv("DEFER_NOTIFY") == "1":
        stats_data = {
            "proxies_count": proxies_count,
            "cf_ips_count": cf_ips_count,
            "scan_ips_count": scan_ips_count,
            "asn_count": asn_count,
            "proxyips_count": proxyips_count,
            "new_proxies": new_proxies,
            "updated_proxies": updated_proxies,
            "new_cf": new_cf,
            "updated_cf": updated_cf,
            "new_scan": new_scan,
            "updated_scan": updated_scan,
            "new_proxyips": new_proxyips,
            "updated_proxyips": updated_proxyips,
            "top_providers": top_providers or [],
            "unrecorded_asns": unrecorded_asns or [],
            "elapsed_seconds": elapsed_seconds,
            "channels": [ch for ch in PROXY_CHANNELS + CF_IP_CHANNELS if ch],
        }
        try:
            atomic_write_json(FETCH_STATS_FILE, stats_data)
            log.info("已将抓取阶段统计暂存至 %s (等待优选 IP 校验后统一推送)", FETCH_STATS_FILE)
            return
        except Exception as e:
            log.warning("暂存 %s 失败，将直接尝试推送: %s", FETCH_STATS_FILE, e)

    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过机器人消息推送")
        return

    bjt = datetime.now(TZ_BJT)
    date_str = bjt.strftime("%Y-%m-%d %H:%M:%S")

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
        proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{proxyips_count}</code> 条 ({proxyip_diff})\n"

    unmatched_block = ""
    if unrecorded_asns:
        valid_unrecorded = [item for item in unrecorded_asns if item.get("count", 0) > 0]
        if valid_unrecorded:
            items = []
            for item in valid_unrecorded[:4]:
                c = item.get("asn", "")
                o = str(item.get("org") or item.get("isp") or "").strip()
                cnt = item.get("count", 0)
                name_str = f" {o}" if o else ""
                cnt_str = f" ({cnt} 条)" if cnt else ""
                items.append(f"   • <code>{c}</code>{name_str}{cnt_str}")
            suffix = f"\n   └ <i>共 {len(valid_unrecorded)} 个已自动收录入库</i>" if len(valid_unrecorded) > 4 else ""
            unmatched_block = f"💡 <b>新收录 ASN (已自动归类入库 +{len(valid_unrecorded)})</b>：\n" + "\n".join(items) + suffix + "\n"

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
        f"{unmatched_block}"
        f"{div}\n"
        f"📡 <b>频道来源</b>：{channels_str}"
        f"{footer_line}"
    )

    try:
        send_tg_message(message, token=token, chat_id=chat_id, tag="tg-fetch")
    except Exception as e:
        log.warning("发送 TG 机器人通知网络异常: %s", e)


def fetch_web_page(url: str, proxy: str = "", timeout: int = 15) -> str:
    """获取网页 HTML 内容，支持 curl 与 urllib.request 优雅降级"""
    if shutil.which("curl"):
        cmd = [
            "curl", "-sL",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        if proxy:
            cmd.extend(["-x", proxy])
        cmd.extend([url, "--max-time", str(timeout)])
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout + 5, check=False)
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
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_external_subscriptions(
    sub_urls: list[str],
    proxy: str,
    tombstone: dict[str, int],
    scraped_proxies: dict[str, str],
) -> int:
    """拉取外部通用订阅源（如 VPNGate SSTP 订阅），解析提取节点并自动去重与墓地过滤"""
    if not sub_urls:
        return 0

    log.info("-" * 50)
    log.info("开始拉取外部通用订阅源: %d 个链接", len(sub_urls))
    total_added = 0

    for sub_url in sub_urls:
        try:
            log.info("拉取外部订阅: %s", sub_url)
            sub_content = fetch_web_page(sub_url, proxy=proxy)
            if sub_content:
                sub_proxies = extract_proxies(sub_content)
                sub_added = 0
                for url, key in sub_proxies:
                    if is_tombstoned(key, tombstone):
                        continue
                    if key not in scraped_proxies:
                        src_label = "vpngate" if ("vpngate" in sub_url.lower() or "opengw" in sub_url.lower()) else "subscription"
                        scraped_proxies[key] = {"url": url, "source": src_label}
                        sub_added += 1
                total_added += sub_added
                log.info("从外部订阅 %s 成功提取节点: %d 个 (有效去重新增: %d 个)", sub_url, len(sub_proxies), sub_added)
            else:
                log.warning("外部订阅 %s 获取内容为空", sub_url)
        except Exception as e:
            log.warning("拉取外部订阅 %s 失败: %s", sub_url, e)

    return total_added


def auto_enrich_and_save_asns(unrecorded_items: list[dict], proxy: str = "") -> int:
    """
    针对自带 ASN / 组织机构属性的数据源（如 EDT-Pages、测速扫描附件等）：
    在抓取阶段直接自动完成网络类型属性分类并持久化入库到 data/asn_database.json。
    对于裸 IP（如 Telegram 频道提取的裸节点），保持在抓取阶段不作处理，交由质检阶段在线反查入库。

    工程保障：
    1. 【严格幂等性】：内存字典去重 + is_asn_recorded 检查 + JSON 对象键覆盖，多次调用与多轮定时任务绝不产生重复条目或频繁写盘。
    2. 【全链路异常隔离】：单条记录解析异常、正则不匹配、在线反查超时、写盘异常均被完全隔离捕获，记录日志后安全跳过，绝不中断抓取主流程。
    3. 【云厂商 SSOT 保护】：若传入的 ASN 属于内置权威已知云厂商（如 AWS、Cloudflare、阿里云、腾讯云等），强制维持权威标准名称与 datacenter 属性，绝对禁止外部数据篡改。
    """
    if not unrecorded_items:
        return 0

    try:
        to_save_map: dict[str, dict] = {}
        for item in unrecorded_items:
            try:
                if not isinstance(item, dict):
                    continue
                raw_asn = str(item.get("asn") or "").strip()
                raw_isp = str(item.get("isp") or item.get("org") or "").strip()
                code = _extract_asn_code(raw_asn, raw_isp)
                if not code or not re.match(r"^AS\d+$", code):
                    continue

                # 云厂商 SSOT 保护：若命中内置权威已知云厂商，坚决维持权威定义，直接跳过并拒绝外部污染
                if code in AUTHORITATIVE_CLOUD_ASNS:
                    log.debug("ASN %s 命中权威已知云厂商 SSOT 锁定列表，维持权威名称 %s，忽略外部标签: %s", code, AUTHORITATIVE_CLOUD_ASNS[code], raw_isp)
                    continue

                # 幂等性快速短路：若本地权威库已收录，直接跳过
                if is_asn_recorded(code):
                    continue

                org = re.sub(r"^AS\d+\s*", "", raw_isp, flags=re.IGNORECASE).strip()
                sample_ip = str(item.get("ip") or "").strip()

                # 若组织名缺失且存在有效公网 IP，尝试轻量在线反查一次获取标准组织名 (隔离超时与异常)
                if not org and sample_ip and is_valid_host(sample_ip):
                    try:
                        resolved_code, resolved_isp = resolve_asn_online(sample_ip)
                        if resolved_code == code and resolved_isp:
                            org = resolved_isp
                    except Exception as resolve_err:
                        log.debug("尝试在线反查缺失组织名的 ASN %s 失败 (已安全跳过反查): %s", code, resolve_err)

                net_type = item.get("net_type") or classify_asn(code, org)
                if code not in to_save_map:
                    to_save_map[code] = {
                        "asn": code,
                        "isp": org,
                        "net_type": net_type,
                    }
                if org:
                    item["org"] = org
                    item["isp"] = org
            except Exception as item_err:
                log.debug("解析单条未收录 ASN 条目发生异常 (已隔离跳过): %s (%s)", item, item_err)
                continue

        if not to_save_map:
            return 0

        i2a, a2i, a2nt = load_asn_database()
        added_count = 0
        for code, info in to_save_map.items():
            # 再次确认 SSOT 保护
            if code in AUTHORITATIVE_CLOUD_ASNS:
                continue
            org = info["isp"]
            n_type = info["net_type"]
            if code not in a2nt:
                a2nt[code] = n_type
                added_count += 1
            if org:
                if code not in a2i:
                    a2i[code] = org
                if org not in i2a:
                    i2a[org] = code

        if added_count > 0:
            save_asn_database(i2a, a2i, a2nt)
            # 同步更新内存运行时 SSOT 字典与 Fast-path
            ASN_TO_PROVIDER.update(a2i)
            if hasattr(providers, "ASN_DATABASE_ASN_TO_NET_TYPE"):
                providers.ASN_DATABASE_ASN_TO_NET_TYPE.update(a2nt)
            if hasattr(providers, "ASN_EXACT_NET_TYPE"):
                providers.ASN_EXACT_NET_TYPE.update(a2nt)

            sample_str = ", ".join(f"{c}[{info['net_type']}]" for c, info in list(to_save_map.items())[:6])
            log.info("【批量自动持久化新 ASN】从自带源提取 %d 个全新自治系统并原子写入数据库: %s", added_count, sample_str)
        return added_count
    except Exception:
        log.exception("【自动收录新 ASN】执行异常（已安全隔离，抓取主流程继续正常执行）")
        return 0


def fetch_edt_proxies(
    proto: str,
    edt_urls: list[str],
    proxy: str,
    tombstone: dict[str, int],
    scraped_proxies: dict[str, dict | str],
    timeout: float = 12.0,
) -> tuple[int, list[dict]]:
    """
    拉取外部 EDT-Pages/Proxy-List 的 {proto}.json 镜像源，
    采用【多镜像并发竞速机制】(Concurrent Racing)：同时向所有候选镜像发起请求，以最先返回有效合法数据的镜像为胜出者并立即采用，彻底避免慢镜像串行阻塞。
    直接过滤剔除机房 (datacenter) 节点，仅抓取保留高价值非机房节点（ISP 宽带、高校教育网、政务网、商业专线），
    提取 clientIp 为实际 egress_ip，并自动去重与过滤墓地黑名单。
    同时动态统计未收录在权威库中的自治系统 (ASN)。
    返回: (有效新增节点数, 未收录 ASN 列表)
    """
    if not edt_urls:
        return 0, []

    proto_lower = proto.strip().lower()
    proto_upper = proto_lower.upper()

    log.info("-" * 50)
    log.info("开始拉取 EDT-Pages 外部 %s 代理镜像源: %d 个候选镜像 (并发竞速模式)", proto_upper, len(edt_urls))

    success_url = ""
    data = []

    def _fetch_single_mirror(u: str) -> tuple[str, list]:
        txt = fetch_web_page(u, proxy=proxy, timeout=int(timeout))
        if not txt or not txt.strip().startswith("["):
            raise ValueError("内容为空或非有效 JSON 列表")
        parsed = json.loads(txt)
        if not isinstance(parsed, list) or len(parsed) == 0:
            raise ValueError("返回 JSON 非列表或无有效节点")
        return u, parsed

    if len(edt_urls) == 1:
        u = edt_urls[0]
        try:
            t0 = time.time()
            success_url, data = _fetch_single_mirror(u)
            log.info("单源拉取 EDT %s 成功: %s (耗时 %.2fs, 记录数 %d)", proto_upper, u, time.time() - t0, len(data))
        except Exception as e:
            log.warning("单源拉取 EDT %s 失败: %s (%s)", proto_upper, u, e)
    else:
        t_start = time.time()
        executor = ThreadPoolExecutor(max_workers=min(len(edt_urls), 8), thread_name_prefix=f"edt-race-{proto_lower}")
        try:
            future_to_url = {executor.submit(_fetch_single_mirror, u): u for u in edt_urls}
            for future in as_completed(future_to_url):
                cand_url = future_to_url[future]
                try:
                    cand_url, cand_data = future.result()
                    success_url = cand_url
                    data = cand_data
                    cost = time.time() - t_start
                    log.info(
                        "🏆 EDT %s 镜像并发竞速胜出: %s (耗时 %.2fs, 原始记录 %d 条), 领先并率先采用！",
                        proto_upper,
                        success_url,
                        cost,
                        len(data),
                    )
                    break
                except Exception as e:
                    log.debug("候选镜像 %s 竞速未达标或较慢: %s", cand_url, e)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    if not data:
        log.warning("所有 EDT %s 代理镜像源竞速拉取均未成功返回有效数据，跳过本次拉取", proto_upper)
        return 0, []

    log.info("成功采用 %s 的 EDT %s 代理源数据: %d 条原始记录", success_url, proto_upper, len(data))

    total_added = 0
    dc_filtered = 0
    unrecorded_asns_map: dict[str, dict] = {}

    for item in data:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "").strip()
        port = safe_int(item.get("port"), 0)
        if not ip or not (1 <= port <= 65535):
            continue

        asn_raw = str(item.get("asn") or "").strip()
        asn_code = f"AS{asn_raw}" if asn_raw and not asn_raw.upper().startswith("AS") else asn_raw.upper()
        org = str(item.get("asOrganization") or "").strip()

        # 核心策略：严格过滤机房节点，仅保留非机房高价值代理
        net_type = classify_asn(asn_code, org)
        if net_type == "datacenter":
            dc_filtered += 1
            continue

        key = f"{ip}:{port}"
        if is_tombstoned(key, tombstone):
            continue

        # 检查是否为未收录的有效非机房 ASN (仅针对通过过滤且存活的高价值候选节点进行收录统计)
        if asn_code and not is_asn_recorded(asn_code, org):
            if asn_code not in unrecorded_asns_map:
                unrecorded_asns_map[asn_code] = {
                    "asn": asn_code,
                    "org": org,
                    "isp": org,
                    "ip": ip,
                    "net_type": net_type,
                    "count": 0,
                }
            unrecorded_asns_map[asn_code]["count"] += 1

        client_ip = str(item.get("clientIp") or "").strip()
        egress_ip = client_ip if client_ip else ip
        country = str(item.get("country") or "").strip().upper()
        formatted_asn = format_asn_isp(asn_code, org)
        proxy_url = f"{proto_lower}://{ip}:{port}"

        meta_dict = {
            "url": proxy_url,
            "proto": proto_lower,
            "host": ip,
            "port": port,
            "country": country,
            "egress_ip": egress_ip,
            "asn": formatted_asn,
            "isp": org,
            "net_type": net_type,
            "source": "EDT-Pages",
            "status": "pending",
        }

        if key not in scraped_proxies:
            scraped_proxies[key] = meta_dict
            total_added += 1
        elif isinstance(scraped_proxies[key], dict):
            # 若已存在但缺乏关键元数据，择优补全
            for m_k in ("country", "egress_ip", "asn", "isp", "net_type", "source"):
                if meta_dict.get(m_k) and not scraped_proxies[key].get(m_k):
                    scraped_proxies[key][m_k] = meta_dict[m_k]

    log.info(
        "EDT %s 过滤与提取完成: 剔除机房节点 %d 个, 提取非机房节点 (有效新增: %d 个), 发现未收录 ASN: %d 个",
        proto_upper,
        dc_filtered,
        total_added,
        len(unrecorded_asns_map),
    )

    return total_added, list(unrecorded_asns_map.values())


def fetch_edt_https_proxies(
    edt_urls: list[str],
    proxy: str,
    tombstone: dict[str, int],
    scraped_proxies: dict[str, dict | str],
) -> tuple[int, list[dict]]:
    """向后兼容历史调用，默认拉取 HTTPS"""
    return fetch_edt_proxies("https", edt_urls, proxy, tombstone, scraped_proxies)


def fetch_zip_proxyips(
    zip_urls: list[str],
    proxy: str,
    tombstone: dict[str, int],
    scraped_proxyips: dict[str, dict],
    timeout: float = 30.0,
) -> tuple[int, list[dict]]:
    """
    拉取外部 ProxyIP 聚合源 (如 cmliussss zip all.json)，
    采用【多镜像并发竞速机制】(Concurrent Racing)：同时向所有候选镜像发起请求，最快返回合法数据的镜像胜出。
    【核心收录策略】：
      - 严格只收录非机房节点（ISP 宽带、高校教育网、政务网、商业企业专线、银行金融），
        net_type == 'datacenter' 的常规机房节点直接过滤剔除。
      - 自动过滤墓地黑名单、自动提取国家/城市/colo 等详细位置信息。
      - 动态发现并汇流未收录在权威库中的自治系统 (ASN)。
    返回: (有效新增 ProxyIP 条数, 未收录 ASN 列表)
    """
    if not zip_urls:
        return 0, []

    log.info("-" * 50)
    log.info("开始拉取外部 ProxyIP 聚合源: %d 个候选镜像 (并发竞速模式, 严控只收录非机房)", len(zip_urls))

    success_url = ""
    data = []

    def _fetch_single_zip_mirror(u: str) -> tuple[str, list]:
        txt = fetch_web_page(u, proxy=proxy, timeout=int(timeout))
        if not txt:
            raise ValueError("内容为空")
        parsed = json.loads(txt)
        if isinstance(parsed, dict):
            parsed = parsed.get("data", [])
        if not isinstance(parsed, list) or len(parsed) == 0:
            raise ValueError("返回 JSON 无有效节点数据列表")
        return u, parsed

    if len(zip_urls) == 1:
        u = zip_urls[0]
        try:
            t0 = time.time()
            success_url, data = _fetch_single_zip_mirror(u)
            log.info("单源拉取 ProxyIP 成功: %s (耗时 %.2fs, 原始记录数 %d)", u, time.time() - t0, len(data))
        except Exception as e:
            log.warning("单源拉取 ProxyIP 失败: %s (%s)", u, e)
    else:
        t_start = time.time()
        executor = ThreadPoolExecutor(max_workers=min(len(zip_urls), 8), thread_name_prefix="proxyip-zip-race")
        try:
            future_to_url = {executor.submit(_fetch_single_zip_mirror, u): u for u in zip_urls}
            for future in as_completed(future_to_url):
                cand_url = future_to_url[future]
                try:
                    cand_url, cand_data = future.result()
                    success_url = cand_url
                    data = cand_data
                    cost = time.time() - t_start
                    log.info(
                        "🏆 ProxyIP 聚合源镜像并发竞速胜出: %s (耗时 %.2fs, 原始记录 %d 条), 领先并率先采用！",
                        success_url,
                        cost,
                        len(data),
                    )
                    break
                except Exception as e:
                    log.debug("候选镜像 %s 竞速未达标或较慢: %s", cand_url, e)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    if not data:
        log.warning("所有 ProxyIP 聚合源镜像竞速拉取均未成功返回有效数据，跳过本次拉取")
        return 0, []

    log.info("成功采用 %s 的 ProxyIP 聚合源数据: %d 条原始记录", success_url, len(data))

    now_bjt = datetime.now(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S")
    total_added = 0
    dc_filtered = 0
    unrecorded_asns_map: dict[str, dict] = {}

    for item in data:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "").strip()
        raw_port = item.get("port")
        if isinstance(raw_port, list):
            ports = [safe_int(p, 0) for p in raw_port]
        elif isinstance(raw_port, (int, str)):
            ports = [safe_int(raw_port, 0)]
        else:
            ports = [443]
        ports = [p for p in ports if 1 <= p <= 65535]
        if not ip or not ports or not is_valid_host(ip):
            continue

        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        raw_asn = str(meta.get("asn") or item.get("asn") or "").strip()
        raw_isp = str(meta.get("asOrganization") or meta.get("isp") or item.get("asOrganization") or item.get("isp") or "").strip()
        asn_code = _extract_asn_code(raw_asn, raw_isp)

        # 核心策略：严格只收录非机房，常规 datacenter 机房节点直接过滤剔除
        net_type = classify_asn(asn_code, raw_isp)
        if net_type == "datacenter":
            dc_filtered += 1
            continue

        colo_obj = meta.get("colo")
        if isinstance(colo_obj, dict):
            colo = str(colo_obj.get("iata") or "").strip().upper()
        else:
            colo = str(colo_obj or "").strip().upper()

        loc_parts = []
        for part in (meta.get("continent_cn"), meta.get("city") or meta.get("region"), meta.get("country_cn") or meta.get("country")):
            p_str = str(part or "").strip()
            if p_str and p_str != "-" and p_str not in loc_parts:
                loc_parts.append(p_str)
        cf_location = " · ".join(loc_parts)

        formatted_asn = format_asn_isp(asn_code or raw_asn, raw_isp)

        for port in ports:
            key = f"{ip}:{port}"
            if is_tombstoned(key, tombstone):
                continue

            tls = "true" if port in (443, 8443, 2053, 2083, 2087, 2096) else "false"
            proxyip_item = {
                "ip": ip,
                "port": str(port),
                "tls": tls,
                "delay_ms": 0,
                "speed_kbs": 0,
                "colo": colo,
                "cf_location": cf_location,
                "isp": raw_isp,
                "asn": formatted_asn,
                "first_seen": now_bjt,
                "channel": "@cmliussss_all",
                "fail_count": 0,
                "net_type": net_type,
            }

            if key not in scraped_proxyips:
                scraped_proxyips[key] = proxyip_item
                total_added += 1
                # 检查是否为未收录的有效非机房 ASN (仅针对通过过滤且存活的高价值候选节点进行收录统计)
                if asn_code and not is_asn_recorded(asn_code, raw_isp):
                    if asn_code not in unrecorded_asns_map:
                        unrecorded_asns_map[asn_code] = {
                            "asn": asn_code,
                            "org": raw_isp,
                            "isp": raw_isp,
                            "ip": ip,
                            "net_type": net_type,
                            "count": 0,
                        }
                    unrecorded_asns_map[asn_code]["count"] += 1
            elif isinstance(scraped_proxyips[key], dict):
                for mk in ("colo", "cf_location", "isp", "asn", "net_type"):
                    if proxyip_item.get(mk) and not scraped_proxyips[key].get(mk):
                        scraped_proxyips[key][mk] = proxyip_item[mk]

    log.info(
        "外部 ProxyIP 源过滤与提取完成: 剔除机房节点 %d 个, 提取非机房 ProxyIP (有效新增: %d 个), 发现未收录 ASN: %d 个",
        dc_filtered,
        total_added,
        len(unrecorded_asns_map),
    )

    return total_added, list(unrecorded_asns_map.values())


def scrape_channel_web(channel: str, cutoff: datetime, proxy: str = "") -> tuple[list[tuple[str, str]], list[dict]]:
    clean_channel = channel.lstrip("@")
    base_url = f"https://t.me/s/{clean_channel}"
    
    proxies_found = []
    cf_ips_found = []
    
    url = base_url
    page_num = 1
    max_pages = safe_int(os.getenv("FETCH_MAX_PAGES"), 35)

    while url and page_num <= max_pages:
        log.info("频道 %s 正在抓取第 %d 页: %s", channel, page_num, url)
        try:
            html_content = fetch_web_page(url, proxy=proxy)
        except Exception as e:
            log.warning("频道 %s 第 %d 页抓取网络错误: %s", channel, page_num, e)
            break

        if not html_content or "tgme_widget_message_wrap" not in html_content:
            if page_num == 1:
                log.info("频道 %s 首次拉取未获取到公开消息卡片，等待 1.5 秒后重试 1 次...", channel)
                time.sleep(1.5)
                try:
                    html_content = fetch_web_page(url, proxy=proxy)
                except Exception as e:
                    log.debug("频道 %s 重试异常: %s", channel, e)
                    html_content = ""
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
                except (ValueError, TypeError, IndexError):
                    pass

            t_m = re.search(r'<time[^>]*datetime="([^"]+)"', chunk)
            dt = None
            if t_m:
                try:
                    dt = datetime.fromisoformat(t_m.group(1).replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
                    if dt < cutoff:
                        # Telegram Web 页面 HTML 中 chunks[0] 为最旧消息，chunks[-1] 为最新消息。
                        # reversed(chunks) 从最新遍历到最旧。遇到早于 cutoff 的消息时标记 reached_cutoff，
                        # 使用 continue 跳过当前旧消息，确保整页消息（及 earliest_id）遍历完整，并在外层停止翻页。
                        reached_cutoff = True
                        continue
                except (ValueError, TypeError):
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
                if not cf_data.get("first_seen") and dt:
                    cf_data["first_seen"] = dt.astimezone(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S")
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
    final_scan_ips: dict | None = None,
    final_proxyips: dict | None = None,
    new_proxies_count: int = 0,
    updated_proxies_count: int = 0,
    new_cf_count: int = 0,
    updated_cf_count: int = 0,
    new_scan_count: int = 0,
    updated_scan_count: int = 0,
    new_proxyips_count: int = 0,
    updated_proxyips_count: int = 0,
    unrecorded_asns: list | None = None,
):
    # 1. 保存通用代理总表（proxies.txt）并按协议独立拆分（原子写入）
    os.makedirs(DATA_DIR, exist_ok=True)
    formatted_proxies = format_proxies_txt(list(final_proxies.values()))
    atomic_write_text(OUTPUT_PROXY_FILE, formatted_proxies)
    log.info("已按协议分段保存通用代理总文件: %s (%d 个全量累积节点)", OUTPUT_PROXY_FILE, len(final_proxies))

    proto_counts = save_proxies_by_protocol(list(final_proxies.values()), OUTPUT_PROXIES_DIR)
    log.info("已在 %s/ 目录下生成 %d 个独立协议文件: %s", OUTPUT_PROXIES_DIR, len(proto_counts), proto_counts)

    save_proxies_csv(list(final_proxies.values()), OUTPUT_PROXIES_CSV)

    # 2. 保存单条优选 IP（原子写入）
    sorted_cf_ips = sorted(
        final_cf_ips.values(),
        key=lambda item: item.get("first_seen", ""),
        reverse=True,
    )
    with atomic_writer(OUTPUT_CF_FILE, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in sorted_cf_ips:
            row.setdefault("fail_count", 0)
            writer.writerow(row)
    log.info("已保存单条优选IP文件: %s (%d 条全量累积记录)", OUTPUT_CF_FILE, len(sorted_cf_ips))

    with atomic_writer(OUTPUT_CF_TXT, encoding="utf-8") as f:
        for row in sorted_cf_ips:
            ip = str(row.get("ip") or "").strip()
            port = safe_int(row.get("port"), 0)
            if ip and 1 <= port <= 65535:
                f.write(f"{ip}:{port}\n")
    log.info("已保存单条优选IP纯文本: %s (%d 行 IP:Port)", OUTPUT_CF_TXT, len(sorted_cf_ips))

    # 3. 保存文件/扫描优选 IP（按 ASN 智能去重、分组归类与独立拆分；原子写入）
    scan_ips_total = 0
    asn_groups_total = 0
    asn_groups = {}
    if final_scan_ips:
        os.makedirs(OUTPUT_SCAN_DIR, exist_ok=True)

        asn_groups = defaultdict(list)
        for row in final_scan_ips.values():
            asn_clean = clean_asn(row.get("asn"), row.get("isp"))
            row["asn"] = format_asn_isp(row.get("asn"), row.get("isp"))
            asn_groups[asn_clean].append(row)

        asn_groups_total = len(asn_groups)

        all_sorted_scan_rows = []
        for asn_name in sorted(asn_groups.keys()):
            group_rows = sorted(asn_groups[asn_name], key=lambda x: x.get("first_seen", ""), reverse=True)
            all_sorted_scan_rows.extend(group_rows)

        with atomic_writer(OUTPUT_SCAN_FILE, encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in all_sorted_scan_rows:
                row.setdefault("fail_count", 0)
                writer.writerow(row)
        log.info("已保存扫描优选IP表格: %s (%d 条全量累积记录)", OUTPUT_SCAN_FILE, len(all_sorted_scan_rows))

        atomic_write_text(OUTPUT_SCAN_TXT, format_scan_ips_txt(all_sorted_scan_rows))
        log.info("已按质检缓冲状态分层保存扫描优选IP汇总文本: %s (%d 行/条记录)", OUTPUT_SCAN_TXT, len(all_sorted_scan_rows))

        save_scan_ips_by_asn(asn_groups, OUTPUT_SCAN_DIR)
        scan_ips_total = len(all_sorted_scan_rows)

    # 4. 保存反代 ProxyIP 独立池（原子写入）
    proxyip_total = 0
    if final_proxyips:
        def _proxyip_sort_key(x):
            d = safe_int(x.get("delay_ms"), 0)
            delay = d if d > 0 else 99999
            return (x.get("first_seen", ""), -delay)

        sorted_proxyips = sorted(
            final_proxyips.values(),
            key=_proxyip_sort_key,
            reverse=True,
        )
        with atomic_writer(OUTPUT_PROXYIP_FILE, encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PROXYIP_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in sorted_proxyips:
                row.setdefault("fail_count", 0)
                row["asn"] = format_asn_isp(row.get("asn", ""), row.get("isp", ""))
                row["net_type"] = classify_asn(row.get("asn", ""), row.get("isp", ""))
                writer.writerow(row)
        log.info("已保存反代 ProxyIP 表格: %s (%d 条全量累积记录)", OUTPUT_PROXYIP_FILE, len(sorted_proxyips))

        atomic_write_text(OUTPUT_PROXYIP_TXT, format_proxyip_txt(sorted_proxyips))
        log.info("已保存反代 ProxyIP 纯文本: %s (%d 行/条记录，按质检状态分层)", OUTPUT_PROXYIP_TXT, len(sorted_proxyips))

        proxyip_split_cnt = save_proxyip_by_country(sorted_proxyips, OUTPUT_PROXYIP_DIR)
        log.info("已在 %s/ 目录下生成 %d 个独立国家/地区纯文本文件", OUTPUT_PROXYIP_DIR, proxyip_split_cnt)

        proxyip_total = len(sorted_proxyips)

    top_providers = []
    if asn_groups:
        sorted_groups = sorted(asn_groups.items(), key=lambda item: len(item[1]), reverse=True)
        seen_names = set()
        for asn_name, group in sorted_groups:
            isp_name = ASN_TO_PROVIDER.get(asn_name, "")
            if not isp_name:
                isp_name = next((r.get("isp") for r in group if r.get("isp")), "")
            raw_name = isp_name if isp_name else asn_name
            # 剥离可能携带的别名括号 (如 GTHost) 及公司形式后缀，确保卡片展示纯粹核心品牌
            clean_name = re.sub(r'\(.*?\)', '', raw_name)
            clean_name = re.sub(r'\b(LLC|Inc|Limited|Ltd|OU|GmbH|Co)\b\.?', '', clean_name, flags=re.IGNORECASE).strip()
            name = clean_name if clean_name else raw_name
            if name and name not in seen_names:
                seen_names.add(name)
                top_providers.append(name)

    elapsed_sec = time.time() - START_TIME

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
        unrecorded_asns=unrecorded_asns,
    )

    log.info("=" * 50)
    log.info("抓取、增量合并、保存与通知任务全部顺利完成！")


def merge_and_save(
    existing_proxies: dict,
    scraped_proxies: dict,
    existing_cf_ips: dict,
    scraped_cf_ips: dict,
    existing_scan_ips: dict | None = None,
    scraped_scan_ips: dict | None = None,
    existing_proxyips: dict | None = None,
    scraped_proxyips: dict | None = None,
    edt_unrecorded_asns: list[dict] | None = None,
    proxy: str = "",
):
    """
    智能增量合并：历史保留，重复更新，新增追加，并持久化落盘与发送通知。
    供 Web 免登录抓取模式与 Telethon API 抓取模式统一复用。
    """
    existing_scan_ips = existing_scan_ips or {}
    scraped_scan_ips = scraped_scan_ips or {}
    existing_proxyips = existing_proxyips or {}
    scraped_proxyips = scraped_proxyips or {}

    tombstone = load_tombstone()

    # 1. 过滤掉命中墓地的节点 (双重防御，杜绝死节点进入待存集合)
    scraped_proxies = {k: v for k, v in scraped_proxies.items() if not is_tombstoned(k, tombstone)}
    scraped_cf_ips = {k: v for k, v in scraped_cf_ips.items() if not is_tombstoned(k, tombstone)}
    scraped_scan_ips = {k: v for k, v in scraped_scan_ips.items() if not is_tombstoned(k, tombstone)}
    scraped_proxyips = {k: v for k, v in scraped_proxyips.items() if not is_tombstoned(k, tombstone)}
    existing_proxies = {k: v for k, v in existing_proxies.items() if not is_tombstoned(k, tombstone)}
    existing_cf_ips = {k: v for k, v in existing_cf_ips.items() if not is_tombstoned(k, tombstone)}
    existing_scan_ips = {k: v for k, v in existing_scan_ips.items() if not is_tombstoned(k, tombstone)}
    existing_proxyips = {k: v for k, v in existing_proxyips.items() if not is_tombstoned(k, tombstone)}

    new_proxy_cnt = sum(1 for k in scraped_proxies if k not in existing_proxies)
    updated_proxy_cnt = sum(1 for k in scraped_proxies if k in existing_proxies)

    new_cf_cnt = sum(1 for k in scraped_cf_ips if k not in existing_cf_ips)
    updated_cf_cnt = sum(1 for k in scraped_cf_ips if k in existing_cf_ips)

    new_scan_cnt = sum(1 for k in scraped_scan_ips if k not in existing_scan_ips)
    updated_scan_cnt = sum(1 for k in scraped_scan_ips if k in existing_scan_ips)

    new_proxyip_cnt = sum(1 for k in scraped_proxyips if k not in existing_proxyips)
    updated_proxyip_cnt = sum(1 for k in scraped_proxyips if k in existing_proxyips)

    # 2. 合并：严格保护历史 fail_count 与元数据，防止被新抓取结果抹除为 0
    final_proxies = {}
    now_bjt = datetime.now(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S")
    for k, v in existing_proxies.items():
        if isinstance(v, dict):
            final_proxies[k] = dict(v)
        else:
            final_proxies[k] = {"url": v, "first_seen": LEGACY_DEFAULT_FIRST_SEEN, "fail_count": 0, "source": ""}
    for k, v in scraped_proxies.items():
        url = v.get("url") if isinstance(v, dict) else v
        src = v.get("source") if isinstance(v, dict) else ""
        if k in final_proxies:
            # 已经存在：严格保留原有 first_seen 及历史质检状态与失败计数，仅刷新 url
            final_proxies[k]["url"] = url
            if isinstance(v, dict):
                for meta_key in ("country", "egress_ip", "asn", "isp", "net_type", "colo", "source"):
                    if v.get(meta_key) and not final_proxies[k].get(meta_key):
                        final_proxies[k][meta_key] = v[meta_key]
        else:
            # 首次抓取收录：记录此时此刻为 first_seen，其余指标待质检
            item = {
                "url": url,
                "first_seen": now_bjt,
                "fail_count": 0,
                "delay_ms": 0,
                "status": "pending",
                "colo": "",
                "source": src,
            }
            if isinstance(v, dict):
                for meta_key in ("country", "egress_ip", "asn", "isp", "net_type", "colo", "source"):
                    if v.get(meta_key):
                        item[meta_key] = v[meta_key]
            final_proxies[k] = item

    final_cf_ips = dict(existing_cf_ips)
    for k, v in scraped_cf_ips.items():
        if k in final_cf_ips:
            # 关键修复：保留已有质检 fail_count，不被抓取默认的 0 抹除
            v["fail_count"] = final_cf_ips[k].get("fail_count", 0)
            if not v.get("first_seen"):
                v["first_seen"] = final_cf_ips[k].get("first_seen") or final_cf_ips[k].get("tested_at", "")
            final_cf_ips[k].update(v)
        else:
            final_cf_ips[k] = v

    final_scan_ips = dict(existing_scan_ips)
    for k, v in scraped_scan_ips.items():
        if k in final_scan_ips:
            # 关键修复：保留已有扫描 IP 失败计数
            v["fail_count"] = final_scan_ips[k].get("fail_count", 0)
            if not v.get("first_seen"):
                v["first_seen"] = final_scan_ips[k].get("first_seen") or final_scan_ips[k].get("tested_at", "")
            final_scan_ips[k].update(v)
        else:
            final_scan_ips[k] = v

    final_proxyips = dict(existing_proxyips)
    for k, v in scraped_proxyips.items():
        if k in final_proxyips:
            # 关键修复：保留已有 ProxyIP 失败计数与质检状态
            v["fail_count"] = final_proxyips[k].get("fail_count", 0)
            if not v.get("first_seen"):
                v["first_seen"] = final_proxyips[k].get("first_seen") or final_proxyips[k].get("tested_at", "")
            final_proxyips[k].update(v)
        else:
            final_proxyips[k] = v

    log.info("=" * 50)
    log.info(
        "代理节点增量合并: 历史保留 %d 个, 本次新增 %d 个, 本次更新 %d 个 -> 全量总计 %d 个",
        len(existing_proxies) - updated_proxy_cnt,
        new_proxy_cnt,
        updated_proxy_cnt,
        len(final_proxies),
    )
    log.info(
        "单条优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条",
        len(existing_cf_ips) - updated_cf_cnt,
        new_cf_cnt,
        updated_cf_cnt,
        len(final_cf_ips),
    )
    if final_scan_ips:
        log.info(
            "扫描优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条",
            len(existing_scan_ips) - updated_scan_cnt,
            new_scan_cnt,
            updated_scan_cnt,
            len(final_scan_ips),
        )
    if final_proxyips:
        log.info(
            "反代 ProxyIP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条",
            len(existing_proxyips) - updated_proxyip_cnt,
            new_proxyip_cnt,
            updated_proxyip_cnt,
            len(final_proxyips),
        )

    # 统计本次新增的未收录 ASN (Mode A: 仅在新抓取到的新增节点中检测)
    from collections import Counter
    unrecorded_counts = Counter()
    unrecorded_orgs = {}
    unrecorded_ips = {}
    unrecorded_net_types = {}

    for k, v in scraped_scan_ips.items():
        if k not in existing_scan_ips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org
                if c not in unrecorded_ips:
                    unrecorded_ips[c] = v.get("ip") or (k.split(":")[0] if ":" in k else "")
                if c not in unrecorded_net_types:
                    unrecorded_net_types[c] = v.get("net_type") or ""

    for k, v in scraped_cf_ips.items():
        if k not in existing_cf_ips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org
                if c not in unrecorded_ips:
                    unrecorded_ips[c] = v.get("ip") or (k.split(":")[0] if ":" in k else "")
                if c not in unrecorded_net_types:
                    unrecorded_net_types[c] = v.get("net_type") or ""

    for k, v in scraped_proxyips.items():
        if k not in existing_proxyips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org
                if c not in unrecorded_ips:
                    unrecorded_ips[c] = v.get("ip") or (k.split(":")[0] if ":" in k else "")
                if c not in unrecorded_net_types:
                    unrecorded_net_types[c] = v.get("net_type") or ""

    for k, v in scraped_proxies.items():
        if k not in existing_proxies and isinstance(v, dict):
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org
                if c not in unrecorded_ips:
                    unrecorded_ips[c] = v.get("host") or v.get("egress_ip") or (k.split(":")[0] if ":" in k else "")
                if c not in unrecorded_net_types:
                    unrecorded_net_types[c] = v.get("net_type") or ""

    unrecorded_asns = []
    for c, cnt in unrecorded_counts.most_common():
        unrecorded_asns.append({
            "asn": c,
            "org": unrecorded_orgs.get(c, ""),
            "count": cnt,
            "ip": unrecorded_ips.get(c, ""),
            "net_type": unrecorded_net_types.get(c, ""),
        })

    # 统一汇流所有自带 ASN 来源（扫描附件、反代池附件、EDT 外部多镜像源等）检测到的新未收录条目
    new_asn_records = list(unrecorded_asns)
    if edt_unrecorded_asns:
        seen_codes = {x.get("asn") for x in new_asn_records if x.get("asn")}
        for item in edt_unrecorded_asns:
            # 严格防穿透：绝不接纳 count <= 0 的幽灵条目，仅收录具有真实存活候选节点的有效 ASN
            if item.get("count", 0) <= 0:
                continue
            c = _extract_asn_code(item.get("asn"), item.get("isp") or item.get("org"))
            if c and c not in seen_codes:
                new_asn_records.append(item)
                seen_codes.add(c)

    enriched_count = 0
    if new_asn_records:
        log.info("本次抓取全源汇总检测到 %d 个自带未收录 ASN，执行统一单次批量原子持久化入库...", len(new_asn_records))
        enriched_count = auto_enrich_and_save_asns(new_asn_records, proxy=proxy)
        if enriched_count > 0:
            log.info("【批量自动持久化新 ASN】全流程批量入库完成: 本次共新收录 %d 个全新自治系统到权威库！", enriched_count)
        else:
            log.debug("【批量自动持久化新 ASN】本次全源无新 ASN 需入库（全部已在库或已去重跳过）")

    # 仅当本次实际入库了新 ASN，且节点计数 > 0，才在通知卡片中展示新收录清单；无新增或 0 条则 0 视觉噪音
    card_unrecorded = [
        item for item in new_asn_records
        if item.get("count", 0) > 0
    ] if enriched_count > 0 else []

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
        unrecorded_asns=card_unrecorded,
    )


def run_web_scraper():
    log.info("=" * 50)
    log.info("模式: 【免登录 Web 抓取模式】（公开 Web 频道预览，无需 API ID / 会话密钥）")
    log.info("本次增量回溯: 最近 %d 天", FETCH_DAYS)
    log.info("代理抓取频道: %s", ", ".join(PROXY_CHANNELS))
    log.info("优选 IP 抓取频道: %s", ", ".join(CF_IP_CHANNELS))
    
    proxy = PROXY or get_system_proxy()
    if proxy:
        log.info("网络连接: 本地代理 (%s)", proxy)
    else:
        log.info("网络连接: 直连 (Direct)")

    # 1. 预先加载本地已保存的历史节点（永久保留，单条、扫描与反代独立存放）
    existing_proxies = load_existing_proxies(OUTPUT_PROXY_FILE)
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE, label="单条优选 IP")
    existing_scan_ips = load_existing_cf_ips(OUTPUT_SCAN_FILE, label="扫描优选 IP")
    existing_proxyips = load_existing_cf_ips(OUTPUT_PROXYIP_FILE, label="反代 ProxyIP")

    tombstone = load_tombstone()
    log.info("已加载墓地黑名单: %d 个冷却中死节点（7天内淘汰）", len(tombstone))

    cutoff = datetime.now(timezone.utc) - timedelta(days=FETCH_DAYS)
    all_channels = sorted(set(PROXY_CHANNELS + CF_IP_CHANNELS))

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
                if is_tombstoned(key, tombstone):
                    continue
                if key not in scraped_proxies:
                    scraped_proxies[key] = {"url": url, "source": channel}
                    p_cnt += 1
            log.info("频道 %s 提取去重代理节点: %d 个", channel, p_cnt)

        if is_cf_target:
            cf_cnt = 0
            for item in raw_cf_ips:
                key = f"{item['ip']}:{item['port']}"
                if is_tombstoned(key, tombstone):
                    continue
                if key not in scraped_cf_ips:
                    scraped_cf_ips[key] = item
                    cf_cnt += 1
            log.info("频道 %s 提取单条优选 IP: %d 条", channel, cf_cnt)

    # 1.5 外部通用订阅源抓取 (如 VPNGate SSTP 订阅等)
    fetch_external_subscriptions(SUB_URLS, proxy, tombstone, scraped_proxies)

    # 1.6 外部 EDT-Pages 多协议代理源抓取 (HTTPS / HTTP / SOCKS5 多镜像容灾、非机房高价值过滤、元数据丰富)
    edt_unrec_all = []
    for proto_name, urls in [("https", EDT_HTTPS_URLS), ("http", EDT_HTTP_URLS), ("socks5", EDT_SOCKS5_URLS)]:
        _, unrec = fetch_edt_proxies(proto_name, urls, proxy, tombstone, scraped_proxies)
        edt_unrec_all.extend(unrec)

    # 1.7 外部 ProxyIP 聚合源抓取 (仅收录非机房原生宽带、教育、专线等高价值反代节点)
    scraped_proxyips = {}
    _, zip_unrec = fetch_zip_proxyips(PROXYIP_ZIP_URLS, proxy, tombstone, scraped_proxyips)
    edt_unrec_all.extend(zip_unrec)

    # Web 预览模式仅提取正文单条代理与优选 IP，扫描附件需 API 模式自动获取
    scraped_scan_ips = {}

    # 2. 智能增量合并并落盘保存 (统一单次原子持久化写盘)
    merge_and_save(
        existing_proxies=existing_proxies,
        scraped_proxies=scraped_proxies,
        existing_cf_ips=existing_cf_ips,
        scraped_cf_ips=scraped_cf_ips,
        existing_scan_ips=existing_scan_ips,
        scraped_scan_ips=scraped_scan_ips,
        existing_proxyips=existing_proxyips,
        scraped_proxyips=scraped_proxyips,
        edt_unrecorded_asns=edt_unrec_all,
        proxy=proxy,
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
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE, label="单条优选 IP")
    existing_scan_ips = load_existing_cf_ips(OUTPUT_SCAN_FILE, label="扫描优选 IP")
    existing_proxyips = load_existing_cf_ips(OUTPUT_PROXYIP_FILE, label="反代 ProxyIP")

    tombstone = load_tombstone()
    log.info("已加载墓地黑名单: %d 个冷却中死节点（7天内淘汰）", len(tombstone))

    client = TelegramClient(
        StringSession(TG_SESSION_STR), int(TG_API_ID), TG_API_HASH
    )

    all_channels = sorted(set(PROXY_CHANNELS + CF_IP_CHANNELS))
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
                                if is_tombstoned(key, tombstone):
                                    continue
                                if key not in scraped_proxies:
                                    scraped_proxies[key] = {"url": url, "source": channel_name}
                                    proxy_count += 1

                        # 支持自动下载并解析代理文件附件 (如 http_proxies.txt, https_proxies.txt, turn_proxies.txt 等)
                        if msg.file and msg.file.name and msg.file.name.lower().endswith(".txt"):
                            fname_lower = msg.file.name.lower()
                            if not fname_lower.startswith("otc_scan") and "proxyip" not in fname_lower and "反代" not in fname_lower and any(k in fname_lower for k in ("proxy", "proxies", "http", "turn", "socks")):
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_proxies = parse_proxy_attachment_content(doc_text)
                                        doc_added = 0
                                        for url, key in doc_proxies:
                                            if is_tombstoned(key, tombstone):
                                                continue
                                            if key not in scraped_proxies:
                                                scraped_proxies[key] = {"url": url, "source": channel_name}
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
                                if not is_tombstoned(cf_key, tombstone):
                                    if cf_key not in scraped_cf_ips:
                                        if not cf_data.get("first_seen") and msg.date:
                                            cf_data["first_seen"] = msg.date.astimezone(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S")
                                        scraped_cf_ips[cf_key] = cf_data
                                        cf_count += 1

                        # 支持自动下载并解析优选扫描附件与反代 ProxyIP 附件 (独立归入各自集合)
                        if msg.file and msg.file.name:
                            fname_lower = msg.file.name.lower()
                            # 1. 反代 ProxyIP 文件 (如 Global-proxyip-443.csv, Global-proxyip-8443.csv, OTC_SCAN_YX_CF-NRT反代.txt 等)
                            if any(k in fname_lower for k in ("proxyip", "proxy_ip", "反代")) and fname_lower.endswith((".csv", ".txt")):
                                try:
                                    doc_bytes = await client.download_media(msg, file=bytes)
                                    if doc_bytes:
                                        doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                        doc_date_str = msg.date.astimezone(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_cf_csv_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        if not doc_items:
                                            doc_items = parse_otc_scan_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if is_tombstoned(cf_key, tombstone):
                                                continue
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
                                        doc_date_str = msg.date.astimezone(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_cf_csv_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        if not doc_items:
                                            doc_items = parse_otc_scan_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if is_tombstoned(cf_key, tombstone):
                                                continue
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
                                        doc_date_str = msg.date.astimezone(TZ_BJT).strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                        doc_items = parse_otc_scan_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        if not doc_items:
                                            doc_items = parse_cf_csv_content(doc_text, default_channel=channel_name, filename=msg.file.name, dt_str=doc_date_str)
                                        doc_added = 0
                                        for cf_item in doc_items:
                                            cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                            if is_tombstoned(cf_key, tombstone):
                                                continue
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

        # 1.5 外部通用订阅源抓取 (如 VPNGate SSTP 订阅等)
        web_proxy = PROXY or get_system_proxy()
        fetch_external_subscriptions(SUB_URLS, web_proxy, tombstone, scraped_proxies)

        # 1.6 外部 EDT-Pages 多协议代理源抓取 (HTTPS / HTTP / SOCKS5 多镜像容灾、非机房高价值过滤、元数据丰富)
        edt_unrec_all = []
        for proto_name, urls in [("https", EDT_HTTPS_URLS), ("http", EDT_HTTP_URLS), ("socks5", EDT_SOCKS5_URLS)]:
            _, unrec = fetch_edt_proxies(proto_name, urls, web_proxy, tombstone, scraped_proxies)
            edt_unrec_all.extend(unrec)

        # 1.7 外部 ProxyIP 聚合源抓取 (与频道附件中提取到的 ProxyIP 增量合并，仅收录非机房)
        _, zip_unrec = fetch_zip_proxyips(PROXYIP_ZIP_URLS, web_proxy, tombstone, scraped_proxyips)
        edt_unrec_all.extend(zip_unrec)

        # 2. 智能增量合并并落盘保存 (统一单次原子持久化写盘)
        merge_and_save(
            existing_proxies=existing_proxies,
            scraped_proxies=scraped_proxies,
            existing_cf_ips=existing_cf_ips,
            scraped_cf_ips=scraped_cf_ips,
            existing_scan_ips=existing_scan_ips,
            scraped_scan_ips=scraped_scan_ips,
            existing_proxyips=existing_proxyips,
            scraped_proxyips=scraped_proxyips,
            edt_unrecorded_asns=edt_unrec_all,
            proxy=web_proxy,
        )

    finally:
        await client.disconnect()

def main():
    # 每次运行前主动清理历史可能残留的中间统计文件，杜绝历史状态回流污染
    if os.path.isfile(FETCH_STATS_FILE):
        try:
            os.remove(FETCH_STATS_FILE)
            log.debug("已清理历史遗留统计缓存: %s", FETCH_STATS_FILE)
        except OSError:
            pass

    # 主动修剪磁盘上超过 7 天的过期墓碑条目并原子持久化 (函数内已记录日志)
    prune_tombstone()

    if TG_API_ID and TG_API_HASH and TG_SESSION_STR:
        import importlib.util
        if importlib.util.find_spec("telethon") is not None:
            asyncio.run(run_telethon())
            return
        log.warning("检测到已配置 TG_API 凭据，但当前 Python 环境未安装 telethon，自动降级为【免登录 Web 模式】")

    run_web_scraper()


if __name__ == "__main__":
    main()
