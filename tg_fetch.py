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
OUTPUT_CF_TXT = "cf_ips.txt"  # 纯净 IP:端口 文本列表，专供 edgetunnel / 各种优选工具一键复制导入
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


def parse_otc_scan_content(text: str, default_channel: str = "@otcfxq", dt_str: str = "") -> list[dict]:
    """解析 OTC 优选扫描导出的 CSV 格式文件内容 (OTC_SCAN_YX_*.txt)"""
    results = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        ip = parts[0]
        port_str = parts[1]
        if not is_valid_host(ip) or not port_str.isdigit():
            continue
        port = int(port_str)
        if not (1 <= port <= 65535):
            continue

        asn = parts[3]
        isp = parts[4]
        colo_loc = parts[5]

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


def load_local_import_ips(import_dir: str = "import_ips") -> dict:
    """扫描本地 import_ips 目录或项目根目录下的 OTC_SCAN_*.txt 文件并自动解析导入"""
    imported = {}
    files_to_check = set()

    # 1. 检查 import_ips 文件夹
    if os.path.isdir(import_dir):
        for fname in os.listdir(import_dir):
            if fname.lower().endswith(".txt"):
                files_to_check.add(os.path.join(import_dir, fname))

    # 2. 检查根目录下匹配 OTC_SCAN*.txt 的文件
    for fname in os.listdir("."):
        if fname.startswith("OTC_SCAN") and fname.lower().endswith(".txt"):
            files_to_check.add(fname)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath), timezone.utc)
            mtime_bjt = mtime.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
            items = parse_otc_scan_content(content, default_channel="@otcfxq", dt_str=mtime_bjt)
            for item in items:
                key = f"{item['ip']}:{item['port']}"
                imported[key] = item
            if items:
                log.info("从本地文件 %s 中导入 %d 条优选 IP 记录", fpath, len(items))
        except Exception as e:
            log.warning("读取本地文件 %s 失败: %s", fpath, e)

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
    new_proxies: int = 0,
    updated_proxies: int = 0,
    new_cf: int = 0,
    updated_cf: int = 0,
):
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过机器人消息推送")
        return

    bjt = datetime.now(timezone(timedelta(hours=8)))
    date_str = bjt.strftime("%Y年%m月%d日 %H:%M:%S")

    message = (
        f"🚀 <b>节点与优选 IP 增量同步完成</b>\n"
        f"------------------------------------\n"
        f"📅 <b>时间</b>：{date_str} (北京时间)\n"
        f"📫 <b>可用代理</b>：总计 <code>{proxies_count}</code> 个 (新增: {new_proxies}, 刷新: {updated_proxies})\n"
        f"🌐 <b>优选 IP</b>：总计 <code>{cf_ips_count}</code> 条 (新增: {new_cf}, 刷新: {updated_cf})\n"
        f"📡 <b>目标频道</b>：@otcfxq, @danfeng2\n"
        f"------------------------------------\n"
        f"✅ <b>持久化策略</b>：只增不减，历史节点全量保留，重复节点智能更新！"
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
    new_proxies_count: int = 0,
    updated_proxies_count: int = 0,
    new_cf_count: int = 0,
    updated_cf_count: int = 0,
):
    with open(OUTPUT_PROXY_FILE, "w", encoding="utf-8") as f:
        for node in final_proxies.values():
            f.write(node + "\n")
    log.info("已保存代理文件: %s (%d 个全量累积节点)", OUTPUT_PROXY_FILE, len(final_proxies))

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
    log.info("已保存优选IP文件: %s (%d 条全量累积记录)", OUTPUT_CF_FILE, len(sorted_cf_ips))

    # 写入 cf_ips.txt（行业通用标准 IP:Port 纯文本列表）
    with open(OUTPUT_CF_TXT, "w", encoding="utf-8") as f:
        for row in sorted_cf_ips:
            f.write(f"{row['ip']}:{row['port']}\n")
    log.info("已保存优选IP纯文本: %s (%d 行 IP:Port)", OUTPUT_CF_TXT, len(sorted_cf_ips))

    send_tg_notification(
        len(final_proxies),
        len(sorted_cf_ips),
        new_proxies=new_proxies_count,
        updated_proxies=updated_proxies_count,
        new_cf=new_cf_count,
        updated_cf=updated_cf_count,
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
        log.info("网络代理: %s", proxy)
    else:
        log.info("网络连接: 直连 (Direct)")

    # 1. 预先加载本地已保存的历史节点（永久保留，只增不减！）
    existing_proxies = load_existing_proxies(OUTPUT_PROXY_FILE)
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE)

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
            log.info("频道 %s 提取去重优选 IP: %d 条", channel, cf_cnt)

    # 1.5 加载本地待导入文件（若有 OTC_SCAN*.txt 等）
    local_imported_ips = load_local_import_ips()
    if local_imported_ips:
        scraped_cf_ips = {**scraped_cf_ips, **local_imported_ips}

    # 2. 智能增量合并：历史保留，重复更新，新增追加
    new_proxy_cnt = sum(1 for k in scraped_proxies if k not in existing_proxies)
    updated_proxy_cnt = sum(1 for k in scraped_proxies if k in existing_proxies)
    
    new_cf_cnt = sum(1 for k in scraped_cf_ips if k not in existing_cf_ips)
    updated_cf_cnt = sum(1 for k in scraped_cf_ips if k in existing_cf_ips)

    final_proxies = {**existing_proxies, **scraped_proxies}
    final_cf_ips = {**existing_cf_ips, **scraped_cf_ips}

    log.info("=" * 50)
    log.info("代理节点增量合并: 历史保留 %d 个, 本次新增 %d 个, 本次更新 %d 个 -> 全量总计 %d 个", 
             len(existing_proxies) - updated_proxy_cnt, new_proxy_cnt, updated_proxy_cnt, len(final_proxies))
    log.info("优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
             len(existing_cf_ips) - updated_cf_cnt, new_cf_cnt, updated_cf_cnt, len(final_cf_ips))

    save_and_notify(
        final_proxies,
        final_cf_ips,
        new_proxies_count=new_proxy_cnt,
        updated_proxies_count=updated_proxy_cnt,
        new_cf_count=new_cf_cnt,
        updated_cf_count=updated_cf_cnt,
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

    # 1. 预先加载本地已保存的历史节点（永久保留，只增不减！）
    existing_proxies = load_existing_proxies(OUTPUT_PROXY_FILE)
    existing_cf_ips = load_existing_cf_ips(OUTPUT_CF_FILE)

    client = TelegramClient(
        StringSession(TG_SESSION_STR), int(TG_API_ID), TG_API_HASH
    )

    all_channels = sorted(list(set(PROXY_CHANNELS + CF_IP_CHANNELS)))
    scraped_proxies = {}
    scraped_cf_ips = {}

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

            try:
                async for msg in client.iter_messages(entity):
                    msg_count += 1
                    if msg.date and msg.date < cutoff:
                        log.info("已到达时间截止点 (%s)，终止该频道扫描", cutoff.strftime("%Y-%m-%d %H:%M:%S UTC"))
                        break

                    if not msg.text:
                        continue

                    if is_proxy_target:
                        for url, key in extract_proxies(msg.text):
                            if key not in scraped_proxies:
                                scraped_proxies[key] = url
                                proxy_count += 1

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

                        # 支持自动下载并解析 .txt 附件 (如 OTC_SCAN_YX_*.txt)
                        if msg.file and msg.file.name and msg.file.name.lower().endswith(".txt"):
                            try:
                                doc_bytes = await client.download_media(msg, file=bytes)
                                if doc_bytes:
                                    doc_text = doc_bytes.decode("utf-8", errors="ignore")
                                    doc_date_str = msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else ""
                                    doc_items = parse_otc_scan_content(doc_text, default_channel=channel_name, dt_str=doc_date_str)
                                    doc_added = 0
                                    for cf_item in doc_items:
                                        cf_key = f"{cf_item['ip']}:{cf_item['port']}"
                                        if cf_key not in scraped_cf_ips:
                                            scraped_cf_ips[cf_key] = cf_item
                                            cf_count += 1
                                            doc_added += 1
                                    log.info("从频道 %s 附件 %s 中提取 %d 条优选 IP", channel_name, msg.file.name, doc_added)
                            except Exception as e:
                                log.warning("下载/解析频道 %s 附件 %s 失败: %s", channel_name, msg.file.name, e)
            except FloodWaitError as e:
                log.warning("频道 %s 扫描时触发 Telegram 频控限制 (等待 %d 秒): %s", channel_name, e.seconds, e)

            log.info("频道 %s 扫描完毕: 消息 %d 条, 新增代理 %d 个, 新增优选IP %d 个", channel_name, msg_count, proxy_count, cf_count)

        # 1.5 加载本地待导入文件（若有 OTC_SCAN*.txt 等）
        local_imported_ips = load_local_import_ips()
        if local_imported_ips:
            scraped_cf_ips = {**scraped_cf_ips, **local_imported_ips}

        # 2. 智能增量合并
        new_proxy_cnt = sum(1 for k in scraped_proxies if k not in existing_proxies)
        updated_proxy_cnt = sum(1 for k in scraped_proxies if k in existing_proxies)
        
        new_cf_cnt = sum(1 for k in scraped_cf_ips if k not in existing_cf_ips)
        updated_cf_cnt = sum(1 for k in scraped_cf_ips if k in existing_cf_ips)

        final_proxies = {**existing_proxies, **scraped_proxies}
        final_cf_ips = {**existing_cf_ips, **scraped_cf_ips}

        log.info("=" * 50)
        log.info("代理节点增量合并: 历史保留 %d 个, 本次新增 %d 个, 本次更新 %d 个 -> 全量总计 %d 个", 
                 len(existing_proxies) - updated_proxy_cnt, new_proxy_cnt, updated_proxy_cnt, len(final_proxies))
        log.info("优选 IP 增量合并: 历史保留 %d 条, 本次新增 %d 条, 本次更新 %d 条 -> 全量总计 %d 条", 
                 len(existing_cf_ips) - updated_cf_cnt, new_cf_cnt, updated_cf_cnt, len(final_cf_ips))

        save_and_notify(
        final_proxies,
        final_cf_ips,
        new_proxies_count=new_proxy_cnt,
        updated_proxies_count=updated_proxy_cnt,
        new_cf_count=new_cf_cnt,
        updated_cf_count=updated_cf_cnt,
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
