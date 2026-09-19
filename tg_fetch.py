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
from providers import (
    load_dotenv,
    safe_int,
    clean_asn,
    send_tg_message,
    ASN_TO_PROVIDER,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    format_categorized_proxyip_txt,
    save_proxyip_by_country,
    classify_asn,
    is_asn_recorded,
    _extract_asn_code,
    normalize_timestamp,
)
from parsers import (
    extract_proxies,
    parse_cf_ip,
    parse_cf_csv_content,
    parse_otc_scan_content,
    parse_proxy_attachment_content,
)

# 确保本地 .env 加载
load_dotenv()

TG_API_ID = os.getenv("TG_API_ID") or ""
TG_API_HASH = os.getenv("TG_API_HASH") or ""
TG_SESSION_STR = os.getenv("TG_SESSION_STR") or ""
FETCH_DAYS = int(os.getenv("FETCH_DAYS") or "3")
PROXY = os.getenv("PROXY") or os.getenv("ALL_PROXY") or os.getenv("HTTPS_PROXY") or ""

PROXY_CHANNELS = ["@otcfxq"]
CF_IP_CHANNELS = ["@otcfxq", "@danfeng2"]

DATA_DIR = "data"
OUTPUT_PROXY_FILE = os.path.join(DATA_DIR, "socks5.txt")
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
    "isp",
    "asn",
    "tested_at",
    "channel",
    "fail_count",
]
PROXYIP_CSV_FIELDS = CF_CSV_FIELDS + ["cf_clean", "net_type"]

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
                    row["fail_count"] = safe_int(row.get("fail_count"), 0)
                    row["tested_at"] = normalize_timestamp(row.get("tested_at", ""))
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
    unrecorded_asns: list = None,
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
            with open(FETCH_STATS_FILE, "w", encoding="utf-8") as sf:
                json.dump(stats_data, sf, ensure_ascii=False, indent=2)
            log.info("已将抓取阶段统计暂存至 %s (等待优选 IP 校验后统一推送)", FETCH_STATS_FILE)
            return
        except Exception as e:
            log.warning("暂存 %s 失败，将直接尝试推送: %s", FETCH_STATS_FILE, e)

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
        proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{proxyips_count}</code> 条 ({proxyip_diff})\n"

    unmatched_block = ""
    if unrecorded_asns:
        items = []
        for item in unrecorded_asns[:4]:
            c = item.get("asn", "")
            o = item.get("org", "").strip()
            cnt = item.get("count", 0)
            name_str = f" {o}" if o else ""
            items.append(f"   • <code>{c}</code>{name_str} ({cnt} 条)")
        suffix = f"\n   └ <i>共 {len(unrecorded_asns)} 个待确认归属</i>" if len(unrecorded_asns) > 4 else ""
        unmatched_block = "💡 <b>发现未收录 ASN (可补充入库)</b>：\n" + "\n".join(items) + suffix + "\n"

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
    unrecorded_asns: list = None,
):
    # 1. 保存代理节点
    os.makedirs(DATA_DIR, exist_ok=True)
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
        writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in sorted_cf_ips:
            row.setdefault("fail_count", 0)
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
            asn_clean = clean_asn(row.get("asn"), row.get("isp"))
            row["asn"] = asn_clean
            asn_groups[asn_clean].append(row)

        asn_groups_total = len(asn_groups)

        all_sorted_scan_rows = []
        for asn_name in sorted(asn_groups.keys()):
            group_rows = sorted(asn_groups[asn_name], key=lambda x: x.get("tested_at", ""), reverse=True)
            all_sorted_scan_rows.extend(group_rows)

        with open(OUTPUT_SCAN_FILE, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in all_sorted_scan_rows:
                row.setdefault("fail_count", 0)
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
            writer = csv.DictWriter(f, fieldnames=PROXYIP_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in sorted_proxyips:
                row.setdefault("fail_count", 0)
                row.setdefault("cf_clean", "")
                row["net_type"] = classify_asn(row.get("asn", ""), row.get("isp", ""))
                writer.writerow(row)
        log.info("已保存反代 ProxyIP 表格: %s (%d 条全量累积记录)", OUTPUT_PROXYIP_FILE, len(sorted_proxyips))

        with open(OUTPUT_PROXYIP_TXT, "w", encoding="utf-8") as f:
            f.write(format_categorized_proxyip_txt(sorted_proxyips))
        log.info("已保存反代 ProxyIP 纯文本: %s (%d 行/条记录，已按国家地区分类)", OUTPUT_PROXYIP_TXT, len(sorted_proxyips))

        proxyip_split_cnt = save_proxyip_by_country(sorted_proxyips, OUTPUT_PROXYIP_DIR)
        log.info("已在 %s/ 目录下生成 %d 个独立国家/地区纯文本文件", OUTPUT_PROXYIP_DIR, proxyip_split_cnt)

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
        unrecorded_asns=unrecorded_asns,
    )

    log.info("=" * 50)
    log.info("抓取、增量合并、保存与通知任务全部顺利完成！")


def merge_and_save(
    existing_proxies: dict,
    scraped_proxies: dict,
    existing_cf_ips: dict,
    scraped_cf_ips: dict,
    existing_scan_ips: dict = None,
    scraped_scan_ips: dict = None,
    existing_proxyips: dict = None,
    scraped_proxyips: dict = None,
):
    """
    智能增量合并：历史保留，重复更新，新增追加，并持久化落盘与发送通知。
    供 Web 免登录抓取模式与 Telethon API 抓取模式统一复用。
    """
    existing_scan_ips = existing_scan_ips or {}
    scraped_scan_ips = scraped_scan_ips or {}
    existing_proxyips = existing_proxyips or {}
    scraped_proxyips = scraped_proxyips or {}

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
    final_proxyips = dict(existing_proxyips)
    for k, v in scraped_proxyips.items():
        if k in final_proxyips:
            if not v.get("cf_clean") and final_proxyips[k].get("cf_clean"):
                v["cf_clean"] = final_proxyips[k]["cf_clean"]
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

    for k, v in scraped_scan_ips.items():
        if k not in existing_scan_ips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org

    for k, v in scraped_cf_ips.items():
        if k not in existing_cf_ips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org

    for k, v in scraped_proxyips.items():
        if k not in existing_proxyips:
            c = _extract_asn_code(v.get("asn"), v.get("isp"))
            if c and not is_asn_recorded(c):
                unrecorded_counts[c] += 1
                if c not in unrecorded_orgs:
                    org = v.get("isp") or v.get("asn") or ""
                    org = re.sub(r"^AS\d+\s*", "", org, flags=re.IGNORECASE).strip()
                    unrecorded_orgs[c] = org

    unrecorded_asns = []
    for c, cnt in unrecorded_counts.most_common():
        unrecorded_asns.append({
            "asn": c,
            "org": unrecorded_orgs.get(c, ""),
            "count": cnt,
        })
    if unrecorded_asns:
        log.info("本次新增节点中检测到 %d 个未收录 ASN: %s", len(unrecorded_asns), ", ".join(f"{x['asn']}({x['count']})" for x in unrecorded_asns[:5]))

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
        unrecorded_asns=unrecorded_asns,
    )


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

    # Web 预览模式仅提取正文单条代理与优选 IP，扫描附件与反代大池需 API 模式自动获取
    scraped_scan_ips = {}
    scraped_proxyips = {}

    # 2. 智能增量合并并落盘保存
    merge_and_save(
        existing_proxies=existing_proxies,
        scraped_proxies=scraped_proxies,
        existing_cf_ips=existing_cf_ips,
        scraped_cf_ips=scraped_cf_ips,
        existing_scan_ips=existing_scan_ips,
        scraped_scan_ips=scraped_scan_ips,
        existing_proxyips=existing_proxyips,
        scraped_proxyips=scraped_proxyips,
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
                            if not fname_lower.startswith("otc_scan") and "proxyip" not in fname_lower and any(k in fname_lower for k in ("proxy", "proxies", "http", "turn", "socks")):
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

        # 2. 智能增量合并并落盘保存
        merge_and_save(
            existing_proxies=existing_proxies,
            scraped_proxies=scraped_proxies,
            existing_cf_ips=existing_cf_ips,
            scraped_cf_ips=scraped_cf_ips,
            existing_scan_ips=existing_scan_ips,
            scraped_scan_ips=scraped_scan_ips,
            existing_proxyips=existing_proxyips,
            scraped_proxyips=scraped_proxyips,
        )

    finally:
        await client.disconnect()

def main():
    if TG_API_ID and TG_API_HASH and TG_SESSION_STR:
        import importlib.util
        if importlib.util.find_spec("telethon") is not None:
            asyncio.run(run_telethon())
            return
        log.warning("检测到已配置 TG_API 凭据，但当前 Python 环境未安装 telethon，自动降级为【免登录 Web 模式】")

    run_web_scraper()


if __name__ == "__main__":
    main()
