#!/usr/bin/env python3
"""
TG 频道代理与 Cloudflare 优选 IP 抓取脚本（GitHub Actions 专用）

任务分工：
  1. @otcfxq: 
     - 抓取代理节点，支持：
       * 标准代理与 TURN: socks5://, http(s)://, turn://
       * 开放代理/服务通报文本: [发现开放 HTTP/HTTPS/SOCKS/TURN 代理/服务] (兼容有/无协议前缀，自动过滤测试域名)
       * TG 官方一键直连链接: tg://socks?... 与 https://t.me/socks?...（自动还原为 socks5://）
     - 抓取 Cloudflare 优选 IP
  2. @danfeng_chat: 
     - 抓取 Cloudflare 优选 IP

输出说明：
  - socks5.txt: 纯净代理节点列表（按 host:port 去重，保留最新节点）
  - cf_ips.csv: Cloudflare 优选 IP 结构化数据（UTF-8-SIG 编码，按 ip:port 覆盖去重，按最新测速时间倒序）

通知功能：
  - 任务完成后若配置了 TG_BOT_TOKEN 与 TG_CHAT_ID，自动推送运行统计到 Telegram。

需要的配置（环境变量）：
  TG_API_ID        Telegram API ID
  TG_API_HASH      Telegram API Hash
  TG_SESSION_STR   Telethon 登录会话字符串
  FETCH_DAYS       抓取最近 N 天，默认 3
  TG_BOT_TOKEN     (可选) TG 通知机器人 Token
  TG_CHAT_ID       (可选) TG 通知接收 Chat ID
"""

import os
import re
import csv
import sys
import json
import asyncio
import logging
import urllib.request
from urllib.parse import parse_qs
from datetime import datetime, timedelta, timezone

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import FloodWaitError

# Windows 事件循环策略，兼容本地调试
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ================= 配置区域 =================
TG_API_ID = os.getenv("TG_API_ID") or ""
TG_API_HASH = os.getenv("TG_API_HASH") or ""
TG_SESSION_STR = os.getenv("TG_SESSION_STR") or ""
FETCH_DAYS = int(os.getenv("FETCH_DAYS") or "3")

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""

# 目标频道与分工
PROXY_CHANNELS = ["@otcfxq"]
CF_IP_CHANNELS = ["@otcfxq", "@danfeng_chat"]

OUTPUT_PROXY_FILE = "socks5.txt"
OUTPUT_CF_FILE = "cf_ips.csv"
# ============================================

# 1. 匹配开放代理/服务通报格式（支持 HTTP/HTTPS/SOCKS/TURN，兼容带/不带协议头，如: [发现开放 HTTPS 代理] https://121.42.225.20:443#CN 或 [发现开放 TURN 服务] IP:Port）
ANNOUNCE_PROXY_RE = re.compile(
    r"\[发现开放\s*(?P<proto>HTTP|SOCKS5|SOCKS4|HTTPS|TURN)\s*(?:代理|服务)?\]\s*(?:(?:https?|socks5|socks4|turn)://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
)

# 2. 匹配 Telegram 官方 SOCKS5 一键导入直连链接（如: tg://socks?... 或 https://t.me/socks?...）
TG_SOCKS_RE = re.compile(
    r"(?:tg://socks|https?://(?:t\.me|telegram\.me)/socks)\?(?P<query>[^\s#]+)"
)

# 3. 匹配标准代理/TURN 节点 URL（支持带认证 user:pass@host:port 与免密 host:port）
PROXY_URL_RE = re.compile(
    r"(?P<url>(?P<proto>socks5|http|https|turn)://(?:[^\s#@]+@)?(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(?P<port>\d{1,5}))"
)

# CSV 输出字段定义
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


def is_valid_host(host: str) -> bool:
    """验证 IP 或域名格式是否合法"""
    parts = host.split(".")
    # 若为纯数字构成的 IPv4，检查每个段是否在 0-255
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(0 <= int(p) <= 255 for p in parts)
    # 域名必须至少有两段且顶级域名必须为纯字母（如 .com, .net, .org, .cn）
    if len(parts) >= 2 and parts[-1].isalpha() and len(parts[-1]) >= 2:
        return all(bool(re.match(r"^[a-zA-Z0-9-]+$", part)) for part in parts)
    return False


def extract_proxies(text: str) -> list:
    """
    从消息文本中提取纯净代理 URL 及去重 key
    支持:
      1. [发现开放 HTTP/HTTPS/SOCKS/TURN 代理/服务] IP:Port 通报文本（自动补全协议头，并隔离该行附带的测试域名）
      2. tg://socks?... 及 https://t.me/socks?... Telegram 官方一键直连链接，自动转换为 socks5://
      3. socks5://, http://, https://, turn:// 标准 URL
    返回: [(url, f"{host}:{port}"), ...]
    """
    results = []
    lines = text.splitlines()

    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue

        # 1. 优先检查开放代理/服务通报行（如 [发现开放 HTTPS 代理] https://... 或 [发现开放 TURN 代理] ...）
        ann_m = ANNOUNCE_PROXY_RE.search(line_s)
        if ann_m:
            proto = ann_m.group("proto").lower()
            ip = ann_m.group("ip")
            port = ann_m.group("port")
            if is_valid_host(ip) and 1 <= int(port) <= 65535:
                url = f"{proto}://{ip}:{port}"
                key = f"{ip}:{port}"
                results.append((url, key))
            # 通报行中，真实代理节点就是紧跟在通报标题后的 IP:Port，后面附带的 "域名:https://..." 是测试目标，必须跳过
            continue

        # 2. TG 官方一键直连链接（tg://socks?... 或 t.me/socks?...）
        for m in TG_SOCKS_RE.finditer(line_s):
            qs = parse_qs(m.group("query"))
            server = qs.get("server", [""])[0].strip()
            port = qs.get("port", [""])[0].strip()
            user = qs.get("user", [""])[0].strip()
            password = qs.get("pass", [""])[0].strip()
            if server and port and is_valid_host(server) and port.isdigit() and 1 <= int(port) <= 65535:
                if user or password:
                    url = f"socks5://{user}:{password}@{server}:{port}"
                else:
                    url = f"socks5://{server}:{port}"
                key = f"{server}:{port}"
                results.append((url, key))

        # 3. 标准 URL 格式（socks5://, http://, https://, turn://）
        for m in PROXY_URL_RE.finditer(line_s):
            host = m.group("host")
            port = m.group("port")
            if is_valid_host(host) and 1 <= int(port) <= 65535:
                url = m.group("url")
                key = f"{host}:{port}"
                results.append((url, key))

    return results


def parse_cf_ip(text: str, default_channel: str = "") -> dict | None:
    """
    从优选 IP 结构化消息中提取各项指标
    若文本不含有效 IP 和端口，则返回 None
    """
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


def send_tg_notification(proxies_count: int, cf_ips_count: int):
    """通过 Telegram Bot API 发送抓取结果通知汇总"""
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过机器人消息推送")
        return

    bjt = datetime.now(timezone(timedelta(hours=8)))
    date_str = bjt.strftime("%Y年%m月%d日 %H:%M:%S")

    message = (
        f"🚀 <b>节点与优选 IP 抓取完成</b>\n"
        f"------------------------------------\n"
        f"📅 <b>时间</b>：{date_str} (北京时间)\n"
        f"📥 <b>可用代理</b>：<code>{proxies_count}</code> 个（已存入 socks5.txt）\n"
        f"🌐 <b>优选 IP</b>：<code>{cf_ips_count}</code> 条（已存入 cf_ips.csv）\n"
        f"📡 <b>目标频道</b>：@otcfxq, @danfeng_chat\n"
        f"------------------------------------\n"
        f"✅ <b>状态</b>：最新数据已自动去重并更新提交！"
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


async def main():
    if not TG_API_ID or not TG_API_HASH:
        log.error("缺少 TG_API_ID 或 TG_API_HASH，请检查环境变量")
        sys.exit(1)
    if not TG_SESSION_STR:
        log.error("缺少 TG_SESSION_STR，请先运行 tg_session.py 获取会话字符串")
        sys.exit(1)

    log.info("=" * 50)
    log.info("TG 节点与优选 IP 抓取启动")
    log.info("抓取时间范围: 最近 %d 天", FETCH_DAYS)
    log.info("代理抓取频道: %s", ", ".join(PROXY_CHANNELS))
    log.info("优选 IP 抓取频道: %s", ", ".join(CF_IP_CHANNELS))

    client = TelegramClient(
        StringSession(TG_SESSION_STR), int(TG_API_ID), TG_API_HASH
    )

    all_channels = sorted(list(set(PROXY_CHANNELS + CF_IP_CHANNELS)))
    proxies_seen = {}  # key -> url
    cf_ips_seen = {}   # key -> dict

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
                # Telethon 默认从最新向最旧遍历
                async for msg in client.iter_messages(entity):
                    msg_count += 1
                    if msg.date and msg.date < cutoff:
                        log.info("已到达时间截止点 (%s)，终止该频道扫描", cutoff.strftime("%Y-%m-%d %H:%M:%S UTC"))
                        break

                    if not msg.text:
                        continue

                    # 提取代理（包含 socks5, http, https, turn, 通报格式, 以及 tg://socks 直连链接）
                    if is_proxy_target:
                        for url, key in extract_proxies(msg.text):
                            if key not in proxies_seen:
                                proxies_seen[key] = url
                                proxy_count += 1

                    # 提取优选 IP
                    if is_cf_target:
                        cf_data = parse_cf_ip(msg.text, default_channel=channel_name)
                        if cf_data:
                            cf_key = f"{cf_data['ip']}:{cf_data['port']}"
                            # 首次遇到即为该 IP:Port 的最新记录
                            if cf_key not in cf_ips_seen:
                                if not cf_data["tested_at"] and msg.date:
                                    cf_data["tested_at"] = msg.date.strftime("%Y-%m-%d %H:%M:%S")
                                cf_ips_seen[cf_key] = cf_data
                                cf_count += 1
            except FloodWaitError as e:
                log.warning("频道 %s 扫描时触发 Telegram 频控限制 (等待 %d 秒): %s", channel_name, e.seconds, e)

            log.info("频道 %s 扫描完毕: 消息 %d 条, 新增代理 %d 个, 新增优选IP %d 个", channel_name, msg_count, proxy_count, cf_count)

        log.info("=" * 50)
        log.info("全部频道扫描完成: 去重代理总数 %d, 去重优选IP总数 %d", len(proxies_seen), len(cf_ips_seen))

        # 写入 socks5.txt
        with open(OUTPUT_PROXY_FILE, "w", encoding="utf-8") as f:
            for node in proxies_seen.values():
                f.write(node + "\n")
        log.info("已写入代理文件: %s (%d 个节点)", OUTPUT_PROXY_FILE, len(proxies_seen))

        # 写入 cf_ips.csv（UTF-8-SIG 兼容 Excel 打开不乱码，按测速时间倒序排序）
        sorted_cf_ips = sorted(
            cf_ips_seen.values(),
            key=lambda item: item.get("tested_at", ""),
            reverse=True,
        )
        with open(OUTPUT_CF_FILE, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CF_CSV_FIELDS)
            writer.writeheader()
            for row in sorted_cf_ips:
                writer.writerow(row)
        log.info("已写入优选IP文件: %s (%d 条记录)", OUTPUT_CF_FILE, len(sorted_cf_ips))

        # 发送 Telegram 机器人通知
        send_tg_notification(len(proxies_seen), len(sorted_cf_ips))

        log.info("=" * 50)
        if not proxies_seen and not cf_ips_seen:
            log.warning("本次运行未提取到任何代理或优选 IP")
        else:
            log.info("抓取、保存与通知任务全部顺利完成！")

    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
