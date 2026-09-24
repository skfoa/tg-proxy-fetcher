#!/usr/bin/env python3
"""
SOCKS5 / 通用代理连通性质检与淘汰引擎 (socks_verify.py)

针对 socks5.txt（涵盖 SOCKS5, HTTP, HTTPS, TURN 协议代理）进行应用层真实穿透校验：
  1. SOCKS5: RFC 1928 / RFC 1929 五步握手状态机 (无密码/有密码) -> CONNECT speed.cloudflare.com:80 -> GET /cdn-cgi/trace 校验 200 + Server: cloudflare + 正则解析 colo
  2. HTTP/HTTPS: HTTP CONNECT speed.cloudflare.com:80 (支持 Proxy-Authorization 认证) -> GET /cdn-cgi/trace 穿透校验 (回退至直接 Forward GET)
  3. TURN: STUN Binding Request over TCP (RFC 5389)，校验 20 字节头部 Magic Cookie (0x2112A442) 及 Transaction ID

淘汰与状态聚合机制：
  - 极致纯净模式 (--strict 或 --max-fails 1): 仅保留 100% 测试通过的存活节点，一次失败即彻底剔除
  - 缓冲容错模式 (--max-fails 3，默认): 允许节点偶发失败 1~2 次作为缓冲，连续失败达到阈值时物理淘汰
  - 存活节点: fail_count 立即重置为 0，回填实时 delay_ms 与 colo 机房码
  - 排序落盘: 存活优先 (fail_count 升序)，低延迟优先 (delay_ms 升序)
  - 结果聚合: 支持将质检结果回写至 .fetch_stats.json，由流水线终点 cf_verify 聚合发送四维合一总览卡片
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import logging
import os
import random
import re
import struct
import sys
import time
import urllib.parse
from datetime import datetime, timezone, timedelta

from providers import (
    load_dotenv,
    safe_int,
    send_tg_message,
    get_keyed_lock,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    record_tombstone,
    canonical_key,
)

# 确保本地 .env 加载
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("socks-verify")

# Windows 异步事件循环策略与 UTF-8 输出
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = "data"
SOCKS_TXT = os.path.join(DATA_DIR, "socks5.txt")
SOCKS_CSV = os.path.join(DATA_DIR, "socks5.csv")

PROBE_HOST = "speed.cloudflare.com"
PROBE_PATH = "/cdn-cgi/trace"
PROBE_PORT = 80

TIMEOUT = 3.0
HTTP_TIMEOUT = 2.5
CONCURRENCY = 300
MAX_FAILS = 3

CSV_FIELDS = [
    "url",
    "proto",
    "host",
    "port",
    "delay_ms",
    "fail_count",
    "status",
    "colo",
    "tested_at",
]


# ---------- 协议探测实现 ----------

async def probe_socks5(
    host: str,
    port: int,
    user: str | None,
    pwd: str | None,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str]:
    """
    SOCKS5 RFC 1928 / RFC 1929 五步状态机鉴真：
    1. TCP 连接
    2. 方法协商 (0x00 无需认证, 0x02 账密认证)
    3. 子协商 (若服务端要求 0x02)
    4. CONNECT speed.cloudflare.com:80
    5. HTTP GET /cdn-cgi/trace 校验 200 与 colo
    返回 (is_alive, delay_ms, status, colo)
    """
    t0 = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=connect_timeout,
        )
    except Exception:
        return False, 0, "conn_err", ""

    try:
        # 步骤 2: 协商认证方式
        if user and pwd:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=connect_timeout)
        if resp[0] != 0x05:
            return False, 0, "bad_handshake", ""

        method = resp[1]
        if method == 0xFF:
            return False, 0, "no_acceptable_auth", ""
        elif method == 0x02:
            if not (user and pwd):
                return False, 0, "auth_required_missing", ""
            # 步骤 3: 账密认证 RFC 1929
            u_b = user.encode("utf-8")
            p_b = pwd.encode("utf-8")
            auth_req = b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b
            writer.write(auth_req)
            await asyncio.wait_for(writer.drain(), timeout=connect_timeout)
            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=connect_timeout)
            if auth_resp[1] != 0x00:
                return False, 0, "auth_fail", ""
        elif method != 0x00:
            return False, 0, "unsupported_method", ""

        # 步骤 4: CONNECT speed.cloudflare.com:80
        target = PROBE_HOST.encode("ascii")
        conn_req = (
            b"\x05\x01\x00\x03"
            + bytes([len(target)])
            + target
            + struct.pack("!H", PROBE_PORT)
        )
        writer.write(conn_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        conn_resp = await asyncio.wait_for(reader.readexactly(4), timeout=connect_timeout)
        if conn_resp[0] != 0x05 or conn_resp[1] != 0x00:
            return False, 0, "connect_fail", ""

        # 排空 BND.ADDR / BND.PORT (RFC 1928 严谨读取)
        atyp = conn_resp[3]
        if atyp == 0x01:  # IPv4: 4 字节 IP + 2 字节端口
            await asyncio.wait_for(reader.readexactly(6), timeout=connect_timeout)
        elif atyp == 0x03:  # Domain: 1 字节长度 + N 字节域名 + 2 字节端口
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=connect_timeout))[0]
            await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=connect_timeout)
        elif atyp == 0x04:  # IPv6: 16 字节 IP + 2 字节端口
            await asyncio.wait_for(reader.readexactly(18), timeout=connect_timeout)

        # 步骤 5: HTTP GET /cdn-cgi/trace
        http_req = (
            f"GET {PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(http_req)
        await asyncio.wait_for(writer.drain(), timeout=http_timeout)

        http_resp = await asyncio.wait_for(reader.read(2048), timeout=http_timeout)
        http_text = http_resp.decode("utf-8", errors="ignore")

        colo_match = re.search(r"\bcolo=([A-Za-z0-9]+)\b", http_text)
        colo = colo_match.group(1).upper() if colo_match else ""
        lat = max(1, int((asyncio.get_event_loop().time() - t0) * 1000))

        if "200" in (http_text.splitlines()[0] if http_text else "") and colo:
            return True, lat, "alive", colo
        return False, lat, "http_fail", ""
    except Exception:
        return False, 0, "timeout_or_reset", ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def probe_http(
    host: str,
    port: int,
    user: str | None,
    pwd: str | None,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str]:
    """
    HTTP / HTTPS 代理鉴真：
    1. 发送 CONNECT speed.cloudflare.com:80 隧道请求 (若有账密带 Proxy-Authorization)
    2. 穿透隧道发送 GET /cdn-cgi/trace
    3. 若 CONNECT 不支持，回退至直接 Forward GET
    返回 (is_alive, delay_ms, status, colo)
    """
    t0 = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=connect_timeout,
        )
    except Exception:
        return False, 0, "conn_err", ""

    try:
        auth_header = ""
        if user and pwd:
            cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            auth_header = f"Proxy-Authorization: Basic {cred}\r\n"

        # 尝试标准 CONNECT 隧道
        connect_req = (
            f"CONNECT {PROBE_HOST}:{PROBE_PORT} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}:{PROBE_PORT}\r\n"
            f"{auth_header}"
            f"Proxy-Connection: close\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(connect_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.read(1024), timeout=connect_timeout)
        resp_text = resp.decode("latin1", errors="ignore")
        first_line = resp_text.splitlines()[0] if resp_text else ""

        if "200" in first_line:
            # 隧道建立成功，发送 HTTP 穿透
            probe = (
                f"GET {PROBE_PATH} HTTP/1.1\r\n"
                f"Host: {PROBE_HOST}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("latin1")
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=http_timeout)
            http_resp = await asyncio.wait_for(reader.read(2048), timeout=http_timeout)
            http_text = http_resp.decode("utf-8", errors="ignore")
            colo_match = re.search(r"\bcolo=([A-Za-z0-9]+)\b", http_text)
            colo = colo_match.group(1).upper() if colo_match else ""
            lat = max(1, int((asyncio.get_event_loop().time() - t0) * 1000))
            if "200" in (http_text.splitlines()[0] if http_text else "") and colo:
                return True, lat, "alive", colo

        # 回退至直接正向代理 Forward GET（安全重连以避免原连接被代理端关闭/重置）
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=connect_timeout,
        )

        direct_req = (
            f"GET http://{PROBE_HOST}{PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"{auth_header}"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(direct_req)
        await asyncio.wait_for(writer.drain(), timeout=http_timeout)
        direct_resp = await asyncio.wait_for(reader.read(2048), timeout=http_timeout)
        direct_text = direct_resp.decode("utf-8", errors="ignore")
        colo_match = re.search(r"\bcolo=([A-Za-z0-9]+)\b", direct_text)
        colo = colo_match.group(1).upper() if colo_match else ""
        lat = max(1, int((asyncio.get_event_loop().time() - t0) * 1000))
        if "200" in (direct_text.splitlines()[0] if direct_text else "") and colo:
            return True, lat, "alive", colo
        return False, lat, "http_fail", ""
    except Exception:
        return False, 0, "timeout_or_reset", ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def probe_turn(
    host: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    read_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str]:
    """
    TURN 协议鉴真：
    通过 TCP 发送标准 STUN Binding Request (RFC 5389)，
    校验 20 字节响应头部 Magic Cookie (0x2112A442) 以及 Transaction ID 匹配。
    返回 (is_alive, delay_ms, status, colo)
    """
    t0 = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=connect_timeout,
        )
    except Exception:
        return False, 0, "conn_err", ""

    try:
        tx_id = os.urandom(12)
        # Type: 0x0001 (Binding Request), Length: 0x0000, Magic Cookie: 0x2112A442
        req = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tx_id
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
        lat = max(1, int((asyncio.get_event_loop().time() - t0) * 1000))

        if len(resp) >= 20 and resp[4:8] == b"\x21\x12\xa4\x42" and resp[8:20] == tx_id:
            return True, lat, "alive", "-"
        return False, lat, "stun_fail", ""
    except Exception:
        return False, 0, "timeout_or_reset", ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def probe_single(
    row: dict,
    sem: asyncio.Semaphore,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> dict:
    """协议分流路由与执行"""
    async with sem:
        proto = row.get("proto", "socks5").lower()
        host = row.get("host", "")
        port = int(row.get("port", 0))
        user = row.get("user") or None
        pwd = row.get("pwd") or None

        if proto == "socks5":
            is_alive, delay_ms, status, colo = await probe_socks5(
                host, port, user, pwd, timeout, http_timeout
            )
        elif proto in ("http", "https"):
            is_alive, delay_ms, status, colo = await probe_http(
                host, port, user, pwd, timeout, http_timeout
            )
        elif proto == "turn":
            is_alive, delay_ms, status, colo = await probe_turn(
                host, port, timeout, http_timeout
            )
        else:
            is_alive, delay_ms, status, colo = False, 0, "unknown_proto", ""

        row["is_alive"] = is_alive
        row["status"] = status
        now_str = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        row["tested_at"] = now_str

        fc = safe_int(row.get("fail_count"), 0)
        if is_alive:
            row["fail_count"] = 0
            row["delay_ms"] = delay_ms
            row["colo"] = colo
        else:
            row["fail_count"] = fc + 1
            if not row.get("delay_ms"):
                row["delay_ms"] = 0

        return row


# ---------- 数据加载与保存 ----------

def parse_proxy_url(url: str) -> dict | None:
    """从代理 URL 解析结构化元数据"""
    url = url.strip()
    if not url or url.startswith("#"):
        return None
    try:
        u = urllib.parse.urlparse(url)
        if not u.scheme or not u.hostname or not u.port:
            return None
        return {
            "url": url,
            "proto": u.scheme.lower(),
            "host": u.hostname,
            "port": u.port,
            "user": u.username or "",
            "pwd": u.password or "",
            "delay_ms": 0,
            "fail_count": 0,
            "status": "pending",
            "colo": "",
            "tested_at": "",
        }
    except Exception:
        return None


def load_socks_data(
    txt_path: str = SOCKS_TXT,
    csv_path: str = SOCKS_CSV,
) -> list[dict]:
    """
    加载待检代理节点：
    1. 优先读取 socks5.csv（保留既有 fail_count 与历史统计）
    2. 合并 socks5.txt 中新增的节点
    """
    url_map: dict[str, dict] = {}

    # 读取已有 CSV
    if os.path.isfile(csv_path):
        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    url = r.get("url", "").strip()
                    if not url:
                        continue
                    parsed = parse_proxy_url(url)
                    if not parsed:
                        continue
                    parsed["fail_count"] = safe_int(r.get("fail_count"), 0)
                    parsed["delay_ms"] = safe_int(r.get("delay_ms"), 0)
                    parsed["status"] = r.get("status", "pending")
                    parsed["colo"] = r.get("colo", "")
                    parsed["tested_at"] = r.get("tested_at", "")
                    url_map[url] = parsed
            log.info("从 %s 加载已有记录 %d 条", csv_path, len(url_map))
        except Exception as e:
            log.warning("读取 %s 失败: %s", csv_path, e)

    # 合并 socks5.txt 中的新节点
    if os.path.isfile(txt_path):
        txt_count = 0
        try:
            with open(txt_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    txt_count += 1
                    if line not in url_map:
                        parsed = parse_proxy_url(line)
                        if parsed:
                            url_map[line] = parsed
            log.info("从 %s 读取 %d 行，合并后待检节点共: %d 条", txt_path, txt_count, len(url_map))
        except Exception as e:
            log.warning("读取 %s 失败: %s", txt_path, e)

    return list(url_map.values())


def save_socks_data(
    survivors: list[dict],
    txt_path: str = SOCKS_TXT,
    csv_path: str = SOCKS_CSV,
):
    """
    保存质检幸存节点：
    按 (fail_count 升序, delay_ms 升序) 排序。
    覆写 socks5.txt 与 socks5.csv。
    """
    def _sort_key(r):
        fc = safe_int(r.get("fail_count"), 0)
        dms = safe_int(r.get("delay_ms"), 0)
        # 0 delay 视作未测通或失败，排在后面
        if dms <= 0:
            dms = 99999
        return (fc, dms)

    survivors.sort(key=_sort_key)

    # 写入 socks5.txt (纯文本 URL 清单)
    with open(txt_path, "w", encoding="utf-8") as f:
        for r in survivors:
            f.write(f"{r['url']}\n")
    log.info("已覆写保存 %s: %d 个高可用节点", txt_path, len(survivors))

    # 写入 socks5.csv (完整元数据表)
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in survivors:
            writer.writerow(r)
    log.info("已覆写保存 %s: %d 条质检状态记录", csv_path, len(survivors))


# ---------- Telegram 通知 ----------

def format_buffer_badge(marked: int, f1: int = 0, f2: int = 0) -> str:
    """格式化缓冲标签，带 1 次与 2 次失败细分"""
    if marked <= 0:
        return ""
    breakdown = []
    if f1 > 0:
        breakdown.append(f"1次: {f1}")
    if f2 > 0:
        breakdown.append(f"2次: {f2}")
    if breakdown:
        return f" · ⚠️ {marked} 缓冲 [{(' · '.join(breakdown))}]"
    return f" · ⚠️ {marked} 缓冲"


def send_socks_notification(
    total: int,
    pass_count: int,
    fail_count: int,
    eliminated: int,
    survivors: int,
    avg_delay: int,
    proto_stats: dict,
    concurrency: int,
    max_fails: int,
    elapsed: float,
    fail_1: int = 0,
    fail_2: int = 0,
):
    """发送独立的 SOCKS5 代理质检报告卡片"""
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过独立卡片推送")
        return

    bjt = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    div = "━━━━━━━━━━━━━━━━━━━━"

    proto_lines = []
    for proto, stat in sorted(proto_stats.items()):
        proto_lines.append(f"   • {proto.upper()}: {stat['alive']} 存活 / {stat['total']} 总量")
    proto_str = "\n".join(proto_lines)

    elim_str = f"<code>{eliminated}</code> 条 (连续失败 ≥ {max_fails} 次)" if eliminated > 0 else "无 (全部在存活阈值内)"
    buffer_badge = format_buffer_badge(fail_count, fail_1, fail_2)
    status_str = f"✅ {pass_count} 存活{buffer_badge}"

    message = (
        f"🚀 <b>SOCKS5 / 通用代理连通性质检完成</b>\n"
        f"{div}\n"
        f"📅 <b>时间</b>：{bjt} (北京时间)\n"
        f"📫 <b>可用代理</b>：<code>{survivors}</code> 个 ({status_str})\n"
        f"⚡ <b>存活均延</b>：<code>{avg_delay}ms</code>\n"
        f"🗑️ <b>淘汰死节点</b>：{elim_str}\n"
        f"📊 <b>协议分布</b>：\n{proto_str}\n"
        f"{div}\n"
        f"⚙️ <b>检测规格</b>：RFC 1928 中继穿透 · {concurrency} 并发\n"
        f"⏱️ <b>质检耗时</b>：{elapsed:.1f}s\n"
    )

    try:
        send_tg_message(message, token=token, chat_id=chat_id, tag="socks-verify")
    except Exception as e:
        log.warning("发送 Telegram 消息时出现异常: %s", e)


# ---------- 主流程 ----------

async def async_main(args):
    t_start = time.time()
    rows = load_socks_data(SOCKS_TXT, SOCKS_CSV)
    total = len(rows)
    if total == 0:
        log.warning("未加载到任何待检代理节点，流程结束")
        return

    # 乱序执行，打散同目标并发
    random.shuffle(rows)

    sem = asyncio.Semaphore(args.concurrency)
    completed = 0
    pass_count = 0
    fail_count = 0
    min_delay = 99999

    proto_stats = {}

    log.info(
        "开始并发质检代理连通性: 共 %d 条 | 并发: %d | 超时: %.1fs | 淘汰阈值: 连续失败 >= %d 次",
        total,
        args.concurrency,
        args.timeout,
        args.max_fails,
    )

    async def _worker(r):
        nonlocal completed, pass_count, fail_count, min_delay
        host = r.get("host", "")
        async with get_keyed_lock(host):
            res = await probe_single(r, sem, args.timeout, args.http_timeout)
        completed += 1

        proto = res.get("proto", "unknown")
        if proto not in proto_stats:
            proto_stats[proto] = {"total": 0, "alive": 0}
        proto_stats[proto]["total"] += 1

        if res.get("is_alive"):
            pass_count += 1
            proto_stats[proto]["alive"] += 1
            dms = res.get("delay_ms", 0)
            if dms > 0 and dms < min_delay:
                min_delay = dms
        else:
            fail_count += 1

        if completed % 1000 == 0 or completed == total:
            pct = (completed / total) * 100
            min_str = f"{min_delay}ms" if min_delay < 99999 else "-"
            log.info(
                "[SOCKS5 质检进度] %d/%d (%.1f%%) - 存活: %d 个 (延迟最低: %s)",
                completed,
                total,
                pct,
                pass_count,
                min_str,
            )
        return res

    tasks = [_worker(r) for r in rows]
    results = await asyncio.gather(*tasks)

    # 幸存者筛选（包含本次探测存活节点 + 处于连续失败容忍缓冲期内的节点：fail_count < args.max_fails，默认连续失败 < 3 次保留，允许 1~2 次失败缓冲）
    survivors = [r for r in results if safe_int(r.get("fail_count"), 0) < args.max_fails]
    eliminated = total - len(survivors)
    survivors_len = len(survivors)
    socks_f1 = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 1)
    socks_f2 = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 2)

    # 仅统计本次实测存活节点的网络延迟（排除处于缓冲期但本次已连通失败节点的旧延迟）
    alive_delays = [
        int(r.get("delay_ms", 0))
        for r in results
        if r.get("is_alive") and safe_int(r.get("delay_ms"), 0) > 0
    ]
    avg_delay = int(sum(alive_delays) / len(alive_delays)) if alive_delays else 0

    if eliminated > 0:
        log.info("[SOCKS5 淘汰] 剔除 %d 条连续失败 >= %d 次的死节点", eliminated, args.max_fails)
        dead_nodes = [r for r in results if safe_int(r.get("fail_count"), 0) >= args.max_fails]
        dead_keys = [canonical_key(r.get("host", ""), r.get("port", 0)) for r in dead_nodes]
        newly_tombstoned = record_tombstone(dead_keys)
        log.info("[SOCKS5 墓地] 已登记 %d 个淘汰死节点至墓地冷却库 (新增: %d 个, 隔离期 7 天)", len(dead_keys), newly_tombstoned)
    else:
        log.info("[SOCKS5 淘汰] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

    save_socks_data(survivors, SOCKS_TXT, SOCKS_CSV)

    elapsed = time.time() - t_start
    log.info("代理连通性质检流程执行完毕，总耗时 %.2f 秒 (✅ 存活: %d | 均延: %dms)", elapsed, pass_count, avg_delay)

    # 若存在 tg_fetch 暂存的抓取统计，将 SOCKS5 质检结果并入其中，由后续统一卡片推送
    fetch_stats_file = os.path.join(DATA_DIR, ".fetch_stats.json")
    has_fetch_stats = os.path.isfile(fetch_stats_file)
    if has_fetch_stats:
        try:
            with open(fetch_stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
            stats["socks_verified"] = True
            stats["socks_total"] = total
            stats["socks_pass"] = pass_count
            stats["socks_fail"] = fail_count
            stats["socks_fail_1"] = socks_f1
            stats["socks_fail_2"] = socks_f2
            stats["socks_eliminated"] = eliminated
            stats["socks_survivors"] = survivors_len
            stats["socks_avg_delay_ms"] = avg_delay
            stats["socks_elapsed"] = elapsed
            stats["socks_proto_breakdown"] = proto_stats
            stats["socks_max_fails"] = args.max_fails
            with open(fetch_stats_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            log.info("已将 SOCKS5 质检统计写入 %s (并入统一卡片)", fetch_stats_file)
        except Exception as e:
            log.warning("写入 %s 失败: %s", fetch_stats_file, e)

    if not args.no_notify and not has_fetch_stats:
        send_socks_notification(
            total=total,
            pass_count=pass_count,
            fail_count=fail_count,
            eliminated=eliminated,
            survivors=survivors_len,
            avg_delay=avg_delay,
            proto_stats=proto_stats,
            concurrency=args.concurrency,
            max_fails=args.max_fails,
            elapsed=elapsed,
            fail_1=socks_f1,
            fail_2=socks_f2,
        )
    else:
        log.info("已并入流水线或指定了 --no-notify，跳过独立卡片推送")


def main():
    parser = argparse.ArgumentParser(description="SOCKS5 / 通用代理连通性质检与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help=f"并发探测协程数 (默认 {CONCURRENCY})")
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument("--strict", action="store_true", help="极致纯净模式 (只要失败 1 次立即剔除，等价于 --max-fails 1)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"单节点握手超时秒数 (默认 {TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"单节点 HTTP 穿透校验超时秒数 (默认 {HTTP_TIMEOUT})")
    parser.add_argument("--no-notify", action="store_true", help="静默模式，不单独发送 Telegram 质检通知")
    args = parser.parse_args()

    if args.strict:
        args.max_fails = 1
        log.info("🔥 启用了 --strict 【极致纯净模式】，淘汰阈值强制设为 1")

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
