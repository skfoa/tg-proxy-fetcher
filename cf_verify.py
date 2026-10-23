#!/usr/bin/env python3
"""
Cloudflare 优选 IP 两阶段主动校验与淘汰引擎 (cf_verify.py)

只要是优选 IP（涵盖 scan_ips 与 cf_ips 全线产物），全部统一执行：
  阶段一：TLS 握手 + CA 证书鉴真（server_hostname=crypto.cloudflare.com 官方证书链，底层校验 Root CA 与 SAN 匹配）
  阶段二：同一连接发送 HTTP 请求，基于统一 deadline 与 4096B 上限循环读取，经双兼容分隔符隔离 Header 与 Body，
          字节级正则匹配状态行 HTTP/X.X 301 与 Server: cloudflare，确认 Cloudflare 边缘重定向行为。

淘汰与全流水线汇总机制：
  1. 物理淘汰：连续失败达到阈值（默认 3 次）的死节点，全面从所有产物中永久删除：
     - scan_ips.csv、scan_ips.txt、scan_ips/*.txt (独立机房分组文本)
     - cf_ips.csv、cf_ips.txt (单条优选数据表与纯文本清单)
  2. 四维合一卡片推送：流水线末尾自动聚合 tg_fetch、proxies_verify、proxyip_verify（各引擎均为连续失败 ≥3 次淘汰）与自身结果，
     向 Telegram 发送全流水线统一统计、分引擎淘汰明细以及动态未收录 ASN 提示卡片。
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import random
import re
import ssl
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from providers import (
    load_dotenv,
    safe_int,
    clean_asn,
    format_asn_isp,
    send_tg_message,
    normalize_timestamp,
    load_ip_cache,
    ASN_TO_PROVIDER,
    get_keyed_lock,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    record_tombstone,
    load_tombstone,
    is_tombstoned,
    canonical_key,
    format_scan_ips_txt,
    RE_HTTP_301,
    RE_SERVER_CF,
    RE_CF_RAY,
    RE_CF_1034,
    RE_NON_CF_FASTLY,
    RE_NON_CF_AKAMAI,
    read_full_response,
    safe_close_writer,
    split_header_body,
    format_buffer_badge,
    format_diff,
    save_scan_ips_by_asn as save_scan_dir,
    atomic_writer,
    atomic_write_text,
)

# 确保本地 .env 加载
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cf-verify")

# Windows 异步事件循环策略与 UTF-8 输出
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = "data"
SCAN_CSV = os.path.join(DATA_DIR, "scan_ips.csv")
SCAN_TXT = os.path.join(DATA_DIR, "scan_ips.txt")
SCAN_DIR = os.path.join(DATA_DIR, "scan_ips")

CF_CSV = os.path.join(DATA_DIR, "cf_ips.csv")
CF_TXT = os.path.join(DATA_DIR, "cf_ips.txt")

PROBE_HOST = "crypto.cloudflare.com"
TIMEOUT = 3.0
HTTP_TIMEOUT = 2.0
MAX_FAILS = 3
CSV_FIELDS = [
    "ip", "port", "tls", "delay_ms", "speed_kbs",
    "colo", "cf_location", "asn", "isp",
    "first_seen", "channel", "fail_count",
]
SCAN_CSV_FIELDS = CSV_FIELDS + ["exit_ip", "exit_asn", "exit_isp", "exit_location"]

# 复用全局 SSL 证书上下文，避免重复加载系统 CA 证书
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = True
SSL_CTX.verify_mode = ssl.CERT_REQUIRED
try:
    SSL_CTX.options |= getattr(ssl, "OP_NO_TICKET", 0)
    if hasattr(SSL_CTX, "session_cache_mode"):
        SSL_CTX.session_cache_mode = ssl.SSL_SESS_CACHE_OFF
except Exception:
    pass


RE_HTTP_STATUS = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})\b")
RE_HTTP_502 = re.compile(rb"^HTTP/\d\.\d\s+502\b")
RE_CL_ZERO = re.compile(rb"(?im)^content-length:\s*0\b")
RE_THIRD_PARTY_SERVER = re.compile(rb"(?im)^server:\s*(nginx|apache|caddy|openresty|envoy|iis|tengine|lighttpd)")

# 确定性硬伤致命状态（端口明确拒绝关闭、空响应断连、脏数据等），当场判死淘汰进墓地
# 注：tls_error (保护第三方自建反代)、status_502 (源站抖动)、connect_timeout (跨国丢包) 等严格排除在外，充分享受 3 次缓冲容错！
FATAL_FAIL_STATUSES = {
    "conn_error",       # 对端端口关闭 (Connection Refused) / 主机不可达，TCP 直接被拒
    "empty_response",   # 建立连接后一发请求即断开 (假服务/死连接)
    "invalid_row",      # 格式损坏的脏数据行
    "non_cf_cdn",       # 异构 CDN 伪节点 (Fastly/Akamai 等，报文特征明确排他)
}

# 官方 Cloudflare Anycast 诊断基线 IP 池 (共 300 个，覆盖并发 250 槽位)
OFFICIAL_BASELINE_IPS = [
    f"104.16.{i}.{j}" for i in range(16, 26) for j in range(1, 11)
] + [
    f"104.17.{i}.{j}" for i in range(16, 26) for j in range(1, 11)
] + [
    f"172.67.{i}.{j}" for i in range(150, 160) for j in range(1, 11)
]


# ---------- 核心探测函数 ----------
async def probe_ip(
    ip: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str]:
    """
    对单个 IP:Port 执行 TLS 握手 + HTTP 301 校验。

    返回 (is_alive, latency_ms, reason):
        is_alive=True  -> 校验通过，latency_ms 为 TLS 握手与连接延迟 (RTT)，reason 为 "ok"
        is_alive=False -> 校验失败，reason 记录具体失败原因 (如 connect_timeout, tls_error, http_timeout, status_502, no_cf_header 等)
    """
    writer = None
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=PROBE_HOST),
            timeout=connect_timeout,
        )
        t1 = time.monotonic()
        latency_ms = max(1, int((t1 - t0) * 1000))
    except asyncio.TimeoutError:
        return False, 0, "connect_timeout"
    except (ssl.SSLError, ssl.CertificateError):
        return False, 0, "tls_error"
    except (ConnectionRefusedError, OSError):
        return False, 0, "conn_error"
    except Exception as e:
        return False, 0, f"connect_failed_{type(e).__name__}"

    try:
        http_deadline = time.monotonic() + http_timeout
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(req)
        drain_timeout = max(0.001, http_deadline - time.monotonic())
        await asyncio.wait_for(writer.drain(), timeout=drain_timeout)

        read_timeout = max(0.001, http_deadline - time.monotonic())
        resp_bytes = await read_full_response(reader, read_timeout)
        if not resp_bytes:
            return False, latency_ms, "empty_response"

        header_part, body_part = split_header_body(resp_bytes)
        status_match = RE_HTTP_STATUS.match(header_part)
        status_code = status_match.group(1).decode("latin1") if status_match else ""

        is_301 = bool(RE_HTTP_301.match(header_part))
        is_cf = bool(RE_SERVER_CF.search(header_part))

        # 精准识别 Cloudflare 官方对 crypto.cloudflare.com:443 透传的特征空包 502
        # 前提：已严格通过 TLS CA 官方证书鉴真，且排除带有 HTML 错误页或第三方 Server 头的真实故障 502
        is_cf_crypto_502 = (
            bool(RE_HTTP_502.match(header_part))
            and bool(RE_CL_ZERO.search(header_part))
            and not bool(RE_THIRD_PARTY_SERVER.search(header_part))
            and len(body_part.strip()) == 0
        )

        # 报文级鉴真：识别 Cloudflare 官方 1034 边缘受限真节点 (403 + Server: cloudflare + CF-RAY + error code: 1034)
        is_cf_1034 = (
            status_code == "403"
            and is_cf
            and bool(RE_CF_RAY.search(header_part))
            and bool(RE_CF_1034.search(body_part))
        )

        if (is_301 and is_cf) or is_cf_crypto_502 or is_cf_1034:
            return True, latency_ms, "ok"

        # 报文级排他：精准识别混入的异构 CDN 伪节点 (Fastly 421 SAN 拒绝 / Akamai 400 Bad Request)
        is_fastly = bool(RE_NON_CF_FASTLY.search(body_part)) or (status_code == "421" and not is_cf)
        is_akamai = bool(RE_NON_CF_AKAMAI.search(header_part))
        if is_fastly or is_akamai:
            return False, latency_ms, "non_cf_cdn"

        if not is_301:
            return False, latency_ms, f"status_{status_code}" if status_code else "invalid_http_status"
        else:
            return False, latency_ms, "no_cf_header"
    except asyncio.TimeoutError:
        return False, latency_ms, "http_timeout"
    except Exception as e:
        return False, latency_ms, f"http_error_{type(e).__name__}"
    finally:
        await safe_close_writer(writer)


async def verify_all(
    rows: list,
    tag: str = "优选 IP",
    concurrency: int = 250,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
    max_fails: int = MAX_FAILS,
) -> list:
    """
    对传入的所有优选 IP 节点无差别执行阶段一与阶段二探测。
    无论端口与元数据如何，全部执行 TLS 握手与 301 重定向鉴真。
    原地更新 fail_count 与 delay_ms，并汇总失败原因分布。
    对确定性致命硬故障 (conn_error / empty_response / invalid_row) 当场拉满淘汰阈值，
    对软性抖动 (status_502 / connect_timeout) 及第三方反代 TLS 异常 (tls_error) 保留 3 次缓冲机会。
    """
    if not rows:
        return rows

    sem = asyncio.Semaphore(concurrency)
    pass_count = 0
    fail_count_total = 0
    completed = 0
    total = len(rows)
    reasons_counter: dict[str, int] = defaultdict(int)

    # 全局显式初始化 _old_fc，确保异常提前返回或空跑时不遗留未定义状态
    for r in rows:
        r.setdefault("_old_fc", safe_int(r.get("fail_count"), 0))

    # 创建乱序执行队列，打散任务调度
    indices = list(range(total))
    random.shuffle(indices)

    async def _check(row: dict):
        nonlocal pass_count, fail_count_total, completed
        fc = safe_int(row.get("fail_count"), 0)
        row["_old_fc"] = fc

        ip = (row.get("ip") or "").strip()
        port = safe_int(row.get("port"), 0)
        # 上游 load_csv 已执行过滤，此处为二次边界防御；非法行标记并拉满失败计数以直接淘汰
        if not ip or port <= 0 or port > 65535:
            completed += 1
            row["_invalid"] = True
            row["fail_count"] = max_fails
            fail_count_total += 1
            reasons_counter["invalid_row"] += 1
            return

        lock_key = f"{ip}:{port}"
        async with sem, get_keyed_lock(lock_key):
            alive, latency, reason = await probe_ip(ip, port, connect_timeout=timeout, http_timeout=http_timeout)

        completed += 1
        reasons_counter[reason] += 1
        row["_reason"] = reason
        if alive:
            row["fail_count"] = 0
            row["delay_ms"] = latency
            pass_count += 1
        else:
            if reason in FATAL_FAIL_STATUSES:
                row["fail_count"] = max_fails
            else:
                row["fail_count"] = fc + 1
            fail_count_total += 1

        if completed % 1000 == 0 or completed == total:
            log.info("[%s] 进度: %d/%d (%.1f%%) - 通过: %d, 失败: %d",
                     tag, completed, total, completed / total * 100, pass_count, fail_count_total)

    tasks = [_check(rows[i]) for i in indices]
    await asyncio.gather(*tasks)

    sorted_reasons = sorted(reasons_counter.items(), key=lambda x: x[1], reverse=True)
    reason_summary = ", ".join(f"{k}: {v}" for k, v in sorted_reasons)
    log.info(
        "[%s] 校验完成: 共 %d 条 | 验证通过 %d 条, 验证失败 %d 条",
        tag, total, pass_count, fail_count_total,
    )
    log.info("[%s] 探测原因汇总: %s", tag, reason_summary)
    return rows


# ---------- 数据读写与 ASN 智能聚合 ----------
def load_csv(path: str) -> list:
    """读取优选 IP CSV 文件，自动兼容 BOM、过滤墓地黑名单及异常端口/IP"""
    if not os.path.exists(path):
        return []
    tombstone = load_tombstone()
    rows = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = str(r.get("ip") or "").strip()
            port_val = safe_int(r.get("port"), 0)
            # 严格过滤无效 IP 与越界/非法的非数值端口，杜绝脏行进入质检池
            if not ip or port_val <= 0 or port_val > 65535:
                continue
            key = canonical_key(ip, port_val)
            if is_tombstoned(key, tombstone):
                continue

            r["ip"] = ip
            r["port"] = str(port_val)
            r["fail_count"] = safe_int(r.get("fail_count"), 0)
            r["first_seen"] = normalize_timestamp(str(r.get("first_seen") or r.get("tested_at") or ""))
            raw_asn = str(r.get("asn") or "").replace("`", "").strip()
            raw_isp = str(r.get("isp") or "").replace("`", "").strip()
            r["asn"] = format_asn_isp(raw_asn, raw_isp)
            r["isp"] = raw_isp
            r["colo"] = str(r.get("colo") or "").replace("`", "").strip()
            r["cf_location"] = str(r.get("cf_location") or "").replace("`", "").strip()
            rows.append(r)
    return rows


# --- 单条优选 IP 保存逻辑 ---
def save_cf_ips(rows: list, csv_path: str = CF_CSV, txt_path: str = CF_TXT):
    """覆写 cf_ips.csv 与 cf_ips.txt（仅保留存活节点，剔除死节点；原子写入防截断）"""
    with atomic_writer(csv_path, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录", csv_path, len(rows))

    with atomic_writer(txt_path, encoding="utf-8") as f:
        for r in rows:
            ip = str(r.get("ip") or "").strip()
            port = safe_int(r.get("port"), 0)
            if ip and 1 <= port <= 65535:
                f.write(f"{ip}:{port}\n")
    log.info("已覆写保存 %s: %d 行 IP:Port", txt_path, len(rows))


# --- 扫描测速优选 IP 保存逻辑 ---
def save_scan_csv(rows: list, path: str = SCAN_CSV):
    """覆写 scan_ips.csv（仅保留存活节点，剔除死节点；原子写入防截断）"""
    with atomic_writer(path, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCAN_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录", path, len(rows))


def save_scan_txt(rows_or_groups, path: str = SCAN_TXT):
    """
    覆写 scan_ips.txt（按质检可用性/缓冲状态分层输出：缓冲节点置顶，存活节点紧随；原子写入防截断）
    具体机房/ASN 独立清单已由 save_scan_dir() 独立保存至 scan_ips/ 目录。
    """
    if isinstance(rows_or_groups, dict):
        rows = []
        for g in rows_or_groups.values():
            rows.extend(g)
    else:
        rows = rows_or_groups

    content = format_scan_ips_txt(rows)
    atomic_write_text(path, content, encoding="utf-8")
    log.info("已按质检缓冲状态分层保存 %s: %d 条记录", path, len(rows))


# ---------- Telegram 结果卡片推送 ----------


def send_verify_notification(
    cf_pass: int,
    cf_eliminated: int,
    cf_survivors: int,
    scan_pass: int,
    scan_eliminated: int,
    scan_survivors: int,
    concurrency: int,
    max_fails: int,
    elapsed_verify: float,
    cf_f1: int = 0,
    cf_f2: int = 0,
    scan_f1: int = 0,
    scan_f2: int = 0,
    cf_buf_new: int = 0,
    cf_buf_rec: int = 0,
    scan_buf_new: int = 0,
    scan_buf_rec: int = 0,
):
    fetch_stats_file = os.path.join(DATA_DIR, ".fetch_stats.json")
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID
    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过 Telegram 推送")
        if os.path.isfile(fetch_stats_file):
            try:
                os.remove(fetch_stats_file)
            except OSError:
                pass
        return

    bjt = datetime.now(timezone(timedelta(hours=8)))
    date_str = bjt.strftime("%Y-%m-%d %H:%M:%S")

    # 检查是否存在 tg_fetch 暂存的抓取统计及 proxyip_verify 质检统计
    fetch_stats = None
    if os.path.isfile(fetch_stats_file):
        try:
            mtime = os.path.getmtime(fetch_stats_file)
            if time.time() - mtime > 6 * 3600:
                log.warning("暂存抓取统计 %s 已过期 (超过 6 小时)，安全丢弃以防污染", fetch_stats_file)
                try:
                    os.remove(fetch_stats_file)
                except OSError:
                    pass
            else:
                with open(fetch_stats_file, "r", encoding="utf-8") as sf:
                    fetch_stats = json.load(sf)
        except Exception as e:
            log.warning("读取暂存抓取统计 %s 失败: %s", fetch_stats_file, e)

    proxyip_verified = False
    proxyip_eliminated = 0
    proxyip_survivors = 0
    if fetch_stats and fetch_stats.get("proxyip_verified"):
        proxyip_verified = True
        proxyip_eliminated = fetch_stats.get("proxyip_eliminated", 0)
        proxyip_survivors = fetch_stats.get("proxyip_survivors", 0)

    proxies_verified = False
    proxies_eliminated = 0
    proxies_survivors = 0
    if fetch_stats and (fetch_stats.get("proxies_verified") or fetch_stats.get("socks_verified")):
        proxies_verified = True
        proxies_eliminated = fetch_stats.get("proxies_eliminated", fetch_stats.get("socks_eliminated", 0))
        proxies_survivors = fetch_stats.get("proxies_survivors", fetch_stats.get("socks_survivors", 0))

    total_eliminated = cf_eliminated + scan_eliminated + proxyip_eliminated + proxies_eliminated
    total_survivors = cf_survivors + scan_survivors + proxyip_survivors + proxies_survivors

    div = "━━━━━━━━━━━━━━━━━━━━"

    github_server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_run_id = os.getenv("GITHUB_RUN_ID")
    github_run_number = os.getenv("GITHUB_RUN_NUMBER")

    footer_parts = []
    total_elapsed = elapsed_verify
    if fetch_stats:
        total_elapsed += fetch_stats.get("elapsed_seconds", 0.0)
        total_elapsed += fetch_stats.get("proxyip_elapsed", 0.0)
        total_elapsed += fetch_stats.get("proxies_elapsed", fetch_stats.get("socks_elapsed", 0.0))
    footer_parts.append(f"⚡ <b>总耗时</b>: {total_elapsed:.1f}s")
    if github_repo:
        repo_url = f"{github_server}/{github_repo}"
        if github_run_id:
            run_label = f"Action #{github_run_number}" if github_run_number else "Action 日志"
            footer_parts.append(f'🔗 <a href="{repo_url}/actions/runs/{github_run_id}">{run_label}</a>')
        footer_parts.append(f'📦 <a href="{repo_url}">产物仓库</a>')

    footer_line = f"\n{div}\n" + " · ".join(footer_parts)

    cf_marked = max(0, cf_survivors - cf_pass)
    scan_marked = max(0, scan_survivors - scan_pass)
    cf_status = f"✅ {cf_pass} 存活" + format_buffer_badge(cf_marked, buf_new=cf_buf_new, buf_rec=cf_buf_rec, f1=cf_f1, f2=cf_f2)
    scan_status = f"✅ {scan_pass} 存活" + format_buffer_badge(scan_marked, buf_new=scan_buf_new, buf_rec=scan_buf_rec, f1=scan_f1, f2=scan_f2)
    elim_details = []
    if proxies_eliminated > 0:
        elim_details.append(f"代理 {proxies_eliminated}")
    if proxyip_eliminated > 0:
        elim_details.append(f"反代 {proxyip_eliminated}")
    if cf_eliminated > 0:
        elim_details.append(f"单条优选 {cf_eliminated}")
    if scan_eliminated > 0:
        elim_details.append(f"扫描优选 {scan_eliminated}")
    detail_str = f" [{', '.join(elim_details)}]" if elim_details else ""
    proxies_max_fails = fetch_stats.get("proxies_max_fails", fetch_stats.get("socks_max_fails", 3)) if fetch_stats else 3
    if total_eliminated > 0:
        if proxies_eliminated > 0 and proxies_max_fails != max_fails:
            if proxies_eliminated == total_eliminated:
                threshold_desc = f"(连续失败 ≥ {proxies_max_fails} 次)"
            else:
                threshold_desc = f"(代理 ≥ {proxies_max_fails} 次 · 其余 ≥ {max_fails} 次)"
        else:
            threshold_desc = f"(连续失败 ≥ {max_fails} 次)"
        elim_str = f"<code>{total_eliminated}</code> 条{detail_str} {threshold_desc}"
    else:
        elim_str = "无 (全部在存活阈值内)"

    if fetch_stats:
        # 联合完整流水线卡片
        proxies_count = fetch_stats.get("proxies_count", 0)
        new_proxies = fetch_stats.get("new_proxies", 0)
        updated_proxies = fetch_stats.get("updated_proxies", 0)

        proxyips_count = fetch_stats.get("proxyips_count", 0)
        new_proxyips = fetch_stats.get("new_proxyips", 0)
        updated_proxyips = fetch_stats.get("updated_proxyips", 0)

        new_cf = fetch_stats.get("new_cf", 0)
        updated_cf = fetch_stats.get("updated_cf", 0)

        new_scan = fetch_stats.get("new_scan", 0)
        updated_scan = fetch_stats.get("updated_scan", 0)
        asn_count = fetch_stats.get("asn_count", 0)
        top_providers = fetch_stats.get("top_providers", [])
        channels = fetch_stats.get("channels", ["@otcfxq", "@danfeng_chat"])

        total_new = new_proxies + new_cf + new_scan + new_proxyips
        total_updated = updated_proxies + updated_cf + updated_scan + updated_proxyips

        header_badges = []
        if total_new > 0:
            header_badges.append(f"🟢 发现 <b>+{total_new}</b> 新增")
        if total_eliminated > 0:
            header_badges.append(f"🗑️ 剔除 <b>{total_eliminated}</b> 死节点")
        elif total_updated > 0 and total_new == 0:
            header_badges.append(f"🔄 刷新 {total_updated} 条数据")

        if header_badges:
            header = f"🚀 <b>节点与优选 IP 同步完成</b> ({' · '.join(header_badges)})"
        else:
            header = "⚡ <b>节点与优选 IP 同步完成</b> (数据已全部为最新)"

        proxy_line = ""
        if proxies_verified:
            s_pass = fetch_stats.get("proxies_pass", fetch_stats.get("socks_pass", 0))
            s_surv = fetch_stats.get("proxies_survivors", fetch_stats.get("socks_survivors", 0))
            s_marked = max(0, s_surv - s_pass)
            s_f1 = fetch_stats.get("proxies_fail_1", fetch_stats.get("socks_fail_1", 0))
            s_f2 = fetch_stats.get("proxies_fail_2", fetch_stats.get("socks_fail_2", 0))
            s_new = fetch_stats.get("proxies_buf_new", fetch_stats.get("socks_buf_new", 0))
            s_rec = fetch_stats.get("proxies_buf_rec", fetch_stats.get("socks_buf_rec", 0))
            s_avg = fetch_stats.get("proxies_avg_delay_ms", fetch_stats.get("socks_avg_delay_ms", 0))
            s_status = f"✅ {s_pass} 存活" + format_buffer_badge(s_marked, buf_new=s_new, buf_rec=s_rec, f1=s_f1, f2=s_f2)
            avg_str = f" · ⚡ 均延 {s_avg}ms" if s_avg > 0 else ""
            proxy_line = f"📫 <b>可用代理</b>：<code>{s_surv}</code> 个 ({s_status}{avg_str})\n"
        elif proxies_count > 0:
            proxy_line = f"📫 <b>可用代理</b>：<code>{proxies_count}</code> 个 ({format_diff(new_proxies, updated_proxies)})\n"

        cf_line = f"🌐 <b>单条优选</b>：<code>{cf_survivors}</code> 条 ({cf_status})\n"

        asn_suffix = f" · {asn_count} 个 ASN" if asn_count > 0 else ""
        scan_line = f"📁 <b>扫描优选</b>：<code>{scan_survivors}</code> 条 ({scan_status}{asn_suffix})\n"
        if top_providers:
            prov_preview = ", ".join(top_providers[:4])
            if len(top_providers) > 4:
                prov_preview += " 等"
            scan_line += f"   └ <i>涵盖: {prov_preview}</i>\n"

        proxyip_line = ""
        if proxyip_verified:
            p_pass = fetch_stats.get("proxyip_pass", 0)
            p_surv = fetch_stats.get("proxyip_survivors", proxyips_count)
            p_marked = max(0, p_surv - p_pass)
            p_f1 = fetch_stats.get("proxyip_fail_1", 0)
            p_f2 = fetch_stats.get("proxyip_fail_2", 0)
            p_new = fetch_stats.get("proxyip_buf_new", 0)
            p_rec = fetch_stats.get("proxyip_buf_rec", 0)
            p_avg = fetch_stats.get("proxyip_avg_delay_ms", 0)
            p_status = f"✅ {p_pass} 存活" + format_buffer_badge(p_marked, buf_new=p_new, buf_rec=p_rec, f1=p_f1, f2=p_f2)
            p_avg_str = f" · ⚡ 均延 {p_avg}ms" if p_avg > 0 else ""
            proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{p_surv}</code> 条 ({p_status}{p_avg_str})\n"
        elif proxyips_count > 0:
            proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{proxyips_count}</code> 条 ({format_diff(new_proxyips, updated_proxyips)})\n"

        specs = ["优选 TLS+301"]
        if proxies_verified:
            specs.append("代理多协议穿透")
        if proxyip_verified:
            specs.append("反代 CDN 鉴真")
        spec_str = f" ({' · '.join(specs)})" if specs else ""
        verify_items = [
            f"   • 质检规范：全链路穿透鉴真{spec_str}",
        ]

        total_buf_new = (
            fetch_stats.get("proxies_buf_new", fetch_stats.get("socks_buf_new", 0))
            + fetch_stats.get("proxyip_buf_new", 0)
            + cf_buf_new
            + scan_buf_new
        )
        total_buf_rec = (
            fetch_stats.get("proxies_buf_rec", fetch_stats.get("socks_buf_rec", 0))
            + fetch_stats.get("proxyip_buf_rec", 0)
            + cf_buf_rec
            + scan_buf_rec
        )
        if total_buf_new > 0 or total_buf_rec > 0:
            dyn_parts = []
            if total_buf_new > 0:
                dyn_parts.append(f"⚠️ 新增缓冲 {total_buf_new} 条")
            if total_buf_rec > 0:
                dyn_parts.append(f"♻️ 取消缓冲 {total_buf_rec} 条 (恢复健康)")
            verify_items.append(f"   • 缓冲动态：{' · '.join(dyn_parts)}")

        verify_items.append(f"   • 淘汰死节点：{elim_str}")
        verify_block = "🛡️ <b>主动鉴真淘汰</b>：\n" + "\n".join(verify_items) + "\n"

        channels_str = ", ".join(dict.fromkeys(channels))

        unrecorded_asns = fetch_stats.get("unrecorded_asns", [])
        unmatched_block = ""
        if unrecorded_asns:
            # 严格过滤 count <= 0 的幽灵条目，仅展示实际包含可用存活节点的入库自治系统
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

        message = (
            f"{header}\n"
            f"{div}\n"
            f"📅 <b>时间</b>：{date_str} (北京时间)\n"
            f"{proxy_line}"
            f"{cf_line}"
            f"{scan_line}"
            f"{proxyip_line}"
            f"{unmatched_block}"
            f"{div}\n"
            f"{verify_block}"
            f"📡 <b>频道来源</b>：{channels_str}"
            f"{footer_line}"
        )
    else:
        # 独立校验卡片
        header = f"🛡️ <b>优选 IP 两阶段鉴真完成</b> (✅ 存活 <b>{total_survivors}</b> 条)"
        cf_line = f"🌐 <b>单条优选</b>：<code>{cf_survivors}</code> 条 ({cf_status})\n"
        scan_line = f"📁 <b>扫描优选</b>：<code>{scan_survivors}</code> 条 ({scan_status})\n"
        dyn_parts = []
        tot_new = cf_buf_new + scan_buf_new
        tot_rec = cf_buf_rec + scan_buf_rec
        if tot_new > 0:
            dyn_parts.append(f"⚠️ 新增缓冲 {tot_new} 条")
        if tot_rec > 0:
            dyn_parts.append(f"♻️ 取消缓冲 {tot_rec} 条 (恢复健康)")
        dyn_line = f"🛡️ <b>缓冲动态</b>：{' · '.join(dyn_parts)}\n" if dyn_parts else ""

        message = (
            f"{header}\n"
            f"{div}\n"
            f"📅 <b>时间</b>：{date_str} (北京时间)\n"
            f"{cf_line}"
            f"{scan_line}"
            f"{dyn_line}"
            f"🗑️ <b>淘汰死节点</b>：{elim_str}\n"
            f"⚙️ <b>检测规格</b>：TLS 握手 + HTTP 301 · {concurrency} 并发\n"
            f"{footer_line}"
        )

    sent = False
    try:
        sent = send_tg_message(message, token=token, chat_id=chat_id, tag="cf-verify")
    except Exception as e:
        log.warning("发送 Telegram 消息时出现异常: %s", e)
        sent = False

    if sent:
        if os.path.isfile(fetch_stats_file):
            try:
                os.remove(fetch_stats_file)
                log.info("Telegram 统计卡片已成功发送，已清理暂存抓取统计: %s", fetch_stats_file)
            except OSError as e:
                log.warning("清理暂存抓取统计 %s 失败: %s", fetch_stats_file, e)
    else:
        log.warning("Telegram 统计卡片发送未成功，保留暂存统计文件 %s 供后续重试或排查", fetch_stats_file)

    return sent


def _cf_sort_key(x):
    fc = safe_int(x.get("fail_count"), 0)
    d = safe_int(x.get("delay_ms"), 0)
    return (fc, d if d > 0 else 99999)


# ---------- 主流程 ----------
async def _verify_and_persist(csv_path: str, tag: str, args, on_save) -> dict:
    rows = load_csv(csv_path)
    total = len(rows)
    res = {
        "pass": 0,
        "eliminated": 0,
        "survivors": 0,
        "f1": 0,
        "f2": 0,
        "buf_new": 0,
        "buf_rec": 0,
    }
    if not rows:
        log.info(">>> %s 文件不存在或无数据，跳过%s校验", csv_path, tag)
        return res

    log.info(">>> 开始校验%s IP (%s): 共 %d 条...", tag, csv_path, total)
    await verify_all(
        rows,
        tag=tag,
        concurrency=args.concurrency,
        timeout=args.timeout,
        http_timeout=args.http_timeout,
        max_fails=args.max_fails,
    )

    survivors = [
        r for r in rows
        if safe_int(r.get("fail_count"), 0) < args.max_fails and not r.get("_invalid")
    ]
    eliminated = total - len(survivors)
    res["pass"] = sum(1 for r in rows if safe_int(r.get("fail_count"), 0) == 0)
    res["eliminated"] = eliminated
    res["survivors"] = len(survivors)
    res["f1"] = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 1)
    res["f2"] = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 2)
    res["buf_new"] = sum(
        1 for r in rows
        if safe_int(r.get("fail_count"), 0) > 0
        and safe_int(r.get("fail_count"), 0) < args.max_fails
        and safe_int(r.get("_old_fc"), 0) == 0
    )
    res["buf_rec"] = sum(
        1 for r in rows
        if safe_int(r.get("fail_count"), 0) == 0
        and safe_int(r.get("_old_fc"), 0) > 0
    )

    if getattr(args, "diag_output", ""):
        res["diag_map"] = {
            canonical_key(r.get("ip", ""), r.get("port", 0)): {
                "reason": r.get("_reason", "unknown"),
                "alive": safe_int(r.get("fail_count"), 0) == 0,
                "latency": safe_int(r.get("delay_ms"), 0),
            }
            for r in rows
            if (r.get("ip") or "").strip() and safe_int(r.get("port"), 0) > 0
        }

    if getattr(args, "dry_run", False):
        log.info("[%s (Dry-Run)] 演练诊断模式：仅统计探测原因，跳过磁盘文件覆写与墓地登记", tag)
        return res

    # 严格保证保存先于登记墓地：若保存失败触发异常，避免墓地预先登记导致状态不一致
    if on_save:
        on_save(survivors)

    if eliminated > 0:
        log.info("[%s] 淘汰剔除 %d 条连续失败 >= %d 次的死节点", tag, eliminated, args.max_fails)
        dead_nodes = [r for r in rows if safe_int(r.get("fail_count"), 0) >= args.max_fails or r.get("_invalid")]
        dead_keys = [
            canonical_key(r.get("ip", ""), r.get("port", 0))
            for r in dead_nodes
            if (r.get("ip") or "").strip() and safe_int(r.get("port"), 0) > 0
        ]
        newly_tombstoned = record_tombstone(dead_keys)
        log.info("[%s 墓地] 已登记 %d 个淘汰死节点至墓地冷却库 (新增: %d 个, 隔离期 7 天)", tag, len(dead_keys), newly_tombstoned)
    else:
        log.info("[%s] 本次无节点达到连续失败 %d 次的淘汰阈值", tag, args.max_fails)

    return res


async def async_main(args):
    t_start = time.time()

    # ================= 1. 校验单条优选 IP (cf_ips) =================
    def _save_cf_track(survivors):
        # 稳定双重排序：先按 first_seen 降序（最新获取优先），再按 (fail_count, delay_ms) 升序（质量优先）
        survivors.sort(key=lambda x: x.get("first_seen", ""), reverse=True)
        survivors.sort(key=_cf_sort_key)
        save_cf_ips(survivors, CF_CSV, CF_TXT)

    cf_res = await _verify_and_persist(CF_CSV, "单条优选", args, _save_cf_track)

    # ================= 2. 校验扫描优选 IP (scan_ips) =================
    def _save_scan_track(survivors):
        asn_groups = defaultdict(list)
        local_ip_cache = load_ip_cache()
        for row in survivors:
            cur_ip = row.get("ip") or ""
            asn_clean = clean_asn(row.get("asn", ""), row.get("isp", ""))
            if cur_ip in local_ip_cache:
                cached = local_ip_cache[cur_ip]
                cached_code = clean_asn(cached.get("asn"), cached.get("isp"))
                if cached_code and cached_code.upper() not in ("AS0", "AS_UNKNOWN", "UNKNOWN", "AS"):
                    if not asn_clean or (asn_clean == "AS13335" and cached_code != "AS13335"):
                        cached_isp = cached.get("isp") or ASN_TO_PROVIDER.get(cached_code, "")
                        row["raw_asn"] = cached_code
                        row["asn"] = format_asn_isp(cached_code, cached_isp)
                        row["isp"] = cached_isp
                        asn_clean = cached_code

            if asn_clean in ASN_TO_PROVIDER:
                std_isp = ASN_TO_PROVIDER[asn_clean]
                if not row.get("isp") or len(str(row.get("isp")).strip()) <= 2 or re.search(r'(?i)^(?:sa|beafort|ht|dc|unknown|none|null|n/a)$', str(row.get("isp")).strip()):
                    row["isp"] = std_isp

            row["asn"] = format_asn_isp(asn_clean, row.get("isp", ""))
            asn_groups[asn_clean].append(row)

        all_sorted_scan = []
        for asn_name in sorted(asn_groups.keys()):
            group_rows = sorted(asn_groups[asn_name], key=lambda x: x.get("first_seen", ""), reverse=True)
            group_rows = sorted(group_rows, key=_cf_sort_key)
            all_sorted_scan.extend(group_rows)

        save_scan_csv(all_sorted_scan, SCAN_CSV)
        save_scan_txt(all_sorted_scan, SCAN_TXT)
        save_scan_dir(asn_groups, SCAN_DIR)

    scan_res = await _verify_and_persist(SCAN_CSV, "扫描优选", args, _save_scan_track)

    baseline_map = {}
    if getattr(args, "probe_baseline", False):
        baseline_rows = [{"ip": ip, "port": "443", "fail_count": 0} for ip in OFFICIAL_BASELINE_IPS]
        log.info(">>> 开始探测官方基线 IP: 共 %d 条 (并发 %d)...", len(baseline_rows), args.concurrency)
        await verify_all(
            baseline_rows,
            tag="官方基线",
            concurrency=args.concurrency,
            timeout=args.timeout,
            http_timeout=args.http_timeout,
        )
        baseline_map = {
            f"{r['ip']}:{r['port']}": {
                "reason": r.get("_reason", "unknown"),
                "alive": safe_int(r.get("fail_count"), 0) == 0,
                "latency": safe_int(r.get("delay_ms"), 0),
            }
            for r in baseline_rows
        }

    if getattr(args, "diag_output", ""):
        diag_data = {
            "timestamp": int(time.time()),
            "concurrency": args.concurrency,
            "timeout": args.timeout,
            "http_timeout": args.http_timeout,
            "baseline": baseline_map,
            "cf_ips": cf_res.get("diag_map", {}),
            "scan_ips": scan_res.get("diag_map", {}),
        }
        try:
            with open(args.diag_output, "w", encoding="utf-8") as f:
                json.dump(diag_data, f, ensure_ascii=False, indent=2)
            log.info("已成功导出逐节点诊断结果至 %s (记录总数: %d)",
                     args.diag_output, len(baseline_map) + len(diag_data["cf_ips"]) + len(diag_data["scan_ips"]))
        except Exception as e:
            log.warning("导出诊断结果文件失败: %s", e)

    elapsed = time.time() - t_start
    log.info(
        "全部优选 IP 两阶段校验流程圆满完成，总耗时 %.2f 秒 (单条缓冲: %d [新增: %d, 取消: %d] | 扫描缓冲: %d [新增: %d, 取消: %d])",
        elapsed,
        (cf_res["survivors"] - cf_res["pass"]),
        cf_res["buf_new"],
        cf_res["buf_rec"],
        (scan_res["survivors"] - scan_res["pass"]),
        scan_res["buf_new"],
        scan_res["buf_rec"],
    )

    if not getattr(args, "no_notify", False) and not getattr(args, "dry_run", False):
        send_verify_notification(
            cf_pass=cf_res["pass"],
            cf_eliminated=cf_res["eliminated"],
            cf_survivors=cf_res["survivors"],
            scan_pass=scan_res["pass"],
            scan_eliminated=scan_res["eliminated"],
            scan_survivors=scan_res["survivors"],
            concurrency=args.concurrency,
            max_fails=args.max_fails,
            elapsed_verify=elapsed,
            cf_f1=cf_res["f1"],
            cf_f2=cf_res["f2"],
            scan_f1=scan_res["f1"],
            scan_f2=scan_res["f2"],
            cf_buf_new=cf_res["buf_new"],
            cf_buf_rec=cf_res["buf_rec"],
            scan_buf_new=scan_res["buf_new"],
            scan_buf_rec=scan_res["buf_rec"],
        )
    else:
        log.info("指定了 --no-notify 或 --dry-run，跳过 Telegram 卡片推送")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 两阶段主动校验与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=250, help="并发探测协程数 (默认 250)")
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="单节点连接与 TLS 握手超时秒数 (默认 3.0)")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help="单节点 HTTP 校验超时秒数 (默认 2.0)")
    parser.add_argument("--no-notify", action="store_true", help="静默模式，不发送 Telegram 质检通知")
    parser.add_argument("--dry-run", action="store_true", help="演练诊断模式，仅探测统计原因，不覆写数据文件也不登记墓地，自动跳过通知")
    parser.add_argument("--probe-baseline", action="store_true", help="探测 300 个官方 Cloudflare Anycast IP 作为并发与网络基线")
    parser.add_argument("--diag-output", type=str, default="", help="诊断结果输出 JSON 路径，记录每个节点的探测原因明细")
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
