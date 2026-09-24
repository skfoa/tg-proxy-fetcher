#!/usr/bin/env python3
"""
Cloudflare 优选 IP 两阶段主动校验与淘汰引擎 (cf_verify.py)

只要是优选 IP（涵盖 scan_ips 与 cf_ips 全线产物），全部统一执行：
  阶段一：TLS 握手 + CA 证书鉴真（server_hostname=crypto.cloudflare.com 官方证书链，底层校验 Root CA 与 SAN 匹配）
  阶段二：同一连接发送 HTTP 请求，基于统一 deadline 与 4096B 上限循环读取，经双兼容分隔符严格隔离 Header 与 Body，
          字节级正则精准匹配状态行 HTTP/X.X 301 与单行 Server: cloudflare（抗报文截断假阴性与伪装头假阳性）

淘汰与全流水线汇总机制：
  1. 物理淘汰：连续失败达到阈值（默认 3 次）的死节点，全面从所有产物中永久删除：
     - scan_ips.csv、scan_ips.txt、scan_ips/*.txt (独立机房分组文本)
     - cf_ips.csv、cf_ips.txt (单条优选数据表与纯文本清单)
  2. 四维合一卡片推送：流水线末尾自动聚合 tg_fetch、socks_verify、proxyip_verify（各引擎均为连续失败 ≥3 次淘汰）与自身结果，
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
    send_tg_message,
    normalize_timestamp,
    get_keyed_lock,
    ASN_TO_PROVIDER,
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
log = logging.getLogger("cf-verify")

# Windows 异步事件循环策略
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

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
    "colo", "cf_location", "isp", "asn",
    "tested_at", "channel", "fail_count",
]

# 复用全局 SSL 证书上下文，避免重复加载系统 CA 证书
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = True
SSL_CTX.verify_mode = ssl.CERT_REQUIRED




# 预编译正则，高并发下零重复编译开销
RE_HTTP_301 = re.compile(rb"^HTTP/\d\.\d\s+301\b")
RE_SERVER_CF = re.compile(rb"(?im)^server:\s*cloudflare\s*$")


async def _read_full_response(reader, http_timeout: float, max_bytes: int = 4096) -> bytes:
    """
    循环读取直到拿到完整的 HTTP 响应头（遇到 \r\n\r\n 或 \n\n）或达到 max_bytes 硬上限。
    用统一 deadline 控制总耗时，避免多次循环导致累计超时远超 http_timeout。
    单次 read() 动态计算剩余可用空间，避免读取超出 max_bytes 上限。
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + http_timeout
    resp_bytes = b""
    while len(resp_bytes) < max_bytes:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        chunk = await asyncio.wait_for(
            reader.read(min(1024, max_bytes - len(resp_bytes))),
            timeout=remaining,
        )
        if not chunk:
            break
        resp_bytes += chunk
        if b"\r\n\r\n" in resp_bytes or b"\n\n" in resp_bytes:
            break
    return resp_bytes


def _split_header_body(resp_bytes: bytes) -> tuple[bytes, bytes]:
    """按 \r\n\r\n 优先、\n\n 兜底切分 Header 与 Body 区域。"""
    idx = resp_bytes.find(b"\r\n\r\n")
    if idx != -1:
        return resp_bytes[:idx], resp_bytes[idx + 4:]
    idx = resp_bytes.find(b"\n\n")
    if idx != -1:
        return resp_bytes[:idx], resp_bytes[idx + 2:]
    return resp_bytes, b""


# ---------- 核心探测函数 ----------
async def probe_ip(
    ip: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int]:
    """
    对单个 IP:Port 执行 TLS 握手 + HTTP 301 校验（修复版 v2）。

    返回 (is_alive, latency_ms):
        is_alive=True  -> 校验通过，latency_ms 为 TLS 握手与连接延迟 (RTT)
        is_alive=False -> 校验失败，latency_ms 为 0
    """
    t0 = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=PROBE_HOST),
            timeout=connect_timeout,
        )
        t1 = asyncio.get_event_loop().time()
        latency_ms = max(1, int((t1 - t0) * 1000))
    except Exception:
        return False, 0

    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=http_timeout)

        resp_bytes = await _read_full_response(reader, http_timeout)
        header_part, _ = _split_header_body(resp_bytes)

        is_301 = bool(RE_HTTP_301.match(header_part))
        is_cf = bool(RE_SERVER_CF.search(header_part))

        return (is_301 and is_cf), latency_ms
    except Exception:
        return False, 0
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def verify_all(
    rows: list,
    tag: str = "优选 IP",
    concurrency: int = 250,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> list:
    """
    对传入的所有优选 IP 节点无差别执行阶段一与阶段二探测。
    无论端口与元数据如何，全部执行 TLS 握手与 301 重定向鉴真。
    原地更新 fail_count 与 delay_ms。
    """
    if not rows:
        return rows

    sem = asyncio.Semaphore(concurrency)
    pass_count = 0
    fail_count_total = 0
    completed = 0
    total = len(rows)

    # 创建乱序执行队列，打散任务调度
    indices = list(range(total))
    random.shuffle(indices)

    async def _check(row: dict):
        nonlocal pass_count, fail_count_total, completed
        port_raw = row.get("port", 0)
        try:
            port = int(port_raw)
        except (ValueError, TypeError):
            port = 0

        ip = (row.get("ip") or "").strip()
        if not ip or port <= 0 or port > 65535:
            completed += 1
            fc = int(row.get("fail_count") or 0)
            row["fail_count"] = fc + 1
            fail_count_total += 1
            return

        async with get_keyed_lock(ip):
            async with sem:
                alive, latency = await probe_ip(ip, port, connect_timeout=timeout, http_timeout=http_timeout)

        completed += 1
        fc = int(row.get("fail_count") or 0)
        if alive:
            row["fail_count"] = 0
            row["delay_ms"] = latency
            pass_count += 1
        else:
            row["fail_count"] = fc + 1
            fail_count_total += 1

        if completed % 1000 == 0 or completed == total:
            log.info("[%s] 进度: %d/%d (%.1f%%) - 通过: %d, 失败: %d",
                     tag, completed, total, completed / total * 100, pass_count, fail_count_total)

    tasks = [_check(rows[i]) for i in indices]
    await asyncio.gather(*tasks)

    log.info(
        "[%s] 校验完成: 共 %d 条 | 验证通过 %d 条, 验证失败 %d 条",
        tag, total, pass_count, fail_count_total,
    )
    return rows


# ---------- 数据读写与 ASN 智能聚合 ----------
def load_csv(path: str) -> list:
    """读取优选 IP CSV 文件，自动兼容 BOM 及旧版本缺少 fail_count 字段的情况"""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            r["fail_count"] = safe_int(r.get("fail_count"), 0)
            r["tested_at"] = normalize_timestamp(r.get("tested_at", ""))
            rows.append(r)
    return rows


# --- 单条优选 IP 保存逻辑 ---
def save_cf_ips(rows: list, csv_path: str = CF_CSV, txt_path: str = CF_TXT):
    """覆写 cf_ips.csv 与 cf_ips.txt（仅保留存活节点，剔除死节点）"""
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录", csv_path, len(rows))

    with open(txt_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(f"{r['ip']}:{r['port']}\n")
    log.info("已覆写保存 %s: %d 行 IP:Port", txt_path, len(rows))


# --- 扫描测速优选 IP 保存逻辑 ---
def save_scan_csv(rows: list, path: str = SCAN_CSV):
    """覆写 scan_ips.csv（仅保留存活节点，剔除死节点）"""
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录", path, len(rows))


def save_scan_txt(asn_groups: dict, path: str = SCAN_TXT):
    """覆写 scan_ips.txt（按 ASN 分组汇总，仅包含存活节点）"""
    total_ips = sum(len(g) for g in asn_groups.values())
    with open(path, "w", encoding="utf-8") as f:
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
    log.info("已覆写保存 %s: 共 %d 个 ASN 分组，%d 行 IP:Port", path, len(asn_groups), total_ips)


def save_scan_dir(asn_groups: dict, scan_dir: str = SCAN_DIR):
    """
    覆写 scan_ips/ 目录下的独立 ASN 纯文本文件（无注释 IP:端口）。
    死节点被淘汰后，其对应的 ASN 文件会即时同步删除该 IP；
    若某个 ASN 旗下所有 IP 全部死亡淘汰，该 ASN 文本文件也会被自动清除删除。
    """
    os.makedirs(scan_dir, exist_ok=True)

    active_files = set()
    for asn_name, group in asn_groups.items():
        isp_name = ASN_TO_PROVIDER.get(asn_name, "")
        if not isp_name:
            isp_name = next((r.get("isp") for r in group if r.get("isp")), "")
        clean_isp = re.sub(r"[^a-zA-Z0-9]", "", isp_name) if isp_name else ""
        fname = f"{asn_name}_{clean_isp}.txt" if clean_isp else f"{asn_name}.txt"
        fpath = os.path.join(scan_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            for r in sorted(group, key=lambda x: (x.get("ip", ""), int(x.get("port", 0)))):
                f.write(f"{r['ip']}:{r['port']}\n")
        active_files.add(fname)

    # 移除已无活跃 IP 的旧分组文件（保留 .gitkeep 保持目录结构）
    for old_f in os.listdir(scan_dir):
        if old_f == ".gitkeep":
            continue
        if old_f.endswith(".txt") and old_f not in active_files:
            try:
                os.remove(os.path.join(scan_dir, old_f))
            except OSError:
                pass

    log.info("已覆写更新 %s/ 目录: %d 个独立 ASN 纯文本文件", scan_dir, len(active_files))


# ---------- Telegram 结果卡片推送 ----------
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


def send_verify_notification(
    cf_total: int,
    cf_pass: int,
    cf_fail: int,
    cf_eliminated: int,
    cf_survivors: int,
    scan_total: int,
    scan_pass: int,
    scan_fail: int,
    scan_eliminated: int,
    scan_survivors: int,
    concurrency: int,
    max_fails: int,
    elapsed_verify: float,
    cf_f1: int = 0,
    cf_f2: int = 0,
    scan_f1: int = 0,
    scan_f2: int = 0,
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

    socks_verified = False
    socks_eliminated = 0
    socks_survivors = 0
    if fetch_stats and fetch_stats.get("socks_verified"):
        socks_verified = True
        socks_eliminated = fetch_stats.get("socks_eliminated", 0)
        socks_survivors = fetch_stats.get("socks_survivors", 0)

    total_eliminated = cf_eliminated + scan_eliminated + proxyip_eliminated + socks_eliminated
    total_survivors = cf_survivors + scan_survivors + proxyip_survivors + socks_survivors

    def format_diff(new_c: int, upd_c: int) -> str:
        parts = []
        if new_c > 0:
            parts.append(f"🟢 <b>+{new_c}</b> 新增")
        if upd_c > 0:
            parts.append(f"🔄 {upd_c} 刷新")
        if not parts:
            return "保持最新"
        return " · ".join(parts)

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
        total_elapsed += fetch_stats.get("socks_elapsed", 0.0)
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
    cf_status = f"✅ {cf_pass} 存活" + format_buffer_badge(cf_marked, cf_f1, cf_f2)
    scan_status = f"✅ {scan_pass} 存活" + format_buffer_badge(scan_marked, scan_f1, scan_f2)
    elim_details = []
    if socks_eliminated > 0:
        elim_details.append(f"代理 {socks_eliminated}")
    if proxyip_eliminated > 0:
        elim_details.append(f"反代 {proxyip_eliminated}")
    if cf_eliminated > 0:
        elim_details.append(f"单条优选 {cf_eliminated}")
    if scan_eliminated > 0:
        elim_details.append(f"扫描优选 {scan_eliminated}")
    detail_str = f" [{', '.join(elim_details)}]" if elim_details else ""
    socks_max_fails = fetch_stats.get("socks_max_fails", 3) if fetch_stats else 3
    if total_eliminated > 0:
        if socks_eliminated > 0 and socks_max_fails != max_fails:
            if socks_eliminated == total_eliminated:
                threshold_desc = f"(连续失败 ≥ {socks_max_fails} 次)"
            else:
                threshold_desc = f"(代理 ≥ {socks_max_fails} 次 · 其余 ≥ {max_fails} 次)"
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
        channels = fetch_stats.get("channels", ["@otcfxq", "@danfeng2"])

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
        if socks_verified:
            s_pass = fetch_stats.get("socks_pass", 0)
            s_surv = fetch_stats.get("socks_survivors", 0)
            s_marked = max(0, s_surv - s_pass)
            s_f1 = fetch_stats.get("socks_fail_1", 0)
            s_f2 = fetch_stats.get("socks_fail_2", 0)
            s_avg = fetch_stats.get("socks_avg_delay_ms", 0)
            s_status = f"✅ {s_pass} 存活" + format_buffer_badge(s_marked, s_f1, s_f2)
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
            p_cf = fetch_stats.get("proxyip_cf_clean", 0)
            p_status = f"✅ {p_pass} 存活" + format_buffer_badge(p_marked, p_f1, p_f2)
            cf_extra = f"\n   └ <i>🌟 兼具优选直连: <code>{p_cf}</code> 条 (已提纯 data/proxyip_cf.txt)</i>" if p_cf > 0 else ""
            proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{p_surv}</code> 条 ({p_status}){cf_extra}\n"
        elif proxyips_count > 0:
            proxyip_line = f"🔀 <b>反代 ProxyIP</b>：<code>{proxyips_count}</code> 条 ({format_diff(new_proxyips, updated_proxyips)})\n"

        verify_items = [
            f"   • 优选检验：TLS 握手 + HTTP 301 ({concurrency} 并发)",
        ]
        if socks_verified:
            verify_items.append("   • 代理检验：RFC 1928 全协议穿透鉴真")
        if proxyip_verified:
            verify_items.append("   • 反代检验：/cdn-cgi/trace 穿透 + 优选双能")
        verify_items.append(f"   • 淘汰死节点：{elim_str}")
        verify_block = "🛡️ <b>主动鉴真淘汰</b>：\n" + "\n".join(verify_items) + "\n"

        channels_str = ", ".join(dict.fromkeys(channels))

        unrecorded_asns = fetch_stats.get("unrecorded_asns", [])
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
        message = (
            f"{header}\n"
            f"{div}\n"
            f"📅 <b>时间</b>：{date_str} (北京时间)\n"
            f"{cf_line}"
            f"{scan_line}"
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


# ---------- 主流程 ----------
async def async_main(args):
    t_start = time.time()

    # ================= 1. 校验单条优选 IP (cf_ips) =================
    cf_rows = load_csv(CF_CSV)
    cf_total = len(cf_rows)
    cf_pass = 0
    cf_fail = 0
    cf_eliminated = 0
    cf_survivors_len = 0

    cf_f1 = 0
    cf_f2 = 0
    if cf_rows:
        log.info(">>> 开始校验单条优选 IP (%s): 共 %d 条...", CF_CSV, cf_total)
        await verify_all(
            cf_rows,
            tag="单条优选",
            concurrency=args.concurrency,
            timeout=args.timeout,
            http_timeout=args.http_timeout,
        )

        cf_pass = sum(1 for r in cf_rows if int(r.get("fail_count", 0)) == 0)
        cf_fail = cf_total - cf_pass
        cf_survivors = [r for r in cf_rows if int(r.get("fail_count", 0)) < args.max_fails]
        cf_eliminated = cf_total - len(cf_survivors)
        cf_survivors_len = len(cf_survivors)
        cf_f1 = sum(1 for r in cf_survivors if safe_int(r.get("fail_count"), 0) == 1)
        cf_f2 = sum(1 for r in cf_survivors if safe_int(r.get("fail_count"), 0) == 2)
        if cf_eliminated > 0:
            log.info("[单条优选] 淘汰剔除 %d 条连续失败 >= %d 次的死节点", cf_eliminated, args.max_fails)
        else:
            log.info("[单条优选] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

        # 稳定双重排序：先按 tested_at 降序（最新获取优先），再按 (fail_count, delay_ms) 升序（质量优先）
        cf_survivors.sort(key=lambda x: x.get("tested_at", ""), reverse=True)
        cf_survivors.sort(key=lambda x: (safe_int(x.get("fail_count"), 0), safe_int(x.get("delay_ms") or 99999, 99999)))
        save_cf_ips(cf_survivors, CF_CSV, CF_TXT)
    else:
        log.info(">>> %s 文件不存在或无数据，跳过单条优选校验", CF_CSV)

    # ================= 2. 校验扫描优选 IP (scan_ips) =================
    scan_rows = load_csv(SCAN_CSV)
    scan_total = len(scan_rows)
    scan_pass = 0
    scan_fail = 0
    scan_eliminated = 0
    scan_survivors_len = 0
    scan_f1 = 0
    scan_f2 = 0

    if scan_rows:
        log.info(">>> 开始校验扫描优选 IP (%s): 共 %d 条...", SCAN_CSV, scan_total)
        await verify_all(
            scan_rows,
            tag="扫描优选",
            concurrency=args.concurrency,
            timeout=args.timeout,
            http_timeout=args.http_timeout,
        )

        scan_pass = sum(1 for r in scan_rows if int(r.get("fail_count", 0)) == 0)
        scan_fail = scan_total - scan_pass
        scan_survivors = [r for r in scan_rows if int(r.get("fail_count", 0)) < args.max_fails]
        scan_eliminated = scan_total - len(scan_survivors)
        scan_survivors_len = len(scan_survivors)
        scan_f1 = sum(1 for r in scan_survivors if safe_int(r.get("fail_count"), 0) == 1)
        scan_f2 = sum(1 for r in scan_survivors if safe_int(r.get("fail_count"), 0) == 2)
        if scan_eliminated > 0:
            log.info("[扫描优选] 淘汰剔除 %d 条连续失败 >= %d 次的死节点", scan_eliminated, args.max_fails)
        else:
            log.info("[扫描优选] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

        asn_groups = defaultdict(list)
        for row in scan_survivors:
            asn_clean = clean_asn(row.get("asn", ""), row.get("isp", ""))
            row["asn"] = asn_clean
            asn_groups[asn_clean].append(row)

        all_sorted_scan = []
        for asn_name in sorted(asn_groups.keys()):
            group_rows = sorted(asn_groups[asn_name], key=lambda x: x.get("tested_at", ""), reverse=True)
            group_rows = sorted(group_rows, key=lambda x: (safe_int(x.get("fail_count"), 0), safe_int(x.get("delay_ms") or 99999, 99999)))
            all_sorted_scan.extend(group_rows)

        save_scan_csv(all_sorted_scan, SCAN_CSV)
        save_scan_txt(asn_groups, SCAN_TXT)
        save_scan_dir(asn_groups, SCAN_DIR)
    else:
        log.info(">>> %s 文件不存在或无数据，跳过扫描优选校验", SCAN_CSV)

    # 统一登记淘汰死节点入墓地冷却库
    all_dead = []
    if cf_rows:
        all_dead.extend([r for r in cf_rows if safe_int(r.get("fail_count"), 0) >= args.max_fails])
    if scan_rows:
        all_dead.extend([r for r in scan_rows if safe_int(r.get("fail_count"), 0) >= args.max_fails])
    if all_dead:
        all_dead_keys = [canonical_key(r.get("ip", ""), r.get("port", 0)) for r in all_dead]
        newly_tombstoned = record_tombstone(all_dead_keys)
        log.info("[优选 IP 墓地] 已登记 %d 个淘汰死节点至墓地冷却库 (新增: %d 个, 隔离期 7 天)", len(all_dead_keys), newly_tombstoned)

    elapsed = time.time() - t_start
    log.info("全部优选 IP 两阶段校验流程圆满完成，总耗时 %.2f 秒", elapsed)

    send_verify_notification(
        cf_total=cf_total,
        cf_pass=cf_pass,
        cf_fail=cf_fail,
        cf_eliminated=cf_eliminated,
        cf_survivors=cf_survivors_len,
        scan_total=scan_total,
        scan_pass=scan_pass,
        scan_fail=scan_fail,
        scan_eliminated=scan_eliminated,
        scan_survivors=scan_survivors_len,
        concurrency=args.concurrency,
        max_fails=args.max_fails,
        elapsed_verify=elapsed,
        cf_f1=cf_f1,
        cf_f2=cf_f2,
        scan_f1=scan_f1,
        scan_f2=scan_f2,
    )


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 两阶段主动校验与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=250, help="并发探测协程数 (默认 250)")
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="单节点连接与 TLS 握手超时秒数 (默认 3.0)")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help="单节点 HTTP 校验超时秒数 (默认 2.0)")
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
