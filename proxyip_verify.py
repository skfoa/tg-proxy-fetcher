#!/usr/bin/env python3
"""
Cloudflare 反代 ProxyIP 穿透质检与淘汰引擎 (proxyip_verify.py)

专门针对反代 ProxyIP（proxyip.csv / proxyip.txt / proxyip_cf.txt）执行深层应用层协议穿透探测：
  1. TCP 三次握手 + TLS ClientHello（SNI: speed.cloudflare.com，跳过反代非官方证书校验）
  2. HTTP/1.1 GET /cdn-cgi/trace 探针请求（浏览器伪装 UA, Connection: close）
  3. 严格三维校验：HTTP 200 + Server: cloudflare + 正则解析提取有效 colo 机房代号
  4. 官方优选直连能力检验（crypto.cloudflare.com 官方 CA 证书链校验 + HTTP 301 重定向）
  5. 优雅四次挥手关闭连接（writer.close + wait_closed），杜绝 RST 异常

淘汰、属性打标与分层导出机制：
  - 存活节点：fail_count 重置为 0，回填实时 delay_ms、colo 机房码并标记 cf_clean 属性
  - 失败节点：fail_count 递增 +1，标记 cf_clean="false"
  - 物理淘汰：连续失败达到阈值（默认 2 次）的死节点从 proxyip.csv 与 proxyip.txt 中永久物理删除
  - 双料提纯：自动筛选兼具 Cloudflare 官方优选直连能力的极品反代节点导出至 data/proxyip_cf.txt
  - 网络属性打标：落盘前调用 classify_asn 计算 net_type（isp/business/education/government/datacenter）
  - 分类分国导出：自动输出分国家独立纯文本文件及【ISP_运营商原生宽带】等 4 类特殊资产纯净列表
  - 排序落盘：存活优先（fail_count 升序），低延迟优先（delay_ms 升序），最新测试时间降序
  - 结果聚合：支持将质检与双料优选统计回写至 .fetch_stats.json，由流水线终点 cf_verify 聚合发送四维合一总览卡片
"""

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
    send_tg_message,
    get_keyed_lock,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    format_categorized_proxyip_txt,
    save_proxyip_by_country,
    classify_asn,
    normalize_timestamp,
)

# 确保本地 .env 加载
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("proxyip-verify")

# Windows 异步事件循环策略与 UTF-8 输出
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = "data"
PROXYIP_CSV = os.path.join(DATA_DIR, "proxyip.csv")
PROXYIP_TXT = os.path.join(DATA_DIR, "proxyip.txt")
PROXYIP_DIR = os.path.join(DATA_DIR, "proxyip")
PROXYIP_CF_TXT = os.path.join(DATA_DIR, "proxyip_cf.txt")
PROXYIP_CF_DIR = os.path.join(DATA_DIR, "proxyip_cf")

PROBE_HOST = "speed.cloudflare.com"
PROBE_PATH = "/cdn-cgi/trace"
PROBE_HOST_CF = "crypto.cloudflare.com"

TIMEOUT = 2.0
HTTP_TIMEOUT = 2.5
CONCURRENCY = 300
MAX_FAILS = 2

# 包含 cf_clean 双能标记的完整字段定义
CSV_FIELDS = [
    "ip", "port", "tls", "delay_ms", "speed_kbs",
    "colo", "cf_location", "isp", "asn",
    "tested_at", "channel", "fail_count", "cf_clean", "net_type",
]

# 1. 反代穿透上下文：跳过证书链校验（用于反代服务器）
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# 2. 官方优选上下文：严格校验 Cloudflare 官方 CA 证书链（用于验证是否具备优选直连能力）
SSL_CTX_CF = ssl.create_default_context()
SSL_CTX_CF.check_hostname = True
SSL_CTX_CF.verify_mode = ssl.CERT_REQUIRED


# ---------- 核心探测函数 ----------
async def probe_proxyip(
    ip: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str]:
    """
    对单个 ProxyIP 节点执行 TLS 穿透 + /cdn-cgi/trace 鉴真。

    返回 (is_alive, latency_ms, colo):
        is_alive=True  -> 探测成功，latency_ms 为握手延迟，colo 为解析到的机房代号
        is_alive=False -> 探测失败，latency_ms 为 0，colo 为空字符串
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
        return False, 0, ""

    try:
        req = (
            f"GET {PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=http_timeout)

        resp = await asyncio.wait_for(reader.read(2048), timeout=http_timeout)
        resp_text = resp.decode("utf-8", errors="ignore")

        # 严格三维校验：
        # 1. HTTP 状态码 200
        lines = resp_text.splitlines()
        first_line = lines[0] if lines else ""
        is_200 = "200" in first_line

        # 2. Server 响应头包含 cloudflare
        is_cf = "server: cloudflare" in resp_text.lower()

        # 3. /cdn-cgi/trace 响应体包含有效的 colo=XXX
        colo_match = re.search(r"\bcolo=([A-Za-z0-9]+)\b", resp_text)
        colo = colo_match.group(1).upper() if colo_match else ""

        is_alive = is_200 and is_cf and bool(colo)
        return is_alive, latency_ms, colo
    except Exception:
        return False, 0, ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def probe_cf_clean(
    ip: str,
    port: int,
    connect_timeout: float = 1.8,
    http_timeout: float = 1.8,
) -> bool:
    """
    针对已确认穿透存活的 ProxyIP 节点，进一步鉴真其是否兼具 Cloudflare 官方优选直连能力。
    判据：连接 crypto.cloudflare.com 必须通过官方 CA 证书链校验，且发送 GET / 返回 HTTP 301。
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX_CF, server_hostname=PROBE_HOST_CF),
            timeout=connect_timeout,
        )
    except Exception:
        return False

    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {PROBE_HOST_CF}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=http_timeout)

        resp = await asyncio.wait_for(reader.read(512), timeout=http_timeout)
        resp_text = resp.decode("utf-8", errors="ignore")
        first_line = resp_text.splitlines()[0] if resp_text else ""
        return ("301" in first_line) and ("server: cloudflare" in resp_text.lower())
    except Exception:
        return False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ---------- 数据加载与保存 ----------
def load_proxyip_csv(path: str) -> list:
    """读取 proxyip.csv，自动处理 utf-8-sig BOM 并自动补齐缺失的 fail_count 列"""
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


def _get_fc(r: dict) -> int:
    return safe_int(r.get("fail_count"), 0)


def save_proxyip(
    rows: list,
    csv_path: str = PROXYIP_CSV,
    txt_path: str = PROXYIP_TXT,
    dir_path: str = PROXYIP_DIR,
    cf_txt_path: str = PROXYIP_CF_TXT,
    cf_dir_path: str = PROXYIP_CF_DIR,
):
    """
    覆写保存 proxyip.csv 与 proxyip.txt，并提纯导出兼具优选直连能力的 proxyip_cf.txt。
    同时将全量反代与双料优选按国家/地区分别拆分至 data/proxyip/ 与 data/proxyip_cf/ 独立目录。
    自动按质量排序：存活节点优先（fail_count 升序），低延迟优先（delay_ms 升序）。
    """
    # 稳定双重排序：先按 tested_at 降序（最新优先），再按 (fail_count, delay_ms) 升序
    rows.sort(key=lambda r: r.get("tested_at", ""), reverse=True)

    def _sort_key(r):
        fc = _get_fc(r)
        delay = safe_int(r.get("delay_ms") or 99999, 99999)
        return (fc, delay)

    rows.sort(key=_sort_key)

    for row in rows:
        row["net_type"] = classify_asn(row.get("asn", ""), row.get("isp", ""))

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录 (含 fail_count, cf_clean, net_type 列)", csv_path, len(rows))

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(format_categorized_proxyip_txt(rows))
    log.info("已按国家地区分类保存 %s: %d 条记录", txt_path, len(rows))

    split_cnt = save_proxyip_by_country(rows, dir_path)
    log.info("已在 %s/ 目录下生成 %d 个独立国家/地区纯文本文件", dir_path, split_cnt)

    # 提纯双料优选反代节点 (cf_clean=true 且 fail_count=0)
    cf_clean_rows = [
        r for r in rows
        if r.get("cf_clean") == "true" and _get_fc(r) == 0
    ]
    with open(cf_txt_path, "w", encoding="utf-8") as f:
        f.write(format_categorized_proxyip_txt(cf_clean_rows))
    log.info("已按国家地区分类提纯保存双料优选反代清单 %s: %d 条记录", cf_txt_path, len(cf_clean_rows))

    cf_split_cnt = save_proxyip_by_country(cf_clean_rows, cf_dir_path)
    log.info("已在 %s/ 目录下生成 %d 个独立国家/地区双料优选纯文本文件", cf_dir_path, cf_split_cnt)


# ---------- 批量质检调度器 ----------
async def verify_proxyips(
    rows: list,
    concurrency: int = CONCURRENCY,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[list, int]:
    """
    并发调度对所有 ProxyIP 进行 /cdn-cgi/trace 穿透鉴真。
    对存活节点同步进行 crypto.cloudflare.com 官方 CA 证书优选能力检验。
    打乱执行顺序以将同 IP 多端口请求自然散列，防止突发流量触发对端防护。
    原地更新 fail_count、delay_ms、colo 与 cf_clean。
    返回 (rows, cf_clean_count)。
    """
    total = len(rows)
    if total == 0:
        return rows, 0

    sem = asyncio.Semaphore(concurrency)
    pass_count = 0
    fail_count_total = 0
    cf_clean_count = 0
    completed = 0

    # 创建乱序执行队列，保护同 IP 多端口节点
    indices = list(range(total))
    random.shuffle(indices)

    async def _check(idx: int):
        nonlocal pass_count, fail_count_total, cf_clean_count, completed
        row = rows[idx]

        port_raw = row.get("port", 0)
        try:
            port = int(port_raw)
        except (ValueError, TypeError):
            port = 0

        ip = (row.get("ip") or "").strip()
        if not ip or port <= 0 or port > 65535:
            completed += 1
            fc = _get_fc(row)
            row["fail_count"] = fc + 1
            row["cf_clean"] = "false"
            fail_count_total += 1
            return

        async with get_keyed_lock(ip):
            async with sem:
                alive, latency, colo = await probe_proxyip(
                    ip, port, connect_timeout=timeout, http_timeout=http_timeout
                )
                is_cf = False
                if alive:
                    is_cf = await probe_cf_clean(
                        ip, port, connect_timeout=min(timeout, 1.8), http_timeout=min(http_timeout, 1.8)
                    )

        completed += 1
        fc = _get_fc(row)
        if alive:
            row["fail_count"] = 0
            row["delay_ms"] = latency
            if colo:
                row["colo"] = colo
            row["cf_clean"] = "true" if is_cf else "false"
            pass_count += 1
            if is_cf:
                cf_clean_count += 1
        else:
            row["fail_count"] = fc + 1
            row["cf_clean"] = "false"
            fail_count_total += 1

        if completed % 1000 == 0 or completed == total:
            log.info(
                "[ProxyIP 质检进度] %d/%d (%.1f%%) - 存活: %d (🌟优选双料: %d), 标记: %d",
                completed, total, completed / total * 100, pass_count, cf_clean_count, fail_count_total,
            )

    tasks = [_check(i) for i in indices]
    await asyncio.gather(*tasks)

    log.info(
        "[ProxyIP 质检] 校验完成: 共 %d 条 | 存活通过 %d 条 (%.1f%%, 🌟优选双料: %d 条), 失败标记 %d 条",
        total, pass_count, (pass_count / total * 100) if total else 0, cf_clean_count, fail_count_total,
    )
    return rows, cf_clean_count


# ---------- Telegram 质检通知 ----------
def send_proxyip_notification(
    total: int,
    pass_count: int,
    fail_count: int,
    eliminated: int,
    survivors: int,
    cf_clean_count: int,
    concurrency: int,
    max_fails: int,
    elapsed: float,
):
    """推送独立的 ProxyIP 穿透质检统计 TG 卡片"""
    token = TG_BOT_TOKEN
    chat_id = TG_CHAT_ID

    if not token or not chat_id:
        log.info("未配置 TG_BOT_TOKEN / TG_CHAT_ID，跳过 Telegram 质检通知推送")
        return

    tz_bj = timezone(timedelta(hours=8))
    now = datetime.now(tz_bj)
    date_str = now.strftime("%Y-%m-%d %H:%M")
    div = "━━━━━━━━━━━━━━━━━━━━"

    elim_str = (
        f"<code>{eliminated}</code> 条 (连续失败 ≥ {max_fails} 次)"
        if eliminated > 0
        else "无 (全部在存活阈值内)"
    )

    header = (
        f"🔀 <b>ProxyIP 穿透质检完成</b> (🗑️ 剔除 <b>{eliminated}</b> 死节点)"
        if eliminated > 0
        else f"🔀 <b>ProxyIP 穿透质检完成</b> (✅ 存活 <b>{pass_count}</b> 条)"
    )

    status_line = f"✅ <b>{pass_count}</b> 存活"
    if fail_count > 0:
        status_line += f" · ⚠️ <b>{fail_count}</b> 失败标记"

    dual_line = (
        f"\n   └ <i>🌟 兼具优选直连: <code>{cf_clean_count}</code> 条 (已导出 data/proxyip_cf.txt)</i>"
        if cf_clean_count > 0
        else ""
    )

    github_server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    github_repo = os.getenv("GITHUB_REPOSITORY")
    github_run_id = os.getenv("GITHUB_RUN_ID")
    github_run_number = os.getenv("GITHUB_RUN_NUMBER")

    footer_parts = [f"⚡ <b>耗时</b>: {elapsed:.1f}s"]
    if github_repo:
        repo_url = f"{github_server}/{github_repo}"
        if github_run_id:
            run_label = f"Action #{github_run_number}" if github_run_number else "Action 日志"
            footer_parts.append(f'🔗 <a href="{repo_url}/actions/runs/{github_run_id}">{run_label}</a>')
        footer_parts.append(f'📦 <a href="{repo_url}">产物仓库</a>')

    footer_line = f"\n{div}\n" + " · ".join(footer_parts)

    message = (
        f"{header}\n"
        f"{div}\n"
        f"📅 <b>时间</b>：{date_str} (北京时间)\n"
        f"🛡️ <b>池内节点</b>：<code>{survivors}</code> 条 ({status_line}){dual_line}\n"
        f"🗑️ <b>淘汰死节点</b>：{elim_str}\n"
        f"⚙️ <b>质检规格</b>：/cdn-cgi/trace 穿透 + 优选双能检验 · {concurrency} 并发\n"
        f"{footer_line}"
    )

    try:
        send_tg_message(message, token=token, chat_id=chat_id, tag="proxyip-verify")
    except Exception as e:
        log.warning("发送 Telegram 消息时出现异常: %s", e)


# ---------- 主流程入口 ----------
async def async_main(args):
    t_start = time.time()

    if not os.path.isfile(PROXYIP_CSV):
        log.info(">>> 未找到 %s 文件，跳过 ProxyIP 质检", PROXYIP_CSV)
        return

    rows = load_proxyip_csv(PROXYIP_CSV)
    total = len(rows)
    log.info(">>> 开始执行 ProxyIP 穿透质检 (%s): 共 %d 条记录...", PROXYIP_CSV, total)

    rows, cf_clean_count = await verify_proxyips(
        rows,
        concurrency=args.concurrency,
        timeout=args.timeout,
        http_timeout=args.http_timeout,
    )

    pass_count = sum(1 for r in rows if _get_fc(r) == 0)
    fail_count = total - pass_count

    # 物理淘汰连续失败达到阈值的节点
    survivors = [r for r in rows if _get_fc(r) < args.max_fails]
    eliminated = total - len(survivors)
    survivors_len = len(survivors)

    if eliminated > 0:
        log.info("[ProxyIP 淘汰] 剔除 %d 条连续失败 >= %d 次的死节点", eliminated, args.max_fails)
    else:
        log.info("[ProxyIP 淘汰] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

    save_proxyip(
        survivors,
        csv_path=PROXYIP_CSV,
        txt_path=PROXYIP_TXT,
        dir_path=PROXYIP_DIR,
        cf_txt_path=PROXYIP_CF_TXT,
        cf_dir_path=PROXYIP_CF_DIR,
    )

    elapsed = time.time() - t_start
    log.info("ProxyIP 穿透质检流程执行完毕，总耗时 %.2f 秒 (🌟兼具优选直连: %d 条)", elapsed, cf_clean_count)

    # 若存在 tg_fetch 暂存的抓取统计，将 ProxyIP 质检与优选双料结果并入其中，由后续统一卡片推送
    fetch_stats_file = os.path.join(DATA_DIR, ".fetch_stats.json")
    has_fetch_stats = os.path.isfile(fetch_stats_file)
    if has_fetch_stats:
        try:
            with open(fetch_stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
            stats["proxyip_verified"] = True
            stats["proxyip_pass"] = pass_count
            stats["proxyip_fail"] = fail_count
            stats["proxyip_eliminated"] = eliminated
            stats["proxyip_survivors"] = survivors_len
            stats["proxyip_cf_clean"] = cf_clean_count
            stats["proxyip_elapsed"] = elapsed
            with open(fetch_stats_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, ensure_ascii=False, indent=2)
            log.info("已将 ProxyIP 质检统计写入 %s (并入统一卡片)", fetch_stats_file)
        except Exception as e:
            log.warning("写入 %s 失败: %s", fetch_stats_file, e)

    if not args.no_notify and not has_fetch_stats:
        send_proxyip_notification(
            total=total,
            pass_count=pass_count,
            fail_count=fail_count,
            eliminated=eliminated,
            survivors=survivors_len,
            cf_clean_count=cf_clean_count,
            concurrency=args.concurrency,
            max_fails=args.max_fails,
            elapsed=elapsed,
        )
    else:
        log.info("已并入流水线或指定了 --no-notify，跳过独立卡片推送，由统一卡片汇总发送")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 反代 ProxyIP 穿透质检与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help=f"并发探测协程数 (默认 {CONCURRENCY})")
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"单节点连接与 TLS 握手超时秒数 (默认 {TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"单节点 HTTP 校验超时秒数 (默认 {HTTP_TIMEOUT})")
    parser.add_argument("--no-notify", action="store_true", help="静默模式，不单独发送 Telegram 质检通知（供流水线协同使用）")
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
