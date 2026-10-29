#!/usr/bin/env python3
"""
Cloudflare 反代 ProxyIP 穿透质检与淘汰引擎 (proxyip_verify.py)

专门针对反代 ProxyIP（proxyip.csv / proxyip.txt）执行深层应用层协议穿透探测：
  1. TCP 三次握手 + TLS ClientHello（SNI: speed.cloudflare.com，跳过反代非官方证书校验，超时 4.0s）
  2. HTTP/1.1 GET /cdn-cgi/trace 探针请求（浏览器伪装 UA, Connection: close，读取超时 3.5s）
  3. 严格三维校验：统一 deadline 循环读取（上限 4096B），Header 与 Body 物理隔离，Header 严格校验 HTTP 200 + Server: cloudflare，Body 正则提取有效 colo 机房代号
  4. 优雅关闭连接（writer.close + wait_closed），释放套接字资源

淘汰、属性打标与分层导出机制：
  - 存活节点：fail_count 重置为 0，回填实时 delay_ms、colo 机房码
  - 失败节点：fail_count 递增 +1
  - 物理淘汰：连续失败达到阈值（默认 3 次）的死节点从 proxyip.csv 与 proxyip.txt 中永久物理删除，并登入墓地（data/tombstone.json）防止回流
  - 网络属性打标：落盘前调用 classify_asn 计算 net_type（严格对齐 ipinfo.io 标准：isp/business/education/government/datacenter）
  - 分类分国导出：自动输出分国家独立纯文本文件及【ISP_运营商原生宽带】、【BIZ_商业企业专线】等 4 类特殊资产纯净列表
  - 排序落盘：存活优先（fail_count 升序），低延迟优先（delay_ms 升序），最新测试时间降序
  - 结果聚合：支持将质检统计回写至 .fetch_stats.json，由流水线终点 cf_verify 聚合发送四维合一总览卡片
"""

from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict
import concurrent.futures
import contextlib
import csv
import json
import logging
import os
import random
import re
import ssl
import sys
import time
from datetime import datetime, timezone, timedelta
import urllib.error
import urllib.request

from providers import (
    load_dotenv,
    safe_int,
    send_tg_message,
    get_keyed_lock,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    format_proxyip_txt,
    save_proxyip_by_country,
    classify_asn,
    normalize_timestamp,
    record_tombstone,
    load_tombstone,
    is_tombstoned,
    canonical_key,
    read_full_response,
    safe_close_writer,
    split_header_body,
    format_buffer_badge,
    RE_SERVER_CF,
    RE_CF_RAY,
    RE_CF_1034,
    RE_NON_CF_FASTLY,
    RE_NON_CF_AKAMAI,
    format_asn_isp,
    atomic_writer,
    atomic_write_text,
    atomic_write_json,
    probe_check_proxyip_api,
    is_asn_recorded,
    auto_enrich_and_save_asns,
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

PROBE_HOST = "speed.cloudflare.com"
PROBE_PATH = "/cdn-cgi/trace"

# 质检调优核心参数（兼顾跨洲网络高延迟与抗误杀设计）
TIMEOUT = 4.0        # TCP 建立连接与 TLS 握手超时（实测 4.0s 显著降低跨洲远距离/家庭宽带假死误杀率）
HTTP_TIMEOUT = 3.5   # HTTP /cdn-cgi/trace 读取统一 deadline 超时
CONCURRENCY = 250    # 异步探测协程池并发上限（平滑并发，兼顾速度与对端防刷限流）
MAX_FAILS = 3        # 连续失败物理淘汰阈值（第 1~2 次缓冲容错，连续 3 次全网不可达永久淘汰）

# 混合分流架构准则（对标 proxies_verify 的成熟模型）：
# 1. 默认读取环境变量 CHECK_PROXYIP_URL；
# 2. 已知画像且非机房的老节点走本地极速原生探测（零外部消耗、250 高并发）；
# 3. 仅对缺少 exit_ip、未定性或 ASN 未知的新节点，通过专用线程池非阻塞调用外部端点补全画像。
CHECK_ENDPOINT = os.getenv("CHECK_PROXYIP_URL", "").strip()
CHECK_CONCURRENCY = safe_int(os.getenv("CHECK_CONCURRENCY"), 32)
_CHECK_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None


def get_check_executor(max_workers: int | None = None) -> concurrent.futures.ThreadPoolExecutor:
    """获取或惰性初始化 ProxyIP 外部质检专用高并发线程池"""
    global _CHECK_EXECUTOR
    if _CHECK_EXECUTOR is None:
        workers = max_workers if max_workers is not None else CHECK_CONCURRENCY
        _CHECK_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="proxyip_worker",
        )
    return _CHECK_EXECUTOR


def shutdown_check_executor(wait: bool = False, cancel_futures: bool = True) -> None:
    """关闭外部质检线程池，释放线程资源"""
    global _CHECK_EXECUTOR
    if _CHECK_EXECUTOR is not None:
        with contextlib.suppress(Exception):
            _CHECK_EXECUTOR.shutdown(wait=wait, cancel_futures=cancel_futures)
        _CHECK_EXECUTOR = None


def check_proxyip_endpoint_health(endpoint: str, timeout: float = 6.0) -> bool:
    """
    质检开始前，对 Check ProxyIP 外部检测端点进行全局健康探针校验。
    确认端点在线可用、域名正确且未欠费或被封禁。
    若探测失败，则安全熔断并全局降级为本地直接探测，避免单节点频繁失败或卡顿。
    """
    if not endpoint:
        return False
    clean_ep = endpoint.rstrip("/")
    probe_urls = [clean_ep] if clean_ep.endswith("/check") else [clean_ep, f"{clean_ep}/check"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    }
    for target in probe_urls:
        try:
            req = urllib.request.Request(target, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 204):
                    return True
        except urllib.error.HTTPError as he:
            if he.code in (200, 400, 404):
                return True
        except Exception as e:
            log.debug("Check ProxyIP 端点健康探针 [%s] 异常: %s", target, e)
    return False


def _sync_check_proxyip_endpoint(
    endpoint: str,
    ip: str,
    port: int,
    timeout: float = 7.0,
) -> tuple[bool, int, str, str, str, str, str]:
    """
    同步调用 Check ProxyIP 外部检测接口（在独立线程池中并发执行，不阻塞事件循环，杜绝盲等）。
    返回 (is_alive, latency_ms, colo, reason, exit_ip, exit_asn, exit_isp)
    """
    t0 = time.monotonic()
    res = probe_check_proxyip_api(ip, port, endpoint=endpoint, timeout=timeout)
    latency_ms = max(1, int((time.monotonic() - t0) * 1000))
    if res.get("success"):
        colo = res.get("colo", "")
        exit_ip = res.get("exit_ip", "")
        exit_asn = res.get("exit_asn", "")
        exit_isp = res.get("exit_isp", "")
        return True, latency_ms, colo, "ok", exit_ip, exit_asn, exit_isp
    else:
        reason = res.get("reason") or (f"status_{res.get('status')}" if res.get('status') else "probe_failed")
        return False, 0, "", reason, "", "", ""


# ProxyIP 纯净数据表字段定义
CSV_FIELDS = [
    "ip", "port", "tls", "delay_ms", "speed_kbs",
    "colo", "cf_location", "asn", "isp",
    "first_seen", "channel", "fail_count", "net_type", "exit_ip",
]

# 反代穿透上下文：跳过非官方证书校验（安全审计说明：有意设计，反代节点由第三方部署且证书各异，需直接与节点建立 TLS 隧道嗅探 CDN /cdn-cgi/trace 边缘机房特征）
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
with contextlib.suppress(Exception):
    SSL_CTX.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
with contextlib.suppress(Exception):
    SSL_CTX.set_ciphers("DEFAULT:@SECLEVEL=0")


# 确定性致命硬故障状态集：协议错配、非反代服务、SNI 域名拒绝或鉴真伪装
# 遇此错误直接判死淘汰（fail_count 直接拉满至 max_fails 并移入墓地冷却库），不进入缓冲期
FATAL_FAIL_STATUSES = {
    "no_cf_header",    # 响应头无 Server: cloudflare（假节点、Captive Portal 登录弹窗或运营商劫持）
    "status_404",      # /cdn-cgi/trace 404（普通 Web 网站，未配置反代转发规则）
    "status_421",      # 421 Misdirected Request（SNI/Host 域名被反代明确拒绝）
    "status_400",      # 400 Bad Request（协议畸形或私有协议误录入）
    "non_cf_cdn",      # 异构 CDN 伪节点 (Fastly/Akamai 等，报文特征明确排他)
    "tls_error",       # TLS 握手异常（纯明文 HTTP 端口或 SSL 协议不匹配）
    "empty_response",  # 建立连接后发送请求立即断开（死连接/假服务）
    "invalid_row",     # 数据行字段损坏或端口非法
}


# 预编译正则，高并发下零重复编译开销
RE_HTTP_STATUS = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})\b")
RE_HTTP_200 = re.compile(rb"^HTTP/\d\.\d\s+200\b")
RE_COLO = re.compile(rb"colo=([A-Za-z0-9]+)", re.IGNORECASE)


# ---------- 核心探测函数 ----------
async def probe_proxyip(
    ip: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str]:
    """
    对单个 ProxyIP 节点执行 TLS 穿透 + /cdn-cgi/trace 鉴真。

    返回 (is_alive, latency_ms, colo, reason):
        is_alive=True  -> 探测成功，latency_ms 为握手延迟，colo 为解析到的机房代号，reason 为 "ok"
        is_alive=False -> 探测失败，reason 记录具体失败原因 (如 connect_timeout, tls_error, http_timeout, status_502, no_cf_header, no_colo 等)
    """
    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=PROBE_HOST),
            timeout=connect_timeout,
        )
        t1 = time.monotonic()
        latency_ms = max(1, int((t1 - t0) * 1000))
    except asyncio.TimeoutError:
        return False, 0, "", "connect_timeout"
    except (ssl.SSLError, ssl.CertificateError):
        return False, 0, "", "tls_error"
    except (ConnectionRefusedError, OSError):
        return False, 0, "", "conn_error"
    except Exception as e:
        return False, 0, "", f"connect_failed_{type(e).__name__}"

    try:
        http_deadline = time.monotonic() + http_timeout
        req = (
            f"GET {PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(req)
        drain_timeout = max(0.001, http_deadline - time.monotonic())
        await asyncio.wait_for(writer.drain(), timeout=drain_timeout)

        read_timeout = max(0.001, http_deadline - time.monotonic())
        resp_bytes = await read_full_response(reader, read_timeout, need_body=True)
        if not resp_bytes:
            return False, latency_ms, "", "empty_response"

        header_part, body_part = split_header_body(resp_bytes)
        status_match = RE_HTTP_STATUS.match(header_part)
        status_code = status_match.group(1).decode("latin1") if status_match else ""

        is_200 = bool(RE_HTTP_200.match(header_part))
        is_cf = bool(RE_SERVER_CF.search(header_part))

        # colo 字段在响应 Body 里（/cdn-cgi/trace 返回纯文本键值对），不在 Header
        colo_match = RE_COLO.search(body_part)
        colo = colo_match.group(1).decode().upper() if colo_match else ""

        if is_200 and is_cf and bool(colo):
            return True, latency_ms, colo, "ok"

        # 报文级鉴真：识别 Cloudflare 官方 1034 边缘受限真节点 (403 + Server: cloudflare + CF-RAY + error code: 1034)
        is_cf_1034 = (
            status_code == "403"
            and is_cf
            and bool(RE_CF_RAY.search(header_part))
            and bool(RE_CF_1034.search(body_part))
        )
        if is_cf_1034:
            m_ray = RE_CF_RAY.search(header_part)
            ray_colo = m_ray.group(1).split(b"-")[-1].decode().upper() if m_ray else "CF"
            return True, latency_ms, ray_colo, "ok"

        # 报文级排他：精准识别混入的异构 CDN 伪节点 (Fastly 421 SAN 拒绝 / Akamai 400 Bad Request)
        is_fastly = bool(RE_NON_CF_FASTLY.search(body_part)) or (status_code == "421" and not is_cf)
        is_akamai = bool(RE_NON_CF_AKAMAI.search(header_part))
        if is_fastly or is_akamai:
            return False, latency_ms, "", "non_cf_cdn"

        if not is_200:
            return False, latency_ms, colo, f"status_{status_code}" if status_code else "invalid_http_status"
        elif not is_cf:
            return False, latency_ms, colo, "no_cf_header"
        else:
            return False, latency_ms, "", "no_colo"
    except asyncio.TimeoutError:
        return False, latency_ms, "", "http_timeout"
    except Exception as e:
        return False, latency_ms, "", f"http_error_{type(e).__name__}"
    finally:
        if writer is not None:
            await safe_close_writer(writer)


# ---------- 数据加载与保存 ----------
def load_proxyip_csv(path: str) -> list:
    """读取 proxyip.csv，自动处理 utf-8-sig BOM、自动过滤墓地黑名单及非法端口"""
    if not os.path.exists(path):
        return []
    tombstone = load_tombstone()
    rows = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            ip = str(r.get("ip") or "").strip()
            port = safe_int(r.get("port"), 0)
            if not ip or port <= 0 or port > 65535:
                continue
            key = canonical_key(ip, port)
            if is_tombstoned(key, tombstone):
                continue
            r["ip"] = ip
            r["port"] = str(port)
            r["fail_count"] = safe_int(r.get("fail_count"), 0)
            r["first_seen"] = normalize_timestamp(str(r.get("first_seen") or r.get("tested_at") or ""))
            rows.append(r)
    return rows


def _get_fc(r: dict) -> int:
    return safe_int(r.get("fail_count"), 0)


def save_proxyip(
    rows: list,
    csv_path: str = PROXYIP_CSV,
    txt_path: str = PROXYIP_TXT,
    dir_path: str = PROXYIP_DIR,
):
    """
    覆写保存 proxyip.csv 与 proxyip.txt。
    同时将全量反代按国家/地区拆分至 data/proxyip/ 独立目录。
    自动按质量排序：存活节点优先（fail_count 升序），低延迟优先（delay_ms 升序）。
    """
    # 稳定双重排序：先按 first_seen 降序（最新优先），再按 (fail_count, delay_ms) 升序
    rows.sort(key=lambda r: r.get("first_seen", ""), reverse=True)

    def _sort_key(r):
        fc = _get_fc(r)
        d = safe_int(r.get("delay_ms"), 0)
        delay = d if d > 0 else 99999
        return (fc, delay)

    rows.sort(key=_sort_key)

    for row in rows:
        exit_asn = row.get("exit_asn") or row.get("asn", "")
        exit_isp = row.get("exit_isp") or row.get("isp", "")
        row["asn"] = format_asn_isp(exit_asn or row.get("asn", ""), exit_isp or row.get("isp", ""))
        row["net_type"] = classify_asn(exit_asn, exit_isp) or row.get("net_type", "datacenter")
        row.setdefault("exit_ip", "")

    with atomic_writer(csv_path, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("已覆写保存 %s: %d 条记录 (含 fail_count, net_type 列)", csv_path, len(rows))

    atomic_write_text(txt_path, format_proxyip_txt(rows), encoding="utf-8")
    log.info("已按质检状态分层保存 %s: %d 条记录", txt_path, len(rows))

    split_cnt = save_proxyip_by_country(rows, dir_path)
    log.info("已在 %s/ 目录下生成 %d 个独立国家/地区纯文本文件", dir_path, split_cnt)


# ---------- 批量质检调度器 ----------
async def verify_proxyips(
    rows: list,
    concurrency: int = CONCURRENCY,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
    max_fails: int = MAX_FAILS,
    check_endpoint: str = "",
    check_executor: concurrent.futures.ThreadPoolExecutor | None = None,
) -> list:
    """
    并发调度对所有 ProxyIP 进行穿透鉴真：
    - 若配置了 check_endpoint，通过外部端点（Check ProxyIP）进行高并发多线程鉴真并提取真实出口与 ASN；
    - 若未配置端点，则回退为本地原生 TLS 穿透 + /cdn-cgi/trace 校验；
    打乱执行顺序以将同 IP 多端口请求自然散列，防止突发流量触发对端防护。
    对致命硬故障（FATAL_FAIL_STATUSES）直接拉满 fail_count = max_fails 即刻淘汰入墓地。
    原地更新 fail_count、delay_ms、colo。
    返回 rows。
    """
    total = len(rows)
    if total == 0:
        return rows

    sem = asyncio.Semaphore(concurrency)
    pass_count = 0
    fail_count_total = 0
    completed = 0
    local_checked_cnt = 0
    worker_checked_cnt = 0
    reasons_counter: dict[str, int] = defaultdict(int)

    # 全局显式初始化 _old_fc，确保异常提前返回或空跑时不遗留未定义状态
    for r in rows:
        r.setdefault("_old_fc", _get_fc(r))

    # 创建乱序执行队列，保护同 IP 多端口节点
    indices = list(range(total))
    random.shuffle(indices)

    async def _check(idx: int):
        nonlocal pass_count, fail_count_total, completed, local_checked_cnt, worker_checked_cnt
        row = rows[idx]
        fc = _get_fc(row)
        row["_old_fc"] = fc

        port = safe_int(row.get("port"), 0)

        ip = (row.get("ip") or "").strip()
        if not ip or port <= 0 or port > 65535:
            completed += 1
            row["fail_count"] = max_fails
            fail_count_total += 1
            reasons_counter["invalid_row"] += 1
            return

        lock_key = f"{ip}:{port}"
        async with sem, get_keyed_lock(lock_key):
            # 混合分流准入控制（对标 proxies_verify 的成熟模型）：
            # 1. 凡是老节点且已确认具备有效出口画像与非机房属性，走本地轻量高并发 probe_proxyip 极速探针，0 消耗 Worker 额度；
            # 2. 凡是新拉取、缺少 exit_ip、未定性或 ASN 未知的节点，走 check_endpoint 外部端点进行严格穿透鉴真并补齐画像；
            raw_asn = (row.get("asn") or "").strip().upper()
            has_complete_profile = (
                bool(row.get("exit_ip"))
                and bool(raw_asn)
                and raw_asn not in ("AS0", "0", "UNKNOWN", "AS_UNKNOWN")
                and (row.get("net_type") or "").strip().lower() in ("isp", "business", "education", "government")
            )

            if not has_complete_profile and check_endpoint and check_executor:
                worker_checked_cnt += 1
                # 外部端点多线程并发穿透鉴真模式（高并发多线程不盲等，精准补齐出口画像）
                loop = asyncio.get_running_loop()
                alive, latency, colo, reason, exit_ip, exit_asn, exit_isp = await loop.run_in_executor(
                    check_executor, _sync_check_proxyip_endpoint, check_endpoint, ip, port, timeout
                )
                if alive:
                    if exit_ip:
                        row["exit_ip"] = exit_ip
                    if exit_asn:
                        row["asn"] = format_asn_isp(exit_asn, exit_isp)
                        row["isp"] = exit_isp
                        if not is_asn_recorded(exit_asn):
                            auto_enrich_and_save_asns([{"asn": exit_asn, "isp": exit_isp, "ip": exit_ip or ip}])
                        row["net_type"] = classify_asn(exit_asn, exit_isp)
            else:
                local_checked_cnt += 1
                # 本地直接 TLS 穿透 + /cdn-cgi/trace 鉴真
                alive, latency, colo, reason = await probe_proxyip(
                    ip, port, connect_timeout=timeout, http_timeout=http_timeout
                )

        completed += 1
        reasons_counter[reason] += 1
        row["_reason"] = reason
        fc = _get_fc(row)
        if alive:
            row["fail_count"] = 0
            row["delay_ms"] = latency
            if colo:
                row["colo"] = colo
            pass_count += 1
        else:
            if reason in FATAL_FAIL_STATUSES:
                row["fail_count"] = max_fails
            else:
                row["fail_count"] = fc + 1
            fail_count_total += 1

        if completed % 1000 == 0 or completed == total:
            log.info(
                "[ProxyIP 质检进度] %d/%d (%.1f%%) - 存活: %d, 标记: %d",
                completed, total, completed / total * 100, pass_count, fail_count_total,
            )

    tasks = [_check(i) for i in indices]
    await asyncio.gather(*tasks)

    sorted_reasons = sorted(reasons_counter.items(), key=lambda x: x[1], reverse=True)
    reason_summary = ", ".join(f"{k}: {v}" for k, v in sorted_reasons)
    log.info(
        "[ProxyIP 质检] 校验完成: 共 %d 条 | 存活通过 %d 条 (%.1f%%), 失败标记 %d 条 (本地原生探测: %d 条, 外部 Worker 鉴真: %d 条)",
        total,
        pass_count,
        (pass_count / total * 100) if total else 0,
        fail_count_total,
        local_checked_cnt,
        worker_checked_cnt,
    )
    log.info("[ProxyIP 质检] 探测原因汇总: %s", reason_summary)
    return rows


# ---------- Telegram 质检通知 ----------


def send_proxyip_notification(
    total: int,
    pass_count: int,
    fail_count: int,
    eliminated: int,
    survivors: int,
    concurrency: int,
    max_fails: int,
    elapsed: float,
    fail_1: int = 0,
    fail_2: int = 0,
    buf_new: int = 0,
    buf_rec: int = 0,
    avg_delay: int = 0,
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

    buffer_badge = format_buffer_badge(fail_count, buf_new=buf_new, buf_rec=buf_rec, f1=fail_1, f2=fail_2, bold=True)
    status_line = f"✅ <b>{pass_count}</b> 存活{buffer_badge}"

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

    delay_str = f"\n⚡ <b>存活均延</b>：<code>{avg_delay}ms</code>" if avg_delay > 0 else ""

    message = (
        f"{header}\n"
        f"{div}\n"
        f"📅 <b>时间</b>：{date_str} (北京时间)\n"
        f"🛡️ <b>池内节点</b>：<code>{survivors}</code> 条 ({status_line})"
        f"{delay_str}\n"
        f"🗑️ <b>淘汰死节点</b>：{elim_str}\n"
        f"⚙️ <b>质检规格</b>：/cdn-cgi/trace 穿透鉴真 · {concurrency} 并发\n"
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

    endpoint = getattr(args, "check_endpoint", "").strip() or CHECK_ENDPOINT
    check_concurrency = getattr(args, "check_concurrency", CHECK_CONCURRENCY)
    check_executor = None

    if endpoint:
        # 质检启动前对 Check ProxyIP 端点进行单次健康探针校验，若不可达则全局安全熔断降级
        is_endpoint_ok = await asyncio.to_thread(check_proxyip_endpoint_health, endpoint)
        if is_endpoint_ok:
            check_executor = get_check_executor(max_workers=check_concurrency)
            log.info(
                "🚀 启用 Check ProxyIP 外部穿透鉴真端点 (混合分流模式: 已知画像走本地, 未知新节点走端点): %s (专用并发线程: %d)",
                endpoint,
                check_concurrency,
            )
        else:
            log.warning(
                "⚠️ Check ProxyIP 端点 [%s] 健康校验失败 (不可达/响应异常)，本轮将全局熔断降级为本地直接探测",
                endpoint,
            )
            endpoint = ""
    else:
        log.info("未配置外部检测端点，采用本地原生 TLS 穿透质检（零外部依赖，并发: %d）", args.concurrency)

    try:
        rows = await verify_proxyips(
            rows,
            concurrency=args.concurrency,
            timeout=args.timeout,
            http_timeout=args.http_timeout,
            max_fails=args.max_fails,
            check_endpoint=endpoint,
            check_executor=check_executor,
        )
    finally:
        if check_executor:
            shutdown_check_executor()

    pass_count = sum(1 for r in rows if _get_fc(r) == 0)
    fail_count = total - pass_count

    # 物理淘汰连续失败达到阈值的节点
    survivors = [r for r in rows if _get_fc(r) < args.max_fails]
    eliminated = total - len(survivors)
    survivors_len = len(survivors)
    proxyip_f1 = sum(1 for r in survivors if _get_fc(r) == 1)
    proxyip_f2 = sum(1 for r in survivors if _get_fc(r) == 2)
    proxyip_buf_new = sum(
        1 for r in rows
        if _get_fc(r) > 0 and _get_fc(r) < args.max_fails and safe_int(r.get("_old_fc"), 0) == 0
    )
    proxyip_buf_rec = sum(
        1 for r in rows
        if _get_fc(r) == 0 and safe_int(r.get("_old_fc"), 0) > 0
    )

    # 仅统计本次实测存活节点的网络延迟（排除缓冲期节点的旧延迟）
    alive_delays = [
        int(r.get("delay_ms", 0))
        for r in rows
        if _get_fc(r) == 0 and safe_int(r.get("delay_ms"), 0) > 0
    ]
    avg_delay = int(sum(alive_delays) / len(alive_delays)) if alive_delays else 0

    elapsed = time.time() - t_start
    log.info("ProxyIP 穿透质检流程执行完毕，总耗时 %.2f 秒 (✅ 存活: %d | 均延: %dms | ⚠️ 缓冲: %d [新增: %d, 取消恢复: %d])", elapsed, pass_count, avg_delay, (survivors_len - pass_count), proxyip_buf_new, proxyip_buf_rec)

    # 导出逐节点诊断结果 (仅在指定参数时生成，无论是否 dry_run)
    if getattr(args, "diag_output", ""):
        diag_data = {
            "timestamp": int(time.time()),
            "concurrency": args.concurrency,
            "timeout": args.timeout,
            "http_timeout": args.http_timeout,
            "proxyip": {
                canonical_key(r.get("ip", ""), r.get("port", 0)): {
                    "reason": r.get("_reason", "unknown"),
                    "alive": _get_fc(r) == 0,
                    "latency": safe_int(r.get("delay_ms"), 0),
                    "colo": r.get("colo", ""),
                }
                for r in rows
                if r.get("ip") and safe_int(r.get("port"), 0) > 0
            },
        }
        try:
            with open(args.diag_output, "w", encoding="utf-8") as f:
                json.dump(diag_data, f, ensure_ascii=False, indent=2)
            log.info("已成功导出 ProxyIP 逐节点诊断结果至 %s", args.diag_output)
        except Exception as e:
            log.warning("导出 ProxyIP 诊断结果失败: %s", e)

    # 诊断演练模式：跳过写入、墓地与通知
    if getattr(args, "dry_run", False):
        log.info("[ProxyIP (Dry-Run)] 演练诊断模式：仅统计探测原因，跳过磁盘文件覆写与墓地登记")
        return

    # 保存优先于墓地登记的时序
    save_proxyip(
        survivors,
        csv_path=PROXYIP_CSV,
        txt_path=PROXYIP_TXT,
        dir_path=PROXYIP_DIR,
    )

    if eliminated > 0:
        log.info("[ProxyIP 淘汰] 剔除 %d 条连续失败 >= %d 次的死节点", eliminated, args.max_fails)
        dead_nodes = [r for r in rows if _get_fc(r) >= args.max_fails]
        dead_keys = [
            canonical_key(r.get("ip", ""), r.get("port", 0))
            for r in dead_nodes
            if r.get("ip") and safe_int(r.get("port"), 0) > 0
        ]
        newly_tombstoned = record_tombstone(dead_keys)
        log.info("[ProxyIP 墓地] 已登记 %d 个淘汰死节点至墓地冷却库 (新增: %d 个, 隔离期 7 天)", len(dead_keys), newly_tombstoned)
    else:
        log.info("[ProxyIP 淘汰] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

    # 若存在 tg_fetch 暂存的抓取统计，将 ProxyIP 质检结果并入其中，由后续统一卡片推送
    fetch_stats_file = os.path.join(DATA_DIR, ".fetch_stats.json")
    has_fetch_stats = os.path.isfile(fetch_stats_file)
    stats_updated = False
    if has_fetch_stats:
        try:
            with open(fetch_stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
            stats["proxyip_verified"] = True
            stats["proxyip_total"] = total
            stats["proxyip_pass"] = pass_count
            stats["proxyip_fail"] = fail_count
            stats["proxyip_fail_1"] = proxyip_f1
            stats["proxyip_fail_2"] = proxyip_f2
            stats["proxyip_buf_new"] = proxyip_buf_new
            stats["proxyip_buf_rec"] = proxyip_buf_rec
            stats["proxyip_eliminated"] = eliminated
            stats["proxyip_survivors"] = survivors_len
            stats["proxyip_elapsed"] = elapsed
            stats["proxyip_max_fails"] = args.max_fails
            stats["proxyip_avg_delay_ms"] = avg_delay
            atomic_write_json(fetch_stats_file, stats)
            stats_updated = True
            log.info("已将 ProxyIP 质检统计写入 %s (并入统一卡片)", fetch_stats_file)
        except Exception as e:
            log.warning("写入 %s 失败: %s", fetch_stats_file, e)

    # 仅在非流水线或写入统计失败时，由独立卡片兜底推送
    if not args.no_notify and not stats_updated and not getattr(args, "dry_run", False):
        send_proxyip_notification(
            total=total,
            pass_count=pass_count,
            fail_count=fail_count,
            eliminated=eliminated,
            survivors=survivors_len,
            concurrency=args.concurrency,
            max_fails=args.max_fails,
            elapsed=elapsed,
            fail_1=proxyip_f1,
            fail_2=proxyip_f2,
            buf_new=proxyip_buf_new,
            buf_rec=proxyip_buf_rec,
            avg_delay=avg_delay,
        )
    else:
        log.info("已并入流水线、指定了 --no-notify 或处于 --dry-run，跳过独立卡片推送")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare 反代 ProxyIP 穿透质检与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help=f"并发探测协程数 (默认 {CONCURRENCY})")
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"单节点连接与 TLS 握手超时秒数 (默认 {TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"单节点 HTTP 校验超时秒数 (默认 {HTTP_TIMEOUT})")
    parser.add_argument("--check-endpoint", type=str, default=CHECK_ENDPOINT, help="Check ProxyIP 外部检测端点 URL (默认读取环境变量 CHECK_PROXYIP_URL，留空使用本地直接探测)")
    parser.add_argument("--check-concurrency", type=int, default=CHECK_CONCURRENCY, help=f"外部检测端点并发线程数 (默认 {CHECK_CONCURRENCY})")
    parser.add_argument("--no-notify", action="store_true", help="静默模式，不单独发送 Telegram 质检通知（供流水线协同使用）")
    parser.add_argument("--dry-run", action="store_true", help="演练诊断模式，仅探测统计原因，不覆写数据文件也不登记墓地")
    parser.add_argument("--diag-output", type=str, default="", help="诊断结果输出 JSON 路径，记录每个节点的探测原因明细")
    args = parser.parse_args()

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
