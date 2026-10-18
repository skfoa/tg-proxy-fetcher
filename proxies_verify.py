#!/usr/bin/env python3
"""
多协议通用代理连通性质检与淘汰引擎 (proxies_verify.py)

针对 proxies.txt（涵盖 SOCKS5, HTTP, HTTPS, TURN, SSTP 协议代理）进行应用层真实穿透校验：
  1. SOCKS5: RFC 1928 / RFC 1929 五步握手状态机 (无密码/有密码) -> CONNECT speed.cloudflare.com:80 -> GET /cdn-cgi/trace 校验 200 + Server: cloudflare + 正则解析 colo
  2. HTTP (明文): RFC 7230 正向代理绝对路径穿透 (单 RTT 直通 speed.cloudflare.com:80，强制校验 200 + colo 机房码，单次判死杜绝二次回退叠加)
  3. HTTPS (加密): TLS 握手 (支持老旧版本与 SECLEVEL=0) -> RFC 7230 绝对 URI GET 深度穿透校验 colo (回退至 CONNECT 443 隧道)
  4. TURN: STUN Binding Request over TCP (RFC 5389)，校验 20 字节头部 Magic Cookie (0x2112A442) 及 Transaction ID
  5. SSTP: MS-SSTP 标准双工信道 (TLS 握手 + SSTP_DUPLEX_POST)，校验 200 OK 确认服务就绪

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
import atexit
import base64
import concurrent.futures
import csv
import functools
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

from providers import (
    load_dotenv,
    safe_int,
    send_tg_message,
    get_keyed_lock,
    TG_BOT_TOKEN,
    TG_CHAT_ID,
    record_tombstone,
    load_tombstone,
    is_tombstoned,
    canonical_key,
    format_proxies_txt,
    save_proxies_by_protocol,
    save_proxies_csv,
    format_buffer_badge,
    read_full_response,
    safe_close_writer,
    PROXY_CSV_FIELDS,
    LEGACY_DEFAULT_FIRST_SEEN,
    resolve_asn_batch_online_async,
    load_ip_cache,
    classify_asn,
    format_asn_isp,
    ASN_TO_PROVIDER,
    ASN_DATABASE_ASN_TO_ISP,
    is_valid_public_ip,
    resolve_domain_to_ip,
    atomic_write_text,
    atomic_write_json,
)

# 确保本地 .env 加载
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("proxies-verify")

# Windows 异步事件循环策略与 UTF-8 输出
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = "data"
PROXIES_TXT = os.path.join(DATA_DIR, "proxies.txt")
PROXIES_CSV = os.path.join(DATA_DIR, "proxies.csv")
PROXIES_DIR = os.path.join(DATA_DIR, "proxies")

PROBE_HOST = "speed.cloudflare.com"
PROBE_PATH = "/cdn-cgi/trace"
PROBE_PORT = 80

TIMEOUT = 3.0
HTTP_TIMEOUT = 2.5
HTTP_PROBE_TIMEOUT = 2.0
HTTP_MAX_LATENCY_MS = 2500
SSTP_TIMEOUT = 8.0
SSTP_READ_TIMEOUT = 4.0
CONCURRENCY = 300
MAX_FAILS = 3
HTTP_MAX_FAILS = 1

# 致命硬故障状态集：对端端口关闭 (Connection Refused)、主机不可达、协议错配或鉴权永久失败
# 遇此错误直接判死淘汰（fail_count 达到淘汰阈值并登记至墓地冷却库），不进入缓冲期
FATAL_FAIL_STATUSES = {
    "conn_err",               # 端口关闭 (Connection Refused) / 主机不可达 / DNS 解析失败
    "bad_handshake",          # 协议头不匹配 (非目标代理协议)
    "no_acceptable_auth",     # 认证方式协商失败 (0xFF)
    "auth_required_missing",  # 代理需要账密认证但未提供
    "auth_fail",              # 代理账密认证错误
    "unsupported_method",     # 不支持的认证方式
    "connect_fail",           # 代理端明确拒绝中继 (CONNECT 响应 REP != 0)
    "http_connect_fail",      # HTTP 代理端明确拒绝 CONNECT 隧道 (400/403/405/502 等)
    "tls_err",                # TLS 握手异常 (非 SSL/TLS 服务)
    "stun_fail",              # STUN/TURN Magic Cookie 校验失败 (非 STUN 服务)
    "stun_not_turn",          # 响应非 TURN Allocate 报文 (纯 STUN 服务，无中继能力)
    "http_connect_no_colo",   # HTTPS 代理 CONNECT 隧道建立后无法读取有效 trace/colo 报文 (假 200 代理)
    "sstp_fail",              # SSTP 隧道请求返回非 200 (非 SSTP 服务)
    "unknown_proto",          # 未知协议
}

CSV_FIELDS = PROXY_CSV_FIELDS

# 复用全局宽容 SSL 证书上下文，避免高并发下每次探测重复加载系统 CA 证书与解析 cipher 导致事件循环冻结
INSECURE_SSL_CTX = ssl.create_default_context()
INSECURE_SSL_CTX.check_hostname = False
INSECURE_SSL_CTX.verify_mode = ssl.CERT_NONE
try:
    INSECURE_SSL_CTX.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
except Exception:
    pass
try:
    INSECURE_SSL_CTX.set_ciphers("DEFAULT:@SECLEVEL=0")
except Exception:
    pass

# 用于与 Cloudflare 边缘服务器建立内层端到端 TLS 隧道的正规现代 SSL 上下文 (避免 SECLEVEL=0 触发 TLSV1_ALERT_INTERNAL_ERROR)
CF_SSL_CTX = ssl.create_default_context()

# 预编译高频响应解析正则，避免协程密集调用中的重复正则解析与查表开销
RE_COLO = re.compile(r"\bcolo=([A-Za-z0-9]+)\b")
RE_LOC = re.compile(r"\bloc=([A-Za-z]{2})\b")
RE_IP = re.compile(r"\bip=([0-9a-fA-F.:]+)\b")
RE_HTTP_200 = re.compile(r"\b200\b")
RE_HTTP_407 = re.compile(r"\b407\b")

CF_CHECK_ENDPOINT = os.getenv("CF_CHECK_ENDPOINT", "").strip()
CF_CONCURRENCY = safe_int(os.getenv("CF_CONCURRENCY"), 32)
_CF_CHECK_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None


def get_cf_check_executor(max_workers: int | None = None) -> concurrent.futures.ThreadPoolExecutor:
    """获取或惰性初始化 Cloudflare Worker SSTP 质检专用高并发线程池"""
    global _CF_CHECK_EXECUTOR
    if _CF_CHECK_EXECUTOR is None:
        workers = max_workers if max_workers is not None else CF_CONCURRENCY
        _CF_CHECK_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="cf_worker",
        )
    return _CF_CHECK_EXECUTOR


def shutdown_cf_check_executor(wait: bool = False, cancel_futures: bool = True) -> None:
    """
    关闭 Cloudflare Worker 质检线程池，释放线程资源。

    【幂等设计与先后互斥说明】：
    1. 正常执行退出时，main() 的 finally 块率先触发，传入 wait=True 优雅等待未决任务收尾，
       并将全局 _CF_CHECK_EXECUTOR 置为 None；
    2. 进程最终终止时触发 atexit 回调，后触发者检测到已为 None 则直接跳过，保证绝不重复关闭；
    3. 若遇异常崩溃或 SIGINT 中断，finally 未能执行，则由 atexit 传入 wait=False 兜底强制丢弃未决任务，
       确保 CI 环境不会因卡在远程 HTTP 超时而导致进程退出挂起。
    """
    global _CF_CHECK_EXECUTOR
    if _CF_CHECK_EXECUTOR is not None:
        try:
            _CF_CHECK_EXECUTOR.shutdown(wait=wait, cancel_futures=cancel_futures)
        except TypeError:
            _CF_CHECK_EXECUTOR.shutdown(wait=wait)
        _CF_CHECK_EXECUTOR = None


# 注册退出回调，异常或中断时非阻塞强行释放（后触发者检测到 None 则跳过）
atexit.register(shutdown_cf_check_executor, wait=False, cancel_futures=True)


def normalize_endpoint(endpoint: str | None) -> str:
    """规整端点 URL，支持协议前缀补全，支持留空或 off/none 显式禁用"""
    if not endpoint:
        return ""
    ep = endpoint.strip()
    if not ep or ep.lower() in ("off", "none", "false", "0", "disabled"):
        return ""
    if not ep.startswith(("http://", "https://")):
        ep = "https://" + ep
    return ep.rstrip("/")


def build_sstp_url(host: str, port: int, user: str | None = None, pwd: str | None = None) -> str:
    """构建标准 SSTP 代理 URL (VPNGate 默认缺省账密为 vpn / vpn)"""
    u = user or "vpn"
    p = pwd or "vpn"
    h = f"[{host}]" if (":" in host and not host.startswith("[")) else host
    return f"sstp://{u}:{p}@{h}:{port}"


def check_cf_worker_health(endpoint: str, timeout: float = 6.0) -> bool:
    """
    质检开始前，对 Cloudflare Worker 外部检测端点进行全局健康探针校验。
    探测 /locations 或 / 根路径，确认端点在线可用、域名正确且未欠费或被封禁。
    若探测失败，则安全熔断并全局降级为本地轻量握手探测，避免单节点频繁失败或卡顿。
    """
    clean_ep = normalize_endpoint(endpoint)
    if not clean_ep:
        return False
    probe_urls = [f"{clean_ep}/locations", f"{clean_ep}/"]
    for target in probe_urls:
        try:
            req = urllib.request.Request(
                target,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tg-proxy-fetcher"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in (200, 204):
                    return True
        except Exception as e:
            log.debug("Cloudflare Worker 端点健康探针 [%s] 异常: %s", target, e)
    return False


def _sync_cf_check(endpoint: str, proxy_url: str, timeout: float = 18.0) -> dict:
    """
    同步调用 Cloudflare Worker 代理检测接口。
    Worker 内部超时通常为 12s，将 Python 端超时放宽至 18s 以便完整接收 Worker 的超时返回。
    结构化捕获 HTTP 4xx/5xx 与网络层异常，返回标准 dict：
      - 成功/明确失败: {"success": True/False, "error": ..., "exit": ..., "responseTime": ...}
      - 网络/HTTP崩溃: {"success": False, "error": "...", "network_error": True}
    """
    target_url = f"{endpoint}/check?proxy={urllib.parse.quote(proxy_url)}"
    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tg-proxy-fetcher"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(body)
            if isinstance(data, dict):
                return data
            return {"success": False, "error": "invalid_worker_json"}
    except urllib.error.HTTPError as he:
        # Worker 在抛出 400/500/524 时响应体可能附带结构化 JSON 错误说明
        try:
            body = he.read().decode("utf-8", errors="ignore")
            data = json.loads(body)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        log.debug("Cloudflare Worker SSTP 质检 HTTP 异常 [%s]: HTTP %s %s", proxy_url, he.code, he.reason)
        return {"success": False, "error": f"HTTP {he.code}: {he.reason}", "http_code": he.code}
    except (urllib.error.URLError, TimeoutError, OSError) as ne:
        log.debug("Cloudflare Worker SSTP 网络超时/故障 [%s]: %s", proxy_url, ne)
        return {"success": False, "error": f"network_error: {ne}", "network_error": True}
    except Exception as e:
        log.debug("Cloudflare Worker SSTP 质检未决异常 [%s]: %s", proxy_url, e)
        return {"success": False, "error": str(e)}


async def check_sstp_exit_cf_worker(
    endpoint: str,
    host: str,
    port: int,
    user: str | None = None,
    pwd: str | None = None,
    timeout: float = 18.0,
    executor: concurrent.futures.ThreadPoolExecutor | None = None,
) -> dict:
    """
    异步调用 Cloudflare Worker 端点针对存活的 SSTP 节点执行深层 PPP 隧道鉴真与出口 IP 探测。
    使用独立的高并发 ThreadPoolExecutor 分派同步 HTTP 探测，打破默认 6 线程瓶颈。
    返回标准 dict 结构（始终保证含 success 字段，绝不返回 None）。
    """
    clean_ep = normalize_endpoint(endpoint)
    if not clean_ep:
        return {"success": False, "error": "endpoint_empty"}
    proxy_url = build_sstp_url(host, port, user, pwd)
    exec_pool = executor or get_cf_check_executor()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(exec_pool, _sync_cf_check, clean_ep, proxy_url, timeout)


# ---------- 协议探测实现 ----------

@functools.lru_cache(maxsize=8192)
def is_ip_literal(host: str) -> bool:
    """快速判断 host 是否为 IP 字面量地址 (IPv4/IPv6)，杜绝向 DoH 发起无意义的 IP 域名反解"""
    if not host or not isinstance(host, str):
        return False
    try:
        ipaddress.ip_address(host.strip())
        return True
    except Exception:
        return False


async def probe_socks5(
    host: str,
    port: int,
    user: str | None,
    pwd: str | None,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str, str, str]:
    """
    SOCKS5 RFC 1928 / RFC 1929 五步状态机鉴真：
    1. TCP 连接
    2. 方法协商 (0x00 无需认证, 0x02 账密认证)
    3. 子协商 (若服务端要求 0x02)
    4. CONNECT speed.cloudflare.com:80
    5. HTTP GET /cdn-cgi/trace 校验 200 与 colo，并提取 country 与 egress_ip
    返回 (is_alive, delay_ms, status, colo, country, egress_ip)
    """
    connect_host = host
    if not is_ip_literal(host):
        resolved = await asyncio.to_thread(resolve_domain_to_ip, host)
        if resolved and is_valid_public_ip(resolved):
            connect_host = resolved
    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port),
            timeout=connect_timeout,
        )

        # 步骤 2: 协商认证方式
        if user and pwd:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=connect_timeout)
        if resp[0] != 0x05:
            return False, 0, "bad_handshake", "", "", ""

        method = resp[1]
        if method == 0xFF:
            return False, 0, "no_acceptable_auth", "", "", ""
        elif method == 0x02:
            if not (user and pwd):
                return False, 0, "auth_required_missing", "", "", ""
            # 步骤 3: 账密认证 RFC 1929
            u_b = user.encode("utf-8")
            p_b = pwd.encode("utf-8")
            auth_req = b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(p_b)]) + p_b
            writer.write(auth_req)
            await asyncio.wait_for(writer.drain(), timeout=connect_timeout)
            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=connect_timeout)
            if auth_resp[1] != 0x00:
                return False, 0, "auth_fail", "", "", ""
        elif method != 0x00:
            return False, 0, "unsupported_method", "", "", ""

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
            return False, 0, "connect_fail", "", "", ""

        # 排空 BND.ADDR / BND.PORT (RFC 1928 严谨读取)
        atyp = conn_resp[3]
        if atyp == 0x01:  # IPv4: 4 字节 IP + 2 字节端口
            await asyncio.wait_for(reader.readexactly(6), timeout=connect_timeout)
        elif atyp == 0x03:  # Domain: 1 字节长度 + N 字节域名 + 2 字节端口
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=connect_timeout))[0]
            await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=connect_timeout)
        elif atyp == 0x04:  # IPv6: 16 字节 IP + 2 字节端口
            await asyncio.wait_for(reader.readexactly(18), timeout=connect_timeout)
        else:
            return False, 0, "bad_handshake", "", "", ""

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

        http_resp = await read_full_response(reader, http_timeout, need_body=True)
        http_text = http_resp.decode("utf-8", errors="ignore")

        colo_match = RE_COLO.search(http_text)
        colo = colo_match.group(1).upper() if colo_match else ""
        loc_match = RE_LOC.search(http_text)
        country = loc_match.group(1).upper() if loc_match else ""
        ip_match = RE_IP.search(http_text)
        egress_ip = ip_match.group(1).strip() if ip_match else ""
        lat = max(1, int((time.monotonic() - t0) * 1000))

        first_line = http_text.splitlines()[0] if http_text else ""
        if RE_HTTP_200.search(first_line) and colo:
            return True, lat, "alive", colo, country, egress_ip
        return False, lat, "http_fail", "", "", ""
    except asyncio.TimeoutError:
        return False, 0, "timeout", "", "", ""
    except ConnectionRefusedError:
        log.debug("SOCKS5 节点端口拒绝连接 [%s:%s]", host, port)
        return False, 0, "conn_err", "", "", ""
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("SOCKS5 节点重置/断开 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_reset", "", "", ""
    except (socket.gaierror, OSError) as e:
        log.debug("SOCKS5 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_err", "", "", ""
    except Exception as e:
        log.debug("SOCKS5 节点未知探测异常 [%s:%s]: %s", host, port, e)
        return False, 0, "fail", "", "", ""
    finally:
        if writer is not None:
            await safe_close_writer(writer)


async def probe_http(
    host: str,
    port: int,
    user: str | None,
    pwd: str | None,
    connect_timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
    max_latency_ms: int = 0,
) -> tuple[bool, int, str, str, str, str]:
    """
    明文 HTTP 代理单阶段标准 RFC 7230 正向代理深度穿透鉴真：
    1. 目标直通：向代理发送标准绝对 URI 请求 (GET http://speed.cloudflare.com/cdn-cgi/trace HTTP/1.1)
    2. 严格鉴真：必须收到 200 OK 且正文必须解析出 Cloudflare 的 colo 与 egress_ip，100% 杜绝假 200 代理
    3. 敏捷判死：单次探测失败（超时、端口拒绝、鉴权失败、非 200 等）立即淘汰，绝不发起第二阶段串行回退
    4. 延迟保护: 若配置了 max_latency_ms (>0) 且总延迟超过上限，判定为 slow_timeout 淘汰
    返回 (is_alive, delay_ms, status, colo, country, egress_ip)
    """
    connect_host = host
    if not is_ip_literal(host):
        resolved = await asyncio.to_thread(resolve_domain_to_ip, host)
        if resolved and is_valid_public_ip(resolved):
            connect_host = resolved

    auth_header = ""
    if user and pwd:
        cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {cred}\r\n"

    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port),
            timeout=connect_timeout,
        )
        forward_req = (
            f"GET http://{PROBE_HOST}{PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"{auth_header}"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(forward_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await read_full_response(reader, http_timeout, need_body=True)
        await safe_close_writer(writer)
        writer = None

        resp_text = resp.decode("utf-8", errors="ignore") if resp else ""
        first_line = resp_text.splitlines()[0] if resp_text else ""

        # 严格鉴真：不仅首行必须包含 200，且正文必须能解析出有效的 colo= 机房码，证明真实穿透至 Cloudflare 边缘节点
        colo_match = RE_COLO.search(resp_text)
        colo = colo_match.group(1).upper() if colo_match else ""

        if RE_HTTP_200.search(first_line) and colo:
            lat = max(1, int((time.monotonic() - t0) * 1000))
            loc_match = RE_LOC.search(resp_text)
            country = loc_match.group(1).upper() if loc_match else ""
            ip_match = RE_IP.search(resp_text)
            egress_ip = ip_match.group(1).strip() if ip_match else ""
            if max_latency_ms > 0 and lat > max_latency_ms:
                return False, lat, "slow_timeout", "", "", ""
            return True, lat, "alive", colo, country, egress_ip

        lat = max(1, int((time.monotonic() - t0) * 1000))
        if RE_HTTP_407.search(first_line):
            status = "auth_fail" if (user and pwd) else "auth_required_missing"
            return False, lat, status, "", "", ""
        return False, lat, "http_fail", "", "", ""
    except asyncio.TimeoutError:
        return False, 0, "timeout", "", "", ""
    except ConnectionRefusedError:
        log.debug("HTTP 节点端口拒绝连接 [%s:%s]", host, port)
        return False, 0, "conn_err", "", "", ""
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("HTTP 节点重置/断开 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_reset", "", "", ""
    except (socket.gaierror, OSError) as e:
        log.debug("HTTP 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_err", "", "", ""
    except Exception as e:
        log.debug("HTTP 节点未知探测异常 [%s:%s]: %s", host, port, e)
        return False, 0, "fail", "", "", ""
    finally:
        if writer is not None:
            await safe_close_writer(writer)


async def probe_https(
    host: str,
    port: int,
    user: str | None,
    pwd: str | None,
    connect_timeout: float = 7.0,
    http_timeout: float = HTTP_TIMEOUT,
    max_latency_ms: int = 0,
) -> tuple[bool, int, str, str, str, str]:
    """
    HTTPS 代理双模稳健鉴真 (TLS 传输层加密握手 + RFC 7230 穿透优先 + CONNECT 443 隧道回退)：
    专用于 proto == "https" 的加密代理服务（高校/企业专网为主，存活率高）：
    1. 首先与代理服务器建立 TLS 加密会话 (支持老旧版本与 SECLEVEL=0)
    2. 阶段 1: 优先发送 RFC 7230 §5.3.2 绝对 URI GET 请求，校验 200 与解析 colo/ip
    3. 阶段 2: 回退标准 CONNECT speed.cloudflare.com:443 隧道请求
    4. 延迟保护: 若配置了 max_latency_ms (>0) 且总探测延迟超过上限，判定为 slow_timeout 淘汰
    返回 (is_alive, delay_ms, status, colo, country, egress_ip)
    """
    connect_host = host
    is_ip = is_ip_literal(host)
    if not is_ip:
        resolved = await asyncio.to_thread(resolve_domain_to_ip, host)
        if resolved and is_valid_public_ip(resolved):
            connect_host = resolved

    ssl_ctx = INSECURE_SSL_CTX
    sni = None if is_ip else host

    auth_header = ""
    if user and pwd:
        cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {cred}\r\n"

    t0 = time.monotonic()

    # --- 阶段 1: 优先尝试 RFC 7230 §5.3.2 绝对 URI GET 深度穿透 (提取真实 colo 与 egress_ip) ---
    writer = None
    connected = False
    stage1_err_status: str | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port, ssl=ssl_ctx, server_hostname=sni),
            timeout=connect_timeout,
        )
        connected = True
        forward_req = (
            f"GET http://{PROBE_HOST}{PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"{auth_header}"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(forward_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await read_full_response(reader, http_timeout, need_body=True)
        await safe_close_writer(writer)
        writer = None

        resp_text = resp.decode("utf-8", errors="ignore") if resp else ""
        first_line = resp_text.splitlines()[0] if resp_text else ""

        if RE_HTTP_200.search(first_line) and ("colo=" in resp_text or "ip=" in resp_text):
            lat = max(1, int((time.monotonic() - t0) * 1000))
            colo_match = RE_COLO.search(resp_text)
            colo = colo_match.group(1).upper() if colo_match else ""
            loc_match = RE_LOC.search(resp_text)
            country = loc_match.group(1).upper() if loc_match else ""
            ip_match = RE_IP.search(resp_text)
            egress_ip = ip_match.group(1).strip() if ip_match else ""
            if max_latency_ms > 0 and lat > max_latency_ms:
                return False, lat, "slow_timeout", "", "", ""
            return True, lat, "alive", colo, country, egress_ip
    except asyncio.TimeoutError:
        if not connected:
            # 建立 TLS 连接超时，对端不可达，直接返回避免进入阶段 2 造成二次超时叠加
            stage1_err_status = "timeout"
    except ssl.SSLError as e:
        log.debug("HTTPS 节点 TLS 握手异常 [%s:%s]: %s", host, port, e)
        stage1_err_status = "tls_err"
    except ConnectionRefusedError:
        log.debug("HTTPS 节点端口拒绝连接 [%s:%s]", host, port)
        stage1_err_status = "conn_err"
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("HTTPS 节点重置/断开 [%s:%s]: %s", host, port, e)
        if not connected:
            stage1_err_status = "conn_reset"
    except (socket.gaierror, OSError) as e:
        log.debug("HTTPS 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        stage1_err_status = "conn_err"
    except Exception as e:
        log.debug("HTTPS 绝对 URI 探测异常 [%s:%s]: %s", host, port, e)
    finally:
        if writer is not None:
            await safe_close_writer(writer)
            writer = None

    # 若阶段 1 在传输层 (TCP/TLS/DNS) 即发生确定性硬故障或连接超时，直接返回对应状态，避免进入阶段 2 造成二次超时叠加
    if stage1_err_status:
        return False, 0, stage1_err_status, "", "", ""

    # --- 阶段 2: 回退标准 CONNECT 隧道深度穿透探测 (RFC 2817 / RFC 7231 §4.3.6) ---
    t0_connect = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port, ssl=ssl_ctx, server_hostname=sni),
            timeout=connect_timeout,
        )
        connect_req = (
            f"CONNECT {PROBE_HOST}:443 HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}:443\r\n"
            f"{auth_header}"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(connect_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        # 校验代理端的 CONNECT 建立响应 (必须包含 HTTP 200 Connection Established)
        resp = await asyncio.wait_for(reader.read(1024), timeout=connect_timeout)
        resp_text = resp.decode("latin1", errors="ignore") if resp else ""
        first_line = resp_text.splitlines()[0] if resp_text else ""

        if not RE_HTTP_200.search(first_line):
            lat = max(1, int((time.monotonic() - t0_connect) * 1000))
            if RE_HTTP_407.search(first_line):
                status = "auth_fail" if (user and pwd) else "auth_required_missing"
                return False, lat, status, "", "", ""
            return False, lat, "http_connect_fail", "", "", ""

        # 阶段 2b: CONNECT 443 隧道建立成功后，升级端到端 TLS (loop.start_tls) 并发送 GET /cdn-cgi/trace
        loop = asyncio.get_running_loop()
        protocol = writer.transport.get_protocol()
        tls_transport = await asyncio.wait_for(
            loop.start_tls(writer.transport, protocol, sslcontext=CF_SSL_CTX, server_hostname=PROBE_HOST),
            timeout=connect_timeout,
        )
        writer._transport = tls_transport

        trace_req = (
            f"GET {PROBE_PATH} HTTP/1.1\r\n"
            f"Host: {PROBE_HOST}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) tg-proxy-fetcher\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(trace_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        trace_resp = await read_full_response(reader, http_timeout, need_body=True)
        await safe_close_writer(writer)
        writer = None

        trace_text = trace_resp.decode("utf-8", errors="ignore") if trace_resp else ""
        trace_first_line = trace_text.splitlines()[0] if trace_text else ""

        if RE_HTTP_200.search(trace_first_line) and ("colo=" in trace_text or "ip=" in trace_text):
            lat = max(1, int((time.monotonic() - t0_connect) * 1000))
            colo_match = RE_COLO.search(trace_text)
            colo = colo_match.group(1).upper() if colo_match else ""
            loc_match = RE_LOC.search(trace_text)
            country = loc_match.group(1).upper() if loc_match else ""
            ip_match = RE_IP.search(trace_text)
            egress_ip = ip_match.group(1).strip() if ip_match else ""
            if max_latency_ms > 0 and lat > max_latency_ms:
                return False, lat, "slow_timeout", "", "", ""
            return True, lat, "alive", colo, country, egress_ip

        lat = max(1, int((time.monotonic() - t0_connect) * 1000))
        return False, lat, "http_connect_no_colo", "", "", ""
    except asyncio.TimeoutError:
        return False, 0, "timeout", "", "", ""
    except ssl.SSLError as e:
        log.debug("HTTPS 节点 TLS 握手异常 [%s:%s]: %s", host, port, e)
        return False, 0, "tls_err", "", "", ""
    except ConnectionRefusedError:
        log.debug("HTTPS 节点端口拒绝连接 [%s:%s]", host, port)
        return False, 0, "conn_err", "", "", ""
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("HTTPS 节点重置/断开 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_reset", "", "", ""
    except (socket.gaierror, OSError) as e:
        log.debug("HTTPS 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_err", "", "", ""
    except Exception as e:
        log.debug("HTTPS 节点未知探测异常 [%s:%s]: %s", host, port, e)
        return False, 0, "fail", "", "", ""
    finally:
        if writer is not None:
            await safe_close_writer(writer)


async def probe_turn(
    host: str,
    port: int,
    connect_timeout: float = TIMEOUT,
    read_timeout: float = HTTP_TIMEOUT,
) -> tuple[bool, int, str, str, str, str]:
    """
    TURN 协议鉴真：
    通过 TCP 发送标准 STUN Binding Request (RFC 5389)，
    校验 20 字节响应头部 Magic Cookie (0x2112A442) 以及 Transaction ID 匹配。
    返回 (is_alive, delay_ms, status, colo, country, egress_ip)
    """
    connect_host = host
    if not is_ip_literal(host):
        resolved = await asyncio.to_thread(resolve_domain_to_ip, host)
        if resolved and is_valid_public_ip(resolved):
            connect_host = resolved
    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port),
            timeout=connect_timeout,
        )

        tx_id = os.urandom(12)
        # RFC 5766 §6.2 TURN Allocate 请求 (Type: 0x0003, Length: 0x0008, Magic Cookie: 0x2112A442)
        # 属性 0x0019 (REQUESTED-TRANSPORT, 长度 4 字节, 协议值 0x11 = 17 UDP + 3 字节保留对齐)
        allocate_req = (
            b"\x00\x03\x00\x08\x21\x12\xa4\x42" + tx_id +
            b"\x00\x19\x00\x04\x11\x00\x00\x00"
        )
        writer.write(allocate_req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
        lat = max(1, int((time.monotonic() - t0) * 1000))

        # 校验 STUN Magic Cookie 与 Transaction ID，并验证服务端支持 TURN Allocate (0x0103成功或0x0113鉴权挑战)
        if len(resp) >= 20 and resp[4:8] == b"\x21\x12\xa4\x42" and resp[8:20] == tx_id:
            msg_type = resp[0:2]
            if msg_type in (b"\x01\x03", b"\x01\x13"):
                return True, lat, "alive", "-", "", connect_host
            return False, lat, "stun_not_turn", "", "", ""
        return False, lat, "stun_fail", "", "", ""
    except asyncio.TimeoutError:
        return False, 0, "timeout", "", "", ""
    except ConnectionRefusedError:
        log.debug("TURN 节点端口拒绝连接 [%s:%s]", host, port)
        return False, 0, "conn_err", "", "", ""
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("TURN 节点重置/断开 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_reset", "", "", ""
    except (socket.gaierror, OSError) as e:
        log.debug("TURN 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_err", "", "", ""
    except Exception as e:
        log.debug("TURN 节点未知探测异常 [%s:%s]: %s", host, port, e)
        return False, 0, "fail", "", "", ""
    finally:
        if writer is not None:
            await safe_close_writer(writer)


async def probe_sstp(
    host: str,
    port: int,
    user: str | None = None,
    pwd: str | None = None,
    connect_timeout: float = SSTP_TIMEOUT,
    read_timeout: float = SSTP_READ_TIMEOUT,
) -> tuple[bool, int, str, str, str, str]:
    """
    SSTP (Secure Socket Tunneling Protocol) 鉴真：
    1. TLS 握手建立加密信道 (兼容自签名证书与通配符证书 ssl.CERT_NONE，支持老旧节点 TLS 1.0/1.1 与 SECLEVEL=0 密码套件)
    2. 发送标准 MS-SSTP 初始双工隧道请求 (携带 SSTPCORRELATIONID 与标准客户端标头):
       SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1
    3. 校验服务端是否返回 HTTP/1.1 200 OK，确认 SSTP 隧道服务活跃就绪
    返回 (is_alive, delay_ms, status, colo, country, egress_ip)
    """
    ctx = INSECURE_SSL_CTX

    # RFC 6066: 纯 IP 地址不应作为 TLS SNI 发送
    is_ip = is_ip_literal(host)
    sni = None if is_ip else host

    # 对域名进行异步安全解析 (DoH 权威防 DNS 污染)，若能解析出公网 IP 则优先直连真实 IP，并将原域名作为 TLS SNI 发送
    connect_host = host
    if not is_ip:
        resolved = await asyncio.to_thread(resolve_domain_to_ip, host)
        if resolved and is_valid_public_ip(resolved):
            connect_host = resolved

    t0 = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, port, ssl=ctx, server_hostname=sni),
            timeout=connect_timeout,
        )

        uri = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
        req = (
            f"SSTP_DUPLEX_POST {uri} HTTP/1.1\r\n"
            f"SSTPCORRELATIONID: {{BA195980-CD49-458b-9E23-C84EE0ADCD75}}\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: SSTP Client\r\n"
            f"Connection: Keep-Alive\r\n"
            f"Content-Length: 18446744073709551615\r\n"
            f"\r\n"
        ).encode("latin1")
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=connect_timeout)

        resp = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
        lat = max(1, int((time.monotonic() - t0) * 1000))
        resp_text = resp.decode("latin1", errors="ignore")
        first_line = resp_text.splitlines()[0] if resp_text else ""

        if re.search(r"\b200\b", first_line):
            return True, lat, "alive", "-", "", connect_host
        return False, lat, "sstp_fail", "", "", ""
    except asyncio.TimeoutError:
        return False, 0, "timeout", "", "", ""
    except ssl.SSLError as e:
        log.debug("SSTP 节点 TLS 握手异常 [%s:%s]: %s", host, port, e)
        return False, 0, "tls_err", "", "", ""
    except ConnectionRefusedError:
        log.debug("SSTP 节点端口拒绝连接 [%s:%s]", host, port)
        return False, 0, "conn_err", "", "", ""
    except (ConnectionResetError, BrokenPipeError) as e:
        log.debug("SSTP 节点重置/断开 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_reset", "", "", ""
    except (socket.gaierror, OSError) as e:
        log.debug("SSTP 节点网络/DNS异常 [%s:%s]: %s", host, port, e)
        return False, 0, "conn_err", "", "", ""
    except Exception as e:
        log.debug("SSTP 节点未知探测异常 [%s:%s]: %s", host, port, e)
        return False, 0, "fail", "", "", ""
    finally:
        if writer is not None:
            await safe_close_writer(writer)


async def probe_single(
    row: dict,
    sem: asyncio.Semaphore | None = None,
    timeout: float = TIMEOUT,
    http_timeout: float = HTTP_TIMEOUT,
    sstp_timeout: float = SSTP_TIMEOUT,
    cf_check_endpoint: str | None = None,
    cf_executor: concurrent.futures.ThreadPoolExecutor | None = None,
    http_probe_timeout: float = HTTP_PROBE_TIMEOUT,
    http_max_latency_ms: int = HTTP_MAX_LATENCY_MS,
    max_fails: int = MAX_FAILS,
    http_max_fails: int = HTTP_MAX_FAILS,
) -> dict:
    """协议分流路由与执行"""
    if sem is not None:
        async with sem:
            return await probe_single(
                row,
                sem=None,
                timeout=timeout,
                http_timeout=http_timeout,
                sstp_timeout=sstp_timeout,
                cf_check_endpoint=cf_check_endpoint,
                cf_executor=cf_executor,
                http_probe_timeout=http_probe_timeout,
                http_max_latency_ms=http_max_latency_ms,
                max_fails=max_fails,
                http_max_fails=http_max_fails,
            )

    proto = row.get("proto", "socks5").lower()
    host = row.get("host", "")
    port = safe_int(row.get("port"), 0)
    user = row.get("user") or None
    pwd = row.get("pwd") or None

    if proto == "socks5":
        is_alive, delay_ms, status, colo, country, egress_ip = await probe_socks5(
            host, port, user, pwd, timeout, http_timeout
        )
    elif proto == "http":
        h_conn_to = min(timeout, http_probe_timeout)
        h_read_to = min(http_timeout, http_probe_timeout)
        is_alive, delay_ms, status, colo, country, egress_ip = await probe_http(
            host,
            port,
            user,
            pwd,
            h_conn_to,
            h_read_to,
            max_latency_ms=http_max_latency_ms,
        )
    elif proto == "https":
        is_alive, delay_ms, status, colo, country, egress_ip = await probe_https(
            host, port, user, pwd, max(timeout, 7.0), http_timeout
        )
    elif proto == "turn":
        is_alive, delay_ms, status, colo, country, egress_ip = await probe_turn(
            host, port, timeout, http_timeout
        )
    elif proto == "sstp":
        if cf_check_endpoint:
            # SSTP 直通 Cloudflare Worker 进行端到端全隧道 PPP 拨号与出口探测，单步到位
            t_cf0 = time.monotonic()
            cf_res = await check_sstp_exit_cf_worker(
                cf_check_endpoint, host, port, user, pwd, timeout=18.0, executor=cf_executor
            )
            if cf_res.get("success"):
                is_alive = True
                calc_delay = max(1, int((time.monotonic() - t_cf0) * 1000))
                delay_ms = safe_int(
                    cf_res.get("responseTime") or cf_res.get("latency_ms") or cf_res.get("time") or calc_delay,
                    calc_delay,
                )
                status = "alive"
                colo = "-"
                country = ""
                egress_ip = ""
                exit_info = cf_res.get("exit") or {}
                exit_ip = str(exit_info.get("ip") or "").strip()
                if is_valid_public_ip(exit_ip):
                    egress_ip = exit_ip
                c_code = str(exit_info.get("country_code") or exit_info.get("country") or "").strip().upper()
                if c_code:
                    country = c_code
                # 若 Worker 已附带 ASN/ISP 归属，直接结构化丰富
                asn_obj = exit_info.get("asn") or {}
                cf_asn = str(asn_obj.get("asn") or "").strip()
                cf_isp = str(asn_obj.get("name") or asn_obj.get("org") or "").strip()
                if cf_asn:
                    row["asn"] = format_asn_isp(cf_asn, cf_isp)
                    row["isp"] = cf_isp
                    row["net_type"] = classify_asn(cf_asn, cf_isp)
            else:
                if cf_res.get("network_error"):
                    # Worker 侧网络抖动或请求 Worker 自身超时，不应归罪节点；保持原状态，不递增 fail_count
                    log.debug("SSTP 节点 [%s:%s] 遇到 Worker 侧网络抖动: %s", host, port, cf_res.get("error"))
                    is_alive = False
                    delay_ms = 0
                    status = "worker_unreachable"
                    colo = ""
                    country = ""
                    egress_ip = ""
                else:
                    # 节点在 Worker 端全隧道 PPP 协商失败（如连接被服务端关闭、隧道拨号超时）
                    err_msg = cf_res.get("error", "sstp_vpn_fail")
                    log.debug("SSTP 节点 [%s:%s] Worker 全隧道拨号失败: %s", host, port, err_msg)
                    is_alive = False
                    delay_ms = 0
                    status = "sstp_vpn_fail"
                    colo = ""
                    country = ""
                    egress_ip = ""
        else:
            # 未配置外部检测端点，执行本地轻量握手探测（无外部依赖）
            is_alive, delay_ms, status, colo, country, egress_ip = await probe_sstp(
                host, port, user, pwd, sstp_timeout, max(http_timeout, SSTP_READ_TIMEOUT)
            )
    else:
        is_alive, delay_ms, status, colo, country, egress_ip = False, 0, "unknown_proto", "", "", ""

    row["is_alive"] = is_alive
    row["status"] = status

    fc = safe_int(row.get("fail_count"), 0)
    row["_old_fc"] = fc
    if is_alive:
        row["fail_count"] = 0
        row["delay_ms"] = delay_ms
        row["colo"] = colo
        row["country"] = country or row.get("country", "")
        row["egress_ip"] = egress_ip or row.get("egress_ip", "")
    else:
        eff_max_fails = http_max_fails if proto == "http" else max_fails
        if status in FATAL_FAIL_STATUSES:
            row["fail_count"] = eff_max_fails
        elif status == "worker_unreachable":
            row["fail_count"] = fc  # Worker 侧网络抖动，保持原有 fail_count，不扣节点分数
        else:
            row["fail_count"] = fc + 1
        if not row.get("delay_ms"):
            row["delay_ms"] = 0
        row.setdefault("country", row.get("country", ""))
        row.setdefault("egress_ip", row.get("egress_ip", ""))
        row.setdefault("asn", row.get("asn", ""))
        row.setdefault("isp", row.get("isp", ""))
        row.setdefault("net_type", row.get("net_type", ""))
        row.setdefault("source", row.get("source", ""))

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
            "country": "",
            "egress_ip": "",
            "asn": "",
            "isp": "",
            "net_type": "",
            "source": "",
        }
    except Exception:
        return None


def load_proxies_data(
    txt_path: str = PROXIES_TXT,
    csv_path: str = PROXIES_CSV,
    proxies_dir: str = PROXIES_DIR,
) -> list[dict]:
    """
    加载待检代理节点：
    1. 优先读取 proxies.csv，保留既有 fail_count 与历史统计
    2. 合并 proxies.txt 中新增的节点
    3. 自动过滤墓地黑名单中的冷却期死节点
    """
    tombstone = load_tombstone()
    url_map: dict[str, dict] = {}

    target_csv = csv_path

    # 读取已有 CSV
    if os.path.isfile(target_csv):
        try:
            with open(target_csv, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    url = r.get("url", "").strip()
                    if not url:
                        continue
                    parsed = parse_proxy_url(url)
                    if not parsed:
                        continue
                    key = canonical_key(parsed["host"], parsed["port"])
                    if is_tombstoned(key, tombstone):
                        continue
                    parsed["fail_count"] = safe_int(r.get("fail_count"), 0)
                    parsed["delay_ms"] = safe_int(r.get("delay_ms"), 0)
                    parsed["status"] = r.get("status", "pending")
                    parsed["colo"] = r.get("colo", "")
                    parsed["country"] = r.get("country", "")
                    parsed["egress_ip"] = r.get("egress_ip", "")
                    parsed["asn"] = r.get("asn", "")
                    parsed["isp"] = r.get("isp", "")
                    parsed["net_type"] = r.get("net_type", "")
                    parsed["first_seen"] = r.get("first_seen", "").strip() or LEGACY_DEFAULT_FIRST_SEEN
                    parsed["source"] = r.get("source", "").strip()
                    url_map[url] = parsed
            log.info("从 %s 加载已有记录 %d 条", target_csv, len(url_map))
        except Exception as e:
            log.warning("读取 %s 失败: %s", target_csv, e)

    target_txt = txt_path

    # 合并 proxies.txt 中的新节点
    if os.path.isfile(target_txt):
        txt_count = 0
        now_str = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(target_txt, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    txt_count += 1
                    if line not in url_map:
                        parsed = parse_proxy_url(line)
                        if parsed:
                            key = canonical_key(parsed["host"], parsed["port"])
                            if is_tombstoned(key, tombstone):
                                continue
                            parsed["first_seen"] = now_str
                            url_map[line] = parsed
            log.info("从 %s 读取 %d 行，合并后待检节点共: %d 条", target_txt, txt_count, len(url_map))
        except Exception as e:
            log.warning("读取 %s 失败: %s", target_txt, e)

    # 合并 data/proxies/ 子目录各独立协议文件中的新节点（如 https.csv, https.txt，防止遗漏单协议新增节点）
    if proxies_dir and os.path.isdir(proxies_dir):
        now_str = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        sub_added = 0
        for fname in sorted(os.listdir(proxies_dir)):
            sub_path = os.path.join(proxies_dir, fname)
            if fname.endswith(".csv"):
                try:
                    with open(sub_path, "r", encoding="utf-8-sig") as f:
                        for r in csv.DictReader(f):
                            url = r.get("url", "").strip()
                            if not url or url in url_map:
                                continue
                            parsed = parse_proxy_url(url)
                            if not parsed:
                                continue
                            key = canonical_key(parsed["host"], parsed["port"])
                            if is_tombstoned(key, tombstone):
                                continue
                            parsed["fail_count"] = safe_int(r.get("fail_count"), 0)
                            parsed["delay_ms"] = safe_int(r.get("delay_ms"), 0)
                            parsed["status"] = r.get("status", "pending")
                            parsed["colo"] = r.get("colo", "")
                            parsed["country"] = r.get("country", "")
                            parsed["egress_ip"] = r.get("egress_ip", "")
                            parsed["asn"] = r.get("asn", "")
                            parsed["isp"] = r.get("isp", "")
                            parsed["net_type"] = r.get("net_type", "")
                            parsed["first_seen"] = r.get("first_seen", "").strip() or now_str
                            parsed["source"] = r.get("source", "").strip()
                            url_map[url] = parsed
                            sub_added += 1
                except Exception as e:
                    log.warning("读取子协议文件 %s 失败: %s", sub_path, e)
            elif fname.endswith(".txt"):
                try:
                    with open(sub_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#") or line in url_map:
                                continue
                            parsed = parse_proxy_url(line)
                            if not parsed:
                                continue
                            key = canonical_key(parsed["host"], parsed["port"])
                            if is_tombstoned(key, tombstone):
                                continue
                            parsed["first_seen"] = now_str
                            url_map[line] = parsed
                            sub_added += 1
                except Exception as e:
                    log.warning("读取子协议文件 %s 失败: %s", sub_path, e)
        if sub_added > 0:
            log.info("从 %s 子目录合并新增节点 %d 条，合并后待检节点共: %d 条", proxies_dir, sub_added, len(url_map))

    return list(url_map.values())


async def enrich_proxies_metadata(survivors: list[dict], max_concurrency: int = 5) -> dict[str, int]:
    """
    为质检存活代理节点补全 ASN、ISP 及网络属性 (net_type：isp/datacenter/business 等)：
    1. 优先使用已有的有效 asn / isp / net_type（避免重复网络查询）
    2. 基于 egress_ip（或 host IP/域名）去重，通过批量 Batch 接口或并发反查 ASN / ISP
    3. 调用 format_asn_isp 与 classify_asn 标准化打标，补全国家/地区代码
    4. 返回各网络属性的统计分布 dict，如 {"isp": 12, "datacenter": 35}
    """
    if not survivors:
        return {}

    persistent_cache = load_ip_cache()
    ip_to_resolve = set()
    for r in survivors:
        asn = r.get("asn", "").strip()
        country = r.get("country", "").strip()
        target_ip = r.get("egress_ip", "").strip() or r.get("host", "").strip()

        # 检查是否已具备完整元数据 (有效 asn 与国家代码)
        cached_entry = persistent_cache.get(target_ip, {}) if target_ip else {}
        has_asn = bool(asn or cached_entry.get("asn"))
        has_country = bool(country or cached_entry.get("country"))

        if not has_asn or not has_country:
            if target_ip and target_ip not in ("127.0.0.1", "localhost"):
                ip_to_resolve.add(target_ip)

    ip_cache: dict[str, tuple[str, str]] = {}
    if ip_to_resolve:
        log.info("正在为 %d 个唯一出口 IP/域名批量解析 ASN 与国家属性...", len(ip_to_resolve))
        ip_cache = await resolve_asn_batch_online_async(list(ip_to_resolve))

    persistent_cache = load_ip_cache()
    net_stats: dict[str, int] = {}
    for r in survivors:
        curr_asn = r.get("asn", "").strip()
        curr_country = r.get("country", "").strip()
        curr_egress = r.get("egress_ip", "").strip()
        target_ip = curr_egress or r.get("host", "").strip()

        if target_ip:
            if not curr_asn:
                if target_ip in ip_cache:
                    asn_code, isp_name = ip_cache[target_ip]
                    if asn_code:
                        r["asn"] = format_asn_isp(asn_code, isp_name)
                        r["isp"] = isp_name
                        cached_nt = (persistent_cache.get(target_ip) or {}).get("net_type")
                        r["net_type"] = cached_nt or classify_asn(asn_code, isp_name)
                elif target_ip in persistent_cache:
                    c_item = persistent_cache[target_ip]
                    asn_code = c_item.get("asn", "")
                    isp_name = c_item.get("isp", "")
                    if asn_code:
                        r["asn"] = format_asn_isp(asn_code, isp_name)
                        r["isp"] = isp_name
                        r["net_type"] = c_item.get("net_type") or classify_asn(asn_code, isp_name)

            if not curr_country:
                c_code = ""
                if target_ip in persistent_cache:
                    c_code = persistent_cache[target_ip].get("country", "")
                if c_code:
                    r["country"] = c_code

            if not curr_egress or not is_valid_public_ip(curr_egress):
                if target_ip in persistent_cache and persistent_cache[target_ip].get("resolved_ip"):
                    r["egress_ip"] = persistent_cache[target_ip]["resolved_ip"]
                elif is_valid_public_ip(target_ip):
                    r["egress_ip"] = target_ip

        if r.get("asn"):
            asn_val = r.get("asn", "")
            isp_val = r.get("isp", "")
            if not isp_val:
                m_code = re.search(r"AS(\d+)", asn_val, re.IGNORECASE)
                if m_code:
                    code_key = f"AS{m_code.group(1)}"
                    isp_val = ASN_TO_PROVIDER.get(code_key, "")
                    if not isp_val and code_key in ASN_DATABASE_ASN_TO_ISP:
                        isp_val = ASN_DATABASE_ASN_TO_ISP[code_key]
                r["isp"] = isp_val
            r["asn"] = format_asn_isp(asn_val, isp_val)
            r["net_type"] = classify_asn(r.get("asn", ""), isp_val)
        else:
            r["net_type"] = classify_asn("", "")

        nt = r.get("net_type", "datacenter")
        net_stats[nt] = net_stats.get(nt, 0) + 1

    return net_stats


def save_proxies_data(
    survivors: list[dict],
    txt_path: str = PROXIES_TXT,
    csv_path: str = PROXIES_CSV,
    proxies_dir: str = PROXIES_DIR,
):
    """
    保存质检幸存节点：
    按 (协议顺序, fail_count 升序, delay_ms 升序) 排序，确保在 CSV 与 TXT 中各协议严格分块独立，绝不交错混杂。
    覆写 proxies.txt 与 proxies.csv，并按协议独立拆分保存至 proxies/ 子目录（包含 .txt, .csv, .json 纯净单协议版）。
    """
    PROTO_ORDER = ["socks5", "http", "https", "turn", "sstp"]

    def _sort_key(r):
        proto = (r.get("proto") or "").strip().lower()
        p_idx = PROTO_ORDER.index(proto) if proto in PROTO_ORDER else len(PROTO_ORDER)
        fc = safe_int(r.get("fail_count"), 0)
        dms = safe_int(r.get("delay_ms"), 0)
        # 0 delay 视作未测通或失败，排在后面
        if dms <= 0:
            dms = 99999
        return (p_idx, fc, dms)

    survivors.sort(key=_sort_key)

    # 写入 proxies.txt (纯文本 URL 清单，按协议分段归类；原子写入防截断)
    formatted_txt = format_proxies_txt(survivors)
    atomic_write_text(txt_path, formatted_txt, encoding="utf-8")
    log.info("已按协议分段覆写保存 %s: %d 个高可用节点", txt_path, len(survivors))

    # 按协议拆分独立文件至 data/proxies/ 子目录 (.txt, .csv, .json)
    proto_counts = save_proxies_by_protocol(survivors, proxies_dir)
    log.info("已在 %s/ 目录下同步覆写 %d 个独立协议文件 (.txt/.csv/.json): %s", proxies_dir, len(proto_counts), proto_counts)

    # 写入 proxies.csv (完整元数据表，按协议分块严格隔离，不混杂；原子写入防截断)
    save_proxies_csv(survivors, csv_path=csv_path)


# 向后兼容历史别名
load_socks_data = load_proxies_data
save_socks_data = save_proxies_data


# ---------- Telegram 通知 ----------


def send_proxies_notification(
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
    buf_new: int = 0,
    buf_rec: int = 0,
    net_stats: dict | None = None,
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

    net_lines = []
    if net_stats:
        type_labels = {
            "isp": "🏠 原生家宽",
            "datacenter": "🏢 数据中心",
            "business": "💼 商业专线",
            "education": "🎓 教育网",
            "government": "🏛️ 政府机构",
            "banking": "🏦 金融网络",
        }
        for k, count in sorted(net_stats.items(), key=lambda x: -x[1]):
            lbl = type_labels.get(k, k.upper())
            net_lines.append(f"{lbl} {count}")
    net_str = f"\n🌐 <b>网络属性</b>：{' · '.join(net_lines)}" if net_lines else ""

    elim_str = f"<code>{eliminated}</code> 条 (连续失败 ≥ {max_fails} 次)" if eliminated > 0 else "无 (全部在存活阈值内)"
    buffer_badge = format_buffer_badge(fail_count, buf_new=buf_new, buf_rec=buf_rec, f1=fail_1, f2=fail_2)
    status_str = f"✅ {pass_count} 存活{buffer_badge}"

    message = (
        f"🚀 <b>SOCKS5 / 通用代理连通性质检完成</b>\n"
        f"{div}\n"
        f"📅 <b>时间</b>：{bjt} (北京时间)\n"
        f"📫 <b>可用代理</b>：<code>{survivors}</code> 个 ({status_str})\n"
        f"⚡ <b>存活均延</b>：<code>{avg_delay}ms</code>\n"
        f"🗑️ <b>淘汰死节点</b>：{elim_str}\n"
        f"📊 <b>协议分布</b>：\n{proto_str}"
        f"{net_str}\n"
        f"{div}\n"
        f"⚙️ <b>检测规格</b>：多协议全链路穿透 · {concurrency} 并发\n"
        f"⏱️ <b>质检耗时</b>：{elapsed:.1f}s\n"
    )

    try:
        send_tg_message(message, token=token, chat_id=chat_id, tag="proxies-verify")
    except Exception as e:
        log.warning("发送 Telegram 消息时出现异常: %s", e)


# ---------- 主流程 ----------

async def async_main(args):
    t_start = time.time()
    rows = load_proxies_data(PROXIES_TXT, PROXIES_CSV)
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

    h_to = getattr(args, "http_probe_timeout", HTTP_PROBE_TIMEOUT)
    h_lat = getattr(args, "http_max_latency", HTTP_MAX_LATENCY_MS)
    h_mf = getattr(args, "http_max_fails", HTTP_MAX_FAILS)

    log.info(
        "开始并发质检代理连通性: 共 %d 条 | 并发: %d | 超时: %.1fs (HTTP专属: %.1fs, 延迟上限: %dms) | 淘汰阈值: 连续失败 >= %d 次 (HTTP专属: >= %d 次)",
        total,
        args.concurrency,
        args.timeout,
        h_to,
        h_lat,
        args.max_fails,
        h_mf,
    )

    # 全局显式初始化 _old_fc，确保异常提前返回或空跑时不遗留未定义状态
    for r in rows:
        r.setdefault("_old_fc", safe_int(r.get("fail_count"), 0))

    cf_endpoint = normalize_endpoint(getattr(args, "cf_check_endpoint", CF_CHECK_ENDPOINT))
    cf_concurrency = getattr(args, "cf_concurrency", CF_CONCURRENCY)
    cf_executor = None
    if cf_endpoint:
        # 质检启动前对 Worker 端点进行单次健康探针校验，若端点自身不可达则全局安全熔断降级
        is_worker_ok = await asyncio.to_thread(check_cf_worker_health, cf_endpoint)
        if is_worker_ok:
            cf_executor = get_cf_check_executor(max_workers=cf_concurrency)
            log.info(
                "SSTP 启用 Cloudflare Worker 独占直连穿透鉴真与出口探测端点: %s (专用并发: %d)",
                cf_endpoint,
                cf_concurrency,
            )
        else:
            log.warning(
                "⚠️ Cloudflare Worker 端点 [%s] 健康探针失败 (不可达/响应异常)，本轮 SSTP 将全局熔断降级为本地轻量握手探测（结果不含全隧道 PPP 验证）",
                cf_endpoint,
            )
            cf_endpoint = ""
    else:
        log.info("SSTP 未配置外部检测端点，采用本地解析轻量直连出口（无外部依赖）")

    async def _worker(r):
        nonlocal completed, pass_count, fail_count, min_delay
        host = r.get("host", "")
        port = r.get("port", 0)
        lock_key = f"{host}:{port}"
        async with sem:
            async with get_keyed_lock(lock_key):
                res = await probe_single(
                    r,
                    sem=None,
                    timeout=args.timeout,
                    http_timeout=args.http_timeout,
                    sstp_timeout=args.sstp_timeout,
                    cf_check_endpoint=cf_endpoint,
                    cf_executor=cf_executor,
                    http_probe_timeout=h_to,
                    http_max_latency_ms=h_lat,
                    max_fails=args.max_fails,
                    http_max_fails=h_mf,
                )
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
                "[通用代理 质检进度] %d/%d (%.1f%%) - 存活: %d 个 (延迟最低: %s)",
                completed,
                total,
                pct,
                pass_count,
                min_str,
            )
        return res

    tasks = [_worker(r) for r in rows]
    results = await asyncio.gather(*tasks)

    # 幸存者筛选（支持按协议分流淘汰阈值：HTTP 专属严格阈值，其余协议维持 max_fails 缓冲容错）
    def _is_survivor(r):
        proto = (r.get("proto") or "").lower()
        fc = safe_int(r.get("fail_count"), 0)
        eff_mf = h_mf if proto == "http" else args.max_fails
        return fc < eff_mf

    survivors = [r for r in results if _is_survivor(r)]
    eliminated = total - len(survivors)
    survivors_len = len(survivors)
    proxies_f1 = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 1)
    proxies_f2 = sum(1 for r in survivors if safe_int(r.get("fail_count"), 0) == 2)
    proxies_buf_new = sum(
        1 for r in results
        if not r.get("is_alive")
        and safe_int(r.get("_old_fc"), 0) == 0
        and _is_survivor(r)
    )
    proxies_buf_rec = sum(
        1 for r in results
        if r.get("is_alive") and safe_int(r.get("_old_fc"), 0) > 0
    )

    # 仅统计本次实测存活节点的网络延迟（排除处于缓冲期但本次已连通失败节点的旧延迟）
    alive_delays = [
        int(r.get("delay_ms", 0))
        for r in results
        if r.get("is_alive") and safe_int(r.get("delay_ms"), 0) > 0
    ]
    avg_delay = int(sum(alive_delays) / len(alive_delays)) if alive_delays else 0

    if eliminated > 0:
        log.info("[通用代理 淘汰] 剔除 %d 条达到淘汰阈值的死节点 (HTTP专属: >= %d 次, 其余协议: >= %d 次)", eliminated, h_mf, args.max_fails)
        dead_nodes = [r for r in results if not _is_survivor(r)]
        dead_keys = [
            canonical_key(r.get("host", ""), r.get("port", 0))
            for r in dead_nodes
            if r.get("host") and safe_int(r.get("port"), 0) > 0
        ]
        newly_tombstoned = record_tombstone(dead_keys)
        log.info("[通用代理 墓地] 已登记 %d 个淘汰死节点至墓地冷却库 (新增: %d 个, 隔离期 7 天)", len(dead_keys), newly_tombstoned)
    else:
        log.info("[通用代理 淘汰] 本次无节点达到淘汰阈值")

    # 补全出口 IP 对应的 ASN 与网络属性打标
    net_stats = await enrich_proxies_metadata(survivors)
    log.info("[通用代理 网络属性] %s", net_stats)

    save_proxies_data(survivors, PROXIES_TXT, PROXIES_CSV)

    elapsed = time.time() - t_start
    log.info("通用代理连通性质检执行完毕，总耗时 %.2f 秒 (✅ 存活: %d | 均延: %dms | ⚠️ 缓冲: %d [新增: %d, 取消恢复: %d])", elapsed, pass_count, avg_delay, (survivors_len - pass_count), proxies_buf_new, proxies_buf_rec)

    # 若存在 tg_fetch 暂存的抓取统计，将通用代理质检结果并入其中，由后续统一卡片推送
    fetch_stats_file = os.path.join(DATA_DIR, ".fetch_stats.json")
    has_fetch_stats = os.path.isfile(fetch_stats_file)
    if has_fetch_stats:
        try:
            with open(fetch_stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
            stats["proxies_verified"] = True
            stats["proxies_total"] = total
            stats["proxies_pass"] = pass_count
            stats["proxies_fail"] = fail_count
            stats["proxies_fail_1"] = proxies_f1
            stats["proxies_fail_2"] = proxies_f2
            stats["proxies_buf_new"] = proxies_buf_new
            stats["proxies_buf_rec"] = proxies_buf_rec
            stats["proxies_eliminated"] = eliminated
            stats["proxies_survivors"] = survivors_len
            stats["proxies_avg_delay_ms"] = avg_delay
            stats["proxies_elapsed"] = elapsed
            stats["proxies_proto_breakdown"] = proto_stats
            stats["proxies_net_stats"] = net_stats
            stats["proxies_max_fails"] = args.max_fails
            stats["proxies_http_max_fails"] = h_mf
            # 兼容历史 socks_* 字段
            stats["socks_verified"] = True
            stats["socks_total"] = total
            stats["socks_pass"] = pass_count
            stats["socks_eliminated"] = eliminated
            stats["socks_survivors"] = survivors_len
            stats["socks_elapsed"] = elapsed
            stats["socks_max_fails"] = args.max_fails
            stats["socks_fail_1"] = proxies_f1
            stats["socks_fail_2"] = proxies_f2
            stats["socks_buf_new"] = proxies_buf_new
            stats["socks_buf_rec"] = proxies_buf_rec
            atomic_write_json(fetch_stats_file, stats)
            log.info("已将通用代理质检统计写入 %s (并入统一卡片)", fetch_stats_file)
        except Exception as e:
            log.warning("写入 %s 失败: %s", fetch_stats_file, e)

    if not args.no_notify and not has_fetch_stats:
        send_proxies_notification(
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
            fail_1=proxies_f1,
            fail_2=proxies_f2,
            buf_new=proxies_buf_new,
            buf_rec=proxies_buf_rec,
            net_stats=net_stats,
        )
    else:
        log.info("已并入流水线或指定了 --no-notify，跳过独立卡片推送")


async def enrich_existing_proxies_file(
    csv_path: str = PROXIES_CSV,
    txt_path: str = PROXIES_TXT,
    proxies_dir: str = PROXIES_DIR,
):
    """仅对现有 proxies.csv 执行 ASN、ISP 与网络属性全量补全与保存，跳过主动网络连通性探测"""
    if not os.path.isfile(csv_path):
        log.warning("CSV 文件不存在: %s", csv_path)
        return
    rows = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            url = (r.get("url") or "").strip()
            if not url:
                continue
            parsed = parse_proxy_url(url)
            if not parsed:
                continue
            item = dict(r)
            item.setdefault("user", parsed.get("user", ""))
            item.setdefault("pwd", parsed.get("pwd", ""))
            item["host"] = parsed["host"]
            item["port"] = parsed["port"]
            item["proto"] = parsed["proto"]
            item["fail_count"] = safe_int(r.get("fail_count"), 0)
            item["delay_ms"] = safe_int(r.get("delay_ms"), 0)
            rows.append(item)

    log.info("【全量 ASN 补全模式】从 %s 读取到 %d 个现有节点", csv_path, len(rows))
    net_stats = await enrich_proxies_metadata(rows)
    log.info("【全量 ASN 补全模式】完成网络属性画像打标: %s", net_stats)
    save_proxies_data(rows, txt_path=txt_path, csv_path=csv_path, proxies_dir=proxies_dir)
    log.info("【全量 ASN 补全模式】数据已全部保存覆写完毕！")


def main():
    global CF_CONCURRENCY
    parser = argparse.ArgumentParser(description="多协议通用代理连通性质检与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help=f"并发探测协程数 (默认 {CONCURRENCY})")
    parser.add_argument(
        "--cf-concurrency",
        type=int,
        default=CF_CONCURRENCY,
        help=f"Cloudflare Worker 质检专用并发线程数 (默认 {CF_CONCURRENCY})",
    )
    parser.add_argument("--max-fails", type=int, default=MAX_FAILS, help=f"连续失败淘汰阈值 (默认 {MAX_FAILS})")
    parser.add_argument(
        "--http-max-fails",
        type=int,
        default=HTTP_MAX_FAILS,
        help=f"明文 HTTP 协议专属淘汰阈值 (默认 {HTTP_MAX_FAILS}，失败立即淘汰，杜绝低质僵尸节点积压占用资源)",
    )
    parser.add_argument("--strict", action="store_true", help="极致纯净模式 (只要失败 1 次立即剔除，等价于 --max-fails 1 --http-max-fails 1)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"单节点握手超时秒数 (默认 {TIMEOUT})")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"单节点 HTTP 穿透校验超时秒数 (默认 {HTTP_TIMEOUT})")
    parser.add_argument(
        "--http-probe-timeout",
        type=float,
        default=HTTP_PROBE_TIMEOUT,
        help=f"明文 HTTP 协议握手与穿透专属严格超时秒数 (默认 {HTTP_PROBE_TIMEOUT})",
    )
    parser.add_argument(
        "--http-max-latency",
        type=int,
        default=HTTP_MAX_LATENCY_MS,
        help=f"明文 HTTP 协议最大允许延迟毫秒数，超出直接淘汰 (默认 {HTTP_MAX_LATENCY_MS})",
    )
    parser.add_argument("--sstp-timeout", type=float, default=SSTP_TIMEOUT, help=f"SSTP 协议专属握手超时秒数 (默认 {SSTP_TIMEOUT})")
    parser.add_argument(
        "--cf-check-endpoint",
        type=str,
        default=CF_CHECK_ENDPOINT,
        help="Cloudflare Workers 代理检测端点 (用于 SSTP 真实出口与链路鉴真，默认留空不执行外部检测，需自行部署 CF-Workers-CheckSocks5)",
    )
    parser.add_argument("--no-notify", action="store_true", help="静默模式，不单独发送 Telegram 质检通知")
    parser.add_argument("--enrich-only", action="store_true", help="仅对现有 proxies.csv 补全 ASN 与网络属性打标，跳过网络连通性探测")
    args = parser.parse_args()

    # 显式将解析出的 CLI 参数同步回模块全局变量，确保各层级与直接引用处保持一致
    CF_CONCURRENCY = args.cf_concurrency

    if args.enrich_only:
        log.info("🚀 启动 --enrich-only 模式：仅补全数据画像，跳过连通性测试")
        asyncio.run(enrich_existing_proxies_file())
        return

    if args.strict:
        args.max_fails = 1
        args.http_max_fails = 1
        log.info("🔥 启用了 --strict 【极致纯净模式】，全协议淘汰阈值强制设为 1")

    try:
        asyncio.run(async_main(args))
    finally:
        shutdown_cf_check_executor(wait=True)


if __name__ == "__main__":
    main()
