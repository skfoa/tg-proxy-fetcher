#!/usr/bin/env python3
"""
Cloudflare 优选 IP 两阶段主动校验与淘汰引擎

只要是优选 IP（涵盖 scan_ips 与 cf_ips 全线产物），全部统一执行：
  阶段一：TLS 握手 + CA 证书校验（server_hostname=crypto.cloudflare.com）
  阶段二：同一连接发送 HTTP 请求，验证返回 301 且 Server: cloudflare

连续失败达到阈值（默认 3 次）的死节点，将全面从以下所有产物中永久删除：
  1. scan_ips.csv、scan_ips.txt、scan_ips/*.txt (独立机房分组文本)
  2. cf_ips.csv、cf_ips.txt (单条优选数据表与纯文本清单)
"""

import argparse
import asyncio
import csv
import logging
import os
import re
import ssl
import sys
import time
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cf-verify")

# Windows 异步事件循环策略
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ---------- 常量与配置 ----------
SCAN_CSV = "scan_ips.csv"
SCAN_TXT = "scan_ips.txt"
SCAN_DIR = "scan_ips"

CF_CSV = "cf_ips.csv"
CF_TXT = "cf_ips.txt"

PROBE_HOST = "crypto.cloudflare.com"
TIMEOUT = 3.0
CSV_FIELDS = [
    "ip", "port", "tls", "delay_ms", "speed_kbs",
    "colo", "cf_location", "isp", "asn",
    "tested_at", "channel", "fail_count",
]

# 复用全局 SSL 证书上下文，避免重复加载系统 CA 证书
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = True
SSL_CTX.verify_mode = ssl.CERT_REQUIRED

# 尝试导入 tg_fetch 中的映射表
ASN_TO_PROVIDER = {}
KNOWN_CLOUD_PROVIDERS = {}
try:
    from tg_fetch import ASN_TO_PROVIDER, KNOWN_CLOUD_PROVIDERS
except ImportError:
    pass


# ---------- 核心探测函数 ----------
async def probe_ip(ip: str, port: int, timeout: float = TIMEOUT) -> tuple[bool, int]:
    """
    对单个 IP:Port 执行 TLS 握手 + HTTP 301 校验。

    返回 (is_alive, rtt_ms):
        is_alive=True  -> 校验通过，rtt_ms 为实测网络延迟
        is_alive=False -> 校验失败，rtt_ms 为 0
    """
    t0 = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=PROBE_HOST),
            timeout=timeout,
        )
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
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        t1 = asyncio.get_event_loop().time()
        rtt_ms = int((t1 - t0) * 1000)

        resp_text = resp.decode("utf-8", errors="ignore")
        first_line = resp_text.splitlines()[0] if resp_text else ""
        is_301 = "301" in first_line
        is_cf = "server: cloudflare" in resp_text.lower()

        return (is_301 and is_cf), rtt_ms
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
) -> list:
    """
    对传入的所有优选 IP 节点无差别执行阶段一与阶段二探测。
    无论端口与元数据如何，全部执行 TLS 握手与 301 重定向鉴真。
    原地更新 fail_count 与 delay_ms。
    """
    sem = asyncio.Semaphore(concurrency)
    pass_count = 0
    fail_count_total = 0
    completed = 0
    total = len(rows)

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

        async with sem:
            alive, rtt = await probe_ip(ip, port, timeout)

        completed += 1
        fc = int(row.get("fail_count") or 0)
        if alive:
            row["fail_count"] = 0
            row["delay_ms"] = rtt
            pass_count += 1
        else:
            row["fail_count"] = fc + 1
            fail_count_total += 1

        if completed % 1000 == 0 or completed == total:
            log.info("[%s] 进度: %d/%d (%.1f%%) - 通过: %d, 失败: %d",
                     tag, completed, total, completed / total * 100, pass_count, fail_count_total)

    tasks = [_check(r) for r in rows]
    await asyncio.gather(*tasks)

    log.info(
        "[%s] 校验完成: 共 %d 条 | 验证通过 %d 条, 验证失败 %d 条",
        tag, total, pass_count, fail_count_total,
    )
    return rows


# ---------- 数据读写与 ASN 智能聚合 ----------
def clean_asn(raw_asn: str, isp: str = "") -> str:
    """提取规范化 ASN 编号 (如 AS979，支持从知名服务商名称智能反推)"""
    raw_asn = (raw_asn or "").strip()
    m = re.search(r"(AS\d+)", raw_asn, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    r_low = (raw_asn + " " + (isp or "")).lower()
    for k in sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True):
        if k in r_low:
            return KNOWN_CLOUD_PROVIDERS[k][0]
    m_d = re.search(r"\b(\d{3,7})\b", raw_asn)
    if m_d:
        return f"AS{m_d.group(1)}"
    return raw_asn if raw_asn else "AS_UNKNOWN"


def load_csv(path: str) -> list:
    """读取优选 IP CSV 文件，自动兼容 BOM 及旧版本缺少 fail_count 字段的情况"""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            if "fail_count" not in r or not str(r.get("fail_count", "")).strip():
                r["fail_count"] = 0
            else:
                try:
                    r["fail_count"] = int(r["fail_count"])
                except ValueError:
                    r["fail_count"] = 0
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


# ---------- 主流程 ----------
def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 两阶段主动校验与淘汰引擎")
    parser.add_argument("--concurrency", type=int, default=250, help="并发探测协程数 (默认 250)")
    parser.add_argument("--max-fails", type=int, default=3, help="连续失败淘汰阈值 (默认 3)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="单节点探测超时秒数 (默认 3.0)")
    args = parser.parse_args()

    t_start = time.time()

    # ================= 1. 校验单条优选 IP (cf_ips) =================
    cf_rows = load_csv(CF_CSV)
    if cf_rows:
        total_cf = len(cf_rows)
        log.info(">>> 开始校验单条优选 IP (%s): 共 %d 条...", CF_CSV, total_cf)
        asyncio.run(verify_all(cf_rows, tag="单条优选", concurrency=args.concurrency, timeout=args.timeout))

        cf_survivors = [r for r in cf_rows if int(r.get("fail_count", 0)) < args.max_fails]
        cf_eliminated = total_cf - len(cf_survivors)
        if cf_eliminated > 0:
            log.info("[单条优选] 淘汰剔除 %d 条连续失败 >= %d 次的死节点", cf_eliminated, args.max_fails)
        else:
            log.info("[单条优选] 本次无节点达到连续失败 %d 次的淘汰阈值", args.max_fails)

        cf_survivors.sort(key=lambda x: x.get("tested_at", ""), reverse=True)
        save_cf_ips(cf_survivors, CF_CSV, CF_TXT)
    else:
        log.info(">>> %s 文件不存在或无数据，跳过单条优选校验", CF_CSV)

    # ================= 2. 校验扫描优选 IP (scan_ips) =================
    scan_rows = load_csv(SCAN_CSV)
    if scan_rows:
        total_scan = len(scan_rows)
        log.info(">>> 开始校验扫描优选 IP (%s): 共 %d 条...", SCAN_CSV, total_scan)
        asyncio.run(verify_all(scan_rows, tag="扫描优选", concurrency=args.concurrency, timeout=args.timeout))

        scan_survivors = [r for r in scan_rows if int(r.get("fail_count", 0)) < args.max_fails]
        scan_eliminated = total_scan - len(scan_survivors)
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
            all_sorted_scan.extend(group_rows)

        save_scan_csv(all_sorted_scan, SCAN_CSV)
        save_scan_txt(asn_groups, SCAN_TXT)
        save_scan_dir(asn_groups, SCAN_DIR)
    else:
        log.info(">>> %s 文件不存在或无数据，跳过扫描优选校验", SCAN_CSV)

    elapsed = time.time() - t_start
    log.info("全部优选 IP 两阶段校验流程圆满完成，总耗时 %.2f 秒", elapsed)


if __name__ == "__main__":
    main()
