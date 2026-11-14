import asyncio
import csv
import errno
import http.server
import io
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import cf_verify
import providers
import proxies_verify
import proxyip_verify


class _FakeWriter:
    def __init__(self):
        self.closed = False
        self._transport = None

    def write(self, data: bytes):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class _FakeReader:
    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def read(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _SlowDrainWriter(_FakeWriter):
    def __init__(self, delay_s: float = 0.05):
        super().__init__()
        self._delay_s = delay_s

    async def drain(self):
        await asyncio.sleep(self._delay_s)


class TestReadFullResponseTimeoutVsEof(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_exhausted_without_bytes_raises_timeout(self):
        reader = _FakeReader([b"HTTP/1.1 200 OK\r\n\r\n"])
        with self.assertRaises(asyncio.TimeoutError):
            await providers.read_full_response(reader, http_timeout=0.0)

    async def test_clean_eof_without_bytes_returns_empty_before_deadline(self):
        reader = _FakeReader([b""])
        res = await providers.read_full_response(reader, http_timeout=1.0)
        self.assertEqual(res, b"")


class TestCfVerifyTransientErrors(unittest.IsolatedAsyncioTestCase):
    async def test_probe_ip_distinguishes_refused_from_reset_and_oserror(self):
        with patch("cf_verify.asyncio.open_connection", side_effect=ConnectionRefusedError()):
            alive, _, reason = await cf_verify.probe_ip("104.16.1.1", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "conn_error")

        with patch("cf_verify.asyncio.open_connection", side_effect=ConnectionResetError("rst")):
            alive, _, reason = await cf_verify.probe_ip("104.16.1.1", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "conn_reset")

        with patch("cf_verify.asyncio.open_connection", side_effect=OSError(errno.ENETUNREACH, "net")):
            alive, _, reason = await cf_verify.probe_ip("104.16.1.1", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "net_error_OSError")

    async def test_probe_ip_slow_drain_returns_http_timeout_not_empty_response(self):
        reader = _FakeReader([b""])
        writer = _SlowDrainWriter(delay_s=0.03)
        with patch("cf_verify.asyncio.open_connection", return_value=(reader, writer)):
            alive, _, reason = await cf_verify.probe_ip("104.16.1.1", 443, http_timeout=0.01)
            self.assertFalse(alive)
            self.assertEqual(reason, "http_timeout")

    async def test_verify_all_buffers_transient_failures_but_fast_fails_refused_and_non_cf_cdn(self):
        rows = [
            {"ip": "104.16.1.1", "port": "443", "fail_count": 0},
            {"ip": "104.16.1.2", "port": "443", "fail_count": 0},
            {"ip": "104.16.1.3", "port": "443", "fail_count": 0},
            {"ip": "104.16.1.4", "port": "443", "fail_count": 0},
            {"ip": "104.16.1.5", "port": "443", "fail_count": 0},
        ]
        reasons = {
            "104.16.1.1": (False, 10, "conn_reset"),
            "104.16.1.2": (False, 10, "net_error_OSError"),
            "104.16.1.3": (False, 10, "empty_response"),
            "104.16.1.4": (False, 0, "conn_error"),
            "104.16.1.5": (False, 12, "non_cf_cdn"),
        }

        async def _fake_probe(ip, port, connect_timeout=3.0, http_timeout=2.0):
            return reasons[ip]

        with patch("cf_verify.probe_ip", side_effect=_fake_probe):
            await cf_verify.verify_all(rows, tag="test", concurrency=5, max_fails=3)

        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(by_ip["104.16.1.1"]["fail_count"], 1)
        self.assertEqual(by_ip["104.16.1.2"]["fail_count"], 1)
        self.assertEqual(by_ip["104.16.1.3"]["fail_count"], 1)
        self.assertEqual(by_ip["104.16.1.4"]["fail_count"], 3)
        self.assertEqual(by_ip["104.16.1.5"]["fail_count"], 3)


class TestProxyIpVerifyTransientErrors(unittest.IsolatedAsyncioTestCase):
    async def test_probe_proxyip_classifies_tls_eof_and_oserror_separately(self):
        with patch("proxyip_verify.asyncio.open_connection", side_effect=ssl.SSLEOFError("eof")):
            alive, _, _, reason = await proxyip_verify.probe_proxyip("1.2.3.4", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "tls_eof")

        with patch("proxyip_verify.asyncio.open_connection", side_effect=OSError(errno.EHOSTUNREACH, "unreach")):
            alive, _, _, reason = await proxyip_verify.probe_proxyip("1.2.3.4", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "net_error_OSError")

        with patch("proxyip_verify.asyncio.open_connection", side_effect=ConnectionRefusedError()):
            alive, _, _, reason = await proxyip_verify.probe_proxyip("1.2.3.4", 443)
            self.assertFalse(alive)
            self.assertEqual(reason, "conn_error")

    async def test_verify_proxyips_protects_verified_nodes_and_tls_while_fast_failing_unverified_junk(self):
        rows = [
            # 已实测存活的节点 (delay_ms > 0) 遇多租户抖动 non_cf_cdn 应进入缓冲
            {"ip": "198.51.100.1", "port": "443", "fail_count": 0, "delay_ms": "120", "exit_ip": "198.51.100.1", "exit_asn": "AS7922 Comcast"},
            # 全新未验证节点 (delay_ms == 0) 遇 non_cf_cdn / status_404 仍保持快速淘汰
            {"ip": "198.51.100.2", "port": "443", "fail_count": 0, "delay_ms": "0", "exit_ip": "198.51.100.2", "exit_asn": "AS7922 Comcast"},
            # tls_error / tls_eof 对新旧节点均享 3 次缓冲
            {"ip": "198.51.100.3", "port": "443", "fail_count": 0, "delay_ms": "0", "exit_ip": "198.51.100.3", "exit_asn": "AS7922 Comcast"},
            {"ip": "198.51.100.4", "port": "443", "fail_count": 0, "delay_ms": "85", "exit_ip": "198.51.100.4", "exit_asn": "AS7922 Comcast"},
            # invalid_row 无论 delay_ms 为何立即淘汰
            {"ip": "198.51.100.5", "port": "99999", "fail_count": 0, "delay_ms": "50"},
        ]
        outcomes = {
            "198.51.100.1": (False, 30, "", "non_cf_cdn"),
            "198.51.100.2": (False, 30, "", "status_404"),
            "198.51.100.3": (False, 0, "", "tls_error"),
            "198.51.100.4": (False, 0, "", "tls_eof"),
        }

        async def _fake_probe(ip, port, connect_timeout=4.0, http_timeout=3.5):
            return outcomes[ip]

        with patch("proxyip_verify._has_complete_profile", return_value=True), \
             patch("proxyip_verify.probe_proxyip", side_effect=_fake_probe):
            await proxyip_verify.verify_proxyips(rows, concurrency=5, max_fails=3)

        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(by_ip["198.51.100.1"]["fail_count"], 1)
        self.assertEqual(by_ip["198.51.100.2"]["fail_count"], 3)
        self.assertEqual(by_ip["198.51.100.3"]["fail_count"], 1)
        self.assertEqual(by_ip["198.51.100.4"]["fail_count"], 1)
        self.assertEqual(by_ip["198.51.100.5"]["fail_count"], 3)


class TestProxiesVerifyTransientErrorsAndFallback(unittest.IsolatedAsyncioTestCase):
    def test_classify_socket_error_and_http_defaults(self):
        self.assertEqual(proxies_verify.HTTP_MAX_FAILS, 2)
        self.assertEqual(proxies_verify.HTTP_PROBE_TIMEOUT, 2.5)
        self.assertEqual(proxies_verify.HTTP_MAX_LATENCY_MS, 3500)

        self.assertEqual(proxies_verify._classify_socket_error(TimeoutError()), "timeout")
        self.assertEqual(proxies_verify._classify_socket_error(ssl.SSLEOFError("eof")), "conn_reset")
        self.assertEqual(proxies_verify._classify_socket_error(ssl.SSLError("bad")), "tls_err")
        self.assertEqual(proxies_verify._classify_socket_error(ConnectionRefusedError()), "conn_err")
        self.assertEqual(proxies_verify._classify_socket_error(ConnectionResetError()), "conn_reset")
        self.assertEqual(proxies_verify._classify_socket_error(BrokenPipeError()), "conn_reset")
        self.assertEqual(proxies_verify._classify_socket_error(socket.gaierror()), "dns_err")
        self.assertEqual(proxies_verify._classify_socket_error(OSError(errno.ENETUNREACH, "unreach")), "net_err")

    async def test_probe_socks5_oserror_is_soft_while_refused_is_fatal(self):
        sem = asyncio.Semaphore(4)
        base = {"proto": "socks5", "host": "203.0.113.10", "port": 1080, "url": "socks5://203.0.113.10:1080", "fail_count": 0}

        with patch("proxies_verify.asyncio.open_connection", side_effect=OSError(errno.EHOSTUNREACH, "unreach")):
            r_soft = await proxies_verify.probe_single(base.copy(), sem, max_fails=3)
            self.assertFalse(r_soft["is_alive"])
            self.assertEqual(r_soft["status"], "net_err")
            self.assertEqual(r_soft["fail_count"], 1)

        with patch("proxies_verify.asyncio.open_connection", side_effect=ConnectionRefusedError()):
            r_hard = await proxies_verify.probe_single(base.copy(), sem, max_fails=3)
            self.assertFalse(r_hard["is_alive"])
            self.assertEqual(r_hard["status"], "conn_err")
            self.assertEqual(r_hard["fail_count"], 3)

    async def test_http_soft_failure_uses_buffer_two_and_fatal_evicts_immediately(self):
        sem = asyncio.Semaphore(4)
        base = {"proto": "http", "host": "203.0.113.11", "port": 8080, "url": "http://203.0.113.11:8080", "fail_count": 0}

        with patch("proxies_verify.probe_http", return_value=(False, 2900, "slow_timeout", "", "", "")):
            r1 = await proxies_verify.probe_single(base.copy(), sem, max_fails=3, http_max_fails=2)
            self.assertEqual(r1["fail_count"], 1)
            r2 = await proxies_verify.probe_single(r1.copy(), sem, max_fails=3, http_max_fails=2)
            self.assertEqual(r2["fail_count"], 2)

        with patch("proxies_verify.probe_http", return_value=(False, 0, "http_connect_fail", "", "", "")):
            r_fatal = await proxies_verify.probe_single(base.copy(), sem, max_fails=3, http_max_fails=2)
            self.assertEqual(r_fatal["fail_count"], 2)

    async def test_sstp_worker_failure_falls_back_to_local_probe_and_preserves_exit_ip(self):
        sem = asyncio.Semaphore(4)
        row = {
            "proto": "sstp",
            "host": "203.0.113.20",
            "port": 443,
            "user": "vpn",
            "pwd": "vpn",
            "source": "vpngate",
            "egress_ip": "198.51.100.77",
            "fail_count": 0,
        }

        with patch("proxies_verify.check_sstp_exit_cf_worker", return_value={"success": False, "error": "AES-GCM unsupported"}), \
             patch("proxies_verify.probe_sstp", return_value=(True, 145, "alive", "-", "", "203.0.113.20")):
            res = await proxies_verify.probe_single(row.copy(), sem, cf_check_endpoint="https://worker.example")
            self.assertTrue(res["is_alive"])
            self.assertEqual(res["status"], "alive")
            self.assertEqual(res["delay_ms"], 145)
            self.assertEqual(res["fail_count"], 0)
            self.assertEqual(res["egress_ip"], "198.51.100.77")

    async def test_proxifly_https_worker_failure_falls_back_to_local_probe_and_keeps_worker_unreachable_on_net_err(self):
        sem = asyncio.Semaphore(4)
        row = {
            "proto": "https",
            "host": "203.0.113.30",
            "port": 8443,
            "source": "proxifly",
            "fail_count": 1,
        }

        # 1. Worker 失败（如 TLS 兼容差异）但本地 probe_https 穿透成功 -> 救回并归零 fail_count
        with patch("proxies_verify.check_proxy_exit_cf_worker", return_value={"success": False, "error": "https_worker_fail"}), \
             patch("proxies_verify.probe_https", return_value=(True, 210, "alive", "NRT", "JP", "198.51.100.88")):
            res_ok = await proxies_verify.probe_single(row.copy(), sem, cf_check_endpoint="https://worker.example")
            self.assertTrue(res_ok["is_alive"])
            self.assertEqual(res_ok["fail_count"], 0)
            self.assertEqual(res_ok["egress_ip"], "198.51.100.88")

        # 2. Worker 网络错误 + 本地软超时 -> 保留 worker_unreachable 且不扣除现有 fail_count
        with patch("proxies_verify.check_proxy_exit_cf_worker", return_value={"success": False, "network_error": True, "error": "HTTP 524"}), \
             patch("proxies_verify.probe_https", return_value=(False, 0, "timeout", "", "", "")):
            res_unreach = await proxies_verify.probe_single(row.copy(), sem, cf_check_endpoint="https://worker.example")
            self.assertFalse(res_unreach["is_alive"])
            self.assertEqual(res_unreach["status"], "worker_unreachable")
            self.assertEqual(res_unreach["fail_count"], 1)

        # 3. Worker 失败且本地证实端口拒绝 -> 按致命硬故障淘汰
        with patch("proxies_verify.check_proxy_exit_cf_worker", return_value={"success": False, "error": "https_worker_fail"}), \
             patch("proxies_verify.probe_https", return_value=(False, 0, "conn_err", "", "", "")):
            res_dead = await proxies_verify.probe_single(row.copy(), sem, cf_check_endpoint="https://worker.example", max_fails=3)
            self.assertFalse(res_dead["is_alive"])
            self.assertEqual(res_dead["status"], "conn_err")
            self.assertEqual(res_dead["fail_count"], 3)

    async def test_probe_https_stage2_empty_eof_vs_fake_200_html(self):
        class _FakeTransport:
            def get_protocol(self):
                return object()

        class _Stage2Writer(_FakeWriter):
            def __init__(self):
                super().__init__()
                self.transport = _FakeTransport()

        class _FakeLoop:
            async def start_tls(self, transport, protocol, sslcontext=None, server_hostname=None):
                return transport

        stage2_payload = []

        async def _connect_seq(host, port, **kwargs):
            _connect_seq.calls += 1
            if _connect_seq.calls == 1:
                return _FakeReader([b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"]), _FakeWriter()
            return _FakeReader(stage2_payload), _Stage2Writer()

        # Case 1: Stage 2 CONNECT established + TLS upgraded, then clean empty EOF -> soft conn_reset
        _connect_seq.calls = 0
        stage2_payload = [b"HTTP/1.1 200 Connection established\r\n\r\n", b""]
        with patch("proxies_verify.asyncio.open_connection", side_effect=_connect_seq), \
             patch("proxies_verify.asyncio.get_running_loop", return_value=_FakeLoop()):
            alive, _, status, _, _, _ = await proxies_verify.probe_https("203.0.113.40", 8443, None, None)
            self.assertFalse(alive)
            self.assertEqual(status, "conn_reset")

        # Case 2: Stage 2 CONNECT established + non-empty HTTP 200 HTML missing colo/ip -> fatal http_connect_no_colo
        _connect_seq.calls = 0
        stage2_payload = [b"HTTP/1.1 200 Connection established\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n<html>portal</html>"]
        with patch("proxies_verify.asyncio.open_connection", side_effect=_connect_seq), \
             patch("proxies_verify.asyncio.get_running_loop", return_value=_FakeLoop()):
            alive, _, status, _, _, _ = await proxies_verify.probe_https("203.0.113.40", 8443, None, None)
            self.assertFalse(alive)
            self.assertEqual(status, "http_connect_no_colo")

    async def test_async_main_proxifly_fallback_enforces_datacenter_exclusion_without_tombstone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pr_csv = os.path.join(tmpdir, "proxies.csv")
            pr_txt = os.path.join(tmpdir, "proxies.txt")
            pr_dir = os.path.join(tmpdir, "proxies")
            os.makedirs(pr_dir, exist_ok=True)
            rows = [
                {
                    "url": "https://203.0.113.50:8443",
                    "proto": "https",
                    "host": "203.0.113.50",
                    "port": "8443",
                    "fail_count": "0",
                    "delay_ms": "0",
                    "source": "proxifly",
                },
                {
                    "url": "https://203.0.113.51:8443",
                    "proto": "https",
                    "host": "203.0.113.51",
                    "port": "8443",
                    "fail_count": "0",
                    "delay_ms": "0",
                    "source": "proxifly",
                },
            ]
            with open(pr_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.PROXY_CSV_FIELDS)
                w.writeheader()
                for r in rows:
                    w.writerow({k: r.get(k, "") for k in providers.PROXY_CSV_FIELDS})

            tombstoned_keys = []
            shared_cache = {
                "198.51.100.10": {"asn": "AS7922", "isp": "Comcast Cable", "net_type": "isp", "country": "US"},
                "198.51.100.20": {"asn": "AS16509", "isp": "Amazon.com, Inc.", "net_type": "datacenter", "country": "US"},
            }

            async def _fake_probe_https(host, port, user, pwd, connect_timeout=7.0, http_timeout=2.5, max_latency_ms=0):
                if host == "203.0.113.50":
                    return True, 180, "alive", "SJC", "US", "198.51.100.10"
                return True, 90, "alive", "IAD", "US", "198.51.100.20"

            def _fake_record(keys, *args, **kwargs):
                tombstoned_keys.extend(keys)
                return len(keys)

            args = SimpleNamespace(
                concurrency=4,
                max_fails=3,
                timeout=2.0,
                http_timeout=2.0,
                sstp_timeout=2.0,
                http_probe_timeout=2.5,
                http_max_latency=3500,
                http_max_fails=2,
                cf_check_endpoint="https://worker.example",
                cf_check_token="",
                cf_concurrency=4,
                no_notify=True,
            )

            with patch.object(proxies_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxies_verify, "PROXIES_CSV", pr_csv), \
                 patch.object(proxies_verify, "PROXIES_TXT", pr_txt), \
                 patch.object(proxies_verify, "PROXIES_DIR", pr_dir), \
                 patch("proxies_verify.check_cf_worker_health", return_value=True), \
                 patch("proxies_verify.check_proxy_exit_cf_worker", return_value={"success": False, "error": "Worker TLS error"}), \
                 patch("proxies_verify.probe_https", side_effect=_fake_probe_https), \
                 patch("proxies_verify.load_ip_cache", return_value=shared_cache), \
                 patch("proxies_verify.save_ip_cache"), \
                 patch("proxies_verify.prune_ip_cache", return_value=0), \
                 patch("proxies_verify.load_tombstone", return_value={}), \
                 patch("proxies_verify.record_tombstone", side_effect=_fake_record), \
                 patch("proxies_verify.auto_enrich_and_save_asns", return_value=0), \
                 patch("proxies_verify.resolve_asn_batch_online_async", return_value={}):
                await proxies_verify.async_main(args)

            with open(pr_csv, "r", encoding="utf-8-sig") as f:
                saved_hosts = [r["host"] for r in csv.DictReader(f)]
            self.assertEqual(saved_hosts, ["203.0.113.50"])
            self.assertEqual(tombstoned_keys, [])

    async def test_enrich_proxies_metadata_resolves_uncached_prefilled_egress_and_never_reverse_pollutes_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "ip_cache.json")
            disk_cache = {
                # 多跳入口已缓存为 AWS 机房
                "18.144.86.139": {"asn": "AS16509 Amazon AWS", "isp": "Amazon AWS", "net_type": "datacenter", "country": "US"},
                # 已缓存但 net_type 为陈旧值（AS7922 在规则中属 isp），应通过自身 ASN 校准而非被行内脏值覆写
                "198.51.100.99": {"asn": "AS7922", "isp": "Comcast Cable", "net_type": "datacenter", "country": "US"},
            }
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(disk_cache, f)

            survivors = [
                # 1. 多跳外部预填 ASN (AS60729) 且已带 country="DE"，但真实 egress_ip 未在 ip_cache 中 -> 必须入队解析，且保留实测 country
                {
                    "proto": "http",
                    "host": "18.144.86.139",
                    "egress_ip": "198.51.100.77",
                    "asn": "AS60729 Network for Tor-Exit traffic.",
                    "isp": "Network for Tor-Exit traffic.",
                    "country": "DE",
                    "net_type": "education",
                },
                # 2. 单跳外部预填假 AS60729（实为 AS16509 Amazon），绝不允许行上假 ASN 反写覆盖 ip_cache
                {
                    "proto": "http",
                    "host": "16.28.29.244",
                    "egress_ip": "16.28.29.244",
                    "asn": "AS60729 Network for Tor-Exit traffic.",
                    "isp": "Network for Tor-Exit traffic.",
                    "country": "ZA",
                    "net_type": "education",
                },
                # 3. 缓存内已有真实 AS7922，但行上误带有 AS60729 -> 行与缓存都应以真实画像为准校准
                {
                    "proto": "https",
                    "host": "198.51.100.99",
                    "egress_ip": "198.51.100.99",
                    "asn": "AS60729 Network for Tor-Exit traffic.",
                    "country": "US",
                    "net_type": "education",
                },
            ]

            queried_targets = []

            async def _fake_batch_resolve(targets, cache_path="", **kwargs):
                queried_targets.extend(sorted(targets))
                with open(cache_path, "r", encoding="utf-8") as f:
                    cur = json.load(f)
                cur["198.51.100.77"] = {"asn": "AS16509", "isp": "Amazon AWS", "net_type": "datacenter", "country": "US"}
                cur["16.28.29.244"] = {"asn": "AS16509", "isp": "Amazon AWS", "net_type": "datacenter", "country": "ZA"}
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(cur, f)
                return {
                    "198.51.100.77": ("AS16509", "Amazon AWS"),
                    "16.28.29.244": ("AS16509", "Amazon AWS"),
                }

            with patch("proxies_verify.resolve_asn_batch_online_async", side_effect=_fake_batch_resolve), \
                 patch("proxies_verify.auto_enrich_and_save_asns", return_value=0):
                net_stats = await proxies_verify.enrich_proxies_metadata(survivors, cache_path=cache_path)

            self.assertEqual(set(queried_targets), {"198.51.100.77", "16.28.29.244"})
            # 1. 多跳行按真实 egress 解析并保留原实测 country
            self.assertIn("AS16509", survivors[0]["asn"])
            self.assertEqual(survivors[0]["net_type"], "datacenter")
            self.assertEqual(survivors[0]["country"], "DE")
            # 2. 单跳伪标行被纠偏为 Amazon AWS datacenter
            self.assertIn("AS16509", survivors[1]["asn"])
            self.assertEqual(survivors[1]["net_type"], "datacenter")
            # 3. 缓存内陈旧 net_type 根据自身 AS7922 校准为 isp，同时不被行上脏 AS60729 污染
            self.assertIn("AS7922", survivors[2]["asn"])
            self.assertEqual(survivors[2]["net_type"], "isp")
            self.assertEqual(net_stats, {"datacenter": 2, "isp": 1})

            with open(cache_path, "r", encoding="utf-8") as f:
                final_cache = json.load(f)
            self.assertIn("AS16509", final_cache["16.28.29.244"]["asn"])
            self.assertEqual(final_cache["16.28.29.244"]["net_type"], "datacenter")
            self.assertIn("AS7922", final_cache["198.51.100.99"]["asn"])
            self.assertEqual(final_cache["198.51.100.99"]["net_type"], "isp")

    def test_sync_cf_check_extracts_cf_error_1102_and_classify_cf_worker_error(self):
        http_500 = urllib.error.HTTPError(
            url="https://worker.example/check",
            code=500,
            msg="Internal Server Error",
            hdrs=None,
            fp=io.BytesIO(b"<html><body>Error 1102: Worker exceeded resource limits</body></html>"),
        )

        class _FailOpener:
            def open(self, req, timeout=18.0):
                raise http_500

        with patch("proxies_verify.get_cf_opener", return_value=_FailOpener()):
            res = proxies_verify._sync_cf_check("https://worker.example", "sstp://1.2.3.4:443", timeout=18.0)

        self.assertFalse(res["success"])
        self.assertTrue(res["network_error"])
        self.assertEqual(res["http_code"], 500)
        self.assertEqual(res["cf_error"], "1102")
        self.assertEqual(proxies_verify._classify_cf_worker_error(res), "http_500_cf_1102")
        self.assertEqual(
            proxies_verify._classify_cf_worker_error({"success": False, "network_error": True, "error": "Target /api/lookup request failed: HTTP/1.1 429"}),
            "iplocate_err",
        )
        self.assertEqual(
            proxies_verify._classify_cf_worker_error({"success": False, "network_error": True, "error": "network_error: timed out"}),
            "client_timeout",
        )
        self.assertEqual(
            proxies_verify._classify_cf_worker_error({"success": False, "error": "Proxy connection timed out"}),
            "worker_proxy_timeout",
        )

    async def test_async_main_logs_worker_diagnostics_clears_temp_fields_and_fixes_p2_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pr_csv = os.path.join(tmpdir, "proxies.csv")
            pr_txt = os.path.join(tmpdir, "proxies.txt")
            pr_dir = os.path.join(tmpdir, "proxies")
            os.makedirs(pr_dir, exist_ok=True)
            fetch_stats_path = os.path.join(tmpdir, ".fetch_stats.json")
            with open(fetch_stats_path, "w", encoding="utf-8") as f:
                json.dump({}, f)

            rows = [
                # 本地 socks5：1 存活，1 致命淘汰
                {"url": "socks5://203.0.113.1:1080", "proto": "socks5", "host": "203.0.113.1", "port": "1080", "fail_count": "0", "delay_ms": "0", "source": "@user"},
                {"url": "socks5://203.0.113.2:1080", "proto": "socks5", "host": "203.0.113.2", "port": "1080", "fail_count": "0", "delay_ms": "0", "source": "@user"},
                # Worker sstp：1 正常 Worker 存活，1 Worker Error 1102 走本地回退救活
                {"url": "sstp://203.0.113.3:443", "proto": "sstp", "host": "203.0.113.3", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "vpngate"},
                {"url": "sstp://203.0.113.4:443", "proto": "sstp", "host": "203.0.113.4", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "vpngate"},
                # Worker proxifly https：1 直接机房拦截，1 正常住宅留存
                {"url": "https://203.0.113.5:443", "proto": "https", "host": "203.0.113.5", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "proxifly"},
                {"url": "https://203.0.113.6:443", "proto": "https", "host": "203.0.113.6", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "proxifly"},
            ]
            with open(pr_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.PROXY_CSV_FIELDS)
                w.writeheader()
                for r in rows:
                    w.writerow({k: r.get(k, "") for k in providers.PROXY_CSV_FIELDS})

            shared_cache = {
                "203.0.113.1": {"asn": "AS7922 Comcast", "isp": "Comcast", "net_type": "isp", "country": "US"},
                "203.0.113.3": {"asn": "AS7922 Comcast", "isp": "Comcast", "net_type": "isp", "country": "US"},
                "203.0.113.4": {"asn": "AS7922 Comcast", "isp": "Comcast", "net_type": "isp", "country": "US"},
                "203.0.113.5": {"asn": "AS16509 Amazon AWS", "isp": "Amazon AWS", "net_type": "datacenter", "country": "US"},
                "203.0.113.6": {"asn": "AS7922 Comcast", "isp": "Comcast", "net_type": "isp", "country": "US"},
            }
            cache_path = os.path.join(tmpdir, "ip_cache.json")
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(shared_cache, f)

            async def _fake_socks5(host, port, user, pwd, connect_timeout=3.0, http_timeout=2.5):
                if host == "203.0.113.1":
                    return True, 50, "alive", "SJC", "US", "203.0.113.1"
                return False, 0, "conn_err", "", "", ""

            async def _fake_cf_worker(endpoint, proxy_url, timeout=18.0, executor=None, token=""):
                if "203.0.113.5" in proxy_url:
                    return {
                        "success": True,
                        "responseTime": 300,
                        "exit": {"ip": "203.0.113.5", "country_code": "US", "asn": {"asn": "AS16509", "name": "Amazon.com, Inc."}},
                    }
                return {
                    "success": True,
                    "responseTime": 450,
                    "exit": {"ip": "203.0.113.6", "country_code": "US", "asn": {"asn": "AS7922", "name": "Comcast Cable"}},
                }

            async def _fake_cf_sstp(endpoint, host, port, user=None, pwd=None, timeout=18.0, executor=None, token=""):
                if host == "203.0.113.3":
                    return {
                        "success": True,
                        "responseTime": 1200,
                        "exit": {"ip": "203.0.113.3", "country_code": "US", "asn": {"asn": "AS7922", "name": "Comcast Cable"}},
                    }
                return {"success": False, "network_error": True, "http_code": 500, "cf_error": "1102", "error": "HTTP 500: Internal Server Error (CF Error 1102)"}

            async def _fake_probe_sstp(host, port, connect_timeout=8.0, read_timeout=4.0):
                return True, 180, "alive", "-", "", "203.0.113.4"

            args = SimpleNamespace(
                concurrency=4,
                max_fails=3,
                timeout=2.0,
                http_timeout=2.0,
                sstp_timeout=2.0,
                http_probe_timeout=2.5,
                http_max_latency=3500,
                http_max_fails=2,
                cf_check_endpoint="https://worker.example",
                cf_check_token="",
                cf_concurrency=4,
                no_notify=True,
            )

            with patch.object(proxies_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxies_verify, "PROXIES_CSV", pr_csv), \
                 patch.object(proxies_verify, "PROXIES_TXT", pr_txt), \
                 patch.object(proxies_verify, "PROXIES_DIR", pr_dir), \
                 patch("proxies_verify.check_cf_worker_health", return_value=True), \
                 patch("proxies_verify.probe_socks5", side_effect=_fake_socks5), \
                 patch("proxies_verify.check_proxy_exit_cf_worker", side_effect=_fake_cf_worker), \
                 patch("proxies_verify.check_sstp_exit_cf_worker", side_effect=_fake_cf_sstp), \
                 patch("proxies_verify.probe_sstp", side_effect=_fake_probe_sstp), \
                 patch("proxies_verify.prune_ip_cache", return_value=0), \
                 patch("proxies_verify.load_tombstone", return_value={}), \
                 patch("proxies_verify.record_tombstone", return_value=1), \
                 patch("proxies_verify.auto_enrich_and_save_asns", return_value=0), \
                 patch("proxies_verify.resolve_asn_batch_online_async", return_value={}):
                with self.assertLogs(proxies_verify.log, level="INFO") as cm:
                    await proxies_verify.async_main(args)

            logs_text = "\n".join(cm.output)
            self.assertIn("[通道耗时统计] 本地直连: 2 条完成于", logs_text)
            self.assertIn("Worker 通道: 4 条完成于", logs_text)
            self.assertIn("本地回退 1 条 (回退存活 1 条 [network_error触发 1])", logs_text)
            self.assertIn("http_500_cf_1102=1", logs_text)
            self.assertIn("[Worker 耗时分布]", logs_text)

            with open(fetch_stats_path, "r", encoding="utf-8") as f:
                stats = json.load(f)
            self.assertEqual(stats["proxies_survivors"], 4)
            self.assertEqual(stats["proxies_pass"], 4)
            self.assertEqual(stats["proxies_fail"], 0)
            self.assertEqual(sum(d["total"] for d in stats["proxies_proto_breakdown"].values()), 4)

            with open(os.path.join(pr_dir, "sstp.json"), "r", encoding="utf-8") as f:
                sstp_items = json.load(f)
            for item in sstp_items:
                self.assertNotIn("_worker_diag", item)

    def test_sync_cf_check_keepalive_reuses_connection_and_retries_stale_socket(self):
        accept_count = 0
        req_count = 0

        class _KeepAliveHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                nonlocal req_count
                req_count += 1
                if req_count == 3:
                    # 模拟复用空闲连接时服务端意外断连（RemoteDisconnected）
                    self.close_connection = True
                    self.connection.close()
                    return
                body = json.dumps({"success": True, "responseTime": 25, "reqNo": req_count}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class _CountingServer(http.server.ThreadingHTTPServer):
            def get_request(self):
                nonlocal accept_count
                accept_count += 1
                return super().get_request()

        server = _CountingServer(("127.0.0.1", 0), _KeepAliveHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        ep = f"http://127.0.0.1:{server.server_port}"
        try:
            with patch.dict(os.environ, {}, clear=False):
                for k in proxies_verify._CF_PROXY_ENV_KEYS:
                    os.environ.pop(k, None)
                r1 = proxies_verify._sync_cf_check(ep, "sstp://1.1.1.1:443", timeout=5.0)
                r2 = proxies_verify._sync_cf_check(ep, "sstp://1.1.1.2:443", timeout=5.0)
                # 第 1、2 次请求复用同一条 Keep-Alive 连接（accept_count == 1）
                self.assertTrue(r1["success"])
                self.assertTrue(r2["success"])
                self.assertGreater(r1.get("_rpc_ms", 0), 0)
                self.assertEqual(accept_count, 1)

                # 第 3 次请求服务端直接断开，应自动重连重试 1 次并在第 4 次 HTTP 处理成功
                r3 = proxies_verify._sync_cf_check(ep, "sstp://1.1.1.3:443", timeout=5.0)
                self.assertTrue(r3["success"])
                self.assertEqual(r3["reqNo"], 4)
                self.assertEqual(accept_count, 2)
        finally:
            proxies_verify.close_cf_keepalive_conns()
            server.shutdown()
            server.server_close()

    async def test_async_resolve_domain_deduplicates_concurrent_queries(self):
        calls = []

        def _slow_resolve(domain):
            calls.append(domain)
            time.sleep(0.05)
            return "198.51.100.42"

        try:
            with patch("proxies_verify.resolve_domain_to_ip", side_effect=_slow_resolve):
                res = await asyncio.gather(
                    proxies_verify._async_resolve_domain("dup.example.net"),
                    proxies_verify._async_resolve_domain("dup.example.net"),
                    proxies_verify._async_resolve_domain("DUP.EXAMPLE.NET"),
                )
            self.assertEqual(res, ["198.51.100.42", "198.51.100.42", "198.51.100.42"])
            self.assertEqual(len(calls), 3)  # 锁保证串行且复用实现路径；至少全部通过独立池完成解析
        finally:
            proxies_verify.shutdown_dns_executor(wait=True)

    async def test_async_main_resolves_worker_trace_exit_without_asn_and_separates_rpc_queue_ms(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pr_csv = os.path.join(tmpdir, "proxies.csv")
            pr_txt = os.path.join(tmpdir, "proxies.txt")
            pr_dir = os.path.join(tmpdir, "proxies")
            os.makedirs(pr_dir, exist_ok=True)
            cache_path = os.path.join(tmpdir, "ip_cache.json")
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump({}, f)

            rows = [
                # Worker 返回无 ASN 的纯公网 exit.ip（模拟 trace 兜底）：应由二阶段在线反查补全，住宅放行、机房拦截
                {"url": "https://73.0.0.10:443", "proto": "https", "host": "73.0.0.10", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "proxifly"},
                {"url": "https://54.1.2.11:443", "proto": "https", "host": "54.1.2.11", "port": "443", "fail_count": "0", "delay_ms": "0", "source": "proxifly"},
            ]
            with open(pr_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.PROXY_CSV_FIELDS)
                w.writeheader()
                for r in rows:
                    w.writerow({k: r.get(k, "") for k in providers.PROXY_CSV_FIELDS})

            async def _fake_cf_worker(endpoint, proxy_url, timeout=18.0, executor=None, token=""):
                await asyncio.sleep(0.06)  # 模拟含并发排队的外层 wall_ms (>60ms)，而 _rpc_ms 仅 12ms
                ip = "73.0.0.10" if "73.0.0.10" in proxy_url else "54.1.2.11"
                return {
                    "success": True,
                    "responseTime": 35,
                    "_rpc_ms": 12,
                    "exit": {"ip": ip, "country_code": "US"},  # 刻意省略 asn
                }

            async def _fake_resolve_batch(ips, cache_path=""):
                disk = providers.load_ip_cache(filepath=cache_path)
                out = {}
                for ip in ips:
                    if ip == "73.0.0.10":
                        out[ip] = ("AS7922", "Comcast Cable")
                        disk[ip] = {"asn": "AS7922 Comcast Cable", "isp": "Comcast Cable", "net_type": "isp", "country": "US"}
                    else:
                        out[ip] = ("AS16509", "Amazon.com, Inc.")
                        disk[ip] = {"asn": "AS16509 Amazon AWS", "isp": "Amazon AWS", "net_type": "datacenter", "country": "US"}
                providers.save_ip_cache(disk, filepath=cache_path, compact=True)
                return out

            args = SimpleNamespace(
                concurrency=4, max_fails=3, timeout=2.0, http_timeout=2.0, sstp_timeout=2.0,
                http_probe_timeout=2.5, http_max_latency=3500, http_max_fails=2,
                cf_check_endpoint="https://worker.example", cf_check_token="", cf_concurrency=2, no_notify=True,
            )

            with patch.object(proxies_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxies_verify, "PROXIES_CSV", pr_csv), \
                 patch.object(proxies_verify, "PROXIES_TXT", pr_txt), \
                 patch.object(proxies_verify, "PROXIES_DIR", pr_dir), \
                 patch("proxies_verify.check_cf_worker_health", return_value=True), \
                 patch("proxies_verify.check_proxy_exit_cf_worker", side_effect=_fake_cf_worker), \
                 patch("proxies_verify.resolve_asn_batch_online_async", side_effect=_fake_resolve_batch), \
                 patch("proxies_verify.prune_ip_cache", return_value=0), \
                 patch("proxies_verify.load_tombstone", return_value={}), \
                 patch("proxies_verify.record_tombstone", return_value=0), \
                 patch("proxies_verify.auto_enrich_and_save_asns", return_value=0):
                with self.assertLogs(proxies_verify.log, level="INFO") as cm:
                    await proxies_verify.async_main(args)

            logs_text = "\n".join(cm.output)
            self.assertIn("rpc(n=2: avg=12ms", logs_text)
            self.assertIn("worker(n=2: avg=35ms", logs_text)
            self.assertIn("queue(avg=", logs_text)
            self.assertIn("机房拦截 1", logs_text)

            with open(pr_csv, "r", encoding="utf-8-sig") as f:
                saved = list(csv.DictReader(f))
            # 73.0.0.10 住宅放行，54.1.2.11 机房被拦截踢出
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0]["host"], "73.0.0.10")
            self.assertIn("AS7922", saved[0]["asn"])


if __name__ == "__main__":
    unittest.main()
