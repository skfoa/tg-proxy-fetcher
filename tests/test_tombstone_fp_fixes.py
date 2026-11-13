import asyncio
import csv
import errno
import os
import socket
import ssl
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
