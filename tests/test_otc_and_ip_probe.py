import asyncio
import json
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import parsers
import providers


def extract_asn_num(asn_text: str) -> str:
    """提取 ASN 纯数字编号（去除 AS 前缀与前导零），用于规范等价比对。"""
    m = re.search(r"AS\s*0*(\d+)", str(asn_text or ""), re.IGNORECASE)
    return m.group(1) if m else ""


class _FakeUrllibResp:
    def __init__(self, payload: dict | list, headers: dict | None = None):
        self._body = json.dumps(payload).encode("utf-8")
        self.headers = headers or {}
        self.status = 200

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class TestOtcScanParsing(unittest.TestCase):
    def test_mode_a_unquoted_comma_isp_rejoin_and_corp_suffix_guard(self):
        text = (
            "103.231.57.14:8443,Singapore,AS4657,XYZ DIGITAL PTE., LTD.,SIN (新加坡),103.231.57.15,仅IPv4\n"
            "198.51.100.10:443,United States,AS139659,Alpha, Beta, LLC,SJC (美国),198.51.100.10,双栈\n"
        )
        fake_cache = {
            "103.231.57.14": {"asn": "AS979", "isp": "Some Entrance ISP", "net_type": "business", "country": "SG"},
            "103.231.57.15": {"asn": "AS4657", "isp": "XYZ DIGITAL PTE., LTD.", "net_type": "isp", "country": "SG"},
            "198.51.100.10": {"asn": "AS139659", "isp": "Alpha, Beta, LLC", "net_type": "isp", "country": "US"},
        }
        items = parsers.parse_otc_scan_content(text, ip_cache=fake_cache)
        self.assertEqual(len(items), 2)

        first = items[0]
        self.assertEqual(first["colo"], "SIN")
        self.assertEqual(first["cf_location"], "新加坡")
        self.assertNotIn("LTD", first["colo"])
        self.assertNotIn("LTD", first["cf_location"])
        self.assertEqual(first["exit_ip"], "103.231.57.15")
        self.assertEqual(extract_asn_num(first["exit_asn"]), "4657")
        self.assertEqual(first["exit_isp"], "XYZ DIGITAL PTE., LTD.")
        # 出入口分离时，入口归属独立取自入口 ip_cache
        self.assertEqual(extract_asn_num(first["raw_asn"]), "979")

        second = items[1]
        self.assertEqual(second["colo"], "SJC")
        self.assertEqual(second["cf_location"], "美国")
        self.assertEqual(second["exit_isp"], "Alpha, Beta, LLC")
        self.assertEqual(extract_asn_num(second["raw_asn"]), "139659")

    def test_mode_b_corp_suffix_not_treated_as_colo(self):
        text = "198.51.100.22:443,US,AS139659,ACME CLOUD,PTE,LLC,LTD,INC\n"
        fake_cache = {
            "198.51.100.22": {"asn": "AS139659", "isp": "ACME CLOUD", "net_type": "isp", "country": "US"},
        }
        items = parsers.parse_otc_scan_content(text, ip_cache=fake_cache)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["colo"], "")

    def test_exit_decoupling_and_fn_asn_hint_downgrade(self):
        # 1) 出入口不同且入口未缓存：入口 ASN 留空待后续增量反查，fn_asn 绝不填入口/出口
        # 2) 出入口相同（无独立出口）且缓存已有 AS4134 时，fn_asn AS216211 不覆盖冲突缓存
        # 3) 纯 IP 行无行内 ASN 且无缓存时，fn_asn AS216211 作为无冲突 hint 生效
        text = (
            "198.51.100.30:443,US,AS139659,ExitOrg,SJC (美国),203.0.113.40,IPv4\n"
            "198.51.100.31:443,12ms\n"
            "198.51.100.32:443,25ms\n"
        )
        fake_cache = {
            "203.0.113.40": {"asn": "AS139659", "isp": "ExitOrg", "net_type": "isp", "country": "US"},
            "198.51.100.31": {"asn": "AS4134", "isp": "Chinanet", "net_type": "isp", "country": "CN"},
        }
        items = parsers.parse_otc_scan_content(
            text,
            filename="OTC_SCAN_YX_AS216211.txt",
            ip_cache=fake_cache,
        )
        self.assertEqual(len(items), 3)

        uncached_ing, conflict_cached, uncached_single = items
        self.assertEqual(uncached_ing["raw_asn"], "")
        self.assertEqual(uncached_ing["asn"], "")
        self.assertEqual(extract_asn_num(uncached_ing["exit_asn"]), "139659")

        self.assertEqual(extract_asn_num(conflict_cached["raw_asn"]), "4134")
        self.assertNotEqual(extract_asn_num(conflict_cached["raw_asn"]), "216211")

        self.assertEqual(extract_asn_num(uncached_single["raw_asn"]), "216211")


class TestIpProbeProxyRotation(unittest.TestCase):
    def setUp(self):
        with providers._IP_PROBE_STATE_LOCK:
            providers._DEAD_IP_PROBE_PROXIES.clear()
            providers._LAST_ONLINE_COUNTRIES.clear()
        with providers._IPINFO_STATE_LOCK:
            self._saved_dead_ipinfo = set(providers._DEAD_IPINFO_PROXIES)

    def tearDown(self):
        with providers._IP_PROBE_STATE_LOCK:
            providers._DEAD_IP_PROBE_PROXIES.clear()
            providers._LAST_ONLINE_COUNTRIES.clear()
        with providers._IPINFO_STATE_LOCK:
            providers._DEAD_IPINFO_PROXIES.clear()
            providers._DEAD_IPINFO_PROXIES.update(self._saved_dead_ipinfo)

    def test_parse_curl_http_response_strips_connect_tunnel_and_extracts_headers(self):
        raw = (
            "HTTP/1.1 200 Connection established\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "X-Rl: 12\r\n"
            "X-Ttl: 48\r\n"
            "\r\n"
            '[{"status":"success","query":"1.1.1.1"}]\n__CURL_STATUS__:200\n'
        )
        status, headers, body = providers._parse_curl_http_response(raw)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-rl"), "12")
        self.assertEqual(headers.get("x-ttl"), "48")
        self.assertEqual(json.loads(body)[0]["query"], "1.1.1.1")

    def test_resolve_asn_online_rotates_proxy_marks_dead_isolated_and_captures_country(self):
        calls = []

        def _fake_fetch(url, proxy="", timeout=4.0, method="GET", data=None, headers=None, prefer_curl_direct=False):
            calls.append((url, proxy))
            if proxy == "http://bad-proxy:8080":
                return 429, {"x-rl": "0"}, "{}"
            if proxy == "http://good-proxy:8080":
                self.assertIn("countryCode", url)
                return 200, {}, json.dumps({
                    "status": "success",
                    "countryCode": "SG",
                    "as": "AS216211 Example Corp",
                    "isp": "Example Corp",
                })
            raise AssertionError(f"Unexpected fallback proxy: {proxy}")

        with patch("providers._fetch_url_via_proxy", side_effect=_fake_fetch):
            asn_code, isp_name = providers.resolve_asn_online(
                "198.51.100.77",
                proxy_candidates=["http://bad-proxy:8080", "http://good-proxy:8080"],
                start_offset=0,
            )

        self.assertEqual(extract_asn_num(asn_code), "216211")
        self.assertTrue(bool(isp_name))
        self.assertEqual(providers.pop_online_country("198.51.100.77"), "SG")
        self.assertEqual([p for _, p in calls], ["http://bad-proxy:8080", "http://good-proxy:8080"])
        self.assertIn("http://bad-proxy:8080", providers._DEAD_IP_PROBE_PROXIES)
        self.assertEqual(set(providers._DEAD_IPINFO_PROXIES), self._saved_dead_ipinfo)

    def test_direct_path_uses_urllib_urlopen_when_proxy_empty(self):
        def _fake_urlopen(req, timeout=3.5):
            self.assertIn("countryCode", req.full_url)
            return _FakeUrllibResp({
                "status": "success",
                "countryCode": "JP",
                "as": "AS2516 KDDI CORPORATION",
                "isp": "KDDI CORPORATION",
            })

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen) as mock_open:
            asn_code, _ = providers.resolve_asn_online("198.51.100.88", proxy_candidates=[], start_offset=0)

        mock_open.assert_called_once()
        self.assertEqual(extract_asn_num(asn_code), "2516")
        self.assertEqual(providers.pop_online_country("198.51.100.88"), "JP")

    def test_batch_online_rotates_on_xrl_without_sleep_and_populates_fallback_country(self):
        sleep_calls = []
        batch_proxies = []

        def _fake_fetch(url, proxy="", timeout=4.0, method="GET", data=None, headers=None, prefer_curl_direct=False):
            if url.endswith("/batch"):
                batch_proxies.append(proxy)
                payload = json.loads(data.decode("utf-8"))
                q_ips = [entry["query"] for entry in payload]
                if q_ips == ["8.8.4.4"]:
                    # 第1批故意只回成功0条，触发单点并发兜底，同时 X-Rl=0 验证切代理免 sleep
                    return 200, {"x-rl": "0", "x-ttl": "30"}, json.dumps([{"query": "8.8.4.4", "status": "fail"}])
                return 200, {"x-rl": "10", "x-ttl": "30"}, json.dumps([
                    {
                        "query": "9.9.9.9",
                        "status": "success",
                        "countryCode": "DE",
                        "as": "AS24940 Hetzner Online GmbH",
                        "isp": "Hetzner Online GmbH",
                    }
                ])
            # 单点兜底路径
            return 200, {}, json.dumps({
                "status": "success",
                "countryCode": "US",
                "as": "AS15169 Google LLC",
                "isp": "Google LLC",
            })

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cache_path = os.path.join(tmpdir, "ip_cache.json")
            with open(tmp_cache_path, "w", encoding="utf-8") as f:
                json.dump({}, f)

            with patch("providers._fetch_url_via_proxy", side_effect=_fake_fetch), \
                 patch("providers.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                res = asyncio.run(
                    providers.resolve_asn_batch_online_async(
                        ["8.8.4.4", "9.9.9.9"],
                        max_chunk_size=1,
                        persist=True,
                        cache_path=tmp_cache_path,
                        proxy_candidates=["http://p1:8080", "http://p2:8080"],
                        start_offset=0,
                    )
                )

            with open(tmp_cache_path, "r", encoding="utf-8") as f:
                saved_cache = json.load(f)

        self.assertEqual(sleep_calls, [])
        self.assertEqual(len(batch_proxies), 2)
        self.assertNotEqual(batch_proxies[0], batch_proxies[1])
        self.assertEqual(extract_asn_num(res["8.8.4.4"][0]), "15169")
        self.assertEqual(extract_asn_num(res["9.9.9.9"][0]), "24940")
        self.assertEqual(saved_cache["8.8.4.4"]["country"], "US")
        self.assertEqual(saved_cache["9.9.9.9"]["country"], "DE")


if __name__ == "__main__":
    unittest.main()
