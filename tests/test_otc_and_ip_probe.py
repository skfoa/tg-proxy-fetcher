import asyncio
import contextlib
import csv
import json
import os
import re
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import cf_verify
import parsers
import providers
import proxyip_verify
import tg_fetch


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
        # 1) 出入口不同且入口未缓存：入口 ASN 留空待后续增量反查，fn_asn 绝不填入口/出口/hint
        # 2) 出入口相同（无独立出口）且缓存已有 AS4134 时，fn_asn AS216211 不覆盖冲突缓存且不生成 hint
        # 3) 纯 IP 行无行内 ASN 且无缓存时，fn_asn AS216211 仅降级存入 asn_hint，解析期不预填 raw_asn/asn
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
        self.assertEqual(uncached_ing.get("asn_hint", ""), "")
        self.assertEqual(extract_asn_num(uncached_ing["exit_asn"]), "139659")

        self.assertEqual(extract_asn_num(conflict_cached["raw_asn"]), "4134")
        self.assertNotEqual(extract_asn_num(conflict_cached["raw_asn"]), "216211")
        self.assertEqual(conflict_cached.get("asn_hint", ""), "")

        self.assertEqual(uncached_single["raw_asn"], "")
        self.assertEqual(uncached_single["asn"], "")
        self.assertEqual(uncached_single.get("asn_hint"), "AS216211")


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


@contextlib.contextmanager
def _isolated_tg_fetch_dir(tmpdir: str):
    """将 tg_fetch 全量路径常量与副作用隔离到临时目录，杜绝测试污染真实 data/ 或发送网络通知。"""
    stack = contextlib.ExitStack()
    try:
        stack.enter_context(patch.object(tg_fetch, "DATA_DIR", tmpdir))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXY_FILE", os.path.join(tmpdir, "proxies.txt")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXIES_CSV", os.path.join(tmpdir, "proxies.csv")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXIES_DIR", os.path.join(tmpdir, "proxies")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_CF_FILE", os.path.join(tmpdir, "cf_ips.csv")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_CF_TXT", os.path.join(tmpdir, "cf_ips.txt")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_SCAN_FILE", os.path.join(tmpdir, "scan_ips.csv")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_SCAN_TXT", os.path.join(tmpdir, "scan_ips.txt")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_SCAN_DIR", os.path.join(tmpdir, "scan_ips")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXYIP_FILE", os.path.join(tmpdir, "proxyip.csv")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXYIP_TXT", os.path.join(tmpdir, "proxyip.txt")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXYIP_JSON", os.path.join(tmpdir, "proxyip.json")))
        stack.enter_context(patch.object(tg_fetch, "OUTPUT_PROXYIP_DIR", os.path.join(tmpdir, "proxyip")))
        stack.enter_context(patch("tg_fetch.send_tg_message"))
        yield stack
    finally:
        stack.close()


def _read_csv_rows(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


class TestFnHintAndAuthoritativeCacheOverride(unittest.TestCase):
    def test_csv_fn_asn_and_cloud_filename_downgraded_and_cache_overrides_non_cf_mislabel(self):
        fake_cache = {
            "45.33.10.2": {"asn": "AS45102", "isp": "Alibaba", "net_type": "datacenter", "country": "SG"},
            "myproxy.example.com": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
        }

        # 1) 无表头 CSV + 云厂商文件名 Aliyun.csv：未缓存 IP 不预填 raw_asn/asn/isp，仅存入 asn_hint/isp_hint
        headerless_rows = parsers.parse_cf_csv_content(
            "45.33.10.1,443,15ms\n45.33.10.2,8443,20ms\n",
            filename="Aliyun.csv",
            default_channel="@danfeng_chat",
            ip_cache=fake_cache,
        )
        self.assertEqual(len(headerless_rows), 2)
        uncached_h, cached_h = headerless_rows
        self.assertEqual(uncached_h["raw_asn"], "")
        self.assertEqual(uncached_h["asn"], "")
        self.assertEqual(uncached_h["isp"], "")
        self.assertEqual(uncached_h.get("asn_hint"), "AS45102")
        self.assertEqual(uncached_h.get("isp_hint"), "Alibaba Cloud")
        self.assertEqual(extract_asn_num(cached_h["raw_asn"]), "45102")
        self.assertEqual(cached_h.get("asn_hint", ""), "")

        # 2) 有表头 DanFeng CSV：行内非 CF 错标 AS24940 必须被缓存 AS45102 压过；未缓存行不吃文件名 AS132203；域名大小写回退命中
        dict_csv = (
            "IP,Port,ASN,ISP\n"
            "45.33.10.1,443,,\n"
            "45.33.10.2,443,AS24940,Hetzner Online GmbH\n"
            "MyProxy.Example.COM,443,AS24940,Hetzner Online GmbH\n"
        )
        dict_rows = parsers.parse_cf_csv_content(
            dict_csv,
            filename="AS132203_Tencent_20260906_190653.csv",
            default_channel="@danfeng_chat",
            ip_cache=fake_cache,
        )
        self.assertEqual(len(dict_rows), 3)
        uncached_d, mislabeled_d, mixed_dom_d = dict_rows
        self.assertEqual(uncached_d["raw_asn"], "")
        self.assertEqual(uncached_d["asn"], "")
        self.assertEqual(uncached_d.get("asn_hint"), "AS132203")
        self.assertEqual(extract_asn_num(mislabeled_d["raw_asn"]), "45102")
        self.assertEqual(extract_asn_num(mixed_dom_d["raw_asn"]), "4766")

    def test_save_paths_enforce_authoritative_ip_cache_and_preserve_as_unknown_sentinel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "ip_cache.json")
            cache_data = {
                "45.33.20.1": {"asn": "AS45102", "isp": "Alibaba", "net_type": "datacenter", "country": "SG"},
                "45.33.20.2": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
                "host.example.com": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            }
            providers.save_ip_cache(cache_data, filepath=cache_path)

            # A. tg_fetch.save_and_notify 三条 CSV（cf_ips / scan_ips / proxyip）
            final_cf = {
                "45.33.20.1:443": {
                    "ip": "45.33.20.1", "port": "443", "tls": "true",
                    "asn": "AS24940 (Hetzner)", "isp": "Hetzner", "first_seen": "2026-09-01 00:00:00",
                },
            }
            final_scan = {
                "45.33.20.1:8443": {
                    "ip": "45.33.20.1", "port": "8443", "tls": "true",
                    "asn": "AS24940 (Hetzner)", "isp": "Hetzner", "first_seen": "2026-09-01 00:00:00",
                },
                "45.33.20.99:443": {
                    "ip": "45.33.20.99", "port": "443", "tls": "true",
                    "asn": "", "isp": "", "first_seen": "2026-09-01 00:00:00",
                },
            }
            final_proxyip = {
                "Host.Example.COM:443": {
                    "ip": "Host.Example.COM", "port": "443", "tls": "true",
                    "asn": "AS24940 (Hetzner)", "isp": "Hetzner", "first_seen": "2026-09-01 00:00:00",
                },
            }

            with _isolated_tg_fetch_dir(tmpdir):
                tg_fetch.save_and_notify(
                    final_proxies={},
                    final_cf_ips=final_cf,
                    final_scan_ips=final_scan,
                    final_proxyips=final_proxyip,
                )
                cf_saved = _read_csv_rows(tg_fetch.OUTPUT_CF_FILE)
                scan_saved = {r["ip"]: r for r in _read_csv_rows(tg_fetch.OUTPUT_SCAN_FILE)}
                proxyip_saved = _read_csv_rows(tg_fetch.OUTPUT_PROXYIP_FILE)

            self.assertEqual(extract_asn_num(cf_saved[0]["asn"]), "45102")
            self.assertEqual(extract_asn_num(scan_saved["45.33.20.1"]["asn"]), "45102")
            self.assertEqual(scan_saved["45.33.20.99"]["asn"], "AS_UNKNOWN")
            self.assertEqual(extract_asn_num(proxyip_saved[0]["asn"]), "4766")

            # B. proxyip_verify.save_proxyip：写入前纠偏非 CF 错标，且先于 exit/net_type 解析
            pv_csv = os.path.join(tmpdir, "pv.csv")
            pv_txt = os.path.join(tmpdir, "pv.txt")
            pv_dir = os.path.join(tmpdir, "pv_dir")
            pv_json = os.path.join(tmpdir, "pv.json")
            with patch.object(proxyip_verify, "DATA_DIR", tmpdir):
                proxyip_verify.save_proxyip(
                    [{
                        "ip": "45.33.20.2", "port": "443", "tls": "true",
                        "asn": "AS24940 (Hetzner)", "isp": "Hetzner",
                        "net_type": "datacenter", "fail_count": 0,
                        "first_seen": "2026-09-01 00:00:00",
                    }],
                    csv_path=pv_csv,
                    txt_path=pv_txt,
                    dir_path=pv_dir,
                    json_path=pv_json,
                )
            pv_rows = _read_csv_rows(pv_csv)
            self.assertEqual(extract_asn_num(pv_rows[0]["asn"]), "4766")
            self.assertEqual(pv_rows[0]["net_type"], "isp")

            # C. cf_verify._save_scan_track：对 AS_UNKNOWN 与非 CF 错标都能用缓存覆写，未缓存保留 AS_UNKNOWN 哨兵
            cfv_cf_csv = os.path.join(tmpdir, "cfv_cf.csv")
            cfv_scan_csv = os.path.join(tmpdir, "cfv_scan.csv")
            cfv_scan_txt = os.path.join(tmpdir, "cfv_scan.txt")
            cfv_scan_dir = os.path.join(tmpdir, "cfv_scan_dir")
            os.makedirs(cfv_scan_dir, exist_ok=True)
            for p, fields, rows in [
                (
                    cfv_cf_csv,
                    providers.CF_BASE_CSV_FIELDS,
                    [{"ip": "45.33.20.1", "port": "443", "asn": "AS24940 (Hetzner)", "isp": "Hetzner"}],
                ),
                (
                    cfv_scan_csv,
                    providers.SCAN_CSV_FIELDS,
                    [
                        {"ip": "45.33.20.1", "port": "443", "asn": "AS24940 (Hetzner)", "isp": "Hetzner"},
                        {"ip": "45.33.20.2", "port": "443", "asn": "AS_UNKNOWN", "isp": ""},
                        {"ip": "45.33.20.99", "port": "443", "asn": "AS_UNKNOWN", "isp": ""},
                    ],
                ),
            ]:
                with open(p, "w", encoding="utf-8-sig", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                    w.writeheader()
                    for r in rows:
                        w.writerow(r)

            async def _fake_verify_all(rows, **kwargs):
                for r in rows:
                    r["fail_count"] = 0
                    r["_invalid"] = False

            args = SimpleNamespace(
                concurrency=4, max_fails=3, timeout=1.0, http_timeout=1.0,
                no_notify=True, dry_run=False, diag_output="",
                check_endpoint="", check_token="", check_concurrency=2,
                no_enrich_exits=True,
            )
            with patch.object(cf_verify, "DATA_DIR", tmpdir), \
                 patch.object(cf_verify, "CF_CSV", cfv_cf_csv), \
                 patch.object(cf_verify, "CF_TXT", os.path.join(tmpdir, "cfv_cf.txt")), \
                 patch.object(cf_verify, "SCAN_CSV", cfv_scan_csv), \
                 patch.object(cf_verify, "SCAN_TXT", cfv_scan_txt), \
                 patch.object(cf_verify, "SCAN_DIR", cfv_scan_dir), \
                 patch("cf_verify.verify_all", side_effect=_fake_verify_all), \
                 patch("cf_verify.rescue_mislabeled_cloudflare_rows", return_value=(cache_data, 0)), \
                 patch("cf_verify.calibrate_all_datasets", return_value={}), \
                 patch("cf_verify.load_tombstone", return_value={}), \
                 patch("cf_verify.record_tombstone"):
                asyncio.run(cf_verify.async_main(args))

            cfv_cf_saved = _read_csv_rows(cfv_cf_csv)
            cfv_saved = {r["ip"]: r for r in _read_csv_rows(cfv_scan_csv)}
            self.assertEqual(extract_asn_num(cfv_cf_saved[0]["asn"]), "45102")
            self.assertEqual(extract_asn_num(cfv_saved["45.33.20.1"]["asn"]), "45102")
            self.assertEqual(extract_asn_num(cfv_saved["45.33.20.2"]["asn"]), "4766")
            self.assertEqual(cfv_saved["45.33.20.99"]["asn"], "AS_UNKNOWN")

            # D. calibrate_all_datasets：补写一个非 CF 错标 scan 行后也能校准
            cal_scan_csv = os.path.join(tmpdir, "cal_scan.csv")
            with open(cal_scan_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.SCAN_CSV_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerow({"ip": "45.33.20.1", "port": "443", "asn": "AS24940 (Hetzner)", "isp": "Hetzner"})
                w.writerow({"ip": "45.33.20.99", "port": "443", "asn": "AS_UNKNOWN", "isp": ""})
            providers.calibrate_all_datasets(
                proxies_dir="", proxies_csv_path="", proxyip_csv_path="", proxyip_dir="",
                ip_cache_path=cache_path, scan_csv_path=cal_scan_csv,
                scan_txt_path="", scan_dir_path="",
            )
            cal_saved = {r["ip"]: r for r in _read_csv_rows(cal_scan_csv)}
            self.assertEqual(extract_asn_num(cal_saved["45.33.20.1"]["asn"]), "45102")
            self.assertEqual(cal_saved["45.33.20.99"]["asn"], "AS_UNKNOWN")


class TestTargetedAsnProbeEngine(unittest.TestCase):
    def setUp(self):
        tg_fetch._reset_asn_probe_budget()

    def tearDown(self):
        tg_fetch._reset_asn_probe_budget()

    def test_priority_order_failed_last_public_ip_filter_and_session_dedup(self):
        ip_cache = {
            # 曾失败过的 P3 IP：必须排在同一层级 P3 内无失败记录 IP 之后
            "45.33.30.32": {"asn": "", "probe_failed_at": 1700000000},
        }
        newly = [
            # P1: 新抓取无 ASN（非白名单频道，含合法 exit_ip 同样缺 ASN）；外加域名和 TEST-NET/私网噪声必须跳过
            {"ip": "45.33.30.10", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@other_chan", "exit_ip": "45.33.30.11", "exit_asn": ""},
            {"ip": "cf-anycast.example.com", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@other_chan"},
            {"ip": "198.51.100.5", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@other_chan"},
            {"ip": "10.0.0.1", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@other_chan"},
            # P2: 新抓取白名单频道有标未缓存
            {"ip": "45.33.30.20", "port": "443", "asn": "AS24940 (Hetzner)", "raw_asn": "AS24940", "isp": "Hetzner", "channel": "@otcjlq"},
            # 非白名单且已有标：绝不进 P2
            {"ip": "45.33.30.90", "port": "443", "asn": "AS24940 (Hetzner)", "raw_asn": "AS24940", "isp": "Hetzner", "channel": "@other_chan"},
        ]
        existing = [
            # P3 failed first in input order, fresh second -> sorting must put 45.33.30.31 before 45.33.30.32
            {"ip": "45.33.30.32", "port": "443", "asn": "AS_UNKNOWN", "isp": "", "channel": "@other_chan"},
            {"ip": "45.33.30.31", "port": "443", "asn": "AS_UNKNOWN", "isp": "", "channel": "@other_chan"},
            # P4: 历史白名单频道有标未缓存
            {"ip": "45.33.30.40", "port": "443", "asn": "AS24940 (Hetzner)", "raw_asn": "AS24940", "isp": "Hetzner", "channel": "@danfeng2"},
        ]

        queried_batches: list[list[str]] = []

        def _fake_resolve(targets, persist=True, cache_path="", **kwargs):
            queried_batches.append(list(targets))
            res = {}
            for ip in targets:
                if ip == "45.33.30.20":
                    # 故意让白名单 P2 失败，验证既不抹掉既有标签，也不在本轮二次重复探测
                    continue
                res[ip] = ("AS45102", "Alibaba")
            return res

        with patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_resolve):
            dirty, resolved = tg_fetch._targeted_asn_probe(
                newly,
                ip_cache,
                existing_rows=existing,
                persist=False,
                apply_hints=True,
            )
            # 同轮二次调用：45.33.30.20 已在 _SESSION_FAILED_IPS 中，绝不再触发网络查询
            tg_fetch._targeted_asn_probe(
                newly,
                ip_cache,
                existing_rows=existing,
                persist=False,
                apply_hints=True,
            )

        self.assertTrue(dirty)
        self.assertEqual(len(queried_batches), 1)
        self.assertEqual(
            queried_batches[0],
            ["45.33.30.10", "45.33.30.11", "45.33.30.20", "45.33.30.31", "45.33.30.32", "45.33.30.40"],
        )
        # 白名单 45.33.30.20 探测失败：保留原 AS24940 标签并写入负缓存时间戳
        self.assertEqual(extract_asn_num(newly[4]["raw_asn"]), "24940")
        self.assertEqual(ip_cache["45.33.30.20"]["asn"], "")
        self.assertIsInstance(ip_cache["45.33.30.20"]["probe_failed_at"], int)
        self.assertEqual(extract_asn_num(resolved["45.33.30.10"][0]), "45102")

    def test_hint_fallback_only_after_probe_failure_or_budget_zero(self):
        ip_cache: dict[str, dict] = {}
        rows = [
            {"ip": "45.33.31.1", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat", "asn_hint": "AS45102", "isp_hint": "Alibaba"},
            {"ip": "45.33.31.2", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat", "asn_hint": "AS45102", "isp_hint": "Alibaba"},
            {"ip": "45.33.31.3", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat", "asn_hint": "AS45102", "isp_hint": "Alibaba"},
            {"ip": "45.33.31.4", "port": "443", "asn": "", "raw_asn": "", "isp": "", "exit_ip": "45.33.31.9", "exit_asn": "AS139659", "channel": "@otcjlq"},
        ]

        tg_fetch._reset_asn_probe_budget(2)

        def _fake_resolve(targets, **kwargs):
            # IP-1 成功返回 AS132203；IP-2 失败；IP-3 超出预算不被查询
            return {"45.33.31.1": ("AS132203", "Tencent")}

        queried: list[list[str]] = []
        with patch("tg_fetch.resolve_asn_batch_online", side_effect=lambda t, **kw: (queried.append(list(t)), _fake_resolve(t, **kw))[1]):
            tg_fetch._targeted_asn_probe(rows, ip_cache, persist=False, apply_hints=True)

        self.assertEqual(len(queried), 1)
        self.assertEqual(len(queried[0]), 2)
        # IP-1 实测覆盖 hint
        self.assertEqual(extract_asn_num(rows[0]["raw_asn"]), "132203")
        # IP-2 探测失败后消费 hint
        self.assertEqual(extract_asn_num(rows[1]["raw_asn"]), "45102")
        # IP-3 预算耗尽后消费 hint
        self.assertEqual(extract_asn_num(rows[2]["raw_asn"]), "45102")
        # 预算耗尽后再调用一次：剩余 0 预算，零网络请求
        with patch("tg_fetch.resolve_asn_batch_online", side_effect=AssertionError("budget=0 must not trigger network")):
            tg_fetch._targeted_asn_probe(
                [{"ip": "45.33.31.5", "port": "443", "asn": "", "raw_asn": "", "isp": "", "asn_hint": "AS216211"}],
                ip_cache,
                persist=False,
                apply_hints=True,
            )

    def test_merge_and_save_flushes_ip_cache_and_collects_newly_discovered_unrecorded_asns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cache_path = os.path.join(tmpdir, "ip_cache.json")
            # 历史缓存里带有 probe_failed_at（探测成功后合并时应清除该过时字段）
            providers.save_ip_cache(
                {"45.33.40.2": {"asn": "", "probe_failed_at": 1700000000}},
                filepath=tmp_cache_path,
            )

            existing_scan = {
                "45.33.40.2:443": {
                    "ip": "45.33.40.2", "port": "443", "tls": "true",
                    "asn": "AS_UNKNOWN", "isp": "", "channel": "@other_chan",
                    "first_seen": "2026-09-01 00:00:00",
                },
            }
            scraped_scan = {
                "45.33.40.1:443": {
                    "ip": "45.33.40.1", "port": "443", "tls": "true",
                    "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat",
                    "first_seen": "2026-09-02 00:00:00",
                },
            }

            captured_enriched: list[dict] = []
            saved_cache_calls: list[str] = []
            orig_tg_save_cache = tg_fetch.save_ip_cache

            def _spy_tg_save_cache(cache, filepath="", compact=True):
                saved_cache_calls.append(filepath)
                return orig_tg_save_cache(cache, filepath=filepath, compact=compact)

            def _fake_resolve(targets, **kwargs):
                res = {}
                for t in targets:
                    if t == "45.33.40.1":
                        res[t] = ("AS45102", "Alibaba")
                    elif t == "45.33.40.2":
                        res[t] = ("AS219393", "UnrecordedNewNet")
                return res

            with _isolated_tg_fetch_dir(tmpdir), \
                 patch("tg_fetch.load_tombstone", return_value={}), \
                 patch("tg_fetch.auto_enrich_and_save_asns", side_effect=lambda items, **kw: (captured_enriched.extend(items), 0)[1]), \
                 patch("tg_fetch.get_session_enriched_asns", return_value=[]), \
                 patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_resolve), \
                 patch("providers.resolve_asn_batch_online", side_effect=_fake_resolve), \
                 patch("tg_fetch.save_ip_cache", side_effect=_spy_tg_save_cache), \
                 patch("tg_fetch.save_and_notify"):
                tg_fetch.merge_and_save(
                    existing_proxies={},
                    scraped_proxies={},
                    existing_cf_ips={},
                    scraped_cf_ips={},
                    existing_scan_ips=existing_scan,
                    scraped_scan_ips=scraped_scan,
                    existing_proxyips={},
                    scraped_proxyips={},
                    edt_unrecorded_asns=[],
                )

            disk_after = providers.load_ip_cache(filepath=tmp_cache_path)
            self.assertGreaterEqual(len(saved_cache_calls), 1)
            self.assertEqual(extract_asn_num(disk_after["45.33.40.1"]["asn"]), "45102")
            self.assertEqual(extract_asn_num(disk_after["45.33.40.2"]["asn"]), "219393")
            self.assertNotIn("probe_failed_at", disk_after["45.33.40.2"])
            enriched_codes = {item.get("asn") for item in captured_enriched}
            self.assertIn("AS219393", enriched_codes)

    def test_recent_probe_failure_cooldown_skipped_and_expired_retried(self):
        now_ts = int(time.time())
        ip_cache = {
            "45.33.50.1": {"asn": "", "probe_failed_at": now_ts - 86400},
            "45.33.50.2": {"asn": "", "probe_failed_at": now_ts - 8 * 86400},
            "45.33.50.3": {"asn": "", "probe_failed_at": now_ts - 2 * 86400},
            "45.33.50.4": {"asn": "", "probe_failed_at": now_ts - 3 * 86400},
        }
        newly = [
            {
                "ip": "45.33.50.1", "port": "443", "asn": "", "raw_asn": "", "isp": "",
                "channel": "@danfeng_chat", "asn_hint": "AS45102", "isp_hint": "Alibaba",
            },
            {
                "ip": "45.33.50.3", "port": "443", "asn": "", "raw_asn": "", "isp": "",
                "channel": "@other_chan",
            },
        ]
        existing = [
            {
                "ip": "45.33.50.2", "port": "443", "asn": "AS_UNKNOWN", "isp": "",
                "channel": "@other_chan", "exit_ip": "45.33.50.4", "exit_asn": "",
            },
        ]
        queried: list[list[str]] = []

        def _fake_resolve(targets, **kwargs):
            queried.append(list(targets))
            return {t: ("AS132203", "Tencent") for t in targets}

        with patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_resolve):
            tg_fetch._targeted_asn_probe(
                newly,
                ip_cache,
                existing_rows=existing,
                persist=False,
                apply_hints=True,
            )

        self.assertEqual(queried, [["45.33.50.2"]])
        # 冷却期内被跳过的新抓行仍按兜底逻辑保留/消费 asn_hint，无 hint 则维持空串不强填
        self.assertEqual(extract_asn_num(newly[0]["raw_asn"]), "45102")
        self.assertEqual(newly[1]["raw_asn"], "")
        # 过期失败项复查成功后写回有效 ASN
        self.assertEqual(extract_asn_num(existing[0]["asn"]), "132203")
        # 冷却期内的 exit_ip 未被探测且仍保持空 exit_asn
        self.assertEqual(existing[0]["exit_asn"], "")

    def test_p1_budget_isolated_from_whitelist_and_historical_pool(self):
        tg_fetch._reset_asn_probe_budget(limit=2, p1_limit=2)
        ip_cache: dict[str, dict] = {}
        attachment_rows = [
            {"ip": "45.33.60.1", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat"},
            {"ip": "45.33.60.2", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat"},
            {"ip": "45.33.60.3", "port": "443", "asn": "", "raw_asn": "", "isp": "", "channel": "@danfeng_chat"},
            {"ip": "45.33.60.10", "port": "443", "asn": "AS24940 (Hetzner)", "raw_asn": "AS24940", "isp": "Hetzner", "channel": "@danfeng_chat"},
        ]
        merge_new = [
            {"ip": "45.33.60.11", "port": "443", "asn": "AS24940 (Hetzner)", "raw_asn": "AS24940", "isp": "Hetzner", "channel": "@otcjlq"},
        ]
        merge_existing = [
            {"ip": "45.33.60.20", "port": "443", "asn": "AS_UNKNOWN", "isp": "", "channel": "@other_chan"},
            {"ip": "45.33.60.30", "port": "443", "asn": "AS24940 (Hetzner)", "isp": "Hetzner", "channel": "@otcjlq"},
        ]
        queried: list[list[str]] = []

        def _fake_resolve(targets, **kwargs):
            queried.append(list(targets))
            return {t: ("AS45102", "Alibaba") for t in targets}

        with patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_resolve):
            tg_fetch._targeted_asn_probe(
                attachment_rows,
                ip_cache,
                persist=False,
                apply_hints=True,
                include_whitelist=False,
            )
            tg_fetch._targeted_asn_probe(
                merge_new,
                ip_cache,
                existing_rows=merge_existing,
                persist=False,
                apply_hints=True,
                include_whitelist=True,
            )

        self.assertEqual(queried[0], ["45.33.60.1", "45.33.60.2"])
        self.assertEqual(queried[1], ["45.33.60.11", "45.33.60.20"])

    def test_apply_authoritative_ip_cache_overrides_exit_asn_and_calibrates_cf_ips(self):
        cache = {
            "212.135.215.10": {"asn": "AS216211", "isp": "Cyberverse", "net_type": "datacenter", "country": "JP"},
            "2403:27c0:c03:1::2e": {"asn": "AS4515", "isp": "PCCW", "net_type": "isp", "country": "HK"},
            "61.172.182.19": {"asn": "AS4811", "isp": "China Telecom", "net_type": "isp", "country": "CN"},
            "154.36.136.50": {"asn": "AS979", "isp": "NetLab", "net_type": "isp", "country": "US"},
            "154.36.136.99": {"asn": "AS16276", "isp": "OVH", "net_type": "datacenter", "country": "FR"},
            "2a09:bac5:661b:28::4:35e": {"asn": "AS13335", "isp": "Cloudflare", "net_type": "datacenter", "country": "US"},
        }
        cf_warp_row = {
            "ip": "212.135.215.10",
            "asn": "AS13335 Cloudflare",
            "isp": "Cloudflare",
            "exit_ip": "2a09:bac5::1",
            "exit_ipv6": "2a09:bac5::1",
            "exit_asn": "AS13335 Cloudflare",
            "exit_isp": "Cloudflare",
        }
        changed, _ = providers.apply_authoritative_ip_cache(cf_warp_row, "212.135.215.10", cache)
        self.assertTrue(changed)
        self.assertEqual(extract_asn_num(cf_warp_row["asn"]), "216211")
        self.assertEqual(extract_asn_num(cf_warp_row["exit_asn"]), "13335")

        cf_exit_healed = {
            "ip": "23.83.226.116",
            "asn": "AS25820 BandwagonHost",
            "isp": "BandwagonHost",
            "exit_ip": "2a09:bac5:661b:28::4:35e",
            "exit_asn": "AS25820 BandwagonHost",
            "exit_isp": "BandwagonHost",
        }
        changed_cf_exit, _ = providers.apply_authoritative_ip_cache(cf_exit_healed, "23.83.226.116", cache)
        self.assertTrue(changed_cf_exit)
        self.assertEqual(extract_asn_num(cf_exit_healed["exit_asn"]), "13335")

        with tempfile.TemporaryDirectory() as tmpdir:
            ip_cache_path = os.path.join(tmpdir, "ip_cache.json")
            cf_csv = os.path.join(tmpdir, "cf_ips.csv")
            cf_txt = os.path.join(tmpdir, "cf_ips.txt")
            scan_csv = os.path.join(tmpdir, "scan_ips.csv")
            scan_txt = os.path.join(tmpdir, "scan_ips.txt")
            scan_dir = os.path.join(tmpdir, "scan_ips")
            proxyip_csv = os.path.join(tmpdir, "proxyip.csv")
            proxyip_txt = os.path.join(tmpdir, "proxyip.txt")
            proxyip_json = os.path.join(tmpdir, "proxyip.json")
            proxyip_dir = os.path.join(tmpdir, "proxyip")
            proxies_csv = os.path.join(tmpdir, "proxies.csv")
            proxies_txt = os.path.join(tmpdir, "proxies.txt")
            proxies_dir = os.path.join(tmpdir, "proxies")

            providers.save_ip_cache(cache, filepath=ip_cache_path)
            with open(cf_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.CF_BASE_CSV_FIELDS)
                w.writeheader()
                w.writerow({"ip": "61.172.182.19", "port": "443", "tls": "true", "asn": "AS21859 Zenlayer", "isp": "Zenlayer", "channel": "@otcfxq"})
            with open(scan_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.SCAN_CSV_FIELDS)
                w.writeheader()
                w.writerow({
                    "ip": "212.135.215.10", "port": "443", "tls": "true",
                    "asn": "AS216211 Cyberverse", "isp": "Cyberverse",
                    "exit_ip": "2403:27c0:c03:1::2e", "exit_asn": "AS137897 Wrong", "exit_isp": "Wrong",
                    "channel": "@otcjlq",
                })
            with open(proxyip_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.PROXYIP_CSV_FIELDS)
                w.writeheader()
                w.writerow({
                    "ip": "154.36.136.50", "port": "443", "tls": "true",
                    "asn": "AS174 Cogent", "isp": "Cogent", "net_type": "isp",
                    "exit_ip": "154.36.136.99", "exit_asn": "AS979 NetLab", "exit_isp": "NetLab",
                    "channel": "@otcjlq",
                })

            with patch("providers.load_tombstone", return_value={}), \
                 patch("providers.prune_tombstone", return_value=0), \
                 patch("providers.prune_ip_cache", return_value=0):
                providers.calibrate_all_datasets(
                    proxies_dir=proxies_dir,
                    proxies_csv_path=proxies_csv,
                    proxies_txt_path=proxies_txt,
                    proxyip_csv_path=proxyip_csv,
                    proxyip_dir=proxyip_dir,
                    ip_cache_path=ip_cache_path,
                    proxyip_txt_path=proxyip_txt,
                    proxyip_json_path=proxyip_json,
                    scan_csv_path=scan_csv,
                    scan_txt_path=scan_txt,
                    scan_dir_path=scan_dir,
                    cf_csv_path=cf_csv,
                    cf_txt_path=cf_txt,
                )

            with open(cf_csv, "r", encoding="utf-8-sig") as f:
                cf_rows = list(csv.DictReader(f))
            with open(scan_csv, "r", encoding="utf-8-sig") as f:
                scan_rows = {r["ip"]: r for r in csv.DictReader(f)}
            with open(proxyip_csv, "r", encoding="utf-8-sig") as f:
                proxy_rows = list(csv.DictReader(f))

            self.assertEqual(extract_asn_num(cf_rows[0]["asn"]), "4811")
            self.assertEqual(extract_asn_num(scan_rows["212.135.215.10"]["exit_asn"]), "4515")
            # 154.36.136.50 修正出口 exit_ip=154.36.136.99 (AS16276 datacenter) 后被降级移入 scan_ips
            self.assertEqual(proxy_rows, [])
            self.assertIn("154.36.136.50", scan_rows)
            self.assertEqual(extract_asn_num(scan_rows["154.36.136.50"]["asn"]), "979")
            self.assertEqual(extract_asn_num(scan_rows["154.36.136.50"]["exit_asn"]), "16276")

    def test_manual_datacenter_overrides_and_separate_exit_profile_guards(self):
        # 1. 已确证 IDC/Hosting ASN 必须稳定归类为 datacenter
        for dc_asn in ("AS206069", "AS134823", "AS131151", "AS38042"):
            self.assertEqual(providers.classify_asn(dc_asn), "datacenter", f"{dc_asn} must be datacenter")
        self.assertIn("@cmliussss_all", tg_fetch.VERIFY_LABELED_CHANNELS)

        # 2. 双跳异址时 _has_complete_profile 不得被入口 ASN 掩盖，且旧版 15 列迁移不复制入口 ASN 到异址出口
        self.assertFalse(
            proxyip_verify._has_complete_profile(
                {
                    "ip": "64.90.21.49",
                    "port": "52840",
                    "asn": "AS979 NetLab",
                    "isp": "NetLab",
                    "exit_ip": "103.117.151.225",
                    "exit_ipv6": "",
                    "exit_asn": "",
                    "exit_isp": "",
                },
                ip_cache={},
            )
        )
        self.assertTrue(
            proxyip_verify._has_complete_profile(
                {
                    "ip": "64.90.21.49",
                    "port": "52840",
                    "asn": "AS979 NetLab",
                    "isp": "NetLab",
                    "exit_ip": "103.117.151.225",
                    "exit_ipv6": "",
                    "exit_asn": "",
                    "exit_isp": "",
                },
                ip_cache={"103.117.151.225": {"asn": "AS56309", "isp": "ReadyIDC", "net_type": "datacenter"}},
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_csv = os.path.join(tmpdir, "legacy_proxyip.csv")
            legacy_fields = [c for c in proxyip_verify.CSV_FIELDS if c not in ("exit_asn", "exit_isp")]
            with open(legacy_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=legacy_fields)
                w.writeheader()
                w.writerow({
                    "ip": "64.90.21.49", "port": "52840", "tls": "true",
                    "asn": "AS979 NetLab", "isp": "NetLab", "net_type": "business",
                    "exit_ip": "103.117.151.225", "exit_ipv6": "",
                })
                w.writerow({
                    "ip": "198.51.100.10", "port": "443", "tls": "true",
                    "asn": "AS979 NetLab", "isp": "NetLab", "net_type": "business",
                    "exit_ip": "198.51.100.10", "exit_ipv6": "",
                })
            with patch("proxyip_verify.load_tombstone", return_value={}):
                loaded = proxyip_verify.load_proxyip_csv(legacy_csv)
            by_port = {r["port"]: r for r in loaded}
            self.assertEqual(by_port["52840"].get("exit_asn", ""), "")
            self.assertEqual(extract_asn_num(by_port["443"].get("exit_asn", "")), "979")

        # 3. fetch_zip_proxyips 不得将入口 ASN 强行写入异址 exit_asn，且命中缓存机房入口/出口应直接剔除
        fake_feed = [
            {
                "ip": "140.115.53.51", "port": 443,
                "meta": {
                    "asn": 18420,
                    "asOrganization": "National Central University",
                    "clientIps": ["2a0e:b107:1954:5300::1"],
                    "colo": "TPE",
                },
            },
            {
                "ip": "198.51.100.20", "port": 443,
                "meta": {
                    "asn": 979,
                    "asOrganization": "NetLab",
                    "clientIps": ["198.51.100.99"],
                    "colo": "HKG",
                },
            },
            {
                "ip": "198.51.100.30", "port": 443,
                "meta": {
                    "asn": 979,
                    "asOrganization": "NetLab",
                    "clientIps": ["2a14:7586:6109:1::21a"],
                    "colo": "NRT",
                },
            },
        ]
        scraped_out: dict[str, dict] = {}
        fake_cache = {
            "2a14:7586:6109:1::21a": {"asn": "AS206069", "isp": "Cornseed Limited", "net_type": "datacenter"},
        }
        with patch("tg_fetch.fetch_web_page", return_value=json.dumps(fake_feed)):
            added, _ = tg_fetch.fetch_zip_proxyips(
                ["https://example.invalid/all.json"],
                proxy="",
                tombstone={},
                scraped_proxyips=scraped_out,
                ip_cache=fake_cache,
            )
        self.assertEqual(added, 2)
        self.assertIn("140.115.53.51:443", scraped_out)
        self.assertEqual(scraped_out["140.115.53.51:443"]["exit_asn"], "")
        self.assertIn("198.51.100.20:443", scraped_out)
        self.assertEqual(scraped_out["198.51.100.20:443"]["exit_asn"], "")
        self.assertNotIn("198.51.100.30:443", scraped_out)

    def test_parse_cf_csv_content_decouples_cross_exit_ingress_asn(self):
        fake_cache = {
            "45.33.10.3": {"asn": "AS45102", "isp": "Alibaba Cloud", "net_type": "datacenter", "country": "SG"},
            "203.0.113.88": {"asn": "AS63949", "isp": "Akamai Connected Cloud", "net_type": "datacenter", "country": "US"},
        }
        csv_text = (
            "IP,Port,ASN,ISP,ExitIP,ExitASN,ExitISP\n"
            "198.51.100.51,443,,,203.0.113.88,AS63949,Akamai\n"
            "198.51.100.52,443,AS63949,Akamai,203.0.113.88,AS63949,Akamai\n"
            "45.33.10.3,443,AS63949,Akamai,203.0.113.88,AS63949,Akamai\n"
            "198.51.100.54,443,,,198.51.100.54,AS63949,Akamai\n"
        )
        rows = parsers.parse_cf_csv_content(csv_text, filename="scan.csv", ip_cache=fake_cache)
        self.assertEqual(len(rows), 4)
        missing_ing, spoofed_ing, cached_ing, same_exit = rows
        self.assertEqual(missing_ing["raw_asn"], "")
        self.assertEqual(spoofed_ing["raw_asn"], "")
        self.assertEqual(extract_asn_num(cached_ing["raw_asn"]), "45102")
        self.assertEqual(extract_asn_num(same_exit["raw_asn"]), "63949")

    def test_targeted_asn_probe_reenqueues_suspect_cross_exit_and_saves_city(self):
        import tg_fetch

        rows = [
            {
                "ip": "45.33.90.61",
                "port": "443",
                "asn": "AS63949 (Akamai Connected Cloud)",
                "isp": "Akamai Connected Cloud",
                "raw_asn": "AS63949",
                "exit_ip": "45.33.91.61",
                "exit_asn": "AS63949 (Akamai Connected Cloud)",
                "exit_isp": "Akamai Connected Cloud",
                "channel": "@other_chan",
            }
        ]
        ip_cache: dict = {
            "45.33.91.61": {"asn": "AS63949", "isp": "Akamai Connected Cloud", "net_type": "datacenter", "country": "US"},
        }

        def _fake_batch(targets, persist=True, cache_path="", **kwargs):
            for tip in targets:
                providers._record_online_country(tip, "UK")
                providers._record_online_city(tip, "London")
            return {tip: ("AS9009", "M247 Europe SRL") for tip in targets}

        tg_fetch._SESSION_FAILED_IPS.discard("45.33.90.61")
        with patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_batch):
            tg_fetch._reset_asn_probe_budget(limit=10, p1_limit=10)
            dirty, resolved = tg_fetch._targeted_asn_probe(rows, ip_cache, persist=False, apply_hints=False)

        self.assertTrue(dirty)
        self.assertEqual(list(resolved.keys()), ["45.33.90.61"])
        self.assertEqual(ip_cache["45.33.90.61"]["country"], "GB")
        self.assertEqual(ip_cache["45.33.90.61"]["city"], "London")
        self.assertEqual(extract_asn_num(rows[0]["raw_asn"]), "9009")

    def test_calibrate_all_datasets_normalizes_country_and_syncs_locations(self):
        import csv

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = os.path.join(tmpdir, "ip_cache.json")
            providers.save_ip_cache({
                "45.33.30.1": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "uk", "city": "London"},
                "203.0.113.70": {"asn": "AS24940", "isp": "Hetzner", "net_type": "datacenter", "country": "DE", "city": "Frankfurt"},
                "45.33.30.2": {"asn": "AS45102", "isp": "Alibaba Cloud", "net_type": "datacenter", "country": "SG", "city": "Singapore"},
            }, filepath=cache_path)

            proxyip_csv = os.path.join(tmpdir, "proxyip.csv")
            proxyip_txt = os.path.join(tmpdir, "proxyip.txt")
            proxyip_json = os.path.join(tmpdir, "proxyip.json")
            proxyip_dir = os.path.join(tmpdir, "proxyip")
            with open(proxyip_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.PROXYIP_CSV_FIELDS)
                w.writeheader()
                w.writerow({
                    "ip": "45.33.30.1", "port": "443", "tls": "true", "delay_ms": "100",
                    "speed_kbs": "", "colo": "FRA", "cf_location": "Frankfurt · DE",
                    "asn": "AS4766 (Korea Telecom)", "isp": "Korea Telecom",
                    "first_seen": "2026-10-01 00:00:00", "channel": "@test", "fail_count": "0",
                    "net_type": "isp", "exit_ip": "45.33.30.1", "exit_ipv6": "",
                    "exit_asn": "AS4766 (Korea Telecom)", "exit_isp": "Korea Telecom",
                })

            scan_csv = os.path.join(tmpdir, "scan_ips.csv")
            scan_txt = os.path.join(tmpdir, "scan_ips.txt")
            scan_dir = os.path.join(tmpdir, "scan_ips")
            with open(scan_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.SCAN_CSV_FIELDS)
                w.writeheader()
                w.writerow({
                    "ip": "45.33.30.2", "port": "443", "tls": "true", "delay_ms": "100",
                    "speed_kbs": "", "colo": "SIN", "cf_location": "Singapore · SG",
                    "asn": "AS45102 (Alibaba Cloud)", "isp": "Alibaba Cloud",
                    "first_seen": "2026-10-01 00:00:00", "channel": "@test", "fail_count": "0",
                    "exit_ip": "203.0.113.70", "exit_asn": "", "exit_isp": "", "exit_location": "Tokyo · JP",
                })

            providers.calibrate_all_datasets(
                proxies_csv_path=os.path.join(tmpdir, "proxies.csv"),
                proxyip_csv_path=proxyip_csv,
                proxyip_txt_path=proxyip_txt,
                proxyip_json_path=proxyip_json,
                proxyip_dir=proxyip_dir,
                scan_csv_path=scan_csv,
                scan_txt_path=scan_txt,
                scan_dir_path=scan_dir,
                ip_cache_path=cache_path,
            )

            norm_cache = providers.load_ip_cache(filepath=cache_path)
            self.assertEqual(norm_cache["45.33.30.1"]["country"], "GB")

            with open(proxyip_csv, "r", encoding="utf-8-sig") as f:
                p_rows = list(csv.DictReader(f))
            self.assertEqual(p_rows[0]["cf_location"], "London · GB")
            self.assertTrue(os.path.isfile(os.path.join(proxyip_dir, "GB_英国.txt")))

            with open(scan_csv, "r", encoding="utf-8-sig") as f:
                s_rows = list(csv.DictReader(f))
            self.assertEqual(extract_asn_num(s_rows[0]["exit_asn"]), "24940")
            self.assertEqual(s_rows[0]["exit_location"], "Frankfurt · DE")

    def test_merge_and_save_counts_reflect_cross_pool_transfers_and_tombstone_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_cache_path = os.path.join(tmpdir, "ip_cache.json")
            ip_cache = {
                "198.51.100.1": {"asn": "AS25820", "isp": "IT7 Networks Inc", "net_type": "datacenter", "country": "US"},
                "198.51.100.2": {"asn": "AS25820", "isp": "IT7 Networks Inc", "net_type": "datacenter", "country": "US"},
                "198.51.100.3": {"asn": "AS25820", "isp": "IT7 Networks Inc", "net_type": "datacenter", "country": "US"},
                "198.51.100.4": {"asn": "AS45102", "isp": "Alibaba Cloud", "net_type": "datacenter", "country": "SG"},
                "198.51.100.5": {"asn": "AS45102", "isp": "Alibaba Cloud", "net_type": "datacenter", "country": "SG"},
                "203.0.113.10": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR", "city": "Seoul"},
                "203.0.113.2": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
                "203.0.113.3": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
                "198.51.100.9": {"asn": "AS13335", "isp": "Cloudflare", "net_type": "datacenter", "country": "US"},
            }
            providers.save_ip_cache(ip_cache, filepath=tmp_cache_path)

            existing_scan = {
                "198.51.100.1:443": {"ip": "198.51.100.1", "port": "443", "asn": "AS25820", "isp": "IT7 Networks Inc", "channel": "@c"},
                "198.51.100.2:443": {
                    "ip": "198.51.100.2", "port": "443", "asn": "AS25820", "isp": "IT7 Networks Inc",
                    "exit_ip": "203.0.113.10", "exit_asn": "AS4766", "exit_isp": "Korea Telecom",
                    "exit_location": "Seoul · KR", "cf_location": "Los Angeles · US", "channel": "@c",
                },
                "198.51.100.5:443": {"ip": "198.51.100.5", "port": "443", "asn": "AS45102", "isp": "Alibaba Cloud", "channel": "@c"},
                "198.51.100.9:443": {"ip": "198.51.100.9", "port": "443", "asn": "AS13335", "isp": "Cloudflare", "channel": "@c"},
            }
            scraped_scan = {
                "198.51.100.4:443": {"ip": "198.51.100.4", "port": "443", "asn": "AS45102", "isp": "Alibaba Cloud", "channel": "@c"},
                "198.51.100.5:443": {"ip": "198.51.100.5", "port": "443", "asn": "AS45102", "isp": "Alibaba Cloud", "channel": "@c"},
            }
            existing_proxyips = {
                "203.0.113.2:443": {"ip": "203.0.113.2", "port": "443", "asn": "AS4766", "isp": "Korea Telecom", "channel": "@c"},
                "198.51.100.3:443": {"ip": "198.51.100.3", "port": "443", "asn": "AS25820", "isp": "IT7 Networks Inc", "channel": "@c"},
            }
            scraped_proxyips = {
                "203.0.113.3:443": {"ip": "203.0.113.3", "port": "443", "asn": "AS4766", "isp": "Korea Telecom", "channel": "@c"},
                "198.51.100.88:443": {"ip": "198.51.100.88", "port": "443", "asn": "AS4766", "isp": "Korea Telecom", "channel": "@c"},
            }

            now_ts = int(time.time())
            captured_calls: list[dict] = []

            def _fake_save(final_proxies, final_cf_ips, final_scan_ips=None, final_proxyips=None, **kwargs):
                captured_calls.append({
                    "scan_len": len(final_scan_ips or {}),
                    "proxyip_len": len(final_proxyips or {}),
                    **kwargs,
                })

            with _isolated_tg_fetch_dir(tmpdir), \
                 patch("tg_fetch.load_tombstone", return_value={"198.51.100.88:443": now_ts}), \
                 patch("tg_fetch.auto_enrich_and_save_asns", return_value=0), \
                 patch("tg_fetch.get_session_enriched_asns", return_value=[]), \
                 patch("tg_fetch.resolve_asn_batch_online", side_effect=AssertionError("unexpected network call")), \
                 patch("providers.resolve_asn_batch_online", side_effect=AssertionError("unexpected network call")), \
                 patch("tg_fetch.save_and_notify", side_effect=_fake_save), \
                 self.assertLogs(tg_fetch.log, level="INFO") as cm:
                tg_fetch.merge_and_save(
                    existing_proxies={},
                    scraped_proxies={},
                    existing_cf_ips={},
                    scraped_cf_ips={},
                    existing_scan_ips=existing_scan,
                    scraped_scan_ips=scraped_scan,
                    existing_proxyips=existing_proxyips,
                    scraped_proxyips=scraped_proxyips,
                    edt_unrecorded_asns=[],
                )

            logs = "\n".join(cm.output)
            self.assertEqual(len(captured_calls), 1)
            call_info = captured_calls[0]
            self.assertEqual(call_info["scan_len"], 4)
            self.assertEqual(call_info["proxyip_len"], 3)
            self.assertEqual(call_info["new_scan_count"], 1)
            self.assertEqual(call_info["updated_scan_count"], 1)
            self.assertEqual(call_info["new_proxyips_count"], 1)
            self.assertEqual(call_info["updated_proxyips_count"], 0)
            self.assertIn("【墓地黑名单拦截】", logs)
            self.assertIn("scraped_proxyips", logs)
            self.assertIn("扫描优选 IP 增量合并: 历史保留 1 条, 本次新增 1 条, 本次更新 1 条, 跨池转入 1 条 (另跨池转出 1 条) -> 全量总计 4 条", logs)
            self.assertIn("反代 ProxyIP 增量合并: 历史保留 1 条, 本次新增 1 条, 本次更新 0 条, 跨池转入 1 条 (另跨池转出 1 条) -> 全量总计 3 条", logs)

    def test_load_existing_cf_ips_logs_skipped_tombstone_and_cloudflare_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cf_csv = os.path.join(tmpdir, "cf_ips.csv")
            with open(cf_csv, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=providers.CF_BASE_CSV_FIELDS)
                w.writeheader()
                w.writerow({"ip": "198.51.100.10", "port": "443", "tls": "true", "asn": "AS25820", "isp": "IT7 Networks Inc", "channel": "@c"})
                w.writerow({"ip": "198.51.100.11", "port": "443", "tls": "true", "asn": "AS25820", "isp": "IT7 Networks Inc", "channel": "@c"})
                w.writerow({"ip": "104.28.1.1", "port": "443", "tls": "true", "asn": "AS13335", "isp": "Cloudflare", "channel": "@c"})

            now_ts = int(time.time())
            ip_cache = {
                "198.51.100.10": {"asn": "AS25820", "isp": "IT7 Networks Inc", "net_type": "datacenter", "country": "US"},
                "104.28.1.1": {"asn": "AS13335", "isp": "Cloudflare, Inc.", "net_type": "datacenter", "country": "US"},
            }
            with patch("tg_fetch.load_tombstone", return_value={"198.51.100.11:443": now_ts}), \
                 patch("tg_fetch.load_ip_cache", return_value=ip_cache), \
                 self.assertLogs(tg_fetch.log, level="INFO") as cm:
                loaded = tg_fetch.load_existing_cf_ips(cf_csv, label="单条优选 IP")

            self.assertEqual(list(loaded.keys()), ["198.51.100.10:443"])
            self.assertIn("已加载本地已存单条优选 IP记录: 1 条（跳过墓地冷却 1 条, Cloudflare入口 1 条", "\n".join(cm.output))


if __name__ == "__main__":
    unittest.main()
