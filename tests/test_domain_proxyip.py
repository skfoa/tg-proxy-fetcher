#!/usr/bin/env python3
"""Unit tests for file-based domain manifests (ProxyIP & CF IPs), DoH parsing, cleanup guards, and merge preservation."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import parsers  # noqa: E402
import providers  # noqa: E402
import tg_fetch  # noqa: E402


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestDoHAndParsers(unittest.TestCase):
    def test_clean_doh_txt_data(self):
        self.assertEqual(
            providers._clean_doh_txt_data('"218.157.145.120:10912,121.128.161.235:10002"'),
            "218.157.145.120:10912,121.128.161.235:10002",
        )
        self.assertEqual(
            providers._clean_doh_txt_data('"218.157.145.120:10912," "121.128.161.235:10002"'),
            "218.157.145.120:10912,121.128.161.235:10002",
        )
        self.assertEqual(providers._clean_doh_txt_data("plain.txt.value"), "plain.txt.value")
        self.assertEqual(providers._clean_doh_txt_data(""), "")

    def test_doh_query_dns_records_a_and_txt_with_fallback(self):
        calls = []

        class _FakeOpener:
            def open(self, req, timeout=3.5):
                url = req.full_url
                calls.append(url)
                if "1.1.1.1" in url:
                    raise OSError("network unreachable")
                if "cloudflare-dns.com" in url and "type=A" in url:
                    return _FakeHTTPResponse(
                        {
                            "Status": 0,
                            "Answer": [
                                {"type": 5, "data": "alias.example.net."},
                                {"type": 1, "data": "192.168.1.1"},
                                {"type": 1, "data": "183.101.136.209"},
                                {"type": 1, "data": "183.101.136.210"},
                                {"type": 1, "data": "183.101.136.209"},
                            ],
                        }
                    )
                if "cloudflare-dns.com" in url and "type=TXT" in url:
                    return _FakeHTTPResponse(
                        {
                            "Status": 0,
                            "Answer": [
                                {
                                    "type": 16,
                                    "data": '"218.157.145.120:10912," "121.128.161.235:10002"',
                                }
                            ],
                        }
                    )
                raise OSError("unexpected")

        with patch("providers.urllib.request.build_opener", return_value=_FakeOpener()):
            a_recs, a_ok, a_detail = providers.doh_query_dns_records("KR.William.US.CI.", record_type="A", timeout=2.0)
            self.assertEqual((a_recs, a_ok, a_detail), (["183.101.136.209", "183.101.136.210"], True, "ok"))

            txt_recs, txt_ok, txt_detail = providers.doh_query_dns_records("kr.william.us.ci", record_type="TXT", timeout=2.0)
            self.assertEqual((txt_recs, txt_ok, txt_detail), (["218.157.145.120:10912,121.128.161.235:10002"], True, "ok"))

            self.assertEqual(providers.doh_resolve_dns_records("kr.william.us.ci", record_type="A", timeout=2.0), ["183.101.136.209", "183.101.136.210"])
            self.assertEqual(providers.doh_resolve_public_ip("kr.william.us.ci", timeout=2.0), "183.101.136.209")

    def test_doh_distinguishes_confirmed_empty_vs_all_failed(self):
        seen_nx = []

        class _NxOpener:
            def open(self, req, timeout=3.5):
                seen_nx.append(req.full_url)
                return _FakeHTTPResponse({"Status": 3, "Answer": []})

        with patch("providers.urllib.request.build_opener", return_value=_NxOpener()):
            res, ok, detail = providers.doh_query_dns_records("missing.example.invalid", record_type="TXT")
        self.assertEqual((res, ok, detail), ([], True, "nxdomain"))
        self.assertEqual(len(seen_nx), 1)

        class _NoRecOpener:
            def open(self, req, timeout=3.5):
                return _FakeHTTPResponse({"Status": 0, "Answer": []})

        with patch("providers.urllib.request.build_opener", return_value=_NoRecOpener()):
            res, ok, detail = providers.doh_query_dns_records("no-txt.example.com", record_type="TXT")
        self.assertEqual((res, ok, detail), ([], True, "no_records"))

        class _FailOpener:
            def open(self, req, timeout=3.5):
                raise TimeoutError("timed out")

        with patch("providers.urllib.request.build_opener", return_value=_FailOpener()):
            res, ok, detail = providers.doh_query_dns_records("timeout.example.com", record_type="TXT")
        self.assertEqual(res, [])
        self.assertFalse(ok)
        self.assertIn("TimeoutError", detail)

        class _ServFailOpener:
            def open(self, req, timeout=3.5):
                return _FakeHTTPResponse({"Status": 2, "Answer": []})

        with patch("providers.urllib.request.build_opener", return_value=_ServFailOpener()):
            res, ok, detail = providers.doh_query_dns_records("servfail.example.com", record_type="TXT")
        self.assertEqual((res, ok, detail), ([], False, "dns_status_2"))

    def test_parse_proxyip_domain_spec(self):
        self.assertEqual(parsers.parse_proxyip_domain_spec("kr.william.us.ci"), ("kr.william.us.ci", 443))
        self.assertEqual(
            parsers.parse_proxyip_domain_spec("TW.William.US.CI.:8443 # comment"),
            ("tw.william.us.ci", 8443),
        )
        self.assertEqual(
            parsers.parse_proxyip_domain_spec("https://Sub.Test.org:2053/path"),
            ("sub.test.org", 2053),
        )
        self.assertIsNone(parsers.parse_proxyip_domain_spec("1.2.3.4"))
        self.assertIsNone(parsers.parse_proxyip_domain_spec("1.2.3.4:443"))
        self.assertIsNone(parsers.parse_proxyip_domain_spec("[2606:4700::1]:443"))
        self.assertIsNone(parsers.parse_proxyip_domain_spec("bad.domain:99999"))
        self.assertIsNone(parsers.parse_proxyip_domain_spec("bad.domain:abc"))

    def test_parse_proxyip_txt_endpoints_strict_ip_port_only(self):
        raw = [
            "218.157.145.120:10912, 121.128.161.235:10002#KT 家宽; [2606:4700:4700::1111]:8443",
            "8443, 10912",  # bare ports without IPs must never become endpoints
            "v=spf1 include:_spf.example.com ~all",
            "192.168.1.10:443, 127.0.0.1:8443, 14.52.210.173:0, 14.52.210.173:12312, 203.69.23.30",
            "218.157.145.120:10912",
        ]
        # Default allow_bare_ip=False strictly rejects bare IP 203.69.23.30 without :port
        strict_eps = parsers.parse_proxyip_txt_endpoints(raw, default_port=2096)
        self.assertEqual(
            strict_eps,
            [
                ("218.157.145.120", 10912),
                ("121.128.161.235", 10002),
                ("2606:4700:4700::1111", 8443),
                ("14.52.210.173", 12312),
            ],
        )

        # Opt-in allow_bare_ip=True appends bare IP using default_port
        permissive_eps = parsers.parse_proxyip_txt_endpoints(raw, default_port=2096, allow_bare_ip=True)
        self.assertEqual(
            permissive_eps,
            [
                ("218.157.145.120", 10912),
                ("121.128.161.235", 10002),
                ("2606:4700:4700::1111", 8443),
                ("14.52.210.173", 12312),
                ("203.69.23.30", 2096),
            ],
        )


class TestDomainManifestsAndOutputs(unittest.TestCase):
    def test_load_domain_manifest_handles_comments_ports_dups_invalid_and_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = os.path.join(tmpdir, "does_not_exist.txt")
            self.assertEqual(tg_fetch.load_domain_manifest(missing_path), [])

            manifest = os.path.join(tmpdir, "domains.txt")
            with open(manifest, "w", encoding="utf-8-sig") as f:
                f.write(
                    "\n"
                    "# Leading comment\n"
                    "  KR.William.US.CI  # Korea dynamic proxyip\n"
                    "tw.william.us.ci:8443\n"
                    "kr.william.us.ci:9999\n"  # duplicate domain, ignored
                    "not a valid domain\n"
                    "1.2.3.4:443\n"
                    "# trailing comment\n"
                )
            with self.assertLogs("tg-fetch", level="WARNING") as cm:
                specs = tg_fetch.load_domain_manifest(manifest)

            self.assertEqual(specs, ["kr.william.us.ci", "tw.william.us.ci:8443"])
            self.assertEqual(len(cm.output), 2)

    def test_repo_domain_manifests_exist_and_parse(self):
        proxyip_manifest = os.path.join(REPO_ROOT, tg_fetch.PROXYIP_DOMAINS_FILE)
        cf_manifest = os.path.join(REPO_ROOT, tg_fetch.CF_IP_DOMAINS_FILE)
        self.assertTrue(os.path.isfile(proxyip_manifest))
        self.assertTrue(os.path.isfile(cf_manifest))
        self.assertEqual(tg_fetch.load_domain_manifest(proxyip_manifest), ["kr.william.us.ci", "tw.william.us.ci"])
        self.assertEqual(tg_fetch.load_domain_manifest(cf_manifest), [])

    def test_save_proxyip_by_country_preserves_domains_txt_nonempty_and_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            domains_path = os.path.join(tmpdir, "domains.txt")
            gitkeep_path = os.path.join(tmpdir, ".gitkeep")
            custom_path = os.path.join(tmpdir, "custom_keep.txt")
            manual_path = os.path.join(tmpdir, "manual_keep.json")
            stale_txt = os.path.join(tmpdir, "US_美国.txt")
            stale_json = os.path.join(tmpdir, "US_美国.json")

            for p, content in (
                (domains_path, "kr.william.us.ci\n"),
                (gitkeep_path, ""),
                (custom_path, "1.1.1.1:443\n"),
                (manual_path, "[]"),
                (stale_txt, "old\n"),
                (stale_json, "[]"),
            ):
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)

            sample_row = {
                "ip": "183.101.136.209",
                "port": "443",
                "tls": "true",
                "delay_ms": 100,
                "speed_kbs": 0,
                "colo": "ICN",
                "cf_location": "Seoul · KR",
                "asn": "AS4766 Korea Telecom",
                "isp": "Korea Telecom",
                "net_type": "isp",
                "fail_count": 0,
                "first_seen": "2026-11-11 10:00:00",
                "channel": "@kr.william.us.ci",
            }
            providers.save_proxyip_by_country([sample_row], tmpdir)

            self.assertTrue(os.path.isfile(domains_path))
            self.assertTrue(os.path.isfile(gitkeep_path))
            self.assertTrue(os.path.isfile(custom_path))
            self.assertTrue(os.path.isfile(manual_path))
            self.assertFalse(os.path.exists(stale_txt))
            self.assertFalse(os.path.exists(stale_json))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "KR_韩国.txt")))
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "KR_韩国.json")))

            # Empty pool clear call (proxyip_verify.py header-only CSV) must remove KR_韩国.* but KEEP domains.txt
            cnt = providers.save_proxyip_by_country([], tmpdir)
            self.assertEqual(cnt, 0)
            self.assertTrue(os.path.isfile(domains_path))
            with open(domains_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "kr.william.us.ci\n")
            self.assertTrue(os.path.isfile(gitkeep_path))
            self.assertTrue(os.path.isfile(custom_path))
            self.assertTrue(os.path.isfile(manual_path))
            self.assertFalse(os.path.exists(os.path.join(tmpdir, "KR_韩国.txt")))
            self.assertFalse(os.path.exists(os.path.join(tmpdir, "KR_韩国.json")))


class TestDomainProxyIPAndCFIntegration(unittest.TestCase):
    def test_fetch_domain_proxyips_manifest_a_txt_and_warnings(self):
        def _fake_query(domain, record_type="A", timeout=5.0, proxy=""):
            if domain == "kr.william.us.ci":
                if record_type == "A":
                    return ["183.101.136.209"], True, "ok"
                if record_type == "TXT":
                    return [
                        "183.101.136.209:443,218.157.145.120:10912,14.52.210.173:80,52.1.2.3:443,121.128.161.235:10002,60.251.142.38"
                    ], True, "ok"
            if domain == "a-only-txt-fail.example.com":
                if record_type == "A":
                    return ["203.69.23.30"], True, "ok"
                if record_type == "TXT":
                    return [], False, "TimeoutError: timed out"
            return [], True, "no_records"

        fake_ip_cache = {
            "183.101.136.209": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "14.52.210.173": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "52.1.2.3": {"asn": "AS16509", "isp": "Amazon.com", "net_type": "datacenter", "country": "US"},
            "121.128.161.235": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "203.69.23.30": {"asn": "AS3462", "isp": "Chunghwa Telecom Data Communication Business Group", "net_type": "isp", "country": "TW"},
            "60.251.142.38": {"asn": "AS3462", "isp": "Chunghwa Telecom Data Communication Business Group", "net_type": "isp", "country": "TW"},
        }
        tombstone = {"121.128.161.235:10002": 9999999999}
        scraped_proxyips = {}
        expanded = set()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = os.path.join(tmpdir, "domains.txt")
            with open(manifest, "w", encoding="utf-8") as f:
                f.write("kr.william.us.ci\na-only-txt-fail.example.com\n")

            with patch.object(tg_fetch, "PROXYIP_DOMAINS_FILE", manifest), \
                 patch("tg_fetch.doh_query_dns_records", side_effect=_fake_query), \
                 patch("tg_fetch.resolve_asn_batch_online") as mock_batch, \
                 patch("tg_fetch.auto_enrich_and_save_asns") as mock_enrich, \
                 self.assertLogs("tg-fetch", level="WARNING") as cm:
                added, unrec = tg_fetch.fetch_domain_proxyips(
                    None,
                    proxy="",
                    tombstone=tombstone,
                    scraped_proxyips=scraped_proxyips,
                    ip_cache=fake_ip_cache,
                    expanded_domains_out=expanded,
                )

        mock_batch.assert_not_called()
        mock_enrich.assert_not_called()
        self.assertTrue(any("DoH TXT 记录查询失败" in msg and "a-only-txt-fail.example.com" in msg for msg in cm.output))
        self.assertEqual(expanded, {"kr.william.us.ci", "a-only-txt-fail.example.com"})
        self.assertEqual(added, 4)
        self.assertEqual(unrec, [])
        self.assertIn("183.101.136.209:443", scraped_proxyips)
        self.assertIn("218.157.145.120:10912", scraped_proxyips)
        self.assertIn("14.52.210.173:80", scraped_proxyips)
        self.assertIn("203.69.23.30:443", scraped_proxyips)
        # Bare TXT IP without explicit :port (60.251.142.38) must NOT be accepted for ProxyIP
        self.assertNotIn("60.251.142.38:443", scraped_proxyips)
        # No cross-product between A IP (183.101.136.209) and TXT ports (10912 / 10002 / 80)
        self.assertNotIn("183.101.136.209:10912", scraped_proxyips)
        self.assertNotIn("52.1.2.3:443", scraped_proxyips)
        self.assertNotIn("121.128.161.235:10002", scraped_proxyips)

        self.assertEqual(scraped_proxyips["218.157.145.120:10912"]["tls"], "true")
        self.assertEqual(scraped_proxyips["14.52.210.173:80"]["tls"], "false")
        self.assertEqual(scraped_proxyips["218.157.145.120:10912"]["cf_location"], "韩国")
        self.assertEqual(scraped_proxyips["218.157.145.120:10912"]["channel"], "@kr.william.us.ci")
        self.assertEqual(scraped_proxyips["218.157.145.120:10912"]["net_type"], "isp")

    def test_collect_external_proxyips_cleanup_isolation_and_incremental_retention(self):
        def _fake_query(domain, record_type="A", timeout=5.0, proxy=""):
            if domain == "tw.william.us.ci" and record_type == "A":
                return ["203.69.23.30"], True, "ok"
            if domain == "all-tomb.example.com" and record_type == "A":
                return ["218.157.145.120"], True, "ok"
            if domain == "all-dc.example.com" and record_type == "A":
                return ["52.1.2.3"], True, "ok"
            if domain == "doh-fail.example.com" and record_type == "A":
                return [], False, "TimeoutError: doh offline"
            return [], True, "no_records"

        fake_ip_cache = {
            "203.69.23.30": {"asn": "AS3462", "isp": "Chunghwa Telecom Data Communication Business Group", "net_type": "isp", "country": "TW"},
            "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "52.1.2.3": {"asn": "AS16509", "isp": "Amazon.com", "net_type": "datacenter", "country": "US"},
        }
        tombstone = {"218.157.145.120:443": 9999999999}
        existing_proxyips = {
            # Historical resolved IP that is NOT in current DNS A/TXT must stay in pool (validator decides removal)
            "125.227.162.252:24159": {"ip": "125.227.162.252", "port": "24159", "fail_count": 0},
            "tw.william.us.ci:443": {"ip": "tw.william.us.ci", "port": "443"},
            "all-tomb.example.com:443": {"ip": "all-tomb.example.com", "port": "443"},
            "all-dc.example.com:443": {"ip": "all-dc.example.com", "port": "443"},
            "doh-fail.example.com:443": {"ip": "doh-fail.example.com", "port": "443"},
            "other.domain.invalid:443": {"ip": "other.domain.invalid", "port": "443"},
        }
        scraped_proxyips = {"tw.william.us.ci:443": {"ip": "tw.william.us.ci", "port": "443"}}
        existing_scan_ips = {}
        scraped_scan_ips = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = os.path.join(tmpdir, "domains.txt")
            with open(manifest, "w", encoding="utf-8") as f:
                f.write("tw.william.us.ci\nall-tomb.example.com\nall-dc.example.com\ndoh-fail.example.com\nother.domain.invalid\n")

            with patch.object(tg_fetch, "PROXYIP_ZIP_URLS", []), \
                 patch.object(tg_fetch, "PROXYIP_DOMAINS_FILE", manifest), \
                 patch("tg_fetch.doh_query_dns_records", side_effect=_fake_query), \
                 self.assertLogs("tg-fetch", level="WARNING") as cm:
                tg_fetch.collect_external_proxyips(
                    proxy="",
                    tombstone=tombstone,
                    existing_proxyips=existing_proxyips,
                    scraped_proxyips=scraped_proxyips,
                    existing_scan_ips=existing_scan_ips,
                    scraped_scan_ips=scraped_scan_ips,
                    ip_cache=fake_ip_cache,
                )

        self.assertTrue(any("doh-fail.example.com" in msg for msg in cm.output))
        self.assertNotIn("tw.william.us.ci:443", existing_proxyips)
        self.assertNotIn("tw.william.us.ci:443", scraped_proxyips)
        self.assertIn("203.69.23.30:443", scraped_proxyips)
        # Historical DNS-dropped IP remains preserved
        self.assertIn("125.227.162.252:24159", existing_proxyips)
        # Zero admitted endpoints / DoH failure -> old unexpanded domain rows must stay preserved
        self.assertIn("all-tomb.example.com:443", existing_proxyips)
        self.assertIn("all-dc.example.com:443", existing_proxyips)
        self.assertIn("doh-fail.example.com:443", existing_proxyips)
        self.assertIn("other.domain.invalid:443", existing_proxyips)

    def test_fetch_and_collect_domain_cf_ips_rules_and_merge_preservation(self):
        dns_calls = []

        def _fake_query(domain, record_type="A", timeout=5.0, proxy=""):
            dns_calls.append((domain, record_type))
            if domain == "cf-anycast.example.com" and record_type == "A":
                return ["104.16.1.1"], True, "ok"
            if domain == "cf-byoip.example.com" and record_type == "A":
                return ["45.85.118.10"], True, "ok"
            if domain == "cf-port.example.com" and record_type == "A":
                return ["65.49.233.236"], True, "ok"
            if domain == "cf-plain.example.com" and record_type == "A":
                return ["64.118.155.168"], True, "ok"
            if record_type == "TXT":
                # Use a valid public IP:Port so only protocol semantics (not IP validity) excludes TXT
                return ["218.157.145.120:10912"], True, "ok"
            if domain == "cf-fail.example.com" and record_type == "A":
                return [], False, "TimeoutError: timed out"
            return [], True, "no_records"

        fake_ip_cache = {
            "104.16.1.1": {"asn": "AS13335", "isp": "Cloudflare, Inc.", "net_type": "datacenter", "country": "US"},
            "45.85.118.10": {"asn": "AS209242", "isp": "Cloudflare London LLC", "net_type": "datacenter", "country": "GB"},
            "65.49.233.236": {"asn": "AS25820", "isp": "IT7 Networks Inc", "net_type": "datacenter", "country": "CA"},
            "64.118.155.168": {"asn": "AS138997", "isp": "Eons Data", "net_type": "datacenter", "country": "US"},
            "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
        }
        existing_cf_ips = {
            # Historical Cloudflare IP must be purged by merge_and_save even if previously stored
            "104.16.1.1:443": {
                "ip": "104.16.1.1",
                "port": "443",
                "tls": "true",
                "delay_ms": "12",
                "speed_kbs": "1024",
                "colo": "LAX",
                "cf_location": "北美洲 · LAX",
                "asn": "AS13335 Cloudflare",
                "isp": "Cloudflare, Inc.",
                "fail_count": 0,
                "first_seen": "2026-10-01 06:00:33",
                "channel": "@old_cf",
            },
            "65.49.233.236:8443": {
                "ip": "65.49.233.236",
                "port": "8443",
                "tls": "true",
                "delay_ms": "25",
                "speed_kbs": "15360.5",
                "colo": "YVR",
                "cf_location": "北美洲 · Vancouver",
                "asn": "AS25820 IT7 Networks Inc",
                "isp": "IT7 Networks Inc",
                "fail_count": 1,
                "first_seen": "2026-10-11 06:00:33",
                "channel": "@danfeng_chat",
            },
            # Old non-CF IP no longer returned in DNS must remain in pool for cf_verify.py lifecycle
            "64.118.155.168:443": {
                "ip": "64.118.155.168",
                "port": "443",
                "tls": "true",
                "delay_ms": "61",
                "speed_kbs": "",
                "colo": "SJC",
                "cf_location": "北美洲 · 美国圣何塞",
                "asn": "AS138997 Eons Data",
                "isp": "Eons Data",
                "fail_count": 0,
                "first_seen": "2026-09-22 06:00:33",
                "channel": "@cf-plain.example.com",
            },
            "cf-plain.example.com:443": {"ip": "cf-plain.example.com", "port": "443"},
            "cf-anycast.example.com:443": {"ip": "cf-anycast.example.com", "port": "443"},
            "cf-fail.example.com:443": {"ip": "cf-fail.example.com", "port": "443"},
        }
        existing_proxyips = {
            "cf-plain.example.com:443": {"ip": "cf-plain.example.com", "port": "443"},
        }
        scraped_cf_ips = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            cf_manifest = os.path.join(tmpdir, "domains.txt")
            with open(cf_manifest, "w", encoding="utf-8") as f:
                f.write(
                    "cf-anycast.example.com\n"
                    "cf-byoip.example.com\n"
                    "cf-port.example.com:8443\n"
                    "cf-plain.example.com:80\n"
                    "cf-fail.example.com\n"
                )

            with patch.object(tg_fetch, "CF_IP_DOMAINS_FILE", cf_manifest), \
                 patch("tg_fetch.doh_query_dns_records", side_effect=_fake_query), \
                 patch("tg_fetch.resolve_asn_batch_online"), \
                 patch("tg_fetch.auto_enrich_and_save_asns"), \
                 self.assertLogs("tg-fetch", level="WARNING") as cm:
                tg_fetch.collect_domain_cf_ips(
                    proxy="",
                    tombstone={},
                    existing_cf_ips=existing_cf_ips,
                    scraped_cf_ips=scraped_cf_ips,
                    ip_cache=fake_ip_cache,
                )

        # Cloudflare ingress (CIDR AS13335 and BYOIP AS209242) must be rejected;
        # valid third-party datacenter ASNs stay allowed, and TXT endpoints remain excluded.
        self.assertNotIn("104.16.1.1:443", scraped_cf_ips)
        self.assertNotIn("45.85.118.10:443", scraped_cf_ips)
        self.assertIn("65.49.233.236:8443", scraped_cf_ips)
        self.assertIn("64.118.155.168:80", scraped_cf_ips)
        self.assertNotIn("218.157.145.120:10912", scraped_cf_ips)
        self.assertEqual(scraped_cf_ips["65.49.233.236:8443"]["tls"], "true")
        self.assertEqual(scraped_cf_ips["64.118.155.168:80"]["tls"], "false")
        self.assertEqual(scraped_cf_ips["65.49.233.236:8443"]["channel"], "@cf-port.example.com")
        self.assertTrue(all(rec_type == "A" for _, rec_type in dns_calls))
        self.assertTrue(any("cf-fail.example.com" in msg for msg in cm.output))

        # Bare domain cleanup removes resolved valid domain from cf_ips only, leaves proxyips and unresolved/failed domains
        self.assertNotIn("cf-plain.example.com:443", existing_cf_ips)
        self.assertIn("cf-anycast.example.com:443", existing_cf_ips)
        self.assertIn("cf-fail.example.com:443", existing_cf_ips)
        self.assertIn("cf-plain.example.com:443", existing_proxyips)

        # Verify merge_and_save purges historical CF IPs, preserves verified non-CF metrics,
        # and keeps historical DNS-dropped non-CF IPs
        captured = {}

        def _fake_save(final_proxies, final_cf_ips, final_scan_ips=None, final_proxyips=None, **kwargs):
            captured["cf_ips"] = final_cf_ips

        with patch("tg_fetch.load_tombstone", return_value={}), \
             patch("tg_fetch.auto_enrich_and_save_asns", return_value=0), \
             patch("tg_fetch.get_session_enriched_asns", return_value=[]), \
             patch("tg_fetch.save_and_notify", side_effect=_fake_save):
            tg_fetch.merge_and_save(
                existing_proxies={},
                scraped_proxies={},
                existing_cf_ips=existing_cf_ips,
                scraped_cf_ips=scraped_cf_ips,
                existing_scan_ips={},
                scraped_scan_ips={},
                existing_proxyips={},
                scraped_proxyips={},
                edt_unrecorded_asns=[],
                ip_cache=fake_ip_cache,
            )

        merged_cf = captured["cf_ips"]
        self.assertNotIn("104.16.1.1:443", merged_cf)
        self.assertIn("64.118.155.168:443", merged_cf)
        kept = merged_cf["65.49.233.236:8443"]
        self.assertEqual(kept["delay_ms"], "25")
        self.assertEqual(kept["speed_kbs"], "15360.5")
        self.assertEqual(kept["colo"], "YVR")
        self.assertEqual(kept["cf_location"], "北美洲 · Vancouver")
        self.assertEqual(kept["first_seen"], "2026-10-11 06:00:33")
        self.assertEqual(kept["channel"], "@danfeng_chat")
        self.assertEqual(kept["fail_count"], 1)

    def test_merge_and_save_preserves_existing_proxyip_metrics(self):
        captured = {}

        def _fake_save(
            final_proxies,
            final_cf_ips,
            final_scan_ips=None,
            final_proxyips=None,
            **kwargs,
        ):
            captured["proxyips"] = final_proxyips

        existing_proxyips = {
            "183.101.136.209:443": {
                "ip": "183.101.136.209",
                "port": "443",
                "tls": "true",
                "delay_ms": 489,
                "speed_kbs": 1200,
                "colo": "SEA",
                "cf_location": "Seoul · KR",
                "asn": "AS4766 Korea Telecom",
                "isp": "Korea Telecom",
                "fail_count": 0,
                "first_seen": "2026-10-25 18:30:49",
                "channel": "@orig_channel",
                "net_type": "isp",
                "exit_ip": "183.101.136.209",
                "exit_ipv6": "",
                "exit_asn": "AS4766 Korea Telecom",
                "exit_isp": "Korea Telecom",
            }
        }
        scraped_proxyips = {
            "183.101.136.209:443": {
                "ip": "183.101.136.209",
                "port": "443",
                "tls": "true",
                "delay_ms": 0,
                "speed_kbs": 0,
                "colo": "",
                "cf_location": "韩国",
                "asn": "AS4766 Korea Telecom",
                "isp": "Korea Telecom",
                "fail_count": 0,
                "first_seen": "2026-11-11 14:00:00",
                "channel": "@kr.william.us.ci",
                "net_type": "isp",
                "exit_ip": "",
                "exit_ipv6": "",
                "exit_asn": "",
                "exit_isp": "",
            },
            "218.157.145.120:10912": {
                "ip": "218.157.145.120",
                "port": "10912",
                "tls": "true",
                "delay_ms": 0,
                "speed_kbs": 0,
                "colo": "",
                "cf_location": "韩国",
                "asn": "AS4766 Korea Telecom",
                "isp": "Korea Telecom",
                "fail_count": 0,
                "first_seen": "2026-11-11 14:00:00",
                "channel": "@kr.william.us.ci",
                "net_type": "isp",
                "exit_ip": "",
                "exit_ipv6": "",
                "exit_asn": "",
                "exit_isp": "",
            },
        }
        ip_cache = {
            "183.101.136.209": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
        }

        with patch("tg_fetch.load_tombstone", return_value={}), \
             patch("tg_fetch.auto_enrich_and_save_asns", return_value=0), \
             patch("tg_fetch.get_session_enriched_asns", return_value=[]), \
             patch("tg_fetch.save_and_notify", side_effect=_fake_save):
            tg_fetch.merge_and_save(
                existing_proxies={},
                scraped_proxies={},
                existing_cf_ips={},
                scraped_cf_ips={},
                existing_scan_ips={},
                scraped_scan_ips={},
                existing_proxyips=existing_proxyips,
                scraped_proxyips=scraped_proxyips,
                edt_unrecorded_asns=[],
                ip_cache=ip_cache,
            )

        kept = captured["proxyips"]["183.101.136.209:443"]
        self.assertEqual(kept["first_seen"], "2026-10-25 18:30:49")
        self.assertEqual(kept["delay_ms"], 489)
        self.assertEqual(kept["speed_kbs"], 1200)
        self.assertEqual(kept["colo"], "SEA")
        self.assertEqual(kept["channel"], "@orig_channel")
        self.assertEqual(kept["exit_ip"], "183.101.136.209")
        self.assertIn("218.157.145.120:10912", captured["proxyips"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
