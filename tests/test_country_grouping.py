#!/usr/bin/env python3
"""Unit tests covering extract_country(), format_proxyip_json_item(), and save_proxyip_by_country()."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import providers  # noqa: E402


class TestCountryGrouping(unittest.TestCase):
    def setUp(self):
        providers.extract_country.cache_clear()

    def tearDown(self):
        providers.extract_country.cache_clear()

    def test_garbage_tokens_collapse_to_other(self):
        garbage_cases = [
            ("LTD.", ""),
            ("PTE", ""),
            ("LLC", ""),
            ("JP Tokyo Tokyo AS137535 JT TELECOM INTERNATIONAL PTE.LTD. 177.3.91.127 ipv4", "PTE"),
            ("US Los Angeles AS25820 Cluster Logic Inc 176.122.172.58 ipv4", ""),
            ("T-Mobile", ""),
            ("Saint-Denis", ""),
            ("Port-au-Prince", ""),
            ("", ""),
        ]
        for cf_location, colo in garbage_cases:
            with self.subTest(cf_location=cf_location, colo=colo):
                self.assertEqual(providers.extract_country(cf_location, colo), "其他地区")

    def test_hyphenated_locations_mapped_to_country(self):
        hyphen_cases = [
            ("美国-波士顿", "BOS", "美国"),
            ("阿塞拜疆-巴库", "GYD", "阿塞拜疆"),
            ("阿曼-马斯喀特", "MCT", "阿曼"),
            ("摩尔多瓦-基希讷乌", "KIV", "摩尔多瓦"),
            ("日本-福冈", "FUK", "日本"),
            ("意大利-巴勒莫", "PMO", "意大利"),
            ("巴林-麦纳麦", "BAH", "巴林"),
            ("US-CA", "", "美国"),
        ]
        for cf_location, colo, expected in hyphen_cases:
            with self.subTest(cf_location=cf_location, colo=colo):
                self.assertEqual(providers.extract_country(cf_location, colo), expected)

    def test_trap1_no_lowercase_iso_or_hk_tw_hijack(self):
        regression_cases = [
            ("Ansan-si · KR", "KIX", "韩国"),
            ("Île-de-France · Paris · 法国", "CDG", "法国"),
            ("Gangwon-do · Chuncheon · 韩国", "ICN", "韩国"),
            ("中国-香港", "HKG", "香港"),
            ("中国-台北", "TPE", "台湾"),
            ("北美洲 · 美国 · 达拉斯-沃斯堡", "", "美国"),
            # 独立无国家后缀时，小写地名词缀 -si / -de / -do 不得误触发两位 ISO 国家码
            ("Ansan-si", "", "其他地区"),
            ("Foo-de-Bar", "", "其他地区"),
            ("Île-de-France", "", "法国"),
            ("Gangwon-do", "", "其他地区"),
        ]
        for cf_location, colo, expected in regression_cases:
            with self.subTest(cf_location=cf_location, colo=colo):
                self.assertEqual(providers.extract_country(cf_location, colo), expected)

    def test_trap2_english_country_normalized_to_chinese(self):
        self.assertEqual(providers.extract_country("Japan", ""), "日本")
        self.assertEqual(providers.extract_country("United Kingdom", ""), "英国")
        self.assertEqual(providers.extract_country("UK", ""), "英国")
        self.assertEqual(providers.extract_country("Japan-Tokyo", ""), "日本")

    def test_standard_multi_part_locations_zero_regression(self):
        self.assertEqual(providers.extract_country("亚洲 · 日本 · 东京", "NRT"), "日本")
        self.assertEqual(providers.extract_country("北美洲 · 美国 · 洛杉矶", "LAX"), "美国")

    def test_trap3_save_merges_multiple_invalid_buckets_into_other(self):
        rows = [
            {
                "ip": "103.231.57.14",
                "port": "8443",
                "tls": "true",
                "colo": "",
                "cf_location": "LTD.",
                "asn": "AS63902 SHINE TELECOM CO., LTD.",
                "isp": "SHINE TELECOM CO., LTD.",
                "channel": "@otcjlq",
            },
            {
                "ip": "198.51.100.20",
                "port": "443",
                "tls": "true",
                "colo": "",
                "cf_location": "XX.YY",
                "asn": "AS64512 Example Net",
                "isp": "Example Net",
                "channel": "@test",
            },
            {
                "ip": "203.0.113.10",
                "port": "443",
                "tls": "true",
                "colo": "",
                "cf_location": "德国",
                "asn": "AS24940 Hetzner Online GmbH",
                "isp": "Hetzner Online GmbH",
                "channel": "@test",
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("providers.extract_country", side_effect=lambda loc, _colo=None: loc):
                providers.save_proxyip_by_country(rows, tmpdir)

            other_txt = os.path.join(tmpdir, "OTHER_其他地区.txt")
            other_json = os.path.join(tmpdir, "OTHER_其他地区.json")
            self.assertTrue(os.path.isfile(other_txt))
            self.assertTrue(os.path.isfile(other_json))
            with open(other_txt, encoding="utf-8") as f:
                txt_lines = [line.strip() for line in f if line.strip()]
            self.assertEqual(txt_lines, ["103.231.57.14:8443", "198.51.100.20:443"])
            with open(other_json, encoding="utf-8") as f:
                json_items = json.load(f)
            self.assertEqual(len(json_items), 2)
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "DE_德国.txt")))

    def test_save_cleans_stale_files_preserves_protected_and_enforces_valid_filenames(self):
        rows = [
            {
                "ip": "176.119.141.154",
                "port": "443",
                "tls": "true",
                "colo": "BOS",
                "cf_location": "美国-波士顿",
                "asn": "AS6282 Atlantis Broadband LLC",
                "isp": "Atlantis Broadband LLC",
                "channel": "@otcjlq",
            },
            {
                "ip": "62.60.188.40",
                "port": "2053",
                "tls": "true",
                "colo": "GYD",
                "cf_location": "阿塞拜疆-巴库",
                "asn": "AS42337 Respina Networks & Beyond PJSC",
                "isp": "Respina Networks & Beyond PJSC",
                "channel": "@otcjlq",
            },
            {
                "ip": "103.231.57.14",
                "port": "8443",
                "tls": "true",
                "colo": "",
                "cf_location": "LTD.",
                "asn": "AS63902 SHINE TELECOM CO., LTD.",
                "isp": "SHINE TELECOM CO.",
                "channel": "@otcjlq",
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            for stale in ("LTD..json", "LTD..txt", "美国-波士顿.txt", "美国-波士顿.json"):
                with open(os.path.join(tmpdir, stale), "w", encoding="utf-8") as f:
                    f.write("stale")
            protected = ("domains.txt", ".gitkeep", "custom_keep.txt", "manual_keep.json")
            for keep in protected:
                with open(os.path.join(tmpdir, keep), "w", encoding="utf-8") as f:
                    f.write("keep")

            providers.save_proxyip_by_country(rows, tmpdir)

            files = set(os.listdir(tmpdir))
            for stale in ("LTD..json", "LTD..txt", "美国-波士顿.txt", "美国-波士顿.json"):
                self.assertNotIn(stale, files)
            for keep in protected:
                self.assertIn(keep, files)
            for expected in (
                "US_美国.txt", "US_美国.json",
                "AZ_阿塞拜疆.txt", "AZ_阿塞拜疆.json",
                "OTHER_其他地区.txt", "OTHER_其他地区.json",
            ):
                self.assertIn(expected, files)

            for fn in files:
                if fn in protected or fn.startswith("【"):
                    continue
                self.assertNotIn("..", fn)
                stem, _ = os.path.splitext(fn)
                self.assertFalse(stem.endswith((".", " ")), f"invalid stem trailing char: {fn}")
                prefix = fn.split("_", 1)[0]
                self.assertTrue(
                    prefix == "OTHER" or (len(prefix) == 2 and prefix.isalpha() and prefix.isupper()),
                    f"unexpected prefix in {fn}",
                )

    def test_format_proxyip_json_item_metadata_guard(self):
        unresolved_item = providers.format_proxyip_json_item({
            "ip": "103.231.57.14",
            "port": "8443",
            "tls": "true",
            "colo": "",
            "cf_location": "LTD.",
            "asn": "AS63902 SHINE TELECOM CO., LTD.",
            "isp": "SHINE TELECOM CO., LTD.",
            "channel": "@otcjlq",
        })
        self.assertEqual(unresolved_item["country"], "")
        self.assertEqual(unresolved_item["country_name"], "其他地区")
        self.assertEqual(unresolved_item["country_cn"], "其他地区")
        self.assertEqual(unresolved_item["country_emoji"], "🌐")

        with patch("providers.extract_country", return_value="UNRESOLVED_GARBAGE."):
            fallback_item = providers.format_proxyip_json_item({
                "ip": "103.231.57.14",
                "port": "8443",
                "cf_location": "UNRESOLVED_GARBAGE.",
            })
        self.assertEqual(fallback_item["country"], "")
        self.assertEqual(fallback_item["country_name"], "其他地区")
        self.assertEqual(fallback_item["country_cn"], "其他地区")

        valid_item = providers.format_proxyip_json_item({
            "ip": "198.51.100.1",
            "port": "443",
            "tls": "true",
            "colo": "FRA",
            "cf_location": "欧洲 · 德国 · 法兰克福",
            "asn": "AS24940 Hetzner Online GmbH",
            "isp": "Hetzner Online GmbH",
            "channel": "@test",
        })
        self.assertEqual(valid_item["country"], "DE")
        self.assertEqual(valid_item["country_name"], "德国")
        self.assertEqual(valid_item["country_cn"], "德国")
        self.assertEqual(valid_item["country_emoji"], "🇩🇪")

    def test_proxyip_json_and_grouping_prioritize_exit_location_and_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            row_with_exit_loc = {
                "ip": "198.51.100.10",
                "port": "443",
                "tls": "true",
                "colo": "FRA",
                "cf_location": "Frankfurt · DE",
                "exit_ip": "203.0.113.5",
                "exit_location": "Tokyo · JP",
                "asn": "AS13335",
                "exit_asn": "AS2516 (KDDI CORPORATION)",
                "exit_isp": "KDDI CORPORATION",
            }
            item1 = providers.format_proxyip_json_item(row_with_exit_loc, ip_cache={})
            self.assertEqual(item1["country"], "JP")
            self.assertEqual(item1["country_name"], "日本")

            fake_cache = {
                "203.0.113.5": {
                    "asn": "AS1136",
                    "isp": "KPN",
                    "net_type": "isp",
                    "country": "NL",
                    "city": "Amsterdam",
                }
            }
            row_cache_exit = {
                "ip": "198.51.100.11",
                "port": "443",
                "tls": "true",
                "colo": "FRA",
                "cf_location": "Frankfurt · DE",
                "exit_ip": "203.0.113.5",
                "exit_asn": "AS1136 (KPN)",
                "exit_isp": "KPN",
            }
            item2 = providers.format_proxyip_json_item(row_cache_exit, ip_cache=fake_cache)
            self.assertEqual(item2["country"], "NL")
            self.assertEqual(item2["country_name"], "荷兰")

            with patch("providers.load_ip_cache", return_value=fake_cache):
                providers.save_proxyip_by_country([row_cache_exit], tmpdir)
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "NL_荷兰.txt")))
            self.assertFalse(os.path.isfile(os.path.join(tmpdir, "DE_德国.txt")))

    def test_resolve_exit_geo_calibration_updates_mismatch_and_city(self):
        cache = {
            "203.0.113.9": {"country": "NL", "city": "Amsterdam"},
            "203.0.113.10": {"country": "US", "city": "Los Angeles"},
            "203.0.113.11": {"country": "JP"},
        }
        self.assertEqual(providers.resolve_exit_geo_calibration("", "203.0.113.9", cache), "Amsterdam · NL")
        self.assertEqual(providers.resolve_exit_geo_calibration("Frankfurt · DE", "203.0.113.9", cache), "Amsterdam · NL")
        self.assertEqual(providers.resolve_exit_geo_calibration("Ashburn · GB", "203.0.113.10", cache), "Los Angeles · US")
        self.assertEqual(providers.resolve_exit_geo_calibration("Dallas · US", "203.0.113.10", cache), "Los Angeles · US")
        self.assertIsNone(providers.resolve_exit_geo_calibration("美国 · 洛杉矶", "203.0.113.10", cache))
        self.assertIsNone(providers.resolve_exit_geo_calibration("Tokyo · JP", "203.0.113.11", cache))


if __name__ == "__main__":
    unittest.main()
