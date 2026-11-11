#!/usr/bin/env python3
"""Unit tests verifying permanent Cloudflare ingress rejection and VPS+WARP exit preservation."""

import asyncio
import csv
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import cf_verify  # noqa: E402
import providers  # noqa: E402
import proxies_verify  # noqa: E402
import proxyip_verify  # noqa: E402
import tg_fetch  # noqa: E402


def _write_csv(path: str, fieldnames: list[str], rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _read_csv(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return [dict(r) for r in csv.DictReader(f)]


class TestCloudflarePrimitives(unittest.TestCase):
    def test_asn_and_isp_matching(self):
        for asn in providers.CLOUDFLARE_ASNS:
            self.assertTrue(providers.is_cloudflare_asn_or_isp(asn=asn))
        self.assertTrue(providers.is_cloudflare_asn_or_isp(asn="AS13335 Cloudflare", isp="Cloudflare London LLC"))
        self.assertTrue(providers.is_cloudflare_asn_or_isp(asn="", isp="Cloudflare, Inc."))
        self.assertFalse(providers.is_cloudflare_asn_or_isp(asn="AS132203", isp="Tencent Cloud Computing"))
        self.assertFalse(providers.is_cloudflare_asn_or_isp(asn="AS24940", isp="Hetzner Online GmbH"))
        self.assertFalse(providers.is_cloudflare_asn_or_isp(asn="", isp=""))

    def test_cidr_cache_precedence_and_warp_exit_preservation(self):
        # 1.1.1.1, 1.0.0.1, 104.16.1.1, 172.68.10.20, 2606:4700::1 are Cloudflare ingress CIDRs
        for cf_ip in ("1.1.1.1", "1.0.0.1", "104.16.1.1", "172.68.10.20", "2606:4700::1"):
            self.assertTrue(providers.is_cloudflare_ip(cf_ip))
            self.assertTrue(providers.is_cloudflare_ingress(cf_ip, asn="AS24940", isp="Hetzner"))

        ip_cache = {
            # True non-CIDR Cloudflare BYOIP
            "45.85.118.10": {"asn": "AS209242", "isp": "Cloudflare London LLC", "net_type": "datacenter"},
            # Real third-party VPS whose upstream row was mislabeled as AS13335 due to WARP exit
            "43.167.11.157": {"asn": "AS132203", "isp": "Tencent Cloud", "net_type": "datacenter"},
        }

        self.assertTrue(providers.is_cloudflare_ingress("45.85.118.10", ip_cache=ip_cache))
        # ip_cache BGP ASN overrides stale upstream AS13335 / Cloudflare London LLC label
        self.assertFalse(
            providers.is_cloudflare_ingress(
                "43.167.11.157",
                asn="AS13335 Cloudflare",
                isp="Cloudflare London LLC",
                ip_cache=ip_cache,
                trusts_asn_label=True,
            )
        )
        # Uncached non-CIDR with trusts_asn_label=False stays eligible for online rescue
        self.assertFalse(
            providers.is_cloudflare_ingress(
                "198.51.100.77",
                asn="AS13335 Cloudflare",
                isp="Cloudflare London LLC",
                ip_cache={},
                trusts_asn_label=False,
            )
        )
        self.assertTrue(
            providers.is_cloudflare_ingress(
                "198.51.100.77",
                asn="AS13335 Cloudflare",
                isp="Cloudflare London LLC",
                ip_cache={},
                trusts_asn_label=True,
            )
        )

        # Third-party VPS ingress + WARP outbound (2a09:bac5::1 / AS13335 exit) must be preserved
        vps_warp_scan = {
            "ip": "43.167.11.157",
            "port": "443",
            "asn": "AS13335 Cloudflare",
            "isp": "Cloudflare London LLC",
            "exit_ip": "2a09:bac5::1",
            "exit_asn": "AS13335 Cloudflare",
            "exit_isp": "Cloudflare, Inc.",
        }
        self.assertFalse(providers.is_cloudflare_node(vps_warp_scan, ip_cache=ip_cache))

        # Tunnel proxy whose egress_ip != host (e.g. WARP exit sets r["asn"] = AS13335) must be preserved
        tunnel_warp_proxy = {
            "url": "socks5://65.49.233.236:1080",
            "host": "65.49.233.236",
            "resolved_ip": "65.49.233.236",
            "egress_ip": "104.28.1.1",
            "asn": "AS13335 Cloudflare",
            "isp": "Cloudflare, Inc.",
        }
        self.assertFalse(providers.is_cloudflare_node(tunnel_warp_proxy, ip_cache={}))

        # Tunnel proxy whose ingress host or resolved_ip IS Cloudflare must be rejected
        cf_host_proxy = {
            "url": "socks5://104.16.1.1:1080",
            "host": "104.16.1.1",
            "resolved_ip": "104.16.1.1",
            "egress_ip": "65.49.233.236",
            "asn": "AS25820 IT7 Networks",
            "isp": "IT7 Networks",
        }
        cf_resolved_proxy = {
            "url": "https://cf-edge.example.com:443",
            "host": "cf-edge.example.com",
            "resolved_ip": "45.85.118.10",
            "egress_ip": "65.49.233.236",
            "asn": "AS25820 IT7 Networks",
            "isp": "IT7 Networks",
        }
        self.assertTrue(providers.is_cloudflare_node(cf_host_proxy, ip_cache={}))
        self.assertTrue(providers.is_cloudflare_node(cf_resolved_proxy, ip_cache=ip_cache))

    def test_rescue_mislabeled_cloudflare_rows_queries_only_uncached_non_cidr(self):
        rows = [
            {"ip": "43.167.11.157", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare London LLC"},
            {"ip": "172.68.10.20", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare, Inc."},
            {"ip": "65.49.233.236", "port": "8443", "asn": "AS25820 IT7 Networks", "isp": "IT7 Networks"},
        ]
        ip_cache = {}
        queried_batches = []

        def _fake_resolve(targets, max_chunk_size=100, persist=True, db_path="", cache_path=""):
            queried_batches.append((list(targets), persist))
            res = {}
            for t in targets:
                res[t] = ("AS132203", "Tencent Cloud")
            return res

        with patch("providers.resolve_asn_batch_online", side_effect=_fake_resolve):
            updated_cache, queried_count = providers.rescue_mislabeled_cloudflare_rows(
                rows, ip_cache=ip_cache, persist=False
            )

        self.assertEqual(queried_count, 1)
        self.assertEqual(queried_batches, [(["43.167.11.157"], False)])
        self.assertFalse(providers.is_cloudflare_node(rows[0], ip_cache=updated_cache))
        self.assertIn("AS132203", rows[0]["asn"])
        self.assertTrue(providers.is_cloudflare_node(rows[1], ip_cache=updated_cache))
        self.assertFalse(providers.is_cloudflare_node(rows[2], ip_cache=updated_cache))


class TestMergeAndCalibrateCloudflarePurge(unittest.TestCase):
    def test_merge_and_save_purges_cloudflare_all_pools_while_rescuing_vps_warp(self):
        captured = {}

        def _fake_save(final_proxies, final_cf_ips, final_scan_ips=None, final_proxyips=None, **kwargs):
            captured["proxies"] = final_proxies
            captured["cf_ips"] = final_cf_ips
            captured["scan_ips"] = final_scan_ips
            captured["proxyips"] = final_proxyips

        ip_cache = {
            "45.85.118.10": {"asn": "AS209242", "isp": "Cloudflare London LLC", "net_type": "datacenter", "country": "GB"},
            "65.49.233.236": {"asn": "AS25820", "isp": "IT7 Networks", "net_type": "datacenter", "country": "CA"},
            "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
            "104.28.1.1": {"asn": "AS13335", "isp": "Cloudflare, Inc.", "net_type": "datacenter", "country": "US"},
            "2a09:bac5::1": {"asn": "AS13335", "isp": "Cloudflare, Inc.", "net_type": "datacenter", "country": "US"},
        }

        existing_proxies = {
            "socks5://104.16.1.1:1080": {
                "url": "socks5://104.16.1.1:1080",
                "proto": "socks5",
                "host": "104.16.1.1",
                "port": "1080",
                "asn": "AS13335",
                "isp": "Cloudflare, Inc.",
            },
            # Non-CF ingress tunneling through WARP exit must survive
            "socks5://65.49.233.236:1080": {
                "url": "socks5://65.49.233.236:1080",
                "proto": "socks5",
                "host": "65.49.233.236",
                "resolved_ip": "65.49.233.236",
                "egress_ip": "104.28.1.1",
                "port": "1080",
                "asn": "AS13335 Cloudflare",
                "isp": "Cloudflare, Inc.",
            },
        }
        scraped_proxies = {
            "https://1.1.1.1:443": {
                "url": "https://1.1.1.1:443",
                "proto": "https",
                "host": "1.1.1.1",
                "port": "443",
                "asn": "AS13335",
                "isp": "Cloudflare, Inc.",
            },
        }
        existing_cf_ips = {
            "45.85.118.10:443": {"ip": "45.85.118.10", "port": "443", "asn": "AS209242 Cloudflare"},
            "65.49.233.236:443": {"ip": "65.49.233.236", "port": "443", "asn": "AS25820 IT7 Networks", "isp": "IT7 Networks"},
        }
        scraped_cf_ips = {
            "172.68.10.20:443": {"ip": "172.68.10.20", "port": "443", "asn": "AS13335"},
        }
        existing_scan_ips = {
            "104.16.2.2:443": {"ip": "104.16.2.2", "port": "443", "asn": "AS13335 Cloudflare", "net_type": "datacenter"},
        }
        scraped_scan_ips = {
            # Uncached non-CIDR mislabeled by upstream as AS13335; rescue resolves it to AS132203 Tencent
            "43.167.11.157:8443": {
                "ip": "43.167.11.157",
                "port": "8443",
                "asn": "AS13335 Cloudflare",
                "isp": "Cloudflare London LLC",
                "exit_ip": "2a09:bac5::1",
                "exit_asn": "AS13335 Cloudflare",
                "exit_isp": "Cloudflare, Inc.",
                "net_type": "datacenter",
            },
        }
        existing_proxyips = {
            "104.16.3.3:443": {"ip": "104.16.3.3", "port": "443", "asn": "AS13335 Cloudflare", "net_type": "isp"},
            "218.157.145.120:443": {"ip": "218.157.145.120", "port": "443", "asn": "AS4766 Korea Telecom", "isp": "Korea Telecom", "net_type": "isp"},
        }

        def _fake_rescue_resolve(targets, max_chunk_size=100, persist=True, db_path="", cache_path=""):
            res = {}
            for t in targets:
                if t == "43.167.11.157":
                    res[t] = ("AS132203", "Tencent Cloud")
            return res

        with patch("tg_fetch.load_tombstone", return_value={}), \
             patch("tg_fetch.auto_enrich_and_save_asns", return_value=0), \
             patch("tg_fetch.get_session_enriched_asns", return_value=[]), \
             patch("tg_fetch.resolve_asn_batch_online", side_effect=_fake_rescue_resolve), \
             patch("providers.resolve_asn_batch_online", side_effect=_fake_rescue_resolve), \
             patch("tg_fetch.save_and_notify", side_effect=_fake_save):
            tg_fetch.merge_and_save(
                existing_proxies=existing_proxies,
                scraped_proxies=scraped_proxies,
                existing_cf_ips=existing_cf_ips,
                scraped_cf_ips=scraped_cf_ips,
                existing_scan_ips=existing_scan_ips,
                scraped_scan_ips=scraped_scan_ips,
                existing_proxyips=existing_proxyips,
                scraped_proxyips={},
                edt_unrecorded_asns=[],
                ip_cache=ip_cache,
            )

        self.assertEqual(set(captured["proxies"].keys()), {"socks5://65.49.233.236:1080"})
        self.assertEqual(set(captured["cf_ips"].keys()), {"65.49.233.236:443"})
        self.assertIn("43.167.11.157:8443", captured["scan_ips"])
        self.assertNotIn("104.16.2.2:443", captured["scan_ips"])
        self.assertEqual(set(captured["proxyips"].keys()), {"218.157.145.120:443"})

    def test_calibrate_all_datasets_purges_cf_and_removes_stale_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proxies_dir = os.path.join(tmpdir, "proxies")
            proxyip_dir = os.path.join(tmpdir, "proxyip")
            scan_dir = os.path.join(tmpdir, "scan_ips")
            os.makedirs(proxies_dir, exist_ok=True)
            os.makedirs(proxyip_dir, exist_ok=True)
            os.makedirs(scan_dir, exist_ok=True)

            proxies_csv = os.path.join(tmpdir, "proxies.csv")
            proxies_txt = os.path.join(tmpdir, "proxies.txt")
            proxyip_csv = os.path.join(tmpdir, "proxyip.csv")
            proxyip_txt = os.path.join(tmpdir, "proxyip.txt")
            proxyip_json = os.path.join(tmpdir, "proxyip.json")
            cf_csv = os.path.join(tmpdir, "cf_ips.csv")
            cf_txt = os.path.join(tmpdir, "cf_ips.txt")
            scan_csv = os.path.join(tmpdir, "scan_ips.csv")
            scan_txt = os.path.join(tmpdir, "scan_ips.txt")
            ip_cache_path = os.path.join(tmpdir, "ip_cache.json")

            domains_manifest = os.path.join(proxyip_dir, "domains.txt")
            with open(domains_manifest, "w", encoding="utf-8") as f:
                f.write("kr.william.us.ci\n")
            stale_cf_scan_file = os.path.join(scan_dir, "AS13335_Cloudflare.txt")
            with open(stale_cf_scan_file, "w", encoding="utf-8") as f:
                f.write("104.16.2.2:443\n")

            with open(ip_cache_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "43.167.11.157": {"asn": "AS132203", "isp": "Tencent Cloud", "net_type": "datacenter", "country": "JP"},
                        "65.49.233.236": {"asn": "AS25820", "isp": "IT7 Networks", "net_type": "datacenter", "country": "CA"},
                        "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"},
                    },
                    f,
                )

            _write_csv(
                proxies_csv,
                proxies_verify.PROXY_CSV_FIELDS,
                [
                    {
                        "url": "socks5://104.16.1.1:1080",
                        "proto": "socks5",
                        "host": "104.16.1.1",
                        "port": "1080",
                        "source": "@danfeng_chat",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare, Inc.",
                    },
                    {
                        "url": "socks5://65.49.233.236:1080",
                        "proto": "socks5",
                        "host": "65.49.233.236",
                        "resolved_ip": "65.49.233.236",
                        "egress_ip": "104.28.1.1",
                        "port": "1080",
                        "source": "@danfeng_chat",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare, Inc.",
                    },
                ],
            )
            _write_csv(
                proxyip_csv,
                providers.PROXYIP_CSV_FIELDS,
                [
                    {
                        "ip": "1.1.1.1",
                        "port": "443",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare, Inc.",
                        "net_type": "isp",
                    },
                    {
                        "ip": "218.157.145.120",
                        "port": "443",
                        "asn": "AS4766 Korea Telecom",
                        "isp": "Korea Telecom",
                        "net_type": "isp",
                        "exit_ip": "218.157.145.120",
                        "exit_asn": "AS4766 Korea Telecom",
                    },
                ],
            )
            _write_csv(
                cf_csv,
                providers.CF_BASE_CSV_FIELDS,
                [
                    {"ip": "104.16.1.1", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare, Inc."},
                    {"ip": "65.49.233.236", "port": "443", "asn": "AS25820 IT7 Networks", "isp": "IT7 Networks"},
                ],
            )
            _write_csv(
                scan_csv,
                providers.SCAN_CSV_FIELDS,
                [
                    {"ip": "172.68.10.20", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare, Inc."},
                    {
                        "ip": "43.167.11.157",
                        "port": "8443",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare London LLC",
                        "exit_ip": "2a09:bac5::1",
                        "exit_asn": "AS13335 Cloudflare",
                    },
                ],
            )

            with patch("providers.load_tombstone", return_value={}), \
                 patch("providers.prune_tombstone", return_value={}), \
                 patch("providers.prune_ip_cache", return_value=0):
                stats = providers.calibrate_all_datasets(
                    proxies_dir=proxies_dir,
                    proxies_csv_path=proxies_csv,
                    proxyip_csv_path=proxyip_csv,
                    proxyip_dir=proxyip_dir,
                    ip_cache_path=ip_cache_path,
                    proxyip_txt_path=proxyip_txt,
                    proxyip_json_path=proxyip_json,
                    scan_csv_path=scan_csv,
                    scan_txt_path=scan_txt,
                    scan_dir_path=scan_dir,
                    proxies_txt_path=proxies_txt,
                    cf_csv_path=cf_csv,
                    cf_txt_path=cf_txt,
                )

            self.assertEqual(stats["proxies_cf_removed"], 1)
            self.assertEqual(stats["proxyip_cf_removed"], 1)
            self.assertEqual(stats["cf_ips_cf_removed"], 1)
            self.assertEqual(stats["scan_ips_cf_removed"], 1)
            self.assertEqual([r["host"] for r in _read_csv(proxies_csv)], ["65.49.233.236"])
            self.assertEqual([r["ip"] for r in _read_csv(proxyip_csv)], ["218.157.145.120"])
            self.assertEqual([r["ip"] for r in _read_csv(cf_csv)], ["65.49.233.236"])
            scan_after = _read_csv(scan_csv)
            self.assertEqual([r["ip"] for r in scan_after], ["43.167.11.157"])
            self.assertIn("AS132203", scan_after[0]["asn"])
            self.assertFalse(os.path.exists(stale_cf_scan_file))
            self.assertTrue(os.path.exists(domains_manifest))
            with open(cf_txt, "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "65.49.233.236:443")


class TestVerifiersCloudflareExclusion(unittest.TestCase):
    def test_cf_verify_blocks_cloudflare_before_probing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cf_only_csv = os.path.join(tmpdir, "cf_only.csv")
            _write_csv(
                cf_only_csv,
                providers.CF_BASE_CSV_FIELDS,
                [{"ip": "104.16.1.1", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare"}],
            )
            saved_calls = []
            args = SimpleNamespace(concurrency=4, timeout=2.0, http_timeout=2.0, max_fails=3, dry_run=False, diag_output="")

            with patch("cf_verify.load_ip_cache", return_value={}), \
                 patch("cf_verify.rescue_mislabeled_cloudflare_rows", return_value=({}, 0)), \
                 patch("cf_verify.verify_all", side_effect=AssertionError("CF node must not be probed")), \
                 patch("cf_verify.record_tombstone"):
                asyncio.run(cf_verify._verify_and_persist(cf_only_csv, "CF优选 IP", args, lambda r: saved_calls.append(r)))

            self.assertEqual(saved_calls, [[]])

            mixed_csv = os.path.join(tmpdir, "cf_mixed.csv")
            _write_csv(
                mixed_csv,
                providers.CF_BASE_CSV_FIELDS,
                [
                    {"ip": "104.16.1.1", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare"},
                    {"ip": "65.49.233.236", "port": "8443", "asn": "AS25820 IT7 Networks", "isp": "IT7 Networks"},
                ],
            )
            probed_ips = []

            async def _fake_verify_all(rows, **kwargs):
                probed_ips.extend(r["ip"] for r in rows)
                for r in rows:
                    r["fail_count"] = 0
                    r["_invalid"] = False
                return rows

            saved_calls.clear()
            with patch("cf_verify.load_ip_cache", return_value={}), \
                 patch("cf_verify.rescue_mislabeled_cloudflare_rows", return_value=({}, 0)), \
                 patch("cf_verify.verify_all", side_effect=_fake_verify_all), \
                 patch("cf_verify.record_tombstone"):
                asyncio.run(cf_verify._verify_and_persist(mixed_csv, "CF优选 IP", args, lambda r: saved_calls.append(r)))

            self.assertEqual(probed_ips, ["65.49.233.236"])
            self.assertEqual([r["ip"] for r in saved_calls[0]], ["65.49.233.236"])

    def test_proxyip_verify_rejects_cloudflare_and_clears_when_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p_csv = os.path.join(tmpdir, "proxyip.csv")
            p_txt = os.path.join(tmpdir, "proxyip.txt")
            p_json = os.path.join(tmpdir, "proxyip.json")
            p_dir = os.path.join(tmpdir, "proxyip")
            s_csv = os.path.join(tmpdir, "scan_ips.csv")
            s_txt = os.path.join(tmpdir, "scan_ips.txt")
            s_dir = os.path.join(tmpdir, "scan_ips")
            os.makedirs(p_dir, exist_ok=True)
            os.makedirs(s_dir, exist_ok=True)

            domains_manifest = os.path.join(p_dir, "domains.txt")
            with open(domains_manifest, "w", encoding="utf-8") as f:
                f.write("kr.william.us.ci\n")
            stale_group = os.path.join(p_dir, "US.txt")
            with open(stale_group, "w", encoding="utf-8") as f:
                f.write("104.16.1.1:443\n")
            with open(p_txt, "w", encoding="utf-8") as f:
                f.write("104.16.1.1:443\n")

            _write_csv(
                p_csv,
                providers.PROXYIP_CSV_FIELDS,
                [{"ip": "104.16.1.1", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare", "net_type": "isp"}],
            )
            args = SimpleNamespace(
                concurrency=4,
                max_fails=3,
                timeout=2.0,
                http_timeout=2.0,
                check_endpoint="",
                check_token="",
                check_concurrency=4,
                no_notify=True,
                dry_run=False,
                diag_output="",
            )

            with patch.object(proxyip_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxyip_verify, "PROXYIP_CSV", p_csv), \
                 patch.object(proxyip_verify, "PROXYIP_TXT", p_txt), \
                 patch.object(proxyip_verify, "PROXYIP_JSON", p_json), \
                 patch.object(proxyip_verify, "PROXYIP_DIR", p_dir), \
                 patch.object(proxyip_verify, "SCAN_CSV", s_csv), \
                 patch.object(proxyip_verify, "SCAN_TXT", s_txt), \
                 patch.object(proxyip_verify, "SCAN_DIR", s_dir), \
                 patch("proxyip_verify.load_ip_cache", return_value={}), \
                 patch("proxyip_verify.rescue_mislabeled_cloudflare_rows", return_value=({}, 0)), \
                 patch("proxyip_verify.verify_proxyips", side_effect=AssertionError("CF node must not be probed")), \
                 patch("proxyip_verify.record_tombstone"):
                asyncio.run(proxyip_verify.async_main(args))

            self.assertEqual(_read_csv(p_csv), [])
            self.assertFalse(os.path.exists(stale_group))
            self.assertTrue(os.path.exists(domains_manifest))

            # Case 2: Mixed CF + valid non-CF ISP row -> only valid non-CF row is probed and retained
            _write_csv(
                p_csv,
                providers.PROXYIP_CSV_FIELDS,
                [
                    {"ip": "104.16.1.1", "port": "443", "asn": "AS13335 Cloudflare", "isp": "Cloudflare", "net_type": "isp"},
                    {"ip": "218.157.145.120", "port": "443", "asn": "AS4766 Korea Telecom", "isp": "Korea Telecom", "net_type": "isp"},
                ],
            )
            probed_proxyips = []

            def _fake_verify_proxyips(rows, **kwargs):
                probed_proxyips.extend(r["ip"] for r in rows)
                for r in rows:
                    r["fail_count"] = 0
                    r["_invalid"] = False
                    r["exit_ip"] = r["ip"]
                    r["exit_asn"] = "AS4766 Korea Telecom"
                    r["exit_isp"] = "Korea Telecom"
                return rows

            mixed_cache = {
                "218.157.145.120": {"asn": "AS4766", "isp": "Korea Telecom", "net_type": "isp", "country": "KR"}
            }
            with patch.object(proxyip_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxyip_verify, "PROXYIP_CSV", p_csv), \
                 patch.object(proxyip_verify, "PROXYIP_TXT", p_txt), \
                 patch.object(proxyip_verify, "PROXYIP_JSON", p_json), \
                 patch.object(proxyip_verify, "PROXYIP_DIR", p_dir), \
                 patch.object(proxyip_verify, "SCAN_CSV", s_csv), \
                 patch.object(proxyip_verify, "SCAN_TXT", s_txt), \
                 patch.object(proxyip_verify, "SCAN_DIR", s_dir), \
                 patch("proxyip_verify.load_ip_cache", return_value=mixed_cache), \
                 patch("proxyip_verify.rescue_mislabeled_cloudflare_rows", return_value=(mixed_cache, 0)), \
                 patch("proxyip_verify.verify_proxyips", side_effect=_fake_verify_proxyips), \
                 patch("proxyip_verify.record_tombstone"):
                asyncio.run(proxyip_verify.async_main(args))

            self.assertEqual(probed_proxyips, ["218.157.145.120"])
            self.assertEqual([r["ip"] for r in _read_csv(p_csv)], ["218.157.145.120"])

    def test_proxies_verify_blocks_cloudflare_ingress_keeps_warp_egress(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pr_csv = os.path.join(tmpdir, "proxies.csv")
            pr_txt = os.path.join(tmpdir, "proxies.txt")
            pr_dir = os.path.join(tmpdir, "proxies")
            os.makedirs(pr_dir, exist_ok=True)

            _write_csv(
                pr_csv,
                proxies_verify.PROXY_CSV_FIELDS,
                [
                    {
                        "url": "socks5://104.16.1.1:1080",
                        "proto": "socks5",
                        "host": "104.16.1.1",
                        "port": "1080",
                        "source": "@danfeng_chat",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare, Inc.",
                    },
                    {
                        "url": "https://cf-edge.example.com:443",
                        "proto": "https",
                        "host": "cf-edge.example.com",
                        "resolved_ip": "",
                        "port": "443",
                        "source": "@danfeng_chat",
                        "asn": "",
                        "isp": "",
                    },
                    {
                        "url": "socks5://65.49.233.236:1080",
                        "proto": "socks5",
                        "host": "65.49.233.236",
                        "resolved_ip": "65.49.233.236",
                        "egress_ip": "104.28.1.1",
                        "port": "1080",
                        "source": "@danfeng_chat",
                        "asn": "AS13335 Cloudflare",
                        "isp": "Cloudflare, Inc.",
                    },
                ],
            )
            probed_hosts = []
            shared_cache = {}

            async def _fake_probe_single(row, **kwargs):
                probed_hosts.append(row["host"])
                return {**row, "fail_count": 0, "delay_ms": 42, "_invalid": False}

            async def _fake_resolve_async(targets, max_chunk_size=100, persist=True, db_path="", cache_path=""):
                res = {}
                for t in targets:
                    if t == "cf-edge.example.com":
                        shared_cache[t] = {
                            "asn": "AS13335",
                            "isp": "Cloudflare, Inc.",
                            "net_type": "datacenter",
                            "country": "US",
                            "resolved_ip": "104.16.9.9",
                        }
                        res[t] = ("AS13335", "Cloudflare, Inc.")
                    elif t == "65.49.233.236":
                        shared_cache[t] = {
                            "asn": "AS25820",
                            "isp": "IT7 Networks",
                            "net_type": "datacenter",
                            "country": "CA",
                            "resolved_ip": "65.49.233.236",
                        }
                        res[t] = ("AS25820", "IT7 Networks")
                return res

            args = SimpleNamespace(
                concurrency=4,
                max_fails=3,
                timeout=2.0,
                http_timeout=2.0,
                sstp_timeout=2.0,
                http_probe_timeout=2.0,
                http_max_latency=2500,
                http_max_fails=1,
                cf_check_endpoint="",
                cf_check_token="",
                cf_concurrency=4,
                no_notify=True,
            )

            with patch.object(proxies_verify, "DATA_DIR", tmpdir), \
                 patch.object(proxies_verify, "PROXIES_CSV", pr_csv), \
                 patch.object(proxies_verify, "PROXIES_TXT", pr_txt), \
                 patch.object(proxies_verify, "PROXIES_DIR", pr_dir), \
                 patch("proxies_verify.load_ip_cache", return_value=shared_cache), \
                 patch("proxies_verify.save_ip_cache"), \
                 patch("proxies_verify.prune_ip_cache", return_value=0), \
                 patch("proxies_verify.load_tombstone", return_value={}), \
                 patch("proxies_verify.record_tombstone"), \
                 patch("proxies_verify.auto_enrich_and_save_asns", return_value=0), \
                 patch("proxies_verify.resolve_asn_batch_online_async", side_effect=_fake_resolve_async), \
                 patch("proxies_verify.probe_single", side_effect=_fake_probe_single):
                asyncio.run(proxies_verify.async_main(args))

            self.assertNotIn("104.16.1.1", probed_hosts)
            self.assertEqual([r["host"] for r in _read_csv(pr_csv)], ["65.49.233.236"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
