import csv
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import parsers
import providers
import tg_fetch


class TestCfChannelCards(unittest.TestCase):
    def test_parse_legacy_and_new_card_templates_with_markdown(self):
        legacy_card = (
            "🇺🇸 美国优选 IP（轮换）\n"
            "地址：`18.117.99.60:443`\n"
            "厂商：AWS\n"
            "出口：哥伦布\n"
            "延迟：999ms\n"
            "速度：7.5 MB/s\n"
            "状态：🟢\n"
            "ProxyIP：🟢\n"
            "大陆：🟢\n"
        )
        items = parsers.parse_cf_channel_cards(legacy_card, default_channel="@C_CFly", ip_cache={})
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it["ip"], "18.117.99.60")
        self.assertEqual(it["port"], "443")
        self.assertEqual(it["tls"], "true")
        self.assertEqual(it["delay_ms"], 0)
        self.assertEqual(it["speed_kbs"], 7680)
        self.assertEqual(it["cf_location"], "哥伦布 · US")
        self.assertEqual(providers.get_country_code(providers.extract_country(it["cf_location"], "")), "US")
        self.assertEqual(it["asn"], "")
        self.assertEqual(it["raw_asn"], "")
        self.assertEqual(it["isp"], "")
        self.assertNotIn("asn_hint", it)
        self.assertEqual(it["channel"], "@C_CFly")

        # 今晚新版：沿用 + 三网延迟 + ProxyIP/状态互换 + 无大陆 + Telethon Markdown 反引号/加粗
        new_card = (
            "🇹🇼 台湾优选 IP（沿用）\n"
            "**地址**：`210.65.177.169:50995`\n"
            "厂商：Chunghwa Telecom\n"
            "出口：Kaohsiung\n"
            "电信：83ms\n"
            "联通：99ms\n"
            "移动：85ms\n"
            "速度：2.2 MB/s\n"
            "ProxyIP：🟢\n"
            "状态：🟢\n"
        )
        items2 = parsers.parse_cf_channel_cards(new_card, default_channel="@C_CFly", ip_cache={})
        self.assertEqual(len(items2), 1)
        it2 = items2[0]
        self.assertEqual(it2["ip"], "210.65.177.169")
        self.assertEqual(it2["port"], "50995")
        self.assertEqual(it2["delay_ms"], 0)
        self.assertEqual(it2["speed_kbs"], 2252)
        self.assertEqual(it2["cf_location"], "Kaohsiung · TW")
        self.assertEqual(providers.get_country_code(providers.extract_country(it2["cf_location"], "")), "TW")
        self.assertEqual(it2["asn"], "")

    def test_parse_recovery_notice_extracts_only_right_side_and_marks_left_dead(self):
        msg = (
            "瑞典节点已恢复 🟢\n"
            "`13.48.85.156:443` → `16.170.253.163:443`\n"
            "归属：Amazon\n"
            "延迟 941ms，速度 6.48 Mbps\n\n"
            "坦桑尼亚节点维护中 🔴\n"
        )
        dead: set[str] = set()
        items = parsers.parse_cf_channel_cards(
            msg, default_channel="@C_CFly", ip_cache={}, dead_keys_out=dead
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["ip"], "16.170.253.163")
        self.assertEqual(items[0]["port"], "443")
        self.assertEqual(items[0]["cf_location"], "瑞典")
        self.assertEqual(providers.get_country_code(providers.extract_country(items[0]["cf_location"], "")), "SE")
        self.assertEqual(items[0]["speed_kbs"], 829)
        self.assertEqual(items[0]["delay_ms"], 0)
        self.assertIn("13.48.85.156:443", dead)
        self.assertNotIn("16.170.253.163:443", dead)

    def test_rejects_red_status_daily_report_and_private_ips(self):
        dead: set[str] = set()
        red_card = (
            "🇭🇰 香港优选 IP（轮换）\n"
            "地址：45.192.247.88:443\n"
            "厂商：Akile\n"
            "状态：🔴\n"
            "ProxyIP：🟢\n"
        )
        self.assertEqual(
            parsers.parse_cf_channel_cards(red_card, default_channel="@C_CFly", ip_cache={}, dead_keys_out=dead),
            [],
        )
        self.assertIn("45.192.247.88:443", dead)

        red_proxyip = (
            "🇯🇵 日本优选 IP（轮换）\n"
            "地址：45.192.247.89:443\n"
            "厂商：Akile\n"
            "状态：🟢\n"
            "ProxyIP：❌\n"
        )
        self.assertEqual(
            parsers.parse_cf_channel_cards(red_proxyip, default_channel="@C_CFly", ip_cache={}, dead_keys_out=dead),
            [],
        )
        self.assertIn("45.192.247.89:443", dead)

        daily_report = (
            "📋 线路日报（11月25日）\n"
            "今日维护：完成换 IP 4 次\n"
            "当前优选 IP：\n"
            "🇭🇰 香港 `223.18.170.192:14198`\n"
            "🇺🇸 美国 `20.184.128.93:80`\n"
        )
        self.assertEqual(parsers.parse_cf_channel_cards(daily_report, default_channel="@C_CFly", ip_cache={}), [])

        private_card = "🇺🇸 美国优选 IP\n地址：10.0.0.1:443\n状态：🟢\nProxyIP：🟢\n"
        self.assertEqual(parsers.parse_cf_channel_cards(private_card, default_channel="@C_CFly", ip_cache={}), [])

    def test_authoritative_ip_cache_hit_populates_asn_without_guessing(self):
        card = (
            "🇹🇼 台湾优选 IP（轮换）\n"
            "地址：69.8.139.116:443\n"
            "厂商：ByteVirt\n"
            "出口：Taipei\n"
            "状态：🟢\n"
            "ProxyIP：🟢\n"
        )
        cache = {"69.8.139.116": {"asn": "AS212336", "isp": "ByteVirt", "net_type": "datacenter", "country": "TW"}}
        items = parsers.parse_cf_channel_cards(card, default_channel="@C_CFly", ip_cache=cache)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["raw_asn"], "AS212336")
        self.assertIn("AS212336", items[0]["asn"])
        self.assertEqual(items[0]["isp"], "ByteVirt")

    def test_merge_scraped_card_ips_respects_existing_richer_sources_tombstone_and_cf(self):
        scraped_card_ips = {
            "1.1.1.1:443": {"ip": "1.1.1.1", "port": "443", "channel": "@C_CFly"},
            "2.2.2.2:443": {"ip": "2.2.2.2", "port": "443", "channel": "@C_CFly"},
            "3.3.3.3:443": {"ip": "3.3.3.3", "port": "443", "channel": "@C_CFly"},
            "4.4.4.4:443": {"ip": "4.4.4.4", "port": "443", "channel": "@C_CFly"},
            "5.5.5.5:443": {"ip": "5.5.5.5", "port": "443", "channel": "@C_CFly"},
            "104.16.1.1:443": {"ip": "104.16.1.1", "port": "443", "channel": "@C_CFly"},
            "6.6.6.6:8444": {"ip": "6.6.6.6", "port": "8444", "channel": "@C_CFly"},
        }
        existing_proxyips = {"1.1.1.1:443": {"ip": "1.1.1.1", "port": "443", "channel": "@danfeng_chat"}}
        existing_scan_ips = {"2.2.2.2:443": {"ip": "2.2.2.2", "port": "443", "channel": "@danfeng_chat"}}
        scraped_proxyips = {"3.3.3.3:443": {"ip": "3.3.3.3", "port": "443", "channel": "@danfeng_chat", "exit_ip": "3.3.3.3"}}
        scraped_scan_ips = {"4.4.4.4:443": {"ip": "4.4.4.4", "port": "443", "channel": "@otcjlq", "colo": "HKG"}}
        tombstone = {"5.5.5.5:443": int(datetime.now(timezone.utc).timestamp())}

        added = tg_fetch._merge_scraped_card_ips(
            scraped_card_ips,
            existing_proxyips,
            existing_scan_ips,
            scraped_proxyips,
            scraped_scan_ips,
            tombstone,
            ip_cache={},
        )
        self.assertEqual(added, 1)
        self.assertIn("6.6.6.6:8444", scraped_scan_ips)
        self.assertEqual(scraped_scan_ips["4.4.4.4:443"]["channel"], "@otcjlq")
        self.assertNotIn("5.5.5.5:443", scraped_scan_ips)
        self.assertNotIn("104.16.1.1:443", scraped_scan_ips)

    def test_scrape_channel_web_preserves_2tuple_and_prevents_old_ip_resurrection(self):
        now_utc = datetime.now(timezone.utc)
        t_old = (now_utc - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        t_mid = (now_utc - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        t_new = (now_utc - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

        # HTML 顺序：最旧在前、最新在后（scrape_channel_web 按 reversed(chunks) 从新到旧扫描）
        fake_html = (
            f'<div class="tgme_widget_message_wrap" data-post="C_CFly/10">'
            f'<time datetime="{t_old}"></time>'
            f'<div class="tgme_widget_message_text">'
            f'🇸🇪 瑞典优选 IP（轮换）<br/>地址：<code>13.48.85.156:443</code><br/>厂商：AWS<br/>状态：🟢<br/>ProxyIP：🟢'
            f'</div></div>'
            f'<div class="tgme_widget_message_wrap" data-post="C_CFly/11">'
            f'<time datetime="{t_mid}"></time>'
            f'<div class="tgme_widget_message_text">'
            f'瑞典节点已恢复 🟢<br/><code>13.48.85.156:443</code> → <code>16.170.253.163:443</code><br/>'
            f'<code>8.8.8.8:443</code> → <code>9.9.9.9:443</code>'
            f'</div></div>'
            f'<div class="tgme_widget_message_wrap" data-post="C_CFly/12">'
            f'<time datetime="{t_new}"></time>'
            f'<div class="tgme_widget_message_text">'
            f'🇭🇰 香港优选 IP（沿用）<br/>地址：<code>8.8.8.8:443</code><br/>厂商：HKBN<br/>出口：Hong Kong<br/>状态：🟢<br/>ProxyIP：🟢'
            f'</div></div>'
        )
        card_out: list[dict] = []
        with mock.patch.object(tg_fetch, "fetch_web_page", side_effect=[fake_html, ""]):
            res = tg_fetch.scrape_channel_web(
                "@C_CFly",
                cutoff=now_utc - timedelta(days=1),
                ip_cache={},
                card_ips_out=card_out,
            )
        self.assertEqual(len(res), 2)
        keys = {f"{item['ip']}:{item['port']}" for item in card_out}
        # 13.48.85.156 在更晚的 post/11 被替换，因此更早的 post/10 不得复活
        self.assertNotIn("13.48.85.156:443", keys)
        self.assertIn("16.170.253.163:443", keys)
        # 8.8.8.8 在更新的 post/12 重新上线，不得被更早的 post/11 抹除
        self.assertIn("8.8.8.8:443", keys)
        self.assertIn("9.9.9.9:443", keys)

    def test_merge_and_save_end_to_end_splits_isp_dc_and_drops_cf(self):
        isp_card = parsers.parse_cf_channel_cards(
            "🇰🇷 韩国优选 IP（轮换）\n地址：`125.143.206.73:8444`\n厂商：Korea Telecom\n出口：Seongnam-si\n状态：🟢\nProxyIP：🟢\n",
            default_channel="@C_CFly",
            ip_cache={},
        )[0]
        dc_card = parsers.parse_cf_channel_cards(
            "🇹🇼 台湾优选 IP（轮换）\n地址：`69.8.139.116:443`\n厂商：ByteVirt\n出口：Taipei\n状态：🟢\nProxyIP：🟢\n",
            default_channel="@C_CFly",
            ip_cache={},
        )[0]
        cf_card = parsers.parse_cf_channel_cards(
            "🇺🇸 美国优选 IP（轮换）\n地址：`45.12.34.56:443`\n厂商：Unknown\n出口：Los Angeles\n状态：🟢\nProxyIP：🟢\n",
            default_channel="@C_CFly",
            ip_cache={},
        )[0]

        scraped_scan_ips: dict[str, dict] = {}
        scraped_proxyips: dict[str, dict] = {}
        scraped_card_ips = {
            f"{it['ip']}:{it['port']}": it for it in (isp_card, dc_card, cf_card)
        }
        tg_fetch._merge_scraped_card_ips(
            scraped_card_ips,
            existing_proxyips={},
            existing_scan_ips={},
            scraped_proxyips=scraped_proxyips,
            scraped_scan_ips=scraped_scan_ips,
            tombstone={},
            ip_cache={},
        )

        def _fake_batch_asn(targets, **_kwargs):
            mapping = {
                "125.143.206.73": ("AS4766", "Korea Telecom"),
                "69.8.139.116": ("AS212336", "ByteVirt"),
                "45.12.34.56": ("AS13335", "Cloudflare, Inc."),
            }
            return {t: mapping[t] for t in targets if t in mapping}

        with tempfile.TemporaryDirectory() as tmp:
            old_data_dir = tg_fetch.DATA_DIR
            try:
                tg_fetch.DATA_DIR = tmp
                tg_fetch._reset_asn_probe_budget()
                with (
                    mock.patch.object(tg_fetch, "OUTPUT_PROXY_FILE", os.path.join(tmp, "proxies.txt")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXIES_DIR", os.path.join(tmp, "proxies")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXIES_CSV", os.path.join(tmp, "proxies.csv")),
                    mock.patch.object(tg_fetch, "OUTPUT_CF_FILE", os.path.join(tmp, "cf_ips.csv")),
                    mock.patch.object(tg_fetch, "OUTPUT_CF_TXT", os.path.join(tmp, "cf_ips.txt")),
                    mock.patch.object(tg_fetch, "OUTPUT_SCAN_FILE", os.path.join(tmp, "scan_ips.csv")),
                    mock.patch.object(tg_fetch, "OUTPUT_SCAN_TXT", os.path.join(tmp, "scan_ips.txt")),
                    mock.patch.object(tg_fetch, "OUTPUT_SCAN_DIR", os.path.join(tmp, "scan_ips")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXYIP_FILE", os.path.join(tmp, "proxyip.csv")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXYIP_TXT", os.path.join(tmp, "proxyip.txt")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXYIP_JSON", os.path.join(tmp, "proxyip.json")),
                    mock.patch.object(tg_fetch, "OUTPUT_PROXYIP_DIR", os.path.join(tmp, "proxyip")),
                    mock.patch.object(tg_fetch, "load_tombstone", return_value={}),
                    mock.patch.object(tg_fetch, "resolve_asn_batch_online", side_effect=_fake_batch_asn),
                    mock.patch.object(tg_fetch, "auto_enrich_and_save_asns", return_value=0),
                    mock.patch.object(tg_fetch, "send_tg_notification"),
                ):
                    tg_fetch.merge_and_save(
                        existing_proxies={},
                        scraped_proxies={},
                        existing_cf_ips={},
                        scraped_cf_ips={},
                        existing_scan_ips={},
                        scraped_scan_ips=scraped_scan_ips,
                        existing_proxyips={},
                        scraped_proxyips=scraped_proxyips,
                        ip_cache={},
                    )

                with open(os.path.join(tmp, "proxyip.csv"), encoding="utf-8-sig") as f:
                    pip_rows = list(csv.DictReader(f))
                with open(os.path.join(tmp, "scan_ips.csv"), encoding="utf-8-sig") as f:
                    scan_rows = list(csv.DictReader(f))

                self.assertEqual([f"{r['ip']}:{r['port']}" for r in pip_rows], ["125.143.206.73:8444"])
                self.assertEqual(pip_rows[0]["net_type"], "isp")
                self.assertEqual(pip_rows[0]["delay_ms"], "0")
                self.assertIn("AS4766", pip_rows[0]["asn"])

                self.assertEqual([f"{r['ip']}:{r['port']}" for r in scan_rows], ["69.8.139.116:443"])
                self.assertIn("AS212336", scan_rows[0]["asn"])
            finally:
                tg_fetch.DATA_DIR = old_data_dir

    def test_default_cf_ip_channels_includes_c_cfly(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            chs = tg_fetch._parse_channels("CF_IP_CHANNELS", ["@otcjlq", "@danfeng_chat", "@C_CFly"])
        self.assertIn("@C_CFly", chs)
        self.assertIn("@C_CFly", tg_fetch.CF_IP_CHANNELS)


if __name__ == "__main__":
    unittest.main()
