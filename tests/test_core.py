"""
核心纯函数与数据流单元测试集 (tests/test_core.py)
覆盖:
  1. is_valid_host: IPv4 (ASCII 校验、边界、Unicode 数字拦截) 与 域名格式校验
  2. format_asn_isp: SSOT 权威查表、地址后缀清除、别名保留与幂等性
  3. normalize_timestamp: 8 位纯数字日期保护、Unix 时间戳转换、ISO 字符串规整
  4. classify_asn: 权威 exact_net_type、启发式分类与兜底逻辑
  5. extract_proxies: 大小写协议通配、脏文本提取与 canonical_key 规范化
  6. load_existing_proxies: TXT 缺失兜底、墓碑黑名单拦截、同 Key 冲突健康度择优
"""

import csv
import json
import os
import sys
import tempfile
import unittest

# 确保导入根目录模块
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from parsers import is_valid_host, extract_proxies
from providers import (
    clean_asn,
    format_asn_isp,
    normalize_timestamp,
    classify_asn,
    save_scan_ips_by_asn,
    ASN_TO_PROVIDER,
    safe_int,
    PROXY_CSV_FIELDS,
    save_proxies_csv,
    save_proxies_json,
    save_proxies_by_protocol,
)
from tg_fetch import load_existing_proxies


class TestParsers(unittest.TestCase):
    def test_is_valid_host_ipv4(self):
        self.assertTrue(is_valid_host("1.1.1.1"))
        self.assertTrue(is_valid_host("192.168.1.1"))
        self.assertTrue(is_valid_host("255.255.255.255"))
        self.assertTrue(is_valid_host("0.0.0.0"))

        # 越界与格式错误
        self.assertFalse(is_valid_host("256.0.0.1"))
        self.assertFalse(is_valid_host("1.2.3"))
        self.assertFalse(is_valid_host("1.2.3.4.5"))
        self.assertFalse(is_valid_host("1.2.3.-1"))
        self.assertFalse(is_valid_host(""))

        # 非 ASCII / Unicode 全角数字防御
        self.assertFalse(is_valid_host("١.٢.٣.٤"))
        self.assertFalse(is_valid_host("１.２.３.４"))

    def test_is_valid_host_domain(self):
        self.assertTrue(is_valid_host("cloudflare.com"))
        self.assertTrue(is_valid_host("speed.cloudflare.com"))
        self.assertTrue(is_valid_host("node-1.vps-provider.org"))
        self.assertFalse(is_valid_host("invalid_domain..com"))
        self.assertFalse(is_valid_host("-bad.com"))

        # RFC 1035 / 1123 长度上限测试 (Q2)
        self.assertFalse(is_valid_host("a" * 64 + ".com"))
        self.assertFalse(is_valid_host("a." * 128 + "com"))
        self.assertTrue(is_valid_host("a" * 63 + ".com"))

    def test_extract_proxies_case_insensitive(self):
        # 支持大小写 scheme
        text = "SOCKS5://user:pass@1.2.3.4:1080\nHTTP://5.6.7.8:8080"
        proxies = extract_proxies(text)
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0], ("SOCKS5://user:pass@1.2.3.4:1080", "1.2.3.4:1080"))
        self.assertEqual(proxies[1], ("HTTP://5.6.7.8:8080", "5.6.7.8:8080"))


class TestProviders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 确保关键测试用的静态映射在内存中存在（防御外部 JSON 漂移与环境隔离, T1）
        from providers import ASN_DATABASE_ASN_TO_ISP, ASN_DATABASE_ISP_TO_ASN, ASN_TO_PROVIDER
        ASN_DATABASE_ASN_TO_ISP["AS63023"] = "Ipxo LLC"
        ASN_TO_PROVIDER["AS63023"] = "Ipxo LLC"
        ASN_DATABASE_ISP_TO_ASN["MobileOne Ltd. Mobile/Internet Service Provider Singapore"] = "AS4773"
        ASN_DATABASE_ASN_TO_ISP["AS4773"] = "M1 LIMITED"
        ASN_TO_PROVIDER["AS4773"] = "M1 LIMITED"

    def test_format_asn_isp_authoritative(self):
        # Cloudflare 权威已知库反查
        formatted = format_asn_isp("13335")
        self.assertIn("AS13335", formatted)
        self.assertIn("Cloudflare", formatted)

        # 腾讯云地址脏后缀清洗
        dirty_tencent = "AS132203 Tencent Building, Kejizhongyi Avenue"
        cleaned = format_asn_isp(dirty_tencent)
        self.assertEqual(cleaned, "AS132203 Tencent Cloud")

    def test_format_asn_isp_alias(self):
        # 租户与宿主多品牌别名保留
        res = format_asn_isp("AS63023", "GTHost")
        self.assertEqual(res, "AS63023 Ipxo LLC (GTHost)")

        # 二次调用幂等性校验
        res2 = format_asn_isp(res, "")
        self.assertEqual(res2, "AS63023 Ipxo LLC (GTHost)")

    def test_clean_asn_and_format_fallback(self):
        # 针对无 AS 前缀、含斜杠/服务商描述的长文本进行别名反查
        raw = "MobileOne Ltd. Mobile/Internet Service Provider Singapore"
        self.assertEqual(clean_asn(raw), "AS4773")
        formatted = format_asn_isp(raw)
        self.assertIn("AS4773", formatted)
        self.assertIn("M1 LIMITED", formatted)
        self.assertIn("MobileOne Ltd.", formatted)

        # 未知且无 AS 编号的文本兜底为 AS_UNKNOWN
        self.assertEqual(clean_asn("Unknown Entity Without AS Number"), "AS_UNKNOWN")

        # 验证 M-net (AS8767) 与 Level 3 (AS3356)
        self.assertEqual(clean_asn("M-net Telekommunikations GmbH"), "AS8767")
        self.assertEqual(classify_asn("AS8767"), "isp")
        self.assertEqual(clean_asn("Level 3 Parent, LLC"), "AS3356")
        self.assertEqual(classify_asn("AS3356"), "isp")

        # 验证国内两大运营商权威归属 (AS4837 联通 / AS9808 移动)
        self.assertEqual(clean_asn("China Unicom"), "AS4837")
        self.assertEqual(clean_asn("CHINA UNICOM China169 Backbone"), "AS4837")
        self.assertEqual(clean_asn("China Mobile"), "AS9808")
        self.assertEqual(format_asn_isp("AS4837"), "AS4837 China Unicom")
        self.assertEqual(format_asn_isp("AS9808"), "AS9808 China Mobile")

        # 验证 IDC Cube (AS36530)
        self.assertEqual(clean_asn("IDC Cube"), "AS36530")
        self.assertEqual(format_asn_isp("AS36530"), "AS36530 IDC Cube")

        # 验证七牛云独立 ASN (AS152644) 与华为云 (AS136907) 解耦
        self.assertEqual(clean_asn("Qiniu Cloud"), "AS152644")
        self.assertEqual(clean_asn("Qiniu"), "AS152644")
        self.assertEqual(format_asn_isp("AS152644"), "AS152644 Qiniu Cloud")
        self.assertEqual(classify_asn("AS152644"), "datacenter")

        # 验证下游租户/分销商别名保留 (Claw Cloud / BageVM)
        self.assertEqual(clean_asn("Claw Cloud"), "AS45102")
        self.assertEqual(format_asn_isp("AS45102", "Claw Cloud"), "AS45102 Alibaba Cloud (Claw Cloud)")
        self.assertEqual(clean_asn("BageVM"), "AS14061")
        self.assertEqual(format_asn_isp("AS14061", "BageVM"), "AS14061 DigitalOcean (BageVM)")

        # 验证 Eweka (AS34343) 归入 isp
        self.assertEqual(clean_asn("Eweka Internet Services B.V."), "AS34343")
        self.assertEqual(classify_asn("AS34343", "Eweka Internet Services B.V."), "isp")

        # 验证石家庄电信 CHINANET 准确指向 AS4134
        self.assertEqual(clean_asn("Shijiazhuang IDC network, CHINANET Hebei province"), "AS4134")
        self.assertEqual(format_asn_isp("AS4134"), "AS4134 China Telecom")

        # 验证 Ting Fiber Inc. 权威归属 AS32133 (ISP)
        self.assertEqual(clean_asn("Ting Fiber Inc."), "AS32133")
        self.assertEqual(classify_asn("AS32133"), "isp")

    def test_normalize_timestamp(self):
        # 8 位纯数字日期必须原样保留，严禁误转换为 1970 年时间戳
        self.assertEqual(normalize_timestamp("20260906"), "20260906")
        self.assertEqual(normalize_timestamp("20261001"), "20261001")

        # 标准 ISO 字符串原样保留
        iso_str = "2026-10-01 12:30:45"
        self.assertEqual(normalize_timestamp(iso_str), iso_str)

        # 毫秒时间戳转换
        ms_ts = "1727784000000"
        converted = normalize_timestamp(ms_ts)
        self.assertTrue(converted.startswith("2024-") or converted.startswith("202"))

    def test_classify_asn(self):
        # 权威 exact_net_type
        self.assertEqual(classify_asn("AS13335", "Cloudflare"), "datacenter")
        # 运营商宽带
        self.assertEqual(classify_asn("AS4134", "China Telecom"), "isp")
        # 海外/东欧/东南亚/中东/拉美/大洋洲头部电信运营商 (Yettel / One NZ / Algar / du / SPT / CS LOXINFO / MTS / MegaFon / Rostelecom)
        for asn, isp in [
            ("AS31042", "Yettel d.o.o."),
            ("AS9500", "One New Zealand"),
            ("AS16735", "ALGAR TELECOM"),
            ("AS57187", "du (EITC)"),
            ("AS7602", "Sai gon Postel"),
            ("AS9891", "CS LOXINFO"),
            ("AS13055", "MTS PJSC"),
            ("AS25159", "PJSC MegaFon"),
            ("AS42610", "Rostelecom"),
            ("AS25106", "MTS JLLC"),
        ]:
            self.assertEqual(classify_asn(asn, isp), "isp")
        # 启发式关键词兜底匹配
        self.assertEqual(classify_asn("", "Rostelecom Regional Network"), "isp")
        self.assertEqual(classify_asn("", "PJSC MegaFon Broadband"), "isp")
        # 教育网
        self.assertEqual(classify_asn("AS24168", "CERNET2"), "education")
        # 银行金融专网
        self.assertEqual(classify_asn("AS138139", "Reserve Bank of Australia"), "banking")


class TestTgFetchWorkflow(unittest.TestCase):
    def test_load_existing_proxies_fallback_and_tombstone(self):
        with tempfile.TemporaryDirectory() as td:
            txt_path = os.path.join(td, "proxies.txt")
            csv_path = os.path.join(td, "proxies.csv")

            # 写入 CSV 包含一条同 Key 重复（待择优）记录
            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["url", "fail_count", "delay_ms", "status", "colo", "egress_ip", "tested_at", "first_seen"],
                )
                writer.writeheader()
                # 记录 1 (健康度低: fail_count=2)
                writer.writerow({
                    "url": "socks5://user1:pass1@2.2.2.2:1080",
                    "fail_count": 2,
                    "delay_ms": 150,
                    "status": "fail",
                    "colo": "",
                    "egress_ip": "",
                    "tested_at": "2026-10-01 10:00:00",
                    "first_seen": "2026-09-01",
                })
                # 记录 2 (同 Key 更优: fail_count=0)
                writer.writerow({
                    "url": "socks5://user2:pass2@2.2.2.2:1080",
                    "fail_count": 0,
                    "delay_ms": 80,
                    "status": "alive",
                    "colo": "SJC",
                    "egress_ip": "198.51.100.2",
                    "tested_at": "2026-10-02 10:00:00",
                    "first_seen": "2026-09-01",
                })
                # 记录 3 (已在墓碑中的已知死节点: 157.90.251.25:3478)
                writer.writerow({
                    "url": "turn://157.90.251.25:3478",
                    "fail_count": 0,
                    "delay_ms": 50,
                    "status": "alive",
                    "colo": "",
                    "egress_ip": "157.90.251.25",
                    "tested_at": "2026-10-01 12:00:00",
                    "first_seen": "2026-09-01",
                })

            # 1. 验证 TXT 缺失时的 CSV 兜底（mock 墓碑包含测试死节点）
            from unittest.mock import patch
            import time
            mock_ts = {"157.90.251.25:3478": int(time.time())}
            with patch("tg_fetch.load_tombstone", return_value=mock_ts):
                loaded = load_existing_proxies(filepath=txt_path, csv_path=csv_path)
                self.assertIn("2.2.2.2:1080", loaded)
                # 优选 fail_count=0
                self.assertEqual(loaded["2.2.2.2:1080"]["fail_count"], 0)
                self.assertEqual(loaded["2.2.2.2:1080"]["colo"], "SJC")
                self.assertEqual(loaded["2.2.2.2:1080"]["egress_ip"], "198.51.100.2")
                # 墓碑死节点必须被拦截
                self.assertNotIn("157.90.251.25:3478", loaded)

                # 2. 验证 TXT 存在时的 key 映射关联
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write("SOCKS5://user_new:pass_new@2.2.2.2:1080\n")
                    f.write("http://4.4.4.4:8080\n")

                loaded_txt = load_existing_proxies(filepath=txt_path, csv_path=csv_path)
                self.assertIn("2.2.2.2:1080", loaded_txt)
                self.assertEqual(loaded_txt["2.2.2.2:1080"]["fail_count"], 0)
                self.assertEqual(loaded_txt["2.2.2.2:1080"]["egress_ip"], "198.51.100.2")
                self.assertIn("4.4.4.4:8080", loaded_txt)
                self.assertEqual(loaded_txt["4.4.4.4:8080"]["fail_count"], 0)
                self.assertEqual(loaded_txt["4.4.4.4:8080"]["egress_ip"], "")

    def test_save_scan_ips_by_asn_sanitizes_filenames(self):
        with tempfile.TemporaryDirectory() as td:
            # 构造包含路径分隔符、非法字符的 ASN 分组键
            asn_groups = {
                "MobileOne Ltd. Mobile/Internet Service Provider Singapore": [
                    {"ip": "1.1.1.1", "port": 443}
                ],
                "AS99999:Test*Group?": [
                    {"ip": "2.2.2.2", "port": 80}
                ]
            }
            # 调用写入，确保不会抛出 FileNotFoundError 或路径解析异常
            count = save_scan_ips_by_asn(asn_groups, td)
            self.assertEqual(count, 2)

            files = os.listdir(td)
            self.assertEqual(len(files), 2)
            # 确认所有生成的文件名均不含非法分隔符且均以 .txt 结尾
            for fname in files:
                self.assertTrue(fname.endswith(".txt"))
                self.assertNotIn("/", fname)
                self.assertNotIn("\\", fname)
                self.assertNotIn(":", fname)
                self.assertNotIn("*", fname)
                self.assertNotIn("?", fname)


class TestProxiesVerifyAndExport(unittest.TestCase):
    def test_proxy_csv_fields_contains_country_egress_ip_asn_isp_net_type(self):
        self.assertIn("country", PROXY_CSV_FIELDS)
        self.assertIn("egress_ip", PROXY_CSV_FIELDS)
        self.assertIn("asn", PROXY_CSV_FIELDS)
        self.assertIn("isp", PROXY_CSV_FIELDS)
        self.assertIn("net_type", PROXY_CSV_FIELDS)
        colo_idx = PROXY_CSV_FIELDS.index("colo")
        country_idx = PROXY_CSV_FIELDS.index("country")
        egress_idx = PROXY_CSV_FIELDS.index("egress_ip")
        asn_idx = PROXY_CSV_FIELDS.index("asn")
        isp_idx = PROXY_CSV_FIELDS.index("isp")
        net_type_idx = PROXY_CSV_FIELDS.index("net_type")
        self.assertEqual(country_idx, colo_idx + 1)
        self.assertEqual(egress_idx, country_idx + 1)
        self.assertEqual(asn_idx, egress_idx + 1)
        self.assertEqual(isp_idx, asn_idx + 1)
        self.assertEqual(net_type_idx, isp_idx + 1)

    def test_save_proxies_csv_and_by_protocol_persists_egress_ip_and_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "proxies.csv")
            proxies_dir = os.path.join(td, "proxies")
            json_path = os.path.join(td, "proxies.json")
            sample_rows = [
                {
                    "url": "socks5://user:pass@1.1.1.1:1080",
                    "proto": "socks5",
                    "host": "1.1.1.1",
                    "port": 1080,
                    "delay_ms": 120,
                    "fail_count": 0,
                    "status": "alive",
                    "colo": "HKG",
                    "country": "HK",
                    "egress_ip": "1.1.1.100",
                    "asn": "AS13335 Cloudflare",
                    "isp": "Cloudflare, Inc.",
                    "net_type": "datacenter",
                    "tested_at": "2026-10-03 12:00:00",
                    "first_seen": "2026-10-01 00:00:00",
                }
            ]
            # 1. 验证 save_proxies_csv
            count = save_proxies_csv(sample_rows, csv_path=csv_path)
            self.assertEqual(count, 1)
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["colo"], "HKG")
                self.assertEqual(rows[0]["country"], "HK")
                self.assertEqual(rows[0]["egress_ip"], "1.1.1.100")
                self.assertEqual(rows[0]["asn"], "AS13335 Cloudflare")
                self.assertEqual(rows[0]["isp"], "Cloudflare, Inc.")
                self.assertEqual(rows[0]["net_type"], "datacenter")

            # 2. 验证 save_proxies_by_protocol 生成 CSV 与 JSON
            proto_counts = save_proxies_by_protocol(sample_rows, output_dir=proxies_dir)
            self.assertIn("socks5", proto_counts)
            socks5_csv = os.path.join(proxies_dir, "socks5.csv")
            socks5_json = os.path.join(proxies_dir, "socks5.json")
            self.assertTrue(os.path.isfile(socks5_csv))
            self.assertTrue(os.path.isfile(socks5_json))
            with open(socks5_csv, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["country"], "HK")
                self.assertEqual(rows[0]["egress_ip"], "1.1.1.100")
                self.assertEqual(rows[0]["asn"], "AS13335 Cloudflare")
                self.assertEqual(rows[0]["isp"], "Cloudflare, Inc.")
                self.assertEqual(rows[0]["net_type"], "datacenter")

            with open(socks5_json, "r", encoding="utf-8") as f:
                json_items = json.load(f)
                self.assertEqual(len(json_items), 1)
                item = json_items[0]
                self.assertEqual(item["proxy"], "socks5://user:pass@1.1.1.1:1080")
                self.assertEqual(item["protocol"], "socks5")
                self.assertEqual(item["ip"], "1.1.1.1")
                self.assertEqual(item["port"], 1080)
                self.assertEqual(item["country"], "HK")
                self.assertEqual(item["country_cn"], "中国香港")
                self.assertEqual(item["country_emoji"], "🇭🇰")
                self.assertEqual(item["asn"], "13335")
                self.assertEqual(item["isp"], "Cloudflare, Inc.")
                self.assertEqual(item["asOrganization"], "Cloudflare, Inc.")
                self.assertEqual(item["net_type"], "datacenter")
                self.assertNotIn("delay_ms", item)
                self.assertNotIn("colo", item)
                self.assertNotIn("egress_ip", item)
                self.assertNotIn("tested_at", item)

            # 3. 验证 save_proxies_json 全量导出
            j_count = save_proxies_json(sample_rows, json_path=json_path)
            self.assertEqual(j_count, 1)
            self.assertTrue(os.path.isfile(json_path))
            with open(json_path, "r", encoding="utf-8") as f:
                all_items = json.load(f)
                self.assertEqual(len(all_items), 1)
                self.assertEqual(all_items[0]["proxy"], "socks5://user:pass@1.1.1.1:1080")

    def test_probe_single_and_parse_proxy_url_egress_ip(self):
        from proxies_verify import parse_proxy_url, probe_single
        import asyncio
        from unittest.mock import patch

        # 1. 验证 parse_proxy_url 默认包含 country, egress_ip, asn, isp, net_type
        parsed = parse_proxy_url("socks5://1.2.3.4:1080")
        self.assertIsNotNone(parsed)
        self.assertIn("country", parsed)
        self.assertIn("egress_ip", parsed)
        self.assertIn("asn", parsed)
        self.assertIn("isp", parsed)
        self.assertIn("net_type", parsed)
        self.assertEqual(parsed["country"], "")
        self.assertEqual(parsed["egress_ip"], "")
        self.assertEqual(parsed["asn"], "")
        self.assertEqual(parsed["isp"], "")
        self.assertEqual(parsed["net_type"], "")

        # 2. 验证 probe_single 在 mock probe 下成功填充 country 与 egress_ip
        async def _test():
            sem = asyncio.Semaphore(10)
            mock_row = {
                "proto": "socks5",
                "host": "1.2.3.4",
                "port": 1080,
                "url": "socks5://1.2.3.4:1080",
                "egress_ip": "",
            }
            with patch("proxies_verify.probe_socks5", return_value=(True, 88, "alive", "NRT", "JP", "203.0.113.19")):
                res = await probe_single(mock_row, sem)
                self.assertEqual(res["colo"], "NRT")
                self.assertEqual(res["country"], "JP")
                self.assertEqual(res["egress_ip"], "203.0.113.19")
                self.assertEqual(res["status"], "alive")

            # 3. 验证探测失败时保留既有 country 与 egress_ip (使用 copy 避免 dict mutate 副作用, T2)
            with patch("proxies_verify.probe_socks5", return_value=(False, 0, "conn_err", "", "", "")):
                res_fail = await probe_single(res.copy(), sem)
                self.assertEqual(res_fail["country"], "JP")
                self.assertEqual(res_fail["egress_ip"], "203.0.113.19")
                self.assertEqual(res_fail["fail_count"], 1)

        asyncio.run(_test())

    def test_probe_turn_and_sstp_return_resolved_egress_ip(self):
        from proxies_verify import probe_turn, probe_sstp
        import asyncio
        from unittest.mock import patch, AsyncMock, MagicMock

        async def _test():
            # 1. Mock TURN connection
            mock_reader = AsyncMock()
            mock_writer = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.wait_closed = AsyncMock()
            written = []
            mock_writer.write = lambda data: written.append(data)

            async def _dynamic_read(n):
                req = written[0]
                tx_id = req[8:20]
                return b"\x01\x01\x00\x00\x21\x12\xa4\x42" + tx_id

            mock_reader.read = _dynamic_read

            async def _fake_turn_conn(*args, **kwargs):
                return mock_reader, mock_writer

            with patch("proxies_verify.resolve_domain_to_ip", return_value="93.184.216.34"), \
                 patch("asyncio.open_connection", side_effect=_fake_turn_conn):
                alive, lat, status, colo, country, egress_ip = await probe_turn("stun.example.com", 3478)
                self.assertTrue(alive)
                self.assertEqual(egress_ip, "93.184.216.34")

            # 2. Mock SSTP connection
            mock_sstp_reader = AsyncMock()
            mock_sstp_writer = MagicMock()
            mock_sstp_writer.drain = AsyncMock()
            mock_sstp_writer.wait_closed = AsyncMock()
            mock_sstp_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

            async def _fake_sstp_conn(*args, **kwargs):
                return mock_sstp_reader, mock_sstp_writer

            with patch("proxies_verify.resolve_domain_to_ip", return_value="93.184.216.35"), \
                 patch("asyncio.open_connection", side_effect=_fake_sstp_conn):
                alive, lat, status, colo, country, egress_ip = await probe_sstp("vpn.example.com", 443)
                self.assertTrue(alive)
                self.assertEqual(egress_ip, "93.184.216.35")

        asyncio.run(_test())

    def test_normalize_endpoint_and_build_sstp_url(self):
        from proxies_verify import normalize_endpoint, build_sstp_url

        # normalize_endpoint
        self.assertEqual(normalize_endpoint(None), "")
        self.assertEqual(normalize_endpoint(""), "")
        self.assertEqual(normalize_endpoint("off"), "")
        self.assertEqual(normalize_endpoint("NONE"), "")
        self.assertEqual(normalize_endpoint("0"), "")
        self.assertEqual(normalize_endpoint("false"), "")
        self.assertEqual(normalize_endpoint("disabled"), "")
        self.assertEqual(
            normalize_endpoint("check.socks5.cmliussss.net/"),
            "https://check.socks5.cmliussss.net",
        )
        self.assertEqual(
            normalize_endpoint("http://myworker.dev/"),
            "http://myworker.dev",
        )

        # build_sstp_url
        self.assertEqual(
            build_sstp_url("vpn.example.com", 443),
            "sstp://vpn:vpn@vpn.example.com:443",
        )
        self.assertEqual(
            build_sstp_url("vpn.example.com", 443, "custom_u", "custom_p"),
            "sstp://custom_u:custom_p@vpn.example.com:443",
        )

    def test_sstp_cf_worker_stage2_verification(self):
        from proxies_verify import probe_single
        import asyncio
        from unittest.mock import patch, AsyncMock

        async def _test():
            sem = asyncio.Semaphore(10)
            base_row = {
                "url": "sstp://vpn:vpn@public-vpn-261.opengw.net:443",
                "proto": "sstp",
                "host": "public-vpn-261.opengw.net",
                "port": 443,
                "user": "vpn",
                "pwd": "vpn",
            }

            # 1. 成功案例：CF Worker 返回 success=True，真实出口 IP、国家与 ASN 结构化丰富
            mock_cf_success = {
                "success": True,
                "colo": "NRT",
                "exit": {
                    "ip": "219.100.37.244",
                    "country_code": "JP",
                    "asn": {
                        "asn": "AS36599",
                        "name": "SoftEther Telecommunication Research Institute, LLC",
                        "type": "isp",
                    },
                },
            }

            with patch("proxies_verify.probe_sstp", return_value=(True, 150, "alive", "-", "", "1.2.3.4")), \
                 patch("proxies_verify.check_sstp_exit_cf_worker", new_callable=AsyncMock, return_value=mock_cf_success):
                res = await probe_single(base_row.copy(), sem, cf_check_endpoint="https://check.socks5.cmliussss.net")
                self.assertTrue(res["is_alive"])
                self.assertEqual(res["egress_ip"], "219.100.37.244")
                self.assertEqual(res["country"], "JP")
                self.assertEqual(res["colo"], "NRT")
                self.assertIn("AS36599", res["asn"])

            # 2. 淘汰假活案例：本地 HTTP 200 初筛通过，但 CF Worker 全隧道 PPP 握手失败
            mock_cf_fail = {
                "success": False,
                "error": "SSTP server connection timed out",
            }

            with patch("proxies_verify.probe_sstp", return_value=(True, 150, "alive", "-", "", "1.2.3.4")), \
                 patch("proxies_verify.check_sstp_exit_cf_worker", new_callable=AsyncMock, return_value=mock_cf_fail):
                res = await probe_single(base_row.copy(), sem, cf_check_endpoint="https://check.socks5.cmliussss.net")
                self.assertFalse(res["is_alive"])
                self.assertEqual(res["status"], "sstp_vpn_fail")
                self.assertEqual(res["fail_count"], 1)

            # 3. 容灾回退案例：CF Worker 网络异常或超时 (返回 None)，平滑回退至本地探测结果
            with patch("proxies_verify.probe_sstp", return_value=(True, 150, "alive", "-", "", "1.2.3.4")), \
                 patch("proxies_verify.check_sstp_exit_cf_worker", new_callable=AsyncMock, return_value=None):
                res = await probe_single(base_row.copy(), sem, cf_check_endpoint="https://check.socks5.cmliussss.net")
                self.assertTrue(res["is_alive"])
                self.assertEqual(res["egress_ip"], "1.2.3.4")

        asyncio.run(_test())

    def test_enrich_proxies_metadata(self):
        from proxies_verify import enrich_proxies_metadata
        import asyncio
        from unittest.mock import patch

        async def _test():
            survivors = [
                {
                    "url": "socks5://1.1.1.1:1080",
                    "proto": "socks5",
                    "host": "1.1.1.1",
                    "egress_ip": "194.109.6.1",
                    "asn": "",
                    "isp": "",
                    "net_type": "",
                },
                {
                    "url": "socks5://2.2.2.2:1080",
                    "proto": "socks5",
                    "host": "2.2.2.2",
                    "egress_ip": "1.1.1.1",
                    "asn": "AS13335 Cloudflare",
                    "isp": "",
                    "net_type": "",
                },
            ]

            async def _mock_resolve(ip, isp_hint="", persist=False):
                if ip == "194.109.6.1":
                    return "AS34343", "Eweka Internet Services B.V."
                return "", ""

            with patch("proxies_verify.resolve_asn_online_async", side_effect=_mock_resolve):
                stats = await enrich_proxies_metadata(survivors)
                self.assertEqual(survivors[0]["asn"], "AS34343 Eweka Internet Services B.V.")
                self.assertEqual(survivors[0]["isp"], "Eweka Internet Services B.V.")
                self.assertEqual(survivors[0]["net_type"], "isp")
                self.assertEqual(survivors[1]["asn"], "AS13335 Cloudflare")
                self.assertEqual(survivors[1]["isp"], "Cloudflare")
                self.assertEqual(survivors[1]["net_type"], "datacenter")
                self.assertEqual(stats.get("isp"), 1)
                self.assertEqual(stats.get("datacenter"), 1)

        asyncio.run(_test())

    def test_resolve_asn_batch_online(self):
        from providers import (
            resolve_asn_batch_online,
            is_valid_public_ip,
            load_ip_cache,
            save_ip_cache,
        )
        from unittest.mock import patch, MagicMock
        import json

        # 1. IP 鉴真工具测试
        self.assertTrue(is_valid_public_ip("8.8.8.8"))
        self.assertTrue(is_valid_public_ip("184.178.172.17"))
        self.assertFalse(is_valid_public_ip("127.0.0.1"))
        self.assertFalse(is_valid_public_ip("192.168.1.1"))
        self.assertFalse(is_valid_public_ip("10.0.0.1"))
        self.assertFalse(is_valid_public_ip(""))
        self.assertFalse(is_valid_public_ip("not_an_ip"))

        # 2. 批量在线解析器模拟响应测试
        fake_api_response = [
            {
                "status": "success",
                "query": "184.178.172.17",
                "as": "AS22773 Cox Communications Inc.",
                "isp": "Cox Communications Inc.",
                "org": "Cox Communications Inc.",
                "asname": "ASN-CXA",
                "countryCode": "US",
            },
            {
                "status": "success",
                "query": "8.210.208.201",
                "as": "AS45102 Alibaba (US) Technology Co., Ltd.",
                "isp": "Alibaba (US) Technology Co., Ltd.",
                "org": "Alibaba Cloud",
                "asname": "ALIBABA-CN-NET",
                "countryCode": "HK",
            },
        ]

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_api_response).encode("utf-8")
        mock_resp.headers = {"X-Rl": "14", "X-Ttl": "50"}
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            results = resolve_asn_batch_online(["184.178.172.17", "8.210.208.201"], persist=False)
            self.assertIn("184.178.172.17", results)
            self.assertEqual(results["184.178.172.17"][0], "AS22773")
            self.assertEqual(results["184.178.172.17"][1], "Cox Communications Inc.")

            # SSOT 权威收录覆盖验证 (AS45102 自动收录为 Alibaba Cloud)
            self.assertIn("8.210.208.201", results)
            self.assertEqual(results["8.210.208.201"][0], "AS45102")
            self.assertEqual(results["8.210.208.201"][1], "Alibaba Cloud")

    def test_doh_and_domain_resolution(self):
        from providers import doh_resolve_public_ip, resolve_domain_to_ip
        from unittest.mock import patch, MagicMock
        import json

        # 1. 模拟 DoH 成功解析 A 记录
        fake_doh_resp = {
            "Status": 0,
            "Answer": [
                {"name": "test.opengw.net", "type": 1, "TTL": 60, "data": "219.100.37.30"}
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_doh_resp).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            ip = doh_resolve_public_ip("test.opengw.net")
            self.assertEqual(ip, "219.100.37.30")

        # 2. 模拟 socket.gethostbyname 返回受污染回环 IP 时，自动回退到 DoH
        with patch("socket.gethostbyname", return_value="127.236.0.63"):
            with patch("urllib.request.urlopen", return_value=mock_resp):
                ip = resolve_domain_to_ip("test.opengw.net")
                self.assertEqual(ip, "219.100.37.30")

    def test_parse_cf_ip_speed_units(self):
        from parsers import parse_cf_ip

        # 1. 括号内标注 MB/s
        text_mb = "节点测试\nIP地址: 1.1.1.1\n端口: 443\n速度(MB/s): 45"
        res_mb = parse_cf_ip(text_mb)
        self.assertIsNotNone(res_mb)
        self.assertEqual(res_mb["speed_kbs"], 45 * 1024)

        # 2. 括号内标注 kB/s（数值 < 50 时严禁误判为 MB/s）
        text_kb = "节点测试\nIP地址: 1.1.1.1\n端口: 443\n速度(kB/s): 45"
        res_kb = parse_cf_ip(text_kb)
        self.assertIsNotNone(res_kb)
        self.assertEqual(res_kb["speed_kbs"], 45)

        # 3. 冒号后标注 MB/s
        text_post = "节点测试\nIP地址: 1.1.1.1\n端口: 443\n下载速度: 12.5 MB/s"
        res_post = parse_cf_ip(text_post)
        self.assertIsNotNone(res_post)
        self.assertEqual(res_post["speed_kbs"], int(12.5 * 1024))

    def test_scrape_channel_web_order_and_cutoff(self):
        from unittest.mock import patch
        from datetime import datetime, timezone
        from tg_fetch import scrape_channel_web

        # 模拟 Telegram 网页 Preview HTML：
        # 页面顶部是最旧消息 (ID 100, 2026-09-25)，底部是最新消息 (ID 102, 2026-10-04)
        mock_html = (
            '<html><body>'
            '<div class="tgme_widget_message_wrap" data-post="testchan/100">'
            '  <time datetime="2026-09-25T10:00:00+00:00"></time>'
            '  <div class="tgme_widget_message_text">http://1.1.1.1:80</div>'
            '</div>'
            '<div class="tgme_widget_message_wrap" data-post="testchan/101">'
            '  <time datetime="2026-10-02T10:00:00+00:00"></time>'
            '  <div class="tgme_widget_message_text">http://2.2.2.2:80</div>'
            '</div>'
            '<div class="tgme_widget_message_wrap" data-post="testchan/102">'
            '  <time datetime="2026-10-04T12:00:00+00:00"></time>'
            '  <div class="tgme_widget_message_text">http://3.3.3.3:80</div>'
            '</div>'
            '</body></html>'
        )

        cutoff = datetime(2026, 10, 1, tzinfo=timezone.utc)
        with patch("tg_fetch.fetch_web_page", return_value=mock_html):
            proxies, cf_ips = scrape_channel_web("@testchan", cutoff=cutoff)
            # 必须成功解析出最新两条 (102 与 101)，而早于 cutoff 的第 100 条被过滤跳过
            urls = [p[0] for p in proxies]
            self.assertIn("http://3.3.3.3:80", urls)
            self.assertIn("http://2.2.2.2:80", urls)
            self.assertNotIn("http://1.1.1.1:80", urls)

    def test_providers_preserves_custom_txt_files(self):
        from providers import save_proxyip_by_country
        with tempfile.TemporaryDirectory() as td:
            custom_file = os.path.join(td, "custom_list.txt")
            manual_file = os.path.join(td, "manual_backup.txt")
            stale_file = os.path.join(td, "stale_country.txt")
            with open(custom_file, "w") as f:
                f.write("1.2.3.4:8080\n")
            with open(manual_file, "w") as f:
                f.write("5.6.7.8:8080\n")
            with open(stale_file, "w") as f:
                f.write("9.9.9.9:8080\n")

            rows = [{"ip": "8.8.8.8", "port": 443, "cf_location": "US", "colo": "SJC", "net_type": "datacenter"}]
            save_proxyip_by_country(rows, td)

            # custom_ 和 manual_ 文件必须保留
            self.assertTrue(os.path.exists(custom_file))
            self.assertTrue(os.path.exists(manual_file))
            # 未在 active_files 且无保护前缀的旧文件被清理
            self.assertFalse(os.path.exists(stale_file))

    def test_prune_tombstone(self):
        from providers import prune_tombstone, record_tombstone, load_tombstone
        import time

        with tempfile.TemporaryDirectory() as td:
            tombstone_file = os.path.join(td, "tombstone.json")
            now = int(time.time())

            # 写入 1 条新鲜记录 (1天前) + 2 条过期记录 (8天前, 10天前)
            data = {
                "1.1.1.1:80": now - 86400,
                "2.2.2.2:80": now - 8 * 86400,
                "3.3.3.3:80": now - 10 * 86400,
            }
            with open(tombstone_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

            # 1. 验证 prune_tombstone 正确剔除 2 条过期条目
            pruned = prune_tombstone(filepath=tombstone_file, max_age_days=7)
            self.assertEqual(pruned, 2)

            # 2. 检查磁盘物理文件内容
            with open(tombstone_file, "r", encoding="utf-8") as f:
                remaining = json.load(f)
            self.assertEqual(len(remaining), 1)
            self.assertIn("1.1.1.1:80", remaining)
            self.assertNotIn("2.2.2.2:80", remaining)

            # 3. 再次运行无过期条目时返回 0 且无冗余写
            pruned_again = prune_tombstone(filepath=tombstone_file, max_age_days=7)
            self.assertEqual(pruned_again, 0)

            # 4. 验证 record_tombstone 传入空列表时也会自动触发修剪
            remaining["4.4.4.4:80"] = now - 9 * 86400
            with open(tombstone_file, "w", encoding="utf-8") as f:
                json.dump(remaining, f)
            added = record_tombstone([], filepath=tombstone_file, max_age_days=7)
            self.assertEqual(added, 0)
            loaded = load_tombstone(filepath=tombstone_file, max_age_days=7, force_reload=True)
            self.assertNotIn("4.4.4.4:80", loaded)


if __name__ == "__main__":
    unittest.main()



