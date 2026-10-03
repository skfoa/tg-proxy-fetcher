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

    def test_extract_proxies_case_insensitive(self):
        # 支持大小写 scheme
        text = "SOCKS5://user:pass@1.2.3.4:1080\nHTTP://5.6.7.8:8080"
        proxies = extract_proxies(text)
        self.assertEqual(len(proxies), 2)
        self.assertEqual(proxies[0], ("SOCKS5://user:pass@1.2.3.4:1080", "1.2.3.4:1080"))
        self.assertEqual(proxies[1], ("HTTP://5.6.7.8:8080", "5.6.7.8:8080"))


class TestProviders(unittest.TestCase):
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
                    fieldnames=["url", "fail_count", "delay_ms", "status", "colo", "tested_at", "first_seen"],
                )
                writer.writeheader()
                # 记录 1 (健康度低: fail_count=2)
                writer.writerow({
                    "url": "socks5://user1:pass1@2.2.2.2:1080",
                    "fail_count": 2,
                    "delay_ms": 150,
                    "status": "fail",
                    "colo": "",
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
                    "tested_at": "2026-10-01 12:00:00",
                    "first_seen": "2026-09-01",
                })

            # 1. 验证 TXT 缺失时的 CSV 兜底
            loaded = load_existing_proxies(filepath=txt_path, csv_path=csv_path)
            self.assertIn("2.2.2.2:1080", loaded)
            # 优选 fail_count=0
            self.assertEqual(loaded["2.2.2.2:1080"]["fail_count"], 0)
            self.assertEqual(loaded["2.2.2.2:1080"]["colo"], "SJC")
            # 墓碑死节点必须被拦截
            self.assertNotIn("157.90.251.25:3478", loaded)

            # 2. 验证 TXT 存在时的 key 映射关联
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("SOCKS5://user_new:pass_new@2.2.2.2:1080\n")
                f.write("http://4.4.4.4:8080\n")

            loaded_txt = load_existing_proxies(filepath=txt_path, csv_path=csv_path)
            self.assertIn("2.2.2.2:1080", loaded_txt)
            self.assertEqual(loaded_txt["2.2.2.2:1080"]["fail_count"], 0)
            self.assertIn("4.4.4.4:8080", loaded_txt)
            self.assertEqual(loaded_txt["4.4.4.4:8080"]["fail_count"], 0)

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


if __name__ == "__main__":
    unittest.main()
