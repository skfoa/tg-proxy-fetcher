#!/usr/bin/env python3
"""
云厂商、CDN、ASN 规范化全局映射及公共工具模块 (providers.py)
作为全系统单一真相源（Single Source of Truth），供全线抓取与质检脚本共享使用：
  1. KNOWN_CLOUD_PROVIDERS / ASN_TO_PROVIDER: 维护主流公有云、CDN、热门 VPS 与骨干网 ASN 标准名称。
  2. clean_asn() / format_asn_isp() / _extract_asn_code(): 统一 ASN 编号与『ASN + 服务商名称』一体化直观标签规范化提取。
  3. ASN_EXACT_NET_TYPE / classify_asn() / is_asn_recorded():
     方案 A+ 两级分层网络类型（ISP/BIZ/EDU/GOV/BANK/机房）识别引擎与收录判定。
  4. format_buffer_nodes_txt() / format_proxyip_txt() / format_scan_ips_txt() / format_proxies_txt() / save_proxyip_by_country():
     节点按质检可用性/缓冲状态分层输出（缓冲节点置顶、存活节点紧随）、通用代理按协议分段归类输出、按国家/地区聚合分组及稀缺高价值网络专线纯文本分类导出。
  5. load_dotenv() / safe_int(): 本地环境加载与安全类型转换。
  6. send_tg_message() / send_ci_failure_alert(): 统一 Telegram 消息推送与 Actions CI 失败秒级告警。
  7. canonical_key() / load_tombstone() / record_tombstone() / is_tombstoned():
     全生命周期淘汰死节点墓地记忆库与隔离冷却机制（默认 7 天自动修剪）。
  8. read_full_response() / split_header_body(): 异步安全网络流分块读取与 HTTP 报文头体切分。
  9. format_buffer_badge() / format_diff(): 质检缓冲标识徽章与增量差量数据统一格式化。
  10. save_scan_ips_by_asn(): 按 ASN 分组导出独立纯文本扫描优选节点列表。
"""

from __future__ import annotations

KNOWN_CLOUD_PROVIDERS = {
    # 头部公有云与 CDN 服务
    "cloudflare": ("AS13335", "Cloudflare"),
    "cf": ("AS13335", "Cloudflare"),
    "fastly": ("AS54113", "Fastly"),
    "aliyun": ("AS45102", "Alibaba Cloud"),
    "alibaba": ("AS45102", "Alibaba Cloud"),
    "alicloud": ("AS45102", "Alibaba Cloud"),
    "tencent": ("AS132203", "Tencent Cloud"),
    "qcloud": ("AS132203", "Tencent Cloud"),
    "tencent_cn": ("AS45090", "Tencent Cloud"),
    "hwcloud": ("AS136907", "Huawei Cloud"),
    "huawei": ("AS136907", "Huawei Cloud"),
    "huaweicloud": ("AS136907", "Huawei Cloud"),
    "ucloud": ("AS138915", "UCloud"),
    "baidu": ("AS38365", "Baidu Cloud"),
    "bce": ("AS38365", "Baidu Cloud"),
    "volcengine": ("AS138699", "ByteDance Volcengine"),
    "bytedance": ("AS138699", "ByteDance Volcengine"),
    "jdcloud": ("AS44907", "JD Cloud"),
    "jcloud": ("AS44907", "JD Cloud"),
    "ksyun": ("AS45062", "Kingsoft Cloud"),
    "kingsoft": ("AS45062", "Kingsoft Cloud"),
    "qiniu": ("AS152644", "Qiniu Cloud"),
    "qiniucloud": ("AS152644", "Qiniu Cloud"),

    # 国际主流公有云
    "aws": ("AS16509", "Amazon AWS"),
    "amazon": ("AS16509", "Amazon AWS"),
    "lightsail": ("AS16509", "Amazon Lightsail"),
    "azure": ("AS8075", "Microsoft Azure"),
    "microsoft": ("AS8075", "Microsoft Azure"),
    "gcp": ("AS15169", "Google Cloud"),
    "google": ("AS15169", "Google Cloud"),
    "oracle": ("AS31898", "Oracle Cloud"),
    "oci": ("AS31898", "Oracle Cloud"),
    "digitalocean": ("AS14061", "DigitalOcean"),
    "vultr": ("AS20473", "Vultr"),
    "choopa": ("AS20473", "Vultr"),
    "linode": ("AS63949", "Linode Akamai"),
    "akamai": ("AS63949", "Linode Akamai"),
    "hetzner": ("AS24940", "Hetzner"),
    "ovh": ("AS16276", "OVH"),
    "scaleway": ("AS12876", "Scaleway"),
    "leaseweb": ("AS60781", "Leaseweb"),
    "kamatera": ("AS35838", "Kamatera"),
    "kamatera_us": ("AS204548", "Kamatera"),
    "amazon_infra": ("AS14618", "Amazon AWS"),
    "google_infra": ("AS396982", "Google Cloud"),
    "softlayer": ("AS36351", "SoftLayer Technologies Inc."),
    "ibmcloud": ("AS36351", "SoftLayer Technologies Inc."),

    # 热门 VPS / 优选反代服务商 (圈内高频出现)
    "akile": ("AS61112", "AkileCloud"),
    "akilecloud": ("AS61112", "AkileCloud"),
    "dmit": ("AS906", "DMIT"),
    "dmitcloud": ("AS906", "DMIT"),
    "netcrew": ("AS906", "DMIT"),
    "bandwagon": ("AS25820", "BandwagonHost"),
    "bwg": ("AS25820", "BandwagonHost"),
    "it7": ("AS25820", "BandwagonHost"),
    # 下游分销/租户品牌（无独立 ASN，现网复用阿里云 AS45102 基础设施；first-win 确保反查标准名锁定为 Alibaba Cloud）
    "claw": ("AS45102", "Claw Cloud"),
    "clawcloud": ("AS45102", "Claw Cloud"),
    "vmiss": ("AS147049", "VMISS"),
    "contabo": ("AS51167", "Contabo"),
    "netcup": ("AS197540", "Netcup"),
    "hostpapa": ("AS36352", "HostPapa"),
    "colocrossing": ("AS36352", "ColoCrossing"),
    "racknerd": ("AS36352", "RackNerd"),
    "buyvm": ("AS53667", "BuyVM FranTech"),
    "frantech": ("AS53667", "BuyVM FranTech"),
    "hostdare": ("AS397373", "HostDare"),
    "pegtech": ("AS54600", "PEG TECH INC"),
    "misaka": ("AS54600", "Misaka"),
    "kurun": ("AS13768", "Kurun Cloud"),
    "spartan": ("AS201106", "SpartanHost"),
    "spartanhost": ("AS201106", "SpartanHost"),
    "wap": ("AS149798", "WAP.ac"),
    # 下游分销/租户品牌（无独立 ASN，现网美西等节点复用 DigitalOcean AS14061；first-win 确保反查标准名锁定为 DigitalOcean）
    "bagevm": ("AS14061", "BageVM"),
    "netlab": ("AS979", "NetLab"),
    "zenlayer": ("AS21859", "Zenlayer"),
    "hostinger": ("AS47583", "Hostinger"),
    "m247": ("AS9009", "M247"),
    "datacamp": ("AS60068", "Datacamp Limited"),
    "aeza": ("AS210644", "Aeza"),
    "bytevirt": ("AS212336", "ByteVirt"),
    "starry": ("AS134835", "Starry Network"),
    "cyberverse": ("AS216211", "Cyberverse"),
    "isif": ("AS209554", "ISIF"),
    "evoxt": ("AS149440", "Evoxt"),
    "mvps": ("AS202448", "MVPS"),
    "zouter": ("AS205548", "Zouter"),
    "u1host": ("AS213877", "U1Host"),
    "bigdatahost": ("AS215346", "BigDataHost"),
    "biilru": ("AS215474", "BIILRU"),
    "h2nexus": ("AS215730", "H2NEXUS"),
    "serverstech": ("AS216071", "ServersTech"),
    "clodocloud": ("AS216154", "ClodoCloud"),
    "baxet": ("AS26383", "BaxetGroup"),
    "kirinonet": ("AS41378", "KirinoNET"),
    "vhglobal": ("AS42960", "VHGLOBAL"),
    "brainstorm": ("AS136258", "BrainStorm Network"),
    "xtom": ("AS8888", "xTom"),
    "virmach": ("AS3258", "VirMach"),
    "gtt": ("AS3257", "GTT Communications"),
    "vtal": ("AS8167", "V.tal"),
    "handynetworks": ("AS30475", "Handy Networks"),
    "veesp": ("AS42532", "VEESP"),
    "primesecurity": ("AS400618", "Prime Security"),
    "eons": ("AS138997", "Eons Data"),
    "neburst": ("AS8143", "Neburst Networks"),
    "xnnet": ("AS6134", "Xnnet"),
    "jttelecom": ("AS137535", "JT Telecom"),
    "maxwell": ("AS62711", "Maxwell Telecom"),
    "as56971": ("AS56971", "AS56971 Cloud"),
    "as3800": ("AS3800", "AS3800 LLC"),
    "ace": ("AS139341", "ACE Data Center"),
    "baykov": ("AS41745", "Baykov Ilya"),
    "hkt": ("AS4760", "HKT"),
    "koreatelecom": ("AS4766", "Korea Telecom"),
    "newserverlife": ("AS49791", "NewServerLife"),
    "nanoit": ("AS52173", "NanoIT"),
    "oneasiahost": ("AS59211", "OneAsiaHost"),
    "skbroadband": ("AS9318", "SK Broadband"),
    "digitalvirt": ("AS11161", "DigitalVirt"),
    "emagine": ("AS31972", "Emagine Concept"),
    "globalcommunication": ("AS152179", "Global Communication Network"),
    "hkglobal": ("AS152179", "Global Communication Network"),
    "halocloud": ("AS50385", "HaloCloud"),
    "desivps": ("AS133619", "DESIVPS"),
    "timeweb": ("AS210976", "Timeweb, LLP"),
    "globaltelehost": ("AS62563", "GlobalTeleHost Corp."),

    # 运营商骨干与出海线路
    "hinet": ("AS3462", "Chunghwa Telecom HiNet"),
    "cmi": ("AS58453", "China Mobile CMI"),
    "chinamobile": ("AS58453", "China Mobile CMI"),
    "cug": ("AS10099", "China Unicom CUG"),
    "chinaunicom": ("AS10099", "China Unicom CUG"),
    "chinatelecom": ("AS4134", "China Telecom"),
    "chinanet": ("AS4134", "China Telecom"),
    "chinatelecom_163": ("AS4134", "China Telecom 163"),
    "cn2": ("AS4809", "China Telecom CN2"),
    "chinatelecom_group": ("AS4811", "China Telecom"),
    "9929": ("AS9929", "China Unicom 9929"),
    "cmin2": ("AS58807", "China Mobile CMIN2"),
}

# ASN 到标准服务商名称反查表（内置权威已知云厂商/VPS/骨干网单一真相源 SSOT）
# 必须使用 first-win 策略：头部顶层公有云名称优先，后续小品牌别名（如 claw/bagevm）不覆盖主品牌
AUTHORITATIVE_CLOUD_ASNS: dict[str, str] = {}
for _asn, _isp in KNOWN_CLOUD_PROVIDERS.values():
    if _asn not in AUTHORITATIVE_CLOUD_ASNS:
        AUTHORITATIVE_CLOUD_ASNS[_asn] = _isp
ASN_TO_PROVIDER = dict(AUTHORITATIVE_CLOUD_ASNS)


# =====================================================================
# 公共实用工具：环境加载、类型转换、ASN 清洗、Telegram 推送与自检
# =====================================================================

import asyncio
import concurrent.futures
import csv
import functools
import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

log = logging.getLogger("providers")


# ---------- 持久化 ASN 数据库加载与在线动态解析补库 ----------

ASN_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "asn_database.json")
ASN_DATABASE_REL_PATH = os.path.join("data", "asn_database.json")


VALID_NET_TYPES: frozenset[str] = frozenset({"isp", "datacenter", "business", "education", "government", "banking"})

# 外部查询接口网络类型枚举映射表 (对齐至内部受控六大标准网络类型)
EXTERNAL_NET_TYPE_MAP: dict[str, str] = {
    # 住宅/民用宽带 (isp)
    "isp": "isp",
    "residential": "isp",
    "broadband": "isp",
    "dialup": "isp",
    "mobile": "isp",
    "cellular": "isp",
    # 数据中心/云服务 (datacenter)
    "datacenter": "datacenter",
    "hosting": "datacenter",
    "transit": "datacenter",
    "server": "datacenter",
    "cloud": "datacenter",
    "cdn": "datacenter",
    # 商业专线 (business)
    "business": "business",
    "corporate": "business",
    "commercial": "business",
    # 教育学术 (education)
    "education": "education",
    "edu": "education",
    "university": "education",
    # 政府政务 (government)
    "government": "government",
    "gov": "government",
    # 银行金融 (banking)
    "banking": "banking",
    "finance": "banking",
}


def normalize_external_asn_info(
    raw_asn: str | int | None = "",
    raw_isp: str = "",
    raw_type: str = "",
    isp_hint: str = "",
    external_type: str = "",
) -> tuple[str, str, str]:
    """
    统一适配不同查询网站/API/WHOIS 返回的异构字段格式，进行防脏清洗与标准对齐：
    返回 (clean_asn, clean_isp, net_type):
      - clean_asn: 规范化为 'AS' + 纯数字 (如 'AS4134')
      - clean_isp: 提取清洗后的服务商/组织机构名
      - net_type: 严格受控的六大标准枚举之一
    """
    clean_asn = ""
    if raw_asn:
        asn_str = str(raw_asn).strip()
        m = re.search(r"\bAS\s*(\d+)\b", asn_str, re.IGNORECASE)
        if m:
            clean_asn = f"AS{m.group(1)}"
        elif re.match(r"^\d+$", asn_str):
            clean_asn = f"AS{asn_str}"
        else:
            m2 = re.search(r"(?:AS)?\s*(\d+)", asn_str, re.IGNORECASE)
            if m2 and m2.group(1):
                clean_asn = f"AS{m2.group(1)}"

    clean_isp = (raw_isp or "").strip()
    if clean_isp:
        clean_isp = re.sub(r"^AS\d+\s*[-:]*\s*", "", clean_isp, flags=re.IGNORECASE).strip()
    if not clean_isp:
        clean_isp = (isp_hint or "").strip()

    target_type = raw_type or external_type
    normalized_type = ""
    if target_type:
        normalized_type = EXTERNAL_NET_TYPE_MAP.get(str(target_type).strip().lower(), "")

    if not normalized_type:
        normalized_type = classify_asn(clean_asn, clean_isp)

    return clean_asn, clean_isp, normalized_type


def validate_asn_database(db: dict | None = None) -> tuple[list[str], list[str]]:
    """
    对 ASN 数据库进行格式、完整性与防污染一致性校验。
    返回 (errors, warnings):
      - errors: 阻断性硬错误（非法格式、孤立无反向映射、空名称、SSOT 权威厂商名称篡改、非法 net_type）
      - warnings: 提示性告警（多业务线 1 对 N 自治域多重反查特征）
    """
    if db is None:
        db_path = ASN_DATABASE_PATH if os.path.isfile(ASN_DATABASE_PATH) else ASN_DATABASE_REL_PATH
        if not os.path.isfile(db_path):
            return ["数据库文件不存在"], []
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)

    i2a = db.get("isp_to_asn", {})
    a2i = db.get("asn_to_isp", {})
    a2nt = db.get("asn_to_net_type", {})
    errors: list[str] = []
    warnings: list[str] = []

    # 1. 格式鉴真与孤立检测
    for isp, asn in i2a.items():
        if not isp or not str(isp).strip():
            errors.append(f"[空名称] isp_to_asn 存在空服务商名称键指向 {asn}")
        if not re.match(r"^AS\d+$", str(asn or "")):
            errors.append(f"[非法ASN格式] isp_to_asn: '{isp}' -> '{asn}'")
        elif asn not in a2i:
            errors.append(f"[孤立映射] isp_to_asn 中 '{isp}' -> '{asn}'，但在 asn_to_isp 中无对应反查")

    for asn, isp in a2i.items():
        if not isp or not str(isp).strip():
            errors.append(f"[空名称] asn_to_isp 中 {asn} 对应服务商名称为空")
        if not re.match(r"^AS\d+$", str(asn or "")):
            errors.append(f"[非法ASN格式] asn_to_isp: '{asn}' -> '{isp}'")
        # 权威 SSOT 纯净性检测
        if asn in AUTHORITATIVE_CLOUD_ASNS and AUTHORITATIVE_CLOUD_ASNS[asn].lower() != str(isp).strip().lower():
            errors.append(f"[SSOT污染] asn_to_isp[{asn}] = '{isp}' 篡改了内置权威服务商 '{AUTHORITATIVE_CLOUD_ASNS[asn]}'")

    # 2. 1 对 N 多业务线与别名映射提示（如 AWS / Google 跨多个不同业务 ASN）
    for asn, std_name in a2i.items():
        if std_name in i2a:
            rev_asn = i2a[std_name]
            if rev_asn != asn:
                warnings.append(f"[1对N多业务线] {asn} 标准名 '{std_name}' 在正向索引中首选指向 {rev_asn}")

    # 3. 校验 asn_to_net_type 格式与受控类型 (允许存在无反查 ISP 名称的纯网络类型自治系统)
    for asn, n_type in a2nt.items():
        if not re.match(r"^AS\d+$", str(asn or "")):
            errors.append(f"[非法ASN格式] asn_to_net_type: '{asn}' -> '{n_type}'")
        if n_type not in VALID_NET_TYPES:
            errors.append(f"[未知网络类型] asn_to_net_type[{asn}] = '{n_type}' 不在受控类型范围")

    return errors, warnings


def load_asn_database(db_path: str = "") -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """从 data/asn_database.json 自动加载持久化 ASN/ISP/NetType 映射字典，并启动自检预警"""
    search_paths = [db_path] if db_path else [ASN_DATABASE_PATH, ASN_DATABASE_REL_PATH]
    for p in search_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    errs, warns = validate_asn_database(data)
                    if errs:
                        for e in errs:
                            log.error("【ASN数据库硬错误】%s", e)
                    if warns:
                        for w in warns:
                            log.debug("【ASN数据库拓扑提示】%s", w)
                    return (
                        data.get("isp_to_asn", {}),
                        data.get("asn_to_isp", {}),
                        data.get("asn_to_net_type", {}),
                    )
            except Exception as e:
                log.debug("读取 %s 异常: %s", p, e)
    return {}, {}, {}


def save_asn_database(
    isp_to_asn: dict[str, str],
    asn_to_isp: dict[str, str],
    asn_to_net_type: dict[str, str] | None = None,
    db_path: str = "",
):
    """持久化保存动态发现的 ASN/ISP/NetType 数据库（带格式鉴真、防冲突覆盖与 SSOT 保护）"""
    target_path = db_path or ASN_DATABASE_PATH
    try:
        clean_i2a: dict[str, str] = {}
        clean_a2i: dict[str, str] = {}
        clean_a2nt: dict[str, str] = {}

        # 1. 规范化加载传入的反向映射字典
        for k, v in asn_to_isp.items():
            asn_code = (k or "").strip().upper()
            isp_name = (v or "").strip()
            if re.match(r"^AS\d+$", asn_code) and isp_name:
                clean_a2i[asn_code] = isp_name

        # 2. 权威 SSOT 锁定：内置权威已知云厂商始终锁定为 SSOT 权威名称，坚决禁止被覆盖
        for asn_code, auth_name in AUTHORITATIVE_CLOUD_ASNS.items():
            if asn_code in clean_a2i and clean_a2i[asn_code] != auth_name:
                log.debug("ASN %s 权威映射维持: %s (替换手工/历史配置: %s)", asn_code, auth_name, clean_a2i[asn_code])
            clean_a2i[asn_code] = auth_name

        # 3. 规范化正向映射，并实施大小写不敏感去重与防冲突检查
        seen_lower_i2a: dict[str, str] = {}
        for k, v in isp_to_asn.items():
            isp_name = (k or "").strip()
            asn_code = (v or "").strip().upper()
            if not re.match(r"^AS\d+$", asn_code) or not isp_name:
                continue

            lower_name = isp_name.lower()
            if lower_name in seen_lower_i2a:
                existing_key = seen_lower_i2a[lower_name]
                if clean_i2a.get(existing_key) == asn_code:
                    continue

            clean_i2a[isp_name] = asn_code
            seen_lower_i2a[lower_name] = isp_name

            # 若反向字典已有该 ASN，检查是否与当前正向名称一致；若不一致仅记录，严禁篡改反向字典
            if asn_code in clean_a2i:
                if clean_a2i[asn_code] != isp_name:
                    log.debug("多对一服务商映射: %s 正向指向 %s，反向标准名称维持 %s", isp_name, asn_code, clean_a2i[asn_code])
            else:
                # 仅当反向完全缺失时进行安全补录，首个记录者锁定，后续多值不覆写
                clean_a2i[asn_code] = isp_name
                log.info("【自愈补齐反向索引】ASN %s 缺失反查名称，自动补录: %s", asn_code, isp_name)

        # 4. 规范化 asn_to_net_type：若未显式传入则取运行时 ASN_DATABASE_ASN_TO_NET_TYPE，绝对杜绝误抹除
        target_a2nt = asn_to_net_type if asn_to_net_type is not None else ASN_DATABASE_ASN_TO_NET_TYPE
        for k, v in target_a2nt.items():
            asn_code = (k or "").strip().upper()
            net_type = (v or "").strip().lower()
            if re.match(r"^AS\d+$", asn_code) and net_type in VALID_NET_TYPES:
                clean_a2nt[asn_code] = net_type

        # 5. 保存前进行硬错误阻断校验
        val_errors, _ = validate_asn_database({
            "isp_to_asn": clean_i2a,
            "asn_to_isp": clean_a2i,
            "asn_to_net_type": clean_a2nt,
        })
        if val_errors:
            log.error("拒绝持久化写入损坏的 ASN 数据库: %s", val_errors)
            return

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        tmp_target = f"{target_path}.tmp"
        with open(tmp_target, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "isp_to_asn": clean_i2a,
                    "asn_to_isp": clean_a2i,
                    "asn_to_net_type": clean_a2nt,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        os.replace(tmp_target, target_path)
        # 同步更新内存运行时字典
        ASN_DATABASE_ASN_TO_NET_TYPE.update(clean_a2nt)
        if "ASN_EXACT_NET_TYPE" in globals():
            ASN_EXACT_NET_TYPE.update(clean_a2nt)
    except Exception as e:
        log.warning("保存 asn_database.json 异常: %s", e)
        if "tmp_target" in locals() and os.path.exists(tmp_target):
            try:
                os.remove(tmp_target)
            except OSError:
                pass


# 加载持久化 ASN 数据库并融合进公共字典（加入防污染校验与格式鉴真）
ASN_DATABASE_ISP_TO_ASN, ASN_DATABASE_ASN_TO_ISP, ASN_DATABASE_ASN_TO_NET_TYPE = load_asn_database()
for _asn, _isp in ASN_DATABASE_ASN_TO_ISP.items():
    _asn_clean = (_asn or "").strip().upper()
    _isp_clean = (_isp or "").strip()
    if not re.match(r"^AS\d+$", _asn_clean):
        continue
    # 权威防污染锁定：坚决禁止外部持久化数据覆盖内置权威已知云厂商
    if _asn_clean in AUTHORITATIVE_CLOUD_ASNS:
        continue
    if _asn_clean not in ASN_TO_PROVIDER and _isp_clean:
        ASN_TO_PROVIDER[_asn_clean] = _isp_clean

# 生成排序别名元组（按关键词长度降序优先匹配更长更精确的名称，如 'huaweicloud' 优于 'huawei'）
# 保持 KNOWN_CLOUD_PROVIDERS 作为权威云厂商/VPS/骨干网词库的独立纯净性，杜绝注入数据库泛 ISP 产生子串碰撞
SORTED_CLOUD_PROVIDER_KEYS = tuple(sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True))
ASN_DATABASE_ISP_LOWER = {k.lower(): (v, k) for k, v in ASN_DATABASE_ISP_TO_ASN.items()}

# 核心基准骨干自治系统兜底定义（在外部 JSON 缺失或损坏时的基础防御）
_CORE_BASELINE_NET_TYPES: dict[str, str] = {
    "AS4134": "isp",     # 中国电信
    "AS4837": "isp",     # 中国联通
    "AS9808": "isp",     # 中国移动
    "AS13335": "datacenter", # Cloudflare
    "AS15169": "datacenter", # Google
    "AS16509": "datacenter", # Amazon AWS
    "AS8075": "datacenter",  # Microsoft Azure
    "AS45102": "datacenter", # Alibaba Cloud
    "AS132203": "datacenter", # Tencent Cloud
}

# 运行时 ASN 精准网络类型对照表（从 data/asn_database.json 动态加载，兼具核心兜底）
ASN_EXACT_NET_TYPE: dict[str, str] = dict(_CORE_BASELINE_NET_TYPES)
ASN_EXACT_NET_TYPE.update(ASN_DATABASE_ASN_TO_NET_TYPE)

# 自动将 KNOWN_CLOUD_PROVIDERS 中未单独显式指定类型的知名云厂商/机房补充进入 ASN_EXACT_NET_TYPE 默认为 datacenter
for _asn, _ in KNOWN_CLOUD_PROVIDERS.values():
    if _asn not in ASN_EXACT_NET_TYPE:
        ASN_EXACT_NET_TYPE[_asn] = "datacenter"


def resolve_asn_online(ip: str, isp_hint: str = "", persist: bool = False, db_path: str = "") -> tuple[str, str]:
    """
    当本地权威库与持久化库无法识别 ASN 时，在线向权威 BGP 数据库实时反查：
    返回 (clean_asn, clean_isp)。
    多通道高可用安全反查架构：
      - 通道 1 (首选)：ip-api.com (结构化解析: 优先取实际商业 ISP 运营商名称与 org，技术域别名 asname)
      - 通道 2 (备选)：iplocate.io (全量 HTTPS，免 Key，原生结构化 ASN 对象)
      - 通道 3 (备选)：ipapi.co (全量 HTTPS，免 Key 每日限额)
    核心防御与防污染机制：
      1. 纯数字/正则提取 AS\\d+，坚决抛弃 as 字段携带的物理注册大厦/街道门牌地址 (如 Tencent Building)
      2. 提取到 ASN 后优先执行 SSOT 校验：若命中本地权威字典 (ASN_TO_PROVIDER)，坚决使用标准服务商名，
         杜绝第三方 API 临时/工商长串/机房脏名称污染
      3. persist 参数默认为 False：反查结果仅保留在当前进程内存字典高速缓存中，不隐式污染磁盘文件；
         仅在离线专门维护阶段显式指定 persist=True 时才持久化写盘。
    """
    if not ip or ip in ("AS_UNKNOWN", "unknown", "127.0.0.1"):
        return "", ""

    clean_asn = ""
    clean_isp = ""
    ext_net_type = ""

    # 通道 1 (首选): ip-api.com (语义优先: 实际商业 isp > 组织机构 org > 路由技术别名 asname)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,asname,org,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            data = json.loads(res.read().decode("utf-8", errors="ignore"))
            if data.get("status") == "success":
                raw_as = str(data.get("as") or "")
                raw_isp_val = (data.get("isp") or "").strip()
                raw_org_val = (data.get("org") or "").strip()
                raw_asname_val = (data.get("asname") or "").strip()
                raw_isp = raw_isp_val or raw_org_val or raw_asname_val
                clean_asn, clean_isp, ext_net_type = normalize_external_asn_info(
                    raw_as, raw_isp, isp_hint=isp_hint
                )
    except Exception as e:
        log.debug("ip-api.com 在线解析 IP %s 失败: %s", ip, e)

    # 通道 2 (备选容灾): iplocate.io (HTTPS, 免 Key)
    if not clean_asn:
        try:
            url = f"https://www.iplocate.io/api/lookup/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3.5) as res:
                data = json.loads(res.read().decode("utf-8", errors="ignore"))
                asn_obj = data.get("asn") or {}
                clean_asn, clean_isp, ext_net_type = normalize_external_asn_info(
                    asn_obj.get("asn"),
                    asn_obj.get("name"),
                    raw_type=asn_obj.get("type", ""),
                    isp_hint=isp_hint,
                )
        except Exception as e:
            log.debug("iplocate.io 在线解析 IP %s 失败: %s", ip, e)

    # 通道 3 (备选容灾): ipapi.co (HTTPS, 免 Key)
    if not clean_asn:
        try:
            url = f"https://ipapi.co/{ip}/json/"
            req = urllib.request.Request(url, headers={"User-Agent": "ipapi.co/#python-v1.0.3"})
            with urllib.request.urlopen(req, timeout=3.5) as res:
                data = json.loads(res.read().decode("utf-8", errors="ignore"))
                clean_asn, clean_isp, ext_net_type = normalize_external_asn_info(data.get("asn"), data.get("org"), isp_hint=isp_hint)
        except Exception as e:
            log.debug("ipapi.co 在线解析 IP %s 失败: %s", ip, e)

    if clean_asn:
        # SSOT 权威优先机制：若该 ASN 已属于权威收录厂商（如 AS132203=Tencent Cloud, AS45102=Alibaba Cloud），
        # 坚决直接使用本地标准名，完全不受第三方 API 冗长工商全称或技术代号干扰
        if clean_asn in ASN_TO_PROVIDER:
            std_isp = ASN_TO_PROVIDER[clean_asn]
            log.debug("IP %s 命中权威已知 ASN %s: %s (忽略 API 原始标签: %s)", ip, clean_asn, std_isp, clean_isp)
            return clean_asn, std_isp

        # 若为全新未收录自治系统，更新本进程运行时内存字典高速缓存
        clean_isp = clean_isp or isp_hint
        if clean_isp and clean_isp not in ASN_DATABASE_ISP_TO_ASN:
            ASN_DATABASE_ISP_TO_ASN[clean_isp] = clean_asn
            ASN_DATABASE_ISP_LOWER[clean_isp.lower()] = (clean_asn, clean_isp)
        if clean_asn not in ASN_DATABASE_ASN_TO_ISP:
            ASN_DATABASE_ASN_TO_ISP[clean_asn] = clean_isp
        if clean_asn not in ASN_TO_PROVIDER:
            ASN_TO_PROVIDER[clean_asn] = clean_isp

        # 联动更新运行时网络类型 (net_type)
        if clean_asn not in ASN_EXACT_NET_TYPE:
            n_type = ext_net_type or classify_asn(clean_asn, clean_isp)
            ASN_EXACT_NET_TYPE[clean_asn] = n_type
            ASN_DATABASE_ASN_TO_NET_TYPE[clean_asn] = n_type

        if persist:
            save_asn_database(ASN_DATABASE_ISP_TO_ASN, ASN_DATABASE_ASN_TO_ISP, ASN_DATABASE_ASN_TO_NET_TYPE, db_path=db_path)
            log.info("【自动完善数据库】已在线反查新 IP %s 并持久化入库: %s -> %s (net_type: %s)", ip, clean_asn, clean_isp, ASN_EXACT_NET_TYPE.get(clean_asn))
        else:
            log.debug("【内存缓存更新】在线反查新 IP %s: %s -> %s (net_type: %s)", ip, clean_asn, clean_isp, ASN_EXACT_NET_TYPE.get(clean_asn))
        return clean_asn, clean_isp

    return "", ""


async def resolve_asn_online_async(ip: str, isp_hint: str = "", persist: bool = False, db_path: str = "") -> tuple[str, str]:
    """resolve_asn_online 的异步无阻塞封装，在独立工作线程中执行同步网络 I/O，杜绝阻塞事件循环"""
    return await asyncio.to_thread(resolve_asn_online, ip, isp_hint, persist, db_path)


# ---------- IP/域名 级别持久化元数据缓存 (data/ip_cache.json) ----------

IP_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ip_cache.json")
IP_CACHE_REL_PATH = os.path.join("data", "ip_cache.json")


def load_ip_cache() -> dict[str, dict]:
    """从 data/ip_cache.json 加载已解析的 IP/域名 -> ASN/ISP/net_type 高速缓存"""
    for p in (IP_CACHE_PATH, IP_CACHE_REL_PATH):
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception as e:
                log.debug("读取 %s 异常: %s", p, e)
    return {}


def save_ip_cache(cache: dict[str, dict], filepath: str = ""):
    """持久化保存 IP/域名 -> ASN/ISP/net_type 缓存字典至 data/ip_cache.json（原子写入）"""
    target_path = filepath or IP_CACHE_PATH
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    tmp_path = f"{target_path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, target_path)
    except Exception as e:
        log.warning("保存 %s 异常: %s", target_path, e)
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def is_valid_public_ip(ip_str: str) -> bool:
    """严格校验是否为合规公网 IPv4/IPv6，剔除回环、内网私有段、链路本地与组播"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except Exception:
        return False


def doh_resolve_public_ip(domain: str, timeout: float = 3.5) -> str:
    """通过安全加密 DNS (DoH) 解析域名，绕过本地 DNS 污染/劫持返回真实公网 IP"""
    if not domain or not isinstance(domain, str):
        return ""
    clean = domain.strip().lower()
    doh_endpoints = [
        f"https://1.1.1.1/dns-query?name={clean}&type=A",
        f"https://cloudflare-dns.com/dns-query?name={clean}&type=A",
        f"https://dns.google/resolve?name={clean}&type=A",
    ]
    for url in doh_endpoints:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0 (compatible; tg-proxy-fetcher/2.0)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                answers = data.get("Answer", [])
                if isinstance(answers, list):
                    for ans in answers:
                        if isinstance(ans, dict) and ans.get("type") == 1:
                            cand_ip = str(ans.get("data", "")).strip()
                            if is_valid_public_ip(cand_ip):
                                return cand_ip
        except Exception:
            continue
    return ""


@functools.lru_cache(maxsize=4096)
def resolve_domain_to_ip(domain: str) -> str:
    """尝试将域名解析为有效公网 IP，若失败或解析为保留/回环 IP 则依次尝试本地系统解析与 DoH 加密解析"""
    if not domain or not isinstance(domain, str):
        return ""
    clean = domain.strip().lower()
    if is_valid_public_ip(clean):
        return clean
    # 识别知名机房模式化反向 PTR 域名 (如 Hetzner: static.D.C.B.A.clients.your-server.de -> A.B.C.D)
    m_hetzner = re.match(r"^static\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.clients\.your-server\.de$", clean)
    if m_hetzner:
        rev_ip = f"{m_hetzner.group(4)}.{m_hetzner.group(3)}.{m_hetzner.group(2)}.{m_hetzner.group(1)}"
        if is_valid_public_ip(rev_ip):
            return rev_ip
    try:
        addr = socket.gethostbyname(clean)
        if is_valid_public_ip(addr):
            return addr
    except Exception:
        pass

    # 本地解析失败或被 DNS 污染拦截（如解析出 127.x.x.x 回环段），自动启用 DoH 权威查询兜底
    return doh_resolve_public_ip(clean)


def resolve_asn_batch_online(
    targets: list[str],
    max_chunk_size: int = 100,
    persist: bool = True,
    db_path: str = "",
    cache_path: str = "",
) -> dict[str, tuple[str, str]]:
    """
    高吞吐批量在线解析目标（IP 或域名）的 ASN 与 ISP：
    - 支持首次大规模全库同步与常态轻量增量解析
    - 优先读取并命中本地持久化 IP 缓存 (data/ip_cache.json)
    - 域名自动安全探测 DNS 解析为公网 IP (多线程并发 + DoH 防污染)
    - 基于 http://ip-api.com/batch 批量通道（单请求上限 100 IP，限额 15 req/min）
    - 动态解析响应头 X-Rl / X-Ttl 自适应限流退避，杜绝 429 封禁
    - 严格遵循 SSOT 权威收录规范与格式防污染清洗
    - 返回 target -> (clean_asn, clean_isp)
    """
    if not targets:
        return {}

    cache = load_ip_cache()
    results: dict[str, tuple[str, str]] = {}
    ip_to_targets: dict[str, list[str]] = {}
    cache_modified = False

    # 1. 第一轮快速初筛：区分已命中缓存、直接公网 IP、以及待解析域名
    unresolved_domains = set()
    cleaned_targets = []
    for t in targets:
        if not t or not isinstance(t, str):
            continue
        clean_t = t.strip()
        if not clean_t or clean_t in ("127.0.0.1", "localhost", "AS_UNKNOWN", "unknown"):
            continue
        cleaned_targets.append(clean_t)

        # 命中缓存 (需同时拥有有效 ASN 与国家代码，否则纳入增量补全)
        if clean_t in cache:
            item = cache[clean_t]
            asn = item.get("asn", "")
            isp = item.get("isp", "")
            country = item.get("country", "")
            if asn and country:
                results[clean_t] = (asn, isp)
                continue

        if not is_valid_public_ip(clean_t):
            # 若缓存已有合法 resolved_ip 则无需重新 DoH 解析
            if not (clean_t in cache and is_valid_public_ip(cache[clean_t].get("resolved_ip", ""))):
                unresolved_domains.add(clean_t)

    # 2. 对所有待解析域名进行多线程并发 DNS / DoH 解析
    domain_to_ip: dict[str, str] = {}
    if unresolved_domains:
        log.info("【域名 DNS 解析】正在并发解析 %d 个域名的真实公网 IP...", len(unresolved_domains))
        workers = min(36, max(4, len(unresolved_domains)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_dom = {pool.submit(resolve_domain_to_ip, dom): dom for dom in unresolved_domains}
            for fut in concurrent.futures.as_completed(future_to_dom):
                dom = future_to_dom[fut]
                try:
                    resolved = fut.result()
                    if resolved and is_valid_public_ip(resolved):
                        domain_to_ip[dom] = resolved
                except Exception as e:
                    log.debug("域名 %s 解析异常: %s", dom, e)

    # 3. 将目标归类到对应的公网 IP
    for clean_t in cleaned_targets:
        if clean_t in results:
            continue

        if is_valid_public_ip(clean_t):
            ip_to_targets.setdefault(clean_t, []).append(clean_t)
        else:
            resolved_ip = domain_to_ip.get(clean_t, "")
            if not resolved_ip and clean_t in cache and is_valid_public_ip(cache[clean_t].get("resolved_ip", "")):
                resolved_ip = cache[clean_t]["resolved_ip"]
            if resolved_ip:
                if resolved_ip in cache and cache[resolved_ip].get("asn") and cache[resolved_ip].get("country"):
                    asn = cache[resolved_ip]["asn"]
                    isp = cache[resolved_ip]["isp"]
                    results[clean_t] = (asn, isp)
                    cache[clean_t] = {
                        "asn": asn,
                        "isp": isp,
                        "net_type": cache[resolved_ip].get("net_type") or classify_asn(asn, isp),
                        "country": cache[resolved_ip].get("country", ""),
                        "resolved_ip": resolved_ip,
                    }
                    cache_modified = True
                else:
                    ip_to_targets.setdefault(resolved_ip, []).append(clean_t)

    # 待在线批量查询的去重 IP 列表
    pending_ips = [ip for ip in ip_to_targets.keys() if ip not in results]
    if not pending_ips:
        if persist and cache_modified:
            save_ip_cache(cache)
        return results

    log.info("【批量 ASN 解析】待解析出口 IP 数量: %d 个 (分批步长: %d)", len(pending_ips), max_chunk_size)

    cache_modified = False
    asn_db_modified = False

    # 按 max_chunk_size 切块批量 POST
    for i in range(0, len(pending_ips), max_chunk_size):
        chunk = pending_ips[i : i + max_chunk_size]
        payload = json.dumps([
            {"query": ip, "fields": "status,message,query,countryCode,as,asname,org,isp"}
            for ip in chunk
        ]).encode("utf-8")

        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (compatible; tg-proxy-fetcher/2.0)"},
        )

        chunk_success = False
        x_rl = None
        x_ttl = None

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                raw_data = resp.read().decode("utf-8", errors="ignore")
                data_list = json.loads(raw_data)
                headers = resp.headers
                x_rl = safe_int(headers.get("X-Rl"), -1)
                x_ttl = safe_int(headers.get("X-Ttl"), -1)

                if isinstance(data_list, list):
                    chunk_success = True
                    for item in data_list:
                        query_ip = (item.get("query") or "").strip()
                        if not query_ip:
                            continue
                        if item.get("status") == "success":
                            raw_as = str(item.get("as") or "")
                            raw_isp = (item.get("isp") or "").strip()
                            raw_org = (item.get("org") or "").strip()
                            raw_asname = (item.get("asname") or "").strip()
                            raw_combined_isp = raw_isp or raw_org or raw_asname
                            country_code = (item.get("countryCode") or "").strip().upper()

                            clean_asn, clean_isp, ext_net_type = normalize_external_asn_info(
                                raw_as, raw_combined_isp
                            )
                            if clean_asn:
                                # SSOT 权威校验
                                if clean_asn in ASN_TO_PROVIDER:
                                    clean_isp = ASN_TO_PROVIDER[clean_asn]

                                # 内存运行时热更新
                                if clean_isp and clean_isp not in ASN_DATABASE_ISP_TO_ASN:
                                    ASN_DATABASE_ISP_TO_ASN[clean_isp] = clean_asn
                                    ASN_DATABASE_ISP_LOWER[clean_isp.lower()] = (clean_asn, clean_isp)
                                    asn_db_modified = True
                                if clean_asn not in ASN_DATABASE_ASN_TO_ISP:
                                    ASN_DATABASE_ASN_TO_ISP[clean_asn] = clean_isp
                                    asn_db_modified = True
                                if clean_asn not in ASN_TO_PROVIDER:
                                    ASN_TO_PROVIDER[clean_asn] = clean_isp

                                # 动态研判与同步 net_type
                                if clean_asn not in ASN_EXACT_NET_TYPE:
                                    n_type = ext_net_type or classify_asn(clean_asn, clean_isp)
                                    ASN_EXACT_NET_TYPE[clean_asn] = n_type
                                    ASN_DATABASE_ASN_TO_NET_TYPE[clean_asn] = n_type
                                    asn_db_modified = True
                                else:
                                    n_type = ASN_EXACT_NET_TYPE[clean_asn]

                                cache_entry = {
                                    "asn": clean_asn,
                                    "isp": clean_isp,
                                    "net_type": n_type,
                                    "country": country_code,
                                }
                                cache[query_ip] = cache_entry
                                cache_modified = True
                                results[query_ip] = (clean_asn, clean_isp)

                                for tgt in ip_to_targets.get(query_ip, []):
                                    results[tgt] = (clean_asn, clean_isp)
                                    if tgt != query_ip:
                                        tgt_entry = dict(cache_entry)
                                        tgt_entry["resolved_ip"] = query_ip
                                        cache[tgt] = tgt_entry
        except Exception as e:
            log.warning("【批量 ASN 解析】第 %d 批 (共 %d 个 IP) 请求失败: %s", (i // max_chunk_size) + 1, len(chunk), e)

        # 若批量失败或个别 IP 漏失，针对缺失 IP 尝试单点通道兜底
        for ip in chunk:
            if ip not in results:
                fallback_asn, fallback_isp = resolve_asn_online(ip, persist=False, db_path=db_path)
                if fallback_asn:
                    results[ip] = (fallback_asn, fallback_isp)
                    n_type = ASN_EXACT_NET_TYPE.get(fallback_asn) or classify_asn(fallback_asn, fallback_isp)
                    cache_entry = {"asn": fallback_asn, "isp": fallback_isp, "net_type": n_type, "country": ""}
                    cache[ip] = cache_entry
                    cache_modified = True
                    asn_db_modified = True
                    for tgt in ip_to_targets.get(ip, []):
                        results[tgt] = (fallback_asn, fallback_isp)
                        if tgt != ip:
                            tgt_entry = dict(cache_entry)
                            tgt_entry["resolved_ip"] = ip
                            cache[tgt] = tgt_entry

        # 自适应限流退避处理 (ip-api batch 限制 15 req/min)
        has_more = (i + max_chunk_size) < len(pending_ips)
        if has_more:
            if x_rl is not None and x_rl <= 1 and x_ttl is not None and x_ttl > 0:
                log.info("【批量 ASN 限流保护】接近配额上限 (剩余: %d)，安全等待 %d 秒...", x_rl, x_ttl + 1)
                time.sleep(x_ttl + 1)
            else:
                time.sleep(0.5)

    if persist and asn_db_modified:
        save_asn_database(ASN_DATABASE_ISP_TO_ASN, ASN_DATABASE_ASN_TO_ISP, ASN_DATABASE_ASN_TO_NET_TYPE, db_path=db_path)
        log.info("【持久化 ASN 数据库】已批量同步更新本地 data/asn_database.json (含 net_type)")

    if persist and cache_modified:
        if cache_path:
            save_ip_cache(cache, filepath=cache_path)
        else:
            save_ip_cache(cache)
        log.info("【持久化 IP 缓存】已更新本地 IP 缓存画像: 当前总计收录 %d 个 IP/域名网络画像", len(cache))

    return results


async def resolve_asn_batch_online_async(
    targets: list[str],
    max_chunk_size: int = 100,
    persist: bool = True,
    db_path: str = "",
    cache_path: str = "",
) -> dict[str, tuple[str, str]]:
    """resolve_asn_batch_online 的异步无阻塞封装，在独立线程执行批量 I/O，杜绝阻塞主事件循环"""
    return await asyncio.to_thread(resolve_asn_batch_online, targets, max_chunk_size, persist, db_path, cache_path)


def resolve_ip_asn(ip: str = "", isp_hint: str = "", allow_online: bool = False) -> tuple[str, str]:
    """
    智能解析/补全 ASN 与 ISP：
    [纯本地极速查表 - 零网络阻塞，微秒级响应]
    1. 优先查持久化数据库 (ASN_DATABASE_ISP_TO_ASN，精确查表与大小写不敏感查表，杜绝子串碰撞误判)
    2. 命中已知云厂商与知名骨干线路关键词 (KNOWN_CLOUD_PROVIDERS 词库，短词采用边界安全匹配)
    [可选在线反查 - 默认关闭，解耦解析流程与网络请求]
    3. 仅当显式指定 allow_online=True 且存在有效 IP 时，才向第三方 BGP 数据库实时反查
    """
    clean_isp = isp_hint.strip()
    if clean_isp:
        # 1. 持久化数据库精确查表
        if clean_isp in ASN_DATABASE_ISP_TO_ASN:
            clean_asn = ASN_DATABASE_ISP_TO_ASN[clean_isp]
            std_name = ASN_TO_PROVIDER.get(clean_asn, clean_isp)
            return clean_asn, std_name

        norm_item = ASN_DATABASE_ISP_LOWER.get(clean_isp.lower())
        if norm_item:
            clean_asn, raw_isp = norm_item
            std_name = ASN_TO_PROVIDER.get(clean_asn, raw_isp)
            return clean_asn, std_name

        # 2. 启发式子串匹配已知云厂商与骨干网关键词
        isp_lower = clean_isp.lower()
        for k in SORTED_CLOUD_PROVIDER_KEYS:
            if len(k) <= 3:
                if re.search(rf"(?:^|[^a-z0-9]){re.escape(k)}(?:[^a-z0-9]|$)", isp_lower):
                    asn_code, std_name = KNOWN_CLOUD_PROVIDERS[k]
                    return asn_code, std_name
            elif k in isp_lower:
                asn_code, std_name = KNOWN_CLOUD_PROVIDERS[k]
                return asn_code, std_name

    # 3. 仅在显式允许时在线反查（解耦数据解析与网络 I/O，杜绝 Parser 阻塞与限流故障）
    if allow_online and ip and ip not in ("AS_UNKNOWN", "unknown"):
        found_asn, found_isp = resolve_asn_online(ip, isp_hint)
        if found_asn:
            return found_asn, found_isp or clean_isp

    return "", clean_isp


_DOTENV_LOADED = False


def load_dotenv(env_path: str | None = None) -> dict:
    """
    自动加载本地 .env 文件至 os.environ（若存在）。
    仅当环境变量尚未在系统/CI 环境中定义时才写入，避免覆盖 GitHub Actions 等上游传入的 Secrets。
    返回本次实际加载的键值字典。
    """
    global _DOTENV_LOADED
    if not env_path and _DOTENV_LOADED:
        return {}
    if not env_path:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    loaded = {}
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'").strip('"')
                    if k and k not in os.environ:
                        os.environ[k] = v
                        loaded[k] = v
        except Exception as e:
            log.debug("读取 .env 文件异常: %s", e)
    if not env_path or env_path.endswith(".env"):
        _DOTENV_LOADED = True
    return loaded


# 模块导入时自动执行一次安全加载
load_dotenv()

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""


# =====================================================================
# 确定性哈希分段锁池 (Striped Locks)
# 解决同 IP/Host 互斥探测需求，且内存常数级 O(1)，无字典无界增长隐患
# =====================================================================
_LOCK_POOL_SIZE = 8192
_LOCK_POOL_MASK = _LOCK_POOL_SIZE - 1
_LOCK_POOL: list[asyncio.Lock] | None = None
_LOCK_POOL_LOOP: asyncio.AbstractEventLoop | None = None


def get_keyed_lock(key: str) -> asyncio.Lock:
    """
    返回与 key (IP/Host) 绑定的确定性分段锁。
    采用 zlib.crc32 保证跨进程/跨运行哈希一致（避免 PYTHONHASHSEED 随机化干扰）。
    同 key 必同锁，不同 key 在 8192 桶位下碰撞率极低，且内存严格常数级 O(1)，杜绝无界增长。
    """
    global _LOCK_POOL, _LOCK_POOL_LOOP
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if _LOCK_POOL is None or current_loop != _LOCK_POOL_LOOP:
        _LOCK_POOL = [asyncio.Lock() for _ in range(_LOCK_POOL_SIZE)]
        _LOCK_POOL_LOOP = current_loop

    idx = zlib.crc32(str(key).encode("utf-8")) & _LOCK_POOL_MASK
    return _LOCK_POOL[idx]


def safe_int(value, default: int = 0) -> int:
    """安全将值转为整数，转换失败或为空时返回默认值"""
    if value is None:
        return default
    try:
        s = str(value).strip()
        return int(s) if s else default
    except (ValueError, TypeError):
        return default


def normalize_timestamp(val, default: str = "") -> str:
    """
    规范化测试与获取时间戳为标准格式 YYYY-MM-DD HH:MM:SS（北京时间）。
    自动识别并转换 Unix 秒级/毫秒级时间戳 (如 1785149364.000) 以及各类非标准日期字符串。
    """
    if val is None:
        return default
    val_str = str(val).strip()
    if not val_str or val_str in ("-", "null", "none"):
        return default

    # 1. 尝试解析为数字（Unix 秒级/毫秒级时间戳）
    try:
        ts = float(val_str)
        if ts > 1e11:  # 毫秒级时间戳
            ts /= 1000.0
        if 1e8 <= ts <= 2.5e9:  # 合理 Unix 时间戳范围 (1973年 ~ 2049年)
            dt = datetime.fromtimestamp(ts, timezone(timedelta(hours=8)))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        pass

    # 2. 若已是标准格式 YYYY-MM-DD HH:MM:SS 直接返回
    if re.match(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}$", val_str):
        return val_str

    # 3. 尝试解析 ISO 8601 带时区时间字符串并转换为北京时间
    if "T" in val_str or "+" in val_str or val_str.endswith("Z"):
        try:
            iso_str = val_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

    # 4. 兼容解析各类标准日期格式 (如 YYYY/MM/DD, ISO 8601 YYYY-MM-DDTHH:MM:SS 等)
    m = re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})(?:[T\s](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?", val_str)
    if m:
        year, month, day, hour, minute, second = m.groups()
        hour = hour or "00"
        minute = minute or "00"
        second = second or "00"
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d} {int(hour):02d}:{int(minute):02d}:{int(second):02d}"

    return val_str


def clean_asn(raw_asn: str, isp: str = "") -> str:
    """提取规范化 ASN 编号 (如 AS979，支持从知名服务商名称智能反推)"""
    raw_asn = (raw_asn or "").strip()
    m = re.search(r"(AS\d+)", raw_asn, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    r_low = (raw_asn + " " + (isp or "")).lower()
    for k in SORTED_CLOUD_PROVIDER_KEYS:
        if len(k) <= 3:
            if re.search(rf"(?:^|[^a-z0-9]){re.escape(k)}(?:[^a-z0-9]|$)", r_low):
                return KNOWN_CLOUD_PROVIDERS[k][0]
        elif k in r_low:
            return KNOWN_CLOUD_PROVIDERS[k][0]
    m_d = re.search(r"\b(\d{3,7})\b", raw_asn)
    if m_d:
        return f"AS{m_d.group(1)}"
    cand = raw_asn or isp
    if cand:
        if cand in ASN_DATABASE_ISP_TO_ASN:
            return ASN_DATABASE_ISP_TO_ASN[cand]
        norm = ASN_DATABASE_ISP_LOWER.get(cand.lower())
        if norm:
            return norm[0]
    return "AS_UNKNOWN"


def format_asn_isp(raw_asn: str, raw_isp: str = "") -> str:
    """
    格式化生成『ASN + 服务商名称』一体化直观标签（如 AS906 DMIT, AS13335 Cloudflare）：
    1. 彻底清除 markdown 反引号 (`) 等多余标记
    2. 支持纯数字 ASN 补齐 AS 前缀（如 22773 -> AS22773）
    3. 过滤街道、大厦等地址型脏后缀（如 Tencent Building, Kejizhongyi Avenue）
    4. 权威优先：若 ASN 在权威字典 ASN_TO_PROVIDER 中收录，优先使用权威标准服务商名称
    5. 若未收录于权威库，保留原有规范后缀或 ISP 名称拼接
    6. 若无法识别，回退至纯 ASN 或 raw_isp
    """
    clean_a = (raw_asn or "").replace("`", "").strip()
    clean_i = (raw_isp or "").replace("`", "").strip()
    if clean_i in ("-", "None", "unknown"):
        clean_i = ""

    code = ""
    suffix = ""
    m = re.search(r"(AS\d+)", clean_a, re.IGNORECASE)
    if m:
        code = m.group(1).upper()
        suffix = clean_a[m.end():].strip().strip("-").strip()
    else:
        m_num = re.match(r"^(\d{1,10})$", clean_a)
        if m_num:
            code = f"AS{m_num.group(1)}"
        else:
            cand = clean_a or clean_i
            found_asn = ""
            if cand in ASN_DATABASE_ISP_TO_ASN:
                found_asn = ASN_DATABASE_ISP_TO_ASN[cand]
            else:
                norm_item = ASN_DATABASE_ISP_LOWER.get(cand.lower())
                if norm_item:
                    found_asn = norm_item[0]
            if found_asn:
                code = found_asn
                if not clean_i and clean_a != found_asn:
                    clean_i = clean_a
            else:
                if clean_a and clean_a != "-" and clean_a.upper() != "AS_UNKNOWN":
                    return clean_a
                return clean_i or "AS_UNKNOWN"

    _addr_pattern = r"(?:\b(?:building|avenue|road|street|floor|suite|room|district|highway|jalan|bldg|kejizhongyi)\b|大厦|大楼|写字楼|园区|胡同|街道|号院)"
    if suffix and re.search(_addr_pattern, suffix, re.IGNORECASE):
        suffix = ""
    if clean_i and re.search(_addr_pattern, clean_i, re.IGNORECASE):
        clean_i = ""

    # 提取 suffix 中已有的别名括号内容，避免多轮调用导致别名丢失或嵌套
    existing_aliases = re.findall(r"\((.*?)\)", suffix)
    existing_alias = " ".join(a.strip() for a in existing_aliases if a.strip())
    if existing_aliases:
        suffix = re.sub(r"\s*\(.*?\)", "", suffix).strip()

    # 权威单一真相源 (SSOT) 优先：若在已收录权威字典中，采用权威统一名称
    auth_isp = ASN_TO_PROVIDER.get(code, "")
    if auth_isp:
        candidate_alias = clean_i or existing_alias or suffix
        cand_aliases = re.findall(r"\((.*?)\)", candidate_alias)
        alias = " ".join(a.strip() for a in cand_aliases if a.strip()) if cand_aliases else candidate_alias.strip()

        if alias and alias.upper() not in ("-", "NONE", "UNKNOWN", "AS_UNKNOWN", "NULL"):
            # 若输入别名与权威统一名称互不包含（即属于多品牌/租户/法定名与商业名不同），保留输入别名
            if alias.lower() not in auth_isp.lower() and auth_isp.lower() not in alias.lower():
                return f"{code} {auth_isp} ({alias})"
        return f"{code} {auth_isp}"

    if suffix:
        return f"{code} {suffix}"
    if clean_i:
        return f"{code} {clean_i}"
    return code


def send_tg_message(text: str, token: str = "", chat_id: str = "", tag: str = "Telegram") -> bool:
    """
    统一发送 Telegram HTML 格式统计/告警消息。
    未传入 token/chat_id 时自动回退至环境变量 TG_BOT_TOKEN / TG_CHAT_ID。
    """
    t = token or os.getenv("TG_BOT_TOKEN") or ""
    c = chat_id or os.getenv("TG_CHAT_ID") or ""
    if not t or not c:
        logging.getLogger(tag).info("未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过 Telegram 消息推送")
        return False

    url = f"https://api.telegram.org/bot{t}/sendMessage"
    payload = json.dumps({
        "chat_id": c,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                logging.getLogger(tag).info("✅ %s 统计卡片已成功发送！", tag)
                return True
            else:
                desc = str(data.get("description") or data)
                if t and t in desc:
                    desc = desc.replace(t, "bot***")
                logging.getLogger(tag).warning("%s 消息发送失败: %s", tag, desc)
                return False
    except Exception as e:
        err_msg = str(e)
        if t and t in err_msg:
            err_msg = err_msg.replace(t, "bot***")
        logging.getLogger(tag).warning("发送 %s 消息时出现异常: %s", tag, err_msg)
        return False


def send_ci_failure_alert(step_name: str = "") -> bool:
    """
    GitHub Actions 流水线失败时发送即时 Telegram 告警卡片。
    自动提取 Actions 环境变量生成直接跳转运行日志的超链接。
    """
    server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    run_num = os.getenv("GITHUB_RUN_NUMBER", "")

    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""
    link = f'<a href="{run_url}">Action #{run_num} 运行日志</a>' if run_url else "请登录 GitHub 查看日志"
    step_hint = f"\n   └ <i>中断阶段: {step_name}</i>" if step_name else ""

    msg = (
        "🚨 <b>GitHub Actions 流水线执行失败！</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"⚠️ 节点抓取或质检过程中触发了异常中断。{step_hint}\n"
        f"🔗 <b>排查链接</b>: {link}"
    )
    return send_tg_message(msg, tag="CI-Failure-Alert")


# ---------------------------------------------------------------------------
# UI 标签格式化与差量格式化工具
# ---------------------------------------------------------------------------

def format_buffer_badge(
    marked: int,
    buf_new: int = 0,
    buf_rec: int = 0,
    f1: int = 0,
    f2: int = 0,
    bold: bool = False,
) -> str:
    """格式化缓冲标签，带新增缓冲与取消缓冲动态"""
    m_str = f"<b>{marked}</b>" if bold else str(marked)
    z_str = "<b>0</b>" if bold else "0"
    if marked <= 0:
        if buf_rec > 0:
            return f" · ⚠️ {z_str} 缓冲 [{buf_rec} 取消]"
        return ""
    changes = []
    if buf_new > 0:
        changes.append(f"+{buf_new} 新增")
    if buf_rec > 0:
        changes.append(f"{buf_rec} 取消")
    if changes:
        return f" · ⚠️ {m_str} 缓冲 [{(' · '.join(changes))}]"
    if f1 > 0 or f2 > 0:
        breakdown = []
        if f1 > 0:
            breakdown.append(f"1次: {f1}")
        if f2 > 0:
            breakdown.append(f"2次: {f2}")
        if breakdown:
            return f" · ⚠️ {m_str} 缓冲 [{(' · '.join(breakdown))}]"
    return f" · ⚠️ {m_str} 缓冲"


def format_diff(new_c: int, upd_c: int) -> str:
    """格式化增量新增与刷新变化标签"""
    parts = []
    if new_c > 0:
        parts.append(f"🟢 <b>+{new_c}</b> 新增")
    if upd_c > 0:
        parts.append(f"🔄 {upd_c} 刷新")
    if not parts:
        return "保持最新"
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# 底层网络流异步安全读取与 HTTP 报文切分工具
# ---------------------------------------------------------------------------

RE_HTTP_301 = re.compile(rb"^HTTP/\d\.\d\s+301\b")
RE_SERVER_CF = re.compile(rb"(?im)^server:\s*cloudflare\s*$")


async def read_full_response(
    reader: asyncio.StreamReader,
    http_timeout: float,
    max_bytes: int = 4096,
    need_body: bool = False,
    early_exit_marker: bytes = b"",
) -> bytes:
    """
    循环读取直到拿到完整的 HTTP 响应（若 need_body=False 遇到 \\r\\n\\r\\n 即可返回；若 need_body=True 读到匹配标志或 EOF）或达到 max_bytes 硬上限。
    用统一 deadline 控制总耗时，避免多次循环导致累计超时远超 http_timeout。
    单次 read() 动态计算剩余可用空间，避免读取超出 max_bytes 上限。
    """
    deadline = time.monotonic() + http_timeout
    resp_bytes = b""
    while len(resp_bytes) < max_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        chunk = await asyncio.wait_for(
            reader.read(min(1024, max_bytes - len(resp_bytes))),
            timeout=remaining,
        )
        if not chunk:
            break
        resp_bytes += chunk
        has_headers = (b"\r\n\r\n" in resp_bytes or b"\n\n" in resp_bytes)
        if has_headers:
            if not need_body:
                break
            # 若响应头表明非 200 OK（如 403, 502 等），Body 绝不会含有效字段，立即返回避免空耗超时
            first_line = resp_bytes.splitlines()[0] if resp_bytes else b""
            if not (b" 200 " in first_line or first_line.endswith(b" 200")):
                break
            # 若指定了提前退出标志，命中则立即返回
            if early_exit_marker and early_exit_marker in resp_bytes:
                break
            # 默认 trace 判定：确保 /cdn-cgi/trace 尾部字段到达 (warp= 或 kex=)，避免因仅匹配 colo= 过早返回导致 loc= (国家) 截断丢失
            if b"warp=" in resp_bytes or b"kex=" in resp_bytes:
                break
    return resp_bytes


async def safe_close_writer(writer: asyncio.StreamWriter, timeout: float = 0.5) -> None:
    """安全关闭 StreamWriter 并等待连接释放，带超时控制防 hang 与静默忽略 RST 异常"""
    try:
        writer.close()
    except Exception:
        pass
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except Exception:
        pass


def split_header_body(resp_bytes: bytes) -> tuple[bytes, bytes]:
    """按 \\r\\n\\r\\n 优先、\\n\\n 兜底切分 Header 与 Body 区域。"""
    idx = resp_bytes.find(b"\r\n\r\n")
    if idx != -1:
        return resp_bytes[:idx], resp_bytes[idx + 4:]
    idx = resp_bytes.find(b"\n\n")
    if idx != -1:
        return resp_bytes[:idx], resp_bytes[idx + 2:]
    return resp_bytes, b""



# ============================================================
# Cloudflare 反代 ProxyIP 地区提取与分类导出工具
# ============================================================

COLO_TO_COUNTRY = {
    # 北美洲
    "IAD": "美国", "LAX": "美国", "SJC": "美国", "EWR": "美国", "MIA": "美国", "ORD": "美国",
    "DFW": "美国", "SEA": "美国", "ATL": "美国", "DEN": "美国", "PHX": "美国", "LAS": "美国",
    "MCI": "美国", "PDX": "美国", "BGR": "美国", "IAH": "美国", "DTW": "美国", "MSP": "美国",
    "YUL": "加拿大", "YYZ": "加拿大", "YVR": "加拿大", "YYC": "加拿大",
    "MXN": "墨西哥", "QRO": "墨西哥",
    # 欧洲
    "FRA": "德国", "MUC": "德国", "BER": "德国", "DUS": "德国", "HAM": "德国", "TXL": "德国",
    "AMS": "荷兰", "ARN": "瑞典", "LHR": "英国", "MAN": "英国", "EDI": "英国",
    "CDG": "法国", "MRS": "法国", "LYS": "法国", "WAW": "波兰", "HEL": "芬兰",
    "TLL": "爱沙尼亚", "RIX": "拉脱维亚", "VNO": "立陶宛", "ZRH": "瑞士", "GVA": "瑞士",
    "VIE": "奥地利", "MAD": "西班牙", "BCN": "西班牙", "SOF": "保加利亚", "PRG": "捷克",
    "OTP": "罗马尼亚", "BUD": "匈牙利", "BEG": "塞尔维亚", "ZAG": "克罗地亚", "BRU": "比利时",
    "CPH": "丹麦", "OSL": "挪威", "DUB": "爱尔兰", "LIS": "葡萄牙", "OPO": "葡萄牙",
    "MXP": "意大利", "FCO": "意大利", "KBP": "乌克兰", "ATH": "希腊", "KEF": "冰岛",
    "TIA": "阿尔巴尼亚", "BTS": "斯洛伐克", "LCA": "塞浦路斯", "TBS": "格鲁吉亚",
    # 亚太
    "SIN": "新加坡", "NRT": "日本", "HND": "日本", "KIX": "日本", "HKG": "香港",
    "ICN": "韩国", "TPE": "台湾", "KHH": "台湾", "SYD": "澳大利亚", "MEL": "澳大利亚",
    "BNE": "澳大利亚", "PER": "澳大利亚", "AKL": "新西兰",
    "BOM": "印度", "DEL": "印度", "MAA": "印度", "BLR": "印度", "CCU": "印度",
    "BKK": "泰国", "MNL": "菲律宾", "KUL": "马来西亚", "CGK": "印度尼西亚",
    "HAN": "越南", "SGN": "越南", "DAC": "孟加拉国", "FRU": "吉尔吉斯斯坦",
    "AKX": "哈萨克斯坦", "ALA": "哈萨克斯坦",
    # 中东与非洲
    "DXB": "阿联酋", "KWI": "科威特", "DOH": "卡塔尔", "RUH": "沙特阿拉伯", "JED": "沙特阿拉伯",
    "IST": "土耳其", "TLV": "以色列", "EVN": "亚美尼亚",
    "JNB": "南非", "CPT": "南非",
    # 南美洲
    "GRU": "巴西", "GIG": "巴西", "EZE": "阿根廷", "SCL": "智利", "BOG": "哥伦比亚", "LIM": "秘鲁",
}

CITY_TO_COUNTRY = {
    # 常用国际城市/首都/机房 -> 国家归类
    "里加": "拉脱维亚", "塔林": "爱沙尼亚", "维尔纽斯": "立陶宛", "索菲亚": "保加利亚",
    "莫斯科": "俄罗斯", "哥本哈根": "丹麦", "布加勒斯特": "罗马尼亚", "奥斯陆": "挪威",
    "布拉迪斯拉发": "斯洛伐克", "布鲁塞尔": "比利时", "特拉维夫": "以色列", "孟买": "印度",
    "班加罗尔": "印度", "贝尔格莱德": "塞尔维亚", "圣保罗": "巴西", "地拉那": "阿尔巴尼亚",
    "埃里温": "亚美尼亚", "迪拜": "阿联酋", "里昂": "法国", "马赛": "法国",
    "罗马": "意大利", "米兰": "意大利", "雅典": "希腊", "雅加达": "印度尼西亚",
    "马尼拉": "菲律宾", "氹仔": "澳门", "哥德堡": "瑞典", "约翰内斯堡": "南非",
    "圣多明各": "多米尼加", "圣地亚哥": "智利", "吉大港": "孟加拉国", "阿克托别": "哈萨克斯坦",
    "阿拉木图": "哈萨克斯坦", "比什凯克": "吉尔吉斯斯坦", "克雷塔罗": "墨西哥", "都柏林": "爱尔兰",
    "拉纳卡": "塞浦路斯", "利雅得": "沙特阿拉伯", "阿尔纳武特柯伊": "土耳其", "布达佩斯": "匈牙利",
    # 美国主要城市/机房
    "堪萨斯城": "美国", "波特兰": "美国", "班戈": "美国", "芝加哥": "美国", "达拉斯": "美国",
    "达拉斯-沃斯堡": "美国", "圣何塞": "美国", "洛杉矶": "美国", "杜勒斯": "美国", "迈阿密": "美国",
    "西雅图": "美国", "纽瓦克": "美国", "亚特兰大": "美国", "丹佛": "美国", "凤凰城": "美国",
    "菲尼克斯": "美国", "拉斯维加斯": "美国", "水牛城": "美国", "圣路易斯": "美国",
    "休斯顿": "美国", "盐湖城": "美国", "檀香山": "美国",
    # 德国主要城市
    "柏林": "德国", "法兰克福": "德国", "慕尼黑": "德国", "杜塞尔多夫": "德国", "汉堡": "德国",
    # 其它重点枢纽
    "阿姆斯特丹": "荷兰", "斯德哥尔摩": "瑞典", "赫尔辛基": "芬兰", "巴黎": "法国",
    "伦敦": "英国", "曼彻斯特": "英国", "爱丁堡": "英国", "东京": "日本", "大阪": "日本",
    "新加坡": "新加坡", "香港": "香港", "首尔": "韩国", "台北": "台湾",
    "悉尼": "澳大利亚", "墨尔本": "澳大利亚", "奥克兰": "新西兰",
    "多伦多": "加拿大", "蒙特利尔": "加拿大", "温哥华": "加拿大",
    "苏黎世": "瑞士", "日内瓦": "瑞士", "维也纳": "奥地利",
    "马德里": "西班牙", "巴塞罗那": "西班牙", "华沙": "波兰", "布拉格": "捷克",
}

COUNTRY_FLAGS = {
    "美国": "🇺🇸", "德国": "🇩🇪", "荷兰": "🇳🇱", "瑞典": "🇸🇪", "新加坡": "🇸🇬",
    "日本": "🇯🇵", "英国": "🇬🇧", "芬兰": "🇫🇮", "香港": "🇭🇰", "法国": "🇫🇷",
    "波兰": "🇵🇱", "爱沙尼亚": "🇪🇪", "拉脱维亚": "🇱🇻", "瑞士": "🇨🇭", "立陶宛": "🇱🇹",
    "西班牙": "🇪🇸", "加拿大": "🇨🇦", "奥地利": "🇦🇹", "保加利亚": "🇧🇬", "捷克": "🇨🇿",
    "韩国": "🇰🇷", "印度": "🇮🇳", "意大利": "🇮🇹", "俄罗斯": "🇷🇺", "土耳其": "🇹🇷",
    "台湾": "🇨🇳", "澳大利亚": "🇦🇺", "丹麦": "🇩🇰", "罗马尼亚": "🇷🇴", "哈萨克斯坦": "🇰🇿",
    "巴西": "🇧🇷", "挪威": "🇳🇴", "比利时": "🇧🇪", "亚美尼亚": "🇦🇲", "冰岛": "🇮🇸",
    "以色列": "🇮🇱", "爱尔兰": "🇮🇪", "阿尔巴尼亚": "🇦🇱", "孟加拉国": "🇧🇩", "斯洛伐克": "🇸🇰",
    "塞浦路斯": "🇨🇾", "吉尔吉斯斯坦": "🇰🇬", "格鲁吉亚": "🇬🇪", "墨西哥": "🇲🇽", "智利": "🇨🇱",
    "阿根廷": "🇦🇷", "哥伦比亚": "🇨🇴", "秘鲁": "🇵🇪", "南非": "🇿🇦", "阿联酋": "🇦🇪",
    "科威特": "🇰🇼", "卡塔尔": "🇶🇦", "沙特阿拉伯": "🇸🇦", "希腊": "🇬🇷", "匈牙利": "🇭🇺",
    "塞尔维亚": "🇷🇸", "克罗地亚": "🇭🇷", "葡萄牙": "🇵🇹", "乌克兰": "🇺🇦", "泰国": "🇹🇭",
    "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", "印度尼西亚": "🇮🇩", "越南": "🇻🇳", "新西兰": "🇳🇿",
    "中国": "🇨🇳", "澳门": "🇲🇴", "阿曼": "🇴🇲", "斯洛文尼亚": "🇸🇮", "白俄罗斯": "🇧🇾",
    "厄瓜多尔": "🇪🇨", "尼日利亚": "🇳🇬", "北马其顿": "🇲🇰", "哥斯达黎加": "🇨🇷", "多米尼加": "🇩🇴",
    "尼泊尔": "🇳🇵", "巴基斯坦": "🇵🇰", "波多黎各": "🇵🇷", "肯尼亚": "🇰🇪", "黎巴嫩": "🇱🇧",
}


def extract_country(cf_location: str | None, colo: str | None) -> str:
    """
    根据 cf_location (如 '北美洲 · 洛杉矶 · 美国') 或 Cloudflare colo 机房三字代码 (如 'LAX')
    提取标准化的国家/地区名称。
    """
    cf_location = (cf_location or "").strip()
    colo = (colo or "").strip().upper()

    def _normalize_name(name: str) -> str:
        name = name.strip()
        if name in ("捷克共和国", "捷克"):
            return "捷克"
        if name in ("俄罗斯联邦", "俄罗斯"):
            return "俄罗斯"
        if name in ("阿拉伯联合酋长国", "阿联酋"):
            return "阿联酋"
        if name in ("US", "USA", "United States"):
            return "美国"
        if name in ("TW", "Taiwan"):
            return "台湾"
        if "香港" in name:
            return "香港"
        if "澳门" in name:
            return "澳门"
        if "巴基斯坦" in name:
            return "巴基斯坦"
        if "多明尼加" in name or "多米尼加" in name:
            return "多米尼加"
        return name

    parts = [p.strip() for p in cf_location.split("·") if p.strip()] if cf_location else []

    # 1. 三段式或以上结构优先取末段（通常为国家/地区名，如 '北美洲 · 洛杉矶 · 美国'）
    if len(parts) >= 3:
        return _normalize_name(parts[-1])

    # 2. 两段式结构（如 '欧洲 · 德国' 或 '北美洲 · 洛杉矶'）
    if len(parts) == 2:
        loc = _normalize_name(parts[1])
        if loc in COUNTRY_FLAGS:
            return loc
        if loc in CITY_TO_COUNTRY:
            return CITY_TO_COUNTRY[loc]

    # 3. 单段式直接匹配国家或城市（如 '日本' 或 '东京'）
    if len(parts) == 1:
        loc = _normalize_name(parts[0])
        if loc in COUNTRY_FLAGS:
            return loc
        if loc in CITY_TO_COUNTRY:
            return CITY_TO_COUNTRY[loc]

    # 4. cf_location 文本中包含已知城市名
    if cf_location:
        for city, c in CITY_TO_COUNTRY.items():
            if city in cf_location:
                return c

    # 5. 回退到 colo 机房代码映射
    if colo in COLO_TO_COUNTRY:
        return COLO_TO_COUNTRY[colo]

    # 6. 两段式/单段式兜底（若未匹配到已知表，直接规范化作为地区名）
    if len(parts) >= 2:
        return _normalize_name(parts[1])
    if len(parts) == 1:
        return _normalize_name(parts[0])

    return "其他地区"


def format_buffer_nodes_txt(rows: list) -> str:
    """
    将 IP 节点列表按质检可用性/缓冲状态分层格式化输出：
      - 有失败 (fail_count > 0 / 缓冲节点)：置顶排在最前，按 (fail_count, delay_ms) 升序排列，便于优先观测
      - 没失败 (fail_count == 0 / 存活节点)：排在后部，按 delay_ms 升序（最低延迟优先）
    适用于 scan_ips.txt 与 proxyip.txt 等全局汇总文本（机房与地区独立分类已由专属目录提供）。
    """
    alive_nodes: list[tuple[int, str]] = []
    buffer_nodes: list[tuple[int, int, str]] = []
    seen = set()

    for r in rows:
        ip = (r.get("ip") or "").strip()
        port = r.get("port", "")
        if not ip or not port:
            continue
        endpoint = f"{ip}:{port}"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        fc = safe_int(r.get("fail_count", 0), 0)
        d = safe_int(r.get("delay_ms"), 0)
        delay = d if d > 0 else 99999
        if fc == 0:
            alive_nodes.append((delay, endpoint))
        else:
            buffer_nodes.append((fc, delay, endpoint))

    # 存活节点按延迟升序
    alive_nodes.sort(key=lambda x: x[0])
    # 缓冲节点按连续失败次数升序，再按延迟升序
    buffer_nodes.sort(key=lambda x: (x[0], x[1]))

    lines = []
    if buffer_nodes:
        lines.append(f"# 缓冲节点 (有失败) - {len(buffer_nodes)} 个")
        for _, _, endpoint in buffer_nodes:
            lines.append(endpoint)

    if alive_nodes:
        if lines:
            lines.append("")
        lines.append(f"# 存活节点 (无失败) - {len(alive_nodes)} 个")
        for _, endpoint in alive_nodes:
            lines.append(endpoint)

    return "\n".join(lines).rstrip() + "\n" if lines else ""


format_proxyip_txt = format_buffer_nodes_txt
format_scan_ips_txt = format_buffer_nodes_txt


# ============================================================
# 通用代理协议展示规范与字段定义
# ============================================================
PROXY_PROTO_ORDER = ["socks5", "http", "https", "turn", "sstp"]
PROXY_PROTO_NAMES = {
    "socks5": "SOCKS5 代理",
    "http": "HTTP 代理",
    "https": "HTTPS 代理",
    "turn": "TURN 协议",
    "sstp": "SSTP 协议",
}
# [Rule 9a Scoped Legacy Migration]
# Expiry condition: Applies to historical proxy records gathered before 2026-10-02 without first_seen.
# Once all legacy records are either backfilled or naturally phased out via tombstone, this fallback can be removed.
LEGACY_DEFAULT_FIRST_SEEN = "2026-10-01 00:00:00"

# ISO 3166-1 alpha-2 常用国家/地区中文映射表
COUNTRY_NAME_MAP: dict[str, str] = {
    "US": "美国", "CN": "中国", "HK": "中国香港", "TW": "中国台湾", "JP": "日本",
    "SG": "新加坡", "KR": "韩国", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度",
    "MY": "马来西亚", "TH": "泰国", "VN": "越南", "ID": "印度尼西亚", "PH": "菲律宾",
    "BR": "巴西", "MX": "墨西哥", "ZA": "南非", "IT": "意大利", "ES": "西班牙",
    "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "PL": "波兰", "CH": "瑞士",
    "AT": "奥地利", "BE": "比利时", "IE": "爱尔兰", "NZ": "新西兰", "AE": "阿联酋",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "RO": "罗马尼亚", "BG": "保加利亚",
    "HU": "匈牙利", "GR": "希腊", "PT": "葡萄牙", "IL": "以色列", "AR": "阿根廷",
    "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁", "EG": "埃及", "KZ": "哈萨克斯坦",
}


def country_code_to_emoji(country_code: str) -> str:
    """将 ISO 3166-1 alpha-2 国家/地区代码转换为标准国旗 Emoji 表情（如 US -> 🇺🇸, JP -> 🇯🇵）"""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🌐"
    code = country_code.upper()
    return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))


PROXY_CSV_FIELDS = [
    "url",
    "proto",
    "host",
    "port",
    "delay_ms",
    "fail_count",
    "status",
    "colo",
    "country",
    "egress_ip",
    "asn",
    "isp",
    "net_type",
    "tested_at",
    "first_seen",
]


def format_proxies_txt(rows: list) -> str:
    """
    将通用代理列表按协议类型分段归类输出：
      - 优先按协议归类展示（SOCKS5 -> HTTP -> HTTPS -> TURN -> SSTP -> 其他）
      - 各协议段内按 (fail_count 升序, delay_ms 升序) 排序
      - 带有清晰的注释头部，避免各协议节点混杂穿插
    """
    groups: dict[str, list] = {}
    seen = set()

    for item in rows:
        if isinstance(item, dict):
            url = (item.get("url") or "").strip()
            proto = (item.get("proto") or "").strip().lower()
            fc = safe_int(item.get("fail_count"), 0)
            dms = safe_int(item.get("delay_ms"), 0)
        else:
            url = str(item).strip()
            proto = ""
            fc = 0
            dms = 0

        if not url or url.startswith("#"):
            continue
        if url in seen:
            continue
        seen.add(url)

        if not proto:
            proto = url.split("://", 1)[0].lower() if "://" in url else "other"

        if dms <= 0:
            dms = 99999

        groups.setdefault(proto, []).append((fc, dms, url))

    def _proto_sort_key(p: str) -> tuple[int, str]:
        if p in PROXY_PROTO_ORDER:
            return (PROXY_PROTO_ORDER.index(p), p)
        return (len(PROXY_PROTO_ORDER), p)

    sorted_protos = sorted(groups.keys(), key=_proto_sort_key)

    sections = []
    for proto in sorted_protos:
        nodes = groups[proto]
        nodes.sort(key=lambda x: (x[0], x[1]))
        title = PROXY_PROTO_NAMES.get(proto, f"{proto.upper()} 代理")
        header = f"# {title} - {len(nodes)} 个"
        section_lines = [header]
        for _, _, url in nodes:
            section_lines.append(url)
        sections.append("\n".join(section_lines))

    return "\n\n".join(sections).rstrip() + "\n" if sections else ""


# 向后兼容历史别名
format_socks_txt = format_proxies_txt


def format_proxy_json_item(r_dict: dict) -> dict:
    """
    转换为适配 EDT-Toolkit / 油猴脚本与第三方前端的标准化 JSON 字典对象：
    支持 proxy, protocol, ip, port, country, country_name, country_emoji, asn, isp, asOrganization, net_type 等全量凭据
    """
    raw_asn = str(r_dict.get("asn") or "").strip()
    m_asn = re.search(r"AS(\d+)", raw_asn, re.IGNORECASE)
    clean_asn_num = m_asn.group(1) if m_asn else raw_asn

    raw_country = str(r_dict.get("country") or "").strip().upper()
    if len(raw_country) == 2 and raw_country != "UN":
        c_code = raw_country
        c_name = COUNTRY_NAME_MAP.get(c_code, c_code)
        c_emoji = country_code_to_emoji(c_code)
    else:
        c_code = ""
        c_name = ""
        c_emoji = ""

    isp_name = str(r_dict.get("isp") or "").strip()
    proto = str(r_dict.get("proto") or "socks5").strip().lower()

    # net_type：优先继承已打标的合规 net_type；若缺失则基于 ASN/ISP 判定；若完全未查询则留空，绝不虚假打标为 datacenter
    curr_nt = str(r_dict.get("net_type") or "").strip().lower()
    if curr_nt in VALID_NET_TYPES:
        net_type_val = curr_nt
    elif clean_asn_num or isp_name:
        net_type_val = classify_asn(clean_asn_num, isp_name)
    else:
        net_type_val = ""

    return {
        "proxy": r_dict.get("url") or "",
        "protocol": proto,
        "ip": r_dict.get("host") or "",
        "port": safe_int(r_dict.get("port"), 0),
        "country": c_code,
        "country_name": c_name,
        "country_cn": c_name,
        "country_emoji": c_emoji,
        "asn": clean_asn_num,
        "asOrganization": isp_name,
        "isp": isp_name,
        "net_type": net_type_val,
    }


def save_proxies_json(rows: list, json_path: str = "data/proxies.json") -> int:
    """
    保存全量通用代理标准化 JSON 文件（原子写入），
    按协议分组与延迟排序，直接适配 EDT-Toolkit / 油猴脚本及第三方 API 调用。
    """
    json_list = [format_proxy_json_item(r) for r in rows if isinstance(r, dict) and r.get("url")]
    dir_name = os.path.dirname(os.path.abspath(json_path))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    tmp_json = f"{json_path}.tmp"
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(json_list, f, ensure_ascii=False, indent=2)
    os.replace(tmp_json, json_path)
    log.info("已覆写保存 %s: %d 个全量代理节点 (标准 JSON 格式)", json_path, len(json_list))
    return len(json_list)


def save_proxies_by_protocol(rows: list, output_dir: str = "data/proxies") -> dict[str, int]:
    """
    按协议独立拆分保存至 output_dir 目录：
    对 SOCKS5、HTTP、HTTPS、TURN、SSTP 等每种协议生成：
      - {proto}.txt  (纯文本 URL 清单，带统计注释头)
      - {proto}.csv  (单协议结构化 CSV，15 列完整元数据，包含 country, egress_ip, asn, isp, net_type)
      - {proto}.json (单协议标准化 JSON，适配 EDT-Toolkit / 油猴脚本全协议抽取与类型筛选)
    自动清理已过时或不存在的协议文件。
    返回每个协议成功保存的节点数量字典。
    """
    os.makedirs(output_dir, exist_ok=True)
    groups: dict[str, list] = {}
    seen = set()

    for item in rows:
        if isinstance(item, dict):
            url = (item.get("url") or "").strip()
            row_dict = dict(item)
        else:
            url = str(item).strip()
            row_dict = {"url": url}

        if not url or url.startswith("#") or url in seen:
            continue
        seen.add(url)

        proto = (row_dict.get("proto") or "").strip().lower()
        if not proto:
            proto = url.split("://", 1)[0].lower() if "://" in url else "other"
        row_dict["proto"] = proto
        row_dict.setdefault("fail_count", safe_int(row_dict.get("fail_count"), 0))
        row_dict.setdefault("delay_ms", safe_int(row_dict.get("delay_ms"), 0))
        row_dict.setdefault("status", row_dict.get("status", "pending"))
        row_dict.setdefault("colo", row_dict.get("colo", ""))
        row_dict.setdefault("country", row_dict.get("country", ""))
        row_dict.setdefault("egress_ip", row_dict.get("egress_ip", ""))
        row_dict.setdefault("asn", row_dict.get("asn", ""))
        row_dict.setdefault("isp", row_dict.get("isp", ""))
        row_dict.setdefault("net_type", row_dict.get("net_type", ""))
        row_dict.setdefault("tested_at", row_dict.get("tested_at", ""))
        row_dict.setdefault("first_seen", row_dict.get("first_seen", "") or LEGACY_DEFAULT_FIRST_SEEN)

        if "host" not in row_dict or not row_dict["host"]:
            try:
                u = urllib.parse.urlparse(url)
                row_dict["host"] = u.hostname or ""
                row_dict["port"] = u.port or ""
                row_dict.setdefault("user", u.username or "")
                row_dict.setdefault("pwd", u.password or "")
            except Exception:
                row_dict["host"] = ""
                row_dict["port"] = ""
                row_dict.setdefault("user", "")
                row_dict.setdefault("pwd", "")

        fc = safe_int(row_dict.get("fail_count"), 0)
        dms = safe_int(row_dict.get("delay_ms"), 0)
        if dms <= 0:
            dms = 99999
        groups.setdefault(proto, []).append((fc, dms, url, row_dict))

    active_files = set()
    result_counts = {}

    for proto, items in groups.items():
        items.sort(key=lambda x: (x[0], x[1]))
        title = PROXY_PROTO_NAMES.get(proto, f"{proto.upper()} 代理")
        safe_proto = re.sub(r'[\\/:*?"<>|]', "_", proto).strip().lower() or "other"

        # 1. 保存纯文本单协议列表（原子写入）
        txt_fname = f"{safe_proto}.txt"
        txt_filepath = os.path.join(output_dir, txt_fname)
        tmp_txt = f"{txt_filepath}.tmp"
        lines = [f"# {title} - {len(items)} 个\n"]
        for _, _, url, _ in items:
            lines.append(f"{url}\n")
        with open(tmp_txt, "w", encoding="utf-8") as f:
            f.writelines(lines)
        os.replace(tmp_txt, txt_filepath)
        active_files.add(txt_fname)

        # 2. 保存纯净单协议结构化 CSV（原子写入）
        csv_fname = f"{safe_proto}.csv"
        csv_filepath = os.path.join(output_dir, csv_fname)
        tmp_csv = f"{csv_filepath}.tmp"
        with open(tmp_csv, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PROXY_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for _, _, _, r_dict in items:
                writer.writerow(r_dict)
        os.replace(tmp_csv, csv_filepath)
        active_files.add(csv_fname)

        # 3. 保存标准化单协议 JSON 接口数据（原子写入，完美兼容 EDT-Toolkit / 油猴脚本）
        json_fname = f"{safe_proto}.json"
        json_filepath = os.path.join(output_dir, json_fname)
        tmp_json = f"{json_filepath}.tmp"
        json_list = [format_proxy_json_item(r_dict) for _, _, _, r_dict in items]
        with open(tmp_json, "w", encoding="utf-8") as f:
            json.dump(json_list, f, ensure_ascii=False, indent=2)
        os.replace(tmp_json, json_filepath)
        active_files.add(json_fname)

        result_counts[proto] = len(items)

    # 仅清理已知代理协议命名的陈旧 .txt、.csv 与 .json 文件，严禁误删用户自定义文件 (P2)
    known_stems = set(PROXY_PROTO_ORDER) | {"other", "unknown", "socks"}
    for old_f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, old_f)
        if not os.path.isfile(fpath):
            continue
        base_name, ext = os.path.splitext(old_f)
        if ext in (".txt", ".csv", ".json") and base_name.lower() in known_stems and old_f not in active_files:
            try:
                os.remove(fpath)
            except OSError:
                pass

    return result_counts


def save_proxies_csv(rows: list, csv_path: str = "data/proxies.csv") -> int:
    """
    保存 proxies.csv 结构化数据总表，按 (协议大类, fail_count 升序, delay_ms 升序) 分块排列（原子写入防截断）。
    彻底杜绝不同协议交错混杂，并与 data/proxies/{proto}.csv 保持完全一致的元数据格式。
    返回保存的有效节点总数。
    """
    formatted_rows = []
    seen = set()

    for item in rows:
        if isinstance(item, dict):
            url = (item.get("url") or "").strip()
            row_dict = dict(item)
        else:
            url = str(item).strip()
            row_dict = {"url": url}

        if not url or url.startswith("#") or url in seen:
            continue
        seen.add(url)

        proto = (row_dict.get("proto") or "").strip().lower()
        if not proto:
            proto = url.split("://", 1)[0].lower() if "://" in url else "other"
        row_dict["proto"] = proto
        row_dict.setdefault("fail_count", safe_int(row_dict.get("fail_count"), 0))
        row_dict.setdefault("delay_ms", safe_int(row_dict.get("delay_ms"), 0))
        row_dict.setdefault("status", row_dict.get("status", "pending"))
        row_dict.setdefault("colo", row_dict.get("colo", ""))
        row_dict.setdefault("country", row_dict.get("country", ""))
        row_dict.setdefault("egress_ip", row_dict.get("egress_ip", ""))
        row_dict.setdefault("asn", row_dict.get("asn", ""))
        row_dict.setdefault("isp", row_dict.get("isp", ""))
        row_dict.setdefault("net_type", row_dict.get("net_type", ""))
        row_dict.setdefault("tested_at", row_dict.get("tested_at", ""))
        row_dict.setdefault("first_seen", row_dict.get("first_seen", "") or LEGACY_DEFAULT_FIRST_SEEN)

        if "host" not in row_dict or not row_dict["host"]:
            try:
                u = urllib.parse.urlparse(url)
                row_dict["host"] = u.hostname or ""
                row_dict["port"] = u.port or ""
                row_dict.setdefault("user", u.username or "")
                row_dict.setdefault("pwd", u.password or "")
            except Exception:
                row_dict["host"] = ""
                row_dict["port"] = ""
                row_dict.setdefault("user", "")
                row_dict.setdefault("pwd", "")

        formatted_rows.append(row_dict)

    def _sort_key(r):
        proto = (r.get("proto") or "").strip().lower()
        p_idx = PROXY_PROTO_ORDER.index(proto) if proto in PROXY_PROTO_ORDER else len(PROXY_PROTO_ORDER)
        fc = safe_int(r.get("fail_count"), 0)
        dms = safe_int(r.get("delay_ms"), 0)
        if dms <= 0:
            dms = 99999
        return (p_idx, fc, dms)

    formatted_rows.sort(key=_sort_key)

    dir_name = os.path.dirname(os.path.abspath(csv_path))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    tmp_csv = f"{csv_path}.tmp"
    with open(tmp_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PROXY_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in formatted_rows:
            writer.writerow(r)
    os.replace(tmp_csv, csv_path)
    log.info("已按协议分块覆写保存 %s: %d 条质检状态记录 (无交错混杂)", csv_path, len(formatted_rows))
    return len(formatted_rows)


# ============================================================
# 网络属性（ISP宽带 / 商业专线 / 高校教育 / 政务公共）识别引擎 (方案 A)
# ============================================================

HOSTING_EXCLUSIONS = (
    "host", "server", "cloud", "vps", "datacenter", "data center",
    "colo", "nodes", "compute", "dedicated", "transit", "voxility",
    "ovh", "hetzner", "digitalocean", "linode", "vultr", "choopa",
    "akamai", "fastly", "cloudflare", "amazon", "alibaba", "tencent",
    "leaseweb", "cogent", "level 3", "lumen", "telia company ab",
    "gtt", "hurricane electric", "he.net", "global connectivity",
    "brainoza", "timeweb", "green floid", "cgi global", "mitelis",
    "globaltelehost", "bytefilter", "globaltech", "perfecto mobile",
    "u1 digital", "serv.host", "it7 networks", "aeza", "netcup",
    "layeronline", "m247", "datacamp", "clouvider", "contabo",
    "sakura internet", "conoha", "kamatera", "racknerd", "buyvm",
    "frantech", "vmiss", "dmit", "akile", "bytevirt", "bandwagon",
    "xtom", "synlinq", "tzulo", "drosys", "dromatics", "nktele",
    "moedove", "fiberxpress", "skyquantum", "gsl networks", "idc cube",
)

EDU_PATTERNS = (
    "university", "college", "school", "education", "cernet",
    "academician research", "academic", "institute of technology",
    "polytechnic", "edunet", "research network", "research", "renater", "dfn", "surfnet",
)

GOV_PATTERNS = (
    "ministry of", "department of", "parliament", "municipality",
    "federal government", "state government", "public administration",
    "beltelecom",
)

BIZ_PATTERNS = (
    "pccw business", "data communication business", "at&t enterprises",
    "enterprise", "corporate", "commercial", "business internet",
)

ISP_RES_PATTERNS = (
    "residential", "consumer broadband", "ftth", "fiber to the home", "adsl customer", "cable internet",
    "superloop", "hyperoptic", "viewqwest", "wyyerd",
    "sony network", "chubu telecom", "internet initiative", "optage", "eo hikari",
    "biglobe", "so-net", "docomo", "softbank", "kddi", "chunghwa", "hinet",
    "comcast", "charter", "spectrum", "cox", "hkt", "hkbn", "korea telecom",
    "sk broadband", "singtel", "deutsche telekom", "vodafone", "orange",
    "shaw", "british telecom", "kazakhtelecom", "transtelecom", "vnpt", "viettel",
    "bell canada", "rogers", "frontier", "windstream", "centurylink", "swisscom",
    "proximus", "kpn", "telenor", "telia", "virgin media", "o2", "turkcell",
    "turk telekom", "china telecom", "china unicom", "china mobile", "wave broadband",
    # 补充完整全称别名兼容
    "charter communications", "cox communications", "hkt limited", "hong kong broadband network",
    "singapore telecommunications", "shaw communications", "british telecommunications",
    "vietnam posts and telecommunications", "softbank corp", "rogers communications",
    "frontier communications", "lumen technologies", "telia sonera", "o2 czech",
    # 扩展日韩与东南亚民用住宅宽带、有线电视 (CATV) 与志愿者网络
    "softether", "jcom", "j:com", "asahi net", "tokai communications", "qtnet",
    "its communications", "itscom", "freebit", "infoweb", "er-telecom", "dom.ru",
    "hellovision", "triple t broadband", "cable tv", "cable television",
    "cable network", "catv", "broadcasting", "fiber network",
    # 补充东欧/俄罗斯/东南亚/中东/拉美/大洋洲头部主流电信运营商关键词
    "rostelecom", "megafon", "mobile telesystems", "mts pjsc", "mts jllc",
    "yettel", "algar telecom", "cs loxinfo", "sai gon postel", "one new zealand",
    "emirates integrated telecommunications",
)

BANKING_PATTERNS = (
    "central bank", "reserve bank", "federal reserve", "monetary authority",
    "commercial bank", "investment bank", "credit union", "banco", "banque",
    "banking", "financial group", "finance", "jpmorgan", "goldman sachs",
    "citigroup", "hsbc", "barclays", "bnp paribas", "deutsche bank",
)

SPECIAL_NET_TYPE_FILES = {
    "isp": "【ISP_运营商原生宽带】.txt",
    "business": "【BIZ_商业企业专线】.txt",
    "education": "【EDU_高校教育科研】.txt",
    "government": "【GOV_政务公共网络】.txt",
    "banking": "【BANK_银行金融专网】.txt",
}

# ----------------------------------------------------
# ASN 正则提取与内置权威精确对照表 (Tier 1)
# ----------------------------------------------------
_ASN_WITH_PREFIX_RE = re.compile(r"\bAS\s*(\d+)\b", re.IGNORECASE)
_PURE_NUMBER_RE = re.compile(r"^\s*(\d+)\s*$")


def _extract_asn_code(asn_str: str | None, isp_str: str | None = "") -> str | None:
    """
    智能提取规范的 AS 编号 (如 AS4760)：
    - 支持前缀格式：AS4760、as4760、AS 4760、as 4760
    - 支持纯数字编号：4760、" 4760 "
    - 优先检查 asn_str，随后检查 isp_str
    """
    for s in (asn_str, isp_str):
        if not s:
            continue
        s = str(s)

        m = _ASN_WITH_PREFIX_RE.search(s)
        if m:
            return f"AS{m.group(1)}"

        m = _PURE_NUMBER_RE.match(s)
        if m:
            return f"AS{m.group(1)}"

    return None


# 注：ASN_EXACT_NET_TYPE 已全面解耦至 data/asn_database.json (asn_to_net_type)
# 并在模块初始化时（见上方）动态加载并与已知云厂商（KNOWN_CLOUD_PROVIDERS）合并，兼具核心骨干基准兜底。


def is_asn_recorded(asn_str: str | None, isp_str: str | None = "") -> bool:
    """
    判断目标节点是否免于触发『未收录 ASN 补库告警』：
    - 返回 True：该 AS 编号已被权威对照表收录，或节点本身无有效 AS 编号（无需作为新 ASN 告警）。
    - 返回 False：提取到了有效 AS 编号，但该编号尚未被内置库收录（需上报至统计卡片，提示补充）。
    注：无有效 ASN 编号时返回 True，是为避免将缺少 ASN 元数据的正常节点误报为待补充的新自治系统。
    """
    code = _extract_asn_code(asn_str, isp_str)
    if not code:
        return True
    return code in ASN_EXACT_NET_TYPE or code in ASN_TO_PROVIDER or code in ASN_DATABASE_ASN_TO_ISP


def classify_asn(asn_str: str | None, isp_str: str | None = "") -> str:
    """
    根据 BGP 广播的 ASN 编号、机构名称与 ISP 归属进行多维度网络类型属性分类（方案 A+ 两级分层体系）：
      [Tier 1] 内置权威精准对照：提取 AS 编号优先查表，秒级高精度定性
      [Tier 2] 启发式词根智能匹配：教育、政务、金融银行、排除机房、商业专线、运营商宽带
      [Tier 3] 安全降级兜底：未命中任何已知特征的全新节点归为 datacenter 机房
    返回类型：
      - education: 高校与学术科研网
      - government: 政府政务与国家公共网
      - banking: 银行金融与央行专网
      - isp: 电信民用原生宽带（非机房资产，信誉拟真度高）
      - business: 商业固定专线与商务光纤
      - datacenter: 常规云主机与数据中心机房（默认）
    """
    # [Tier 1] 内置权威精准对照 (Fast-path Lookup)
    asn_code = _extract_asn_code(asn_str, isp_str)
    if asn_code and asn_code in ASN_EXACT_NET_TYPE:
        return ASN_EXACT_NET_TYPE[asn_code]

    # [Tier 2] 启发式词根规则智能匹配 (Pattern Fallback)
    text = f"{asn_str or ''} {isp_str or ''}".lower().strip()
    if not text:
        return "datacenter"

    # 1. 优先识别教育网
    if any(p in text for p in EDU_PATTERNS):
        return "education"

    # 2. 识别政务公用网
    if any(p in text for p in GOV_PATTERNS):
        return "government"

    # 3. 识别银行与金融专网
    if any(p in text for p in BANKING_PATTERNS):
        return "banking"

    # 4. 排除机房/主机商（对短词如 host/vps/colo 使用独立单词边界匹配，杜绝 ghost/colorado 等合法运营商词根误杀）
    is_hosting = False
    for h in HOSTING_EXCLUSIONS:
        if len(h) <= 4:
            if re.search(rf"\b{re.escape(h)}\b", text, re.IGNORECASE):
                is_hosting = True
                break
        elif h in text:
            is_hosting = True
            break

    # 5. 识别商业专线
    if any(p in text for p in BIZ_PATTERNS) and not is_hosting:
        return "business"

    # 6. 识别电信运营商原生宽带
    if any(p in text for p in ISP_RES_PATTERNS) and not is_hosting:
        return "isp"

    # [Tier 3] 安全降级兜底 (Default Fallback)
    return "datacenter"


def save_proxyip_by_country(rows: list, output_dir: str) -> int:
    """
    将 ProxyIP 列表按国家/地区拆分输出为独立的纯文本文件（如 美国.txt、日本.txt）。
    同时自动提取高价值稀缺属性节点导出为独立专用清单（如 【ISP_运营商原生宽带】.txt 等）。
    每个文件内容仅包含纯净的 IP:端口（保留传入时的原始质量排序，无任何注释头），
    方便用户直接在编辑器中全选复制（Ctrl+A / Ctrl+C）或按国家/属性独立订阅。
    自动清理目录中已不存在的旧地区文件，返回生成的独立文件数量。
    """
    if not rows:
        return 0

    os.makedirs(output_dir, exist_ok=True)
    groups: dict[str, list] = {}
    type_groups: dict[str, list] = {}

    for r in rows:
        country = extract_country(r.get("cf_location"), r.get("colo"))
        groups.setdefault(country, []).append(r)

        # 复用已打标属性，缺失时兜底补齐
        nt = r.get("net_type") or classify_asn(r.get("asn", ""), r.get("isp", ""))
        r["net_type"] = nt
        if nt in SPECIAL_NET_TYPE_FILES:
            type_groups.setdefault(nt, []).append(r)

    active_files = set()

    # 1. 导出各国家/地区独立清单
    for country, members in groups.items():
        lines = [
            f"{(r.get('ip') or '').strip()}:{r.get('port')}\n"
            for r in members
            if (r.get("ip") or "").strip() and r.get("port")
        ]
        if not lines:
            continue
        safe_country = re.sub(r'[\\/:*?"<>|]', "_", country).strip() or "其他地区"
        fname = f"{safe_country}.txt"
        filepath = os.path.join(output_dir, fname)
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
        active_files.add(fname)

    # 2. 导出高价值特殊网络属性清单（运营商宽带、企业专线、高校教育、政务公用、银行金融）
    for nt, fname in SPECIAL_NET_TYPE_FILES.items():
        members = type_groups.get(nt, [])
        lines = [
            f"{(r.get('ip') or '').strip()}:{r.get('port')}\n"
            for r in members
            if (r.get("ip") or "").strip() and r.get("port")
        ]
        if not lines:
            continue
        filepath = os.path.join(output_dir, fname)
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
        active_files.add(fname)

    # 清理已不存在或旧命名格式的 .txt 文件（保留 .gitkeep 等非 txt 标记文件，以及 custom_ / manual_ 用户自定义文件）
    for old_f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, old_f)
        if (
            os.path.isfile(fpath)
            and old_f.endswith(".txt")
            and old_f not in active_files
            and not old_f.startswith("custom_")
            and not old_f.startswith("manual_")
        ):
            try:
                os.remove(fpath)
            except OSError:
                pass

    return len(active_files)


def save_scan_ips_by_asn(asn_groups: dict, output_dir: str) -> int:
    """
    覆写 scan_ips/ 目录下的独立 ASN 纯文本文件（无注释 IP:端口；原子写入防截断）。
    死节点被淘汰后，其对应的 ASN 文件会即时同步删除该 IP；
    若某个 ASN 旗下所有 IP 全部死亡淘汰，该 ASN 文本文件也会被自动清除删除（保留 .gitkeep 保持目录结构）。
    返回生成的独立文件数量。
    """
    if not asn_groups:
        return 0

    os.makedirs(output_dir, exist_ok=True)
    active_files = set()
    for asn_name, group in asn_groups.items():
        isp_name = ASN_TO_PROVIDER.get(asn_name, "")
        if not isp_name:
            isp_name = next((r.get("isp") for r in group if r.get("isp")), "")

        # 严谨过滤文件名非法字符（特别是 Windows / Linux 路径分隔符 / 与 \，以及冒号等）
        safe_asn = re.sub(r'[\\/:*?"<>|\s]', "_", str(asn_name).strip()).strip(" ._") or "AS_UNKNOWN"
        safe_asn = re.sub(r"_+", "_", safe_asn)
        clean_isp = re.sub(r"[^a-zA-Z0-9]", "", isp_name) if isp_name else ""
        if clean_isp and clean_isp.lower() != safe_asn.lower():
            fname = f"{safe_asn}_{clean_isp}.txt"
        else:
            fname = f"{safe_asn}.txt"
        fpath = os.path.join(output_dir, fname)
        tmp_fpath = f"{fpath}.tmp"

        valid_rows = [
            r for r in group
            if r.get("ip") and safe_int(r.get("port"), 0) > 0 and safe_int(r.get("port"), 0) <= 65535
        ]
        if not valid_rows:
            continue

        with open(tmp_fpath, "w", encoding="utf-8") as f:
            for r in sorted(valid_rows, key=lambda x: (x.get("ip", ""), safe_int(x.get("port"), 0))):
                f.write(f"{r['ip']}:{safe_int(r.get('port'), 0)}\n")
        os.replace(tmp_fpath, fpath)
        active_files.add(fname)

    # 移除已无活跃 IP 的旧分组文件（保留 .gitkeep 保持目录结构）
    for old_f in os.listdir(output_dir):
        if old_f == ".gitkeep":
            continue
        if (
            old_f.endswith(".txt")
            and old_f not in active_files
            and not old_f.startswith("custom_")
            and not old_f.startswith("manual_")
        ):
            try:
                os.remove(os.path.join(output_dir, old_f))
            except OSError:
                pass

    log.info("已覆写更新 %s/ 目录: %d 个独立 ASN 纯文本文件", output_dir, len(active_files))
    return len(active_files)


# 兼容别名
save_scan_dir = save_scan_ips_by_asn


# =====================================================================
# 墓地机制 (Tombstone): 淘汰死节点记忆库与隔离冷却管理
# =====================================================================

TOMBSTONE_FILE = os.path.join("data", "tombstone.json")
TOMBSTONE_MAX_AGE_DAYS = 7


def canonical_key(host_or_ip: str, port: int | str) -> str:
    """生成标准化节点去重/墓地键 (小写 host/ip + 规范纯数字端口)"""
    h = str(host_or_ip).strip().lower()
    try:
        p = int(str(port).strip())
    except (ValueError, TypeError):
        p = str(port).strip()
    return f"{h}:{p}"


_TOMBSTONE_CACHE: dict[str, int] | None = None
_TOMBSTONE_CACHE_FILE: str | None = None
_TOMBSTONE_CACHE_MTIME: float = 0.0


def load_tombstone(
    filepath: str | None = None,
    max_age_days: int = TOMBSTONE_MAX_AGE_DAYS,
    force_reload: bool = False,
) -> dict[str, int]:
    """
    读取墓地黑名单 (已被淘汰的死节点记忆库)。
    自动过滤/清理超过 max_age_days 天的过期记录，确保黑名单体积极简轻量。
    带轻量进程内缓存与 mtime 变更检测，避免同一批次多模块重复反序列化。
    返回 {canonical_key: eliminated_timestamp}。
    """
    global _TOMBSTONE_CACHE, _TOMBSTONE_CACHE_FILE, _TOMBSTONE_CACHE_MTIME
    target_path = filepath if filepath is not None else TOMBSTONE_FILE
    if not os.path.isfile(target_path):
        _TOMBSTONE_CACHE = {}
        _TOMBSTONE_CACHE_FILE = target_path
        _TOMBSTONE_CACHE_MTIME = 0.0
        return {}

    try:
        mtime = os.path.getmtime(target_path)
    except OSError:
        mtime = 0.0

    if not force_reload and _TOMBSTONE_CACHE is not None and _TOMBSTONE_CACHE_FILE == target_path and mtime == _TOMBSTONE_CACHE_MTIME:
        return dict(_TOMBSTONE_CACHE)

    now = int(time.time())
    max_age_sec = max_age_days * 86400
    valid: dict[str, int] = {}
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, ts in data.items():
                if isinstance(ts, (int, float)) and (now - int(ts)) < max_age_sec:
                    valid[str(k).strip().lower()] = int(ts)
        _TOMBSTONE_CACHE = valid
        _TOMBSTONE_CACHE_FILE = target_path
        _TOMBSTONE_CACHE_MTIME = mtime
    except Exception as e:
        log.warning("读取墓地文件 %s 失败: %s", target_path, e)
    return dict(valid)


def prune_tombstone(
    filepath: str | None = None,
    max_age_days: int = TOMBSTONE_MAX_AGE_DAYS,
) -> int:
    """
    主动修剪磁盘上超过 max_age_days 天的过期墓碑条目并原子持久化。
    若磁盘文件无过期条目或文件不存在，不产生冗余写 I/O。
    返回本次修剪删除的过期条目数量。
    """
    global _TOMBSTONE_CACHE, _TOMBSTONE_CACHE_FILE, _TOMBSTONE_CACHE_MTIME
    target_path = filepath if filepath is not None else TOMBSTONE_FILE
    if not os.path.isfile(target_path):
        return 0

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning("读取墓地文件 %s 执行修剪失败: %s", target_path, e)
        return 0

    if not isinstance(data, dict) or not data:
        return 0

    now = int(time.time())
    max_age_sec = max_age_days * 86400
    valid: dict[str, int] = {}
    pruned_count = 0

    for k, ts in data.items():
        if isinstance(ts, (int, float)) and (now - int(ts)) < max_age_sec:
            valid[str(k).strip().lower()] = int(ts)
        else:
            pruned_count += 1

    if pruned_count > 0:
        dir_name = os.path.dirname(os.path.abspath(target_path))
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        tmp_path = f"{target_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(valid, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, target_path)
            _TOMBSTONE_CACHE = valid
            _TOMBSTONE_CACHE_FILE = target_path
            try:
                _TOMBSTONE_CACHE_MTIME = os.path.getmtime(target_path)
            except OSError:
                _TOMBSTONE_CACHE = None
            log.info("已主动修剪墓地文件 %s: 剔除 %d 个超过 %d 天的过期条目 (剩余: %d 个)", target_path, pruned_count, max_age_days, len(valid))
        except Exception as e:
            log.warning("写回修剪后的墓地文件 %s 失败: %s", target_path, e)
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    return pruned_count


def record_tombstone(
    keys: list[str] | set[str],
    filepath: str | None = None,
    max_age_days: int = TOMBSTONE_MAX_AGE_DAYS,
) -> int:
    """
    将新淘汰的死节点 canonical_key 批量登记至墓地持久化文件。
    登记时间为当前 Unix 时间戳，同时自动修剪超过 max_age_days 的历史陈旧死节点。
    采用原子写入 (.tmp -> os.replace) 防止并发损坏。
    返回本次新增登记的节点数量。
    """
    global _TOMBSTONE_CACHE, _TOMBSTONE_CACHE_FILE, _TOMBSTONE_CACHE_MTIME
    if not keys:
        prune_tombstone(filepath=filepath, max_age_days=max_age_days)
        return 0
    if filepath is None:
        filepath = TOMBSTONE_FILE
    now = int(time.time())
    tombstone = load_tombstone(filepath=filepath, max_age_days=max_age_days)
    new_count = 0
    for k in keys:
        if not k:
            continue
        clean_k = str(k).strip().lower()
        if clean_k not in tombstone:
            new_count += 1
        tombstone[clean_k] = now

    dir_name = os.path.dirname(os.path.abspath(filepath))
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    tmp_path = f"{filepath}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(tombstone, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, filepath)
        try:
            _TOMBSTONE_CACHE = tombstone
            _TOMBSTONE_CACHE_FILE = filepath
            _TOMBSTONE_CACHE_MTIME = os.path.getmtime(filepath)
        except OSError:
            _TOMBSTONE_CACHE = None
    except Exception as e:
        log.warning("写入墓地文件 %s 失败: %s", filepath, e)
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    return new_count


def is_tombstoned(
    key: str,
    tombstone: dict[str, int],
    max_age_days: int = TOMBSTONE_MAX_AGE_DAYS,
) -> bool:
    """检查节点是否处于墓地冷却隔离期内 (O(1) 判定)"""
    if not key or not tombstone:
        return False
    clean_k = str(key).strip().lower()
    ts = tombstone.get(clean_k)
    if ts is None:
        return False
    now = int(time.time())
    return (now - ts) < (max_age_days * 86400)


if __name__ == "__main__":
    import sys
    if "--validate" in sys.argv or len(sys.argv) == 1:
        errs, warns = validate_asn_database()
        if warns:
            print(f"[*] 检测到 {len(warns)} 条合法多业务线 (1对N) 自治域映射")
        if errs:
            print(f"[!] 发现 {len(errs)} 处 ASN 数据库阻断性硬错误:")
            for e in errs:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("[+] ASN 数据库一致性校验通过，0 阻断性硬错误，结构纯净合法。")
            sys.exit(0)
