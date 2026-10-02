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
    "qiniu": ("AS136907", "Qiniu Cloud"),

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
    "bandwagon": ("AS25820", "BandwagonHost"),
    "bwg": ("AS25820", "BandwagonHost"),
    "it7": ("AS25820", "BandwagonHost"),
    "claw": ("AS45102", "Claw Cloud"),
    "clawcloud": ("AS45102", "Claw Cloud"),
    "vmiss": ("AS147049", "VMISS"),
    "contabo": ("AS51167", "Contabo"),
    "netcup": ("AS197540", "Netcup"),
    "racknerd": ("AS36352", "RackNerd"),
    "buyvm": ("AS53667", "BuyVM FranTech"),
    "frantech": ("AS53667", "BuyVM FranTech"),
    "hostdare": ("AS397373", "HostDare"),
    "misaka": ("AS54600", "Misaka"),
    "kurun": ("AS13768", "Kurun Cloud"),
    "spartan": ("AS201106", "SpartanHost"),
    "spartanhost": ("AS201106", "SpartanHost"),
    "wap": ("AS149798", "WAP.ac"),
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

    # 运营商骨干与出海线路
    "hinet": ("AS3462", "Chunghwa Telecom HiNet"),
    "cmi": ("AS58453", "China Mobile CMI"),
    "chinamobile": ("AS58453", "China Mobile CMI"),
    "cug": ("AS10099", "China Unicom CUG"),
    "chinaunicom": ("AS10099", "China Unicom CUG"),
    "ctg": ("AS4134", "China Telecom CTG"),
    "chinatelecom": ("AS4134", "China Telecom 163"),
    "cn2": ("AS4809", "China Telecom CN2"),
    "chinatelecom_group": ("AS4811", "China Telecom"),
    "9929": ("AS9929", "China Unicom 9929"),
    "cmin2": ("AS58807", "China Mobile CMIN2"),
}

# ASN 到标准服务商名称反查表
ASN_TO_PROVIDER = {}
for _asn, _isp in KNOWN_CLOUD_PROVIDERS.values():
    if _asn not in ASN_TO_PROVIDER:
        ASN_TO_PROVIDER[_asn] = _isp


# =====================================================================
# 公共实用工具：环境加载、类型转换、ASN 清洗、Telegram 推送与自检
# =====================================================================

import asyncio
import csv
import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

log = logging.getLogger("providers")


# ---------- 持久化 ASN 数据库加载与在线动态解析补库 ----------

ASN_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "asn_database.json")
ASN_DATABASE_REL_PATH = os.path.join("data", "asn_database.json")


def load_asn_database() -> tuple[dict[str, str], dict[str, str]]:
    """从 data/asn_database.json 自动加载持久化 ASN/ISP 映射字典"""
    for db_path in (ASN_DATABASE_PATH, ASN_DATABASE_REL_PATH):
        if os.path.isfile(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("isp_to_asn", {}), data.get("asn_to_isp", {})
            except Exception as e:
                log.debug("读取 %s 异常: %s", db_path, e)
    return {}, {}


def save_asn_database(isp_to_asn: dict[str, str], asn_to_isp: dict[str, str]):
    """持久化保存动态发现的 ASN/ISP 数据库"""
    db_path = ASN_DATABASE_PATH
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump({"isp_to_asn": isp_to_asn, "asn_to_isp": asn_to_isp}, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.warning("保存 asn_database.json 异常: %s", e)


# 加载持久化 ASN 数据库并融合进公共字典
ASN_DATABASE_ISP_TO_ASN, ASN_DATABASE_ASN_TO_ISP = load_asn_database()
for _asn, _isp in ASN_DATABASE_ASN_TO_ISP.items():
    if _asn not in ASN_TO_PROVIDER and _isp:
        ASN_TO_PROVIDER[_asn] = _isp

# 生成排序别名元组（按关键词长度降序优先匹配更长更精确的名称，如 'huaweicloud' 优于 'huawei'）
# 保持 KNOWN_CLOUD_PROVIDERS 作为权威云厂商/VPS/骨干网词库的独立纯净性，杜绝注入数据库泛 ISP 产生子串碰撞
SORTED_CLOUD_PROVIDER_KEYS = tuple(sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True))
ASN_DATABASE_ISP_LOWER = {k.lower(): (v, k) for k, v in ASN_DATABASE_ISP_TO_ASN.items()}


def resolve_asn_online(ip: str, isp_hint: str = "", persist: bool = False) -> tuple[str, str]:
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

    # 通道 1 (首选): ip-api.com (语义优先: 实际商业 isp > 组织机构 org > 路由技术别名 asname)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,asname,org,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            data = json.loads(res.read().decode("utf-8", errors="ignore"))
            if data.get("status") == "success":
                raw_as = str(data.get("as") or "")
                as_match = re.search(r"(AS\d+)", raw_as, re.IGNORECASE)
                if as_match:
                    clean_asn = as_match.group(1).upper()
                    # 正规语义提取：坚决不从 as 字段中截取大厦/街道地址，根治地址污染
                    raw_isp_val = (data.get("isp") or "").strip()
                    raw_org_val = (data.get("org") or "").strip()
                    raw_asname_val = (data.get("asname") or "").strip()
                    clean_isp = raw_isp_val or raw_org_val or raw_asname_val or isp_hint or ""
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
                raw_asn = asn_obj.get("asn") or ""
                m = re.search(r"(AS\d+)", str(raw_asn), re.IGNORECASE)
                if m:
                    clean_asn = m.group(1).upper()
                    clean_isp = asn_obj.get("name") or isp_hint or ""
        except Exception as e:
            log.debug("iplocate.io 在线解析 IP %s 失败: %s", ip, e)

    # 通道 3 (备选容灾): ipapi.co (HTTPS, 免 Key)
    if not clean_asn:
        try:
            url = f"https://ipapi.co/{ip}/json/"
            req = urllib.request.Request(url, headers={"User-Agent": "ipapi.co/#python-v1.0.3"})
            with urllib.request.urlopen(req, timeout=3.5) as res:
                data = json.loads(res.read().decode("utf-8", errors="ignore"))
                raw_asn = data.get("asn") or ""
                m = re.search(r"(AS\d+)", str(raw_asn), re.IGNORECASE)
                if m:
                    clean_asn = m.group(1).upper()
                    clean_isp = data.get("org") or isp_hint or ""
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

        if persist:
            save_asn_database(ASN_DATABASE_ISP_TO_ASN, ASN_DATABASE_ASN_TO_ISP)
            log.info("【自动完善数据库】已在线反查新 IP %s 并持久化入库: %s -> %s", ip, clean_asn, clean_isp)
        else:
            log.debug("【内存缓存更新】在线反查新 IP %s: %s -> %s", ip, clean_asn, clean_isp)
        return clean_asn, clean_isp

    return "", ""


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


def load_dotenv(env_path: str | None = None) -> dict:
    """
    自动加载本地 .env 文件至 os.environ（若存在）。
    仅当环境变量尚未在系统/CI 环境中定义时才写入，避免覆盖 GitHub Actions 等上游传入的 Secrets。
    返回本次实际加载的键值字典。
    """
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
    return loaded


# 模块导入时自动执行一次安全加载
load_dotenv()

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.getenv("TG_CHAT_ID") or ""


# =====================================================================
# 确定性哈希分段锁池 (Striped Locks)
# 解决同 IP/Host 互斥探测需求，且内存常数级 O(1)，无字典无界增长隐患
# =====================================================================
_LOCK_POOL_SIZE = 2048
_LOCK_POOL_MASK = _LOCK_POOL_SIZE - 1
_LOCK_POOL: list[asyncio.Lock] | None = None
_LOCK_POOL_LOOP: asyncio.AbstractEventLoop | None = None


def get_keyed_lock(key: str) -> asyncio.Lock:
    """
    返回与 key (IP/Host) 绑定的确定性分段锁。
    采用 zlib.crc32 保证跨进程/跨运行哈希一致（避免 PYTHONHASHSEED 随机化干扰）。
    同 key 必同锁，不同 key 在 2048 桶位下碰撞率极低，且内存严格常数级 O(1)，杜绝无界增长。
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
    return raw_asn if raw_asn else "AS_UNKNOWN"


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
            if clean_a and clean_a != "-":
                return clean_a
            return clean_i or "AS_UNKNOWN"

    addr_keywords = ("building", "avenue", "road", "street", "floor", "suite", "room", "district", "highway", "jalan", "park", "bldg", "kejizhongyi")
    if suffix and any(k in suffix.lower() for k in addr_keywords):
        suffix = ""
    if clean_i and any(k in clean_i.lower() for k in addr_keywords):
        clean_i = ""

    # 权威单一真相源 (SSOT) 优先：若在已收录权威字典中，采用权威统一名称
    auth_isp = ASN_TO_PROVIDER.get(code, "")
    if auth_isp:
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
                logging.getLogger(tag).warning("%s 消息发送失败: %s", tag, data.get("description") or data)
                return False
    except Exception as e:
        logging.getLogger(tag).warning("发送 %s 消息时出现异常: %s", tag, e)
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


async def read_full_response(reader: asyncio.StreamReader, http_timeout: float, max_bytes: int = 4096) -> bytes:
    """
    循环读取直到拿到完整的 HTTP 响应头（遇到 \\r\\n\\r\\n 或 \\n\\n）或达到 max_bytes 硬上限。
    用统一 deadline 控制总耗时，避免多次循环导致累计超时远超 http_timeout。
    单次 read() 动态计算剩余可用空间，避免读取超出 max_bytes 上限。
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + http_timeout
    resp_bytes = b""
    while len(resp_bytes) < max_bytes:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        chunk = await asyncio.wait_for(
            reader.read(min(1024, max_bytes - len(resp_bytes))),
            timeout=remaining,
        )
        if not chunk:
            break
        resp_bytes += chunk
        if b"\r\n\r\n" in resp_bytes or b"\n\n" in resp_bytes:
            break
    return resp_bytes


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
        delay = safe_int(r.get("delay_ms") or 99999, 99999)
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
PROXY_CSV_FIELDS = [
    "url",
    "proto",
    "host",
    "port",
    "delay_ms",
    "fail_count",
    "status",
    "colo",
    "tested_at",
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


def save_proxies_by_protocol(rows: list, output_dir: str = "data/proxies") -> dict[str, int]:
    """
    将通用代理列表按协议类型拆分并独立保存至 output_dir 目录下：
      - socks5.txt / socks5.csv: 纯 SOCKS5 代理节点
      - turn.txt / turn.csv: 纯 TURN 协议节点
      - sstp.txt / sstp.csv: 纯 SSTP 协议节点
      - http.txt / http.csv: 纯 HTTP 代理节点
      - https.txt / https.csv: 纯 HTTPS 代理节点
    各协议文件内按 (fail_count 升序, delay_ms 升序) 排列，首行附带注释汇总头，彻底杜绝不同协议交错混杂。
    返回各协议文件生成的节点数量字典。
    """
    os.makedirs(output_dir, exist_ok=True)

    groups: dict[str, list] = {}
    seen = set()

    for item in rows:
        if isinstance(item, dict):
            url = (item.get("url") or "").strip()
            proto = (item.get("proto") or "").strip().lower()
            fc = safe_int(item.get("fail_count"), 0)
            dms = safe_int(item.get("delay_ms"), 0)
            row_dict = dict(item)
        else:
            url = str(item).strip()
            proto = ""
            fc = 0
            dms = 0
            row_dict = {"url": url}

        if not url or url.startswith("#"):
            continue
        if url in seen:
            continue
        seen.add(url)

        if not proto:
            proto = url.split("://", 1)[0].lower() if "://" in url else "other"

        if dms <= 0:
            dms = 99999

        row_dict["proto"] = proto
        row_dict.setdefault("fail_count", fc)
        row_dict.setdefault("delay_ms", item.get("delay_ms", 0) if isinstance(item, dict) else 0)
        row_dict.setdefault("status", item.get("status", "pending") if isinstance(item, dict) else "pending")
        row_dict.setdefault("colo", item.get("colo", "") if isinstance(item, dict) else "")
        row_dict.setdefault("tested_at", item.get("tested_at", "") if isinstance(item, dict) else "")

        if "host" not in row_dict or not row_dict["host"]:
            try:
                u = urllib.parse.urlparse(url)
                row_dict["host"] = u.hostname or ""
                row_dict["port"] = u.port or ""
            except Exception:
                row_dict["host"] = ""
                row_dict["port"] = ""

        groups.setdefault(proto, []).append((fc, dms, url, row_dict))

    active_files = set()
    result_counts = {}

    for proto, items in groups.items():
        items.sort(key=lambda x: (x[0], x[1]))
        title = PROXY_PROTO_NAMES.get(proto, f"{proto.upper()} 代理")
        safe_proto = re.sub(r'[\\/:*?"<>|]', "_", proto).strip().lower() or "other"

        # 1. 保存纯文本单协议列表
        txt_fname = f"{safe_proto}.txt"
        txt_filepath = os.path.join(output_dir, txt_fname)
        lines = [f"# {title} - {len(items)} 个\n"]
        for _, _, url, _ in items:
            lines.append(f"{url}\n")
        with open(txt_filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
        active_files.add(txt_fname)

        # 2. 保存纯净单协议结构化 CSV
        csv_fname = f"{safe_proto}.csv"
        csv_filepath = os.path.join(output_dir, csv_fname)
        with open(csv_filepath, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PROXY_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for _, _, _, r_dict in items:
                writer.writerow(r_dict)
        active_files.add(csv_fname)

        result_counts[proto] = len(items)

    # 清理已不存在或旧命名格式的 .txt 与 .csv 文件
    for old_f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, old_f)
        if os.path.isfile(fpath) and old_f.endswith((".txt", ".csv")) and old_f not in active_files:
            try:
                os.remove(fpath)
            except OSError:
                pass

    return result_counts


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


ASN_EXACT_NET_TYPE = {
    # 1. 运营商原生民用家宽 (isp) - 共 903 个
        "AS2527": "isp", "AS18126": "isp", "AS2497": "isp", "AS17511": "isp", "AS17676": "isp", "AS2516": "isp",
        "AS4713": "isp", "AS2518": "isp", "AS17506": "isp", "AS2519": "isp", "AS2514": "isp", "AS9605": "isp",
        "AS4725": "isp", "AS4760": "isp", "AS9269": "isp", "AS9304": "isp", "AS9231": "isp", "AS10103": "isp",
        "AS135327": "isp", "AS3462": "isp", "AS4780": "isp", "AS9924": "isp", "AS18049": "isp", "AS18182": "isp",
        "AS4609": "isp", "AS9908": "isp", "AS4766": "isp", "AS9318": "isp", "AS3786": "isp", "AS9249": "isp",
        "AS17858": "isp", "AS7562": "isp", "AS4657": "isp", "AS10099": "isp", "AS58807": "isp", "AS45899": "isp",
        "AS7552": "isp", "AS18403": "isp", "AS4775": "isp", "AS9198": "isp", "AS9121": "isp", "AS16135": "isp",
        "AS7473": "isp", "AS18106": "isp", "AS9541": "isp", "AS7713": "isp", "AS38060": "isp", "AS17885": "isp",
        "AS131445": "isp", "AS135905": "isp", "AS216472": "isp", "AS23673": "isp", "AS131207": "isp", "AS7470": "isp",
        "AS13132": "isp", "AS38040": "isp", "AS4761": "isp", "AS9299": "isp", "AS4765": "isp", "AS9930": "isp",
        "AS23700": "isp", "AS10030": "isp", "AS9498": "isp", "AS55836": "isp", "AS9829": "isp", "AS45595": "isp",
        "AS10143": "isp", "AS7545": "isp", "AS56030": "isp", "AS9790": "isp", "AS17477": "isp", "AS7922": "isp",
        "AS20115": "isp", "AS22773": "isp", "AS11404": "isp", "AS852": "isp", "AS812": "isp", "AS577": "isp",
        "AS701": "isp", "AS7018": "isp", "AS5650": "isp", "AS7029": "isp", "AS209": "isp", "AS6327": "isp",
        "AS10796": "isp", "AS11351": "isp", "AS19165": "isp", "AS6128": "isp", "AS22394": "isp", "AS21928": "isp",
        "AS33588": "isp", "AS13037": "isp", "AS6079": "isp", "AS54936": "isp", "AS11426": "isp", "AS7992": "isp",
        "AS30036": "isp", "AS5056": "isp", "AS14155": "isp", "AS5769": "isp", "AS16591": "isp", "AS20001": "isp",
        "AS19108": "isp", "AS11232": "isp", "AS11139": "isp", "AS855": "isp", "AS5645": "isp", "AS19970": "isp",
        "AS3320": "isp", "AS5607": "isp", "AS3215": "isp", "AS2856": "isp", "AS6830": "isp", "AS3303": "isp",
        "AS12322": "isp", "AS1241": "isp", "AS30722": "isp", "AS6805": "isp", "AS3352": "isp", "AS5410": "isp",
        "AS5466": "isp", "AS8422": "isp", "AS3269": "isp", "AS43376": "isp", "AS3301": "isp", "AS3292": "isp",
        "AS6713": "isp", "AS8551": "isp", "AS1273": "isp", "AS56478": "isp", "AS5089": "isp", "AS5378": "isp", "AS13285": "isp",
        "AS3209": "isp", "AS35244": "isp", "AS8767": "isp", "AS33915": "isp", "AS12741": "isp", "AS35179": "isp",
        "AS8758": "isp", "AS15796": "isp", "AS51582": "isp", "AS12479": "isp", "AS25400": "isp", "AS6866": "isp",
        "AS35805": "isp", "AS34984": "isp", "AS58002": "isp", "AS15557": "isp", "AS24589": "isp", "AS15895": "isp",
        "AS205673": "isp", "AS20632": "isp", "AS34351": "isp", "AS51032": "isp", "AS8881": "isp", "AS8612": "isp",
        "AS1267": "isp", "AS197828": "isp", "AS5432": "isp", "AS6848": "isp", "AS3243": "isp", "AS12353": "isp",
        "AS12912": "isp", "AS25513": "isp", "AS12883": "isp", "AS52163": "isp", "AS199669": "isp",
        "AS60042": "isp", "AS62366": "isp", "AS51248": "isp", "AS6697": "isp", "AS4230": "isp", "AS10834": "isp",
        "AS52468": "isp", "AS4134": "isp", "AS4837": "isp", "AS9808": "isp", "AS58453": "isp", "AS4809": "isp",
        "AS4811": "isp", "AS4812": "isp", "AS4813": "isp", "AS4816": "isp", "AS4847": "isp", "AS36678": "isp",
        "AS58772": "isp", "AS56040": "isp",
        "AS9929": "isp", "AS4808": "isp", "AS270062": "isp", "AS3816": "isp", "AS269771": "isp", "AS274170": "isp",
        "AS264778": "isp", "AS208972": "isp", "AS61461": "isp", "AS22884": "isp", "AS3549": "isp", "AS131464": "isp",
        "AS45903": "isp", "AS263791": "isp", "AS272838": "isp", "AS146954": "isp", "AS138782": "isp", "AS270052": "isp",
        "AS45758": "isp", "AS28387": "isp", "AS203214": "isp", "AS28186": "isp", "AS264628": "isp", "AS9050": "isp",
        "AS37403": "isp", "AS28330": "isp", "AS15704": "isp", "AS11427": "isp", "AS329402": "isp", "AS328539": "isp",
        "AS12389": "isp", "AS133443": "isp", "AS55492": "isp", "AS151542": "isp", "AS139994": "isp", "AS132296": "isp",
        "AS35699": "isp", "AS58689": "isp", "AS272112": "isp", "AS37305": "isp", "AS154217": "isp", "AS265038": "isp",
        "AS273974": "isp", "AS8368": "isp", "AS23889": "isp", "AS273001": "isp", "AS27951": "isp", "AS17501": "isp",
        "AS269139": "isp", "AS264075": "isp", "AS152479": "isp", "AS45804": "isp", "AS135341": "isp", "AS28326": "isp",
        "AS262753": "isp", "AS274128": "isp", "AS263980": "isp", "AS27988": "isp", "AS45433": "isp", "AS52871": "isp",
        "AS149770": "isp", "AS38156": "isp", "AS273009": "isp", "AS264556": "isp", "AS262595": "isp", "AS27901": "isp",
        "AS12975": "isp", "AS13999": "isp", "AS265629": "isp", "AS267699": "isp", "AS269891": "isp", "AS58800": "isp",
        "AS7303": "isp", "AS264162": "isp", "AS139524": "isp", "AS262989": "isp", "AS265579": "isp", "AS266900": "isp",
        "AS45905": "isp", "AS262807": "isp", "AS9230": "isp", "AS133989": "isp", "AS8400": "isp", "AS26879": "isp",
        "AS4618": "isp", "AS11556": "isp", "AS150750": "isp", "AS139009": "isp", "AS274956": "isp", "AS28146": "isp",
        "AS38182": "isp", "AS12997": "isp", "AS31549": "isp", "AS207044": "isp", "AS19751": "isp", "AS206854": "isp",
        "AS212444": "isp", "AS63969": "isp", "AS55330": "isp", "AS28343": "isp", "AS21246": "isp", "AS64139": "isp",
        "AS21782": "isp", "AS328490": "isp", "AS52263": "isp", "AS56654": "isp", "AS1423": "isp", "AS17488": "isp",
        "AS18712": "isp", "AS14988": "isp", "AS138652": "isp", "AS263135": "isp", "AS32133": "isp", "AS11776": "isp",
        "AS14615": "isp", "AS36996": "isp", "AS28006": "isp", "AS35900": "isp", "AS14642": "isp", "AS15146": "isp",
        "AS52233": "isp", "AS33363": "isp", "AS6057": "isp", "AS9644": "isp", "AS133269": "isp", "AS22646": "isp",
        "AS214238": "isp", "AS63150": "isp", "AS204785": "isp", "AS214743": "isp", "AS13489": "isp", "AS3356": "isp",
        "AS265688": "isp", "AS262186": "isp", "AS264689": "isp", "AS19429": "isp", "AS14080": "isp", "AS4007": "isp",
        "AS154372": "isp", "AS35540": "isp", "AS133120": "isp", "AS37123": "isp", "AS14453": "isp", "AS2914": "isp",
        "AS3257": "isp", "AS6939": "isp", "AS39326": "isp", "AS210464": "isp", "AS149020": "isp", "AS6871": "isp",
        "AS197213": "isp", "AS16019": "isp", "AS8220": "isp", "AS199298": "isp", "AS16086": "isp", "AS15925": "isp",
        "AS209604": "isp", "AS15440": "isp", "AS28886": "isp", "AS34665": "isp", "AS196695": "isp", "AS48822": "isp",
        "AS44620": "isp", "AS33842": "isp", "AS41275": "isp", "AS50911": "isp", "AS39347": "isp", "AS208837": "isp",
        "AS39153": "isp", "AS8732": "isp", "AS41925": "isp", "AS63916": "isp", "AS206069": "isp", "AS11421": "isp",
        "AS134835": "isp", "AS9002": "isp", "AS29049": "isp", "AS39318": "isp", "AS41798": "isp", "AS215670": "isp",
        "AS31200": "isp", "AS58678": "isp", "AS48266": "isp", "AS38333": "isp", "AS209699": "isp", "AS23679": "isp",
        "AS154657": "isp", "AS150970": "isp", "AS273096": "isp", "AS49100": "isp", "AS38511": "isp", "AS140479": "isp",
        "AS269919": "isp", "AS136121": "isp", "AS147131": "isp", "AS24323": "isp", "AS8151": "isp", "AS12605": "isp",
        "AS270176": "isp", "AS4800": "isp", "AS265583": "isp", "AS269920": "isp", "AS141982": "isp", "AS38783": "isp",
        "AS149360": "isp", "AS34470": "isp", "AS268084": "isp", "AS8193": "isp", "AS153855": "isp", "AS8452": "isp",
        "AS197192": "isp", "AS152438": "isp", "AS139963": "isp", "AS264831": "isp", "AS274413": "isp", "AS22363": "isp",
        "AS394684": "isp", "AS138089": "isp", "AS11014": "isp", "AS136290": "isp", "AS153135": "isp", "AS263703": "isp",
        "AS131706": "isp", "AS132199": "isp", "AS29256": "isp", "AS18881": "isp", "AS32098": "isp", "AS138064": "isp",
        "AS202561": "isp", "AS6147": "isp", "AS150468": "isp", "AS136873": "isp", "AS24835": "isp", "AS17451": "isp",
        "AS266742": "isp", "AS141610": "isp", "AS36992": "isp", "AS149319": "isp", "AS141606": "isp", "AS37061": "isp",
        "AS141928": "isp", "AS270158": "isp", "AS153774": "isp", "AS140469": "isp", "AS17995": "isp", "AS11562": "isp",
        "AS8781": "isp", "AS140481": "isp", "AS150279": "isp", "AS8359": "isp", "AS63859": "isp", "AS214707": "isp",
        "AS274099": "isp", "AS142386": "isp", "AS24863": "isp", "AS270096": "isp", "AS31195": "isp", "AS142370": "isp",
        "AS7438": "isp", "AS264646": "isp", "AS142393": "isp", "AS268863": "isp", "AS45305": "isp", "AS139421": "isp",
        "AS45722": "isp", "AS273850": "isp", "AS272954": "isp", "AS329021": "isp", "AS134204": "isp", "AS20207": "isp",
        "AS273894": "isp", "AS139982": "isp", "AS149888": "isp", "AS153887": "isp", "AS18678": "isp", "AS138079": "isp",
        "AS34602": "isp", "AS269934": "isp", "AS214095": "isp", "AS272334": "isp", "AS149933": "isp", "AS24529": "isp",
        "AS23953": "isp", "AS152032": "isp", "AS30041": "isp", "AS151505": "isp", "AS263238": "isp", "AS262913": "isp",
        "AS8717": "isp", "AS152775": "isp", "AS3216": "isp", "AS55701": "isp", "AS142347": "isp", "AS23956": "isp",
        "AS21003": "isp", "AS23923": "isp", "AS270075": "isp", "AS55507": "isp", "AS28118": "isp", "AS262191": "isp",
        "AS263285": "isp", "AS23969": "isp", "AS53078": "isp", "AS4788": "isp", "AS134526": "isp", "AS38758": "isp",
        "AS134648": "isp", "AS141127": "isp", "AS44375": "isp", "AS32003": "isp", "AS273836": "isp", "AS269804": "isp",
        "AS58965": "isp", "AS35047": "isp", "AS28683": "isp", "AS138134": "isp", "AS269269": "isp", "AS138640": "isp",
        "AS51669": "isp", "AS27876": "isp", "AS152073": "isp", "AS153968": "isp", "AS149766": "isp", "AS132637": "isp",
        "AS28075": "isp", "AS271968": "isp", "AS154180": "isp", "AS151549": "isp", "AS154834": "isp", "AS58821": "isp",
        "AS39608": "isp", "AS27947": "isp", "AS141083": "isp", "AS142331": "isp", "AS149359": "isp", "AS32020": "isp",
        "AS34368": "isp", "AS9905": "isp", "AS138839": "isp", "AS21453": "isp", "AS152825": "isp", "AS138109": "isp",
        "AS262662": "isp", "AS272405": "isp", "AS141077": "isp", "AS153820": "isp", "AS149345": "isp", "AS153986": "isp",
        "AS135607": "isp", "AS147122": "isp", "AS14259": "isp", "AS150272": "isp", "AS23688": "isp", "AS265767": "isp",
        "AS147137": "isp", "AS141145": "isp", "AS141098": "isp", "AS329261": "isp", "AS17426": "isp", "AS140016": "isp",
        "AS17552": "isp", "AS152376": "isp", "AS45700": "isp", "AS55685": "isp", "AS274255": "isp", "AS142189": "isp",
        "AS151006": "isp", "AS150196": "isp", "AS272106": "isp", "AS23951": "isp", "AS36909": "isp", "AS151198": "isp",
        "AS28539": "isp", "AS154208": "isp", "AS133481": "isp", "AS265894": "isp", "AS134084": "isp", "AS151585": "isp",
        "AS6167": "isp", "AS152034": "isp", "AS141126": "isp", "AS6400": "isp", "AS267871": "isp", "AS270026": "isp",
        "AS147118": "isp", "AS17639": "isp", "AS135477": "isp", "AS24560": "isp", "AS209001": "isp", "AS28458": "isp",
        "AS140946": "isp", "AS273217": "isp", "AS140457": "isp", "AS133354": "isp", "AS147113": "isp", "AS152436": "isp",
        "AS8053": "isp", "AS18103": "isp", "AS139460": "isp", "AS273078": "isp", "AS42337": "isp", "AS152086": "isp",
        "AS47551": "isp", "AS274777": "isp", "AS55699": "isp", "AS265627": "isp", "AS134952": "isp", "AS141123": "isp",
        "AS58224": "isp", "AS154538": "isp", "AS37675": "isp", "AS267830": "isp", "AS149878": "isp", "AS11172": "isp",
        "AS328858": "isp", "AS153938": "isp", "AS327750": "isp", "AS141673": "isp", "AS23949": "isp", "AS8595": "isp",
        "AS152787": "isp", "AS273110": "isp", "AS20771": "isp", "AS262589": "isp", "AS136128": "isp", "AS2764": "isp",
        "AS153600": "isp", "AS264926": "isp", "AS151984": "isp", "AS5087": "isp", "AS147127": "isp", "AS269730": "isp",
        "AS132972": "isp", "AS201550": "isp", "AS149720": "isp", "AS150554": "isp", "AS46029": "isp", "AS136055": "isp",
        "AS141955": "isp", "AS147164": "isp", "AS52361": "isp", "AS150553": "isp", "AS9341": "isp", "AS206088": "isp",
        "AS152777": "isp", "AS327804": "isp", "AS140216": "isp", "AS273133": "isp", "AS21826": "isp", "AS58369": "isp",
        "AS152377": "isp", "AS38235": "isp", "AS142338": "isp", "AS270207": "isp", "AS31252": "isp", "AS24173": "isp",
        "AS28773": "isp", "AS152004": "isp", "AS153359": "isp", "AS141071": "isp", "AS211407": "isp", "AS141613": "isp",
        "AS151538": "isp", "AS23724": "isp", "AS131111": "isp", "AS152014": "isp", "AS44217": "isp", "AS138123": "isp",
        "AS141664": "isp", "AS152769": "isp", "AS150927": "isp", "AS42189": "isp", "AS137909": "isp", "AS267809": "isp",
        "AS131717": "isp", "AS28323": "isp", "AS133360": "isp", "AS265911": "isp", "AS328471": "isp", "AS141898": "isp",
        "AS266754": "isp", "AS207221": "isp", "AS154314": "isp", "AS45458": "isp", "AS152424": "isp", "AS272403": "isp",
        "AS17557": "isp", "AS54221": "isp", "AS41733": "isp", "AS64134": "isp", "AS270172": "isp", "AS149404": "isp",
        "AS29399": "isp", "AS142375": "isp", "AS24342": "isp", "AS132649": "isp", "AS154344": "isp", "AS138862": "isp",
        "AS329497": "isp", "AS135549": "isp", "AS134216": "isp", "AS57016": "isp", "AS151983": "isp", "AS267210": "isp",
        "AS153727": "isp", "AS53075": "isp", "AS28642": "isp", "AS266436": "isp", "AS142271": "isp", "AS50482": "isp",
        "AS24492": "isp", "AS46023": "isp", "AS264001": "isp", "AS138004": "isp", "AS141607": "isp", "AS58474": "isp",
        "AS273103": "isp", "AS136141": "isp", "AS138087": "isp", "AS149175": "isp", "AS133720": "isp", "AS56233": "isp",
        "AS147096": "isp", "AS142340": "isp", "AS34757": "isp", "AS48739": "isp", "AS271967": "isp", "AS272894": "isp",
        "AS152388": "isp", "AS265201": "isp", "AS151521": "isp", "AS136089": "isp", "AS38165": "isp", "AS270457": "isp",
        "AS136384": "isp", "AS141114": "isp", "AS8473": "isp", "AS147145": "isp", "AS142201": "isp", "AS151576": "isp",
        "AS136865": "isp", "AS270186": "isp", "AS152050": "isp", "AS37012": "isp", "AS140404": "isp", "AS142390": "isp",
        "AS153806": "isp", "AS6535": "isp", "AS140448": "isp", "AS9129": "isp", "AS270024": "isp", "AS49007": "isp",
        "AS139653": "isp", "AS211791": "isp", "AS271869": "isp", "AS152833": "isp", "AS153038": "isp", "AS137633": "isp",
        "AS131773": "isp", "AS52492": "isp", "AS274156": "isp", "AS139449": "isp", "AS52510": "isp", "AS142387": "isp",
        "AS150265": "isp", "AS272851": "isp", "AS142341": "isp", "AS154709": "isp", "AS141645": "isp", "AS141642": "isp",
        "AS134129": "isp", "AS64313": "isp", "AS64300": "isp", "AS138130": "isp", "AS150517": "isp", "AS141596": "isp",
        "AS264528": "isp", "AS142315": "isp", "AS262241": "isp", "AS59158": "isp", "AS271113": "isp", "AS263767": "isp",
        "AS153582": "isp", "AS154689": "isp", "AS37284": "isp", "AS152048": "isp", "AS141595": "isp", "AS135353": "isp",
        "AS137453": "isp", "AS273026": "isp", "AS153822": "isp", "AS274404": "isp", "AS154503": "isp", "AS204834": "isp",
        "AS147117": "isp", "AS154747": "isp", "AS207097": "isp", "AS150001": "isp", "AS264268": "isp", "AS58466": "isp",
        "AS271935": "isp", "AS136106": "isp", "AS5009": "isp", "AS265798": "isp", "AS263677": "isp", "AS206119": "isp",
        "AS26210": "isp", "AS17882": "isp", "AS136880": "isp", "AS134630": "isp", "AS1680": "isp", "AS133524": "isp",
        "AS150247": "isp", "AS153789": "isp", "AS59362": "isp", "AS63885": "isp", "AS151993": "isp", "AS136009": "isp",
        "AS140464": "isp", "AS271795": "isp", "AS262779": "isp", "AS142381": "isp", "AS206065": "isp", "AS45701": "isp",
        "AS149924": "isp", "AS270209": "isp", "AS12083": "isp", "AS270068": "isp", "AS4764": "isp", "AS52911": "isp",
        "AS151484": "isp", "AS56054": "isp", "AS149374": "isp", "AS141731": "isp", "AS16322": "isp", "AS149664": "isp",
        "AS149240": "isp", "AS47119": "isp", "AS139381": "isp", "AS273141": "isp", "AS264551": "isp", "AS150501": "isp",
        "AS147087": "isp", "AS8905": "isp", "AS397540": "isp", "AS33763": "isp", "AS7670": "isp", "AS8092": "isp",
        "AS198317": "isp", "AS32653": "isp", "AS22933": "isp", "AS327697": "isp", "AS8399": "isp", "AS9044": "isp",
        "AS205119": "isp", "AS6855": "isp", "AS23201": "isp", "AS33576": "isp", "AS33923": "isp",
        "AS5617": "isp", "AS62642": "isp", "AS46887": "isp", "AS36924": "isp", "AS395561": "isp", "AS47881": "isp",
        "AS24634": "isp", "AS262145": "isp", "AS150552": "isp", "AS203953": "isp", "AS56450": "isp", "AS59686": "isp",
        "AS12874": "isp", "AS20057": "isp", "AS12430": "isp", "AS4755": "isp", "AS11686": "isp", "AS203081": "isp",
        "AS214143": "isp", "AS17222": "isp", "AS6769": "isp", "AS199181": "isp", "AS28327": "isp", "AS63490": "isp",
        "AS33582": "isp", "AS24904": "isp", "AS55666": "isp", "AS28317": "isp", "AS152739": "isp", "AS8866": "isp",
        "AS9141": "isp", "AS396304": "isp", "AS55900": "isp", "AS23650": "isp", "AS34177": "isp",
        "AS141201": "isp", "AS15805": "isp", "AS16347": "isp", "AS50629": "isp", "AS2116": "isp", "AS25255": "isp",
        "AS5603": "isp", "AS3226": "isp", "AS212559": "isp", "AS40786": "isp", "AS12301": "isp", "AS21104": "isp",
        "AS25540": "isp", "AS35549": "isp", "AS12460": "isp", "AS21565": "isp", "AS54253": "isp", "AS20255": "isp",
        "AS38794": "isp", "AS51077": "isp",
        "AS6730": "isp", "AS12338": "isp", "AS15694": "isp", "AS20042": "isp", "AS12530": "isp",
        "AS10091": "isp", "AS10898": "isp", "AS11311": "isp", "AS45464": "isp", "AS45465": "isp",
    # 2. 商业企业专线 (business) - 共 21 个
        "AS174": "business", "AS27015": "business", "AS4451": "business", "AS132822": "business", "AS254": "business",
        "AS396290": "business", "AS142554": "business", "AS979": "business", "AS153061": "business", "AS198357": "business", "AS55344": "business",
        "AS198103": "business", "AS15779": "business", "AS26307": "business",
        "AS11428": "business", "AS26401": "business", "AS16738": "business", "AS40034": "business", "AS4601": "business",
        "AS16781": "business", "AS45463": "business",
    # 3. 高校科研教育 (education) - 共 45 个
        "AS11246": "education", "AS4538": "education", "AS20965": "education", "AS1103": "education", "AS2200": "education", "AS680": "education",
        "AS786": "education", "AS2614": "education", "AS376": "education", "AS138231": "education", "AS2907": "education", "AS2500": "education",
        "AS1659": "education", "AS11537": "education", "AS7575": "education", "AS6509": "education", "AS766": "education", "AS137": "education",
        "AS2523": "education", "AS7539": "education", "AS10886": "education", "AS197119": "education", "AS1887": "education", "AS150192": "education",
        "AS2202": "education", "AS2607": "education", "AS2018": "education", "AS26": "education", "AS2107": "education", "AS5724": "education",
        "AS9433": "education", "AS3335": "education", "AS14041": "education", "AS1930": "education", "AS17956": "education", "AS9432": "education",
        "AS12093": "education", "AS46988": "education", "AS8643": "education", "AS328439": "education",
        "AS3480": "education", "AS2722": "education", "AS7610": "education", "AS26462": "education", "AS2382": "education",
    # 4. 政务公共网络与互联网治理 (government) - 共 13 个
        "AS201648": "government", "AS2522": "government", "AS23974": "government", "AS140426": "government", "AS20981": "government", "AS7633": "government",
        "AS271145": "government", "AS55656": "government", "AS327724": "government", "AS197497": "government", "AS28616": "government", "AS5576": "government",
        "AS45467": "government",
    # 5. 银行与金融专网 (banking) - 共 24 个（经 ipapi.is 官方分类与权威 RIR RDAP 双重实测核验）
        "AS9221": "banking", "AS8435": "banking", "AS2600": "banking", "AS9016": "banking", "AS3187": "banking", "AS9487": "banking",
        "AS9128": "banking", "AS7630": "banking", "AS5458": "banking", "AS8373": "banking", "AS7609": "banking", "AS9522": "banking",
        "AS9630": "banking", "AS9772": "banking", "AS7820": "banking", "AS6773": "banking", "AS9099": "banking", "AS9118": "banking",
        "AS6674": "banking", "AS9863": "banking", "AS1311": "banking", "AS5091": "banking", "AS25883": "banking", "AS207986": "banking",
    # 6. 知名机房数据中心 (datacenter) - 共 756 个
        "AS13335": "datacenter", "AS16509": "datacenter", "AS8075": "datacenter", "AS15169": "datacenter", "AS45102": "datacenter", "AS132203": "datacenter",
        "AS136907": "datacenter", "AS20473": "datacenter", "AS14061": "datacenter", "AS24940": "datacenter", "AS16276": "datacenter", "AS51167": "datacenter",
        "AS197540": "datacenter", "AS60068": "datacenter", "AS9009": "datacenter", "AS25820": "datacenter", "AS63949": "datacenter", "AS61112": "datacenter",
        "AS906": "datacenter", "AS210644": "datacenter", "AS212336": "datacenter", "AS36352": "datacenter", "AS53667": "datacenter", "AS47583": "datacenter",
        "AS21859": "datacenter", "AS147049": "datacenter", "AS9370": "datacenter", "AS7684": "datacenter", "AS56971": "datacenter", "AS31898": "datacenter",
        "AS63023": "datacenter", "AS9123": "datacenter", "AS213877": "datacenter", "AS216127": "datacenter", "AS26383": "datacenter", "AS216071": "datacenter",
        "AS42532": "datacenter", "AS57043": "datacenter", "AS35916": "datacenter", "AS207957": "datacenter", "AS152460": "datacenter", "AS44051": "datacenter",
        "AS213520": "datacenter", "AS200740": "datacenter", "AS207569": "datacenter", "AS50053": "datacenter", "AS215540": "datacenter", "AS210976": "datacenter",
        "AS8560": "datacenter", "AS30058": "datacenter", "AS19871": "datacenter", "AS46606": "datacenter", "AS489909": "datacenter", "AS22612": "datacenter",
        "AS215373": "datacenter", "AS63759": "datacenter", "AS54600": "datacenter", "AS37963": "datacenter", "AS398101": "datacenter", "AS13188": "datacenter",
        "AS14742": "datacenter", "AS3302": "datacenter", "AS4694": "datacenter",
        "AS46562": "datacenter", "AS212238": "datacenter", "AS397032": "datacenter", "AS214483": "datacenter", "AS3170": "datacenter", "AS200197": "datacenter",
        "AS25369": "datacenter", "AS140227": "datacenter", "AS138997": "datacenter", "AS137535": "datacenter", "AS9607": "datacenter", "AS7506": "datacenter",
        "AS212860": "datacenter", "AS8342": "datacenter", "AS216475": "datacenter", "AS53808": "datacenter", "AS57717": "datacenter", "AS60982": "datacenter",
        "AS216138": "datacenter", "AS48096": "datacenter", "AS11878": "datacenter", "AS134677": "datacenter", "AS137409": "datacenter", "AS36530": "datacenter",
        "AS3214": "datacenter", "AS44486": "datacenter", "AS210329": "datacenter", "AS41436": "datacenter", "AS44709": "datacenter", "AS25052": "datacenter",
        "AS5404": "datacenter", "AS15510": "datacenter", "AS5065": "datacenter", "AS5606": "datacenter", "AS213230": "datacenter", "AS14618": "datacenter",
        "AS30633": "datacenter", "AS214996": "datacenter", "AS57695": "datacenter", "AS36007": "datacenter", "AS142036": "datacenter", "AS395839": "datacenter",
        "AS25697": "datacenter", "AS19318": "datacenter", "AS14956": "datacenter", "AS213535": "datacenter", "AS204957": "datacenter", "AS18450": "datacenter",
        "AS54913": "datacenter", "AS33724": "datacenter", "AS32613": "datacenter", "AS49791": "datacenter", "AS32181": "datacenter", "AS40021": "datacenter",
        "AS54290": "datacenter", "AS19905": "datacenter", "AS219399": "datacenter", "AS202015": "datacenter", "AS396982": "datacenter", "AS62633": "datacenter",
        "AS7488": "datacenter", "AS211273": "datacenter", "AS64236": "datacenter", "AS63473": "datacenter", "AS149042": "datacenter", "AS7489": "datacenter",
        "AS199959": "datacenter", "AS917": "datacenter", "AS402506": "datacenter", "AS40065": "datacenter", "AS8796": "datacenter", "AS395954": "datacenter",
        "AS135377": "datacenter", "AS46475": "datacenter", "AS6233": "datacenter", "AS201525": "datacenter", "AS138152": "datacenter", "AS397968": "datacenter",
        "AS402799": "datacenter", "AS18779": "datacenter", "AS400619": "datacenter", "AS399804": "datacenter", "AS14315": "datacenter", "AS7203": "datacenter",
        "AS26666": "datacenter", "AS402169": "datacenter", "AS53850": "datacenter", "AS62563": "datacenter", "AS50131": "datacenter", "AS212317": "datacenter",
        "AS62005": "datacenter", "AS19527": "datacenter", "AS198983": "datacenter", "AS205544": "datacenter", "AS62240": "datacenter", "AS212815": "datacenter",
        "AS6364": "datacenter", "AS62000": "datacenter", "AS8069": "datacenter", "AS202448": "datacenter", "AS29169": "datacenter", "AS216154": "datacenter",
        "AS60781": "datacenter", "AS61046": "datacenter", "AS212027": "datacenter", "AS216139": "datacenter", "AS202053": "datacenter", "AS215703": "datacenter",
        "AS44066": "datacenter", "AS200223": "datacenter", "AS215439": "datacenter", "AS61003": "datacenter", "AS24961": "datacenter", "AS56611": "datacenter",
        "AS211693": "datacenter", "AS202602": "datacenter", "AS209207": "datacenter", "AS14576": "datacenter", "AS209693": "datacenter", "AS210705": "datacenter",
        "AS198550": "datacenter", "AS205406": "datacenter", "AS61272": "datacenter", "AS211066": "datacenter", "AS16003": "datacenter", "AS60144": "datacenter",
        "AS40676": "datacenter", "AS60117": "datacenter", "AS197574": "datacenter", "AS28753": "datacenter", "AS219337": "datacenter", "AS7979": "datacenter",
        "AS207513": "datacenter", "AS209874": "datacenter", "AS198178": "datacenter", "AS39798": "datacenter", "AS30823": "datacenter", "AS200185": "datacenter",
        "AS212477": "datacenter", "AS210546": "datacenter", "AS200904": "datacenter", "AS43350": "datacenter", "AS57568": "datacenter", "AS59711": "datacenter",
        "AS219269": "datacenter", "AS198037": "datacenter", "AS49635": "datacenter", "AS201988": "datacenter", "AS47447": "datacenter", "AS214677": "datacenter",
        "AS49581": "datacenter", "AS200823": "datacenter", "AS212743": "datacenter", "AS12574": "datacenter", "AS25198": "datacenter", "AS200019": "datacenter",
        "AS12586": "datacenter", "AS203380": "datacenter", "AS202051": "datacenter", "AS47890": "datacenter", "AS203154": "datacenter", "AS35278": "datacenter",
        "AS199144": "datacenter", "AS48040": "datacenter", "AS56740": "datacenter", "AS200487": "datacenter", "AS62082": "datacenter", "AS213683": "datacenter",
        "AS200563": "datacenter", "AS214891": "datacenter", "AS201094": "datacenter", "AS211183": "datacenter", "AS205399": "datacenter", "AS200000": "datacenter",
        "AS64439": "datacenter", "AS48018": "datacenter", "AS138915": "datacenter", "AS204997": "datacenter", "AS207279": "datacenter", "AS200350": "datacenter",
        "AS8685": "datacenter", "AS48282": "datacenter", "AS59504": "datacenter", "AS44094": "datacenter", "AS208677": "datacenter", "AS209641": "datacenter",
        "AS33993": "datacenter", "AS197715": "datacenter", "AS48753": "datacenter", "AS205090": "datacenter", "AS215761": "datacenter", "AS212913": "datacenter",
        "AS197648": "datacenter", "AS50113": "datacenter", "AS43362": "datacenter", "AS57814": "datacenter", "AS212508": "datacenter", "AS3258": "datacenter",
        "AS134351": "datacenter", "AS203090": "datacenter", "AS141995": "datacenter", "AS208450": "datacenter", "AS208795": "datacenter", "AS207333": "datacenter",
        "AS202958": "datacenter", "AS205431": "datacenter", "AS327813": "datacenter", "AS43647": "datacenter", "AS204104": "datacenter", "AS48988": "datacenter",
        "AS134823": "datacenter", "AS59684": "datacenter", "AS151419": "datacenter", "AS9312": "datacenter", "AS7720": "datacenter", "AS55933": "datacenter",
        "AS154309": "datacenter", "AS133752": "datacenter", "AS8888": "datacenter", "AS133199": "datacenter", "AS215859": "datacenter", "AS216444": "datacenter",
        "AS133398": "datacenter", "AS37153": "datacenter", "AS59253": "datacenter", "AS150895": "datacenter", "AS152194": "datacenter", "AS263511": "datacenter",
        "AS329184": "datacenter", "AS24429": "datacenter", "AS55990": "datacenter", "AS38283": "datacenter", "AS45090": "datacenter", "AS215708": "datacenter",
        "AS328882": "datacenter", "AS136897": "datacenter", "AS197019": "datacenter", "AS51430": "datacenter", "AS42422": "datacenter", "AS52048": "datacenter",
        "AS393886": "datacenter", "AS15401": "datacenter", "AS205559": "datacenter", "AS34549": "datacenter", "AS400226": "datacenter", "AS265919": "datacenter",
        "AS216054": "datacenter", "AS42831": "datacenter", "AS17971": "datacenter", "AS45179": "datacenter", "AS200698": "datacenter", "AS44964": "datacenter",
        "AS150694": "datacenter", "AS51115": "datacenter", "AS139341": "datacenter", "AS35280": "datacenter", "AS30081": "datacenter", "AS53334": "datacenter",
        "AS8849": "datacenter", "AS53724": "datacenter", "AS396356": "datacenter", "AS211381": "datacenter", "AS212890": "datacenter", "AS208951": "datacenter",
        "AS41745": "datacenter", "AS29802": "datacenter", "AS3842": "datacenter", "AS44382": "datacenter", "AS203273": "datacenter", "AS401486": "datacenter",
        "AS26832": "datacenter", "AS20278": "datacenter", "AS32489": "datacenter", "AS400587": "datacenter", "AS58061": "datacenter", "AS22295": "datacenter",
        "AS394727": "datacenter", "AS7393": "datacenter", "AS40824": "datacenter", "AS398343": "datacenter", "AS399646": "datacenter", "AS32097": "datacenter",
        "AS30475": "datacenter", "AS136258": "datacenter", "AS26042": "datacenter", "AS209554": "datacenter", "AS38136": "datacenter", "AS199058": "datacenter",
        "AS399334": "datacenter", "AS205548": "datacenter", "AS151338": "datacenter", "AS984": "datacenter", "AS976": "datacenter", "AS1054": "datacenter",
        "AS201667": "datacenter", "AS210661": "datacenter", "AS140869": "datacenter", "AS401418": "datacenter", "AS967": "datacenter", "AS46783": "datacenter",
        "AS54286": "datacenter", "AS207043": "datacenter", "AS149440": "datacenter", "AS199524": "datacenter", "AS53755": "datacenter", "AS60024": "datacenter",
        "AS41378": "datacenter", "AS22781": "datacenter", "AS396073": "datacenter", "AS400992": "datacenter", "AS398493": "datacenter", "AS197196": "datacenter",
        "AS153371": "datacenter", "AS46997": "datacenter", "AS35661": "datacenter", "AS34534": "datacenter", "AS20860": "datacenter", "AS48950": "datacenter",
        "AS63119": "datacenter", "AS58065": "datacenter", "AS216382": "datacenter", "AS50926": "datacenter", "AS199741": "datacenter", "AS197922": "datacenter",
        "AS47264": "datacenter", "AS197223": "datacenter", "AS211507": "datacenter", "AS210734": "datacenter", "AS206300": "datacenter", "AS56630": "datacenter",
        "AS214036": "datacenter", "AS12876": "datacenter", "AS20857": "datacenter", "AS203758": "datacenter", "AS21100": "datacenter", "AS215311": "datacenter",
        "AS210083": "datacenter", "AS39572": "datacenter", "AS214798": "datacenter", "AS49981": "datacenter", "AS207992": "datacenter", "AS48207": "datacenter",
        "AS62068": "datacenter", "AS60404": "datacenter", "AS199792": "datacenter", "AS57169": "datacenter", "AS210429": "datacenter", "AS204044": "datacenter",
        "AS207728": "datacenter", "AS58212": "datacenter", "AS216024": "datacenter", "AS47674": "datacenter", "AS44493": "datacenter", "AS43641": "datacenter",
        "AS60790": "datacenter", "AS215102": "datacenter", "AS219095": "datacenter", "AS216129": "datacenter", "AS51247": "datacenter", "AS214716": "datacenter",
        "AS199053": "datacenter", "AS58087": "datacenter", "AS203446": "datacenter", "AS215365": "datacenter", "AS200566": "datacenter", "AS219464": "datacenter",
        "AS208226": "datacenter", "AS202423": "datacenter", "AS200758": "datacenter", "AS50673": "datacenter", "AS213896": "datacenter", "AS213887": "datacenter",
        "AS215590": "datacenter", "AS216078": "datacenter", "AS210097": "datacenter", "AS199884": "datacenter", "AS56594": "datacenter", "AS204601": "datacenter",
        "AS206134": "datacenter", "AS199948": "datacenter", "AS48729": "datacenter", "AS215730": "datacenter", "AS39378": "datacenter", "AS204548": "datacenter",
        "AS200651": "datacenter", "AS49683": "datacenter", "AS214481": "datacenter", "AS213495": "datacenter", "AS212374": "datacenter", "AS197170": "datacenter",
        "AS35415": "datacenter", "AS52000": "datacenter", "AS207994": "datacenter", "AS201682": "datacenter", "AS207252": "datacenter", "AS215305": "datacenter",
        "AS206216": "datacenter", "AS29066": "datacenter", "AS50132": "datacenter", "AS211895": "datacenter", "AS35042": "datacenter", "AS45839": "datacenter",
        "AS49532": "datacenter", "AS399275": "datacenter", "AS212552": "datacenter", "AS51202": "datacenter", "AS215381": "datacenter", "AS206411": "datacenter",
        "AS14475": "datacenter", "AS59432": "datacenter", "AS213250": "datacenter", "AS58329": "datacenter", "AS57935": "datacenter", "AS203466": "datacenter",
        "AS213929": "datacenter", "AS201011": "datacenter", "AS198362": "datacenter", "AS198883": "datacenter", "AS215607": "datacenter", "AS216155": "datacenter",
        "AS214172": "datacenter", "AS213693": "datacenter", "AS215784": "datacenter", "AS51395": "datacenter", "AS202422": "datacenter", "AS45014": "datacenter",
        "AS199566": "datacenter", "AS24806": "datacenter", "AS200313": "datacenter", "AS8648": "datacenter", "AS202269": "datacenter", "AS3920": "datacenter",
        "AS56655": "datacenter", "AS43357": "datacenter", "AS61424": "datacenter", "AS209829": "datacenter", "AS62212": "datacenter", "AS212341": "datacenter",
        "AS51852": "datacenter", "AS29222": "datacenter", "AS264617": "datacenter", "AS210558": "datacenter", "AS207590": "datacenter", "AS44133": "datacenter",
        "AS214640": "datacenter", "AS61335": "datacenter", "AS215120": "datacenter", "AS31034": "datacenter", "AS207003": "datacenter", "AS42708": "datacenter",
        "AS201814": "datacenter", "AS210779": "datacenter", "AS215960": "datacenter", "AS37518": "datacenter", "AS51264": "datacenter", "AS30893": "datacenter",
        "AS60485": "datacenter", "AS210895": "datacenter", "AS44925": "datacenter", "AS214379": "datacenter", "AS213468": "datacenter", "AS207408": "datacenter",
        "AS205007": "datacenter", "AS207567": "datacenter", "AS206804": "datacenter", "AS200367": "datacenter", "AS51765": "datacenter", "AS203662": "datacenter",
        "AS213459": "datacenter", "AS35594": "datacenter", "AS213115": "datacenter", "AS203534": "datacenter", "AS16125": "datacenter", "AS215272": "datacenter",
        "AS216246": "datacenter", "AS44901": "datacenter", "AS197155": "datacenter", "AS212531": "datacenter", "AS49505": "datacenter", "AS43317": "datacenter",
        "AS207083": "datacenter", "AS42352": "datacenter", "AS209378": "datacenter", "AS34702": "datacenter", "AS51659": "datacenter", "AS207713": "datacenter",
        "AS41722": "datacenter", "AS202226": "datacenter", "AS8254": "datacenter", "AS43513": "datacenter", "AS34959": "datacenter", "AS29182": "datacenter",
        "AS214822": "datacenter", "AS50340": "datacenter", "AS48347": "datacenter", "AS57271": "datacenter", "AS208427": "datacenter", "AS203004": "datacenter",
        "AS206446": "datacenter", "AS204490": "datacenter", "AS42474": "datacenter", "AS213220": "datacenter", "AS212810": "datacenter", "AS56694": "datacenter",
        "AS50867": "datacenter", "AS201670": "datacenter", "AS202831": "datacenter", "AS49063": "datacenter", "AS41535": "datacenter", "AS207483": "datacenter",
        "AS197450": "datacenter", "AS197695": "datacenter", "AS42807": "datacenter", "AS215314": "datacenter", "AS210756": "datacenter", "AS39494": "datacenter",
        "AS198610": "datacenter", "AS43581": "datacenter", "AS51177": "datacenter", "AS56380": "datacenter", "AS211619": "datacenter", "AS51711": "datacenter",
        "AS48716": "datacenter", "AS208626": "datacenter", "AS15626": "datacenter", "AS48881": "datacenter", "AS12695": "datacenter", "AS201575": "datacenter",
        "AS399629": "datacenter", "AS201664": "datacenter", "AS61493": "datacenter", "AS216058": "datacenter", "AS396856": "datacenter", "AS61102": "datacenter",
        "AS142433": "datacenter", "AS400464": "datacenter", "AS401615": "datacenter", "AS51847": "datacenter", "AS205516": "datacenter", "AS4785": "datacenter",
        "AS63801": "datacenter", "AS46829": "datacenter", "AS49304": "datacenter", "AS61414": "datacenter", "AS24282": "datacenter", "AS203087": "datacenter",
        "AS18526": "datacenter", "AS402628": "datacenter", "AS211860": "datacenter", "AS58791": "datacenter", "AS43180": "datacenter", "AS200590": "datacenter",
        "AS216211": "datacenter", "AS138195": "datacenter", "AS43289": "datacenter", "AS59878": "datacenter", "AS44578": "datacenter", "AS42447": "datacenter",
        "AS204844": "datacenter", "AS133159": "datacenter", "AS139659": "datacenter", "AS58683": "datacenter", "AS202662": "datacenter", "AS204071": "datacenter",
        "AS32167": "datacenter", "AS15012": "datacenter", "AS153914": "datacenter", "AS394695": "datacenter", "AS212194": "datacenter", "AS215355": "datacenter",
        "AS219289": "datacenter", "AS203923": "datacenter", "AS150452": "datacenter", "AS150670": "datacenter", "AS22439": "datacenter", "AS54801": "datacenter",
        "AS137897": "datacenter", "AS209557": "datacenter", "AS135330": "datacenter", "AS6134": "datacenter", "AS42960": "datacenter", "AS136557": "datacenter",
        "AS132816": "datacenter", "AS63199": "datacenter", "AS6206": "datacenter", "AS216245": "datacenter", "AS24482": "datacenter", "AS138115": "datacenter",
        "AS142594": "datacenter", "AS154690": "datacenter", "AS401701": "datacenter", "AS135918": "datacenter", "AS135161": "datacenter", "AS136510": "datacenter",
        "AS56309": "datacenter", "AS152992": "datacenter", "AS9335": "datacenter", "AS196709": "datacenter", "AS149107": "datacenter", "AS11179": "datacenter",
        "AS134926": "datacenter", "AS38731": "datacenter", "AS140815": "datacenter", "AS33387": "datacenter", "AS11506": "datacenter", "AS209109": "datacenter",
        "AS205100": "datacenter", "AS42675": "datacenter", "AS63835": "datacenter", "AS134366": "datacenter", "AS62651": "datacenter", "AS57497": "datacenter",
        "AS61125": "datacenter", "AS10297": "datacenter", "AS136188": "datacenter", "AS139021": "datacenter", "AS400506": "datacenter", "AS212271": "datacenter",
        "AS329272": "datacenter", "AS50919": "datacenter", "AS397423": "datacenter", "AS58461": "datacenter", "AS140042": "datacenter", "AS213873": "datacenter",
        "AS215125": "datacenter", "AS209783": "datacenter", "AS46844": "datacenter", "AS141039": "datacenter", "AS208323": "datacenter", "AS396507": "datacenter",
        "AS56803": "datacenter", "AS25184": "datacenter", "AS135967": "datacenter", "AS398823": "datacenter", "AS5533": "datacenter", "AS401696": "datacenter",
        "AS15830": "datacenter", "AS52441": "datacenter", "AS150249": "datacenter", "AS26496": "datacenter", "AS46664": "datacenter", "AS62214": "datacenter",
        "AS63989": "datacenter", "AS15456": "datacenter", "AS151873": "datacenter", "AS132335": "datacenter", "AS133480": "datacenter", "AS57494": "datacenter",
        "AS13737": "datacenter", "AS47748": "datacenter", "AS41564": "datacenter", "AS47810": "datacenter", "AS15987": "datacenter", "AS15395": "datacenter",
        "AS200760": "datacenter", "AS203101": "datacenter", "AS62744": "datacenter", "AS20853": "datacenter", "AS62044": "datacenter", "AS53107": "datacenter",
        "AS24875": "datacenter", "AS53356": "datacenter", "AS398993": "datacenter", "AS197706": "datacenter", "AS1342": "datacenter", "AS133296": "datacenter",
        "AS37191": "datacenter", "AS263812": "datacenter", "AS17378": "datacenter", "AS13284": "datacenter", "AS9371": "datacenter", "AS216269": "datacenter",
        "AS36114": "datacenter", "AS18229": "datacenter", "AS47381": "datacenter", "AS30175": "datacenter", "AS139220": "datacenter", "AS39351": "datacenter",
        "AS393398": "datacenter", "AS397503": "datacenter", "AS31130": "datacenter", "AS50812": "datacenter", "AS12306": "datacenter", "AS7385": "datacenter",
        "AS57495": "datacenter", "AS198614": "datacenter", "AS149573": "datacenter", "AS12655": "datacenter", "AS141968": "datacenter", "AS35758": "datacenter",
        "AS55470": "datacenter", "AS16371": "datacenter", "AS205275": "datacenter"
}

# 自动将 KNOWN_CLOUD_PROVIDERS 中未单独显式指定类型的知名云厂商/机房补充进入 ASN_EXACT_NET_TYPE 默认为 datacenter
for _asn, _ in KNOWN_CLOUD_PROVIDERS.values():
    if _asn not in ASN_EXACT_NET_TYPE:
        ASN_EXACT_NET_TYPE[_asn] = "datacenter"


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
    return code in ASN_EXACT_NET_TYPE or code in ASN_TO_PROVIDER


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

    # 4. 排除机房/主机商
    is_hosting = any(h in text for h in HOSTING_EXCLUSIONS)

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

    # 清理已不存在或旧命名格式的 .txt 文件（保留 .gitkeep 等非 txt 标记文件）
    for old_f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, old_f)
        if os.path.isfile(fpath) and old_f.endswith(".txt") and old_f not in active_files:
            try:
                os.remove(fpath)
            except OSError:
                pass

    return len(active_files)


def save_scan_ips_by_asn(asn_groups: dict, output_dir: str) -> int:
    """
    覆写 scan_ips/ 目录下的独立 ASN 纯文本文件（无注释 IP:端口）。
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
        clean_isp = re.sub(r"[^a-zA-Z0-9]", "", isp_name) if isp_name else ""
        fname = f"{asn_name}_{clean_isp}.txt" if clean_isp else f"{asn_name}.txt"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            for r in sorted(group, key=lambda x: (x.get("ip", ""), int(x.get("port", 0)))):
                f.write(f"{r['ip']}:{r['port']}\n")
        active_files.add(fname)

    # 移除已无活跃 IP 的旧分组文件（保留 .gitkeep 保持目录结构）
    for old_f in os.listdir(output_dir):
        if old_f == ".gitkeep":
            continue
        if old_f.endswith(".txt") and old_f not in active_files:
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


def load_tombstone(filepath: str | None = None, max_age_days: int = TOMBSTONE_MAX_AGE_DAYS) -> dict[str, int]:
    """
    读取墓地黑名单 (已被淘汰的死节点记忆库)。
    自动过滤/清理超过 max_age_days 天的过期记录，确保黑名单体积极简轻量。
    返回 {canonical_key: eliminated_timestamp}。
    """
    if filepath is None:
        filepath = TOMBSTONE_FILE
    if not os.path.isfile(filepath):
        return {}
    now = int(time.time())
    max_age_sec = max_age_days * 86400
    valid: dict[str, int] = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, ts in data.items():
                if isinstance(ts, (int, float)) and (now - int(ts)) < max_age_sec:
                    valid[str(k).strip().lower()] = int(ts)
    except Exception as e:
        log.warning("读取墓地文件 %s 失败: %s", filepath, e)
    return valid


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
    if not keys:
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



