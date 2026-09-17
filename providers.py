#!/usr/bin/env python3
"""
云厂商、CDN 与 ASN 规范化全局映射表
供 tg_fetch.py 与 cf_verify.py 共享使用，避免模块循环依赖与冗余硬编码。
"""

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
    "hkt": ("AS4760", "HKT"),
    "koreatelecom": ("AS4766", "Korea Telecom"),
    "newserverlife": ("AS49791", "NewServerLife"),
    "nanoit": ("AS52173", "NanoIT"),
    "oneasiahost": ("AS59211", "OneAsiaHost"),
    "skbroadband": ("AS9318", "SK Broadband"),

    # 运营商骨干与出海线路
    "hinet": ("AS3462", "Chunghwa Telecom HiNet"),
    "cmi": ("AS58453", "China Mobile CMI"),
    "chinamobile": ("AS58453", "China Mobile CMI"),
    "cug": ("AS10099", "China Unicom CUG"),
    "chinaunicom": ("AS10099", "China Unicom CUG"),
    "ctg": ("AS4134", "China Telecom CTG"),
    "chinatelecom": ("AS4134", "China Telecom 163"),
    "cn2": ("AS4809", "China Telecom CN2"),
    "9929": ("AS9929", "China Unicom 9929"),
    "cmin2": ("AS58807", "China Mobile CMIN2"),
}

# ASN 到标准服务商名称反查表
ASN_TO_PROVIDER = {}
for _k, (_asn, _isp) in KNOWN_CLOUD_PROVIDERS.items():
    if _asn not in ASN_TO_PROVIDER:
        ASN_TO_PROVIDER[_asn] = _isp


# =====================================================================
# 公共实用工具：环境加载、类型转换、ASN 清洗、Telegram 推送与自检
# =====================================================================

import json
import logging
import os
import re
import urllib.request

log = logging.getLogger("providers")


def load_dotenv(env_path: str = None) -> dict:
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


def safe_int(value, default: int = 0) -> int:
    """安全将值转为整数，转换失败或为空时返回默认值"""
    if value is None:
        return default
    try:
        s = str(value).strip()
        return int(s) if s else default
    except (ValueError, TypeError):
        return default


def clean_asn(raw_asn: str, isp: str = "") -> str:
    """提取规范化 ASN 编号 (如 AS979，支持从知名服务商名称智能反推)"""
    raw_asn = (raw_asn or "").strip()
    m = re.search(r"(AS\d+)", raw_asn, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    r_low = (raw_asn + " " + (isp or "")).lower()
    for k in sorted(KNOWN_CLOUD_PROVIDERS.keys(), key=len, reverse=True):
        if k in r_low:
            return KNOWN_CLOUD_PROVIDERS[k][0]
    m_d = re.search(r"\b(\d{3,7})\b", raw_asn)
    if m_d:
        return f"AS{m_d.group(1)}"
    return raw_asn if raw_asn else "AS_UNKNOWN"


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


def get_asn_conflicts() -> list:
    """检测多厂商/多别名映射至同一 ASN 的情况，返回 (asn, primary_isp, alias_isp, alias_key) 列表"""
    seen = {}
    conflicts = []
    for k, (asn, isp) in KNOWN_CLOUD_PROVIDERS.items():
        if asn in seen and seen[asn] != isp:
            conflicts.append((asn, seen[asn], isp, k))
        elif asn not in seen:
            seen[asn] = isp
    return conflicts


if __name__ == "__main__":
    print(f"Known cloud provider aliases: {len(KNOWN_CLOUD_PROVIDERS)}")
    print(f"Unique mapped ASNs: {len(ASN_TO_PROVIDER)}")
    c_list = get_asn_conflicts()
    if c_list:
        print(f"\n[Notice] {len(c_list)} multi-tenant / alias ASN mappings detected:")
        for _asn, _primary, _alias_isp, _alias_k in c_list:
            print(f"  - {_asn}: primary '{_primary}' | alias '{_alias_k}' -> '{_alias_isp}'")
    else:
        print("\n[OK] No ASN mapping conflicts detected.")

