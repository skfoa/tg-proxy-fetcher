#!/usr/bin/env python3
"""
云厂商、CDN、ASN 规范化全局映射及公共工具模块 (providers.py)
作为全系统单一真相源（Single Source of Truth），供全线抓取与质检脚本共享使用：
  1. KNOWN_CLOUD_PROVIDERS / ASN_TO_PROVIDER: 维护主流公有云、CDN、热门 VPS 与骨干网 ASN 标准名称。
  2. clean_asn() / _extract_asn_code(): 统一 ASN 编号与服务商提取清洗。
  3. ASN_EXACT_NET_TYPE / classify_asn() / is_asn_recorded():
     方案 A+ 两级分层网络类型（ISP/BIZ/EDU/GOV/机房）识别引擎与收录判定。
  4. format_categorized_proxyip_txt() / save_proxyip_by_country():
     ProxyIP 按国家/地区聚合分组及稀缺高价值网络专线纯文本分类导出。
  5. load_dotenv() / safe_int(): 本地环境加载与安全类型转换。
  6. send_tg_message() / send_ci_failure_alert(): 统一 Telegram 消息推送与 Actions CI 失败秒级告警。
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
    "kamatera_us": ("AS204548", "Kamatera"),
    "amazon_infra": ("AS14618", "Amazon AWS"),
    "google_infra": ("AS396982", "Google Cloud"),

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
        if "巴基斯坦" in name:
            return "巴基斯坦"
        if "多明尼加" in name or "多米尼加" in name:
            return "多米尼加"
        return name

    # 1. 优先解析 cf_location 结构
    if cf_location:
        parts = [p.strip() for p in cf_location.split("·") if p.strip()]
        if len(parts) >= 3:
            return _normalize_name(parts[-1])
        if len(parts) == 2:
            city = parts[1]
            if city in CITY_TO_COUNTRY:
                return CITY_TO_COUNTRY[city]
            if city in ["新加坡", "香港", "台湾", "澳门"]:
                return city
        for city, c in CITY_TO_COUNTRY.items():
            if city in cf_location:
                return c

    # 2. 回退到 colo 机房代码映射
    if colo in COLO_TO_COUNTRY:
        return COLO_TO_COUNTRY[colo]

    # 3. 兜底解析 parts 中提取的名称
    if cf_location:
        parts = [p.strip() for p in cf_location.split("·") if p.strip()]
        if len(parts) >= 2:
            return _normalize_name(parts[1])

    return "其他地区"


def format_categorized_proxyip_txt(rows: list) -> str:
    """
    将 ProxyIP 列表按国家/地区聚合分组，并格式化为带 `# 地区 - 数量 个` 注释头的纯文本内容。
    国家组按节点数量降序排列（“其他地区”排在最后）。
    各组内部保持传入时的原始排序（通常已由调用方完成质量排序：fail_count 升序，delay_ms 升序）。
    """
    groups: dict[str, list] = {}
    for r in rows:
        country = extract_country(r.get("cf_location"), r.get("colo"))
        groups.setdefault(country, []).append(r)

    def _group_sort_key(item):
        country, members = item
        is_other = (country == "其他地区")
        return (is_other, -len(members), country)

    sorted_groups = sorted(groups.items(), key=_group_sort_key)

    lines = []
    for country, members in sorted_groups:
        flag = COUNTRY_FLAGS.get(country, "")
        header_name = f"{flag} {country}".strip() if flag else country
        lines.append(f"# {header_name} - {len(members)} 个")
        for r in members:
            ip = (r.get("ip") or "").strip()
            port = r.get("port", "")
            if ip and port:
                lines.append(f"{ip}:{port}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n" if lines else ""


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
)

EDU_PATTERNS = (
    "university", "college", "school", "education", "cernet",
    "academician research", "academic", "institute of technology",
    "polytechnic", "edunet", "research network", "renater", "dfn", "surfnet",
)

GOV_PATTERNS = (
    "ministry of", "department of", "parliament", "municipality",
    "federal government", "state government", "public administration",
    "beltelecom",
)

ISP_RES_PATTERNS = (
    "comcast", "charter communications", "spectrum", "cox communications",
    "hkt limited", "hong kong broadband network", "korea telecom", "sk broadband",
    "singapore telecommunications", "deutsche telekom", "vodafone", "orange",
    "shaw communications", "british telecommunications", "kazakhtelecom",
    "transtelecom", "vietnam posts and telecommunications", "softbank corp",
    "chunghwa telecom", "kddi", "bell canada", "rogers communications",
    "frontier communications", "windstream", "centurylink", "lumen technologies",
    "swisscom", "proximus", "kpn", "telenor", "telia sonera",
    "virgin media", "o2 czech", "turkcell", "turk telekom",
    "china telecom", "china unicom", "china mobile", "wave broadband",
)

BIZ_PATTERNS = (
    "pccw business", "data communication business", "at&t enterprises",
    "enterprise", "corporate", "commercial", "business internet",
)

SPECIAL_NET_TYPE_FILES = {
    "isp": "【ISP_运营商原生宽带】.txt",
    "business": "【BIZ_商业企业专线】.txt",
    "education": "【EDU_高校教育科研】.txt",
    "government": "【GOV_政务公共网络】.txt",
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
    # ----------------------------------------------------
    # 1. 知名电信民用原生宽带 ASN (isp)
    # ----------------------------------------------------
    # 香港
    "AS4760": "isp",     # HKT Limited (PCCW)
    "AS9269": "isp",     # Hong Kong Broadband Network (HKBN)
    # 韩国
    "AS4766": "isp",     # Korea Telecom (KT)
    "AS9318": "isp",     # SK Broadband
    "AS3786": "isp",     # LG Uplus (LG U+)
    # 北美 (美国 / 加拿大)
    "AS7922": "isp",     # Comcast Cable Communications
    "AS20115": "isp",    # Charter Communications (Spectrum)
    "AS22773": "isp",    # Cox Communications
    "AS11404": "isp",    # Wave Broadband / Astound
    "AS852": "isp",      # TELUS Communications
    "AS812": "isp",      # Rogers Communications
    "AS577": "isp",      # Bell Canada
    "AS701": "isp",      # Verizon
    "AS7018": "isp",     # AT&T Services
    "AS5650": "isp",     # Frontier Communications
    "AS7029": "isp",     # Windstream
    "AS209": "isp",      # CenturyLink
    # 欧洲
    "AS3320": "isp",     # Deutsche Telekom
    "AS5607": "isp",     # Sky UK (Vodafone / Sky)
    "AS12576": "isp",    # Orange France
    "AS3215": "isp",     # Orange
    "AS2856": "isp",     # British Telecommunications (BT)
    "AS6830": "isp",     # Liberty Global (Virgin Media)
    "AS3303": "isp",     # Swisscom
    "AS12322": "isp",    # Free SAS (Iliad)
    "AS1241": "isp",     # Vodafone Spain
    "AS30722": "isp",    # Vodafone Italy
    "AS6805": "isp",     # Telefonica Germany (O2)
    "AS3352": "isp",     # Iberbanda / Telefonica de Espana
    "AS5410": "isp",     # Bouygues Telecom
    "AS254": "isp",      # KPN (Netherlands)
    "AS5466": "isp",     # Eir / Eircom (Ireland)
    # 亚太、中亚与其他
    "AS4657": "isp",     # Singapore Telecommunications (Singtel)
    "AS17676": "isp",    # SoftBank Corp.
    "AS2516": "isp",     # KDDI Corporation
    "AS4713": "isp",     # NTT Communications (OCN residential)
    "AS3462": "isp",     # Data Communication Business Group (Hinet/Chunghwa Telecom)
    "AS9198": "isp",     # Kazakhtelecom
    "AS3468": "isp",     # Transtelecom
    "AS45899": "isp",    # VNPT (Vietnam Posts and Telecommunications)
    "AS7552": "isp",     # Viettel Group
    "AS18403": "isp",    # FPT Telecom
    "AS9121": "isp",     # Turk Telekom
    "AS16135": "isp",    # Turkcell Superonline
    "AS4134": "isp",     # China Telecom Backbone
    "AS4837": "isp",     # China Unicom Backbone
    "AS9808": "isp",     # China Mobile Guangdong
    "AS58453": "isp",    # China Mobile International

    # ----------------------------------------------------
    # 2. 商业固定专线与商务宽带 (business)
    # ----------------------------------------------------
    "AS286": "business",   # KPN Business Internet
    "AS174": "business",   # Cogent Communications Enterprise

    # ----------------------------------------------------
    # 3. 高校教育科研网 (education)
    # ----------------------------------------------------
    "AS11246": "education",  # University of Maine System
    "AS4538": "education",   # CERNET (China Education and Research Network)
    "AS20965": "education",  # GÉANT (European academic research network)
    "AS1103": "education",   # SURFnet (Netherlands higher education)
    "AS2200": "education",   # RENATER (French academic network)
    "AS680": "education",    # DFN (German research network)
    "AS786": "education",    # Janet (UK higher education network)

    # ----------------------------------------------------
    # 4. 国家政务公用网 (government)
    # ----------------------------------------------------
    "AS6697": "government",  # Republican Unitary Enterprise Beltelecom (白俄罗斯政务网络)

    # ----------------------------------------------------
    # 5. 知名云服务商与数据中心机房强锁定 (datacenter)
    #    (防止名称包含 telecom/broadband 或别名时被规则误判)
    # ----------------------------------------------------
    "AS13335": "datacenter",   # Cloudflare
    "AS16509": "datacenter",   # Amazon AWS
    "AS8075": "datacenter",    # Microsoft Azure
    "AS15169": "datacenter",   # Google Cloud
    "AS45102": "datacenter",   # Alibaba Cloud
    "AS132203": "datacenter",  # Tencent Cloud
    "AS136907": "datacenter",  # Huawei Cloud
    "AS20473": "datacenter",   # Vultr / Choopa
    "AS14061": "datacenter",   # DigitalOcean
    "AS24940": "datacenter",   # Hetzner Online
    "AS16276": "datacenter",   # OVH
    "AS51167": "datacenter",   # Contabo
    "AS197540": "datacenter",  # Netcup
    "AS60068": "datacenter",   # Datacamp Limited
    "AS9009": "datacenter",    # M247
    "AS25820": "datacenter",   # BandwagonHost / IT7 Networks
    "AS63949": "datacenter",   # Linode Akamai
    "AS61112": "datacenter",   # AkileCloud
    "AS906": "datacenter",     # DMIT
    "AS210644": "datacenter",  # Aeza
    "AS212336": "datacenter",  # ByteVirt
    "AS36352": "datacenter",   # RackNerd
    "AS53667": "datacenter",   # BuyVM FranTech
    "AS47583": "datacenter",   # Hostinger
    "AS21859": "datacenter",   # Zenlayer
    "AS147049": "datacenter",  # VMISS
}

# 自动将 KNOWN_CLOUD_PROVIDERS 中未单独显式指定类型的知名云厂商/机房补充进入 ASN_EXACT_NET_TYPE 默认为 datacenter
for _asn in ASN_TO_PROVIDER:
    if _asn not in ASN_EXACT_NET_TYPE:
        ASN_EXACT_NET_TYPE[_asn] = "datacenter"


def is_asn_recorded(asn_str: str | None, isp_str: str | None = "") -> bool:
    """
    判断给定的 ASN 是否已被内置权威对照表（ASN_EXACT_NET_TYPE 或 ASN_TO_PROVIDER）精确收录。
    返回 True 表示已收录，False 表示属于未收录的新自治系统。
    若无法从文本中提取出有效 AS 编号（例如纯机构名），返回 True（不作为未收录 ASN 触发告警）。
    """
    code = _extract_asn_code(asn_str, isp_str)
    if not code:
        return True
    return code in ASN_EXACT_NET_TYPE or code in ASN_TO_PROVIDER


def classify_asn(asn_str: str | None, isp_str: str | None = "") -> str:
    """
    根据 BGP 广播的 ASN 编号、机构名称与 ISP 归属进行多维度网络类型属性分类（方案 A+ 两级分层体系）：
      [Tier 1] 内置权威精准对照：提取 AS 编号优先查表，秒级高精度定性
      [Tier 2] 启发式词根智能匹配：教育、政务、排除机房、商业专线、运营商宽带
      [Tier 3] 安全降级兜底：未命中任何已知特征的全新节点归为 datacenter 机房
    返回类型：
      - education: 高校与学术科研网
      - government: 政府政务与国家公共网
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

    # 3. 排除机房/主机商
    is_hosting = any(h in text for h in HOSTING_EXCLUSIONS)

    # 4. 识别商业专线
    if any(p in text for p in BIZ_PATTERNS) and not is_hosting:
        return "business"

    # 5. 识别电信运营商原生宽带
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
    os.makedirs(output_dir, exist_ok=True)
    groups: dict[str, list] = {}
    type_groups: dict[str, list] = {}

    for r in rows:
        country = extract_country(r.get("cf_location"), r.get("colo"))
        groups.setdefault(country, []).append(r)

        # 打标网络属性分类
        nt = classify_asn(r.get("asn", ""), r.get("isp", ""))
        r["net_type"] = nt
        if nt in SPECIAL_NET_TYPE_FILES:
            type_groups.setdefault(nt, []).append(r)

    active_files = set()

    # 1. 导出各国家/地区独立清单
    for country, members in groups.items():
        safe_country = re.sub(r'[\\/:*?"<>|]', "_", country).strip() or "其他地区"
        fname = f"{safe_country}.txt"
        filepath = os.path.join(output_dir, fname)
        with open(filepath, "w", encoding="utf-8") as f:
            for r in members:
                ip = (r.get("ip") or "").strip()
                port = r.get("port", "")
                if ip and port:
                    f.write(f"{ip}:{port}\n")
        active_files.add(fname)

    # 2. 导出高价值特殊网络属性清单（运营商宽带、企业专线、高校教育、政务公用）
    for nt, fname in SPECIAL_NET_TYPE_FILES.items():
        members = type_groups.get(nt, [])
        if members:
            filepath = os.path.join(output_dir, fname)
            with open(filepath, "w", encoding="utf-8") as f:
                for r in members:
                    ip = (r.get("ip") or "").strip()
                    port = r.get("port", "")
                    if ip and port:
                        f.write(f"{ip}:{port}\n")
            active_files.add(fname)

    # 清理已不存在或旧命名格式的 .txt 文件（保留 .gitkeep 等非 txt 标记文件）
    for old_f in os.listdir(output_dir):
        if old_f.endswith(".txt") and old_f not in active_files:
            try:
                os.remove(os.path.join(output_dir, old_f))
            except OSError:
                pass

    return len(active_files)


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

