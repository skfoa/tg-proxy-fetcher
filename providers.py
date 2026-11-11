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
    "ucloud": ("AS135377", "UCloud"),
    "baidu": ("AS38365", "Baidu Cloud"),
    "bce": ("AS38365", "Baidu Cloud"),
    "volcengine": ("AS138699", "ByteDance Volcengine"),
    "bytedance": ("AS138699", "ByteDance Volcengine"),
    "jdcloud": ("AS137753", "JD Cloud"),
    "jcloud": ("AS137753", "JD Cloud"),
    "jdcom": ("AS131486", "JD.com"),
    "ksyun": ("AS59019", "Kingsoft Cloud"),
    "kingsoft": ("AS59019", "Kingsoft Cloud"),
    "telegram": ("AS44907", "Telegram Messenger Inc."),
    "netease": ("AS45062", "NetEase"),
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
    "oracle_corp": ("AS54253", "Oracle Corporation"),
    "digitalocean": ("AS14061", "DigitalOcean"),
    "vultr": ("AS20473", "Vultr"),
    "choopa": ("AS20473", "Vultr"),
    "linode": ("AS63949", "Linode Akamai"),
    "akamai": ("AS63949", "Linode Akamai"),
    "hetzner": ("AS24940", "Hetzner"),
    "ovh": ("AS16276", "OVH"),
    "scaleway": ("AS12876", "Scaleway"),
    "leaseweb": ("AS60781", "Leaseweb"),
    "kamatera": ("AS36007", "Kamatera"),
    "kamatera_us": ("AS204548", "Kamatera"),
    "kamatera_eu": ("AS35838", "Kamatera"),
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
    "vmiss": ("AS967", "VMISS"),
    "contabo": ("AS51167", "Contabo"),
    "netcup": ("AS197540", "Netcup"),
    "hostpapa": ("AS36352", "HostPapa"),
    "colocrossing": ("AS36352", "ColoCrossing"),
    "racknerd": ("AS36352", "RackNerd"),
    "buyvm": ("AS53667", "BuyVM FranTech"),
    "frantech": ("AS53667", "BuyVM FranTech"),
    "h4y": ("AS397373", "H4Y Technologies LLC"),
    "hostdare": ("AS397373", "H4Y Technologies LLC"),  # 品牌 HostDare 挂载于 H4Y Technologies LLC
    "pegtech": ("AS54600", "PEG TECH INC"),
    "misaka": ("AS54600", "PEG TECH INC"),             # 品牌 Misaka 挂载于 PEG TECH INC
    "kurun": ("AS8796", "Kurun Cloud"),
    "kuruncloud": ("AS8796", "Kurun Cloud"),
    "spartan": ("AS201106", "Spartan Host Ltd"),       # 品牌 SpartanHost
    "spartanhost": ("AS201106", "Spartan Host Ltd"),
    "wap": ("AS198100", "WAP.ac"),
    "windscribe": ("AS397540", "Windscribe Limited"),
    "hosttech": ("AS207143", "hosttech GmbH"),
    "taymaz": ("AS216054", "Taymaz Gostaran Naghshe Almas"),
    "mtfinance": ("AS214822", "MT FINANCE LLC"),
    "tothost": ("AS151873", "TOTHOST"),
    "serverion": ("AS213035", "Serverion B.V."),
    "softshell": ("AS213035", "Serverion B.V."),      # 品牌 SoftShellWeb 挂载于 Serverion B.V.
    "softshellweb": ("AS213035", "Serverion B.V."),
    "fiberstate": ("AS26042", "FiberState, LLC"),
    "bagecloud": ("AS63150", "Bage Cloud"),
    "bage": ("AS63150", "Bage Cloud"),
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
    "wawacloud": ("AS402799", "WawaCloud Inc."),
    "wawa": ("AS402799", "WawaCloud Inc."),
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
    "xtom_jp": ("AS3258", "xTom Japan"),
    "virmach": ("AS25693", "VirMach"),
    "virmach_jp": ("AS3258", "VirMach"),
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
    "as56971": ("AS56971", "CGI GLOBAL LIMITED"),
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
    "hexcore": ("AS199144", "HexCore cloud s.r.o."),
    "edis": ("AS57169", "EDIS GmbH"),
    "fbwnetworks": ("AS34534", "FBW Networks"),
    "siberfy": ("AS135598", "Siberfy"),

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
# L0: 人工确证网络类型裁决表 (Manual SSOT Overrides: 核心公有云/数据中心机房/知名宽带ISP/商业专线与金融专网)
# =====================================================================
MANUAL_OVERRIDE_NET_TYPES: dict[str, str] = {
    # --- [L0 裁决 A: 头部公有云、IDC 与 VPS 主机商，严格锁定为 datacenter] ---
    "AS16509": "datacenter",  # Amazon AWS / Amazon.com, Inc. (amazon.com)
    "AS14618": "datacenter",  # Amazon.com / AWS (amazon.com)
    "AS8075": "datacenter",   # Microsoft Corporation / Azure (microsoft.com)
    "AS45102": "datacenter",  # Alibaba (US) Technology Co., Ltd. (alibabagroup.com)
    "AS132203": "datacenter", # Tencent Building, Kejizhongyi Avenue (tencent.com)
    "AS31898": "datacenter",  # Oracle Corporation (oracle.com)
    "AS3214": "datacenter",   # xTom GmbH (xtom.com, 知名 VPS/主机商)
    "AS3258": "datacenter",   # xTom Tokyo / VirMach (xtom.com)
    "AS4785": "datacenter",   # xTom Osaka (xtom.com)
    "AS6233": "datacenter",   # xTom San Jose (xtom.com)
    "AS7720": "datacenter",   # Skywolf Cloud (skywolf.net)
    "AS8888": "datacenter",   # xTom APAC (xtom.com)
    "AS9312": "datacenter",   # xTom Hong Kong (xtom.com)
    "AS22295": "datacenter",  # Advin Services LLC (advinservers.com, VPS 主机商)
    "AS22781": "datacenter",  # Black Oak Computers Inc (算力服务器)
    "AS34343": "datacenter",  # BIP Backbone ASN / Eweka (eweka.nl, ipinfo核准为hosting)
    "AS39618": "datacenter",  # HostCram LLC (hostcram.com, 主机商)
    "AS44382": "datacenter",  # FibaCloud (fibacloud.com, 云服务器机房)
    "AS45090": "datacenter",  # 腾讯云 (Shenzhen Tencent Computer Systems Company Limited, tencent.com)
    "AS49870": "datacenter",  # Alsycon B.V. (as49870.net, 云主机托管)
    "AS55933": "datacenter",  # Cloudie Limited (worria.com, 云主机托管)
    "AS56971": "datacenter",  # CGI GLOBAL LIMITED (hostvds.com, 香港云主机)
    "AS61112": "datacenter",  # AkileCloud Network (akilecloud.com, 云服务器机房)
    "AS62651": "datacenter",  # Strong Technology, LLC (strongtechnology.net, 算力服务器)
    "AS134677": "datacenter", # Dromatics Systems Pte Ltd (drosys.com, 机房 IDC)
    "AS136258": "datacenter", # BrainStorm Network, Inc (oneprovider.com, 机房)
    "AS138915": "datacenter", # Kaopu Cloud HK Limited (kaopucloud.com, 云主机)
    "AS146943": "datacenter", # Tier 4 Cloud Services (tier4.cloud, 数据中心)
    "AS149440": "datacenter", # Evoxt Sdn. Bhd. (evoxt.com, VPS 主机商)
    "AS198610": "datacenter", # Beget LLC (beget.com, 云主机托管)
    "AS202448": "datacenter", # MVPS LTD (mvps.net, VPS 主机商)
    "AS206216": "datacenter", # Advin Services LLC (advinservers.com, VPS 主机商)
    "AS206675": "datacenter", # PumpCloud JP / PAN-LIAN (pumpcloud.net, 云主机机房)
    "AS207847": "datacenter", # CloudBlast LLC (cloudblast.io, 云主机)
    "AS214478": "datacenter", # Sakura Clouds LLC (sakuraclouds.com, 云服务器)
    "AS207143": "datacenter", # hosttech GmbH (hosttech.ch, 瑞士机房/主机托管)
    "AS216054": "datacenter", # Taymaz Gostaran Naghshe Almas (viphost.cloud, 算力IDC)
    "AS200912": "datacenter", # Joel Krause (vpslayer.net, ipinfo核准为hosting)
    "AS55799": "datacenter",  # IPTELECOM ASIA (iptelecom.asia, ipinfo: hosting)
    "AS135357": "datacenter", # HONG KONG KOWLOON TELECOMMUNICATIONS (as3491.net, ipinfo: hosting)
    "AS199669": "datacenter", # Okay-Telecom Ltd. / ATLEX.RU (atlex.ru, ipinfo: hosting)
    "AS33842": "datacenter",  # Citytelecom LLC (CrossTelecom, crosstelecom.ru, ipinfo: hosting)
    "AS62642": "datacenter",  # Bigleaf Networks, Inc. (bigleaf.net, ipinfo: hosting)
    "AS137535": "datacenter", # JT Telecom International / JTTI (jtti.cc, 云主机/机房)
    "AS205548": "datacenter", # Zouter Limited (zouter.io, 云主机/VPS)
    "AS202147": "datacenter", # VPSUS LTD (vpsus.com, 云主机/VPS)
    "AS397373": "datacenter", # H4Y Technologies LLC / HostDare (hostdare.com, 云主机/机房)
    "AS54600": "datacenter",  # PEG TECH INC (misaka.io, 云主机/机房)
    "AS201106": "datacenter", # Spartan Host Ltd (spartanhost.org, VPS/主机)
    "AS38136": "datacenter",  # Akari Networks Limited (akarinetworks.com, 香港IDC)
    "AS14315": "datacenter",  # 1GSERVERS, LLC (1gservers.com, Phoenix机房)
    "AS202996": "datacenter", # Helkor (Ondrej Vrana, cbe-hosting.com, 捷克机房)
    "AS214159": "datacenter", # UAB Cherry Servers (balticservers.com, 立陶宛机房)
    "AS59642": "datacenter",  # UAB Cherry Servers (balticservers.com, 立陶宛机房)
    "AS213840": "datacenter", # DDOS PROTECTION LTD (英国高防机房)
    "AS152324": "datacenter", # 3XNET Co., Ltd. (亚太云主机机房)
    "AS135636": "datacenter", # PT. RACKH LINTAS ASIA (rackh.co.id, 印尼机房)
    "AS151873": "datacenter", # TOTHOST SOLUTIONS AND TECHNOLOGIES COMPANY LIMITED (tothost.vn, 越南VPS/机房)
    "AS213035": "datacenter", # Serverion B.V. (serverion.com, 荷兰机房/主机托管, SoftShellWeb上游)
    "AS26042": "datacenter",  # FiberState, LLC (ipinfo: Hosting)
    "AS152194": "datacenter", # CTG Server Limited (机房/云主机, ipinfo: Hosting)
    "AS20071": "datacenter",  # KUXUEYUN LLC (酷雪云, IDC机房, ipinfo: Hosting)
    "AS906": "datacenter",    # DMIT Cloud Services (IDC机房, ipinfo: Hosting)
    "AS214195": "datacenter", # Tres Teknoloji A.S. (IDC机房, ipinfo: Hosting)
    "AS8796": "datacenter",   # FASTNET DATA INC (Kurun Cloud, IDC机房, ipinfo: Hosting)
    "AS216475": "datacenter", # NKtelecom INC (ipinfo: Hosting)
    "AS200239": "datacenter", # Bogahost Bilisim (ipinfo: Hosting)
    "AS15401": "datacenter",  # Orange Business Services SA (orange.com, ipinfo: Hosting)
    "AS10753": "datacenter",  # Level 3 Parent, LLC / Lumen (lumen.com, ipinfo: Hosting)
    "AS7630": "datacenter",   # (ipinfo: Hosting)
    "AS207705": "datacenter", # TW NCU (ipinfo: Hosting)
    "AS214822": "datacenter", # MT FINANCE LLC (ipinfo: Hosting)
    "AS199144": "datacenter", # HexCore cloud s.r.o. (ipinfo: Hosting)
    "AS57169": "datacenter",  # EDIS GmbH (ipinfo: Hosting)
    "AS396986": "datacenter", # Bytedance Inc. (ipinfo: Hosting)
    "AS27284": "datacenter",  # Fourplex Telecom LLC (ipinfo: Hosting / 静态机房双ISP, 收敛为机房)
    "AS23724": "datacenter",  # IDC, China Telecommunications Corporation (ipinfo: Hosting)
    "AS135598": "datacenter", # Siberfy (APNIC: SIBERFY-AS-AP, ipinfo: Hosting)
    "AS13335": "datacenter",  # Cloudflare
    "AS15169": "datacenter",  # Google
    "AS54253": "datacenter",  # Oracle Corporation (ipinfo: Hosting)
    "AS45062": "datacenter",  # NetEase
    "AS137753": "datacenter", # JD Cloud
    "AS59019": "datacenter",  # Kingsoft Cloud
    "AS137280": "datacenter", # Kingsoft Cloud
    "AS135377": "datacenter", # UCloud
    "AS36007": "datacenter",  # Kamatera
    "AS25693": "datacenter",  # VirMach

    # --- [L0 裁决 B: 知名正牌民用宽带 ISP，权威核准为 isp] ---
    "AS4134": "isp",          # 中国电信 163
    "AS4811": "isp",          # 中国电信集团
    "AS4809": "isp",          # 中国电信 CN2
    "AS4837": "isp",          # 中国联通 169
    "AS9929": "isp",          # 中国联通 9929
    "AS10099": "isp",         # 中国联通 CUG
    "AS9808": "isp",          # 中国移动
    "AS58453": "isp",         # 中国移动 CMI
    "AS58807": "isp",         # 中国移动 CMIN2
    "AS3462": "isp",          # 中华电信 HiNet
    "AS4760": "isp",          # 香港电讯 HKT
    "AS4766": "isp",          # 韩国电信 KT
    "AS9318": "isp",          # 韩国 SK Broadband
    "AS174": "isp",           # Cogent Communications, LLC (Tier 1 国际骨干/ISP, ipinfo: ISP)
    "AS1299": "isp",          # Arelion Sweden AB / Telia (Tier 1 国际骨干/ISP, ipinfo: ISP)
    "AS3257": "isp",          # GTT Communications Inc. (Tier 1 国际骨干/ISP, ipinfo: ISP)
    "AS58682": "isp",         # Level3 Carrier Ltd. (Tier 1 国际骨干/ISP, ipinfo: ISP)
    "AS7738": "isp",          # V.tal (vtal.com, 巴西主流电信与国际海缆, ipinfo: ISP)
    "AS8167": "isp",          # V.tal (ipinfo: ISP)
    "AS9891": "isp",          # CS LOXINFO (csloxinfo.com, ipinfo: ISP)
    "AS34665": "isp",         # Petersburg Internet Network (pindc.ru, ipinfo: ISP)
    "AS134835": "isp",        # Starry Network (ipinfo: ISP)
    "AS152179": "isp",        # (ipinfo: ISP)
    "AS209604": "isp",        # 2E TELEKOMUNIKASYON (ipinfo: ISP)
    "AS400951": "isp",        # Akari Networks LLC (akarinetworks.com, ipinfo: ISP)
    "AS273961": "isp",        # LUDWIN GROUP COMPANY SRL (ipinfo: ISP)
    "AS273007": "isp",        # SPEEDNET, C.A (ipinfo: ISP)
    "AS274414": "isp",        # Osbaldo Tovar Campero (ipinfo: ISP)
    "AS1257": "isp",          # Tele2 Sverige AB (tele2.com, 欧洲顶级电信与家庭宽带)
    "AS18106": "isp",         # Viewqwest Pte Ltd (viewqwest.com, 新加坡知名光纤宽带 ISP)
    "AS63150": "isp",         # BAGE CLOUD LLC (bage.dev, 双ISP广播, 权威ipinfo核准为ISP)
    "AS3226": "isp",          # OOO NI (mark.ru, Mark-ITT 俄罗斯老牌宽带运营商, 权威ipinfo核准为ISP)
    "AS4787": "isp",          # PT Cyberindo Aditama (cbn.id, 印尼知名民用光纤宽带 CBN)
    "AS135130": "isp",        # Anik Computer & Networking (aniknetwork.net, 孟加拉民用宽带ISP)
    "AS197275": "isp",        # Link Telecom NN Ltd. (lt-nn.net, 俄罗斯下诺夫哥罗德电信运营商)
    "AS16814": "isp",         # NSS S.A. (IPLAN Telecomunicaciones, iplan.com.ar, 阿根廷主流光纤运营商)
    "AS206069": "isp",        # Cornseed Limited (ipinfo: ISP)
    "AS397540": "isp",        # Windscribe Limited (ipinfo: ISP)
    "AS35540": "isp",         # OVH SAS / OVH Telecom (ovhcloud.com, 法国电信与宽带接入网)
    "AS17621": "isp",         # China Unicom Shanghai network (中国联通上海网络)
    "AS25341": "isp",         # NPF ROI LLC (cstnet.ru, 俄罗斯宽带ISP)
    "AS44347": "isp",         # Limited Company "SiNT" (俄罗斯地区ISP)
    "AS24530": "isp",         # PT. Power Telecom Indonesia (Powertel, 印尼ISP)
    "AS14813": "isp",         # Columbus Telecommunications (Barbados) Limited (巴巴多斯电信宽带)
    "AS29076": "isp",         # Citytelecom LLC (Filanco, citytelecom.ru, 俄罗斯宽带ISP)
    "AS272605": "isp",        # Grupo Ultra Fibra (巴西宽带ISP)
    "AS36902": "isp",         # Intelvision Ltd (塞舌尔宽带ISP)
    "AS24550": "isp",         # Websurfer Nepal Communication System (尼泊尔宽带ISP)
    "AS14593": "isp",         # SpaceX Services / Starlink (星链低轨卫星民用宽带)
    "AS134760": "isp",        # CHINANET Hebei (中国电信河北民用原生宽带)
    "AS134420": "isp",        # CHINANET Chongqing (中国电信重庆民用原生宽带)
    "AS137694": "isp",        # CHINANET Xinjiang (中国电信新疆民用原生宽带)
    "AS137697": "isp",        # CHINANET Jiangsu (中国电信江苏民用原生宽带)
    "AS4773": "isp",          # M1 LIMITED (新加坡主流电信与家庭光纤宽带)
    "AS17547": "isp",         # M1 NET LTD (新加坡 M1 宽带网)
    "AS8708": "isp",          # DIGI ROMANIA S.A. (罗马尼亚第一大民用光纤宽带)
    "AS27699": "isp",         # TELEFÔNICA BRASIL S.A / Vivo (巴西第一大电信与民用光纤宽带)
    "AS7004": "isp",          # TELEFÓNICA CHILE S.A. / Movistar (智利第一大民用光纤宽带)
    "AS131429": "isp",        # MobiFone (越南主流移动通信与手机蜂窝宽带)
    "AS14051": "isp",          # Fidium / Consolidated Communications (fidiumfiber.com, 美国民用光纤宽带)
    "AS28716": "isp",          # Retelit Digital Services S.p.A. (retelit.it, 意大利电信与光纤宽带)
    "AS17529": "isp",          # STARCAT Co., LTD. (starcat.co.jp, 日本名古屋有线电视与民用宽带 ISP)
    "AS7511": "isp",           # SYNAPSE Co.,Ltd. (synapse.jp, 日本鹿儿岛民用宽带 ISP)
    "AS62560": "isp",          # Hosted America (hostedamerica.com, 美国民用光纤宽带 ISP)
    "AS62711": "isp",          # Maxwell Telecom LLC (ipinfo: ISP)
    "AS38060": "isp",          # BIZNET / PT. Supra Primatama Nusantara (biznetnetworks.com, 印尼民用光纤宽带)
    "AS8427": "isp",           # Joint Stock Company TransTeleCom / TTK (ttk.ru, 俄罗斯骨干电信与宽带运营商)
    "AS21271": "isp",          # Society of Mali's Telecommunications / SOTELMA (sotelma.ml, 马里国家电信与宽带运营商)
    "AS139282": "isp",         # Novus Network (novusnetwork, 宽带接入 ISP)
    "AS11404": "isp",          # Wave Broadband / Astound (astound.com, 美国民用有线与光纤宽带)
    "AS265606": "isp",         # DIGY NETWORKS (digynetworks.com.br, 巴西民用光纤宽带)
    "AS154462": "isp",         # Yournet Communications (yournet.in, 印度民用宽带 ISP)
    "AS152045": "isp",         # PT. PETABYTE NETWORK INDONESIA (petabyte.net.id, 印尼光纤宽带 ISP)
    "AS12252": "isp",          # America Movil Peru S.A.C. / Claro Peru (claro.com.pe, 秘鲁电信与民用宽带)
    "AS16010": "isp",          # Magticom Ltd. (magticom.ge, 格鲁吉亚第一大电信与民用光纤宽带)
    "AS265605": "isp",         # VELOCOM SA DE CV (velocom.com.mx, 墨西哥电信与民用宽带)
    "AS3302": "isp",           # Retelit Digital Services S.p.A. (retelit.it, 意大利全国光纤骨干与电信 ISP)
    "AS394311": "isp",         # Digicel Turks and Caicos Ltd (digicelgroup.com, 加勒比海特克斯和凯科斯群岛电信宽带)
    "AS17975": "isp",          # APT Datamatrix Limited (aptdatamatrix.com, 香港亚太卫星与电信网络)
    "AS203101": "isp",         # Navarino Single Member S.A. (navarino.gr, 希腊海事卫星与电信网络服务商)
    "AS38264": "isp",          # Wateen Telecom Limited (wateen.com, 巴基斯坦全国光纤与民用宽带 ISP)

    # --- [L0 裁决 C: 核心国际银行金融专网 (对齐 ipinfo.io 业界权威标准，统一归入 business 商业专线)] ---
    "AS1311": "business", "AS2600": "business", "AS3187": "business", "AS5091": "business",
    "AS5458": "business", "AS6674": "business", "AS6773": "business", "AS7609": "business",
    "AS7820": "business", "AS8373": "business",
    "AS9016": "business", "AS9099": "business", "AS9118": "business", "AS9128": "business",
    "AS9221": "business", "AS9522": "business", "AS9630": "business",
    "AS9772": "business", "AS9863": "business", "AS207986": "business",
    "AS8435": "business",     # Bank of Korea (ipinfo: business)
    "AS25883": "business",    # Citigroup Inc. (ipinfo: business)

    # --- [L0 裁决 D: 核心学术科研教育网 (权威核准为 education)] ---
    "AS9488": "education",    # Seoul National University / SNU (首尔大学)
    "AS199578": "education",  # Verein zur Foerderung eines Deutschen Forschungsnetzes e.V. (DFN, 德国国家科研教育网)
    "AS142078": "education",  # CERNET FITI Nodes (清华大学/未来互联网试验设施教育网节点)
    "AS3132": "education",    # Red Cientifica Peruana (rcp.pe, 秘鲁教育网, ipinfo: education)

    # --- [L0 裁决 E: 商业企业专线与骨干中继 (权威核准为 business)] ---
    "AS44907": "business",    # Telegram Messenger Inc. (ipinfo: Business)
    "AS131486": "business",   # JD.com (ipinfo: Business)
    "AS979": "business",      # NetLab Global (as979.net, 国际机房网络, ipinfo: business)
    "AS20981": "business",    # InnovaPuglia SpA (RUPAR Puglia 区域宽带专网运营商, ipinfo: business)
    "AS274029": "business",   # KAZAV LATAM E.I.R.L. / ASU TELECOM PERU (秘鲁商业网络, ipinfo: business)

    # --- [L0 裁决 F: 国家政务与公共网络 (权威核准为 government)] ---
    "AS327724": "government",  # National Information Technology Authority Uganda (NITA-U, 乌干达国家信息技术管理局政务网)
    "AS9487": "government",    # Bank of Korea (ipinfo: government)
}

# 权威已知云厂商与核心骨干网 SSOT 网络类型基准表
AUTHORITATIVE_CLOUD_NET_TYPES: dict[str, str] = {}
for _asn, _isp in AUTHORITATIVE_CLOUD_ASNS.items():
    if _asn in MANUAL_OVERRIDE_NET_TYPES:
        AUTHORITATIVE_CLOUD_NET_TYPES[_asn] = MANUAL_OVERRIDE_NET_TYPES[_asn]
    else:
        text = f"{_asn} {_isp}".lower()
        if any(p in text for p in ("china telecom", "korea telecom", "chunghwa telecom", "unicom", "mobile", "broadband", "hinet")):
            AUTHORITATIVE_CLOUD_NET_TYPES[_asn] = "isp"
        else:
            AUTHORITATIVE_CLOUD_NET_TYPES[_asn] = "datacenter"



# =====================================================================
# 公共实用工具：环境加载、类型转换、ASN 清洗、Telegram 推送与自检
# =====================================================================

import asyncio
import concurrent.futures
import contextlib
import csv
import functools
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

log = logging.getLogger("providers")


# ---------- 原子写入与安全落盘工具 (Atomic File Operations) ----------

@contextlib.contextmanager
def atomic_writer(
    path: str,
    mode: str = "w",
    encoding: str | None = "utf-8",
    newline: str | None = None,
):
    """
    上下文管理器：安全原子写入文件（tmp -> os.replace）。
    1. 自动确保目标目录存在；
    2. 写入 {path}.tmp 临时文件；
    3. 正常退出时显式关闭文件句柄后再执行 os.replace 覆写目标文件（彻底消除 Windows 平台占用锁冲突）；
    4. 遇异常退出时立即关闭句柄并清理未完成的 .tmp 临时文件，杜绝遗留脏数据。

    用法：
        with atomic_writer("data/nodes.csv", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=...)
            writer.writeheader()
    """
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp"
    is_binary = "b" in mode
    enc = None if is_binary else encoding
    nl = None if is_binary else newline
    f = open(tmp, mode, encoding=enc, newline=nl)  # noqa: SIM115  # 必须在 os.replace 前显式释放文件句柄以彻底规避 Windows WinError 32 锁冲突
    try:
        yield f
        f.close()
        os.replace(tmp, path)
    except Exception:
        f.close()
        if os.path.exists(tmp):
            with contextlib.suppress(OSError):
                os.remove(tmp)
        raise


def atomic_write_text(path: str, text: str, encoding: str = "utf-8", newline: str | None = "\n") -> None:
    """原子覆写纯文本数据 (跨平台默认严格强制 LF 换行，彻底杜绝 CRLF 污染)"""
    with atomic_writer(path, mode="w", encoding=encoding, newline=newline) as f:
        f.write(text)


def atomic_write_json(path: str, obj, *, indent: int | None = 2, newline: str | None = "\n") -> None:
    """原子序列化并覆写 JSON 数据 (跨平台默认严格强制 LF 换行，彻底杜绝 CRLF 污染；indent=None 时采用紧凑格式)"""
    if indent is None:
        text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(obj, ensure_ascii=False, indent=indent)
    atomic_write_text(path, text, encoding="utf-8", newline=newline)


def inspect_csv_state(
    path: str,
    required_columns: tuple[str, ...] = ("ip", "port"),
) -> tuple[list[str], int]:
    """
    校验已有 CSV 文件的表头合法性并统计原始数据行数（不含表头与全空行）。
    若文件不存在返回 ([], 0)；若文件存在但为 0 字节、无表头或缺失必需列，抛出 ValueError。
    """
    if not os.path.exists(path):
        return [], 0
    with open(path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fields = [str(col).strip() for col in (reader.fieldnames or []) if col is not None]
        missing = [col for col in required_columns if col not in fields]
        if not fields or missing:
            raise ValueError(f"{path} 表头无效或文件为空（缺失必需列 {', '.join(required_columns)}: {fields}）")
        raw_count = sum(
            1
            for r in reader
            if any(
                str(x or "").strip()
                for v in r.values()
                for x in (v if isinstance(v, list) else [v])
            )
        )
    return fields, raw_count


# ---------- 持久化 ASN 数据库加载与在线动态解析补库 ----------

ASN_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "asn_database.json")
ASN_DATABASE_REL_PATH = os.path.join("data", "asn_database.json")


# L0 人工网络类型裁决表已在上方统一声明为 MANUAL_OVERRIDE_NET_TYPES，单真理源 (SSOT) 杜绝重复定义



VALID_NET_TYPES: frozenset[str] = frozenset({"isp", "datacenter", "business", "education", "government"})

# 外部查询接口网络类型枚举映射表 (对齐至 ipinfo.io 业界权威五大标准网络类型)
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
    # 商业专线与金融机构 (business，对齐 ipinfo.io 标准：商业企业、银行金融均归入 business)
    "business": "business",
    "corporate": "business",
    "commercial": "business",
    "banking": "business",
    "finance": "business",
    # 教育学术 (education)
    "education": "education",
    "edu": "education",
    "university": "education",
    # 政府政务 (government)
    "government": "government",
    "gov": "government",
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
    """持久化保存动态发现的 ASN/ISP/NetType 数据库（严格 Append-Only 只增不改与 SSOT 保护）"""
    target_path = db_path or ASN_DATABASE_PATH
    try:
        # 0. 严格只增不改 (Append-Only): 优先加载磁盘文件基准，既有条目永久不可变
        existing_data = {}
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as cur_f:
                    existing_data = json.load(cur_f)
            except Exception:
                existing_data = {}

        cur_i2a = existing_data.get("isp_to_asn", {})
        cur_a2i = existing_data.get("asn_to_isp", {})
        cur_a2nt = existing_data.get("asn_to_net_type", {})

        clean_i2a: dict[str, str] = dict(cur_i2a)
        clean_a2i: dict[str, str] = dict(cur_a2i)
        clean_a2nt: dict[str, str] = dict(cur_a2nt)

        # 1. 规范化增量加载传入的反向映射字典 (既有条目锁定，只准追加新 ASN)
        for k, v in asn_to_isp.items():
            asn_code = (k or "").strip().upper()
            isp_name = (v or "").strip()
            if re.match(r"^AS\d+$", asn_code) and isp_name:
                if asn_code not in clean_a2i:
                    clean_a2i[asn_code] = isp_name

        # 2. 权威 SSOT 锁定：内置权威已知云厂商始终锁定为 SSOT 权威名称，坚决禁止被覆盖
        for asn_code, auth_name in AUTHORITATIVE_CLOUD_ASNS.items():
            clean_a2i[asn_code] = auth_name

        # 3. 规范化增量加载正向映射 (既有条目锁定，只准追加新服务商名称)
        seen_lower_i2a: dict[str, str] = {k.lower(): k for k in clean_i2a}
        for k, v in isp_to_asn.items():
            isp_name = (k or "").strip()
            asn_code = (v or "").strip().upper()
            if not re.match(r"^AS\d+$", asn_code) or not isp_name:
                continue

            lower_name = isp_name.lower()
            if lower_name in seen_lower_i2a:
                continue

            clean_i2a[isp_name] = asn_code
            seen_lower_i2a[lower_name] = isp_name

            if asn_code not in clean_a2i:
                clean_a2i[asn_code] = isp_name

        # 4. 规范化增量加载 asn_to_net_type (既有条目锁定，只准追加官方探针确证的新 ASN)
        target_a2nt = asn_to_net_type if asn_to_net_type is not None else ASN_DATABASE_ASN_TO_NET_TYPE
        for k, v in target_a2nt.items():
            asn_code = (k or "").strip().upper()
            net_type = (v or "").strip().lower()
            if re.match(r"^AS\d+$", asn_code) and net_type in VALID_NET_TYPES:
                if asn_code not in clean_a2nt:
                    clean_a2nt[asn_code] = net_type

        # 权威云厂商与核心骨干网 SSOT 属性保护：锁定官方权威网络类型
        for auth_asn, auth_type in AUTHORITATIVE_CLOUD_NET_TYPES.items():
            if clean_a2nt.get(auth_asn) != auth_type:
                clean_a2nt[auth_asn] = auth_type

        # 人工裁决表保护：锁定 MANUAL_OVERRIDE_NET_TYPES
        for man_asn, man_type in MANUAL_OVERRIDE_NET_TYPES.items():
            if clean_a2nt.get(man_asn) != man_type:
                clean_a2nt[man_asn] = man_type

        # 彻底废除 classify_asn 正则猜测自愈补齐：未被探针/人工确证的 ASN 绝不自动填补落盘

        # 5. 保存前进行硬错误阻断校验
        val_errors, _ = validate_asn_database({
            "isp_to_asn": clean_i2a,
            "asn_to_isp": clean_a2i,
            "asn_to_net_type": clean_a2nt,
        })
        if val_errors:
            log.error("拒绝持久化写入损坏的 ASN 数据库: %s", val_errors)
            return False

        # 6. 脏写检测 (Dirty Check / 零 I/O 优化)：若磁盘文件内容完全一致，坚决跳过写盘
        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8") as cur_f:
                    cur_data = json.load(cur_f)
                if (
                    cur_data.get("isp_to_asn") == clean_i2a
                    and cur_data.get("asn_to_isp") == clean_a2i
                    and cur_data.get("asn_to_net_type") == clean_a2nt
                ):
                    log.debug("【零 I/O 优化】ASN 数据库内容完全一致无新增变更，跳过磁盘写入: %s", target_path)
                    if not db_path or os.path.abspath(target_path) == os.path.abspath(ASN_DATABASE_PATH):
                        ASN_DATABASE_ASN_TO_NET_TYPE.update(clean_a2nt)
                        if "ASN_EXACT_NET_TYPE" in globals():
                            ASN_EXACT_NET_TYPE.update(clean_a2nt)
                    return False
            except Exception:
                pass

        atomic_write_json(
            target_path,
            {
                "isp_to_asn": clean_i2a,
                "asn_to_isp": clean_a2i,
                "asn_to_net_type": clean_a2nt,
            },
        )
        # 仅当写入默认系统数据库时才同步更新进程全局单例运行时字典
        if not db_path or os.path.abspath(target_path) == os.path.abspath(ASN_DATABASE_PATH):
            ASN_DATABASE_ASN_TO_NET_TYPE.update(clean_a2nt)
            if "ASN_EXACT_NET_TYPE" in globals():
                ASN_EXACT_NET_TYPE.update(clean_a2nt)
        return True
    except Exception as e:
        log.warning("保存 asn_database.json 异常: %s", e)
        return False


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

# 运行时 ASN 精准网络类型对照表 (从权威持久化数据库与云厂商基准构建，受人工裁决表最高优先级锁定保护)
ASN_EXACT_NET_TYPE: dict[str, str] = dict(ASN_DATABASE_ASN_TO_NET_TYPE)

# 1. 权威已知云厂商与核心骨干网 SSOT 纯净性锁定
ASN_EXACT_NET_TYPE.update(AUTHORITATIVE_CLOUD_NET_TYPES)

# 2. 人工网络类型裁决表 (L0) 最高优先级锁定覆盖
ASN_EXACT_NET_TYPE.update(MANUAL_OVERRIDE_NET_TYPES)



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

        # 在线 IP 反查仅用于识别 IP 所属 ASN 与 ISP 名称，未通过 IPinfo 官方探针定性前不写入权威 ASN 数据库字典
        clean_isp = clean_isp or isp_hint
        log.debug("【在线 IP 反查】识别新 IP %s: %s -> %s", ip, clean_asn, clean_isp)
        return clean_asn, clean_isp

    return "", ""


# ---------- IP/域名 级别持久化元数据缓存 (data/ip_cache.json) ----------

IP_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ip_cache.json")
IP_CACHE_REL_PATH = os.path.join("data", "ip_cache.json")


def load_ip_cache(filepath: str = "") -> dict[str, dict]:
    """从 data/ip_cache.json 加载已解析的 IP/域名 -> ASN/ISP/net_type 高速缓存"""
    search_paths = [filepath] if filepath else [IP_CACHE_PATH, IP_CACHE_REL_PATH]
    for p in search_paths:
        if p and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception as e:
                log.debug("读取 %s 异常: %s", p, e)
    return {}


def save_ip_cache(cache: dict[str, dict], filepath: str = "", compact: bool = True):
    """持久化保存 IP/域名 -> ASN/ISP/net_type 缓存字典至 data/ip_cache.json（原子写入，默认紧凑压缩）"""
    target_path = filepath or IP_CACHE_PATH
    try:
        atomic_write_json(target_path, cache, indent=None if compact else 2)
    except Exception as e:
        log.warning("保存 %s 异常: %s", target_path, e)


def prune_ip_cache(
    cache: dict[str, dict] | None = None,
    active_ips: set[str] | None = None,
    filepath: str = "",
) -> int:
    """
    修剪持久化 IP 缓存 (data/ip_cache.json)，仅保留当前在用活跃节点画像，防止无界膨胀：
    1. 动态提取当前库中所有在用活跃标识（cf_ips、scan_ips、proxyip 的入出口 IP，以及 proxies 的入口 IP/域名与多跳落地出口 egress_ip）；
    2. 对在用域名缓存关联的 resolved_ip 同步保护保留；
    3. 已从全部活跃库淘汰的孤儿记录直接物理剔除（不保留静态机房 IP 黑名单）；
    4. 修剪后以紧凑 Compact JSON 原子覆写。
    返回修剪淘汰的孤儿记录数量。
    """
    target_path = filepath or IP_CACHE_PATH
    explicit_cache = cache is not None
    if cache is None:
        cache = load_ip_cache(filepath=target_path)
    if not cache:
        return 0

    if active_ips is None:
        active_ips = set()
        base_dir = os.path.dirname(os.path.abspath(target_path))
        has_any_dataset = False

        def _add_key(val: str):
            v = (val or "").strip().strip("[]")
            if v:
                active_ips.add(v)
                active_ips.add(v.lower())

        # 1. 扫描单条优选、扫描优选与反代库 (入口 IP + 出口 IPv4/IPv6)
        for fname in ("cf_ips.csv", "scan_ips.csv", "proxyip.csv"):
            fpath = os.path.join(base_dir, fname)
            if os.path.isfile(fpath):
                has_any_dataset = True
                try:
                    with open(fpath, "r", encoding="utf-8-sig", errors="ignore") as f:
                        for row in csv.DictReader(f):
                            raw_ip = (row.get("ip") or "").strip()
                            if raw_ip:
                                _add_key(raw_ip)
                                for ep in extract_ips(raw_ip):
                                    _add_key(ep)
                            for col in ("exit_ip", "exit_ipv6"):
                                col_val = (row.get(col) or "").strip()
                                if col_val:
                                    for ep in extract_ips(col_val):
                                        _add_key(ep)
                except Exception as e:
                    log.debug("读取 %s 收集活跃 IP 异常: %s", fpath, e)

        # 2. 扫描结构化代理总表 proxies.csv (覆盖入口 IP/域名与多跳落地出口 egress_ip)
        proxies_csv_path = os.path.join(base_dir, "proxies.csv")
        if os.path.isfile(proxies_csv_path):
            has_any_dataset = True
            try:
                with open(proxies_csv_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    for row in csv.DictReader(f):
                        host_val = (row.get("host") or "").strip()
                        if host_val:
                            _add_key(host_val)
                        url_val = (row.get("url") or "").strip()
                        if url_val:
                            try:
                                parsed_u = urllib.parse.urlparse(url_val)
                                if parsed_u.hostname:
                                    _add_key(parsed_u.hostname)
                            except Exception:
                                pass
                        egress_val = (row.get("egress_ip") or "").strip()
                        if egress_val:
                            _add_key(egress_val)
                            for ep in extract_ips(egress_val):
                                _add_key(ep)
            except Exception as e:
                log.debug("读取 %s 收集活跃 IP/域名异常: %s", proxies_csv_path, e)

        # 3. 兜底扫描原始代理池 proxies.txt (兼容手工追加尚未进入 csv 的节点)
        proxies_txt_path = os.path.join(base_dir, "proxies.txt")
        if os.path.isfile(proxies_txt_path):
            has_any_dataset = True
            try:
                with open(proxies_txt_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        try:
                            parsed_u = urllib.parse.urlparse(s)
                            if parsed_u.hostname:
                                _add_key(parsed_u.hostname)
                        except Exception:
                            pass
                        for ep in extract_ips(s):
                            _add_key(ep)
            except Exception as e:
                log.debug("读取 %s 收集活跃 IP/域名异常: %s", proxies_txt_path, e)

        if not has_any_dataset:
            return 0

    # 同步保护在用域名缓存中关联的 resolved_ip，避免重复 DNS -> ASN 查询
    resolved_linked = set()
    for k, entry in cache.items():
        if isinstance(entry, dict) and (k in active_ips or str(k).lower() in active_ips):
            res_ip = (entry.get("resolved_ip") or "").strip()
            if res_ip:
                resolved_linked.add(res_ip)
                resolved_linked.add(res_ip.lower())
    effective_active = active_ips | resolved_linked

    pruned_cache = {}
    pruned_count = 0

    for ip_key, entry in cache.items():
        if not isinstance(entry, dict):
            pruned_count += 1
            continue
        if ip_key in effective_active or str(ip_key).lower() in effective_active:
            pruned_cache[ip_key] = entry
        else:
            pruned_count += 1

    if pruned_count > 0 or explicit_cache:
        save_ip_cache(pruned_cache, filepath=target_path, compact=True)
    if pruned_count > 0:
        log.info(
            "已修剪 IP 缓存 %s: 剔除 %d 条淘汰孤儿记录，当前保留 %d 条活跃画像",
            target_path,
            pruned_count,
            len(pruned_cache),
        )
    return pruned_count


def is_valid_ipv4(ip_str: str) -> bool:
    """严格校验是否为有效 IPv4 地址"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        return ipaddress.ip_address(ip_str.strip().strip("[]")).version == 4
    except Exception:
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    """严格校验是否为有效 IPv6 地址"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        return ipaddress.ip_address(ip_str.strip().strip("[]")).version == 6
    except Exception:
        return False


def extract_ips(val) -> list[str]:
    """从任意输入（单串、列表、逗号/分号/斜杠/空格分隔）中提取所有合法 IP 地址（IPv4 与 IPv6），保持顺序并去重"""
    if not val:
        return []
    if isinstance(val, (list, tuple, set)):
        raw_items = [str(x) for x in val]
    else:
        raw_items = re.split(r"[,;\s/|]+", str(val).strip())
    res = []
    seen = set()
    for item in raw_items:
        clean = item.strip().strip("[]'\"")
        if clean:
            try:
                ipaddress.ip_address(clean)
                if clean not in seen:
                    seen.add(clean)
                    res.append(clean)
            except Exception:
                pass
    return res


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


_DOH_RECORD_TYPES = {"A": 1, "TXT": 16, "AAAA": 28}


def _clean_doh_txt_data(raw: str) -> str:
    """规范化还原 DoH JSON 返回的 RFC-1035 TXT 字符串（支持单段与超长分段拼接引号）"""
    s = str(raw or "").strip()
    if not s:
        return ""
    if re.fullmatch(r'(?:"(?:[^"\\]|\\.)*"\s*)+', s):
        chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', s)
        joined = "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)
        return joined.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1].replace('\\"', '"').replace("\\\\", "\\").strip()
    return s


def doh_query_dns_records(
    domain: str,
    record_type: str = "A",
    timeout: float = 3.5,
    proxy: str = "",
) -> tuple[list[str], bool, str]:
    """
    通过安全加密 DNS (DoH) 查询域名指定类型（A / TXT / AAAA）的全部权威记录，
    支持全球与国内直连多端点容灾及可选 HTTP 代理。
    返回 (records, ok, detail):
      - ok=True  表示 DoH 查询成功得到权威 DNS 状态（含明确无记录 empty/nxdomain 与有记录 ok）
      - ok=False 表示全部 DoH 端点请求失败或返回 SERVFAIL 等异常状态（此时 detail 记录具体原因）
    """
    if not domain or not isinstance(domain, str):
        return [], False, "invalid_domain"
    clean = domain.strip().rstrip(".").lower()
    rtype = str(record_type or "A").strip().upper()
    target_type = _DOH_RECORD_TYPES.get(rtype)
    if not clean or target_type is None:
        return [], False, "invalid_query"

    q_name = urllib.parse.quote(clean, safe="")
    doh_endpoints = [
        (f"https://1.1.1.1/dns-query?name={q_name}&type={rtype}", False),
        (f"https://cloudflare-dns.com/dns-query?name={q_name}&type={rtype}", False),
        (f"https://dns.google/resolve?name={q_name}&type={rtype}", False),
        (f"https://223.5.5.5/resolve?name={q_name}&type={rtype}", True),
        (f"https://1.12.12.12/dns-query?name={q_name}&type={rtype}", True),
    ]

    headers = {
        "Accept": "application/dns-json",
        "User-Agent": "Mozilla/5.0 (compatible; tg-proxy-fetcher/2.0)",
    }
    proxy_str = str(proxy or "").strip()
    proxy_opener = (
        urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_str, "https": proxy_str}))
        if proxy_str and not proxy_str.startswith("socks")
        else None
    )
    direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    any_valid_dns_resp = False
    last_err = "all_doh_endpoints_failed"

    for url, is_cn_direct in doh_endpoints:
        openers = []
        if proxy_opener is not None:
            openers.append(proxy_opener)
            if is_cn_direct:
                openers.append(direct_opener)
        else:
            openers.append(urllib.request.build_opener())
            if is_cn_direct:
                openers.append(direct_opener)

        for opener in openers:
            try:
                req = urllib.request.Request(url, headers=headers)
                with opener.open(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if not isinstance(data, dict):
                    last_err = "invalid_json_type"
                    continue
                status = data.get("Status")
                if status not in (0, 3):
                    last_err = f"dns_status_{status}"
                    continue

                answers = data.get("Answer", [])
                results: list[str] = []
                seen: set[str] = set()
                has_cname_only = False
                if isinstance(answers, list):
                    for ans in answers:
                        if not isinstance(ans, dict):
                            continue
                        ans_type = ans.get("type")
                        if ans_type == 5:
                            has_cname_only = True
                        if ans_type != target_type:
                            continue
                        raw_val = str(ans.get("data", "")).strip()
                        if rtype in ("A", "AAAA"):
                            if is_valid_public_ip(raw_val) and raw_val not in seen:
                                seen.add(raw_val)
                                results.append(raw_val)
                        elif rtype == "TXT":
                            cleaned_txt = _clean_doh_txt_data(raw_val)
                            if cleaned_txt and cleaned_txt not in seen:
                                seen.add(cleaned_txt)
                                results.append(cleaned_txt)

                if results:
                    return results, True, "ok"
                if status == 3:
                    return [], True, "nxdomain"
                if status == 0 and not has_cname_only:
                    return [], True, "no_records"
                any_valid_dns_resp = True
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                continue

    if any_valid_dns_resp:
        return [], True, "no_records"
    return [], False, last_err


def doh_resolve_dns_records(
    domain: str,
    record_type: str = "A",
    timeout: float = 3.5,
    proxy: str = "",
) -> list[str]:
    """
    通过安全加密 DNS (DoH) 查询域名指定类型（A / TXT / AAAA）的全部权威记录，
    返回去重且保序的记录列表；若需区分“确认无记录”与“查询失败”，请使用 `doh_query_dns_records`。
    """
    records, _, _ = doh_query_dns_records(domain, record_type=record_type, timeout=timeout, proxy=proxy)
    return records


def doh_resolve_public_ip(domain: str, timeout: float = 3.5, proxy: str = "") -> str:
    """通过安全加密 DNS (DoH) 解析域名，绕过本地 DNS 污染/劫持返回首选真实公网 IP"""
    records, _, _ = doh_query_dns_records(domain, record_type="A", timeout=timeout, proxy=proxy)
    return records[0] if records else ""


@functools.lru_cache(maxsize=4096)
def resolve_domain_to_ip(domain: str) -> str:
    """尝试将域名解析为有效公网 IP，若失败或解析为保留/回环 IP 则依次尝试本地系统解析与 DoH 加密解析"""
    if not domain or not isinstance(domain, str):
        return ""
    clean = domain.strip().lower()
    try:
        ipaddress.ip_address(clean)
        return clean if is_valid_public_ip(clean) else ""
    except ValueError:
        pass
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

    cache = load_ip_cache(filepath=cache_path)
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
    pending_ips = [ip for ip in ip_to_targets if ip not in results]
    if not pending_ips:
        if persist and cache_modified:
            save_ip_cache(cache, filepath=cache_path)
        return results

    log.info("【批量 ASN 解析】待解析出口 IP 数量: %d 个 (分批步长: %d)", len(pending_ips), max_chunk_size)

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
                                # SSOT 权威校验：已收录于权威字典的 ASN 直接采用权威标准名；未收录新 ASN 统一交由后续 auto_enrich_and_save_asns 经 IPinfo 探针定性入库
                                if clean_asn in ASN_TO_PROVIDER:
                                    clean_isp = ASN_TO_PROVIDER[clean_asn]

                                # 动态研判 net_type (仅用于当前 IP 缓存条目画像，不越权直接写持久化 ASN 数据库)
                                n_type = ASN_EXACT_NET_TYPE.get(clean_asn) or ext_net_type or classify_asn(clean_asn, clean_isp)

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


def resolve_ip_asn(
    ip: str = "",
    isp_hint: str = "",
    allow_online: bool = False,
    ip_cache: dict[str, dict] | None = None,
) -> tuple[str, str]:
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

    # 2.5 检查本地持久化 IP 缓存 (data/ip_cache.json)
    if ip and ip not in ("AS_UNKNOWN", "unknown", "127.0.0.1"):
        try:
            cache = ip_cache if ip_cache is not None else load_ip_cache()
            if ip in cache and cache[ip].get("asn"):
                c_asn = cache[ip]["asn"]
                c_isp = cache[ip].get("isp") or ASN_TO_PROVIDER.get(c_asn, clean_isp)
                if c_asn and c_asn.upper() not in ("AS0", "AS_UNKNOWN", "UNKNOWN"):
                    return c_asn, c_isp
        except Exception:
            pass

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
CHECK_PROXYIP_URL = os.getenv("CHECK_PROXYIP_URL") or ""
CHECK_PROXYIP_TOKEN = (
    os.getenv("CHECK_PROXYIP_TOKEN", "").strip()
    or os.getenv("CF_CHECK_TOKEN", "").strip()
    or os.getenv("AUTH_TOKEN", "").strip()
)


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
    """安全将值转为整数，转换失败或为空时返回默认值 (兼容浮点数字符串，如 '156.4' -> 156)"""
    if value is None:
        return default
    try:
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        if not s:
            return default
        try:
            return int(s)
        except ValueError:
            return int(float(s))
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
        code = m.group(1).upper()
        if code != "AS0":
            return code
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


# 预编译 format_asn_isp 热点地址过滤与别名匹配正则
_ADDR_RE = re.compile(
    r"(?:\b(?:building|avenue|road|street|floor|suite|room|district|highway|jalan|bldg|kejizhongyi)\b|大厦|大楼|写字楼|园区|胡同|街道|号院)",
    re.IGNORECASE,
)
_ALIAS_RE = re.compile(r"\((.*?)\)")
_ALIAS_STRIP_RE = re.compile(r"\s*\(.*?\)")


@functools.lru_cache(maxsize=4096)
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

    if suffix and _ADDR_RE.search(suffix):
        suffix = ""
    if clean_i and _ADDR_RE.search(clean_i):
        clean_i = ""

    # 提取 suffix 中已有的别名括号内容，避免多轮调用导致别名丢失或嵌套
    existing_aliases = _ALIAS_RE.findall(suffix)
    existing_alias = " ".join(a.strip() for a in existing_aliases if a.strip())
    if existing_aliases:
        suffix = _ALIAS_STRIP_RE.sub("", suffix).strip()

    # 权威单一真相源 (SSOT) 优先：若在已收录权威字典中，采用权威统一名称
    auth_isp = ASN_TO_PROVIDER.get(code, "")
    if auth_isp:
        candidate_alias = clean_i or existing_alias or suffix
        cand_aliases = _ALIAS_RE.findall(candidate_alias)
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
    """格式化缓冲标签，带新进缓冲与恢复健康动态"""
    m_str = f"<b>{marked}</b>" if bold else str(marked)
    z_str = "<b>0</b>" if bold else "0"
    if marked <= 0:
        if buf_rec > 0:
            return f" · ⚠️ {z_str} 缓冲 [{buf_rec} 恢复]"
        return ""
    changes = []
    if buf_new > 0:
        changes.append(f"+{buf_new} 新进")
    if buf_rec > 0:
        changes.append(f"{buf_rec} 恢复")
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
RE_SERVER_CF = re.compile(rb"(?im)^server:\s*[^\r\n]*\bcloudflare\b")
RE_CF_RAY = re.compile(rb"(?im)^cf-ray:\s*([a-f0-9]+-[a-z0-9]+)")
RE_CF_1034 = re.compile(rb"(?i)error code:\s*1034\b")
RE_NON_CF_FASTLY = re.compile(rb"(?i)fastly\.com")
RE_NON_CF_AKAMAI = re.compile(rb"(?im)^server:\s*AkamaiGHost\b")



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
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)


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
    "休斯顿": "美国", "盐湖城": "美国", "檀香山": "美国", "Buffalo": "美国", "Salt Lake City": "美国",
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
    "德黑兰": "伊朗", "Tehran": "伊朗",
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
    "乌兹别克斯坦": "🇺🇿", "津巴布韦": "🇿🇼", "阿塞拜疆": "🇦🇿", "埃及": "🇪🇬", "叙利亚": "🇸🇾",
    "伊朗": "🇮🇷",
}

COUNTRY_TO_CODE = {
    "美国": "US", "德国": "DE", "荷兰": "NL", "瑞典": "SE", "新加坡": "SG",
    "日本": "JP", "英国": "GB", "芬兰": "FI", "香港": "HK", "法国": "FR",
    "波兰": "PL", "爱沙尼亚": "EE", "拉脱维亚": "LV", "瑞士": "CH", "立陶宛": "LT",
    "西班牙": "ES", "加拿大": "CA", "奥地利": "AT", "保加利亚": "BG", "捷克": "CZ",
    "韩国": "KR", "印度": "IN", "意大利": "IT", "俄罗斯": "RU", "土耳其": "TR",
    "台湾": "TW", "澳大利亚": "AU", "丹麦": "DK", "罗马尼亚": "RO", "哈萨克斯坦": "KZ",
    "巴西": "BR", "挪威": "NO", "比利时": "BE", "亚美尼亚": "AM", "冰岛": "IS",
    "以色列": "IL", "爱尔兰": "IE", "阿尔巴尼亚": "AL", "孟加拉国": "BD", "斯洛伐克": "SK",
    "塞浦路斯": "CY", "吉尔吉斯斯坦": "KG", "格鲁吉亚": "GE", "墨西哥": "MX", "智利": "CL",
    "阿根廷": "AR", "哥伦比亚": "CO", "秘鲁": "PE", "南非": "ZA", "阿联酋": "AE",
    "科威特": "KW", "卡塔尔": "QA", "沙特阿拉伯": "SA", "希腊": "GR", "匈牙利": "HU",
    "塞尔维亚": "RS", "克罗地亚": "HR", "葡萄牙": "PT", "乌克兰": "UA", "泰国": "TH",
    "菲律宾": "PH", "马来西亚": "MY", "印度尼西亚": "ID", "越南": "VN", "新西兰": "NZ",
    "中国": "CN", "澳门": "MO", "阿曼": "OM", "斯洛文尼亚": "SI", "白俄罗斯": "BY",
    "厄瓜多尔": "EC", "尼日利亚": "NG", "北马其顿": "MK", "哥斯达黎加": "CR", "多米尼加": "DO",
    "尼泊尔": "NP", "巴基斯坦": "PK", "波多黎各": "PR", "肯尼亚": "KE", "黎巴嫩": "LB",
    "乌兹别克斯坦": "UZ", "津巴布韦": "ZW", "阿塞拜疆": "AZ", "埃及": "EG", "叙利亚": "SY",
    "伊朗": "IR", "其他地区": "OTHER",
}

CODE_TO_COUNTRY = {v: k for k, v in COUNTRY_TO_CODE.items() if k != "其他地区"}
CODE_TO_COUNTRY["GB"] = "英国"

# 权威 ISO 3166-1 alpha-2 标准国家/地区代码完整全集 (249 项官方 ISO 代码 + XK 科索沃 + EU 欧盟网络区域)
ISO_3166_COUNTRY_CODES: frozenset[str] = frozenset({
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "EU", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE",
    "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK",
    "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE",
    "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB",
    "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
    "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF",
    "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU",
    "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR",
    "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN",
    "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG",
    "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW"
})

ENGLISH_COUNTRY_TO_CODE: dict[str, str] = {
    "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US",
    "UNITED KINGDOM": "GB", "GREAT BRITAIN": "GB", "UK": "GB",
    "CHINA": "CN", "PEOPLE'S REPUBLIC OF CHINA": "CN",
    "HONG KONG": "HK", "TAIWAN": "TW", "MACAO": "MO", "MACAU": "MO",
    "JAPAN": "JP", "SOUTH KOREA": "KR", "KOREA": "KR", "REPUBLIC OF KOREA": "KR",
    "SINGAPORE": "SG", "GERMANY": "DE", "FRANCE": "FR", "NETHERLANDS": "NL",
    "RUSSIA": "RU", "RUSSIAN FEDERATION": "RU", "CANADA": "CA", "AUSTRALIA": "AU",
    "INDIA": "IN", "BRAZIL": "BR", "ITALY": "IT", "SPAIN": "ES",
    "SWITZERLAND": "CH", "SWEDEN": "SE", "NORWAY": "NO", "FINLAND": "FI",
    "POLAND": "PL", "TURKEY": "TR", "TURKIYE": "TR",
    "UNITED ARAB EMIRATES": "AE", "UAE": "AE",
    "VIETNAM": "VN", "THAILAND": "TH", "MALAYSIA": "MY", "INDONESIA": "ID", "PHILIPPINES": "PH",
    "UKRAINE": "UA", "CZECH REPUBLIC": "CZ", "CZECHIA": "CZ", "AUSTRIA": "AT",
    "BELGIUM": "BE", "DENMARK": "DK", "IRELAND": "IE", "NEW ZEALAND": "NZ",
    "PORTUGAL": "PT", "GREECE": "GR", "HUNGARY": "HU", "ROMANIA": "RO",
    "BULGARIA": "BG", "SLOVAKIA": "SK", "SLOVENIA": "SI", "CROATIA": "HR",
    "SERBIA": "RS", "ESTONIA": "EE", "LATVIA": "LV", "LITHUANIA": "LT",
    "ICELAND": "IS", "ISRAEL": "IL", "SOUTH AFRICA": "ZA", "MEXICO": "MX",
    "ARGENTINA": "AR", "CHILE": "CL", "COLOMBIA": "CO", "PERU": "PE",
    "SAUDI ARABIA": "SA", "QATAR": "QA", "KUWAIT": "KW", "OMAN": "OM",
    "BAHRAIN": "BH", "EGYPT": "EG", "PAKISTAN": "PK", "BANGLADESH": "BD",
    "KAZAKHSTAN": "KZ", "UZBEKISTAN": "UZ", "GEORGIA": "GE", "ARMENIA": "AM",
    "AZERBAIJAN": "AZ", "CYPRUS": "CY", "MALTA": "MT", "LUXEMBOURG": "LU",
    "BELARUS": "BY", "MOLDOVA": "MD", "ALBANIA": "AL", "BOSNIA AND HERZEGOVINA": "BA",
    "NORTH MACEDONIA": "MK", "MONTENEGRO": "ME",
    "GUERNSEY": "GG", "ISLE OF MAN": "IM", "JERSEY": "JE", "EUROPEAN UNION": "EU",
}


def get_country_code(country_name: str) -> str:
    """获取国家或地区的标准 ISO 3166-1 alpha-2 两位大写代码（支持两位代码本身、中英文国名转换，非标准代码如 UK 强制归一为 GB，无效代码返回空串）"""
    clean_name = (country_name or "").strip()
    if not clean_name:
        return ""
    uname = clean_name.upper()
    # 1. 兼容性非标准二位代码强制修正为官方 ISO 3166-1 代码 (UK -> GB)
    if uname == "UK":
        return "GB"
    # 2. 若本身已是合法受支持的两位 ISO 3166-1 代码，直接返回
    if len(uname) == 2 and uname in ISO_3166_COUNTRY_CODES:
        return uname
    # 3. 英文国名全称转换
    if uname in ENGLISH_COUNTRY_TO_CODE:
        code = ENGLISH_COUNTRY_TO_CODE[uname]
        return "GB" if code == "UK" else code
    # 4. 中文国名转换
    if clean_name in COUNTRY_TO_CODE:
        code = COUNTRY_TO_CODE[clean_name]
        return "GB" if code == "UK" else code
    # 5. Emoji 国旗转换
    flag = COUNTRY_FLAGS.get(clean_name, "")
    if len(flag) == 2:
        try:
            cand = "".join(chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag).upper()
            if cand == "UK":
                return "GB"
            if cand in ISO_3166_COUNTRY_CODES:
                return cand
        except Exception:
            pass
    return ""


@functools.lru_cache(maxsize=2048)
def extract_country(cf_location: str | None, colo: str | None) -> str:
    """
    根据 cf_location (如 '北美洲 · 美国 · 洛杉矶') 或 Cloudflare colo 机房三字代码 (如 'LAX')
    提取标准化的国家/地区名称。
    """
    cf_location = (cf_location or "").strip()
    colo = (colo or "").strip().upper()

    def _normalize_name(name: str) -> str:
        name = name.strip()
        uname = name.upper()
        if "香港" in name or uname in ("HK", "HONG KONG"):
            return "香港"
        if "台湾" in name or uname in ("TW", "TAIWAN"):
            return "台湾"
        if "澳门" in name or uname in ("MO", "MACAO", "MACAU"):
            return "澳门"
        if uname in CODE_TO_COUNTRY:
            return CODE_TO_COUNTRY[uname]
        if name in ("捷克共和国", "捷克", "Czechia", "Czech Republic"):
            return "捷克"
        if name in ("俄罗斯联邦", "俄罗斯", "Russia", "Russian Federation"):
            return "俄罗斯"
        if name in ("阿拉伯联合酋长国", "阿联酋", "UAE", "United Arab Emirates"):
            return "阿联酋"
        if name in ("US", "USA", "United States"):
            return "美国"
        if "巴基斯坦" in name:
            return "巴基斯坦"
        if "多明尼加" in name or "多米尼加" in name:
            return "多米尼加"
        return name

    parts = [p.strip() for p in cf_location.split("·") if p.strip()] if cf_location else []

    # 1. 优先从右向左逐段探测已知国家/地区（兼容 "北美洲 · 美国 · 洛杉矶" 与 "California · Los Angeles · 美国"）
    for p in reversed(parts):
        n = _normalize_name(p)
        if n in COUNTRY_FLAGS or n in COUNTRY_TO_CODE:
            return n

    # 2. 若无直接国家匹配，探测是否为已知城市名并反查所属国家
    for p in reversed(parts):
        if p in CITY_TO_COUNTRY:
            return CITY_TO_COUNTRY[p]

    # 3. cf_location 文本全词匹配已知城市名
    if cf_location:
        for city, c in CITY_TO_COUNTRY.items():
            if city in cf_location:
                return c

    # 4. 回退到 Cloudflare colo 机房三字代码映射
    if colo in COLO_TO_COUNTRY:
        return COLO_TO_COUNTRY[colo]

    # 5. 非大洲名称的两段式/单段式兜底
    for p in reversed(parts):
        n = _normalize_name(p)
        if n and n not in ("北美洲", "欧洲", "亚洲", "大洋洲", "南美洲", "非洲"):
            return n

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

# ISO 3166-1 alpha-2 全量国家/地区标准中文映射表
COUNTRY_NAME_MAP: dict[str, str] = {
    # 亚洲 (Asia)
    "CN": "中国", "HK": "香港", "MO": "澳门", "TW": "台湾",
    "JP": "日本", "KR": "韩国", "KP": "朝鲜", "MN": "蒙古",
    "SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
    "ID": "印度尼西亚", "PH": "菲律宾", "MM": "缅甸", "KH": "柬埔寨",
    "LA": "老挝", "BN": "文莱", "TL": "东帝汶",
    "IN": "印度", "PK": "巴基斯坦", "BD": "孟加拉国", "LK": "斯里兰卡",
    "NP": "尼泊尔", "BT": "不丹", "MV": "马尔代夫",
    "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "KG": "吉尔吉斯斯坦",
    "TJ": "塔吉克斯坦", "TM": "土库曼斯坦",
    "AF": "阿富汗", "IR": "伊朗", "IQ": "伊拉克", "SY": "叙利亚",
    "LB": "黎巴嫩", "IL": "以色列", "PS": "巴勒斯坦", "JO": "约旦",
    "SA": "沙特阿拉伯", "YE": "也门", "OM": "阿曼", "AE": "阿联酋",
    "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "CY": "塞浦路斯",
    "TR": "土耳其", "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "IO": "英属印度洋领地", "CC": "科科斯群岛", "CX": "圣诞岛",

    # 欧洲 (Europe)
    "RU": "俄罗斯", "UA": "乌克兰", "BY": "白俄罗斯", "MD": "摩尔多瓦",
    "GB": "英国", "UK": "英国", "IE": "爱尔兰",
    "FR": "法国", "DE": "德国", "NL": "荷兰", "BE": "比利时",
    "LU": "卢森堡", "MC": "摩纳哥",
    "PL": "波兰", "CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利",
    "AT": "奥地利", "CH": "瑞士", "LI": "列支敦士登",
    "EE": "爱沙尼亚", "LV": "拉脱维亚", "LT": "立陶宛",
    "ES": "西班牙", "PT": "葡萄牙", "AD": "安道尔", "GI": "直布罗陀",
    "IT": "意大利", "VA": "梵蒂冈", "SM": "圣马力诺", "MT": "马耳他",
    "GR": "希腊", "AL": "阿尔巴尼亚", "MK": "北马其顿", "BG": "保加利亚",
    "RO": "罗马尼亚", "RS": "塞尔维亚", "ME": "黑山", "BA": "波黑",
    "HR": "克罗地亚", "SI": "斯洛文尼亚", "XK": "科索沃",
    "NO": "挪威", "SE": "瑞典", "FI": "芬兰", "DK": "丹麦",
    "IS": "冰岛", "FO": "法罗群岛", "AX": "奥兰群岛", "SJ": "斯瓦尔巴群岛",
    "GG": "根西岛", "JE": "泽西岛", "IM": "马恩岛", "EU": "欧盟",

    # 北美洲 (North America)
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "GL": "格陵兰", "BM": "百慕大",
    "PA": "巴拿马", "CR": "哥斯达黎加", "NI": "尼加拉瓜", "HN": "洪都拉斯",
    "SV": "萨尔瓦多", "GT": "危地马拉", "BZ": "伯利兹",
    "CU": "古巴", "JM": "牙买加", "HT": "海地", "DO": "多米尼加",
    "PR": "波多黎各", "BS": "巴哈马", "TT": "特立尼达和多巴哥",
    "BB": "巴巴多斯", "LC": "圣卢西亚", "CW": "库拉索", "AW": "阿鲁巴",
    "KY": "开曼群岛", "VG": "英属维尔京群岛", "VI": "美属维尔京群岛",
    "AG": "安提瓜和巴布达", "DM": "多米尼克", "GD": "格林纳达",
    "KN": "圣基茨和尼维斯", "VC": "圣文森特和格林纳丁斯", "TC": "特克斯和凯科斯群岛",
    "SX": "荷属圣马丁", "MF": "法属圣马丁", "BL": "圣巴泰勒米", "PM": "圣皮埃尔和密克隆",
    "AI": "安圭拉", "MS": "蒙特塞拉特", "BQ": "荷兰加勒比区",
    "GP": "瓜德罗普", "MQ": "马提尼克", "UM": "美国本土外小岛屿",

    # 南美洲 (South America)
    "BR": "巴西", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "PE": "秘鲁", "VE": "委内瑞拉", "EC": "厄瓜多尔", "BO": "玻利维亚",
    "PY": "巴拉圭", "UY": "乌拉圭", "GY": "圭亚那", "SR": "苏里南",
    "GF": "法属圭亚那", "FK": "福克兰群岛",

    # 大洋洲 (Oceania)
    "AU": "澳大利亚", "NZ": "新西兰", "PG": "巴布亚新几内亚",
    "FJ": "斐济", "SB": "所罗门群岛", "VU": "瓦努阿图", "NC": "新喀里多尼亚",
    "PF": "法属波利尼西亚", "GU": "关岛", "MP": "北马里亚纳群岛",
    "WS": "萨摩亚", "AS": "美属萨摩亚", "TO": "汤加", "FM": "密克罗尼西亚",
    "PW": "帕劳", "MH": "马绍尔群岛", "KI": "基里巴斯", "NR": "瑙鲁",
    "TV": "图瓦卢", "CK": "库克群岛", "NU": "纽埃", "TK": "托克劳",
    "WF": "瓦利斯和富图纳",

    # 非洲 (Africa)
    "EG": "埃及", "ZA": "南非", "NG": "尼日利亚", "KE": "肯尼亚",
    "ET": "埃塞俄比亚", "GH": "加纳", "TZ": "坦桑尼亚", "UG": "乌干达",
    "DZ": "阿尔及利亚", "MA": "摩洛哥", "TN": "突尼斯", "LY": "利比亚",
    "SD": "苏丹", "SS": "南苏丹", "SO": "索马里", "DJ": "吉布提",
    "ER": "厄立特里亚", "AO": "安哥拉", "ZM": "赞比亚", "ZW": "津巴布韦",
    "BW": "博茨瓦纳", "NA": "纳米比亚", "MZ": "莫桑比克", "MW": "马拉维",
    "MG": "马达加斯加", "MU": "毛里求斯", "SC": "塞舌尔", "RW": "卢旺达",
    "BI": "布隆迪", "CM": "喀麦隆", "GA": "加蓬", "CG": "刚果共和国",
    "CD": "刚果民主共和国", "CF": "中非", "TD": "乍得", "NE": "尼日尔",
    "ML": "马里", "SN": "塞内加尔", "CI": "科特迪瓦", "BF": "布基纳法索",
    "GN": "几内亚", "BJ": "贝宁", "TG": "多哥", "SL": "塞拉利昂",
    "LR": "利比里亚", "MR": "毛里塔尼亚", "GM": "冈比亚", "GW": "几内亚比绍",
    "CV": "佛得角", "ST": "圣多美和普林西比", "GQ": "赤道几内亚",
    "KM": "科摩罗", "LS": "莱索托", "SZ": "斯威士兰", "RE": "留尼汪",
    "YT": "马约特", "SH": "圣赫勒拿", "EH": "西撒哈拉",

    # 南极与极地岛屿 (Polar & Remote Islands)
    "AQ": "南极洲", "BV": "布韦岛", "GS": "南乔治亚和南桑威奇群岛",
    "HM": "赫德岛和麦克唐纳群岛", "NF": "诺福克岛", "PN": "皮特凯恩群岛",
    "TF": "法属南部领地",
}

# 确保双向对照表完整对齐
CODE_TO_COUNTRY.update(COUNTRY_NAME_MAP)
COUNTRY_TO_CODE.update({v: k for k, v in COUNTRY_NAME_MAP.items() if k != "UK"})
COUNTRY_TO_CODE.update({
    "中国香港": "HK",
    "中国台湾": "TW",
    "中国澳门": "MO",
    "香港特别行政区": "HK",
    "澳门特别行政区": "MO",
})


@functools.lru_cache(maxsize=512)
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
    "first_seen",
    "source",
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

    # net_type：优先依据自治系统权威研判 (SSOT) 实时核算，杜绝陈旧属性污染；无有效 ASN 时继承合规值，完全未查询则留空
    curr_nt = str(r_dict.get("net_type") or "").strip().lower()
    eff_asn_code = _extract_asn_code(clean_asn_num, isp_name)
    if eff_asn_code:
        net_type_val = classify_asn(eff_asn_code, isp_name)
    elif curr_nt in VALID_NET_TYPES:
        net_type_val = curr_nt
    else:
        net_type_val = ""

    raw_egress = str(r_dict.get("egress_ip") or r_dict.get("resolved_ip") or r_dict.get("exit_ip") or "").strip()
    raw_exit_v6 = str(r_dict.get("exit_ipv6") or "").strip()
    raw_host = str(r_dict.get("host") or "").strip()

    cand_ips = []
    for cand in (r_dict.get("clientIps"), r_dict.get("client_ips"), raw_egress, raw_exit_v6):
        if cand:
            cand_ips.extend(extract_ips(cand))

    seen_ips = set()
    unique_exit_ips = []
    for ip_item in cand_ips:
        if ip_item not in seen_ips:
            seen_ips.add(ip_item)
            unique_exit_ips.append(ip_item)

    v4_ips = [cip for cip in unique_exit_ips if is_valid_ipv4(cip)]
    v6_ips = [cip for cip in unique_exit_ips if is_valid_ipv6(cip)]
    client_ipv4 = v4_ips[0] if v4_ips else ""
    client_ipv6 = v6_ips[0] if v6_ips else ""
    client_ip = client_ipv4 or client_ipv6 or raw_egress or raw_host
    client_ips = unique_exit_ips if unique_exit_ips else ([client_ip] if client_ip else [])
    dual_stack = bool(client_ipv4 and client_ipv6)

    return {
        "proxy": r_dict.get("url") or "",
        "protocol": proto,
        "ip": r_dict.get("host") or "",
        "port": safe_int(r_dict.get("port"), 0),
        "clientIp": client_ip,
        "clientIps": client_ips,
        "clientIpv4": client_ipv4,
        "clientIpv6": client_ipv6,
        "dual_stack": dual_stack,
        "country": c_code,
        "country_name": c_name,
        "country_cn": c_name,
        "country_emoji": c_emoji,
        "asn": clean_asn_num,
        "asOrganization": isp_name,
        "isp": isp_name,
        "net_type": net_type_val,
        "source": str(r_dict.get("source") or "").strip(),
    }


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
        asn_str = row_dict.get("asn", "")
        isp_str = row_dict.get("isp", "")
        if asn_str or isp_str:
            row_dict["net_type"] = classify_asn(asn_str, isp_str) or row_dict.get("net_type", "")
        else:
            row_dict.setdefault("net_type", row_dict.get("net_type", ""))
        row_dict.setdefault("first_seen", row_dict.get("first_seen", "") or LEGACY_DEFAULT_FIRST_SEEN)
        row_dict.setdefault("source", str(row_dict.get("source") or "").strip())

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
        lines = [f"# {title} - {len(items)} 个\n"]
        for _, _, url, _ in items:
            lines.append(f"{url}\n")
        atomic_write_text(txt_filepath, "".join(lines))
        active_files.add(txt_fname)

        # 2. 保存纯净单协议结构化 CSV（原子写入）
        csv_fname = f"{safe_proto}.csv"
        csv_filepath = os.path.join(output_dir, csv_fname)
        with atomic_writer(csv_filepath, encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PROXY_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for _, _, _, r_dict in items:
                writer.writerow(r_dict)
        active_files.add(csv_fname)

        # 3. 保存标准化单协议 JSON 接口数据（原子写入，完美兼容 EDT-Toolkit / 油猴脚本）
        json_fname = f"{safe_proto}.json"
        json_filepath = os.path.join(output_dir, json_fname)
        json_list = [format_proxy_json_item(r_dict) for _, _, _, r_dict in items]
        atomic_write_json(json_filepath, json_list)
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
        asn_str = row_dict.get("asn", "")
        isp_str = row_dict.get("isp", "")
        if asn_str or isp_str:
            row_dict["net_type"] = classify_asn(asn_str, isp_str) or row_dict.get("net_type", "")
        else:
            row_dict.setdefault("net_type", row_dict.get("net_type", ""))
        row_dict.setdefault("first_seen", row_dict.get("first_seen", "") or LEGACY_DEFAULT_FIRST_SEEN)
        row_dict.setdefault("source", str(row_dict.get("source") or "").strip())

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

    with atomic_writer(csv_path, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PROXY_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in formatted_rows:
            writer.writerow(r)
    log.info("已按协议分块覆写保存 %s: %d 条质检状态记录 (无交错混杂)", csv_path, len(formatted_rows))
    return len(formatted_rows)



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


@functools.lru_cache(maxsize=4096)
def _extract_asn_code(asn_str: str | None, isp_str: str | None = "") -> str | None:
    """
    智能提取规范的 AS 编号 (如 AS4760)：
    - 支持前缀格式：AS4760、as4760、AS 4760、as 4760
    - 支持纯数字编号：4760、" 4760 "
    - 优先检查 asn_str，随后检查 isp_str
    - 严格遵循 RFC 7607 排除非路由保留编号 AS0
    """
    for s in (asn_str, isp_str):
        if not s:
            continue
        s = str(s)

        m = _ASN_WITH_PREFIX_RE.search(s)
        if m:
            num = m.group(1).lstrip("0") or "0"
            if num == "0":
                continue
            return f"AS{num}"

        m = _PURE_NUMBER_RE.match(s)
        if m:
            num = m.group(1).lstrip("0") or "0"
            if num == "0":
                continue
            return f"AS{num}"

    return None


# 注：ASN_EXACT_NET_TYPE 已全面解耦至 data/asn_database.json (asn_to_net_type)
# 并在模块初始化时（见上方）动态加载并与已知云厂商（KNOWN_CLOUD_PROVIDERS）合并，兼具核心骨干基准兜底。


def is_asn_recorded(asn_str: str | None, isp_str: str | None = "") -> bool:
    """
    判断目标节点是否免于触发『未收录 ASN 补库告警』：
    - 返回 True：该 AS 编号已被权威对照表收录（含人工裁决表、ASN 基础数据库、权威云厂商），
                 或节点本身无有效 AS 编号（含 AS0 占位符，无需作为新 ASN 告警）。
    - 返回 False：提取到了有效 AS 编号，但该编号尚未被内置库收录（提示补充）。
    注：无有效 ASN 编号时返回 True，是为避免将缺少 ASN 元数据的正常节点误报为待补充的新自治系统。
    """
    code = _extract_asn_code(asn_str, isp_str)
    if not code or code == "AS0":
        return True
    return (
        code in MANUAL_OVERRIDE_NET_TYPES
        or code in ASN_EXACT_NET_TYPE
        or code in ASN_DATABASE_ASN_TO_NET_TYPE
        or code in AUTHORITATIVE_CLOUD_ASNS
    )


def classify_asn(asn_str: str | None, isp_str: str | None = "") -> str:
    """
    根据 BGP 广播的 ASN 编号进行网络类型属性分类 (三级权威架构 Tier 1~3)：
      [Tier 1] 人工裁决表 (Manual SSOT Overrides)：针对已确证的核心专网与特例的人工高优先级裁决
      [Tier 2] 权威持久化 ASN 库 (Authoritative Local DB)：来自 4200+ 条权威 ASN 库与权威云厂商基准
      [Tier 3] 默认安全降级兜底 (Default Fallback)：其余全新未确证 ASN 一律安全降级为 datacenter 机房
    返回类型（严格对齐 ipinfo.io 业界权威五大标准网络类型）：
      - education: 高校与学术科研网
      - government: 政府政务与国家公共网
      - isp: 电信民用原生宽带
      - business: 商业固定专线、企业专网与银行金融机构
      - datacenter: 常规云主机与数据中心机房（hosting，默认）
    """
    asn_code = _extract_asn_code(asn_str, isp_str)

    # [Tier 1] 人工高优先级裁决 (最高优先级覆盖)
    if asn_code and asn_code in MANUAL_OVERRIDE_NET_TYPES:
        return MANUAL_OVERRIDE_NET_TYPES[asn_code]

    # [Tier 2] 权威精准对照表 (包含持久化 ASN 库与权威云厂商 SSOT)
    if asn_code and asn_code in ASN_EXACT_NET_TYPE:
        return ASN_EXACT_NET_TYPE[asn_code]

    # [Tier 3] 默认安全降级兜底 (Default Fallback)
    return "datacenter"


classify_asn.cache_clear = _extract_asn_code.cache_clear  # type: ignore[attr-defined]


# 全局共享优选 / 扫描优选 / 反代 ProxyIP 标准 CSV 字段定义 (SSOT)
CF_BASE_CSV_FIELDS = [
    "ip",
    "port",
    "tls",
    "delay_ms",
    "speed_kbs",
    "colo",
    "cf_location",
    "asn",
    "isp",
    "fail_count",
    "first_seen",
    "channel",
]
SCAN_CSV_FIELDS = CF_BASE_CSV_FIELDS + ["exit_ip", "exit_asn", "exit_isp", "exit_location"]
PROXYIP_CSV_FIELDS = CF_BASE_CSV_FIELDS + ["net_type", "exit_ip", "exit_ipv6", "exit_asn", "exit_isp"]

_CF_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "104.28.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
        "2a09:bac0::/29",
        "1.1.1.0/24",
        "1.0.0.0/24",
    )
)


@functools.lru_cache(maxsize=4096)
def is_cloudflare_ip(ip_str: str) -> bool:
    """判定 IP 是否属于 Cloudflare 官方 Anycast / WARP (2a09:bac0::/29, 104.28.0.0/14 等) 网段 (AS13335)"""
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(str(ip_str).strip().strip("[]"))
        return any(addr in net for net in _CF_NETWORKS)
    except Exception:
        return False


CLOUDFLARE_ASNS: frozenset[str] = frozenset({
    "AS13335",   # Cloudflare, Inc. (Primary Anycast / WARP)
    "AS209242",  # Cloudflare London, LLC / BYOIP
    "AS132892",  # Cloudflare, Inc.
    "AS394536",  # Cloudflare (CLOUDFLARENET-SFO)
    "AS395747",  # Cloudflare (CLOUDFLARENET-SFO05)
    "AS14789",   # Cloudflare, Inc.
    "AS202623",  # Cloudflare Inc (CLOUDFLARENET-CORE)
    "AS203898",  # Cloudflare, Inc.
})
_CF_NAME_RE = re.compile(r"(?<![a-z0-9])cloudflare", re.IGNORECASE)


def is_cloudflare_asn_or_isp(asn: str = "", isp: str = "") -> bool:
    """判定 ASN 或 ISP/Org 名称是否明确归属 Cloudflare 系自治系统"""
    code = _extract_asn_code(asn, isp)
    if code in CLOUDFLARE_ASNS:
        return True
    combined = f"{asn or ''} {isp or ''}".strip()
    return bool(combined and _CF_NAME_RE.search(combined))


def extract_node_host(item: dict | str) -> str:
    """从节点字典或 URL 中提取标准化的入口 host/IP"""
    if isinstance(item, str):
        raw = item.strip()
        m = re.match(r"^[a-z0-9+.-]+://(?:[^/@]+@)?(\[[^\]]+\]|[^:/?#]+)", raw, re.IGNORECASE)
        return (m.group(1) if m else raw.split(":")[0]).strip().strip("[]")
    if not isinstance(item, dict):
        return ""
    host = str(item.get("ip") or item.get("host") or "").strip().strip("[]")
    if not host and item.get("url"):
        m = re.match(r"^[a-z0-9+.-]+://(?:[^/@]+@)?(\[[^\]]+\]|[^:/?#]+)", str(item["url"]).strip(), re.IGNORECASE)
        if m:
            host = m.group(1).strip().strip("[]")
    return host


def is_cloudflare_ingress(
    host_or_ip: str = "",
    asn: str = "",
    isp: str = "",
    ip_cache: dict | None = None,
    resolved_ip: str = "",
    trusts_asn_label: bool = True,
) -> bool:
    """
    判定节点【入口】是否属于 Cloudflare 系网络（CIDR + ip_cache BGP + 入口 ASN/ISP）：
    - 若入口 IP/解析 IP 命中 Cloudflare CIDR (_CF_NETWORKS)，直接判为 True；
    - 若 ip_cache 已记录该入口 IP 的非 Cloudflare BGP ASN，以真实 BGP 为准返回 False（避免第三方 VPS + WARP 出站被误标连坐）；
    - 否则依据缓存 BGP ASN 或可信入口 ASN/ISP 标签判定是否归属 Cloudflare。
    """
    host = str(host_or_ip or "").strip().strip("[]")
    res_ip = str(resolved_ip or "").strip().strip("[]")
    if host and is_cloudflare_ip(host):
        return True
    if res_ip and is_cloudflare_ip(res_ip):
        return True

    if isinstance(ip_cache, dict):
        c_entry = None
        for key in (host, host.lower(), res_ip):
            if key and isinstance(ip_cache.get(key), dict):
                c_entry = ip_cache[key]
                break
        if isinstance(c_entry, dict):
            c_res = str(c_entry.get("resolved_ip") or "").strip().strip("[]")
            if c_res and is_cloudflare_ip(c_res):
                return True
            c_asn = _extract_asn_code(c_entry.get("asn"), c_entry.get("isp"))
            c_isp = str(c_entry.get("isp") or "").strip()
            if not c_asn and c_res and isinstance(ip_cache.get(c_res), dict):
                r_entry = ip_cache[c_res]
                c_asn = _extract_asn_code(r_entry.get("asn"), r_entry.get("isp"))
                c_isp = str(r_entry.get("isp") or "").strip() or c_isp
            if c_asn:
                return is_cloudflare_asn_or_isp(c_asn, c_isp)
            if c_isp and is_cloudflare_asn_or_isp("", c_isp):
                return True

    if trusts_asn_label and is_cloudflare_asn_or_isp(asn, isp):
        return True
    return False


def is_cloudflare_node(
    item: dict | str,
    ip_cache: dict | None = None,
    *,
    trusts_asn_label: bool | None = None,
) -> bool:
    """
    统一判定任意池节点 (proxies / cf_ips / scan_ips / proxyip) 入口是否属于 Cloudflare 系。
    对携带独立隧道出口 (egress_ip != host) 的通用代理或走 WARP 出站的第三方 ProxyIP/scan_ips，
    仅核验入口本身，不因 WARP 出口为 AS13335 而误伤第三方入口节点；
    传入 trusts_asn_label=False 时仅依据 CIDR / ip_cache / resolved_ip 确定性拦截，
    用于历史加载与初采阶段放行未缓存嫌疑节点至后续 BGP 纠偏。
    """
    if isinstance(item, str):
        host = extract_node_host(item)
        eff_trust = True if trusts_asn_label is None else bool(trusts_asn_label)
        return is_cloudflare_ingress(host, ip_cache=ip_cache, trusts_asn_label=eff_trust)
    if not isinstance(item, dict):
        return False

    host = extract_node_host(item)
    res_ip = str(item.get("resolved_ip") or "").strip().strip("[]")
    is_proxy_row = "url" in item or "proto" in item or "egress_ip" in item
    egress = str(item.get("egress_ip") or "").strip().strip("[]")
    default_trust = not (is_proxy_row and egress and egress != host)
    eff_trust = default_trust if trusts_asn_label is None else (default_trust and bool(trusts_asn_label))
    return is_cloudflare_ingress(
        host,
        asn=str(item.get("asn") or ""),
        isp=str(item.get("isp") or ""),
        ip_cache=ip_cache,
        resolved_ip=res_ip,
        trusts_asn_label=eff_trust,
    )


def rescue_mislabeled_cloudflare_rows(
    rows: list[dict],
    ip_cache: dict | None = None,
    persist: bool = True,
    cache_path: str = "",
) -> tuple[dict[str, dict], int]:
    """
    对未命中 Cloudflare CIDR、且尚未入缓存却在文本中被标为 Cloudflare ASN/ISP 的入口 IP，
    批量反查其真实 BGP 归属：将第三方机房+WARP 出站被上游误标为 Cloudflare London LLC/AS13335 的节点自动纠正并保留。
    返回: (更新后的 ip_cache, 纠正还原的节点数)
    """
    cache = ip_cache if isinstance(ip_cache, dict) else load_ip_cache(filepath=cache_path)
    if not rows:
        return cache, 0

    suspects: list[str] = []
    seen: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        host = extract_node_host(r)
        res_ip = str(r.get("resolved_ip") or "").strip().strip("[]")
        lookup_ip = host if is_valid_public_ip(host) else (res_ip if is_valid_public_ip(res_ip) else "")
        if not lookup_ip or is_cloudflare_ip(lookup_ip) or (host and is_cloudflare_ip(host)):
            continue
        is_proxy_row = "url" in r or "proto" in r or "egress_ip" in r
        egress = str(r.get("egress_ip") or "").strip().strip("[]")
        if is_proxy_row and egress and egress != host:
            continue
        cached = (
            cache.get(lookup_ip) if isinstance(cache.get(lookup_ip), dict)
            else (cache.get(host) if host and isinstance(cache.get(host), dict) else None)
        )
        if isinstance(cached, dict) and _extract_asn_code(cached.get("asn"), cached.get("isp")):
            continue
        if is_cloudflare_asn_or_isp(str(r.get("asn") or ""), str(r.get("isp") or "")):
            if lookup_ip not in seen:
                seen.add(lookup_ip)
                suspects.append(lookup_ip)

    resolved_map: dict[str, tuple[str, str]] = {}
    if suspects:
        try:
            resolved_map = resolve_asn_batch_online(suspects, persist=persist, cache_path=cache_path) or {}
            if persist:
                disk_cache = load_ip_cache(filepath=cache_path)
                if isinstance(disk_cache, dict):
                    for k, v in disk_cache.items():
                        if isinstance(v, dict):
                            cache[k] = v
            for tip, (r_asn, r_isp) in resolved_map.items():
                c_code = _extract_asn_code(r_asn, r_isp)
                if c_code:
                    prev = cache.get(tip) if isinstance(cache.get(tip), dict) else {}
                    cache[tip] = {
                        **prev,
                        "asn": c_code,
                        "isp": r_isp or ASN_TO_PROVIDER.get(c_code, "") or prev.get("isp", ""),
                        "net_type": classify_asn(c_code, r_isp) or prev.get("net_type", ""),
                    }
        except Exception as e:
            log.warning("批量核验疑似 Cloudflare 误标节点真实 BGP 失败: %s", e)

    rescued = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        host = extract_node_host(r)
        res_ip = str(r.get("resolved_ip") or "").strip().strip("[]")
        lookup_ip = host if is_valid_public_ip(host) else (res_ip if is_valid_public_ip(res_ip) else host)
        if not lookup_ip or is_cloudflare_ip(lookup_ip) or (host and is_cloudflare_ip(host)):
            continue
        if not is_cloudflare_asn_or_isp(str(r.get("asn") or ""), str(r.get("isp") or "")):
            continue
        c_entry = (
            cache.get(lookup_ip) if isinstance(cache.get(lookup_ip), dict)
            else (cache.get(host) if host and isinstance(cache.get(host), dict) else None)
        )
        real_asn, real_isp = ("", "")
        if isinstance(c_entry, dict):
            real_asn = _extract_asn_code(c_entry.get("asn"), c_entry.get("isp"))
            real_isp = str(c_entry.get("isp") or "").strip()
        elif lookup_ip in resolved_map:
            raw_a, raw_i = resolved_map[lookup_ip]
            real_asn = _extract_asn_code(raw_a, raw_i)
            real_isp = str(raw_i or "").strip()
        if real_asn and not is_cloudflare_asn_or_isp(real_asn, real_isp):
            std_isp = ASN_TO_PROVIDER.get(real_asn) or real_isp
            r["asn"] = format_asn_isp(real_asn, std_isp)
            r["isp"] = std_isp
            rescued += 1

    if rescued > 0:
        log.info("【BGP 纠偏】从上游误标 Cloudflare 的节点中成功还原 %d 条第三方入口真实 ASN/ISP", rescued)
    return cache, rescued


def resolve_node_exit_and_net_type(
    item: dict,
    ip_cache: dict | None = None,
) -> tuple[bool, str, str, str]:
    """
    全链路统一的节点出口画像与网络属性裁决函数 (SSOT)：
    严格遵循【出口即正义 + 自治系统三级权威库实时核算优先于缓存旧标签】准则：
    1. 校验并提取合法出口 IP (自动剔除 '0' 等非法占位串)。
    2. 解析真实出口自治域 (exit_code, exit_isp)：
       - 优先取显式有效 exit_asn / exit_isp；
       - 若出口 IP 命中 Cloudflare 官方 Anycast / WARP 网段 (如 2a09:bac0::/29)，直接锁定为 AS13335 Cloudflare；
       - 其次查 ip_cache 中出口 IP 关联的 ASN 并经 classify_asn 实时核算（绝不盲信缓存中的陈旧 net_type 字符串）；
       - 若单跳直连 (exit_ip == ip)，复用入口有效 ASN；
       - 兼容旧版 15 列 proxyip.csv（无 exit_asn 列）平滑迁移：若原记录无 exit_asn 键且原 asn 为非机房，将其迁移为出口 ASN。
    3. 裁决网络类型与归属池：
       - 若已具备真实出口 IP：严格按出口网络类型裁决（无有效出口 ASN 时辅以缓存无 ASN 标签或安全降级为 datacenter）；
       - 若尚未探测出口 IP：按入口有效 ASN / 缓存 / 合法存量标签兜底。
    返回: (is_proxyip, effective_net_type, resolved_exit_code, resolved_exit_isp)
    """
    ip = str(item.get("ip") or "").strip()
    cand_exits = extract_ips([item.get("exit_ip"), item.get("exit_ipv6")])
    v4_exits = [cip for cip in cand_exits if is_valid_ipv4(cip)]
    v6_exits = [cip for cip in cand_exits if is_valid_ipv6(cip)]
    exit_v4 = v4_exits[0] if v4_exits else ""
    exit_v6 = v6_exits[0] if v6_exits else ""
    primary_exit = exit_v4 or exit_v6

    raw_exit_asn = str(item.get("exit_asn") or "").strip()
    raw_exit_isp = str(item.get("exit_isp") or "").strip()
    exit_code = _extract_asn_code(raw_exit_asn, raw_exit_isp)

    raw_ing_asn = str(item.get("asn") or "").strip()
    raw_ing_isp = str(item.get("isp") or "").strip()
    ing_code = _extract_asn_code(raw_ing_asn, raw_ing_isp)

    if primary_exit and not exit_code:
        if any(is_cloudflare_ip(ep) for ep in (exit_v4, exit_v6) if ep):
            exit_code = "AS13335"
            if not raw_exit_isp:
                raw_exit_isp = ASN_TO_PROVIDER.get("AS13335", "Cloudflare")

    cache_exit_nt = ""
    if primary_exit and not exit_code and ip_cache:
        for ep in (exit_v4, exit_v6):
            if ep and ep in ip_cache and isinstance(ip_cache[ep], dict):
                ent = ip_cache[ep]
                c_code = _extract_asn_code(ent.get("asn"), ent.get("isp"))
                if c_code:
                    exit_code = c_code
                    if not raw_exit_isp:
                        raw_exit_isp = str(ent.get("isp") or "").strip()
                    break
                ent_nt = str(ent.get("net_type") or "").strip().lower()
                if not cache_exit_nt and ent_nt in VALID_NET_TYPES:
                    cache_exit_nt = ent_nt

    if primary_exit and not exit_code:
        if primary_exit == ip and ing_code:
            exit_code = ing_code
            if not raw_exit_isp:
                raw_exit_isp = raw_ing_isp
        elif ("exit_asn" not in item or not str(item.get("exit_asn") or "").strip()) and ing_code:
            # 兼容旧版 15 列 proxyip.csv 平滑升级与空 exit_asn 节点平滑继承：若原记录无有效 exit_asn 且原 asn 为非机房，将其作为出口 ASN
            if classify_asn(ing_code, raw_ing_isp) != "datacenter":
                exit_code = ing_code
                if not raw_exit_isp:
                    raw_exit_isp = raw_ing_isp

    if exit_code and not raw_exit_isp:
        raw_exit_isp = ASN_TO_PROVIDER.get(exit_code) or ASN_DATABASE_ASN_TO_ISP.get(exit_code) or ""

    # 1. 已具备真实出口 IP 或明确出口 ASN：严格按出口裁决
    if exit_code:
        exit_nt = classify_asn(exit_code, raw_exit_isp)
        return (exit_nt != "datacenter"), exit_nt, exit_code, raw_exit_isp

    if primary_exit:
        if cache_exit_nt:
            return (cache_exit_nt != "datacenter"), cache_exit_nt, "", raw_exit_isp
        return False, "datacenter", "", raw_exit_isp

    # 2. 尚未探测出口 IP：按入口有效 ASN -> 缓存 -> 存量合法标签兜底
    cache_ing_nt = ""
    if not ing_code and ip and ip_cache and ip in ip_cache and isinstance(ip_cache[ip], dict):
        ent = ip_cache[ip]
        c_code = _extract_asn_code(ent.get("asn"), ent.get("isp"))
        if c_code:
            ing_code = c_code
            if not raw_ing_isp:
                raw_ing_isp = str(ent.get("isp") or "").strip()
        else:
            ent_nt = str(ent.get("net_type") or "").strip().lower()
            if ent_nt in VALID_NET_TYPES:
                cache_ing_nt = ent_nt

    if ing_code:
        ing_nt = classify_asn(ing_code, raw_ing_isp)
        return (ing_nt != "datacenter"), ing_nt, "", ""

    if cache_ing_nt:
        return (cache_ing_nt != "datacenter"), cache_ing_nt, "", ""

    curr_nt = str(item.get("net_type") or "").strip().lower()
    if curr_nt in VALID_NET_TYPES:
        return (curr_nt != "datacenter"), curr_nt, "", ""

    return False, "datacenter", "", ""


def is_channel_or_user_source(source: str) -> bool:
    """
    判断代理来源是否为 Telegram 频道/群组或用户自留数据：
    - 允许保留机房的来源白名单：以 '@' 开头的频道/交流群（如 @danfeng_chat, @otcjlq, @otcfxq, @user 等）
      以及明确标明用户自留提供者 ('user', 'manual', 'custom')。
    - 其余所有外部订阅、镜像爬虫源（EDT-Pages, vpngate, proxifly, subscription 等）：严格过滤机房节点！
    """
    s = str(source or "").strip()
    if not s:
        return False
    if s.startswith("@"):
        return True
    return s.lower() in ("user", "manual", "custom")


def format_proxyip_json_item(r_dict: dict) -> dict:
    """
    转换为适配第三方调用、反代配置与前端订阅的标准化 ProxyIP JSON 字典对象：
    支持 proxy (ip:port), ip, port, tls, clientIp (出口真实 IP), country, country_name, country_cn, country_emoji, asn, asOrganization, isp, net_type, source 等全量凭据
    """
    raw_ip = str(r_dict.get("ip") or "").strip()
    port = safe_int(r_dict.get("port"), 0)
    proxy_str = f"{raw_ip}:{port}" if raw_ip and port else ""

    raw_tls = r_dict.get("tls")
    if isinstance(raw_tls, bool):
        tls_val = raw_tls
    elif isinstance(raw_tls, str):
        tls_val = raw_tls.strip().lower() in ("true", "1", "yes")
    else:
        tls_val = True

    raw_exit = str(r_dict.get("exit_ip") or "").strip()
    raw_exit_v6 = str(r_dict.get("exit_ipv6") or "").strip()

    cand_ips = []
    for cand in (
        r_dict.get("clientIps"),
        r_dict.get("client_ips"),
        r_dict.get("exit_ips"),
        r_dict.get("clientIpv4"),
        raw_exit,
        r_dict.get("clientIpv6"),
        raw_exit_v6,
    ):
        if cand:
            cand_ips.extend(extract_ips(cand))

    seen_ips = set()
    unique_exit_ips = []
    for ip_item in cand_ips:
        if ip_item not in seen_ips:
            seen_ips.add(ip_item)
            unique_exit_ips.append(ip_item)

    v4_ips = [cip for cip in unique_exit_ips if is_valid_ipv4(cip)]
    v6_ips = [cip for cip in unique_exit_ips if is_valid_ipv6(cip)]
    client_ipv4 = v4_ips[0] if v4_ips else ""
    client_ipv6 = v6_ips[0] if v6_ips else ""
    client_ip = client_ipv4 or client_ipv6 or raw_ip
    client_ips = unique_exit_ips if unique_exit_ips else ([client_ip] if client_ip else [])
    dual_stack = bool(client_ipv4 and client_ipv6)

    raw_country = str(r_dict.get("country") or "").strip().upper()
    if len(raw_country) == 2 and raw_country != "UN":
        c_code = raw_country
        c_name = COUNTRY_NAME_MAP.get(c_code, c_code)
        c_emoji = country_code_to_emoji(c_code)
    else:
        country_name = extract_country(r_dict.get("cf_location"), r_dict.get("colo"))
        code = get_country_code(country_name)
        if code and len(code) == 2:
            c_code = code.upper()
            c_name = COUNTRY_NAME_MAP.get(c_code, country_name or c_code)
            c_emoji = country_code_to_emoji(c_code)
        else:
            c_code = ""
            c_name = country_name or ""
            c_emoji = country_code_to_emoji(c_code) if c_code else ("🌐" if country_name else "")

    _, resolved_nt, exit_code, exit_isp = resolve_node_exit_and_net_type(r_dict)
    eff_code = exit_code or _extract_asn_code(r_dict.get("asn"), r_dict.get("isp")) or ""
    clean_asn_num = eff_code[2:] if eff_code.upper().startswith("AS") else eff_code

    isp_name = exit_isp or str(r_dict.get("exit_isp") or r_dict.get("isp") or "").strip()
    if not isp_name and eff_code:
        isp_name = ASN_TO_PROVIDER.get(eff_code) or ASN_DATABASE_ASN_TO_ISP.get(eff_code) or ""

    curr_nt = str(r_dict.get("net_type") or "").strip().lower()
    if eff_code:
        net_type_val = classify_asn(eff_code, isp_name)
    elif curr_nt in VALID_NET_TYPES:
        net_type_val = curr_nt
    else:
        net_type_val = resolved_nt if resolved_nt in VALID_NET_TYPES else ""

    source_val = str(r_dict.get("channel") or r_dict.get("source") or "").strip()

    return {
        "proxy": proxy_str,
        "ip": raw_ip,
        "port": port,
        "tls": tls_val,
        "clientIp": client_ip,
        "clientIps": client_ips,
        "clientIpv4": client_ipv4,
        "clientIpv6": client_ipv6,
        "dual_stack": dual_stack,
        "country": c_code,
        "country_name": c_name,
        "country_cn": c_name,
        "country_emoji": c_emoji,
        "asn": clean_asn_num,
        "asOrganization": isp_name,
        "isp": isp_name,
        "net_type": net_type_val,
        "source": source_val,
    }


def save_proxyip_json(rows: list, json_path: str = "data/proxyip.json") -> int:
    """
    保存全量反代 ProxyIP 标准化 JSON 文件（原子写入）。
    """
    json_list = [
        format_proxyip_json_item(r)
        for r in rows
        if isinstance(r, dict) and (r.get("ip") or "").strip() and safe_int(r.get("port"), 0) > 0
    ]
    atomic_write_json(json_path, json_list)
    log.info("已覆写保存 %s: %d 个全量 ProxyIP 节点 (标准 JSON 格式)", json_path, len(json_list))
    return len(json_list)


def save_proxyip_by_country(rows: list, output_dir: str) -> int:
    """
    将 ProxyIP 列表按国家/地区拆分输出为独立的纯文本与标准化 JSON 文件（如 美国.txt / 美国.json）。
    同时自动提取高价值稀缺属性节点导出为独立专用清单（如 【ISP_运营商原生宽带】.txt / .json 等）。
    纯文本内容仅包含纯净的 IP:端口，JSON 文件包含完整元数据（含 clientIp 出口 IP）。
    自动清理目录中已不存在的旧地区文件，返回生成的独立文件数量。
    """
    if rows is None or not isinstance(rows, (list, tuple, set)):
        raise ValueError(f"save_proxyip_by_country requires a valid list of rows, got {type(rows).__name__}")
    if not rows and not os.path.isdir(output_dir):
        return 0

    os.makedirs(output_dir, exist_ok=True)
    groups: dict[str, list] = {}
    type_groups: dict[str, list] = {}

    for r in rows:
        country = extract_country(r.get("cf_location"), r.get("colo"))
        groups.setdefault(country, []).append(r)

        # 始终依据出口真实 ASN 与权威研判实时校准网络类型，确保分流分类一致
        _, nt, _, _ = resolve_node_exit_and_net_type(r)
        r["net_type"] = nt
        if nt in SPECIAL_NET_TYPE_FILES:
            type_groups.setdefault(nt, []).append(r)

    active_files = set()

    # 1. 导出各国家/地区独立清单 (.txt 与 .json)
    for country, members in groups.items():
        valid_members = [
            r for r in members
            if (r.get("ip") or "").strip() and safe_int(r.get("port"), 0) > 0
        ]
        if not valid_members:
            continue
        lines = [f"{(r.get('ip') or '').strip()}:{r.get('port')}\n" for r in valid_members]
        safe_country = re.sub(r'[\\/:*?"<>|]', "_", country).strip() or "其他地区"
        code = get_country_code(safe_country) or get_country_code(country)
        base_name = f"{code}_{safe_country}" if code else safe_country
        txt_fname = f"{base_name}.txt"
        json_fname = f"{base_name}.json"

        atomic_write_text(os.path.join(output_dir, txt_fname), "".join(lines))
        active_files.add(txt_fname)

        json_items = [format_proxyip_json_item(r) for r in valid_members]
        atomic_write_json(os.path.join(output_dir, json_fname), json_items)
        active_files.add(json_fname)

    # 2. 导出高价值特殊网络属性清单（运营商宽带、企业专线/金融、高校教育、政务公用，.txt 与 .json）
    for nt, fname in SPECIAL_NET_TYPE_FILES.items():
        members = type_groups.get(nt, [])
        valid_members = [
            r for r in members
            if (r.get("ip") or "").strip() and safe_int(r.get("port"), 0) > 0
        ]
        if not valid_members:
            continue
        lines = [f"{(r.get('ip') or '').strip()}:{r.get('port')}\n" for r in valid_members]
        atomic_write_text(os.path.join(output_dir, fname), "".join(lines))
        active_files.add(fname)

        json_fname = fname[:-4] + ".json"
        json_items = [format_proxyip_json_item(r) for r in valid_members]
        atomic_write_json(os.path.join(output_dir, json_fname), json_items)
        active_files.add(json_fname)

    # 清理已不存在或旧命名格式的 .txt 与 .json 文件（保留 domains.txt、.gitkeep 等标记文件，以及 custom_ / manual_ 用户自定义文件）
    for old_f in os.listdir(output_dir):
        fpath = os.path.join(output_dir, old_f)
        if (
            os.path.isfile(fpath)
            and (old_f.endswith(".txt") or old_f.endswith(".json"))
            and old_f != "domains.txt"
            and old_f not in active_files
            and not old_f.startswith("custom_")
            and not old_f.startswith("manual_")
        ):
            try:
                os.remove(fpath)
            except OSError:
                pass

    return len(active_files)


def save_scan_ips_by_asn(asn_groups: dict, output_dir: str, min_nodes: int = 5) -> int:
    """
    覆写 scan_ips/ 目录下的独立 ASN 纯文本文件（无注释 IP:端口；原子写入防截断）。
    - 活跃节点数 >= min_nodes (默认 5) 的 ASN 生成独立专属文件（如 AS906_DMIT.txt）
    - 活跃节点数 < min_nodes 的长尾微型 ASN 统一收纳进 OTHER_长尾网络聚合.txt，避免文件碎片化
    - 死节点被淘汰后，若某个 ASN 文本文件已无活跃 IP，会自动清除删除（保留 .gitkeep 保持目录结构）
    返回生成的独立文件数量。
    """
    if asn_groups is None or not isinstance(asn_groups, dict):
        raise ValueError(f"save_scan_ips_by_asn requires a valid dict of asn_groups, got {type(asn_groups).__name__}")
    if not asn_groups and not os.path.isdir(output_dir):
        return 0

    os.makedirs(output_dir, exist_ok=True)
    active_files = set()
    other_rows = []

    for asn_name, group in asn_groups.items():
        valid_rows = [
            r for r in group
            if r.get("ip") and safe_int(r.get("port"), 0) > 0 and safe_int(r.get("port"), 0) <= 65535
        ]
        if not valid_rows:
            continue

        # 严格过滤非法 AS 编号与未知占位符，绝不生成 AS0_xxx.txt 或 AS_UNKNOWN.txt
        safe_asn_check = str(asn_name).strip().upper()
        if safe_asn_check in ("AS0", "AS_UNKNOWN", "UNKNOWN", "AS", "") or safe_asn_check.startswith("AS0_"):
            other_rows.extend(valid_rows)
            continue

        # 小于 min_nodes 门槛的长尾 ASN，统一收纳进长尾聚合集合
        if len(valid_rows) < min_nodes:
            other_rows.extend(valid_rows)
            continue

        isp_name = ASN_TO_PROVIDER.get(asn_name, "")
        if not isp_name:
            isp_name = next((r.get("isp") for r in group if r.get("isp")), "")

        # 严格过滤地址字符串、过短字符与无意义泛化占位符（如 Private Customer、3rd Floor、SA、Beafort 等），避免生成脏文件名
        if isp_name and (
            len(isp_name.strip()) <= 2
            or _ADDR_RE.search(isp_name)
            or re.search(r'(?i)^(?:private\s*customer|shared\s*assignment|customer\s*ip|nat\s*pool|undefined|sa|beafort|ht|dc|vps|cloud|ip|llc|ltd|na|null|none|unknown)$', isp_name.strip())
        ):
            isp_name = ""

        # 严谨过滤文件名非法字符（特别是 Windows / Linux 路径分隔符 / 与 \，以及冒号等）
        safe_asn = re.sub(r'[\\/:*?"<>|\s]', "_", str(asn_name).strip()).strip(" ._") or "AS_UNKNOWN"
        safe_asn = re.sub(r"_+", "_", safe_asn)
        if safe_asn.upper() in ("AS0", "AS_UNKNOWN", "UNKNOWN", "AS") or safe_asn.upper().startswith("AS0_"):
            other_rows.extend(valid_rows)
            continue

        clean_isp = re.sub(r"[^a-zA-Z0-9]", "", isp_name) if isp_name else ""
        if clean_isp and clean_isp.lower() != safe_asn.lower():
            fname = f"{safe_asn}_{clean_isp}.txt"
        else:
            fname = f"{safe_asn}.txt"
        fpath = os.path.join(output_dir, fname)

        with atomic_writer(fpath, encoding="utf-8", newline="\n") as f:
            for r in sorted(valid_rows, key=lambda x: (x.get("ip", ""), safe_int(x.get("port"), 0))):
                f.write(f"{r['ip']}:{safe_int(r.get('port'), 0)}\n")
        active_files.add(fname)

    # 写入长尾网络聚合文件
    if other_rows:
        other_fname = "OTHER_长尾网络聚合.txt"
        other_fpath = os.path.join(output_dir, other_fname)
        seen_keys = set()
        unique_other = []
        for r in other_rows:
            key = (r.get("ip", ""), safe_int(r.get("port"), 0))
            if key not in seen_keys:
                seen_keys.add(key)
                unique_other.append(r)
        with atomic_writer(other_fpath, encoding="utf-8", newline="\n") as f:
            for r in sorted(unique_other, key=lambda x: (x.get("ip", ""), safe_int(x.get("port"), 0))):
                f.write(f"{r['ip']}:{safe_int(r.get('port'), 0)}\n")
        active_files.add(other_fname)

    # 移除已无活跃 IP 或已合并进长尾的旧分组文件（保留 .gitkeep 保持目录结构）
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

    log.info("已覆写更新 %s/ 目录: %d 个独立 ASN 纯文本文件（含长尾聚合）", output_dir, len(active_files))
    return len(active_files)


# 兼容别名
save_scan_dir = save_scan_ips_by_asn


def get_top_quality_proxies(
    csv_path: str = "data/proxies.csv",
    limit: int = 8,
    max_delay: int = 350,
) -> list[str]:
    """
    从本地已质检的 proxies.csv 中智能提取跨区、低延时、0 失败率的优质代理列表：
    分段轮换防封架构：
    1. 严格排除国内 CN 节点（境内节点访问境外 IPinfo 易被阻断或握手重置）
    2. 按国家/地区分桶（如 US, SG, DE, JP, HK, GB, FR 等），优先从每个国家各取 1 个最低延时节点
    3. 组建跨大洲、跨机房多元化代理候选链，彻底避免单一机房/区域连坐触发 Cloudflare 验证码
    4. 自动将 socks5:// 协议前缀转换为 socks5h:// 以确保代理端远程解析 DNS
    """
    if not os.path.isfile(csv_path):
        return []
    try:
        by_country: dict[str, list[tuple[int, str, str]]] = {}
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for r in reader:
                if r.get("status") == "alive" and safe_int(r.get("fail_count"), 99) == 0:
                    proto = (r.get("proto") or "").lower()
                    if proto in ("socks5", "http"):
                        country = str(r.get("country") or "").strip().upper()
                        if not country or country == "CN":
                            continue
                        dms = safe_int(r.get("delay_ms"), 99999)
                        if 0 < dms <= max_delay:
                            url = r.get("url") or ""
                            if url:
                                by_country.setdefault(country, []).append((dms, proto, url))

        # 各国家桶内部按延时升序排序
        for c in by_country:
            by_country[c].sort(key=lambda x: x[0])

        # 按各国家桶的最优延迟排序国家优先顺序
        sorted_countries = sorted(by_country.keys(), key=lambda c: by_country[c][0][0])

        # 轮换分桶抽样：优先每个国家抽取 1 条
        selected = []
        for c in sorted_countries:
            if len(selected) >= limit:
                break
            selected.append(by_country[c][0])

        # 若国家数量不足 limit，从各桶的次优节点继续补齐
        if len(selected) < limit:
            for c in sorted_countries:
                for cand in by_country[c][1:]:
                    if len(selected) >= limit:
                        break
                    selected.append(cand)
                if len(selected) >= limit:
                    break

        result = []
        for _, proto, raw_url in selected:
            if proto == "socks5" and raw_url.startswith("socks5://"):
                clean_url = "socks5h://" + raw_url[len("socks5://"):]
            else:
                clean_url = raw_url
            result.append(clean_url)
        return result
    except Exception as e:
        log.debug("读取优质代理列表异常 (已安全隔离): %s", e)
        return []


def extract_ipinfo_page_meta(html: str) -> tuple[str, str]:
    """
    从 IPinfo SSR 页面提取官方网络分类 (raw_type) 与官方组织机构名 (as_name)。
    四通道稳态校验架构：
    1. 优先解析 schema.org JSON-LD DataFeed (SEO 结构化数据，最标准)
    2. 权威 Title / OpenGraph Meta 标签提取组织机构名 (SEO 规范，无 DOM 漂移风险)
    3. HTML Summary 表格提取网络类型（行级作用域隔离 + 受控枚举白名单，彻底杜绝 .*? 越界误伤）
    4. Next.js RSC / PropertyValue 键值对提取（兼容正反序与引号反斜杠转义）
    返回 (raw_type, as_name)，如 ("isp", "Gorodok Ltd.")。
    """
    if not html:
        return "", ""

    net_type = ""
    as_name = ""

    # 通道 1: schema.org JSON-LD 结构化数据 (SEO 官方内嵌，首选)
    for script_match in re.findall(r'<script[^>]*type=[\'"]application/ld\+json[\'"][^>]*>(.*?)</script>', html, re.DOTALL):
        try:
            data = json.loads(script_match.strip())
            if isinstance(data, dict) and data.get("@type") == "DataFeed":
                for prop in data.get("variableMeasured", []):
                    if not isinstance(prop, dict):
                        continue
                    p_name = str(prop.get("name") or "").strip().lower()
                    p_val = str(prop.get("value") or "").strip()
                    if p_name in ("type", "asn type") and p_val:
                        net_type = p_val.lower()
                    elif p_name in ("as name", "name", "as_name") and p_val:
                        as_name = p_val
                if net_type:
                    break
        except Exception:
            pass

    # 通道 2: HTML 标题与 Meta 标签提取组织名 (SEO 官方内嵌，最稳定标准)
    if not as_name:
        title_m = re.search(r'<title>\s*AS\d+\s+(.*?)\s+(?:AS details|AS Details)\s*\|\s*IPinfo\s*</title>', html, re.IGNORECASE)
        if title_m:
            as_name = title_m.group(1).strip()
        else:
            og_m = re.search(r'<meta\s+(?:property|name)=[\'"](?:og:title|twitter:title)[\'"]\s+content=[\'"]AS\d+\s+(.*?)\s+(?:AS details|AS Details)[\'"]', html, re.IGNORECASE)
            if og_m:
                as_name = og_m.group(1).strip()

    # 通道 3: HTML 表格 Summary 解析（行级作用域隔离 + 受控枚举白名单，彻底杜绝 .*? 越界污染）
    if not net_type:
        tr_m = re.search(r'<tr[^>]*>(?:(?!</tr>).)*?ASN\s+type(?:(?!</tr>).)*?</tr>', html, re.DOTALL | re.IGNORECASE)
        if tr_m:
            tr_content = tr_m.group(0)
            type_m = re.search(r'\b(isp|hosting|business|education|government)\b', tr_content, re.IGNORECASE)
            if type_m:
                net_type = type_m.group(1).lower()

    # 通道 4: 正则匹配 PropertyValue 结构（兼容反斜杠转义与双向键值顺序）
    if not net_type:
        prop_m = re.search(r'\\?["\']name\\?["\']\s*:\s*\\?["\']Type\\?["\']\s*,\s*\\?["\']value\\?["\']\s*:\s*\\?["\']([a-zA-Z]+)\\?["\']', html, re.IGNORECASE)
        if not prop_m:
            prop_m = re.search(r'\\?["\']value\\?["\']\s*:\s*\\?["\']([a-zA-Z]+)\\?["\']\s*,\s*\\?["\']name\\?["\']\s*:\s*\\?["\']Type\\?["\']', html, re.IGNORECASE)
        if prop_m:
            candidate = prop_m.group(1).lower()
            if candidate in ("isp", "hosting", "business", "education", "government"):
                net_type = candidate

    return net_type, as_name


_DEAD_IPINFO_PROXIES: set[str] = set()
_PROBE_FAILED_ASNS: set[str] = set()
_SESSION_ENRICHED_ASNS: dict[str, dict] = {}
_IPINFO_STATE_LOCK = threading.Lock()


def get_session_enriched_asns() -> list[dict]:
    """返回当前进程生命周期内通过 auto_enrich_and_save_asns 实际新增写入 asn_database.json 的 ASN 列表副本"""
    with _IPINFO_STATE_LOCK:
        return [dict(v) for v in _SESSION_ENRICHED_ASNS.values()]


def _sync_enriched_asns_to_fetch_stats(
    newly_persisted: list[dict],
    fetch_stats_path: str = os.path.join("data", ".fetch_stats.json"),
) -> None:
    """
    若磁盘上已存在流水线暂存的 data/.fetch_stats.json（如在 proxies_verify / proxyip_verify / cf_verify 阶段），
    将本阶段实际新增入库的 ASN 增量合并进 stats["unrecorded_asns"]，确保最终通知卡片与 asn_database.json 的新增入库数严格 100% 一致。
    """
    if not newly_persisted or not os.path.isfile(fetch_stats_path):
        return
    try:
        with open(fetch_stats_path, "r", encoding="utf-8") as f:
            stats = json.load(f)
        if not isinstance(stats, dict):
            return
        existing_list = stats.get("unrecorded_asns")
        if not isinstance(existing_list, list):
            existing_list = []
        by_code: dict[str, dict] = {}
        ordered_codes: list[str] = []
        for item in existing_list:
            if not isinstance(item, dict):
                continue
            c = _extract_asn_code(item.get("asn"), item.get("isp") or item.get("org"))
            if c and c not in by_code:
                by_code[c] = dict(item)
                ordered_codes.append(c)
        changed = False
        for item in newly_persisted:
            c = _extract_asn_code(item.get("asn"), item.get("isp") or item.get("org"))
            if not c:
                continue
            auth_org = ASN_TO_PROVIDER.get(c) or item.get("org") or item.get("isp") or ""
            cnt = max(1, safe_int(item.get("count"), 1))
            if c not in by_code:
                by_code[c] = {
                    "asn": c,
                    "org": auth_org,
                    "isp": auth_org,
                    "net_type": item.get("net_type") or classify_asn(c, auth_org),
                    "count": cnt,
                }
                ordered_codes.append(c)
                changed = True
            else:
                if auth_org and by_code[c].get("org") != auth_org:
                    by_code[c]["org"] = auth_org
                    by_code[c]["isp"] = auth_org
                    changed = True
                if safe_int(by_code[c].get("count"), 0) <= 0:
                    by_code[c]["count"] = cnt
                    changed = True
        if changed:
            stats["unrecorded_asns"] = [by_code[c] for c in ordered_codes]
            atomic_write_json(fetch_stats_path, stats)
    except Exception as e:
        log.debug("同步新入库 ASN 至 %s 异常 (已忽略): %s", fetch_stats_path, e)


def probe_asn_from_ipinfo(
    asn: str,
    proxy_candidates: list[str] | None = None,
    timeout: float = 4.0,
    max_tries: int = 2,
    start_offset: int = 0,
) -> tuple[str, str]:
    """
    通过本地代理池轮换出口对 IPinfo.io 发起微探针，精准提取官方 ASN 权威类型与机构名称。
    用于在 GitHub Actions 运行收录全新 ASN 时消除启发式正则推测误差，实现 100% 官方标准注入。
    内置坏代理熔断 (_DEAD_IPINFO_PROXIES) 与跨区偏移轮换 (start_offset)，避免死代理重复超时及单出口频控。
    返回: (official_type, official_name)，如 ("isp", "Starry, Inc.")；失败时返回 ("", "")。
    """
    clean_code = (asn or "").strip().upper()
    if not clean_code:
        return "", ""
    if not clean_code.startswith("AS"):
        clean_code = f"AS{clean_code}"
    if not re.match(r"^AS\d+$", clean_code) or clean_code == "AS0":
        return "", ""

    # 快速旁路 1: 权威已知云厂商直接返回 datacenter 与标准名 (0ms 免网络请求)
    if clean_code in AUTHORITATIVE_CLOUD_ASNS:
        return "datacenter", AUTHORITATIVE_CLOUD_ASNS[clean_code]

    # 快速旁路 2: 人工特例表与已收录权威数据库直接复用 (0ms 免请求，节约探针开销)
    if clean_code in MANUAL_OVERRIDE_NET_TYPES:
        cached_name = ASN_DATABASE_ASN_TO_ISP.get(clean_code) or ""
        return MANUAL_OVERRIDE_NET_TYPES[clean_code], cached_name

    if clean_code in ASN_EXACT_NET_TYPE:
        cached_name = ASN_DATABASE_ASN_TO_ISP.get(clean_code) or ""
        return ASN_EXACT_NET_TYPE[clean_code], cached_name

    url = f"https://ipinfo.io/{clean_code}"

    # 组织候选代理列表：过滤本轮已熔断失效代理，并按 start_offset 跨国家桶轮换起点，兜底加入直连
    cand_proxies = list(proxy_candidates) if proxy_candidates is not None else get_top_quality_proxies()
    with _IPINFO_STATE_LOCK:
        dead_snapshot = set(_DEAD_IPINFO_PROXIES)
    healthy_proxies = [p for p in cand_proxies if p and p not in dead_snapshot]
    if healthy_proxies:
        offset = max(0, int(start_offset)) % len(healthy_proxies)
        rotated = healthy_proxies[offset:] + healthy_proxies[:offset]
        trials = rotated[:max_tries]
    else:
        trials = []
    if "" not in trials:
        trials.append("")

    curl_bin = "curl.exe" if shutil.which("curl.exe") else ("curl" if shutil.which("curl") else "")

    def _mark_dead_proxy(bad_proxy: str) -> None:
        if bad_proxy:
            with _IPINFO_STATE_LOCK:
                _DEAD_IPINFO_PROXIES.add(bad_proxy)

    for p in trials:
        html = ""
        try:
            if curl_bin:
                cmd = [
                    curl_bin, "-sL",
                    "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "--max-time", str(int(timeout)),
                ]
                if p:
                    cmd.extend(["-x", p])
                cmd.append(url)
                res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout + 2, check=False)
                if res.returncode == 0 and res.stdout:
                    html = res.stdout
            elif not p or not p.startswith("socks"):
                handlers = []
                if p:
                    handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
                opener = urllib.request.build_opener(*handlers)
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    }
                )
                with opener.open(req, timeout=timeout) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            _mark_dead_proxy(p)
            log.debug("IPinfo 代理探针尝试 %s 访问 %s 异常 (已熔断该代理): %s", p or "直连", clean_code, e)
            continue

        if not html:
            _mark_dead_proxy(p)
            continue

        # 避坑：若遭遇 Cloudflare 拦截、429 频控或非 IPinfo 错误页，熔断跳过此代理
        if (
            "Just a moment" in html
            or "challenge-platform" in html
            or "429 Too Many Requests" in html
            or "ipinfo" not in html.lower()
        ):
            _mark_dead_proxy(p)
            log.debug("IPinfo 代理探针访问 %s 触发风控或非预期响应 (已熔断此代理 %s)", clean_code, p or "直连")
            continue

        raw_type, raw_name = extract_ipinfo_page_meta(html)
        if raw_type:
            log.debug("【IPinfo 官方探针精准命中】%s -> Type: %s | Name: %s (出海通道: %s)", clean_code, raw_type, raw_name, p or "直连")
            return raw_type, raw_name

    return "", ""


def auto_enrich_and_save_asns(
    unrecorded_items: list[dict],
    proxy: str = "",
    max_workers: int = 4,
) -> int:
    """
    针对自带 ASN / 组织机构属性的数据源（如 EDT-Pages、测速扫描附件、质检在线反查等）：
    在全链路各阶段自动完成网络类型属性分类并持久化入库到 data/asn_database.json。

    工程保障：
    1. 【严格只增不改 (Append-Only)】：仅当 IPinfo 官方探针精准命中权威分类时才新增入库，既有条目绝不覆写。
    2. 【防猜测写盘】：探针未响应或遭遇拦截时绝不落盘，不拿正则盲猜污染数据库。
    3. 【运行时防重试风暴】：同进程生命周期内失败的 ASN 记录进 _PROBE_FAILED_ASNS，避免重复发起探测。
    4. 【云厂商 SSOT 保护】：若传入的 ASN 属于内置权威已知云厂商，强制维持权威标准名称与 datacenter 属性。
    5. 【LRU 缓存实时自愈】：写盘入库后同步更新运行时字典与 fast-path，并主动清空 classify_asn LRU 缓存。
    6. 【有界跨区并发探测】：对去重后的待查 ASN 执行有界并发探测（默认 max_workers=4，按跨国代理桶轮换起点），单线程汇总原子落盘。
    """
    if not unrecorded_items:
        return 0

    try:
        to_save_map: dict[str, dict] = {}
        # 预先拉取一次候选优质代理列表（复用，避免在循环中重复读取 CSV 文件）
        top_proxies = get_top_quality_proxies()
        if proxy and proxy not in top_proxies:
            top_proxies.append(proxy)

        code_to_items: dict[str, list[dict]] = {}
        code_fallback_org: dict[str, str] = {}
        with _IPINFO_STATE_LOCK:
            failed_snapshot = set(_PROBE_FAILED_ASNS)

        for item in unrecorded_items:
            try:
                if not isinstance(item, dict):
                    continue
                raw_asn = str(item.get("asn") or "").strip()
                raw_isp = str(item.get("isp") or item.get("org") or "").strip()
                code = _extract_asn_code(raw_asn, raw_isp)
                if not code or not re.match(r"^AS\d+$", code) or code == "AS0":
                    continue

                # 运行期防重复探测拦截
                if code in failed_snapshot:
                    continue

                # 云厂商 SSOT 保护：若命中内置权威已知云厂商，坚决维持权威定义，直接跳过并拒绝外部污染
                if code in AUTHORITATIVE_CLOUD_ASNS:
                    log.debug("ASN %s 命中权威已知云厂商 SSOT 锁定列表，维持权威名称 %s，忽略外部标签: %s", code, AUTHORITATIVE_CLOUD_ASNS[code], raw_isp)
                    continue

                # 幂等性快速短路：若本地权威库已收录且已有明确网络类型，直接跳过
                if is_asn_recorded(code):
                    continue

                code_to_items.setdefault(code, []).append(item)
                if not code_fallback_org.get(code):
                    org_clean = re.sub(r"^AS\d+\s*", "", raw_isp, flags=re.IGNORECASE).strip()
                    if org_clean:
                        code_fallback_org[code] = org_clean
            except Exception as item_err:
                log.debug("解析单条未收录 ASN 条目发生异常 (已隔离跳过): %s (%s)", item, item_err)
                continue

        codes_to_probe = list(code_to_items.keys())
        if not codes_to_probe:
            return 0

        def _probe_single_code(idx_and_code: tuple[int, str]) -> tuple[str, str, str]:
            idx, c = idx_and_code
            try:
                o_type, o_name = probe_asn_from_ipinfo(
                    c,
                    proxy_candidates=top_proxies,
                    timeout=4.0,
                    start_offset=idx,
                )
                return c, o_type, o_name
            except Exception as probe_err:
                log.debug("IPinfo 探针探测 ASN %s 异常 (已安全跳过): %s", c, probe_err)
                return c, "", ""

        probe_results: list[tuple[str, str, str]] = []
        workers = max(1, min(int(max_workers), len(codes_to_probe)))
        if workers == 1:
            probe_results = [_probe_single_code((0, codes_to_probe[0]))]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ipinfo-asn") as pool:
                probe_results = list(pool.map(_probe_single_code, enumerate(codes_to_probe)))

        newly_failed: list[str] = []
        for code, official_type, official_name in probe_results:
            org = official_name or code_fallback_org.get(code, "")
            if official_type and official_type in EXTERNAL_NET_TYPE_MAP:
                net_type = EXTERNAL_NET_TYPE_MAP[official_type]
                log.debug("【ASN 精准注入】ASN %s 成功通过 IPinfo 官方探针精准打标: %s -> %s", code, org, net_type)
                to_save_map[code] = {
                    "asn": code,
                    "isp": org,
                    "net_type": net_type,
                }
                for item in code_to_items.get(code, ()):
                    if org:
                        item["org"] = org
                        item["isp"] = org
                    item["net_type"] = net_type
            else:
                # 探针未响应/拦截/失败：坚决不拿正则猜测充数入库，记录防重试集合并安全跳过
                newly_failed.append(code)
                log.debug("ASN %s 探针未获取到官方有效网络类型，跳过持久化写入（避免猜测污染数据库）", code)

        if newly_failed:
            with _IPINFO_STATE_LOCK:
                _PROBE_FAILED_ASNS.update(newly_failed)

        if not to_save_map:
            return 0

        i2a, a2i, a2nt = load_asn_database()
        added_count = 0
        newly_persisted: list[dict] = []
        for code, info in to_save_map.items():
            if code in AUTHORITATIVE_CLOUD_ASNS:
                continue
            org = info["isp"]
            n_type = info["net_type"]
            if code not in a2nt:
                a2nt[code] = n_type
                added_count += 1
                raw_cnt = sum(max(1, safe_int(it.get("count"), 1)) for it in code_to_items.get(code, []))
                newly_persisted.append({
                    "asn": code,
                    "org": org,
                    "isp": org,
                    "net_type": n_type,
                    "count": max(1, raw_cnt),
                })
            if org:
                if code not in a2i:
                    a2i[code] = org
                if org not in i2a:
                    i2a[org] = code

        if added_count > 0:
            save_asn_database(i2a, a2i, a2nt)
            # 同步更新内存运行时 SSOT 字典与 Fast-path
            ASN_TO_PROVIDER.update(a2i)
            ASN_DATABASE_ASN_TO_ISP.update(a2i)
            ASN_DATABASE_ASN_TO_NET_TYPE.update(a2nt)
            ASN_EXACT_NET_TYPE.update(a2nt)
            classify_asn.cache_clear()
            format_asn_isp.cache_clear()

            with _IPINFO_STATE_LOCK:
                for entry in newly_persisted:
                    c_key = entry["asn"]
                    auth_org = ASN_TO_PROVIDER.get(c_key) or entry["org"]
                    entry["org"] = auth_org
                    entry["isp"] = auth_org
                    if c_key not in _SESSION_ENRICHED_ASNS:
                        _SESSION_ENRICHED_ASNS[c_key] = dict(entry)
                    else:
                        _SESSION_ENRICHED_ASNS[c_key]["count"] = max(
                            _SESSION_ENRICHED_ASNS[c_key].get("count", 1),
                            entry["count"],
                        )

            _sync_enriched_asns_to_fetch_stats(newly_persisted)

            sample_str = ", ".join(f"{e['asn']}[{e['net_type']}]" for e in newly_persisted[:6])
            if len(newly_persisted) > 6:
                sample_str += f" 等共 {len(newly_persisted)} 个"
            log.info("【批量自动持久化新 ASN】提取并持久化 %d 个全新自治系统并原子写入数据库: %s", added_count, sample_str)
        return added_count
    except Exception:
        log.exception("【自动收录新 ASN】执行异常（已安全隔离，主流程继续正常执行）")
        return 0


def _write_scan_ips_outputs(
    scan_rows: list[dict],
    scan_csv_path: str,
    scan_txt_path: str = "",
    scan_dir_path: str = "",
) -> int:
    """按 ASN 分组并统一排序输出 scan_ips.csv、scan_ips.txt 与 scan_ips/ ASN 分组文件（自动过滤 AS13335 分组）。"""
    asn_groups: dict[str, list] = {}
    for r in scan_rows:
        ing_asn = _extract_asn_code(r.get("asn"), r.get("isp"))
        ex_asn = _extract_asn_code(r.get("exit_asn"), r.get("exit_isp"))
        if ing_asn and not is_cloudflare_asn_or_isp(ing_asn, r.get("isp", "")):
            c_asn = ing_asn
        elif ex_asn and not is_cloudflare_asn_or_isp(ex_asn, r.get("exit_isp", "")):
            c_asn = ex_asn
        else:
            c_asn = "AS_UNKNOWN"
        asn_groups.setdefault(c_asn, []).append(r)

    sorted_scan_rows: list[dict] = []
    for asn_name in sorted(asn_groups.keys()):
        grp = sorted(asn_groups[asn_name], key=lambda x: str(x.get("first_seen") or ""), reverse=True)
        grp = sorted(
            grp,
            key=lambda x: (
                safe_int(x.get("fail_count"), 0),
                safe_int(x.get("delay_ms"), 0) if safe_int(x.get("delay_ms"), 0) > 0 else 99999,
            ),
        )
        sorted_scan_rows.extend(grp)

    if scan_csv_path:
        with atomic_writer(scan_csv_path, encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SCAN_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for r in sorted_scan_rows:
                writer.writerow(r)

    if scan_txt_path:
        atomic_write_text(scan_txt_path, format_scan_ips_txt(sorted_scan_rows))
    if scan_dir_path:
        save_scan_ips_by_asn(asn_groups, scan_dir_path)
    return len(sorted_scan_rows)


def merge_demoted_into_scan_ips(
    demoted_rows: list[dict],
    scan_csv_path: str = "data/scan_ips.csv",
    scan_txt_path: str = "data/scan_ips.txt",
    scan_dir_path: str = "data/scan_ips",
) -> int:
    """
    将经校准或外部鉴真确认为机房 (net_type == 'datacenter') 的节点从 ProxyIP 池安全移入 scan_ips 优选池，
    同步更新 scan_ips.csv、scan_ips.txt 与 scan_ips/ ASN 分组目录（幂等合并，严格过滤墓地死节点与 Cloudflare 入口）。
    返回本次新并入或补全的记录条数。
    """
    if not demoted_rows:
        return 0

    tombstone = load_tombstone()
    ip_cache = load_ip_cache()
    scan_map: dict[str, dict] = {}
    cf_purged_existing = 0
    if scan_csv_path and os.path.isfile(scan_csv_path):
        try:
            with open(scan_csv_path, "r", encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    ip = str(r.get("ip") or "").strip()
                    port = safe_int(r.get("port"), 0)
                    if not ip or port <= 0 or port > 65535:
                        continue
                    k = canonical_key(ip, port)
                    if is_tombstoned(k, tombstone):
                        continue
                    if is_cloudflare_node(r, ip_cache):
                        cf_purged_existing += 1
                        continue
                    r["ip"] = ip
                    r["port"] = str(port)
                    r["fail_count"] = safe_int(r.get("fail_count"), 0)
                    scan_map[k] = r
        except Exception as e:
            log.warning("读取 %s 以合并降级机房节点失败: %s", scan_csv_path, e)

    merged_cnt = 0
    for dr in demoted_rows:
        ip = str(dr.get("ip") or "").strip()
        port = safe_int(dr.get("port"), 0)
        if not ip or port <= 0 or port > 65535:
            continue
        k = canonical_key(ip, port)
        if is_tombstoned(k, tombstone) or is_cloudflare_node(dr, ip_cache):
            continue

        cand_exits = extract_ips([dr.get("exit_ip"), dr.get("exit_ipv6")])
        v4_exits = [cip for cip in cand_exits if is_valid_ipv4(cip)]
        v6_exits = [cip for cip in cand_exits if is_valid_ipv6(cip)]
        eff_exit_ip = v4_exits[0] if v4_exits else (v6_exits[0] if v6_exits else "")

        ex_code = _extract_asn_code(dr.get("exit_asn"), dr.get("exit_isp"))
        ex_isp = str(dr.get("exit_isp") or "").strip()
        ing_code = _extract_asn_code(dr.get("asn"), dr.get("isp"))
        ing_isp = str(dr.get("isp") or "").strip()

        if not ex_code and eff_exit_ip and eff_exit_ip == ip and ing_code:
            ex_code = ing_code
            ex_isp = ex_isp or ing_isp
        if ex_code and not ex_isp:
            ex_isp = ASN_TO_PROVIDER.get(ex_code) or ASN_DATABASE_ASN_TO_ISP.get(ex_code) or ""

        eff_exit_asn = format_asn_isp(ex_code, ex_isp) if ex_code else ""
        # 严禁将 WARP 出口 (Cloudflare) 回写为未知入口节点的 ingress ASN
        non_cf_ex_code = ex_code if (ex_code and not is_cloudflare_asn_or_isp(ex_code, ex_isp)) else ""
        eff_ing_asn = format_asn_isp(ing_code or non_cf_ex_code, ing_isp or (ex_isp if non_cf_ex_code else ""))
        eff_ing_isp = ing_isp or (ex_isp if non_cf_ex_code else "")

        if k not in scan_map:
            scan_map[k] = {
                "ip": ip,
                "port": str(port),
                "tls": str(dr.get("tls") or "true").lower(),
                "delay_ms": safe_int(dr.get("delay_ms"), 0),
                "speed_kbs": str(dr.get("speed_kbs") or ""),
                "colo": str(dr.get("colo") or ""),
                "cf_location": str(dr.get("cf_location") or ""),
                "asn": eff_ing_asn,
                "isp": eff_ing_isp,
                "first_seen": normalize_timestamp(str(dr.get("first_seen") or "")),
                "channel": str(dr.get("channel") or ""),
                "fail_count": safe_int(dr.get("fail_count"), 0),
                "exit_ip": eff_exit_ip,
                "exit_asn": eff_exit_asn,
                "exit_isp": ex_isp,
                "exit_location": str(dr.get("exit_location") or dr.get("cf_location") or ""),
            }
            merged_cnt += 1
        else:
            ex_row = scan_map[k]
            updated = False
            for mk, mv in (
                ("colo", dr.get("colo")),
                ("cf_location", dr.get("cf_location")),
                ("asn", eff_ing_asn),
                ("isp", eff_ing_isp),
                ("exit_ip", eff_exit_ip),
                ("exit_asn", eff_exit_asn),
                ("exit_isp", ex_isp),
            ):
                if mv and not str(ex_row.get(mk) or "").strip():
                    ex_row[mk] = mv
                    updated = True
            if updated:
                merged_cnt += 1

    if (merged_cnt > 0 or cf_purged_existing > 0) and scan_csv_path:
        _write_scan_ips_outputs(
            list(scan_map.values()),
            scan_csv_path=scan_csv_path,
            scan_txt_path=scan_txt_path,
            scan_dir_path=scan_dir_path,
        )
        log.info("【机房归池闭环】已将 %d 条机房属性节点从 ProxyIP 池安全移入 %s (同步清理 CF 入口 %d 条)", merged_cnt, scan_csv_path, cf_purged_existing)

    return merged_cnt


def calibrate_all_datasets(
    proxies_dir: str = "data/proxies",
    proxies_csv_path: str = "data/proxies.csv",
    proxyip_csv_path: str = "data/proxyip.csv",
    proxyip_dir: str = "data/proxyip",
    ip_cache_path: str = "data/ip_cache.json",
    proxies_only: bool = False,
    proxyip_txt_path: str = "data/proxyip.txt",
    proxyip_json_path: str = "data/proxyip.json",
    scan_csv_path: str = "data/scan_ips.csv",
    scan_txt_path: str = "data/scan_ips.txt",
    scan_dir_path: str = "data/scan_ips",
    proxies_txt_path: str = "",
    cf_csv_path: str = "",
    cf_txt_path: str = "",
) -> dict[str, int]:
    """
    全量数据自动化属性校准闭环引擎：
    以 data/asn_database.json 与 classify_asn 为权威唯一真实来源 (SSOT)，
    自动对整个项目中所有持久化数据文件执行网络属性、Cloudflare 入口剔除与元数据校准同步：
    1. 【ip_cache.json】：校准所有持久化 IP 缓存中的 net_type 与标准 ISP 名称
    2. 【data/proxies/ 与 data/proxies.csv】：重新核算 net_type 与 ASN 标准格式，剔除 Cloudflare 入口，重建 .csv/.txt/.json
    3. 【data/proxyip.csv & data/proxyip/】：剔除 Cloudflare 入口并按统一出口口径校准 ProxyIP 属性，自动将校准为 datacenter 的非 CF 节点移入 scan_ips.csv，重建 proxyip 产出
    4. 【data/cf_ips.csv & data/scan_ips.csv】：剔除 Cloudflare 入口节点，使用本地 ip_cache 纠偏并重建对应输出文件
    返回各校准项变更计数统计字典。
    """
    # 0. 兜底扫描并自动收录所有数据集中可能遗漏的新 ASN（跳过 Cloudflare 入口）
    unrec_map_cal: dict[str, dict] = {}
    for ds_path in (proxies_csv_path, proxyip_csv_path):
        if os.path.isfile(ds_path):
            try:
                with open(ds_path, "r", encoding="utf-8-sig") as f:
                    for row in csv.DictReader(f):
                        for asn_val, isp_val, ip_val in (
                            (row.get("exit_asn", ""), row.get("exit_isp", ""), row.get("exit_ip") or row.get("ip", "")),
                            (row.get("asn", ""), row.get("isp", ""), row.get("host") or row.get("ip", "")),
                        ):
                            if is_cloudflare_ip(ip_val) or is_cloudflare_asn_or_isp(asn_val, isp_val):
                                continue
                            c = _extract_asn_code(asn_val, isp_val)
                            if c and not is_asn_recorded(c):
                                if c not in unrec_map_cal:
                                    unrec_map_cal[c] = {
                                        "asn": c,
                                        "isp": isp_val,
                                        "ip": ip_val,
                                        "count": 0,
                                    }
                                unrec_map_cal[c]["count"] += 1
            except Exception:
                pass
    enriched_count = 0
    if unrec_map_cal:
        enriched_count = auto_enrich_and_save_asns(list(unrec_map_cal.values()))
        if enriched_count > 0:
            log.info("【全量校准】自动捕获并沉淀入库 %d 个未收录 ASN", enriched_count)
            classify_asn.cache_clear()

    classify_asn.cache_clear()
    stats = {
        "asns_enriched": enriched_count,
        "ip_cache_updated": 0,
        "proxies_csv_updated": 0,
        "proxies_sub_updated": 0,
        "proxyip_csv_updated": 0,
        "proxyip_demoted_to_scan": 0,
        "proxyip_files_written": 0,
        "cf_removed": 0,
        "proxies_cf_removed": 0,
        "proxyip_cf_removed": 0,
        "cf_ips_cf_removed": 0,
        "scan_ips_cf_removed": 0,
    }

    # 1. 校准 data/ip_cache.json
    cache: dict[str, dict] = {}
    if os.path.isfile(ip_cache_path):
        try:
            cache = load_ip_cache(filepath=ip_cache_path)
            updated_cache = 0
            for ip, info in cache.items():
                if not isinstance(info, dict):
                    continue
                asn = info.get("asn", "")
                isp = info.get("isp", "")
                if _extract_asn_code(asn, isp):
                    correct_nt = classify_asn(asn, isp)
                    if correct_nt and info.get("net_type") != correct_nt:
                        info["net_type"] = correct_nt
                        updated_cache += 1
            if updated_cache > 0:
                save_ip_cache(cache, filepath=ip_cache_path, compact=True)
                stats["ip_cache_updated"] = updated_cache
                log.info("【全量校准】已校准 ip_cache.json 中 %d 个节点的网络属性", updated_cache)
        except Exception as e:
            log.warning("校准 ip_cache.json 异常: %s", e)

    # 2. 校准 data/proxies.csv 与 data/proxies/
    if os.path.isfile(proxies_csv_path):
        try:
            rows = []
            with open(proxies_csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                p_fields = list(reader.fieldnames or [])
                if not p_fields or "url" not in p_fields:
                    raise ValueError(f"{proxies_csv_path} 表头无效或文件为空（缺失必需列 url: {p_fields}）")
                rows = list(reader)
            cache, rescued_proxies = rescue_mislabeled_cloudflare_rows(
                rows,
                ip_cache=cache,
                persist=bool(ip_cache_path),
                cache_path=ip_cache_path,
            )

            changed_proxies = rescued_proxies
            clean_rows = []
            dropped_edt_dc = 0
            dropped_cf_proxies = 0
            for r in rows:
                if is_cloudflare_node(r, cache):
                    dropped_cf_proxies += 1
                    changed_proxies += 1
                    continue

                code = _extract_asn_code(r.get("asn"), r.get("isp"))
                isp_val = r.get("isp") or ""
                correct_nt = ""
                if code:
                    std_isp = ASN_TO_PROVIDER.get(code) or ASN_DATABASE_ASN_TO_ISP.get(code) or isp_val
                    if std_isp and not isp_val:
                        r["isp"] = std_isp
                    r["asn"] = format_asn_isp(code, r.get("isp", ""))
                    correct_nt = classify_asn(code, r.get("isp", ""))
                    if correct_nt and r.get("net_type") != correct_nt:
                        r["net_type"] = correct_nt
                        changed_proxies += 1
                else:
                    correct_nt = str(r.get("net_type") or "").strip().lower()

                # 准入规则：除了频道（@ 开头）和用户自留提供者 (@user / user / manual / custom)，
                # 其余所有外部来源 (EDT-Pages, vpngate, proxifly, subscription 等) 均严格过滤机房节点，
                # 若校准裁决为 datacenter 坚决剔除淘汰！
                src_val = str(r.get("source") or "").strip()
                eff_nt = correct_nt or str(r.get("net_type") or "").strip().lower()
                if not is_channel_or_user_source(src_val) and eff_nt == "datacenter":
                    dropped_edt_dc += 1
                    changed_proxies += 1
                    log.info("【全量校准 准入拦截】清理非频道/非用户来源的机房节点: %s (%s, 来源: %s)", r.get("url"), r.get("asn"), src_val)
                    continue

                clean_rows.append(r)

            if dropped_cf_proxies > 0:
                log.info("【全量校准 CF 拦截】清理剔除 %d 个 Cloudflare 入口通用代理节点", dropped_cf_proxies)
                stats["proxies_cf_removed"] = dropped_cf_proxies
                stats["cf_removed"] += dropped_cf_proxies
            if dropped_edt_dc > 0:
                log.info("【全量校准 准入拦截】共清理剔除 %d 个外部来源的机房 (datacenter) 节点", dropped_edt_dc)
            rows = clean_rows

            if changed_proxies > 0 or not proxies_only:
                save_proxies_csv(rows, csv_path=proxies_csv_path)
                stats["proxies_csv_updated"] = changed_proxies
                eff_proxies_txt = proxies_txt_path or os.path.join(os.path.dirname(proxies_csv_path), "proxies.txt")
                if eff_proxies_txt and (proxies_txt_path or os.path.isfile(eff_proxies_txt)):
                    atomic_write_text(eff_proxies_txt, format_proxies_txt(rows))
                if proxies_dir and os.path.isdir(proxies_dir):
                    sub_counts = save_proxies_by_protocol(rows, output_dir=proxies_dir)
                    stats["proxies_sub_updated"] = sum(sub_counts.values())
                    log.info("【全量校准】已校准并在 %s/ 重建 %d 个协议节点 (更新 %d 条)", proxies_dir, sum(sub_counts.values()), changed_proxies)
        except Exception as e:
            log.warning("校准 proxies 数据异常: %s", e)

    if proxies_only:
        return stats

    # 3. 校准 data/proxyip.csv 与 data/proxyip/ (剔除 Cloudflare 入口 + 统一出口口径 + 非 CF 机房节点自动归入 scan_ips)
    if os.path.isfile(proxyip_csv_path):
        try:
            proxyip_rows = []
            orig_fields: list[str] = []
            with open(proxyip_csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                orig_fields = list(reader.fieldnames or [])
                if not orig_fields or "ip" not in orig_fields or "port" not in orig_fields:
                    raise ValueError(f"{proxyip_csv_path} 表头无效或文件为空（缺失必需列 ip/port: {orig_fields}）")
                proxyip_rows = list(reader)
            cache, rescued_proxyip = rescue_mislabeled_cloudflare_rows(
                proxyip_rows,
                ip_cache=cache,
                persist=bool(ip_cache_path),
                cache_path=ip_cache_path,
            )

            schema_upgraded = orig_fields != PROXYIP_CSV_FIELDS
            changed_proxyip = rescued_proxyip
            dropped_cf_proxyip = 0
            clean_proxyip_rows: list[dict] = []
            dc_demoted_rows: list[dict] = []

            for r in proxyip_rows:
                raw_fs = str(r.get("first_seen") or "").strip()
                raw_ch = str(r.get("channel") or "").strip()
                if re.match(r"^\d{4}-\d{2}-\d{2}", raw_ch) and not re.match(r"^\d{4}-\d{2}-\d{2}", raw_fs):
                    r["first_seen"] = normalize_timestamp(raw_ch)
                    r["channel"] = ""
                    changed_proxyip += 1

                row_ip = str(r.get("ip") or "").strip()
                ing_code_pre = _extract_asn_code(r.get("asn"), r.get("isp"))
                if row_ip and row_ip in cache and isinstance(cache[row_ip], dict):
                    c_code = _extract_asn_code(cache[row_ip].get("asn"), cache[row_ip].get("isp"))
                    c_isp = str(cache[row_ip].get("isp") or "").strip() or ASN_TO_PROVIDER.get(c_code, "")
                    if c_code and (not ing_code_pre or (is_cloudflare_asn_or_isp(ing_code_pre, r.get("isp", "")) and not is_cloudflare_asn_or_isp(c_code, c_isp))):
                        r["asn"] = format_asn_isp(c_code, c_isp)
                        r["isp"] = c_isp
                        changed_proxyip += 1

                if is_cloudflare_node(r, cache):
                    dropped_cf_proxyip += 1
                    changed_proxyip += 1
                    continue

                cand_exits = extract_ips([r.get("exit_ip"), r.get("exit_ipv6")])
                v4_exits = [cip for cip in cand_exits if is_valid_ipv4(cip)]
                v6_exits = [cip for cip in cand_exits if is_valid_ipv6(cip)]
                new_exit_ip = v4_exits[0] if v4_exits else (v6_exits[0] if v6_exits else "")
                new_exit_v6 = v6_exits[0] if v6_exits else ""
                if (r.get("exit_ip") or "") != new_exit_ip or (r.get("exit_ipv6") or "") != new_exit_v6:
                    r["exit_ip"] = new_exit_ip
                    r["exit_ipv6"] = new_exit_v6
                    changed_proxyip += 1

                is_p, correct_nt, exit_code, exit_isp = resolve_node_exit_and_net_type(r, cache)
                ing_code = _extract_asn_code(r.get("asn"), r.get("isp"))
                ing_isp = str(r.get("isp") or "").strip()

                if ing_code:
                    std_ing_isp = ASN_TO_PROVIDER.get(ing_code) or ASN_DATABASE_ASN_TO_ISP.get(ing_code) or ing_isp
                    if std_ing_isp and not ing_isp:
                        r["isp"] = std_ing_isp
                    r["asn"] = format_asn_isp(ing_code, r.get("isp", ""))
                elif exit_code and not is_cloudflare_asn_or_isp(exit_code, exit_isp):
                    r["isp"] = exit_isp
                    r["asn"] = format_asn_isp(exit_code, exit_isp)

                if exit_code:
                    r["exit_isp"] = exit_isp
                    r["exit_asn"] = format_asn_isp(exit_code, exit_isp)
                else:
                    r["exit_asn"] = ""
                    r["exit_isp"] = ""

                if correct_nt and r.get("net_type") != correct_nt:
                    r["net_type"] = correct_nt
                    changed_proxyip += 1

                if not is_p or r.get("net_type") == "datacenter":
                    dc_demoted_rows.append(r)
                else:
                    clean_proxyip_rows.append(r)

            if dropped_cf_proxyip > 0:
                log.info("【全量校准 CF 拦截】从 proxyip.csv 剔除 %d 条 Cloudflare 入口节点", dropped_cf_proxyip)
                stats["proxyip_cf_removed"] = dropped_cf_proxyip
                stats["cf_removed"] += dropped_cf_proxyip

            if dc_demoted_rows:
                demoted_cnt = merge_demoted_into_scan_ips(
                    dc_demoted_rows,
                    scan_csv_path=scan_csv_path,
                    scan_txt_path=scan_txt_path,
                    scan_dir_path=scan_dir_path,
                )
                stats["proxyip_demoted_to_scan"] = len(dc_demoted_rows)
                log.info("【全量校准】检测到 %d 条 ProxyIP 节点经校准属于机房属性 (并入 scan_ips: %d 条)", len(dc_demoted_rows), demoted_cnt)

            if changed_proxyip > 0 or dc_demoted_rows or dropped_cf_proxyip > 0 or schema_upgraded:
                with atomic_writer(proxyip_csv_path, encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=PROXYIP_CSV_FIELDS, extrasaction="ignore")
                    writer.writeheader()
                    for r in clean_proxyip_rows:
                        writer.writerow(r)
                if proxyip_txt_path:
                    atomic_write_text(proxyip_txt_path, format_proxyip_txt(clean_proxyip_rows))
                if proxyip_json_path:
                    save_proxyip_json(clean_proxyip_rows, json_path=proxyip_json_path)
                stats["proxyip_csv_updated"] = changed_proxyip + len(dc_demoted_rows)

            if proxyip_dir:
                written_files = save_proxyip_by_country(clean_proxyip_rows, output_dir=proxyip_dir)
                stats["proxyip_files_written"] = written_files
                log.info("【全量校准】已校准 proxyip.csv (保留非机房 %d 条, 移出机房 %d 条, 属性更新 %d 条)，并在 %s/ 生成 %d 个分流文件", len(clean_proxyip_rows), len(dc_demoted_rows), changed_proxyip, proxyip_dir, written_files)
        except Exception as e:
            log.error("校准 proxyip 数据异常，保留现有分组文件并中止校准: %s", e)
            raise

    # 3.5 校准 data/cf_ips.csv 与 data/scan_ips.csv（剔除 Cloudflare 入口，保留非 CF + WARP 出站第三方节点）
    eff_cf_csv = cf_csv_path or (os.path.join(os.path.dirname(scan_csv_path), "cf_ips.csv") if scan_csv_path else "")
    if eff_cf_csv and os.path.isfile(eff_cf_csv):
        try:
            with open(eff_cf_csv, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                cf_fields = list(reader.fieldnames or [])
                cf_rows_raw = list(reader) if ("ip" in cf_fields and "port" in cf_fields) else []
            cache, rescued_cf = rescue_mislabeled_cloudflare_rows(
                cf_rows_raw,
                ip_cache=cache,
                persist=bool(ip_cache_path),
                cache_path=ip_cache_path,
            )
            clean_cf_rows: list[dict] = []
            dropped_cf_ips = 0
            for r in cf_rows_raw:
                if is_cloudflare_node(r, cache):
                    dropped_cf_ips += 1
                    continue
                clean_cf_rows.append(r)
            if dropped_cf_ips > 0 or rescued_cf > 0:
                with atomic_writer(eff_cf_csv, encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=CF_BASE_CSV_FIELDS, extrasaction="ignore")
                    writer.writeheader()
                    for r in clean_cf_rows:
                        writer.writerow(r)
                eff_cf_txt = cf_txt_path or os.path.join(os.path.dirname(eff_cf_csv), "cf_ips.txt")
                if eff_cf_txt and (cf_txt_path or os.path.isfile(eff_cf_txt)):
                    with atomic_writer(eff_cf_txt, encoding="utf-8") as f:
                        for r in clean_cf_rows:
                            ip = str(r.get("ip") or "").strip()
                            port = safe_int(r.get("port"), 0)
                            if ip and 1 <= port <= 65535:
                                f.write(f"{ip}:{port}\n")
                if dropped_cf_ips > 0:
                    stats["cf_ips_cf_removed"] = dropped_cf_ips
                    stats["cf_removed"] += dropped_cf_ips
                    log.info("【全量校准 CF 拦截】从 %s 剔除 %d 条 Cloudflare 入口单条优选记录", eff_cf_csv, dropped_cf_ips)
        except Exception as e:
            log.warning("校准 %s 异常: %s", eff_cf_csv, e)

    if scan_csv_path and os.path.isfile(scan_csv_path):
        try:
            with open(scan_csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                scan_fields = list(reader.fieldnames or [])
                scan_rows_raw = list(reader) if ("ip" in scan_fields and "port" in scan_fields) else []
            cache, rescued_scan = rescue_mislabeled_cloudflare_rows(
                scan_rows_raw,
                ip_cache=cache,
                persist=bool(ip_cache_path),
                cache_path=ip_cache_path,
            )
            clean_scan_rows: list[dict] = []
            dropped_cf_scan = 0
            scan_asn_fixed = rescued_scan
            for r in scan_rows_raw:
                ip = str(r.get("ip") or "").strip()
                ing_code = _extract_asn_code(r.get("asn"), r.get("isp"))
                if ip and ip in cache and isinstance(cache[ip], dict):
                    c_code = _extract_asn_code(cache[ip].get("asn"), cache[ip].get("isp"))
                    c_isp = str(cache[ip].get("isp") or "").strip() or ASN_TO_PROVIDER.get(c_code, "")
                    if c_code and (not ing_code or (is_cloudflare_asn_or_isp(ing_code, r.get("isp", "")) and not is_cloudflare_asn_or_isp(c_code, c_isp))):
                        r["asn"] = format_asn_isp(c_code, c_isp)
                        r["isp"] = c_isp
                        scan_asn_fixed += 1
                if is_cloudflare_node(r, cache):
                    dropped_cf_scan += 1
                    continue
                r["fail_count"] = safe_int(r.get("fail_count"), 0)
                clean_scan_rows.append(r)

            stale_cf_files = (
                scan_dir_path
                and os.path.isdir(scan_dir_path)
                and any(
                    fn.endswith(".txt") and any(fn.upper().startswith(a) for a in CLOUDFLARE_ASNS)
                    for fn in os.listdir(scan_dir_path)
                )
            )
            if dropped_cf_scan > 0 or scan_asn_fixed > 0 or stale_cf_files:
                _write_scan_ips_outputs(
                    clean_scan_rows,
                    scan_csv_path=scan_csv_path,
                    scan_txt_path=scan_txt_path,
                    scan_dir_path=scan_dir_path,
                )
                stats["scan_ips_cf_removed"] = dropped_cf_scan
                stats["cf_removed"] += dropped_cf_scan
                log.info("【全量校准 CF 拦截】清理 scan_ips.csv: 剔除 Cloudflare 入口 %d 条 (BGP 纠偏 %d 条, 剩余 %d 条)", dropped_cf_scan, scan_asn_fixed, len(clean_scan_rows))
        except Exception as e:
            log.warning("校准 %s 异常: %s", scan_csv_path, e)

    # 4. 终态修剪 ip_cache.json：在全部数据集完成淘汰与分流校准后，剔除已不在活跃库中的孤儿缓存记录
    base_cache_dir = os.path.dirname(os.path.abspath(ip_cache_path))
    if not proxies_only and os.path.isfile(ip_cache_path) and any(
        os.path.isfile(os.path.join(base_cache_dir, fn))
        for fn in ("cf_ips.csv", "scan_ips.csv", "proxyip.csv", "proxies.csv")
    ):
        try:
            stats["ip_cache_pruned"] = prune_ip_cache(filepath=ip_cache_path)
        except Exception as e:
            log.warning("终态修剪 ip_cache.json 异常: %s", e)

    # 5. 墓地机制已彻底解耦：机房拒收节点不再入墓地，入出口画像已完全解耦。
    # 墓地中记录的均为真实超时/不可达的物理死节点，不再执行基于非机房标签的自动解封，
    # 确保死节点严格遵循 7 天隔离冷却期，彻底杜绝死节点诈尸回流。
    stats["tombstone_unbanned"] = 0

    return stats


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
    strict: bool = False,
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
        if not isinstance(data, dict):
            raise ValueError(f"墓地文件顶层结构必须为 JSON 对象 (dict)，实际为 {type(data).__name__}")
        for k, ts in data.items():
            if isinstance(ts, (int, float)) and (now - int(ts)) < max_age_sec:
                valid[str(k).strip().lower()] = int(ts)
        _TOMBSTONE_CACHE = valid
        _TOMBSTONE_CACHE_FILE = target_path
        _TOMBSTONE_CACHE_MTIME = mtime
    except Exception as e:
        if strict:
            log.error("读取墓地文件 %s 失败: %s", target_path, e)
            raise RuntimeError(f"读取墓地文件 {target_path} 失败: {e}") from e
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
        log.error("读取墓地文件 %s 执行修剪失败: %s", target_path, e)
        raise RuntimeError(f"读取墓地文件 {target_path} 执行修剪失败: {e}") from e

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
        try:
            atomic_write_json(target_path, valid)
            _TOMBSTONE_CACHE = valid
            _TOMBSTONE_CACHE_FILE = target_path
            try:
                _TOMBSTONE_CACHE_MTIME = os.path.getmtime(target_path)
            except OSError:
                _TOMBSTONE_CACHE = None
            log.info("已主动修剪墓地文件 %s: 剔除 %d 个超过 %d 天的过期条目 (剩余: %d 个)", target_path, pruned_count, max_age_days, len(valid))
        except Exception as e:
            _TOMBSTONE_CACHE = None
            log.error("写回修剪后的墓地文件 %s 失败: %s", target_path, e)
            raise RuntimeError(f"写回修剪后的墓地文件 {target_path} 失败: {e}") from e

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
    返回本次新增登记的节点数量；若读取或持久化失败则抛出 RuntimeError，确保调用方与流水线感知失败。
    """
    global _TOMBSTONE_CACHE, _TOMBSTONE_CACHE_FILE, _TOMBSTONE_CACHE_MTIME
    if not keys:
        prune_tombstone(filepath=filepath, max_age_days=max_age_days)
        return 0
    if filepath is None:
        filepath = TOMBSTONE_FILE
    now = int(time.time())
    tombstone = load_tombstone(filepath=filepath, max_age_days=max_age_days, strict=True)
    new_count = 0
    for k in keys:
        if not k:
            continue
        clean_k = str(k).strip().lower()
        if clean_k not in tombstone:
            new_count += 1
        tombstone[clean_k] = now

    try:
        atomic_write_json(filepath, tombstone)
        try:
            _TOMBSTONE_CACHE = tombstone
            _TOMBSTONE_CACHE_FILE = filepath
            _TOMBSTONE_CACHE_MTIME = os.path.getmtime(filepath)
        except OSError:
            _TOMBSTONE_CACHE = None
    except Exception as e:
        _TOMBSTONE_CACHE = None
        log.error("写入墓地文件 %s 失败: %s", filepath, e)
        raise RuntimeError(f"写入墓地文件 {filepath} 失败: {e}") from e
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


# =====================================================================
# Check ProxyIP 在线探针 API 适配模块
# =====================================================================
def format_check_proxyip_url(
    base_url: str,
    ip: str,
    port: int,
    timeout_ms: int | None = None,
) -> str:
    """智能格式化 Check ProxyIP 请求 URL，自适应 IPv6 方括号包裹与 timeoutMs 参数透传"""
    if not base_url:
        return ""
    clean_ip = str(ip or "").strip()
    if not clean_ip:
        return ""
    host_part = f"[{clean_ip}]" if (":" in clean_ip and not clean_ip.startswith("[")) else clean_ip
    raw_target = f"{host_part}:{port}"
    encoded_target = urllib.parse.quote(raw_target, safe="")

    u = base_url.strip()
    if "{target}" in u:
        res_url = u.replace("{target}", encoded_target)
    elif "{ip}" in u and "{port}" in u:
        res_url = u.replace("{ip}", urllib.parse.quote(host_part, safe="")).replace("{port}", str(port))
    elif u.endswith("="):
        res_url = f"{u}{encoded_target}"
    elif "?" in u:
        sep = "&" if not u.endswith("&") and not u.endswith("?") else ""
        res_url = f"{u}{sep}proxyip={encoded_target}"
    else:
        u = u.rstrip("/")
        if u.endswith("/check"):
            res_url = f"{u}?proxyip={encoded_target}"
        else:
            res_url = f"{u}/check?proxyip={encoded_target}"

    if timeout_ms and timeout_ms > 0 and "timeoutMs=" not in res_url:
        sep = "&" if "?" in res_url else "?"
        res_url = f"{res_url}{sep}timeoutMs={int(timeout_ms)}"
    return res_url


def probe_check_proxyip_api(
    ip: str,
    port: int,
    endpoint: str = "",
    timeout: float = 6.0,
    token: str = "",
) -> dict:
    """
    通过 Check ProxyIP API 在线探测节点的出口真实 IP、出口 ASN、机房、真实握手延迟与地理位置。
    若 endpoint 留空则使用全局 CHECK_PROXYIP_URL。若未配置任何端点，直接返回 {"success": False}。
    返回字段中的 network_error=True 表示 Worker 自身请求异常/限流/WAF 拦截，以便上游无损降级回退本地探测。
    """
    ep = endpoint or CHECK_PROXYIP_URL
    if not ep:
        return {"success": False, "reason": "no_endpoint", "network_error": True}

    worker_timeout_ms = int(min(max(float(timeout) * 1000.0, 4000.0), 8000.0))
    http_outer_timeout = max(float(timeout) + 8.0, 12.0)

    target_url = format_check_proxyip_url(ep, ip, port, timeout_ms=worker_timeout_ms)
    if not target_url:
        return {"success": False, "reason": "invalid_url", "network_error": False}

    auth_token = token.strip() if token else CHECK_PROXYIP_TOKEN
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Accept": "application/json",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        req = urllib.request.Request(
            target_url,
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=http_outer_timeout) as resp:
            if resp.status != 200:
                return {
                    "success": False,
                    "status": resp.status,
                    "reason": f"worker_http_{resp.status}",
                    "network_error": True,
                }
            content_type = (resp.headers.get("Content-Type") or "").lower()
            raw_body = resp.read()
            if "application/json" not in content_type and not raw_body.strip().startswith(b"{"):
                return {
                    "success": False,
                    "reason": "waf_challenge_or_html_response",
                    "network_error": True,
                }
            try:
                data = json.loads(raw_body.decode("utf-8", errors="ignore"))
            except Exception:
                return {"success": False, "reason": "invalid_json", "network_error": True}
            if not isinstance(data, dict):
                return {"success": False, "reason": "invalid_json", "network_error": True}

            has_probe_results = isinstance(data.get("probe_results"), dict)
            probe = data.get("probe_results") if has_probe_results else {}
            v4_obj = probe.get("ipv4", {}) if isinstance(probe.get("ipv4"), dict) else {}
            v6_obj = probe.get("ipv6", {}) if isinstance(probe.get("ipv6"), dict) else {}
            v4_exit = v4_obj.get("exit") if isinstance(v4_obj.get("exit"), dict) else {}
            v6_exit = v6_obj.get("exit") if isinstance(v6_obj.get("exit"), dict) else {}
            fallback_exit = data.get("exit") if isinstance(data.get("exit"), dict) else {}

            v4_ip = str(v4_exit.get("ip") or v4_exit.get("ipAddress") or "").strip()
            v6_ip = str(v6_exit.get("ip") or v6_exit.get("ipAddress") or "").strip()
            fb_ip = str(fallback_exit.get("ip") or fallback_exit.get("ipAddress") or data.get("exit_ip") or "").strip()

            if not v4_ip and fb_ip and is_valid_ipv4(fb_ip):
                v4_ip = fb_ip
            if not v6_ip and fb_ip and is_valid_ipv6(fb_ip):
                v6_ip = fb_ip

            dual_stack = bool(data.get("dual_stack")) or bool(v4_ip and v6_ip)
            supports_v4 = bool(data.get("supports_ipv4")) or bool(v4_ip)
            supports_v6 = bool(data.get("supports_ipv6")) or bool(v6_ip)

            primary_exit_ip = v4_ip or v6_ip or fb_ip
            primary_info = v4_exit if v4_ip else (v6_exit if v6_ip else fallback_exit)
            primary_probe = v4_obj if v4_ip else (v6_obj if v6_ip else {})

            is_ok = bool(data.get("success", False)) or bool(primary_exit_ip)
            if not is_ok:
                err_detail = str(v4_obj.get("error") or v6_obj.get("error") or data.get("error") or "").strip()
                return {
                    "success": False,
                    "reason": "worker_probe_failed",
                    "detail": err_detail,
                    "network_error": False,
                }

            exit_asn = primary_info.get("asn") or data.get("exit_asn") or ""
            exit_isp = primary_info.get("asOrganization") or primary_info.get("org") or data.get("exit_isp") or ""
            # CF-Workers-CheckProxyIP 顶层 data.colo 为 Worker 自身边缘节点 (req.cf.colo)，必须优先取穿透出口 primary_info.colo
            if has_probe_results:
                colo = primary_info.get("colo") or probe.get("colo") or ""
            else:
                colo = primary_info.get("colo") or data.get("colo") or ""
            country = primary_info.get("country") or data.get("country") or ""
            city = primary_info.get("city") or data.get("city") or ""

            c_ms = primary_probe.get("connect_ms")
            t_ms = primary_probe.get("tls_ms")
            resp_ms = data.get("responseTime")
            if isinstance(c_ms, (int, float)) and c_ms >= 0 and isinstance(t_ms, (int, float)) and t_ms >= 0:
                probe_delay_ms = max(1, int(round(c_ms + t_ms)))
            elif isinstance(c_ms, (int, float)) and c_ms > 0:
                probe_delay_ms = max(1, int(round(c_ms)))
            elif isinstance(resp_ms, (int, float)) and resp_ms > 0:
                probe_delay_ms = max(1, int(round(resp_ms)))
            else:
                probe_delay_ms = 0

            asn_code = _extract_asn_code(str(exit_asn), str(exit_isp))
            exit_asn_norm = asn_code or ""
            net_type = classify_asn(exit_asn_norm, exit_isp) if exit_asn_norm else ""

            all_exit_ips = [x for x in (v4_ip, v6_ip) if x]
            if not all_exit_ips and primary_exit_ip:
                all_exit_ips = [primary_exit_ip]

            return {
                "success": True,
                "network_error": False,
                "delay_ms": probe_delay_ms,
                "connect_ms": c_ms,
                "tls_ms": t_ms,
                "response_time": resp_ms,
                "exit_ip": str(primary_exit_ip).strip(),
                "exit_ipv4": str(v4_ip).strip(),
                "exit_ipv6": str(v6_ip).strip(),
                "exit_ips": all_exit_ips,
                "dual_stack": dual_stack,
                "supports_ipv4": supports_v4,
                "supports_ipv6": supports_v6,
                "exit_asn": exit_asn_norm,
                "exit_isp": str(exit_isp).strip(),
                "colo": str(colo).strip().upper(),
                "country": str(country).strip(),
                "city": str(city).strip(),
                "net_type": net_type,
            }
    except urllib.error.HTTPError as he:
        return {
            "success": False,
            "status": he.code,
            "reason": f"worker_http_{he.code}",
            "network_error": True,
        }
    except Exception as e:
        return {
            "success": False,
            "reason": f"request_error_{type(e).__name__}",
            "network_error": True,
        }


if __name__ == "__main__":
    import sys
    if "--calibrate" in sys.argv:
        print("[*] 正在执行全量数据自动化属性校准...")
        cal_stats = calibrate_all_datasets()
        print("[+] 全量校准执行完毕:")
        for k, v in cal_stats.items():
            print(f"  - {k}: {v}")
        sys.exit(0)
    elif "--validate" in sys.argv or len(sys.argv) == 1:
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
