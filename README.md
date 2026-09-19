# TG-Proxy-Fetcher —— Telegram 代理与 Cloudflare 优选 IP 自动化同步工具

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-2088FF?logo=github-actions&logoColor=white)](https://github.com/skfoa/tg-proxy-fetcher/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)

每天自动从 Telegram 优质公开频道（[@otcfxq](https://t.me/otcfxq)、[@danfeng2](https://t.me/danfeng2)）抓取多协议代理节点、Cloudflare 优选 IP 以及反代 ProxyIP。系统具备**智能增量持久化**、**全局智能去重**与**三大主动质检淘汰机制**，自动导出通用代理列表、纯净 `IP:端口` 文本列表以及结构化测速数据表格，并通过 GitHub Actions 每天定时自动执行四阶段质检流水线并推送到仓库。

---

## ⚡ 运行模式与能力对比

系统采用**双引擎驱动**架构。了解不同模式的能力边界，有助于按需选择配置：

| 特性 / 产物 | 🚀 免登录 Web 模式<br>(零门槛开箱即用) | 🛡️ 官方 API 模式<br>(全功能完整版 · 强烈推荐) |
| :--- | :---: | :---: |
| **运行门槛** | **无需任何密钥或账号**<br>Fork 仓库开启 Actions 即可全自动运行 | **需配置 3 项 Secret**<br>`TG_API_ID`、`TG_API_HASH`、`TG_SESSION_STR` |
| **底层原理** | 爬取 Telegram 公开网页预览 (`t.me/s/`) | 启用 Telethon 客户端直连 MTProto 协议 |
| **正文通用代理 (`data/socks5.txt`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道正文单条优选 (`data/cf_ips.*`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道附件自动下载解析** | ❌ **不支持**（网页端无附件下载接口） | ✅ **完全支持自动下载解析** |
| **批量扫描大池 (`data/scan_ips/`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析 OTC/DanFeng 测速附件 |
| **反代 ProxyIP 池 (`data/proxyip.*`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析反代文件附件 |
| **全协议鉴真与缓冲淘汰** | ✅ 支持（对抓取到的正文节点鉴真） | ✅ 全量支持（覆盖正文与海量附件大池） |
| **适用场景** | 快速验证、仅需基础正文代理与单条 IP | 正式部署、需要海量机房扫描池与反代池 |

---

## 🌟 核心特性亮点

- **🚀 免登录基础模式**：未配置 API 凭据时自动启用，零门槛抓取频道消息正文中的通用代理与单条优选 IP。
- **🛡️ 官方 API 全功能模式**：配置 `TG_API_ID`、`TG_API_HASH` 与 `TG_SESSION_STR` 后自动激活，解锁频道附件自动下载，获取千条级机房扫描 IP 与反代池。
- **📦 智能增量持久化与缓冲保护**：历史抓取的有效节点自动累积留存，新节点自动追加去重，同时引入公网抖动缓冲保护（连续 2 次全网不可达方才剔除死节点），兼顾大池沉淀与高可用纯净度。
- **🔍 跨文件严格唯一去重**：以 `IP:端口` 为全局主键，新老文件重复提取自动刷新覆盖，绝无重复行；IP 归属更正时自动迁移所属 ASN 文件。
- **📁 智能 ASN 分组与命名**：
  - **DanFeng 测速**：CSV 内部无 ASN 列时自动从文件名（如 `AS45102_CNNICALIBABACNNETAP_*.csv`）解析归类。
  - **OTC 优选扫描**：单 ASN 文件以文件名目标 ASN 为准；混合扫描文件（如 `OTC_SCAN_YX_杂.txt`）自动逐行提取具体 ASN 与 ISP 拆分归类。
- **⚡ 纯净 IP:端口 列表导出**：自动导出纯文本格式的 `IP:端口` 列表（`data/cf_ips.txt`、`data/scan_ips/*.txt`、`data/proxyip.txt`），方便直接复制或作为远程订阅导入。
- **🧩 模块化解耦与确定性分段锁**：提取独立 `providers.py` 作为云厂商与 ASN 规范化字典的单一真相源（Single Source of Truth）；内置基于 `zlib.crc32` 的 2048 桶位确定性哈希分段锁池（`get_keyed_lock`），保证同 IP 严格互斥防风控、异 IP 高并发并行，且内存严格维持在常数级 $O(1)$（约 300KB），杜绝无界增长。
- **💡 未收录 ASN 动态发现与自适应预警**：增量抓取遇外部新自治系统时，自动比对内置权威对照库；若发现未收录 ASN，将在 Telegram 卡片中动态高亮提示并展示待确认明细，方便一键入库；若无未知 ASN 则 0 噪音完全隐藏。
- **📱 动态双状态 Telegram 运行卡片**：首行支持「🟢 发现新增 + 🗑️ 剔除死节点」双状态动态高亮呈现，底栏包含细分引擎淘汰明细 `[代理 X, 反代 Y, 扫描 Z]`，锁屏即知变动。
- **🛡️ 静态安全门禁与故障秒级告警**：工作流启动 1 秒内通过 `py_compile` 与 `ruff` 拦截未定义变量与语法错误；若流水线任何环节异常中断，自动秒级推送 Telegram 告警卡片并附带日志直链。
- **🧹 自动维护与构建瘦身**：每次运行自动清理 GitHub Actions 历史记录，始终**仅保留最近 5 次运行记录**，告别冗余历史堆积！

---

## 架构与工作流程

```text
                                     Telegram 公开频道
                          ┌─── @otcfxq ────────┐
                          │   (代理 + 优选IP)  │
    tg_fetch.py ──────────┤                    ├────► 增量抓取 & 全局智能去重 ──┬──► data/socks5.txt / socks5.csv
    (免登录/官方API双模)   │                    │                               ├──► data/cf_ips.txt / cf_ips.csv
                          └─── @danfeng2 ──────┘                               ├──► data/scan_ips.txt / scan_ips.csv
                               (优选IP 专属)                                     ├──► data/scan_ips/AS{ASN}_{ISP}.txt *
                                                                                ├──► data/proxyip.txt / proxyip.csv *
                                    ▲                                           └──► data/proxyip_cf.txt *
                                    │ 统一接入公共映射
                              providers.py
                     (云厂商 & ASN 规范化单一真相源)
                                    │ 统一接入公共映射
                                    ▼
                            四阶段流水线主动鉴真与淘汰引擎
  ┌───────────────────────┬─────────────────────────┬─────────────────────────┐
  ▼                       ▼                         ▼                         ▼
Step 1: tg_fetch        Step 2: socks_verify      Step 3: proxyip_verify    Step 4: cf_verify
多协议增量抓取          RFC 1928 全协议质检       /cdn-cgi/trace 穿透       全量优选 TLS+301 鉴真
全局唯一去重合并        SOCKS5/HTTP/TURN 穿透     + TLS 1.3 优选直连提纯    + 全局四合一 TG 统一卡片

* 注：标记 * 的扫描机房大池与反代池需配置【官方 API 模式】方可自动下载获取。
```

### 核心模块清单

| 模块文件 | 定位与职责 |
| :--- | :--- |
| **`tg_fetch.py`** | **数据抓取与合并核心**：实现免登录 Web 爬虫与 Telethon API 双模抓取，跨文件全局唯一去重合并保存至 `data/`。 |
| **`parsers.py`** | **文本与协议解析器模块**：提取通用代理正则、单条优选卡片、测速 CSV 附件、OTC 扫描清单等解析规则，全面解耦数据提取与业务流。 |
| **`providers.py`** | **公共规范与网络分类中心**：全系统单一真相源（Single Source of Truth），维护云厂商与关键 ASN 映射表、两级分层网络分类引擎（Tier 1 权威对照 + Tier 2 词根规则）、未收录 ASN 检测，以及 ProxyIP 分国别与特殊网络分类导出工具。 |
| **`socks_verify.py`** | **通用代理主动质检引擎**：基于 RFC 1928 (readexactly 精确字节读取)、RFC 5389 (STUN/TURN Binding) 与 HTTP CONNECT 穿透检验。 |
| **`proxyip_verify.py`** | **反代 ProxyIP 质检引擎**：验证反代真实穿透能力，并提纯兼具 TLS 官方优选直连的极品清单 `data/proxyip_cf.txt`。 |
| **`cf_verify.py`** | **全量优选 IP 鉴真与最终卡片推送**：执行 TLS 官方证书鉴真 + HTTP 301 重定向校验，汇总流水线所有阶段数据并推送统一 TG 统计卡片。 |
| **`gen_session.py`** | **Telethon Session 辅助生成器**：本地运行快速交互登录 Telegram 并输出 Session 字符串，供 GitHub Actions 免交互调用。 |

---

## 产物清单与订阅直链

所有数据产物集中收纳于 **`data/`** 目录，保持根目录代码纯净：

| 文件名 | 内容说明 | 生成条件 | GitHub Raw 永久直链（点击即可导入） |
| :--- | :--- | :---: | :--- |
| **`data/socks5.txt`** | 质检存活的多协议通用代理清单（纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/socks5.txt` |
| **`data/socks5.csv`** | 代理质检数据表（协议/延迟/fail_count/机房） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/socks5.csv` |
| **`data/cf_ips.txt`** | 频道日常单条优选 IP（纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/cf_ips.txt` |
| **`data/cf_ips.csv`** | 频道日常单条优选 IP（数据表） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/cf_ips.csv` |
| **`data/scan_ips.txt`** | 扫描测速总清单（按 ASN 分组） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips.txt` |
| **`data/scan_ips/*.txt`** | 独立 ASN + 厂商纯文本列表（单文件） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips/AS{ASN}_{ISP}.txt` |
| **`data/scan_ips.csv`** | 扫描测速优选 IP（数据表） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips.csv` |
| **`data/proxyip.txt`** | 反代 ProxyIP 总清单（按国家/地区分类，纯文本） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.txt` |
| **`data/proxyip/*.txt`** | 独立国家/地区纯净反代列表（如 `美国.txt`、`日本.txt`） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip/{地区}.txt` |
| **`data/proxyip/【...】.txt`** | 稀缺网络属性独立反代列表（原生宽带/商业/教育/政务） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip/【ISP_运营商原生宽带】.txt` 等 |
| **`data/proxyip.csv`** | 反代 ProxyIP 详细数据表（含 `net_type` 网络分类） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.csv` |
| **`data/proxyip_cf.txt`** | 兼具优选直连特性的提纯反代总清单（按国家分类） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip_cf.txt` |
| **`data/proxyip_cf/*.txt`** | 兼具优选直连特性的独立国家/地区纯净反代列表 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip_cf/{地区}.txt` |
| **`data/proxyip_cf/【...】.txt`** | 兼具优选直连特性的稀缺网络属性反代列表 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip_cf/【ISP_运营商原生宽带】.txt` 等 |

---

## 支持提取的节点与内容类型

1. **通用标准代理 URL**：
   - `socks5://...`、`http://...`、`https://...`（兼容免密与带账号密码认证）
2. **TURN 穿透协议节点**：
   - `turn://114.34.87.173:3479#TW...`（自动识别 `turn://` 协议，智能剥离测速后缀与中文标签）
3. **Telegram 官方 SOCKS5 一键直连链接**：
   - `tg://socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - `https://t.me/socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - 自动无损转换为通用标准 `socks5://user:pass@ip:port` 格式，支持任意第三方客户端直接导入。
4. **开放代理/服务通报消息（已做防污染隔离）**：
   - `[发现开放 HTTP 代理] 174.138.165.213:34887` ➔ 自动补全为 `http://174.138.165.213:34887`
   - `[发现开放 HTTPS 代理] https://121.42.225.20:443#CN` ➔ 自动提取为 `https://121.42.225.20:443`
   - `[发现开放 SOCKS5 代理] IP:Port` ➔ 自动补全为 `socks5://IP:Port`
   - `[发现开放 TURN 代理/服务] IP:Port 或 turn://IP:Port` ➔ 自动提取为 `turn://IP:Port`
   - 🛡️ **防污染机制**：通报消息后半段附带的第三方 SNI 测试目标域名（如 `域名:https://hf.molikuaiyin.com:443...`）会被自动精准过滤，确保代理库 100% 纯净。
5. **代理附件文件自动解析（需官方 API 模式）**：
   - 自动识别频道发布的代理附件文件（如 `http_proxies.txt`、`https_proxies.txt`、`turn_proxies.txt` 等）。
   - 自动提取行首有效节点与认证信息，过滤后续测速说明与反向 PTR 域名别名，统一去重合并至 `data/socks5.txt`。
6. **Cloudflare 优选 IP 与反代池（需官方 API 模式）**：
   - 提取包含 IP、端口、TLS、网络延迟（纯数值 ms）、下载速度（纯数值 kB/s）、数据中心（Colo）、落地位置、ASN、运营商、测速时间等全量指标。

---

## 输出产物与去重规则详细说明

### 1. `data/socks5.txt` / `data/socks5.csv`（通用代理节点清单与质检表）
* **智能增量合并**：每次抓取优先比对历史库，新发布的节点自动追加并去重，以 `host:port` 为唯一标识刷新认证与配置。
* **主动质检淘汰（`socks_verify.py`）**：集成 RFC 1928（SOCKS5 协商/认证/CONNECT 隧道穿透）、RFC 5389（STUN/TURN Binding 鉴真）、HTTP CONNECT 穿透全套真实网络协议握手引擎。
* **连续失败缓冲保护（`--max-fails 3`）**：首次探测失败标记缓冲（`fail_count=1`），连续 3 次全网不可达方才彻底剔除，避免公网抖动误杀。
* **双模持久化**：
  - `data/socks5.txt`：纯文本每行一个可用节点 URL，开箱即用。
  - `data/socks5.csv`：结构化表格，包含协议类型、测速延迟（ms）、连续失败次数、Cloudflare Colo 数据中心与质检时间戳。

### 2. `data/cf_ips.txt` / `data/cf_ips.csv`（频道日常单条优选 IP）
* 仅收录频道日常消息正文中发布的单条优选 IP（如 `@danfeng2`、`@otcfxq` 的实时测速通报）。
* `data/cf_ips.txt` 为纯文本格式，每行一个 `IP:端口`。
* `data/cf_ips.csv` 为 UTF-8-SIG 结构化表格，可直接用 Excel 查看。

### 3. 扫描文件优选 IP（按 ASN 智能去重与分组）
* **与单条日常 IP 物理隔离**：独立收录来自测速扫描附件（如 OTC 的 `OTC_SCAN_YX_*.txt`、DanFeng 的 `AS*.csv` 与云厂商测速 `Aliyun.csv`/`Tencent.csv`/`DMIT.csv`/`Akile.csv` 等常见云厂商及 VPS）。
* **智能归类与解析规则**：
  1. **DanFeng 命名规范（`AS{ASN}_{ISP}_{DATE}_{TIME}.csv`）**：
     - DanFeng 导出的 CSV 文件内部只有 `IP地址,端口,TLS,数据中心,地区,城市,网络延迟`，**内部无 ASN 与 ISP 列**。
     - 脚本原生支持从**文件名**中直接读取权威目标 ASN、服务商名称及测速时间，并自动规范化。
  2. **OTC 扫描文件（`OTC_SCAN_YX_*.txt`）**：
     - **文件名含目标 ASN 时**（如 `OTC_SCAN_YX_AS210644.txt`）：全文件节点以文件名中的目标 ASN 为准，避免扫描端本地过时 GeoIP 离线库误标老旧上游历史 AS。
     - **文件名无目标 ASN 时**（如混合扫描文件 `OTC_SCAN_YX_杂.txt`）：自动逐行读取探测每条具体的实际 ASN 与 ISP，分别归入对应机房组。
* **跨文件严格去重与时效刷新**：
  - **全局唯一**：无论新老文件，均以 `IP:端口` 为全局主键，**绝对不会在任何产物中出现重复 IP 行**。
  - **时效覆盖**：新文件中的最新延迟、更新时间与配置自动覆盖刷新老旧数据。
  - **归属迁移**：若某 IP 在新文件中被修正了归属机房，它会自动迁移至新机房的 `data/scan_ips/AS{新ASN}_{厂商}.txt`，旧分组中自动清除，绝不跨组重复。
* **三模导出输出**：
  1. **总汇总清单（`data/scan_ips.txt`）**：将所有 ASN 分组整合在一起，带有清晰的 ASN 标题注释（如 `# AS906 (DMIT) - 15 个`）。
  2. **独立机房厂商文本（`data/scan_ips/ASxxx_厂商.txt`）**：在 `data/scan_ips/` 目录下按 ASN 及厂商名拆分生成独立文件（如 `data/scan_ips/AS906_DMIT.txt`、`data/scan_ips/AS210644_Aeza.txt`、`data/scan_ips/AS212336_ByteVirt.txt`），内容为 100% 纯净的 `IP:端口`，无任何注释，方便单独导入或按机房远程订阅。
  3. **结构化总表（`data/scan_ips.csv`）**：按 ASN 字母序聚合排序，方便通过 Excel 集中筛选分析。

### 4. `data/proxyip/` 与 `data/proxyip_cf/`（反代 ProxyIP 专属池、分国别与高价值属性分类）
* **独立反代池**：专门收录来自频道发布的反代文件（如 `Global-proxyip-443.csv`、`Global-proxyip-8443.csv` 等）。
* **智能国家/地区分类与数量统计**：`data/proxyip.txt` 与 `data/proxyip_cf.txt` 自动根据机房数据中心代码（Colo）与落地信息归类聚合，按节点规模降序排列，以 `# 🇺🇸 美国 - 6686 个` 等清晰注释头分组，组内按延迟升序严选排列，既保证纯净即用（兼容主流 Worker/脚本），又极大方便按目标国家筛选取用。
* **分国家/地区独立单文件（点击即复制）**：
  - `data/proxyip/*.txt`：在 `data/proxyip/` 目录下按国家/地区拆分为独立文件（如 `data/proxyip/美国.txt`、`data/proxyip/日本.txt`、`data/proxyip/香港.txt` 等 76 个地区），内容 100% 为纯净的 `IP:端口`，无任何注释行，直接全选（Ctrl+A ➔ Ctrl+C）即可复制或作为分地区远程订阅。
  - `data/proxyip_cf/*.txt`：针对兼具官方证书直连能力的双料提纯节点，同样提供分国家独立纯净文本列表（如 `data/proxyip_cf/美国.txt`、`data/proxyip_cf/日本.txt`）。
* **双能提纯直连（`data/proxyip_cf.txt`）**：由质检引擎并发探测，自动筛选提纯出既能作为反代穿透、又兼具 Cloudflare 官方证书 TLS 握手直连特性的优质节点，是兼具双料特性的极品清单。
* **高价值特殊网络类型提取（方案 A 离线精准分类）**：
  在总计 30,000+ 的反代节点池中，99.3% 为常规 VPS/数据中心机房。系统通过 **方案 A（基于 BGP 自治系统组织与 ISP 权威名称离线规则清洗引擎）**，精准剥离出极其稀缺的非机房资产，在 `data/proxyip/` 与 `data/proxyip_cf/` 目录下单独输出为 4 个高优先级文件（文件名前缀加 `【...】`，排序置顶）：
  - **`【ISP_运营商原生宽带】.txt`**：电信运营商原生宽带与精品线路网络（收录 中国电信 CN2、中国联通 9929/CUG、中国移动 CMIN2，以及 Comcast, Charter/Spectrum, Cox, HKT, HKBN, KT, SK Broadband, Vodafone, Orange, Singtel, Kazakhtelecom 等顶级电信商与骨干）。
  - **`【BIZ_商业企业专线】.txt`**：大型企业商业专线与商务宽带（收录 AT&T Enterprises, PCCW Business, Data Communication Business 等）。
  - **`【EDU_高校教育科研】.txt`**：高校与学术科研网（收录 University of Maine, CERNET, Academic Research 等）。
  - **`【GOV_政务公共网络】.txt`**：政务公用网与国家通信骨干（收录 Beltelecom 等）。
  所有特殊分类清单同样采用 **100% 纯净 `IP:端口`（按延迟升序排列，无多余注释）**，方便直接全选复制。
* **技术实现与边界说明（方案 A+ 两级分层分类体系）**：
  - **两级架构执行逻辑**：
    1. **Tier 1（内置权威精准对照，Fast-path Lookup）**：智能正则提取 AS 编号（支持 `AS4760`、`AS 4760`、`as4760` 以及纯数字 `701`、`4760` 等各种格式），优先与内置核心 ASN 映射字典比对（涵盖电信 CN2 AS4809、联通 9929 AS9929、联通 CUG AS10099、移动 CMIN2 AS58807 以及 HKT、HKBN、Comcast、Charter、Cox、KT、SK Broadband、Verizon、AT&T、Orange、Vodafone、CERNET 等顶级自治系统，以及 Cloudflare、AWS、Azure、Alibaba 等机房强锁定），命中即确定网络类型，纳秒级高精度定性；
    2. **Tier 2（启发式词根规则智能匹配，Pattern Fallback）**：针对对照表中未收录的冷门/新出现 ASN，或上游仅提供文本名称的数据行，自动进入词根模式识别（优先识别教育与政务网，严密排除 `host`/`cloud`/`vps`/`datacenter`/`dedicated` 等数十种机房关键词，随后识别商业专线与运营商原生宽带）；
    3. **Tier 3（安全降级兜底，Default Fallback）**：两级均未命中的未知节点，稳妥归入 `datacenter` 机房，确保特殊资产清单的绝对高纯度，同时保证不丢失任何一个有效节点。
  - **全库 100% 映射自查基线**：
    已对全库 33,000+ 节点涉及的全部 54 个独立 ASN 完成权威映射自查，未收录基线已清零；任何未来抓取到的全新自治系统均会自动触发动态提醒。
  - **客观界限（为什么不宣传为“100% 家中物理光猫”）**：
    由于 Tier 1 / Tier 2 顶级电信运营商（如 HKT, SK Broadband, Comcast, Charter 等）名下的自治系统（ASN）属于综合广播，同一个自治系统内部通常既广播给普通居民家庭光纤宽带，也广播给本地商户静态专线，甚至包含部分自建机房。因此，**在无需付费调用第三方商业 IP 数据库的前提下，方案 A+ 保证的是“运营商原生广播资产（非托管机房）”，无法保证 100% 来自居民家里的真实物理光猫**。
  - **风控优势**：
    常规机房 IP（如 AWS, 腾讯云, 阿里云, Hetzner, DigitalOcean 等）在各大反欺诈（IP Fraud Score）、反爬虫与 Cloudflare Turnstile / 盾防御数据库中均被标记为高风险 `Hosting / Datacenter`，极易弹出人机验证甚至直接拦截。而**运营商原生宽带、商业专线与高校科研网节点在主流风控体系中具有极高的天然声誉（Trust Score）**，过盾成功率和防封稳定性显著优于常规 VPS。
* **结构化数据**：`data/proxyip.csv` 新增 `net_type` 字段（取值：`datacenter`、`isp`、`business`、`education`、`government`），保留延迟、数据中心、落地位置与 `cf_clean` 优选标记等关键信息。

### 5. 数据表通用字段说明
* 采用 `UTF-8-SIG` 编码，Windows Excel 直接双击打开不乱码。
* 数值字段（`delay_ms`, `speed_kbs`）均为纯数字，并在保存时按 **`tested_at`（测速/探测时间）倒序排序**。
* 全项目共有 4 个核心 CSV 数据表，按用途与结构分为以下 3 大规范体系：

#### ① 优选 IP 测速数据表（`data/cf_ips.csv`、`data/scan_ips.csv`）
*共 12 个字段，记录 Cloudflare 优选 IP 的真实测速指标与机房归属：*

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `ip` | 字符串 | 优选 IP 地址 | `23.249.18.144` |
| `port` | 整数 | 服务端口 | `8581` |
| `tls` | 字符串 | 是否开启 TLS (`true`/`false`) | `true` |
| `delay_ms` | 整数 | 网络延迟（毫秒纯数值，便于排序） | `2` |
| `speed_kbs` | 整数 | 下载速度（kB/s 纯数值，便于排序） | `89086` |
| `colo` | 字符串 | Cloudflare 数据中心三字代码 | `HKG`、`NRT`、`LAX` |
| `cf_location` | 字符串 | Cloudflare 落地地理位置 | `亚太 · 香港` |
| `isp` | 字符串 | 网络运营商 / 托管商名称 | `Prime Security Corp.` |
| `asn` | 字符串 | ASN 编号与组织 | `AS400618 Prime Security Corp.` |
| `tested_at` | 时间字符串 | 测速与发布时间 | `2026-09-13 18:00:33` |
| `channel` | 字符串 | 来源频道 | `@danfeng2` / `@otcfxq` |
| `fail_count` | 整数 | 连续探测失败次数（默认 0，连续失败 ≥ 2 次自动淘汰剔除） | `0` |

#### ② 反代 ProxyIP 穿透与网络属性数据表（`data/proxyip.csv`）
*共 14 个字段，除基础网络字段外，独占 `cf_clean`（优选直连提纯）与 `net_type`（两级分层网络识别）两大核心资产属性：*

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `ip` | 字符串 | 反代 IP 地址 | `104.16.132.229` |
| `port` | 整数 | 反代端口 | `443` |
| `tls` | 字符串 | 是否开启 TLS (`true`/`false`) | `true` |
| `delay_ms` | 整数 | /cdn-cgi/trace 穿透响应延迟（毫秒） | `145` |
| `speed_kbs` | 整数 | 下载速度（kB/s 纯数值，保留字段） | `0` |
| `colo` | 字符串 | 穿透返回的 Cloudflare 实际处理机房三字码 | `HKG` |
| `cf_location` | 字符串 | 落地地理位置 | `中国 · 香港特别行政区` |
| `isp` | 字符串 | 自治系统组织 / 运营商名称 | `HKBN Hong Kong Broadband` |
| `asn` | 字符串 | 规范化 ASN 编号与组织 | `AS9269 Hong Kong Broadband` |
| `tested_at` | 时间字符串 | 穿透质检测试时间 | `2026-09-19 18:00:00` |
| `channel` | 字符串 | 来源频道或附件源 | `@danfeng2` |
| `fail_count` | 整数 | 连续探测失败次数（连续失败 ≥ 2 次永久物理删除） | `0` |
| `cf_clean` | 字符串 | **【核心属性】** 是否兼具 Cloudflare 官方证书直连优选能力 (`true`/`false`) | `true` |
| `net_type` | 字符串 | **【核心属性】** 网络类型归属（详见下方 5 类取值说明） | `isp` |

> 📌 **`net_type` 网络分类取值与对应导出品**：
> - `isp`：运营商原生民用宽带 ➔ 对应导出 `data/proxyip/【ISP_运营商原生宽带】.txt`
> - `business`：商业专线与企业宽带 ➔ 对应导出 `data/proxyip/【BIZ_商业企业专线】.txt`
> - `education`：高校教育科研网 ➔ 对应导出 `data/proxyip/【EDU_高校教育科研】.txt`
> - `government`：政务公用网与国家骨干 ➔ 对应导出 `data/proxyip/【GOV_政务公共网络】.txt`
> - `datacenter`：常规数据中心/托管机房 ➔ 归入各国家/地区常规列表

#### ③ 通用代理质检数据表（`data/socks5.csv`）
*共 9 个字段，记录 SOCKS5/HTTP/HTTPS/TURN 等通用代理应用层穿透结果：*

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `url` | 字符串 | 包含协议、账号密码、主机的完整代理 URL | `socks5://user:pass@1.2.3.4:1080` |
| `proto` | 字符串 | 协议类型（`socks5`、`http`、`https`、`turn`） | `socks5` |
| `host` | 字符串 | 节点域名或 IP 地址 | `1.2.3.4` |
| `port` | 整数 | 服务端口 | `1080` |
| `delay_ms` | 整数 | RFC 1928 握手与穿透测速延迟（毫秒纯数值） | `320` |
| `fail_count` | 整数 | 连续探测失败次数（连续失败 ≥ 3 次自动淘汰剔除） | `0` |
| `status` | 字符串 | 探测状态（`alive` 存活 或 `fail` 失败） | `alive` |
| `colo` | 字符串 | 通过该代理中继访问返回的 Cloudflare 机房代号 | `NRT` |
| `tested_at` | 时间字符串 | 质检探测完成时间 | `2026-09-19 18:35:00` |

---

### 6. 全线三大异步主动鉴真与缓冲淘汰体系
为防止长期累积的节点失效或死灰复燃，系统配备了三套独立的高并发主动质检探测引擎：

#### ① 代理连通性质检引擎（`socks_verify.py`）
* **全协议真实握手**：
  * **SOCKS5**：RFC 1928 握手协商（无密 `0x00` / 账密 `0x02` RFC 1929）➔ 发送 CONNECT 指令 ➔ 穿透请求 `/cdn-cgi/trace` 检验 200 与机房。
  * **HTTP / HTTPS**：CONNECT 隧道穿透 + 正向代理回退双路径校验。
  * **TURN / STUN**：构造 RFC 5389 STUN Binding Request 二进制包，严格校验 Magic Cookie (`0x2112A442`) 与 Transaction ID。
* **淘汰机制**：连续失败达到阈值（默认 3 次）彻底从 `data/socks5.txt` 与 `data/socks5.csv` 永久删除。

#### ② 反代 ProxyIP 穿透质检引擎（`proxyip_verify.py`）
* **穿透与优选双能探测**：
  * **穿透鉴真**：向反代节点发起 TLS ClientHello 握手（SNI: `speed.cloudflare.com`，跳过非官方证书校验），发送 HTTP/1.1 GET `/cdn-cgi/trace` 探针请求，严格校验 `HTTP 200` + `Server: cloudflare` + 有效 `colo` 机房代号。
  * **优选直连探测**：并发探测存活节点是否同时支持作为直连优选 IP（`crypto.cloudflare.com` 官方 CA 证书鉴真与 HTTP 301 重定向校验），自动提纯生成兼具双料特性的 `data/proxyip_cf.txt` 极品清单。
* **淘汰机制**：连续失败达到阈值（默认 2 次）彻底从 `data/proxyip.txt`、`data/proxyip.csv` 永久物理删除。

#### ③ 优选 IP 两阶段主动鉴真引擎（`cf_verify.py`）
* **全量优选 IP 覆盖**：无论来源，**只要是优选 IP（涵盖 `data/scan_ips` 扫描测速与 `data/cf_ips` 每日单条全线产物），一律全部执行阶段一与阶段二探测**：
  * **阶段一（TLS 握手 + 证书鉴真）**：建立 TLS 握手并验证 `crypto.cloudflare.com` 官方证书有效性。
  * **阶段二（HTTP 301 重定向 + 服务头验证）**：同一连接请求根路径，验证返回 `301 Moved Permanently` 且响应头包含 `Server: cloudflare`。
* **全产物联动删除剔除**：达到淘汰阈值的死节点，同步从 `data/scan_ips.csv`、`data/scan_ips.txt`、`data/scan_ips/*.txt`、`data/cf_ips.csv`、`data/cf_ips.txt` 中**彻底永久删除**。

---

## 环境变量配置

在 GitHub 仓库 **Settings -> Secrets and variables -> Actions** 中进行配置：

### 1. Repository Secrets（机密密钥 · 位于 Secrets 标签页）

> 💡 **项目只需这 5 项敏感凭据，绝无遗漏**：
> - 启用**全功能官方 API 模式**只需配置前 3 项；
> - 启用 **Telegram 消息推送**只需配置后 2 项；
> - `GITHUB_TOKEN` 为 GitHub Actions 官方内置，无需手动添加。

| 变量名 | 用途 | 适用模式 | 必要性 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| `TG_API_ID` | Telegram API ID（纯数字） | 官方 API 模式 | API 必填 | 从 [my.telegram.org](https://my.telegram.org) 获取 |
| `TG_API_HASH` | Telegram API Hash（32位字符） | 官方 API 模式 | API 必填 | 从 [my.telegram.org](https://my.telegram.org) 获取 |
| `TG_SESSION_STR` | Telethon 会话认证字符串 | 官方 API 模式 | API 必填 | 本地运行 `python gen_session.py` 登录生成 |
| `TG_BOT_TOKEN` | Telegram 通知机器人 Token | 推送卡片 | 可选 | 从 [@BotFather](https://t.me/BotFather) 获取 |
| `TG_CHAT_ID` | 通知接收人 / 频道 / 群组 ID | 推送卡片 | 可选 | 机器人的目标推送聊天 ID |

### 2. Repository Variables（常规运行变量 · 位于 Variables 标签页 · 全可选）

> 💡 **Variables 默认全部留空也能 100% 正常运行！** 系统已内置经过实测的最佳默认值，仅在有特殊调优需求时选填：

| 变量名 | 用途 | 默认值 | 必要性 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| `FETCH_DAYS` | 单次增量回溯天数（扫描时间窗口） | `3` | 可选 | 增量模式下只读取最近 N 天频道消息，加快运行速度 |
| `PROXY` | 抓取代理设置 | 留空 | 可选 | GitHub Actions 云端默认直连 Telegram 无需配置；自建私有 Runner 或特殊网络时可按需配置 |
| `PROXY_CHANNELS` | 代理抓取目标频道（逗号/空格分隔） | `@otcfxq` | 可选 | 自定义抓取通用代理的 Telegram 公开频道列表 |
| `CF_IP_CHANNELS` | 优选 IP 抓取目标频道（逗号/空格分隔） | `@otcfxq, @danfeng2` | 可选 | 自定义抓取 Cloudflare 优选 IP 与测速附件的大池频道列表 |

### 3. 高级调优参数与本地调试对照（可选）

各引擎脚本还支持以下高级命令行参数，可在本地开发或工作流调整时使用（GitHub Actions 默认已自动配置最优参数）：

| 参数名 / 选项 | 对应脚本 | CI 预设值 | 默认值 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| `--concurrency` | 校验脚本 | `250` ~ `300` | `100` ~ `150` | 质检异步并发协程数，数值越大质检越快 |
| `--max-fails` | 校验脚本 | `2` | `2` | 连续失败物理淘汰阈值（设为 `1` 即为严格无缓冲模式） |
| `--timeout` | 校验脚本 | `3.0` | `5.0` | 单节点连接建立与 TLS 握手超时秒数 |
| `--no-notify` | 校验脚本 | 流水线静默 | 关闭 | 不单独推送各引擎卡片，由流水线终点聚合为四合一卡片 |
| `DEFER_NOTIFY` | `tg_fetch.py` | `1` | `0` | 延迟 Telegram 推送标记，确保四合一卡片聚合完整 |

---

## 📱 Telegram 运行通知卡片示例

配置 `TG_BOT_TOKEN` 与 `TG_CHAT_ID` 后，流水线运行完成会自动发送四维合一的现代精简风统计卡片：

```text
🚀 节点与优选 IP 同步完成 (🟢 发现 +25 新增 · 🗑️ 剔除 31 死节点)
━━━━━━━━━━━━━━━━━━━━
📅 时间：2026-09-17 18:35:00 (北京时间)
📫 可用代理：741 个 (✅ 698 存活 · ⚠️ 43 缓冲 · ⚡ 均延 520ms)
🌐 单条优选：37 条 (✅ 28 存活 · ⚠️ 9 缓冲)
📁 扫描优选：5,015 条 (✅ 4,862 存活 · ⚠️ 153 缓冲 · 20 个 ASN)
   └ 涵盖: Aeza, DMIT, ByteVirt, Starry Network 等
🔀 反代 ProxyIP：30,545 条 (✅ 29,820 存活 · ⚠️ 725 缓冲)
   └ 🌟 兼具优选直连: 4,832 条 (已提纯 data/proxyip_cf.txt)
💡 发现未收录 ASN (可补充入库)：
   • AS13335 Cloudflare, Inc. (12 条)
   • AS16509 Amazon.com, Inc. (5 条)
   └ 共 2 个待确认归属
━━━━━━━━━━━━━━━━━━━━
🛡️ 主动鉴真淘汰：
   • 优选检验：TLS 握手 + HTTP 301 (250 并发)
   • 代理检验：RFC 1928 全协议穿透鉴真
   • 反代检验：/cdn-cgi/trace 穿透 + 优选双能
   • 淘汰死节点：31 条 [代理 12, 反代 15, 扫描优选 4] (连续失败 ≥ 2 次)
📡 频道来源：@danfeng2, @otcfxq
━━━━━━━━━━━━━━━━━━━━
⚡ 总耗时: 165.2s · 🔗 Action #35 · 📦 产物仓库
```

* **锁屏即知变动**：首行支持 `(🟢 发现 +N 新增 · 🗑️ 剔除 N 死节点)` 双状态动态高亮组合呈现，变动一目了然。
* **增量与健康一览**：每类节点直观展示存活数量、缓冲标记与实测均延（均延仅计算实测存活节点，排除处于容忍缓冲期失败节点的历史旧延迟污染）。
* **自适应未知预警**：遇未收录新自治系统时动态展示 `💡 发现未收录 ASN (可补充入库)` 明细（展示前 4 个及待确认总数），全量命中时自动隐藏，0 视觉噪音。
* **主动鉴真审计**：实时汇报全协议穿透质检、TLS + 301 重定向鉴真与连续失败永久淘汰数量。
* **细分淘汰明细**：底栏汇报各引擎分类淘汰数量 `[代理 X, 反代 Y, 扫描优选 Z]`，精准掌控全库死节点流失情况。
* **厂商覆盖一览**：自动统计展示覆盖的主力机房与服务商。
* **一键直达日志**：附带 GitHub Action 运行记录与产物仓库直达超链接。

---

## 🚀 云端自动化部署指南（推荐 · 3步极简托管）

本项目设计为 **100% 托管于 GitHub Actions** 的全自动云端系统，所有抓取、质检、推送到 `data/` 及日志维护完全在云端完成，**日常使用无需在本地电脑运行脚本，也无需自备服务器**。

### 第一步：Fork 本仓库
点击仓库右上角 **Fork** 按钮，将本项目完整复制到您的个人 GitHub 账号下。

### 第二步：配置 GitHub Secrets（按需选择模式）
进入您的 Fork 仓库，点击 **Settings -> Secrets and variables -> Actions**，添加 Repository secret：

#### 方案 A：🚀 零门槛免登录模式（开箱即用）
* **无需配置任何密钥**！
* 保持 Secrets 留空即可，系统自动以 Web 免登录模式运行，定时同步公开频道消息正文中的通用代理与单条优选 IP。

#### 方案 B：🛡️ 官方 API 全功能模式（强烈推荐 · 解锁机房大池与反代池）
若需要自动下载附件（获取 DanFeng CSV、OTC 测速扫描 TXT、ProxyIP 反代池等万级大池）：
1. 访问 [my.telegram.org](https://my.telegram.org) 登录获取 `API ID` 与 `API Hash`。
2. **（仅需在本地运行一次）** 生成认证字符串（因 Telegram 登录需交互式输入手机验证码）：
   ```bash
   pip install telethon
   python gen_session.py
   ```
   按终端提示输入手机号与验证码后，控制台将输出一串 Session 字符串。
3. 在 GitHub Secrets 中填入对应 3 项：
   - `TG_API_ID`：你的 API ID（纯数字）
   - `TG_API_HASH`：你的 API Hash（32 位字符）
   - `TG_SESSION_STR`：生成的 Session 字符串

#### 方案 C：📱 Telegram 统计卡片与即时告警（可选）
若希望每天收到漂亮的汇总统计卡片，并在流水线故障时 1 秒内收到警报：
- `TG_BOT_TOKEN`：Telegram 机器人 Token（从 [@BotFather](https://t.me/BotFather) 获取）
- `TG_CHAT_ID`：目标接收人 / 频道 / 群组 ID

---

### 第三步：启用 Actions 定时任务
1. 打开仓库的 **Actions** 标签页，点击绿色按钮开启工作流权限（*“I understand my workflows, go ahead and enable them”*）。
2. **自动定时调度**：每天 **北京时间 18:05（UTC 10:05）** 自动执行完整的流水线（含语法预检、三级主动质检、数据去重提交与旧记录清理）。
3. **手动随时触发**：在 Actions 页面左侧点击 **Fetch Proxies and CF IPs** ➔ **Run workflow**，即可按需随时触发一次同步。

---

## 🛠️ 开发者指南与本地离线调试（可选）

> 💡 **普通使用者无需阅读本节**。仅供希望修改爬虫规则、二次开发或本地排查问题的开发者参考。

### 本地环境配置
```bash
git clone https://github.com/你的用户名/tg-proxy-fetcher.git
cd tg-proxy-fetcher
pip install -r requirements.txt
```
*注：若在中国大陆本地开发，脚本会自动尝试读取系统代理设置（如 v2rayN）；或通过 `$env:PROXY="socks5h://127.0.0.1:10808"` 显式指定代理。*

### 本地回归校验与测试命令
```bash
# ① 语法与静态变量检查（与 GitHub Actions 门禁一致，0.5秒拦截未定义变量）
python -m py_compile *.py
pip install ruff
ruff check . --select F82

# ② 通用代理连通性质检
python socks_verify.py --concurrency 100 --no-notify

# ③ 反代 ProxyIP 穿透与优选直连双料质检
python proxyip_verify.py --concurrency 150 --no-notify

# ④ 全量优选 IP 两阶段（TLS + HTTP 301）主动鉴真
python cf_verify.py --concurrency 150 --timeout 3.0
```

---

## 🙏 致谢

本项目节点与优选 IP 数据源来自以下 Telegram 公开频道，在此表示感谢：

- [@otcfxq](https://t.me/otcfxq)
- [@danfeng2](https://t.me/danfeng2)

---

## 📄 开源许可证 / License

本项目遵循 [MIT License](LICENSE) 协议开源。
