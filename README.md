# TG-Proxy-Fetcher —— Telegram 代理与 Cloudflare 优选 IP 自动化同步工具

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-2088FF?logo=github-actions&logoColor=white)](https://github.com/skfoa/tg-proxy-fetcher/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)

每天自动从 Telegram 公开频道与交流群（[@otcfxq](https://t.me/otcfxq)、[@danfeng_chat](https://t.me/danfeng_chat)）抓取多协议代理节点、Cloudflare 优选 IP 以及反代 ProxyIP。系统具备**增量持久化**、**去重合并**与**多阶段主动质检淘汰机制**，自动导出通用代理列表、纯净 `IP:端口` 文本列表以及结构化测速数据表格，并通过 GitHub Actions 每天北京时间 08:15 定时自动执行质检流水线并推送到仓库。

---

## ⚡ 运行模式与能力对比

系统支持**免登录 Web 模式**与**官方 API 模式**两种运行方式，了解不同模式的能力边界有助于按需选择配置：

| 特性 / 产物 | 🚀 免登录 Web 模式<br>(零门槛开箱即用) | 🛡️ 官方 API 模式<br>(全功能完整版 · 强烈推荐) |
| :--- | :---: | :---: |
| **运行门槛** | **无需任何密钥或账号**<br>Fork 仓库开启 Actions 即可全自动运行 | **需配置 3 项 Secret**<br>`TG_API_ID`、`TG_API_HASH`、`TG_SESSION_STR` |
| **底层原理** | 爬取 Telegram 公开网页预览 (`t.me/s/`) | 启用 Telethon 客户端直连 MTProto 协议 |
| **正文通用代理 (`data/proxies.txt`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道正文单条优选 (`data/cf_ips.*`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道附件自动下载解析** | ❌ **不支持**（网页端无附件下载接口） | ✅ **完全支持自动下载解析** |
| **批量扫描大池 (`data/scan_ips/`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析 OTC/DanFeng 测速附件 |
| **反代 ProxyIP 池 (`data/proxyip.*`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析反代文件附件 |
| **全协议鉴真与缓冲淘汰** | ✅ 支持（对抓取到的正文节点鉴真） | ✅ 全量支持（覆盖正文与海量附件大池） |
| **适用场景** | 快速验证、仅需基础正文代理与单条 IP | 正式部署、需要机房扫描测速池与反代池 |

---

## 🌟 核心特性亮点

- **🚀 免登录基础模式**：未配置 API 凭据时自动启用，零门槛抓取频道消息正文中的通用代理与单条优选 IP。
- **🛡️ 官方 API 全功能模式**：配置 `TG_API_ID`、`TG_API_HASH` 与 `TG_SESSION_STR` 后自动激活，解锁频道附件自动下载，获取机房测速扫描 IP 与反代文件。
- **📦 增量持久化与缓冲保护**：历史抓取的有效节点自动累积留存，新节点自动追加去重，同时引入公网抖动缓冲保护（节点连续 3 次全网不可达方才剔除死节点），兼顾历史留存与可用性筛选。
- **🔍 跨文件唯一去重**：以 `IP:端口` 为全局主键，新老文件重复提取自动刷新覆盖，避免重复行；IP 归属更正时自动迁移所属 ASN 文件。
- **📁 智能 ASN 分组与命名**：
  - **DanFeng 测速**：CSV 内部无 ASN 列时自动从文件名（如 `AS45102_CNNICALIBABACNNETAP_*.csv`）解析归类。
  - **OTC 优选扫描**：单 ASN 文件以文件名目标 ASN 为准；混合扫描文件（如 `OTC_SCAN_YX_杂.txt`）自动逐行提取具体 ASN 与 ISP 拆分归类。
- **🧩 模块化解耦与分段锁调度**：提取独立 `providers.py` 集中维护云厂商与 ASN 字典映射；内置基于 `zlib.crc32` 的 8192 桶位哈希分段锁（`get_keyed_lock`），同 IP 互斥排队避免瞬时高并发触发对端限流，异 IP 并行探测，分段锁内存维持在常数级 $O(1)$。
- **🧠 双向索引 ASN 离线知识库与 BGP 字典体系**：引入 `data/asn_database.json` 维持 1,000+ 条双向索引字典（`isp_to_asn` 1,080+ 条与 `asn_to_isp` 1,020+ 条）以及 1,800+ 条自治系统网络分类基准表，配合权威 SSOT 字典实现解析归一化；运行时支持动态增量自愈维护与持久化；内置防污染保护（保留权威标准命名不被第三方脏标签篡改）与两级查表机制（精准查表 + 边界安全词根匹配），兼顾解析性能与自治系统归属；支持多品牌别名保留（如 `AS63023 Ipxo LLC (GTHost)`）与幂等处理。
- **💡 未收录 ASN 动态发现与自适应预警**：增量抓取遇外部新自治系统时，自动比对内置权威对照库；若发现未收录 ASN，将在 Telegram 卡片中提示并展示待确认明细，提示管理员按需确认并补充入库；若无未知 ASN 则自动隐藏。
- **📱 动态双状态 Telegram 运行卡片**：首行支持「🟢 发现新增 + 🗑️ 剔除死节点」双状态动态呈现，底栏包含细分引擎淘汰明细 `[代理 X, 反代 Y, 扫描 Z]`，锁屏即知变动。
- **🛡️ 响应防截断、原子覆写与协议校验**：质检引擎采用统一 Deadline 超时控制与循环读取（`read_full_response`），完整获取 `/cdn-cgi/trace` 响应中的 `colo` 属性，非 200 响应快速退出；严格切分 Header 与 Body 区域，校验状态码（`301`/`200`）与 `Server: cloudflare`；全链路数据落盘统一采用 `.tmp` $\rightarrow$ `os.replace` 原子替换，避免进程意外中断产生损坏文件。
- **🛡️ 静态安全门禁与自动化回归测试**：在数据抓取前首先通过 `py_compile` 拦截语法错误、`ruff` 拦截未定义变量，由 `providers.py --validate` 校验数据库一致性，并运行 `tests/test_core.py` 自动化回归测试（覆盖协议解析、Host 格式校验、防污染与容灾自愈）；若流水线任何环节异常中断，自动推送 Telegram 告警卡片并附带日志直链。
- **🧹 自动维护与构建瘦身**：每次运行自动清理 GitHub Actions 历史记录（工作流已显式预置 `actions: write` 权限），始终**仅保留最近 4 次运行记录**，告别冗余历史堆积！

---

## 架构与工作流程

```text
                                     Telegram 公开频道
                          ┌─── @otcfxq ────────┐
                          │   (代理 + 优选IP)  │
    tg_fetch.py ──────────┤                    ├────► 增量抓取 & 全局智能去重 ──┬──► data/proxies.txt / proxies.csv
    (免登录/官方API双模)   │                    │                               ├──► data/cf_ips.txt / cf_ips.csv
                          └─── @danfeng_chat ──┘                               ├──► data/scan_ips.txt / scan_ips.csv
                               (优选IP 专属)                                     ├──► data/scan_ips/AS{ASN}_{ISP}.txt *
                                                                                └──► data/proxyip.txt / proxyip.csv *
                                    ▲                                          
                                    │ 统一接入公共映射与离线字典
                              providers.py ◄──► data/asn_database.json
                     (云厂商/ASN 单一真相源)   (离线双向索引字典)
                                    │ 统一接入公共映射
                                    ▼
                            四阶段流水线主动鉴真与淘汰引擎
  ┌───────────────────────┬─────────────────────────┬─────────────────────────┐
  ▼                       ▼                         ▼                         ▼
Step 1: tg_fetch        Step 2: proxies_verify    Step 3: proxyip_verify    Step 4: cf_verify
多协议增量抓取          多协议质检                /cdn-cgi/trace 穿透       全量优选 TLS+301 鉴真
全局唯一去重合并        SOCKS5/HTTP/TURN/SSTP 穿透 质检分层与纯净导出        + 全局四合一 TG 统一卡片

* 注：标记 * 的扫描机房大池与反代池需配置【官方 API 模式】方可自动下载获取。
```

### 核心模块清单

| 模块文件 | 定位与职责 |
| :--- | :--- |
| **`tg_fetch.py`** | **数据抓取与合并核心**：实现免登录 Web 爬虫与 Telethon API 双模抓取，跨文件全局唯一去重合并保存至 `data/`。 |
| **`parsers.py`** | **文本提取与数据格式解析模块**：提取通用代理正则、单条优选卡片、测速 CSV 附件、OTC 扫描清单等解析规则，全面解耦纯文本提取与底层网络探测。 |
| **`providers.py`** | **公共规范与网络分类中心**：全系统单一真相源（Single Source of Truth），维护云厂商与关键 ASN 映射表、两级分层网络分类引擎（Tier 1 权威对照 + Tier 2 词根规则），加载维护 `data/asn_database.json` 离线知识库，并提供 ProxyIP 分国别与稀缺高价值网络专线纯文本分类导出。 |
| **`proxies_verify.py`** | **多协议通用代理质检引擎**：基于 RFC 1928、RFC 5389 (STUN/TURN Binding)、HTTP CONNECT 穿透及 MS-SSTP 隧道状态握手检验，支持配置自建 CF Worker 探测真实出口 IP。 |
| **`proxyip_verify.py`** | **反代 ProxyIP 质检引擎**：抗分包/防截断（Header/Body 隔离），验证反代真实穿透能力，并按质检状态分层导出分国与网络属性纯净列表。 |
| **`cf_verify.py`** | **全量优选 IP 鉴真与最终卡片推送**：执行 TLS 官方证书鉴真 + HTTP 301 重定向抗截断精准校验，汇总流水线所有阶段数据并推送统一 TG 统计卡片。 |
| **`gen_session.py`** | **Telethon Session 辅助生成器**：本地运行快速交互登录 Telegram 并输出 Session 字符串，供 GitHub Actions 免交互调用。 |
| **`tests/test_core.py`** | **核心回归测试套件**：标准 `unittest` 自动化测试集，覆盖 Host 鉴真与防注入、路径穿越防御、多品牌别名幂等格式化、六大网络分类定性与数据容灾自愈，已深度接入 CI 门禁。 |

---

## 产物清单与订阅直链

所有数据产物集中收纳于 **`data/`** 目录，保持根目录代码纯净：

| 文件名 | 内容说明 | 生成条件 | GitHub Raw 永久直链（点击即可导入） |
| :--- | :--- | :---: | :--- |
| **`data/proxies.txt`** | 质检存活的多协议通用代理全量清单（按协议分段注释归类，纯文本；每段以 `# {协议} 代理 - N 个` 开头，客户端订阅时请过滤 `#` 注释行，或直接使用下方单协议纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxies.txt` |
| **`data/proxies.csv`** | 代理质检数据总表（15 字段完整元数据，含出口国家、出口 IP、ASN、ISP 与网络分类） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxies.csv` |
| **`data/proxies/*.txt`** | 按协议独立拆分的纯净单协议代理清单（如 `socks5.txt`、`turn.txt`、`sstp.txt`，无注释行） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxies/{协议}.txt` |
| **`data/proxies/*.csv`** | 按协议独立拆分的纯净单协议结构化数据表（如 `socks5.csv`、`turn.csv`、`sstp.csv`） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxies/{协议}.csv` |
| **`data/proxies/*.json`** | 按协议独立拆分的标准化 JSON 端点（如 `socks5.json`、`turn.json`、`sstp.json`，结构化输出协议、国家、出口真实 IP、ASN 与网络属性，兼容各类通用客户端与工具链拉取） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxies/{协议}.json` |
| **`data/cf_ips.txt`** | 频道日常单条优选 IP（纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/cf_ips.txt` |
| **`data/cf_ips.csv`** | 频道日常单条优选 IP（数据表） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/cf_ips.csv` |
| **`data/scan_ips.txt`** | 扫描测速总清单（按存活/缓冲质检状态分层排序，纯文本） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips.txt` |
| **`data/scan_ips/*.txt`** | 独立 ASN + 厂商纯文本列表（单文件） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips/AS{ASN}_{ISP}.txt` |
| **`data/scan_ips.csv`** | 扫描测速优选 IP（数据表） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/scan_ips.csv` |
| **`data/proxyip.txt`** | 反代 ProxyIP 总清单（按存活/缓冲质检状态分层排序，纯文本） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.txt` |
| **`data/proxyip/*.txt`** | 独立国家/地区纯净反代列表（如 `美国.txt`、`日本.txt`） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip/{地区}.txt` |
| **`data/proxyip/【...】.txt`** | 稀缺网络属性独立反代列表（原生宽带/商业/教育/政务，ASN 粗筛） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip/【ISP_运营商原生宽带】.txt` 等 |
| **`data/proxyip.csv`** | 反代 ProxyIP 详细数据表（含 `net_type` 网络分类） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.csv` |
| **`data/asn_database.json`** | 内置离线 ASN 知识库（收录 1,000+ 条双向索引映射与 1,800+ 条网络分类基准；遇到新 ASN 时自动在线查询增量同步） | 运行时增量维护（由 CI 自动提交） | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/asn_database.json` |
| **`data/tombstone.json`** | 死节点记忆库（7 天隔离冷却与生命周期闭环防回流） | 全模式支持（质检引擎运行触发） | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/tombstone.json` |

---

## 支持提取的节点与内容类型

1. **通用标准代理 URL**：
   - `socks5://...`、`http://...`、`https://...`（兼容免密与带账号密码认证）
2. **TURN 穿透协议节点**：
   - `turn://114.34.87.173:3479#TW...`（自动识别 `turn://` 协议，智能剥离测速后缀与中文标签）
3. **SSTP 安全隧道协议节点（含 VPNGate 外部订阅）**：
   - `sstp://vpn:vpn@public-vpn-xxx.opengw.net:443`（自动识别与提取，支持通过 `SUB_URLS` 环境变量直接拉取外部订阅链接并自动去重合并）
4. **Telegram 官方 SOCKS5 一键直连链接**：
   - `tg://socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - `https://t.me/socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - 自动无损转换为通用标准 `socks5://user:pass@ip:port` 格式，支持任意第三方客户端直接导入。
5. **开放代理/服务通报消息（已做防污染隔离）**：
   - `[发现开放 HTTP 代理] 174.138.165.213:34887` ➔ 自动补全为 `http://174.138.165.213:34887`
   - `[发现开放 HTTPS 代理] https://121.42.225.20:443#CN` ➔ 自动提取为 `https://121.42.225.20:443`
   - `[发现开放 SOCKS5 代理] IP:Port` ➔ 自动补全为 `socks5://IP:Port`
   - `[发现开放 TURN 代理/服务] IP:Port 或 turn://IP:Port` ➔ 自动提取为 `turn://IP:Port`
   - `[发现开放 SSTP 代理/服务] IP:Port 或 sstp://IP:Port` ➔ 自动提取为 `sstp://IP:Port`
   - 🛡️ **目标隔离**：通报消息中附带的第三方 SNI 目标域名（如 `域名:https://...`）会被自动过滤，仅保留代理服务器自身的主机与端口。
6. **代理附件文件自动解析（需官方 API 模式）**：
   - 自动识别频道发布的代理附件文件（如 `http_proxies.txt`、`https_proxies.txt`、`turn_proxies.txt` 等）。
   - 自动提取行首有效节点与认证信息，过滤后续测速说明与反向 PTR 域名别名，统一去重合并至 `data/proxies.txt`。
7. **Cloudflare 优选 IP 与反代池（需官方 API 模式）**：
   - 提取包含 IP、端口、TLS、网络延迟（纯数值 ms）、下载速度（纯数值 kB/s）、数据中心（Colo）、落地位置、ASN、运营商、测速时间等全量指标。

---

## 输出产物与去重规则详细说明

### 1. `data/proxies.txt`、`data/proxies/` 与 `data/proxies.csv`（通用代理汇总与独立协议拆分）
* **增量合并**：每次抓取优先比对历史库，新发布的节点自动追加并去重，以 `host:port` 为唯一标识刷新认证与配置。
* **主动质检淘汰（`proxies_verify.py`）**：集成 RFC 1928（SOCKS5 协商/认证/CONNECT 隧道穿透）、RFC 5389（STUN/TURN Binding 鉴真）、HTTP CONNECT 穿透、MS-SSTP 标准双工隧道握手真实网络协议握手校验。
* **连续失败缓冲保护（`--max-fails 3`）**：探测失败标记缓冲（`fail_count=1~2` 为缓冲期），连续 3 次全网不可达方才清理剔除，避免公网抖动误杀。
* **协议专属分类与多格式导出（按协议分块归类，避免混杂）：**
  - `data/proxies.txt`：全量代理汇总纯文本，按协议分段归类输出（`# SOCKS5 代理`、`# TURN 协议`、`# SSTP 协议` 等），段内按实测延迟严选升序排列。
  - `data/proxies.csv`：结构化质检总表（15 字段完整凭据），严格按协议大类分块聚集排序（SOCKS5 块 ➔ TURN 块 ➔ SSTP 块），行与行之间无交错混插。
  - `data/proxies/`：专属单协议独立拆分子目录，提供单协议 `.txt`、`.csv` 与 `.json` 文件：
    - `data/proxies/socks5.txt` / `socks5.csv` / `socks5.json`：SOCKS5 代理节点列表、表格与 JSON 数据源（便于定向导入 Telegram / Proxifier / EDT-Toolkit 等）；
    - `data/proxies/turn.txt` / `turn.csv` / `turn.json`：TURN 穿透协议节点列表、表格与 JSON；
    - `data/proxies/sstp.txt` / `sstp.csv` / `sstp.json`：SSTP 安全隧道协议节点列表、表格与 JSON（VPNGate 等）；
    - `data/proxies/http.txt` / `http.csv` / `http.json`：HTTP 代理节点列表、表格与 JSON；
    - `data/proxies/https.txt` / `https.csv` / `https.json`：HTTPS 代理节点列表、表格与 JSON。

### 2. `data/cf_ips.txt` / `data/cf_ips.csv`（频道日常单条优选 IP）
* 仅收录频道日常消息正文中发布的单条优选 IP（如 `@danfeng_chat`、`@otcfxq` 的实时测速通报）。
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
* **跨文件去重与时效刷新**：
  - **主键去重**：无论新老文件，均以 `IP:端口` 为全局主键，避免在产物中出现重复 IP 行。
  - **时效覆盖**：新文件中的最新延迟、更新时间与配置自动覆盖刷新老旧数据。
  - **归属迁移**：若某 IP 在新文件中被修正了归属机房，它会自动迁移至新机房的 `data/scan_ips/AS{新ASN}_{厂商}.txt`，旧分组中自动清除，绝不跨组重复。
* **多模导出输出**：
  1. **总汇总清单（`data/scan_ips.txt`）**：按缓冲状态与存活状态分段，段内按实测延迟升序排列；机房 ASN 专属分类则由 `data/scan_ips/*.txt` 独立提供。
  2. **独立机房厂商文本（`data/scan_ips/ASxxx_厂商.txt`）**：在 `data/scan_ips/` 目录下按 ASN 及厂商名拆分生成独立文件（如 `data/scan_ips/AS906_DMIT.txt`、`data/scan_ips/AS210644_Aeza.txt`、`data/scan_ips/AS212336_ByteVirt.txt`），内容为纯净的 `IP:端口`，无任何注释，方便单独导入或按机房远程订阅。
  3. **结构化总表（`data/scan_ips.csv`）**：按 ASN 字母序聚合排序，方便通过 Excel 集中筛选分析。

### 4. `data/proxyip/`（反代 ProxyIP 专属池、分国别与网络属性分类）
* **独立反代池**：专门收录来自频道发布的反代文件（如 `Global-proxyip-443.csv`、`Global-proxyip-8443.csv` 等）。
* **质检分层排序与分国专属列表**：`data/proxyip.txt` 按缓冲状态与存活状态清晰分段，段内按实测延迟升序排列；各国家/地区专属分类由 `data/proxyip/*.txt` 独立提供。
* **分国家/地区独立单文件**：
  - `data/proxyip/*.txt`：在 `data/proxyip/` 目录下按国家/地区拆分为独立文件（如 `data/proxyip/美国.txt`、`data/proxyip/日本.txt`、`data/proxyip/香港.txt` 等），内容为纯净的 `IP:端口` 格式，方便直接复制或作为分地区订阅。
* **特殊网络类型提取（基于 ASN 静态属性的离线粗筛机制）**：
  在抓取的反代节点中，绝大多数属于常规云服务器或机房托管 IP。系统通过 **ASN 分类规则与关键词清洗**，从混合池中筛选出潜在的运营商网络、商业专线及教育科研资产，在 `data/proxyip/` 目录下单独导出（文件名前缀加 `【...】`，排序置顶）：
  - **`【ISP_运营商原生宽带】.txt`**：电信运营商原生宽带与精品线路网络（收录 中国电信 CN2、中国联通 9929/CUG、中国移动 CMIN2，以及 Comcast, Spectrum, Cox, HKT, HKBN, KT, SK Broadband, Vodafone, Orange 等常见电信服务商）。
  - **`【BIZ_商业企业专线】.txt`**：企业商业专线与商务宽带（收录 AT&T Enterprises, PCCW Business 等）。
  - **`【EDU_高校教育科研】.txt`**：高校与学术科研网（收录 CERNET, University 等科研学术网络）。
  - **`【GOV_政务公共网络】.txt`**：政务公用网与国家通信骨干。
  所有特殊分类清单同样采用 **纯净 `IP:端口`（按延迟升序排列，无多余注释）**，方便直接使用。
* **技术实现与边界说明（两级分层分类体系）**：
  - **执行逻辑**：
    1. **Tier 1（内置精准对照，Fast-path Lookup）**：智能正则提取 AS 编号，优先与内置核心 ASN 映射字典比对（涵盖电信 CN2 AS4809、联通 9929 AS9929、移动 CMIN2 AS58807 以及 HKT、HKBN、Comcast、KT 等自治系统，以及 Cloudflare、AWS、Azure 等机房锁定），快速判定网络类型；
    2. **Tier 2（启发式词根规则智能匹配，Pattern Fallback）**：针对对照表中未收录的冷门/新出现 ASN，或上游仅提供文本名称的数据行，自动进入词根模式识别（优先识别教育与政务网，排除 `host`/`cloud`/`vps`/`datacenter` 等机房关键词，随后识别商业专线与运营商原生宽带）；
    3. **Tier 3（降级兜底，Default Fallback）**：未命中的节点稳妥归入 `datacenter` 机房，避免泛化误分类。
  - **网络分类对照基准**：
    代码内置与 `asn_database.json` 合并维护 1,800+ 条独立自治系统的网络分类基准表（`ASN_EXACT_NET_TYPE`，与 1,000+ 条双向索引字典独立分工），覆盖主流电信运营商、企业专线与机房；遇到未收录的冷门自治系统时，分类引擎会自动进入启发式词根识别与机房兜底；且在 `tg_fetch.py` 增量抓取到未收录新自治系统时，会自动在线解析入库并在 Telegram 卡片中提示归属确认。
  - **挑选定位与后续筛选（粗筛候选池）**：
    本项目中的 ISP 及特殊网络归属主要作为**第一阶段的「ASN 粗筛」**。其核心作用是从海量混合扫描池中，通过自治系统属性快速甄别出潜在的民用宽带资产并剔除托管机房。这批导出的特殊列表本质上是**经过自治系统分类后的粗筛候选池**，使用者后续可根据具体应用需求，将粗筛出的节点**继续进行深入的连通性与穿透检测筛选**。
  - **客观界限**：
    由于 Tier 1 / Tier 2 顶级电信运营商（如 HKT, SK Broadband, Comcast, Charter 等）名下的自治系统（ASN）属于综合广播，同一个自治系统内部通常既广播给普通居民家庭宽带，也广播给本地商户静态专线，甚至包含部分自建机房。因此，**在不调用商业付费 IP 库的前提下，本机制依据的是自治系统（ASN）广播属性筛选（排除已知托管机房），无法保证属于居民家庭光纤。**
  - **风控特性参考**：
    非机房 ASN 在部分网站的 IP 风险评分中通常被定性为 ISP 或 Business，相比机房 Hosting IP 较少被直接标记为代理，但在实际使用中效果仍取决于目标站点的风控策略与节点当前状态。
* **结构化数据**：`data/proxyip.csv` 与 `data/proxies.csv` 均包含 `net_type` 字段（取值：`datacenter`、`isp`、`business`、`education`、`government`、`banking`），保留网络属性画像，基于内置 1,800+ 条网络分类字典快速定性。

### 5. 数据表通用字段说明
* 采用 `UTF-8-SIG` 编码，Windows Excel 直接双击打开不乱码。
* 数值字段（`delay_ms`, `speed_kbs`）均为纯数字，并在保存时按**质检状态（`fail_count` 升序）、可用性与低延迟（`delay_ms` 升序）、测速探测时间（`tested_at` 降序）**执行多重稳定质量排序。
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
| `asn` | 字符串 | **【核心规范】** 『ASN 编号 + 服务商名称』一体化直观标签 | `AS400618 Prime Security Corp.` |
| `isp` | 字符串 | 自治系统所属运营商 / 托管商组织名称 | `Prime Security Corp.` |
| `tested_at` | 时间字符串 | 测速与发布时间 | `2026-09-13 18:00:33` |
| `channel` | 字符串 | 来源频道 | `@danfeng_chat` / `@otcfxq` |
| `fail_count` | 整数 | 连续探测失败次数（默认 0，连续失败 ≥ 3 次自动淘汰剔除） | `0` |

#### ② 反代 ProxyIP 穿透与网络属性数据表（`data/proxyip.csv`）
*共 13 个字段，除基础网络字段外，包含 `net_type`（两级分层网络识别）核心资产属性：*

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `ip` | 字符串 | 反代 IP 地址 | `104.16.132.229` |
| `port` | 整数 | 反代端口 | `443` |
| `tls` | 字符串 | 是否开启 TLS (`true`/`false`) | `true` |
| `delay_ms` | 整数 | /cdn-cgi/trace 穿透响应延迟（毫秒） | `145` |
| `speed_kbs` | 整数 | 下载速度（kB/s 纯数值，保留字段） | `0` |
| `colo` | 字符串 | 穿透返回的 Cloudflare 实际处理机房三字码 | `HKG` |
| `cf_location` | 字符串 | 落地地理位置 | `中国 · 香港特别行政区` |
| `asn` | 字符串 | **【核心规范】** 『ASN 编号 + 服务商名称』一体化直观标签 | `AS9269 HKBN Hong Kong Broadband` |
| `isp` | 字符串 | 自治系统组织 / 运营商组织全称 | `HKBN Hong Kong Broadband` |
| `tested_at` | 时间字符串 | 穿透质检测试时间 | `2026-09-19 18:00:00` |
| `channel` | 字符串 | 来源频道或附件源 | `@danfeng_chat` |
| `fail_count` | 整数 | 连续探测失败次数（连续失败 ≥ 3 次永久物理删除） | `0` |
| `net_type` | 字符串 | **【核心属性】** 网络类型归属（详见下方 6 类取值说明） | `isp` |

> 📌 **`net_type` 网络分类取值与对应导出品**：
> - `isp`：运营商原生民用宽带（ASN 粗筛候选） ➔ 对应导出 `data/proxyip/【ISP_运营商原生宽带】.txt`
> - `business`：商业专线与企业宽带 ➔ 对应导出 `data/proxyip/【BIZ_商业企业专线】.txt`
> - `education`：高校教育科研网 ➔ 对应导出 `data/proxyip/【EDU_高校教育科研】.txt`
> - `government`：政务公用网与国家骨干 ➔ 对应导出 `data/proxyip/【GOV_政务公共网络】.txt`
> - `banking`：银行金融与中央银行专网 ➔ 对应导出 `data/proxyip/【BANK_银行金融专网】.txt`
> - `datacenter`：常规数据中心/托管机房 ➔ 归入各国家/地区常规列表

#### ③ 通用代理质检数据表（`data/proxies.csv`）
*共 15 个字段，记录 SOCKS5/HTTP/HTTPS/TURN/SSTP 等通用代理应用层穿透结果、出口机房国家、出口真实 IP、自治系统 ASN、运营商 ISP 组织、原生家宽/数据中心属性、质检状态与首次收录生命周期：*

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `url` | 字符串 | 包含协议、账号密码、主机的完整代理 URL | `socks5://user:pass@1.2.3.4:1080` |
| `proto` | 字符串 | 协议类型（`socks5`、`http`、`https`、`turn`、`sstp`） | `socks5` |
| `host` | 字符串 | 节点域名或 IP 地址 | `1.2.3.4` |
| `port` | 整数 | 服务端口 | `1080` |
| `delay_ms` | 整数 | RFC 1928 握手与穿透测速延迟（毫秒纯数值） | `320` |
| `fail_count` | 整数 | 连续探测失败次数（连续失败 ≥ 3 次自动淘汰剔除） | `0` |
| `status` | 字符串 | 探测状态（`alive` 存活 或 `fail` 失败） | `alive` |
| `colo` | 字符串 | 通过该代理中继访问返回的 Cloudflare 机房代号 | `NRT` |
| `country` | 字符串 | 出口落地国家或地区 ISO 二字代码（Cloudflare trace `loc`） | `JP`、`US` |
| `egress_ip` | 字符串 | 代理节点向外访问时 Cloudflare 观测到的出口真实 IP（直连隧道为节点 host） | `198.51.100.2` |
| `asn` | 字符串 | 自治系统编号与运营商标准归属（一体化直观标签） | `AS13335 Cloudflare`、`AS34343 Eweka` |
| `isp` | 字符串 | **【核心凭据】** 自治系统所属运营商 / 托管商组织名称（与 `proxyip.csv` 规范统一对齐） | `Cloudflare, Inc.`、`Eweka Internet Services B.V.` |
| `net_type` | 字符串 | **【核心凭据】** 网络类型属性分类（`isp` 原生家宽 / `datacenter` 机房 / `business` 商业专线等） | `isp`、`datacenter` |
| `tested_at` | 时间字符串 | 质检探测完成时间 | `2026-09-19 18:35:00` |
| `first_seen` | 时间字符串 | 首次收录时间（以第一次抓取入库为准，永久不变，用于统计节点存活时长与长期可用性；注：针对 2026-10-01 前无此字段的历史旧节点，统一兼容赋予 2026-10-01 00:00:00 作为基准初值） | `2026-10-01 00:00:00` |

---

### 6. 核心认知与架构解析：ASN 与 ISP 的本质区别与一体化设计规范

为确保全系统数据结构的科学严谨性与日常使用的极致直观性，本项目彻底厘清了 **ASN（自治系统编号）** 与 **ISP（互联网服务提供商）** 的定义边界、层级关系与工程协同：

#### ① 什么是 ASN（自治系统编号，Autonomous System Number）？
* **定义与技术本质**：
  ASN 是由全球互联网数字分配机构（**IANA**）及其下属五大区域性互联网注册机构（**RIR**，如负责亚太的 APNIC、负责北美的 ARIN、负责欧洲的 RIPE NCC 等）全球统一分配的**自治网络唯一数字标识号**（格式固定为 `AS` 前缀加纯数字，如 `AS906`、`AS13335`、`AS4134`）。
* **网络层意义（BGP 路由自治体）**：
  拥有独立 ASN 的机构，代表其拥有在跨国骨干网之间运行 **BGP（边界网关协议）** 的自主权，能够自主宣告其持有的 IP 地址块（IP Prefixes），并与全球其它电信运营商建立互联对等（Peering / Transit）。全球跨网数据路由寻路，本质上就是在不同 ASN 之间跳转。
* **技术唯一性**：ASN 是**机器可读、全球绝对唯一**的网络层技术编号。

#### ② 什么是 ISP（互联网服务提供商，Internet Service Provider）？
* **定义与实体本质**：
  ISP 是现实商业世界中实际出资建设、物理拥有并运营维护该网络设施与数据中心/宽带业务的**商业法人实体、电信运营商或云厂商组织机构**（例如 `China Telecom`、`DMIT Inc.`、`Cloudflare, Inc.`、`Hong Kong Broadband Network`）。
* **业务层意义（商业与运营实体）**：
  它代表的是**商业实体身份与法律责任主体**。现实中，用户订购宽带、租用服务器、购买专线，合同签约方都是该实体 ISP。
* **名称多样性**：ISP 名称通常为商业注册文字，常伴有别名、母子公司简称或地方分部名称（如 `The Constant Company, LLC` 俗称 `Vultr`）。

#### ③ ASN 与 ISP 的关键区别与多维映射关系对照

| 对比维度 | ASN（自治系统编号） | ISP（互联网服务提供商） |
| :--- | :--- | :--- |
| **所属层级** | 互联网网络技术与 BGP 动态路由层（**网络层技术身份**） | 现实商业世界与网络运营实体（**现实商业实体身份**） |
| **标识表现** | 严谨的全球唯一数字编号：如 `AS906`、`AS4134` | 商业机构名称/商标全称：如 `DMIT`、`China Telecom` |
| **分配管理** | IANA / APNIC / ARIN 等国际 IP 与自治网络管理机构 | 各国工商企业登记及工信电信监管部门 |
| **映射关系** | **1 对 N / N 对 1 复杂非对称映射**：<br>1. **一个 ISP 拥有多个 ASN**：电信巨头往往按业务分拆多个 ASN（如中国电信同时拥有 `AS4134` 骨干网、`AS4809` CN2 高端精品网、`AS58772` 国际分部）；<br>2. **多个主体共用上游 ASN**：小型转售商可能广播于上游机房的同一个 ASN 下。 | 实体公司可拥有一个或多个自治网络运营资质与号段 |
| **本项目存储** | **『ASN + 服务商名称』一体化直观标签**：<br>例如 `AS906 DMIT Cloud Services`、`AS13335 Cloudflare`<br>（兼具人类肉眼快速辨识与机器正则提取 `AS\d+`） | **规范机构组织全称**：<br>例如 `DMIT Inc.`、`Cloudflare, Inc.`<br>（用于底层实体溯源、Tier 1 权威映射与离线分析） |

#### ④ 常见认知混淆说明
1. ❌ **误区一：拿技术编号当商业品牌（数字冒充 ISP）**
   * *常见情况*：直接将 `AS906` 填入 ISP 字段，导致用户仅看到纯数字代号，无法直观辨识具体服务商。
2. ❌ **误区二：拿商业品牌丢弃技术编号（品牌冒充 ASN）**
   * *常见情况*：将 `DMIT` 填入 ASN 字段，丢失了原始的 `AS906` 编号，导致无法按自治系统编号进行网络聚类。
3. ❌ **误区三：单向割裂无映射**
   * *常见情况*：命名格式不一致，导致同一机房不同批次的数据难以对齐。

#### ⑤ 本项目的数据展示规范
* **`format_asn_isp()` 一体化直观标签与别名保留**：输出为 `AS{编号} {服务商}` 结构，使在查看 CSV 表格、订阅列表文件名（如 `data/scan_ips/AS906_DMIT.txt`）以及 Telegram 统计卡片时既能看清编号也能辨识品牌。对于多租户品牌（如 GTHost 租用 Ipxo LLC 广播），规范保留别名为 `AS63023 Ipxo LLC (GTHost)`，具备幂等性避免嵌套。
* **`asn_database.json` 双向索引与网络分类知识库**：维持 1,000+ 条服务商双向索引字典（`isp_to_asn` / `asn_to_isp`）及 1,800+ 条网络分类基准表（`asn_to_net_type`），配合权威字典对 `asn` 列实现一体化直观归类，并在抓取阶段支持自动在线解析与增量持久化回写。

---

### 7. 主动质检与缓冲淘汰体系
为防止失效节点堆积，系统配备了主动质检探测机制：

#### ① 多协议通用代理质检引擎（`proxies_verify.py`）
* **协议握手探测**：
  * **SOCKS5**：RFC 1928 握手协商（无密 `0x00` / 账密 `0x02` RFC 1929）➔ 发送 CONNECT 指令 ➔ 穿透请求 `/cdn-cgi/trace` 检验 200 与机房。
  * **HTTP / HTTPS**：CONNECT 隧道穿透 + 正向代理回退双路径校验。
  * **TURN / STUN**：构造 RFC 5389 STUN Binding Request 二进制包，校验 Magic Cookie (`0x2112A442`) 与 Transaction ID。
  * **SSTP**：MS-SSTP 标准双工隧道握手（TLS 握手 + `SSTP_DUPLEX_POST` 校验 `HTTP/1.1 200 OK` 确认服务就绪）；支持配置自建 Cloudflare Worker 进行第二阶段真实出口 IP 与 PPP 链路鉴真。
* **淘汰机制**：连续失败达到阈值（默认 3 次）从 `data/proxies.txt` 与 `data/proxies.csv` 中清理剔除。

#### ② 反代 ProxyIP 穿透质检引擎（`proxyip_verify.py`）
* **穿透鉴真**：向反代节点发起 TLS 握手，发送 HTTP/1.1 GET `/cdn-cgi/trace` 探针请求。采用统一 Deadline 超时控制与循环读取（`read_full_response`），严格切分 Header 与 Body 区域，校验状态码与 Server 标头，提取有效 `colo` 机房代号。
* **参数配置**：握手与连接超时设为 `4.0s`（HTTP 读取 `3.5s`），兼容高延迟跨洲网络；默认并发控制为 `250` 协程，配合哈希分段锁平滑调度。
* **淘汰机制**：连续失败达到阈值（默认 3 次）从 `data/proxyip.txt` 与 `data/proxyip.csv` 中清理剔除，并登记入墓地（`data/tombstone.json`）进行 7 天冷却隔离。

#### ③ 优选 IP 两阶段主动鉴真引擎（`cf_verify.py`）
* **全量优选 IP 覆盖**：优选 IP（涵盖 `data/scan_ips` 扫描测速与 `data/cf_ips` 每日单条）执行两阶段探测：
  * **阶段一（TLS 握手 + 证书鉴真）**：建立 TLS 握手并验证 `crypto.cloudflare.com` 官方证书有效性。
  * **阶段二（同一连接 HTTP 301 重定向 + 服务头验证）**：在同一连接发送 GET 请求，循环读取切分 Header 区域，校验状态行 `301` 与 `Server: cloudflare`。
  * **端口与格式校验**：入库加载前进行端口范围校验（`1 <= port <= 65535`），非法格式行自动累加失败计数并剔除。
* **联动剔除**：达到淘汰阈值（默认 3 次）的失效节点，同步从 `scan_ips` 与 `cf_ips` 各产物中清理删除。

#### ④ 淘汰节点墓地冷却机制（`data/tombstone.json`）
* **阻断失效节点回流**：由于抓取存在历史回溯窗口（默认 3 天），若仅在质检时删除节点，下一次抓取历史消息时容易重复抓回。墓地机制通过登记失效节点的主键，在抓取阶段直接过滤。
* **机制特点**：
  * **跨工作流持久化**：被淘汰的节点提取键名（`canonical_key`，如 `host:port`）登记入 `data/tombstone.json`，由 Git 跟踪并在工作流运行时同步。
  * **7 天隔离期与自动修剪**：默认设置 7 天冷却期，覆盖 3 天抓取回溯窗口。在读取与登记时自动清除超过 7 天的过期记录，保持轻量。
  * **源头拦截**：`tg_fetch.py` 在加载本地历史、抓取正文消息及解析附件时比对墓地记录，过滤已淘汰的失效节点，避免因频道历史回溯重复抓取入库。

#### ⑤ 双向索引与网络分类知识库（`data/asn_database.json`）
* **双向索引与网络分类分层维护**：维护 1,000+ 条权威服务商双向索引（`isp_to_asn` 1,080+ 条 / `asn_to_isp` 1,020+ 条）以及 1,800+ 条独立自治系统网络分类基准表（`asn_to_net_type` 1,870+ 条），优先通过本地离线数据与云厂商特征词库匹配，零外部网络查询开销。
* **自动增量维护与持久化**：抓取阶段若遇到未收录新 ASN，系统自动通过并发在线查询进行自愈式补全，自动落盘写入 `data/asn_database.json` 并由 GitHub Actions 自动 commit 推送回仓库，保持知识库长期自适应演进。
* **防覆盖与安全隔离**：
  * **权威名称防污染**：反查出的 ASN 若已收录于本地权威字典，保留规范化标准名称；针对多租户/分销品牌（如 Claw Cloud 复用阿里云 `AS45102`），保留别名为 `AS45102 Alibaba Cloud (Claw Cloud)`。
  * **两级查表匹配**：第一级执行精准哈希匹配，避免将含 IDC 字符串的名称误判为具体 ASN；第二级仅对权威别名执行词界匹配。
  * **分类保护**：仅对明确的云主机厂商归入机房类别，避免高校学术网与电信宽带被误打标。

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
| `TG_SESSION_STR` | Telethon 会话认证字符串 | 官方 API 模式 | API 必填 | 本地运行 `python gen_session.py` 登录生成。<br>⚠️ **极高敏感度凭据**：Session 字符串等价于 Telegram 账号在当前设备的完整登录凭据（可免验证码直接访问），请严密保管，切勿在公开 Issues、截图或构建日志中暴露！ |
| `TG_BOT_TOKEN` | Telegram 通知机器人 Token | 推送卡片 | 可选 | 从 [@BotFather](https://t.me/BotFather) 获取 |
| `TG_CHAT_ID` | 通知接收人 / 频道 / 群组 ID | 推送卡片 | 可选 | 机器人的目标推送聊天 ID |

### 2. Repository Variables（常规运行变量 · 位于 Variables 标签页 · 全可选）

> 💡 **自适应配置机制**：
> - **Variables 默认全部留空即可正常自动运行**，仓库代码内置了开箱即用的默认值。
> - **覆盖优先级（网页配置优先）**：若在 GitHub 网页的 Variables 标签页中配置了自定义变量，系统将优先采用您自定义配置的频道或参数；若留空或未配置，则自动无缝回退至代码内置默认值（如未配置时自动抓取 `@otcfxq` 与 `@danfeng_chat`），完全无需手动干预。

| 变量名 | 用途 | 默认值 | 必要性 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| `FETCH_DAYS` | 单次增量回溯天数（扫描时间窗口） | `3` | 可选 | 增量模式下只读取最近 N 天频道消息，加快运行速度 |
| `FETCH_MAX_PAGES` | Web 免登录模式最大抓取页数 | `35` | 可选 | 控制无凭据网页爬虫向前抓取历史消息的最大分页数（每页约 20 条消息） |
| `PROXY` | 抓取代理设置 | 留空 | 可选 | GitHub Actions 云端默认直连 Telegram 无需配置；自建私有 Runner 或特殊网络时可按需配置 |
| `PROXY_CHANNELS` | 代理抓取目标频道/群组（逗号/空格分隔） | `@otcfxq, @danfeng_chat` | 可选 | 自定义抓取通用代理的频道/群组（若未配置自动回退至全局 `CHANNELS` 或默认值） |
| `CF_IP_CHANNELS` | 优选 IP 抓取目标频道/群组（逗号/空格分隔） | `@otcfxq, @danfeng_chat` | 可选 | 自定义抓取 Cloudflare 优选 IP 与测速附件的频道/群组（若未配置自动回退至全局 `CHANNELS` 或默认值） |
| `SUB_URLS` | 外部通用订阅源 URL 列表（逗号/换行分隔） | `sub.cmliussss.net/vpngate` (留空默认) | 可选 | 配置外部公开订阅链接（默认加载开源公共镜像 `https://sub.cmliussss.net/vpngate` 获取 VPNGate SSTP 节点）；如需**彻底禁用外部订阅**，设置为 `off`、`none` 或 `false` 即可；也可填入自有公开订阅链接 |
| `CF_CHECK_ENDPOINT` | SSTP 代理出口检测端点 URL | 留空（不执行） | 可选 | 用于存活 SSTP 节点的第二阶段真实出口 IP 与链路鉴真。<br>💡 **需自行部署**：本项目**默认不预设第三方公共端点**（避免占用他人私人项目额度）。推荐使用开源项目 [CF-Workers-CheckSocks5](https://github.com/cmlius/CF-Workers-CheckSocks5) 部署到个人 Cloudflare Workers 免费账号（每日 100,000 次免费请求额度），部署后将个人 Worker 域名填入此处。若留空则仅使用本地探测，完全不调用外部服务。 |

### 3. 高级调优参数与本地调试对照（可选）

各引擎脚本还支持以下高级命令行参数，可在本地开发或工作流调整时使用（GitHub Actions 默认已自动配置最优参数）：

| 参数名 / 选项 | 对应脚本 | CI 预设值 | 默认值 | 说明 |
| :--- | :--- | :---: | :---: | :--- |
| `--concurrency` | 校验脚本 | `反代 250 · 优选 250 · 代理 300` | `代理 300 · 反代 250 · 优选 250` | 质检异步并发协程数，平滑并发兼顾探测速度与对端防刷 |
| `--max-fails` | 校验脚本 | `全部引擎统一为 3` | `全部引擎统一为 3` | 连续失败物理淘汰阈值（全线引擎统一默认 3 次，允许 1~2 次网络抖动缓冲；设为 `1` 即为严格无缓冲模式） |
| `--timeout` | 校验脚本 | `反代 4.0 · 优选 3.0 · 代理 3.0` | `代理 3.0 · 反代 4.0 · 优选 3.0` | 单节点连接建立与 TLS 握手超时秒数（反代默认 4.0s 充分兼容跨洲 RTT） |
| `--http-timeout` | `proxyip_verify.py` | `3.5` | `3.5` | 反代 HTTP /cdn-cgi/trace 响应读取统一 deadline 超时秒数 |
| `--cf-check-endpoint` | `proxies_verify.py` | 留空 | 留空 | SSTP 真实出口与 PPP 链路鉴真端点 URL (默认留空不执行外部检测，需自行部署 CF-Workers-CheckSocks5) |
| `--no-notify` | 校验脚本 | 流水线静默 | 关闭 | 不单独推送各引擎卡片，由流水线终点聚合为四合一卡片 |
| `DEFER_NOTIFY` | `tg_fetch.py` | `1` | `0` | 延迟 Telegram 推送标记，确保四合一卡片聚合完整 |

---

## 📱 Telegram 运行通知卡片示例

配置 `TG_BOT_TOKEN` 与 `TG_CHAT_ID` 后，流水线运行完成会自动发送四维合一的现代精简风统计卡片：

```text
🚀 节点与优选 IP 同步完成 (🟢 发现 +25 新增 · 🗑️ 剔除 31 死节点)
━━━━━━━━━━━━━━━━━━━━
📅 时间：2026-09-17 18:35:00 (北京时间)
📫 可用代理：741 个 (✅ 698 存活 · ⚠️ 43 缓冲 [+5 新增 · 8 取消] · ⚡ 均延 520ms)
🌐 单条优选：37 条 (✅ 28 存活 · ⚠️ 9 缓冲 [+1 新增 · 3 取消])
📁 扫描优选：5,015 条 (✅ 4,862 存活 · ⚠️ 153 缓冲 [+24 新增 · 31 取消] · 20 个 ASN)
   └ 涵盖: Aeza, DMIT, ByteVirt, Starry Network 等
🔀 反代 ProxyIP：30,545 条 (✅ 29,820 存活 · ⚠️ 725 缓冲 [+95 新增 · 61 取消])
💡 发现未收录 ASN (可补充入库)：
   • AS213233 FastPath Network (12 条)
   • AS216386 HostCircle Inc. (5 条)
   └ 共 2 个待确认归属
━━━━━━━━━━━━━━━━━━━━
🛡️ 主动鉴真淘汰：
   • 缓冲动态：⚠️ 新增缓冲 125 条 · ♻️ 取消缓冲 103 条 (恢复健康)
   • 优选检验：TLS 握手 + HTTP 301 (250 并发)
   • 代理检验：RFC 1928 全协议穿透鉴真
   • 反代检验：/cdn-cgi/trace 穿透鉴真
   • 淘汰死节点：31 条 [代理 12, 反代 15, 扫描优选 4] (连续失败 ≥ 3 次)
📡 频道来源：@danfeng_chat, @otcfxq
━━━━━━━━━━━━━━━━━━━━
⚡ 总耗时: 165.2s · 🔗 Action #35 · 📦 产物仓库
```

* **锁屏即知变动**：首行支持 `(🟢 发现 +N 新增 · 🗑️ 剔除 N 死节点)` 双状态动态高亮组合呈现，变动一目了然。
* **增量与健康一览（核心：什么是“存活”、“新增缓冲”与“取消缓冲”？）**：
  - **✅ 当次存活（`fail_count = 0`）**：在当次 CI 流水线中成功通过真实握手/穿透质检的节点，排在产物最前列优先使用。
  - **⚠️ 缓冲保护（`1 <= fail_count < 3`）**：在当次探测中因公网跨洲抖动、偶发丢包或目标端短暂限流导致超时的节点。系统设定了 **1~2 次容忍缓冲期**（排在存活节点之后保留，连续 3 次失败才彻底物理淘汰）。
  - **📊 跨轮次动态对比（评估质检算法准确性）**：
    - **`+N 新增`（首次转入缓冲）**：上一次运行还是健康可用（`old_fail_count = 0`）的节点，在本次探测中首次出现不可达（`new_fail_count = 1`）。若单次大面积激增，通常提示外部跨洲网络波动或对端短时限流。
    - **`N 取消`（取消缓冲 · 自愈恢复）**：上一次运行处于缓冲期（`old_fail_count > 0`）的节点，在本次探测中重新连通成功、`fail_count` 自动清零恢复健康！
    - **准确性评估价值**：「取消缓冲」的持续发生，直接印证了缓冲保护机制的抗误杀鉴真能力——成功挽救了被瞬时网络波动假死误伤的有效节点；通过观察新增与取消缓冲的动态平衡，可以清晰量化当前网络环境与校验方法的真实稳定性。
  - **⚡ 均延计算纯净度**：实测平均延迟（如 `均延 520ms`）**仅计算当次实测存活节点**的最新耗时，严格排除处于缓冲期失败节点的历史陈旧数据污染。
* **自适应未知预警**：遇未收录新自治系统时动态展示 `💡 发现未收录 ASN (可补充入库)` 明细（展示前 4 个及待确认总数），全量命中时自动隐藏，0 视觉噪音。
* **主动鉴真审计**：实时汇报全协议穿透质检、TLS + 301 重定向鉴真与连续失败永久淘汰数量。
* **细分淘汰明细**：底栏汇报各引擎分类淘汰数量 `[代理 X, 反代 Y, 扫描优选 Z]`，精准掌控全库死节点流失情况。
* **厂商覆盖一览**：自动统计展示覆盖的主力机房与服务商。
* **一键直达日志**：附带 GitHub Action 运行记录与产物仓库直达超链接。

---

## 🚀 云端自动化部署指南（推荐 · 3步极简托管）

本项目可完全托管于 **GitHub Actions** 自动运行，所有抓取、质检、推送到 `data/` 及日志维护完全在云端完成，**日常使用无需在本地电脑常开脚本，也无需自备服务器**。

### 第一步：Fork 本仓库
点击仓库右上角 **Fork** 按钮，将本项目复制到您的个人 GitHub 账号下。

### 第二步：配置 GitHub Secrets（按需选择模式）
进入您的 Fork 仓库，点击 **Settings -> Secrets and variables -> Actions**，添加 Repository secret：

#### 方案 A：🚀 零门槛免登录模式（开箱即用）
* **无需配置任何密钥**！
* 保持 Secrets 留空即可，系统自动以 Web 免登录模式运行，定时同步公开频道消息正文中的通用代理与单条优选 IP。

#### 方案 B：🛡️ 官方 API 全功能模式（强烈推荐 · 解锁机房测速大池与反代池）
若需要自动下载附件（获取 DanFeng CSV、OTC 测速扫描 TXT、ProxyIP 反代池等附件）：
1. 访问 [my.telegram.org](https://my.telegram.org) 登录获取 `API ID` 与 `API Hash`。
2. **（仅需在本地运行一次）** 生成认证字符串（因 Telegram 登录需交互式输入手机验证码）：
   ```bash
   pip install telethon
   python gen_session.py
   ```
   按终端提示输入手机号与验证码后，控制台将输出一串 Session 字符串。（脚本内置自动识别本地运行的代理端口，并以 SOCKS5 远程 DNS（`rdns=True`）模式直连 Telegram，国内开发环境免受 DNS 污染困扰，开箱平滑直连）。
3. 在 GitHub Secrets 中填入对应 3 项：
   - `TG_API_ID`：你的 API ID（纯数字）
   - `TG_API_HASH`：你的 API Hash（32 位字符）
   - `TG_SESSION_STR`：生成的 Session 字符串

#### 方案 C：📱 Telegram 统计卡片与即时告警（可选）
若希望每天收到汇总统计卡片，并在流水线异常时及时收到警报：
- `TG_BOT_TOKEN`：Telegram 机器人 Token（从 [@BotFather](https://t.me/BotFather) 获取）
- `TG_CHAT_ID`：目标接收人 / 频道 / 群组 ID

---

### 第三步：启用 Actions 定时任务
1. 打开仓库的 **Actions** 标签页，点击绿色按钮开启工作流权限（*“I understand my workflows, go ahead and enable them”*）。（注：流水线 YAML 已显式声明 `permissions: contents: write` 与 `actions: write`，开箱即支持自动提交数据产物与清理历史运行；若为 Fork 仓库，可在 Settings -> Actions -> General 中确认 "Workflow permissions" 允许读写）。
2. **自动定时调度**：每天 **北京时间 08:15（UTC 00:15）** 自动执行完整的流水线（位于 Cloudflare Workers 每日免费额度刷新后，并微调 15 分钟避开整点排队拥堵）。
3. **手动随时触发**：在 Actions 页面左侧点击 **Fetch Proxies and CF IPs** ➔ **Run workflow**，支持自定义输入 `fetch_days` 与 `cf_check_endpoint`，按需随时触发同步。

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
# ① 语法、静态门禁与核心回归测试（与 GitHub Actions 门禁一致，执行语法、未定义变量、ASN 结构与逻辑回归测试）
python -m py_compile *.py
pip install ruff
ruff check . --select F82
python providers.py --validate
python -m unittest discover -s tests

# ② 通用代理连通性质检
python proxies_verify.py --concurrency 100 --no-notify

# ③ 反代 ProxyIP 应用层穿透质检
python proxyip_verify.py --concurrency 150 --no-notify

# ④ 全量优选 IP 两阶段（TLS + HTTP 301）主动鉴真
python cf_verify.py --concurrency 150 --timeout 3.0
```

---

## 🙏 致谢

本项目节点与优选 IP 数据源来自以下 Telegram 公开频道，在此表示感谢：

- [@otcfxq](https://t.me/otcfxq)
- [DanFeng 交流群 (@danfeng_chat)](https://t.me/danfeng_chat)

---

## 📄 开源许可证 / License

本项目遵循 [MIT License](LICENSE) 协议开源。
