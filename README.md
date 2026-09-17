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
| **运行门槛** | **无需任何密钥或账号**<br>Fork / Clone 即可直接运行 | **需配置 3 项 Secret**<br>`TG_API_ID`、`TG_API_HASH`、`TG_SESSION_STR` |
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
- **🧩 模块化解耦与统一映射**：提取独立 `providers.py` 作为云厂商与 ASN 规范化字典的单一真相源（Single Source of Truth），保障校验脚本零依赖独立冷启动。
- **📱 动态双状态 Telegram 运行卡片**：首行支持「🟢 发现新增 + 🗑️ 剔除死节点」双状态动态高亮呈现，底栏包含细分引擎淘汰明细 `[代理 X, 反代 Y, 扫描 Z]`，锁屏即知变动。
- **🌐 Windows 本地智能环境自适应**：本地运行自动读取 Windows 系统代理（如 v2rayN 等），无缝突破网络限制。
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
| **`providers.py`** | **公共规范映射中心**：维护云厂商名称归一化规则与关键 ASN 映射表，作为全系统单一真相源（Single Source of Truth）。 |
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
| **`data/proxyip.txt`** | 反代 ProxyIP 清单（纯文本） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.txt` |
| **`data/proxyip.csv`** | 反代 ProxyIP 详细数据表 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip.csv` |
| **`data/proxyip_cf.txt`** | 兼具优选直连特性的提纯反代清单 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/data/proxyip_cf.txt` |

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
* **连续失败缓冲保护（`--max-fails 2`）**：首次探测失败标记缓冲（`fail_count=1`），连续 2 次全网不可达方才彻底剔除，避免公网抖动误杀。
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

### 4. `data/proxyip.txt` / `data/proxyip.csv` / `data/proxyip_cf.txt`（反代 ProxyIP 专属池）
* **独立反代池**：专门收录来自频道发布的反代文件（如 `Global-proxyip-443.csv`、`Global-proxyip-8443.csv` 等）。
* **纯净即用**：`data/proxyip.txt` 导出纯净 `IP:端口`，可直接复制或配置于 edgetunnel / Cloudflare Workers 作为反代地址。
* **双能提纯直连（`data/proxyip_cf.txt`）**：由质检引擎并发探测，自动筛选提纯出既能作为反代穿透、又兼具 Cloudflare 官方证书 TLS 握手直连特性的优质节点，是兼具双料特性的极品清单。
* **结构化数据**：`data/proxyip.csv` 保留延迟、数据中心、落地位置与 `cf_clean` 优选标记等关键信息。

### 5. 数据表通用字段说明
* 采用 `UTF-8-SIG` 编码，Windows Excel 直接双击打开不乱码。
* 数值字段（`delay_ms`, `speed_kbs`）均为纯数字，并在保存时按 **`tested_at`（测速时间）倒序排序**：

#### ① 优选 IP 表（`data/cf_ips.csv`、`data/scan_ips.csv`）及 反代表（`data/proxyip.csv`）

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `ip` | 字符串 | 优选 IP 地址 | `23.249.18.144` |
| `port` | 整数 | 服务端口 | `8581` |
| `tls` | 字符串 | 是否开启 TLS (`true`/`false`) | `true` |
| `delay_ms` | 整数 | 网络延迟（毫秒纯数值，便于排序） | `2` |
| `speed_kbs` | 整数 | 下载速度（kB/s 纯数值，便于排序） | `89086` |
| `colo` | 字符串 | Cloudflare 数据中心三字代码 | `HKG`、`NRT`、`LAX` |
| `cf_location` | 字符串 | Cloudflare 落地地理位置 | `亚太 · 香港` |
| `isp` | 字符串 | 网络运营商 | `Prime Security Corp.` |
| `asn` | 字符串 | ASN 编号与组织 | `AS400618 Prime Security Corp.` |
| `tested_at` | 时间字符串 | 测试/发布时间 | `2026-09-13 18:00:33` |
| `channel` | 字符串 | 来源频道 | `@danfeng2` / `@otcfxq` |
| `fail_count` | 整数 | 连续探测失败次数（默认 0，连续失败 ≥ 2 次自动淘汰剔除） | `0` |
| `cf_clean` | 字符串 | *(仅 `data/proxyip.csv`)* 是否兼具官方优选直连能力 (`true`/`false`) | `true` |

#### ② 代理质检表（`data/socks5.csv`）

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `url` | 字符串 | 包含协议、账号密码、主机的完整代理 URL | `socks5://user:pass@1.2.3.4:1080` |
| `proto` | 字符串 | 协议类型（`socks5`、`http`、`turn` 等） | `socks5` |
| `host` | 字符串 | 节点域名或 IP 地址 | `1.2.3.4` |
| `port` | 整数 | 服务端口 | `1080` |
| `delay_ms` | 整数 | 穿透测速延迟（毫秒纯数值） | `320` |
| `fail_count` | 整数 | 连续探测失败次数（连续失败 ≥ 2 次自动淘汰剔除） | `0` |
| `status` | 字符串 | 探测状态（`alive` 或 `fail`） | `alive` |
| `colo` | 字符串 | 通过该代理访问返回的 Cloudflare 数据中心三字代码 | `NRT` |
| `tested_at` | 时间字符串 | 质检探测完成时间 | `2026-09-17 18:35:00` |

---

### 6. 全线三大异步主动鉴真与缓冲淘汰体系
为防止长期累积的节点失效或死灰复燃，系统配备了三套独立的高并发主动质检探测引擎：

#### ① 代理连通性质检引擎（`socks_verify.py`）
* **全协议真实握手**：
  * **SOCKS5**：RFC 1928 握手协商（无密 `0x00` / 账密 `0x02` RFC 1929）➔ 发送 CONNECT 指令 ➔ 穿透请求 `/cdn-cgi/trace` 检验 200 与机房。
  * **HTTP / HTTPS**：CONNECT 隧道穿透 + 正向代理回退双路径校验。
  * **TURN / STUN**：构造 RFC 5389 STUN Binding Request 二进制包，严格校验 Magic Cookie (`0x2112A442`) 与 Transaction ID。
* **淘汰机制**：连续失败达到阈值（默认 2 次）彻底从 `data/socks5.txt` 与 `data/socks5.csv` 永久删除。

#### ② 反代 ProxyIP 穿透质检引擎（`proxyip_verify.py`）
* **穿透与优选双能探测**：
  * **穿透鉴真**：通过反代向 `speed.cloudflare.com:80` 发起真实 GET 请求，验证 `/cdn-cgi/trace` 穿透成功。
  * **优选直连探测**：并发探测该节点是否同时支持作为直连优选 IP（TLS 1.3 握手成功），自动生成兼具双料特性的 `data/proxyip_cf.txt` 极品清单。
* **淘汰机制**：连续失败 ≥ 2 次从 `data/proxyip.txt`、`data/proxyip.csv` 永久删除。

#### ③ 优选 IP 两阶段主动鉴真引擎（`cf_verify.py`）
* **全量优选 IP 覆盖**：无论来源，**只要是优选 IP（涵盖 `data/scan_ips` 扫描测速与 `data/cf_ips` 每日单条全线产物），一律全部执行阶段一与阶段二探测**：
  * **阶段一（TLS 握手 + 证书鉴真）**：建立 TLS 握手并验证 `crypto.cloudflare.com` 官方证书有效性。
  * **阶段二（HTTP 301 重定向 + 服务头验证）**：同一连接请求根路径，验证返回 `301 Moved Permanently` 且响应头包含 `Server: cloudflare`。
* **全产物联动删除剔除**：达到淘汰阈值的死节点，同步从 `data/scan_ips.csv`、`data/scan_ips.txt`、`data/scan_ips/*.txt`、`data/cf_ips.csv`、`data/cf_ips.txt` 中**彻底永久删除**。

---

## 环境变量配置

在 GitHub 仓库 **Settings -> Secrets and variables -> Actions** 中进行配置：

### 1. Repository Secrets（密钥配置）

> 💡 **启用官方 API 模式必须同时配置前三项**（`TG_API_ID`、`TG_API_HASH`、`TG_SESSION_STR`），任一缺失将自动降级为免登录 Web 模式。

| 变量名 | 用途 | 适用模式 | 说明 |
| :--- | :--- | :---: | :--- |
| `TG_API_ID` | Telegram API ID（纯数字） | 官方 API 模式 | 从 [my.telegram.org](https://my.telegram.org) 获取 |
| `TG_API_HASH` | Telegram API Hash（32位字符） | 官方 API 模式 | 从 [my.telegram.org](https://my.telegram.org) 获取 |
| `TG_SESSION_STR` | Telethon 会话认证字符串 | 官方 API 模式 | 本地运行 `python gen_session.py` 登录生成 |
| `TG_BOT_TOKEN` | Telegram 通知机器人 Token | 可选（通知推送） | 从 [@BotFather](https://t.me/BotFather) 获取 |
| `TG_CHAT_ID` | 通知接收人 / 频道 / 群组 ID | 可选（通知推送） | 机器人的目标推送聊天 ID |

### 2. Repository Variables（常规变量配置）

可在 **Settings -> Secrets and variables -> Actions -> Variables** 中配置：

| 变量名 | 用途 | 默认值 | 说明 |
| :--- | :--- | :---: | :--- |
| `FETCH_DAYS` | 单次增量回溯天数（扫描时间窗口） | `3` | 增量模式下只读取最近 N 天频道消息，加快运行速度 |
| `PROXY` | 抓取代理设置 | 留空 | 本地 Windows 运行会自动读取系统代理；Linux 环境可按需设置 |

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
🛡️ 反代 ProxyIP：30,545 条 (✅ 29,820 存活 · ⚠️ 725 缓冲)
   └ 🌟 兼具优选直连: 4,832 条 (已提纯 proxyip_cf.txt)
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
* **增量与健康一览**：每类节点直观展示存活数量、缓冲标记与实测均延。
* **主动鉴真审计**：实时汇报全协议穿透质检、TLS + 301 重定向鉴真与连续失败永久淘汰数量。
* **细分淘汰明细**：底栏汇报各引擎分类淘汰数量 `[代理 X, 反代 Y, 扫描优选 Z]`，精准掌控全库死节点流失情况。
* **厂商覆盖一览**：自动统计展示覆盖的主力机房与服务商。
* **一键直达日志**：附带 GitHub Action 运行记录与产物仓库直达超链接。

---

## 本地运行

### 1. 免登录 Web 模式运行（基础体验）
本地无需安装 Telethon，直接运行脚本即可抓取正文代理与单条 IP：
```bash
python tg_fetch.py
```
> 💡 Windows 运行环境会自动识别系统代理设置（如 v2rayN 等）。若需要显式指定代理，可设置环境变量：
> ```bash
> # Windows PowerShell
> $env:PROXY="socks5h://127.0.0.1:10808"; python tg_fetch.py
> 
> # Linux / macOS
> PROXY="socks5h://127.0.0.1:10808" python tg_fetch.py
> ```

### 2. 官方 API 全功能模式运行（推荐）
如果你需要自动下载频道扫描附件（获取千条级机房优选大池与反代池），请生成 Session 字符串：
```bash
pip install -r requirements.txt
python gen_session.py
```
按终端交互提示输入 API ID、API Hash 与验证码后，脚本会生成一串 Session 字符串。随后配置环境变量即可运行：
```bash
# Windows PowerShell
$env:TG_API_ID="你的API_ID"
$env:TG_API_HASH="你的API_HASH"
$env:TG_SESSION_STR="你的Session字符串"
python tg_fetch.py

# Linux / macOS
export TG_API_ID="你的API_ID"
export TG_API_HASH="你的API_HASH"
export TG_SESSION_STR="你的Session字符串"
python tg_fetch.py
```

### 3. 主动质检引擎本地运行（可选）
本地测试或需要立即进行质量筛查时，可独立运行三大质检引擎：
```bash
# ① 运行通用代理连通性质检（支持 --sample 抽样快速冒烟）
python socks_verify.py --concurrency 100 --sample 50 --no-notify

# ② 运行反代 ProxyIP 穿透与优选直连双料质检
python proxyip_verify.py --concurrency 150 --no-notify

# ③ 运行全量优选 IP 两阶段（TLS + HTTP 301）主动鉴真
python cf_verify.py --concurrency 150 --timeout 3.0
```

---

## 定时任务（GitHub Actions）

工作流文件位于 `.github/workflows/fetch.yml`。

每天 **北京时间 18:05（UTC 10:05）** 自动执行完整的四阶段主动质检流水线：
1. **📡 Step 1: 抓取 TG 代理与优选 IP (`tg_fetch.py`)**：
   - 未配置 API 凭据时自动使用 Web 模式抓取正文中的基础代理与单条 IP。
   - 配置 API 凭据后全速解锁全功能，自动下载解析扫描附件与反代池附件。
   - 自动全局去重并增量合并，生成最新节点池暂存。
2. **🚀 Step 2: SOCKS5 / 通用代理连通性质检 (`socks_verify.py`)**：
   - 并发 300 执行 RFC 1928 / RFC 5389 / HTTP 真实网络穿透校验，累计连续失败次数，淘汰不可达死节点。
3. **🔍 Step 3: ProxyIP 穿透存活质检 (`proxyip_verify.py`)**：
   - 并发 300 执行 `/cdn-cgi/trace` 真实穿透质检，同时探测 TLS 1.3 优选直连特性，提纯导出 `data/proxyip_cf.txt`。
4. **🛡️ Step 4: 优选 IP 两阶段主动鉴真 (`cf_verify.py`)**：
   - 并发 250 执行 TLS 官方证书鉴真 + HTTP 301 重定向校验，淘汰死节点，并汇总全流水线数据向 Telegram 发送精美卡片。
5. **📄 Step 5: 变动提交与推送**：
   - 具备并发互斥锁（`concurrency`）与 `git pull --rebase` 自动防冲突机制。
   - 仅在产物有实际变动时自动提交并推送回仓库，绝不产生无意义的空提交。
6. **🧹 Step 6: 自动清理旧工作流**：
   - 自动清理历史构建记录，始终**仅保留最近 5 次记录**，避免仓库历史膨胀。

> 💡 同时也支持在 GitHub 仓库 **Actions** 页面随时点击 **Run workflow** 手动指定回溯天数立即触发。

---

## 🙏 致谢

本项目节点与优选 IP 数据源来自以下 Telegram 公开频道，在此表示感谢：

- [@otcfxq](https://t.me/otcfxq)
- [@danfeng2](https://t.me/danfeng2)

---

## 📄 开源许可证 / License

本项目遵循 [MIT License](LICENSE) 协议开源。
