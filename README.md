# TG-Proxy-Fetcher —— Telegram 代理与 Cloudflare 优选 IP 自动化同步工具

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-2088FF?logo=github-actions&logoColor=white)](https://github.com/skfoa/tg-proxy-fetcher/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)

每天自动从 Telegram 优质公开频道（[@otcfxq](https://t.me/otcfxq)、[@danfeng2](https://t.me/danfeng2)）抓取多协议代理节点、Cloudflare 优选 IP 以及反代 ProxyIP。系统具备**永久增量持久化（只增不减）**与**全局智能去重**机制，自动导出通用代理列表、纯净 `IP:端口` 文本列表以及结构化测速数据表格，并通过 GitHub Actions 每天定时自动提交并推送到仓库。

---

## ⚡ 运行模式与能力对比

系统采用**双引擎驱动**架构。了解不同模式的能力边界，有助于按需选择配置：

| 特性 / 产物 | 🚀 免登录 Web 模式<br>(零门槛开箱即用) | 🛡️ 官方 API 模式<br>(全功能完整版 · 强烈推荐) |
| :--- | :---: | :---: |
| **运行门槛** | **无需任何密钥或账号**<br>Fork / Clone 即可直接运行 | **需配置 3 项 Secret**<br>`TG_API_ID`、`TG_API_HASH`、`TG_SESSION_STR` |
| **底层原理** | 爬取 Telegram 公开网页预览 (`t.me/s/`) | 启用 Telethon 客户端直连 MTProto 协议 |
| **正文通用代理 (`socks5.txt`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道正文单条优选 (`cf_ips.*`)** | ✅ 支持自动抓取 | ✅ 支持自动抓取 |
| **频道附件自动下载解析** | ❌ **不支持**（网页端无附件下载接口） | ✅ **完全支持自动下载解析** |
| **批量扫描大池 (`scan_ips/`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析 OTC/DanFeng 测速附件 |
| **反代 ProxyIP 池 (`proxyip.*`)** | ❌ 无法自动下载（产物为 0） | ✅ 自动下载解析反代文件附件 |
| **适用场景** | 快速验证、仅需基础正文代理与单条 IP | 正式部署、需要海量机房扫描池与反代池 |

---

## 🌟 核心特性亮点

- **🚀 免登录基础模式**：未配置 API 凭据时自动启用，零门槛抓取频道消息正文中的通用代理与单条优选 IP。
- **🛡️ 官方 API 全功能模式**：配置 `TG_API_ID`、`TG_API_HASH` 与 `TG_SESSION_STR` 后自动激活，解锁频道附件自动下载，获取千条级机房扫描 IP 与反代池。
- **📦 永久增量持久化（只增不减）**：历史抓取的有效节点全部永久留存，新节点自动追加，绝不草率淘汰。
- **🔍 跨文件严格唯一去重**：以 `IP:端口` 为全局主键，新老文件重复提取自动刷新覆盖，绝无重复行；IP 归属更正时自动迁移所属 ASN 文件。
- **📁 智能 ASN 分组与命名**：
  - **DanFeng 测速**：CSV 内部无 ASN 列时自动从文件名（如 `AS45102_CNNICALIBABACNNETAP_*.csv`）解析归类。
  - **OTC 优选扫描**：单 ASN 文件以文件名目标 ASN 为准；混合扫描文件（如 `OTC_SCAN_YX_杂.txt`）自动逐行提取具体 ASN 与 ISP 拆分归类。
- **⚡ 纯净 IP:端口 列表导出**：自动导出纯文本格式的 `IP:端口` 列表（`cf_ips.txt`、`scan_ips/*.txt`、`proxyip.txt`），方便直接复制或作为远程订阅导入。
- **📱 极简高亮 Telegram 运行卡片**：锁屏即知变动摘要、变动数据绿色加粗高亮、涵盖 Top 服务商预览、运行耗时统计与 Actions 日志直链。
- **🌐 Windows 本地智能环境自适应**：本地运行自动读取 Windows 系统代理（如 v2rayN 等），无缝突破网络限制。
- **🧹 自动维护与构建瘦身**：每次运行自动清理 GitHub Actions 历史记录，始终**仅保留最近 5 次运行记录**，告别冗余历史堆积！

---

## 架构与工作流程

```text
                      ┌─── @otcfxq ────────┐
                      │   (代理 + 优选IP)  │
tg_fetch.py ──────────┤                    ├────► 增量抓取 & 全局智能去重 ──┬──► socks5.txt / socks5.csv (通用多协议代理节点)
(免登录/官方API双模)   │                    │                               ├──► cf_ips.txt / cf_ips.csv (单条优选 IP)
                      └─── @danfeng2 ──────┘                               ├──► scan_ips.txt / scan_ips.csv (扫描优选 IP 汇总) *
                           (优选IP 专属)                                     ├──► scan_ips/AS{ASN}_{ISP}.txt (独立机房纯文本) *
                                                                            ├──► proxyip.txt / proxyip.csv (反代 ProxyIP 专属池) *
                                                                            └──► proxyip_cf.txt (兼具优选直连特性的提纯反代清单) *

                               流水线主动鉴真与淘汰引擎
  ┌───────────────────────┬─────────────────────────┬─────────────────────────┐
  ▼                       ▼                         ▼                         ▼
socks_verify.py         proxyip_verify.py         cf_verify.py              Telegram Bot
SOCKS5/HTTP/TURN        /cdn-cgi/trace 穿透       TLS 握手 + HTTP 301       四合一精美统计卡片
RFC 1928 全协议质检     + TLS 优选双能鉴真        全线优选 IP 鉴真淘汰      锁屏即知健康变动

* 注：标记 * 的扫描机房大池与反代池需配置【官方 API 模式】方可自动下载获取。
```

---

## 产物清单与订阅直链

| 文件名 | 内容说明 | 生成条件 | GitHub Raw 永久直链（点击即可导入） |
| :--- | :--- | :---: | :--- |
| **`socks5.txt`** | 质检存活的多协议通用代理清单（纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/socks5.txt` |
| **`socks5.csv`** | 代理质检数据表（协议/延迟/fail_count/机房） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/socks5.csv` |
| **`cf_ips.txt`** | 频道日常单条优选 IP（纯文本） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/cf_ips.txt` |
| **`cf_ips.csv`** | 频道日常单条优选 IP（数据表） | 全模式支持 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/cf_ips.csv` |
| **`scan_ips.txt`** | 扫描测速总清单（按 ASN 分组） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/scan_ips.txt` |
| **`scan_ips/*.txt`** | 独立 ASN + 厂商纯文本列表（单文件） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/scan_ips/{ASN}_{ISP}.txt` |
| **`scan_ips.csv`** | 扫描测速优选 IP（数据表） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/scan_ips.csv` |
| **`proxyip.txt`** | 反代 ProxyIP 清单（纯文本） | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/proxyip.txt` |
| **`proxyip.csv`** | 反代 ProxyIP 详细数据表 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/proxyip.csv` |
| **`proxyip_cf.txt`** | 兼具优选直连特性的提纯反代清单 | 需官方 API 模式 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/proxyip_cf.txt` |

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
   - 自动提取行首有效节点与认证信息，过滤后续测速说明与反向 PTR 域名别名，统一去重合并至 `socks5.txt`。
6. **Cloudflare 优选 IP 与反代池（需官方 API 模式）**：
   - 提取包含 IP、端口、TLS、网络延迟（纯数值 ms）、下载速度（纯数值 kB/s）、数据中心（Colo）、落地位置、ASN、运营商、测速时间等全量指标。

---

## 输出产物与去重规则详细说明

### 1. `socks5.txt` / `socks5.csv`（通用代理节点清单与质检表）
* **智能增量合并**：每次抓取优先比对历史库，新发布的节点自动追加并去重，以 `host:port` 为唯一标识刷新认证与配置。
* **主动质检淘汰（`socks_verify.py`）**：集成 RFC 1928（SOCKS5 协商/认证/CONNECT 隧道穿透）、RFC 5389（STUN/TURN Binding 鉴真）、HTTP CONNECT 穿透全套真实网络协议握手引擎。
* **连续失败缓冲保护（`--max-fails 2`）**：首次探测失败标记缓冲（`fail_count=1`），连续 2 次全网不可达方才彻底剔除，避免公网抖动误杀。
* **双模持久化**：
  - `socks5.txt`：纯文本每行一个可用节点 URL，开箱即用。
  - `socks5.csv`：结构化表格，包含协议类型、测速延迟（ms）、连续失败次数、Cloudflare Colo 数据中心与质检时间戳。

### 2. `cf_ips.txt` / `cf_ips.csv`（频道日常单条优选 IP）
* 仅收录频道日常消息正文中发布的单条优选 IP（如 `@danfeng2`、`@otcfxq` 的实时测速通报）。
* `cf_ips.txt` 为纯文本格式，每行一个 `IP:端口`。
* `cf_ips.csv` 为 UTF-8-SIG 结构化表格，可直接用 Excel 查看。

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
  - **归属迁移**：若某 IP 在新文件中被修正了归属机房，它会自动迁移至新机房的 `scan_ips/AS{新ASN}_{厂商}.txt`，旧分组中自动清除，绝不跨组重复。
* **三模导出输出**：
  1. **总汇总清单（`scan_ips.txt`）**：将所有 ASN 分组整合在一起，带有清晰的 ASN 标题注释（如 `# AS906 (DMIT) - 15 个`）。
  2. **独立机房厂商文本（`scan_ips/ASxxx_厂商.txt`）**：在 `scan_ips/` 目录下按 ASN 及厂商名拆分生成独立文件（如 `scan_ips/AS906_DMIT.txt`、`scan_ips/AS210644_Aeza.txt`、`scan_ips/AS212336_ByteVirt.txt`），内容为 100% 纯净的 `IP:端口`，无任何注释，方便单独导入或按机房远程订阅。
  3. **结构化总表（`scan_ips.csv`）**：按 ASN 字母序聚合排序，方便通过 Excel 集中筛选分析。

### 4. `proxyip.txt` / `proxyip.csv`（反代 ProxyIP 专属池）
* **独立反代池**：专门收录来自频道发布的反代文件（如 `Global-proxyip-443.csv`、`Global-proxyip-8443.csv` 等）。
* **纯净即用**：`proxyip.txt` 导出纯净 `IP:端口`，可直接复制或配置于 edgetunnel / Cloudflare Workers 作为反代地址。
* **结构化数据**：`proxyip.csv` 保留延迟、数据中心与落地位置等关键信息。

### 5. 数据表通用字段说明
* 采用 `UTF-8-SIG` 编码，Windows Excel 直接双击打开不乱码。
* 包含完整指标，数值字段（`delay_ms`, `speed_kbs`）均为纯数字，并在保存时按 **`tested_at`（测速时间）倒序排序**：

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

---

### 7. 全线三大异步主动鉴真与缓冲淘汰体系
为防止长期累积的节点失效或死灰复燃，系统配备了三套独立的高并发主动质检探测引擎：

#### ① 代理连通性质检引擎（`socks_verify.py`）
* **全协议真实握手**：
  * **SOCKS5**：RFC 1928 握手协商（无密 `0x00` / 账密 `0x02` RFC 1929）➔ 发送 CONNECT 指令 ➔ 穿透请求 `/cdn-cgi/trace` 检验 200 与机房。
  * **HTTP / HTTPS**：CONNECT 隧道穿透 + 正向代理回退双路径校验。
  * **TURN / STUN**：构造 RFC 5389 STUN Binding Request 二进制包，严格校验 Magic Cookie (`0x2112A442`) 与 Transaction ID。
* **淘汰机制**：连续失败达到阈值（默认 2 次）彻底从 `socks5.txt` 与 `socks5.csv` 永久删除。

#### ② 反代 ProxyIP 穿透质检引擎（`proxyip_verify.py`）
* **穿透与优选双能探测**：
  * **穿透鉴真**：通过反代向 `speed.cloudflare.com:80` 发起真实 GET 请求，验证 `/cdn-cgi/trace` 穿透成功。
  * **优选直连探测**：并发探测该节点是否同时支持作为直连优选 IP（TLS 1.3 握手成功），自动生成兼具双料特性的 `proxyip_cf.txt` 极品清单。
* **淘汰机制**：连续失败 ≥ 2 次从 `proxyip.txt`、`proxyip.csv` 永久删除。

#### ③ 优选 IP 两阶段主动鉴真引擎（`cf_verify.py`）
* **全量优选 IP 覆盖**：无论来源，**只要是优选 IP（涵盖 `scan_ips` 扫描测速与 `cf_ips` 每日单条全线产物），一律全部执行阶段一与阶段二探测**：
  * **阶段一（TLS 握手 + 证书鉴真）**：建立 TLS 握手并验证 `crypto.cloudflare.com` 官方证书有效性。
  * **阶段二（HTTP 301 重定向 + 服务头验证）**：同一连接请求根路径，验证返回 `301 Moved Permanently` 且响应头包含 `Server: cloudflare`。
* **全产物联动删除剔除**：达到淘汰阈值的死节点，同步从 `scan_ips.csv`、`scan_ips.txt`、`scan_ips/*.txt`、`cf_ips.csv`、`cf_ips.txt` 中**彻底永久删除**。

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
🚀 节点与优选 IP 同步完成 (🗑️ 剔除 31 死节点)
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
   • 淘汰死节点：31 条 (连续失败 ≥ 2 次)
📡 频道来源：@danfeng2, @otcfxq
━━━━━━━━━━━━━━━━━━━━
⚡ 总耗时: 165.2s · 🔗 Action #35 · 📦 产物仓库
```

* **锁屏即知变动**：首行直观呈现 `(🟢 发现 +N 条新数据)` 或 `(🗑️ 剔除 N 死节点)`。
* **增量与健康一览**：每类节点直观展示存活数量、缓冲标记与实测均延。
* **主动鉴真审计**：实时汇报全协议穿透质检、TLS + 301 重定向鉴真与连续失败永久淘汰数量。
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

---

## 定时任务（GitHub Actions）

工作流文件位于 `.github/workflows/fetch.yml`。

每天 **北京时间 18:05（UTC 10:05）** 自动执行：
- **未配置 API 密钥时**：自动使用 Web 模式抓取正文中的基础代理与单条 IP。
- **配置了 API 密钥后**：自动解锁全功能，下载扫描附件与反代池附件。
- 智能增量合并更新历史数据，历史节点永久留存（只增不减）。
- 具备并发互斥锁（`concurrency`）与 `git pull --rebase` 自动防冲突机制。
- 具备 `if: always()` 容错提交机制与存在性校验，有变动自动提交并推送回仓库。
- 执行完成后（若配置了机器人凭据）自动向 Telegram 发送精致运行统计卡片。
- 自动清理工作流运行历史，始终**仅保留最近 5 次记录**，避免仓库膨胀。
- 支持在 GitHub 仓库 **Actions** 页面随时点击 **Run workflow** 手动触发立即更新。

---

## 🙏 致谢

本项目节点与优选 IP 数据源来自以下 Telegram 公开频道，在此表示感谢：

- [@otcfxq](https://t.me/otcfxq)
- [@danfeng2](https://t.me/danfeng2)

---

## 📄 开源许可证 / License

本项目遵循 [MIT License](LICENSE) 协议开源。
