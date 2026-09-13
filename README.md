# TG-Proxy-Fetcher —— Telegram 代理与 Cloudflare 优选 IP 自动化同步工具

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-2088FF?logo=github-actions&logoColor=white)](https://github.com/skfoa/tg-proxy-fetcher/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)

每天自动从 Telegram 优质公开频道（[@otcfxq](https://t.me/otcfxq)、[@danfeng2](https://t.me/danfeng2)）抓取多协议代理节点与 Cloudflare 优选 IP。具备**永久增量持久化（只增不减）**与**智能去重**机制，自动生成通用代理订阅源、全平台测速通用的 `IP:端口` 纯文本清单以及结构化测速数据表格，并通过 GitHub Actions 每天定时自动提交并推送到仓库。

> 🌟 **核心特性亮点**
> - **🚀 免登录 / 零密钥模式（开箱即用）**：基于公开 Web 频道预览机制，**无需注册 Telegram API、无需配置任何 Secret 密钥、无需手机号或验证码**！Fork 或 Clone 即可直接跑通！
> - **🛡️ 官方 API 模式（可选兼容）**：配置 `TG_API_ID` 与 `TG_SESSION_STR` 后自动无感升级为 Telethon MTProto 客户端协议。
> - **📦 永久增量持久化（绝不超时淘汰）**：历史抓取的有效节点全部永久留存，新节点自动追加，重复节点按最新配置/测速实时更新覆盖，节点池只增不减、越用越丰富！
> - **⚡ 全平台通用测速标准格式（IP:端口）**：自动导出所有主流测速工具通用的纯净 `IP:端口` 文本列表，支持一键全选复制，或直接作为远程 IP 库订阅导入各大测速工具（如 CloudflareSpeedTest、edgetunnel、CM优选等）！
> - **🌐 Windows 本地智能环境自适应**：本地运行自动读取 Windows 系统代理（如 v2rayN 等），无缝突破网络限制。
> - **🧹 自动维护与构建瘦身**：每次运行自动清理 GitHub Actions 历史记录，始终**仅保留最近 5 次运行记录**，告别冗余历史堆积！

---

## 架构与工作流程

```text
                      ┌─── @otcfxq ────────┐
                      │   (代理 + 优选IP)  │
tg_fetch.py ──────────┤                    ├────► 增量抓取 & 智能去重 ──┬──► socks5.txt (通用多协议代理节点)
(免登录/官方API双模)   │                    │                           ├──► cf_ips.txt (通用标准 IP:端口，适配各类测速工具)
                      └─── @danfeng2 ──────┘                           ├──► cf_ips.csv (Cloudflare 优选 IP 详细表格)
                           (优选IP 专属)                                 └──► Telegram Bot 运行卡片推送 (可选)
```

---

## 产物清单与订阅直链

| 文件名 | 内容说明 | 适用场景 / 客户端 | GitHub Raw 永久直链（点击即可导入） |
| :--- | :--- | :--- | :--- |
| **`socks5.txt`** | 纯净多协议代理清单 | Clash、v2rayN、Sing-box、Shadowrocket 等 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/socks5.txt` |
| **`cf_ips.txt`** | 通用标准 `IP:端口` 优选 IP | **全平台测速工具**（CloudflareSpeedTest 等）、edgetunnel、CM 优选、各类测速脚本 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/cf_ips.txt` |
| **`cf_ips.csv`** | 结构化优选 IP 数据表 | Excel 排序筛选、二次数据分析 | `https://raw.githubusercontent.com/skfoa/tg-proxy-fetcher/main/cf_ips.csv` |

---

## 支持提取的节点类型

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
5. **Cloudflare 优选 IP**：
   - 提取包含 IP、端口、TLS、网络延迟（纯数值 ms）、下载速度（纯数值 kB/s）、数据中心（Colo）、落地位置、ASN、运营商、测速时间等全量指标。

---

## 输出产物详细说明

### 1. `socks5.txt`（代理节点清单）
* **永久累积（只增不减）**：每次抓取优先读取历史文件，已存在的有效节点永久保留，绝不会因为时间推移被误删。
* **智能覆盖更新**：以 `host:port` 为唯一标识。如果频道主重新发布了某个节点，自动以最新发布的认证密码与配置刷新覆盖。
* **纯净即用**：纯文本每行一个有效 URL，可直接导入各大代理客户端。
* **合规校验机制**：自动校验端口范围（1~65535）与 IP/域名有效性，彻底杜绝畸变脏数据。

### 2. `cf_ips.txt`（全平台测速标准格式：IP:端口）
* **行业通用标准**：纯文本格式，每行一个 `IP:端口`（如 `23.249.18.144:8581`），属于几乎所有测速工具、优选平台与代理客户端通用的核心标准格式。
* **广泛适用**：完美适配 CloudflareSpeedTest、edgetunnel 后台、CM 优选、各种优选测速脚本以及客户端节点直接导入。
* **两种使用方式**：
  1. **一键复制测试**：在 GitHub 打开该文件，点击右上角 `Copy raw file` 按钮，直接整段复制并粘贴到测速工具或面板的待选列表中即可立即测速。
  2. **远程 IP 库订阅**：直接将 Raw 订阅链接填入各大支持远程 IP 库的工具中，即可自动定时同步最新优选 IP！

### 3. `cf_ips.csv`（Cloudflare 优选 IP 结构化表格）
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

---

## 环境变量配置

> 💡 **零配置声明**：默认采用**免登录 Web 模式**，**无需配置任何必填 Secret**，开箱即可直接运行！

若需要启用官方 API 模式或 TG 机器人通知，可在 GitHub 仓库 **Settings -> Secrets and variables -> Actions** 中配置以下变量：

| 变量名 | 用途 | 是否必填 | 默认值 / 说明 |
| :--- | :--- | :---: | :--- |
| `TG_API_ID` | Telegram API ID（纯数字） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `TG_API_HASH` | Telegram API Hash（32位字符） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `TG_SESSION_STR` | Telethon 会话字符串（由 `tg_session.py` 生成） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `FETCH_DAYS` | 单次增量回溯的天数（扫描窗口，支持在 Repo Variables / Secrets 中自定义） | 否 | `3` |
| `PROXY` | 本地抓取代理（如 `socks5h://127.0.0.1:10808`） | 否 | Windows 本地运行可自动读取系统代理设置 |
| `TG_BOT_TOKEN` | TG 通知机器人 Token | 否（可选） | 用于抓取完成后推送运行结果卡片 |
| `TG_CHAT_ID` | TG 通知接收人的 Chat ID 或频道/群组 ID | 否（可选） | 用于抓取完成后推送运行结果卡片 |

---

## 本地运行

### 1. 直接运行（免登录 Web 模式，推荐）
本地无需安装 Telethon，直接运行脚本即可：
```bash
python tg_fetch.py
```
> 💡 Windows 运行环境会自动识别系统代理设置（如 v2rayN 等）。如果需要显式指定代理，可设置环境变量：
> ```bash
> # Windows PowerShell
> $env:PROXY="socks5h://127.0.0.1:10808"; python tg_fetch.py
> 
> # Linux / macOS
> PROXY="socks5h://127.0.0.1:10808" python tg_fetch.py
> ```

### 2. 官方 API 模式运行（可选）
如果拥有 Telegram API 凭据，可生成 Session 字符串：
```bash
pip install -r requirements.txt
python tg_session.py
```
按终端提示输入凭据并生成 Session 字符串后，配置环境变量即可运行：
```bash
export TG_API_ID="你的API_ID"
export TG_API_HASH="你的API_HASH"
export TG_SESSION_STR="你的Session字符串"
python tg_fetch.py
```

---

## 定时任务（GitHub Actions）

工作流文件位于 `.github/workflows/fetch.yml`。

每天 **北京时间 18:05（UTC 10:05）** 自动执行：
- 默认无需配置任何 Secrets，开箱即可通过 Web 模式自动抓取。
- 智能增量合并更新 `socks5.txt`、`cf_ips.txt` 与 `cf_ips.csv`，历史节点永久留存。
- 具备并发互斥锁（`concurrency`）与 `git pull --rebase` 自动防冲突机制。
- 具备 `if: always()` 容错提交机制与存在性校验，有变动自动提交并推送回仓库。
- 执行完成后（若配置了机器人凭据）自动向 Telegram 发送运行统计卡片。
- 支持在 GitHub 仓库 **Actions** 页面随时点击 **Run workflow** 手动触发立即更新。

---

## 🙏 致谢 / Acknowledgements

本项目由衷感谢以下开源项目、社区平台以及频道博主的无私分享与技术贡献：

* **核心数据源频道**：
  * [@otcfxq](https://t.me/otcfxq) — 长期持续无私分享海量优质多协议代理节点与优质优选测速数据。
  * [@danfeng2](https://t.me/danfeng2)（丹峰科技） — 专注 Cloudflare 优选 IP 深度测速与实时通报，数据精准可靠。
* **上游开源项目与生态**：
  * [Telethon](https://github.com/LonamiWebs/Telethon) — 纯 Python 实现的优秀 Telegram MTProto 客户端框架。
  * [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) — 全平台优选 IP 测速工具行业标杆。
  * [edgetunnel](https://github.com/cmliu/edgetunnel) — 优秀的边缘计算代理网络方案。
* **基础设施**：
  * [GitHub Actions](https://github.com/features/actions) — 提供稳定可靠的全球定时自动化构建与运行环境。

---

## 📄 开源许可证 / License

本项目遵循 [MIT License](LICENSE) 协议开源。抓取数据仅供个人网络连通性调试与学术测速研究，请遵守当地法律法规。
