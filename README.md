# TG-Proxy-Fetcher —— Telegram 代理与 Cloudflare 优选 IP 同步工具

从 Telegram 公开频道（[@otcfxq](https://t.me/otcfxq)、[@danfeng2](https://t.me/danfeng2)）自动获取多协议代理节点与 Cloudflare 优选 IP，按键覆盖去重，保存为纯净代理列表与结构化表格，并通过 GitHub Actions 每天定时自动执行并推送到仓库。

> 🌟 **核心特性：支持「免登录 / 零密钥模式」与「官方 API 模式」双模驱动**
> - **免登录 Web 模式（默认 / 零配置）**：无需任何 Telegram API 账号、密钥或验证码，Fork 后直接运行，开箱即用！
> - **官方 API 模式（可选）**：配置 `TG_API_ID` 与 `TG_SESSION_STR` 凭证后自动无缝切换至 Telethon MTProto 模式。

---

## 架构与工作流程

```text
                   ┌─── @otcfxq ────────┐
                   │   (代理 + 优选IP)  │
tg_fetch.py ───────┤                    ├────► 提取与去重 ──────┬───► socks5.txt (纯净代理节点)
(支持免登录/API双模) │                    │                       ├───► cf_ips.csv (Cloudflare 优选 IP 表格)
                   └─── @danfeng2 ──────┘                       └───► Telegram Bot 每日卡片推送 (可选)
                        (优选IP 专属)
```

---

## 支持提取的节点类型

1. **通用标准代理 URL**：
   - `socks5://...`、`http://...`、`https://...`（兼容免密与带账号密码认证）
2. **TURN 穿透协议节点**：
   - `turn://114.34.87.173:3479#TW...`（自动识别 `turn://` 协议，剔除标签说明与测速后缀）
3. **Telegram 官方 SOCKS5 一键直连链接**：
   - `tg://socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - `https://t.me/socks?server=8.210.224.195&port=6666&user=6666&pass=6666`
   - 自动无损转换为标准 `socks5://user:pass@ip:port` 格式，支持任意通用客户端导入。
4. **开放代理/服务通报消息（已做防污染隔离）**：
   - `[发现开放 HTTP 代理] 174.138.165.213:34887` ➔ 自动补全为 `http://174.138.165.213:34887`
   - `[发现开放 HTTPS 代理] https://121.42.225.20:443#CN` ➔ 自动提取为 `https://121.42.225.20:443`
   - `[发现开放 SOCKS5 代理] IP:Port` ➔ 自动补全为 `socks5://IP:Port`
   - `[发现开放 TURN 代理/服务] IP:Port 或 turn://IP:Port` ➔ 自动提取为 `turn://IP:Port`
   - 🛡️ **防污染机制**：通报行后半段附带的第三方 SNI 测试目标域名（如 `域名:https://hf.molikuaiyin.com:443...`）会被自动精准隔离过滤，确保代理库 100% 纯净。
5. **Cloudflare 优选 IP**：
   - 提取包含 IP、端口、TLS、网络延迟（纯数值 ms）、下载速度（纯数值 kB/s）、数据中心（Colo）、落地位置、ASN、运营商等全量指标的优选 IP 消息。

---

## 环境变量配置

> 💡 **特别说明**：如果你使用默认的**免登录 Web 模式**，**无需配置任何必填 Secret**，仓库开箱即可直接运行！

若需要启用官方 API 模式或 TG 机器人通知，可在 GitHub 仓库 **Settings -> Secrets and variables -> Actions** 中配置以下变量：

| 变量名 | 用途 | 是否必填 | 默认值 / 说明 |
| :--- | :--- | :---: | :--- |
| `TG_API_ID` | Telegram API ID（纯数字） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `TG_API_HASH` | Telegram API Hash（32位字符） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `TG_SESSION_STR` | Telethon 会话字符串（由 `tg_session.py` 生成） | 否（可选） | 留空则自动使用免登录 Web 模式 |
| `FETCH_DAYS` | 回溯抓取最近 N 天内的消息 | 否 | `3` |
| `PROXY` | 本地抓取代理（如 `socks5h://127.0.0.1:10808`） | 否 | Windows 本地运行可自动读取系统代理设置 |
| `TG_BOT_TOKEN` | TG 通知机器人 Token | 否（可选） | 用于抓取完成后推送卡片通知 |
| `TG_CHAT_ID` | TG 通知接收人的 Chat ID 或频道/群组 ID | 否（可选） | 用于抓取完成后推送卡片通知 |

---

## 输出产物说明

### 1. `socks5.txt`（代理节点清单）
* 纯文本格式，每行一个有效 URL，可直接导入 Clash、v2rayN、Sing-box、Shadowrocket 等客户端。
* 以 `host:port` 作为唯一去重键，严格按时间从新到旧遍历，同一节点重复发布时仅保留最新一条。
* 内置合规校验机制：自动校验端口合法性（1~65535）与 IP 地址有效性，杜绝畸变垃圾数据。

### 2. `cf_ips.csv`（Cloudflare 优选 IP 结构化表格）
* 采用 `UTF-8-SIG` 编码，Windows Excel 直接双击打开不乱码。
* 包含完整指标，数值字段（`delay_ms`, `speed_kbs`）均为纯数字，方便在 Excel 中直接排序筛选：

| 字段 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `ip` | 字符串 | 优选 IP 地址 | `154.31.112.237` |
| `port` | 整数 | 服务端口 | `26418` |
| `tls` | 字符串 | 是否开启 TLS (`true`/`false`) | `true` |
| `delay_ms` | 整数 | 网络延迟（毫秒纯数值，便于排序） | `116` |
| `speed_kbs` | 整数 | 下载速度（kB/s 纯数值，便于排序） | `20815` |
| `colo` | 字符串 | Cloudflare 数据中心三字代码 | `NRT`、`LAX` |
| `cf_location` | 字符串 | Cloudflare 落地地理位置 | `亚洲 · 日本东京` |
| `isp` | 字符串 | 网络运营商 | `DMIT Cloud Services` |
| `asn` | 字符串 | ASN 编号与组织 | `AS906` |
| `tested_at` | 时间字符串 | 测试/发布时间 | `2026-09-10 18:00:36` |
| `channel` | 字符串 | 来源频道 | `@danfeng2` / `@otcfxq` |

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
- 默认无需配置任何 Secrets，开箱即可通过 Web 模式自动抓取
- 抓取目标频道最近 3 天内的多协议代理与优选 IP
- 自动按 `IP:Port` 覆盖去重，生成并更新 `socks5.txt` 与 `cf_ips.csv`
- 具备并发互斥锁（`concurrency`）与 `git pull --rebase` 自动防冲突机制
- 具备 `if: always()` 容错提交机制与存在性校验，有变动自动提交并推送回仓库
- 执行完成后（若配置了机器人凭据）自动向 Telegram 发送运行统计卡片
- 支持在 GitHub 仓库 **Actions** 页面随时点击 **Run workflow** 手动触发立即更新
