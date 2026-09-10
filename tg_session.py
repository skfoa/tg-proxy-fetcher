#!/usr/bin/env python3
"""
生成 Telethon StringSession 登录凭证的本地交互脚本

使用方法：
  1. 在本地终端安装依赖：pip install -r requirements.txt
  2. 运行本脚本：python tg_session.py
  3. API ID 直接回车（默认使用 Telegram 官方客户端内置通用凭据，免官网申请）
  4. 可选输入本地代理（针对中国大陆网络环境，如 127.0.0.1:7890）
  5. 按提示输入手机号、Telegram 验证码（若有两步验证密码则再输入）
  6. 成功后控制台输出 TG_SESSION_STR，将其配置到 GitHub Secrets 中
"""

import sys
import asyncio
import urllib.parse
from telethon import TelegramClient
from telethon.sessions import StringSession

# Windows 事件循环兼容
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def parse_proxy(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    if "://" not in text:
        text = "socks5://" + text
    u = urllib.parse.urlparse(text)
    scheme = u.scheme.lower()
    return {
        "proxy_type": scheme,
        "addr": u.hostname,
        "port": u.port or (7890 if "socks" in scheme else 8080),
        "username": u.username,
        "password": u.password,
    }


async def main():
    print("=" * 60)
    print(" Telethon StringSession 会话凭证生成工具")
    print("=" * 60)

    api_id_input = input("1. 请输入 API ID (直接按【回车】使用官方通用免申请凭据): ").strip()
    if not api_id_input:
        api_id = 2040
        api_hash = "b18441a1ff607e10a989891a5462e627"
        print("   -> 已启用 Telegram Desktop 官方内置凭据 (免去官网申请烦恼！)")
    else:
        if not api_id_input.isdigit():
            print("❌ 错误: API ID 必须是纯数字！")
            return
        api_id = int(api_id_input)
        api_hash = input("2. 请输入 Telegram API Hash: ").strip()
        if not api_hash:
            print("❌ 错误: API Hash 不能为空！")
            return

    proxy_input = input("2. 本地代理配置（如 127.0.0.1:7890，直接回车跳过）: ").strip()
    proxy = parse_proxy(proxy_input)
    if proxy:
        print(f"   -> 已启用代理: {proxy['proxy_type']}://{proxy['addr']}:{proxy['port']}")
    else:
        print("   -> 直连 Telegram 服务器")

    print("\n正在连接 Telegram 服务器，请按提示输入手机号与验证码...\n")

    client = TelegramClient(StringSession(), api_id, api_hash, proxy=proxy)
    await client.start()

    session_string = client.session.save()
    print("\n" + "=" * 60)
    print("【登录成功！】请妥善保管以下 TG_SESSION_STR (切勿泄露)：")
    print("=" * 60 + "\n")
    print(session_string)
    print("\n" + "=" * 60)
    print("请复制上方完整字符串，粘贴到 GitHub 仓库：")
    print("Settings -> Secrets and variables -> Actions -> TG_SESSION_STR")
    print("=" * 60)

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
