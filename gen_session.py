#!/usr/bin/env python3
"""
生成 Telethon Session 字符串（用于 GitHub Actions 免交互登录）

使用方法：
1. 本脚本已自动配置本地代理支持（解决国内连接 Telegram 超时问题）
2. 运行本脚本：python gen_session.py
3. 按提示输入 API ID、API Hash、手机号、验证码
4. 将最后输出的 Session 字符串填到 GitHub Secrets 的 TG_SESSION_STR 中
"""

import asyncio
import os
import socket
import sys

try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
except ImportError:
    print("❌ 请先安装 telethon：pip install telethon")
    sys.exit(1)


def detect_local_proxy():
    """自动检测常见的本地代理端口（如 v2rayN、Clash 等）"""
    # 优先检查系统环境变量
    for env_var in ('ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'all_proxy', 'https_proxy', 'http_proxy'):
        val = os.environ.get(env_var)
        if val:
            val_clean = val.replace('http://', '').replace('https://', '').replace('socks5://', '').strip('/')
            if ':' in val_clean:
                host, port = val_clean.split(':', 1)
                try:
                    p_type = 'socks5' if 'socks5' in val.lower() else 'http'
                    return (p_type, host, int(port))
                except ValueError:
                    pass

    # 检测常用本地代理端口
    common_probes = [
        ('socks5', 10808),  # v2rayN / Xray SOCKS5
        ('http', 10809),    # v2rayN / Xray HTTP
        ('socks5', 7890),   # Clash 混合/SOCKS5
        ('http', 7890),     # Clash HTTP
        ('socks5', 7897),   # Clash Verge Rev
        ('http', 7897),
        ('socks5', 1080),   # Shadowsocks / 通用 SOCKS5
        ('socks5', 2080),
    ]

    for p_type, port in common_probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    if p_type == 'socks5':
                        s.sendall(b'\x05\x01\x00')
                        resp = s.recv(2)
                        if resp == b'\x05\x00':
                            return ('socks5', '127.0.0.1', port)
                    else:
                        return (p_type, '127.0.0.1', port)
        except Exception:
            pass

    return None


async def main():
    print("=" * 60)
    print("📱 Telegram Session 字符串生成器 (支持本地代理)")
    print("=" * 60)

    # 1. 代理配置
    detected = detect_local_proxy()
    proxy = None

    if detected:
        p_type, p_host, p_port = detected
        print(f"\n🔍 检测到本地代理可用: {p_type}://{p_host}:{p_port}")
        choice = input(f"是否直接使用该代理？[Y/n/自定义输入其他端口]: ").strip()
        if choice.lower() in ('', 'y', 'yes'):
            proxy = (p_type, p_host, p_port)
        elif choice.lower() == 'n':
            proxy = None
        elif choice.isdigit():
            proxy = ('socks5', '127.0.0.1', int(choice))
        else:
            if ':' in choice:
                parts = choice.split(':')
                proxy = ('socks5', parts[0], int(parts[1]))
            else:
                proxy = ('socks5', '127.0.0.1', 10808)
    else:
        print("\n⚠️ 未自动检测到本地运行的代理端口（如 10808, 7890）。")
        custom = input("请输入你的本地代理端口（如 10808 或 7890，不使用代理直接按回车）：").strip()
        if custom.isdigit():
            proxy = ('socks5', '127.0.0.1', int(custom))

    if proxy:
        print(f"✅ 将通过代理连接 Telegram: {proxy[0]}://{proxy[1]}:{proxy[2]}")
    else:
        print("⚠️ 未设置代理，将尝试直连（国内网络通常会超时）。")

    # 2. 账号 API 信息
    api_id = input("\n请输入你的 API ID（纯数字）：").strip()
    api_hash = input("请输入你的 API Hash：").strip()

    if not api_id.isdigit():
        print("❌ 错误：API ID 必须是纯数字！")
        return

    # 3. 创建客户端并登录
    print("\n⏳ 正在连接 Telegram 服务器，请稍候...")
    try:
        client = TelegramClient(
            StringSession(),
            int(api_id),
            api_hash,
            proxy=proxy
        )
        await client.connect()
    except Exception as e:
        print(f"\n❌ 连接失败: {e}")
        print("提示：国内直连 Telegram 会超时，请确保开启了代理软件（如 v2rayN/Clash）并配置了正确的端口。")
        return

    try:
        # 交互式认证
        print("✅ 已成功连接到 Telegram 服务器！")
        print("提示：手机号请输入带国际区号的格式，例如中国手机号为 +8613812345678\n")
        await client.start()

        session_str = client.session.save()

        print("\n" + "=" * 60)
        print("🎉 登录成功！以下是你的 Session 字符串：")
        print("=" * 60)
        print(f"\n{session_str}\n")
        print("=" * 60)
        print("📋 后续操作步骤：")
        print("1. 复制上方这一整行长字符串（不要带前后空格）")
        print("2. 打开 GitHub 你的仓库页面")
        print("3. 进入 Settings -> Secrets and variables -> Actions -> New repository secret")
        print("4. 添加三个 Secrets：")
        print("   - TG_API_ID      : 你的 API ID")
        print("   - TG_API_HASH    : 你的 API Hash")
        print("   - TG_SESSION_STR : 上方生成的长字符串")
        print("=" * 60)
    except Exception as e:
        print(f"\n❌ 认证过程出现异常: {e}")
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
