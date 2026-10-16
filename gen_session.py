#!/usr/bin/env python3
"""
生成 Telethon Session 字符串（用于 GitHub Actions 免交互登录）

使用方法：
1. 本脚本已自动配置本地代理支持（解决国内连接 Telegram 超时问题）
2. 运行本脚本：python gen_session.py
3. 按提示确认/输入 API ID、API Hash、手机号、验证码与两步验证密码 (如有)
4. 将最后输出的 Session 字符串填到 GitHub Secrets 的 TG_SESSION_STR 中
"""

import asyncio
import getpass
import os
import socket
import sys
import urllib.parse

# Windows 终端编码与事件循环策略保护
if sys.platform == "win32":
    if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 优先尝试自动加载本地 .env 配置
try:
    from providers import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
except ImportError:
    print("❌ 请先安装 telethon：pip install telethon")
    sys.exit(1)


def parse_proxy_str(val: str) -> tuple | None:
    """
    通用代理字符串解析器，输出 Telethon 兼容的 proxy tuple：
    - 纯端口数字: '10808' -> ('socks5', '127.0.0.1', 10808, True)
    - host:port: '127.0.0.1:7890' -> ('socks5', '127.0.0.1', 7890, True)
    - 完整 URL: 'http://127.0.0.1:7890' -> ('http', '127.0.0.1', 7890, False)
    - 带鉴权: 'socks5://user:pass@127.0.0.1:10808' -> ('socks5', '127.0.0.1', 10808, True, 'user', 'pass')
    """
    if not val:
        return None
    val = val.strip()
    if not val:
        return None

    if val.isdigit():
        return ("socks5", "127.0.0.1", int(val), True)

    target_url = val if "://" in val else f"socks5://{val}"
    try:
        u = urllib.parse.urlsplit(target_url)
        scheme = u.scheme.lower()
        p_type = "socks5" if "socks" in scheme else "http"
        host = u.hostname or "127.0.0.1"
        port = u.port
        if not port:
            return None
        rdns = True if p_type == "socks5" else False
        username = u.username or None
        password = u.password or None
        if username or password:
            return (p_type, host, port, rdns, username, password)
        return (p_type, host, port, rdns)
    except Exception:
        return None


def detect_local_proxy():
    """多级自动探测本地运行的代理服务（环境变量 -> Windows 系统代理 -> 常见本地代理端口）"""
    # 1. 优先检查标准系统环境变量
    for env_var in ("PROXY", "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "all_proxy", "https_proxy", "http_proxy"):
        val = os.environ.get(env_var)
        if val:
            parsed = parse_proxy_str(val)
            if parsed:
                return parsed

    # 2. Windows 平台自动探测系统代理设置 (winreg)
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if enabled:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    if server:
                        # 兼容多协议形如 "http=127.0.0.1:7890;https=127.0.0.1:7890" 或 "127.0.0.1:7890"
                        s_target = server.split(";")[0].split("=")[-1].strip()
                        parsed = parse_proxy_str(s_target)
                        if parsed:
                            return parsed
        except Exception:
            pass

    # 3. 轮询探测常用本地代理开放端口
    common_probes = [
        ("socks5", 10808),  # v2rayN / Xray SOCKS5
        ("http", 10809),    # v2rayN / Xray HTTP
        ("socks5", 7890),   # Clash 混合/SOCKS5
        ("http", 7890),     # Clash HTTP
        ("socks5", 7897),   # Clash Verge Rev
        ("http", 7897),
        ("socks5", 1080),   # Shadowsocks / 通用 SOCKS5
        ("socks5", 2080),   # sing-box / NekoBox
    ]

    for p_type, port in common_probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    if p_type == "socks5":
                        s.sendall(b"\x05\x01\x00")
                        resp = s.recv(2)
                        if resp in (b"\x05\x00", b"\x05\x02"):
                            return ("socks5", "127.0.0.1", port, True)
                    else:
                        return (p_type, "127.0.0.1", port, False)
        except Exception:
            pass

    return None


async def main():
    print("=" * 60)
    print("📱 Telegram Session 字符串生成器 (支持本地代理 & 2FA)")
    print("=" * 60)

    # 1. 代理配置
    detected = detect_local_proxy()
    proxy = None

    if detected:
        p_type, p_host, p_port = detected[0], detected[1], detected[2]
        print(f"\n🔍 检测到本地代理可用: {p_type}://{p_host}:{p_port}")
        choice = input("是否直接使用该代理？[Y/n/自定义输入其他端口或地址]: ").strip()
        if choice.lower() in ("", "y", "yes"):
            proxy = detected
        elif choice.lower() == "n":
            proxy = None
        else:
            custom_p = parse_proxy_str(choice)
            if custom_p:
                proxy = custom_p
            else:
                print(f"⚠️ 无法识别代理输入 '{choice}'，回退至自动检测的代理。")
                proxy = detected
    else:
        print("\n⚠️ 未自动检测到本地运行的代理端口（如 10808, 7890）。")
        custom = input("请输入你的本地代理端口或完整地址（如 10808 或 http://127.0.0.1:7890，直连请按回车）：").strip()
        if custom:
            proxy = parse_proxy_str(custom)
            if not proxy:
                print(f"⚠️ 无法解析代理格式 '{custom}'，将尝试直连。")

    if proxy:
        print(f"✅ 将通过代理连接 Telegram: {proxy[0]}://{proxy[1]}:{proxy[2]}")
    else:
        print("⚠️ 未设置代理，将尝试直连（国内网络通常会超时）。")

    # 2. 账号 API 信息 (支持预填 .env 凭据)
    env_api_id = (os.getenv("TG_API_ID") or "").strip()
    env_api_hash = (os.getenv("TG_API_HASH") or "").strip()

    if env_api_id and env_api_hash:
        print("\n🔑 检测到环境变量/.env 中已有凭据:")
        print(f"   TG_API_ID  : {env_api_id}")
        masked_hash = f"{env_api_hash[:4]}****{env_api_hash[-4:]}" if len(env_api_hash) > 8 else "****"
        print(f"   TG_API_HASH: {masked_hash}")
        use_env = input("是否直接使用已有凭据？[Y/n]: ").strip().lower()
        if use_env in ("", "y", "yes"):
            api_id = env_api_id
            api_hash = env_api_hash
        else:
            api_id = input("\n请输入你的 API ID（纯数字）：").strip()
            api_hash = input("请输入你的 API Hash：").strip()
    else:
        api_id = input("\n请输入你的 API ID（纯数字）：").strip()
        api_hash = input("请输入你的 API Hash：").strip()

    if not api_id.isdigit():
        print("❌ 错误：API ID 必须是纯数字！")
        return

    if not api_hash:
        print("❌ 错误：API Hash 不能为空！")
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
        print("✅ 已成功连接到 Telegram 服务器！开始登录认证：\n")
        await client.start(
            phone=lambda: input("请输入你的手机号（带国家区号，如 +8613812345678）: ").strip(),
            code_callback=lambda: input("请输入收到的 Telegram 登录验证码: ").strip(),
            password=lambda: getpass.getpass("请输入两步验证密码 (2FA Password，未开启直接回车): ").strip(),
        )

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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 用户手动取消操作，已安全退出。")
        sys.exit(0)
