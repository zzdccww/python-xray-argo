#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import socket
import base64
import random
import secrets
import shutil
import hashlib
import asyncio
import logging
import uuid as uuidlib

import aiohttp
from aiohttp import web

# ---- configuration -------------------------------------------------------
ENV = os.environ


def int_env(raw, default):
    """非负整数 env：缺失/非法/负数一律回退默认值。"""
    try:
        n = int(str(raw).strip())
        return n if n >= 0 else default
    except (TypeError, ValueError):
        return default


NODE_ID = ENV.get('UUID') or str(uuidlib.uuid4())
NODE_ID_HEX = NODE_ID.replace('-', '')
WSPATH = ENV.get('WSPATH') or secrets.token_hex(8)
SUB_PATH = ENV.get('SUB_PATH', '')            # 空 = 不启用 HTTP 订阅路由（opt-in）
NAME = ENV.get('NAME', '')
DOMAIN = ENV.get('DOMAIN', '')
TG_TOKEN = ENV.get('TG_BOT_TOKEN', '')
TG_CHAT = ENV.get('TG_CHAT_ID', '')
TG_API_BASE = (ENV.get('TG_API_BASE') or 'https://api.telegram.org').rstrip('/')
SERVER_HEADER = ENV.get('SERVER_HEADER') or 'nginx/1.24.0'
SITE_TITLE = ENV.get('SITE_TITLE', '')
SITE_THEME = ENV.get('SITE_THEME', '')
SELF_DESTRUCT = ENV.get('SELF_DESTRUCT', 'true') != 'false'
SELF_DESTRUCT_AFTER = int_env(ENV.get('SELF_DESTRUCT_AFTER'), 90)
PORT = int_env(ENV.get('SERVER_PORT') or ENV.get('PORT'), 8501)

IP_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')

SENSITIVE_ENV = [
    'UUID', 'WSPATH', 'SUB_PATH', 'NAME', 'DOMAIN',
    'TG_BOT_TOKEN', 'TG_CHAT_ID', 'TG_API_BASE', 'SERVER_HEADER', 'SITE_TITLE',
    'SITE_THEME', 'SELF_DESTRUCT', 'SELF_DESTRUCT_AFTER', 'PORT', 'SERVER_PORT',
]

# 速率测试域名拦截（防止节点被 speedtest 探测流量打爆 / 暴露带宽特征）
PROTECTED_HOSTS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org',
]


def is_protected_host(host):
    if not host:
        return False
    h = str(host).lower()
    return any(h == b or h.endswith('.' + b) for b in PROTECTED_HOSTS)


# ---- node identity (domain/port/tls) —— 无外呼，启动即定 -----------------
# DOMAIN 为域名 → TLS:443；为 IPv4 → 直连:PORT。未设 DOMAIN 则节点不可用。
meta_domain = ''
meta_port = 443
meta_tls = 'tls'
meta_valid = False
if DOMAIN:
    meta_domain = DOMAIN
    if IP_RE.match(DOMAIN):
        meta_tls = 'none'
        meta_port = PORT
    else:
        meta_tls = 'tls'
        meta_port = 443
    meta_valid = True


# ---- subscription --------------------------------------------------------
def build_subscription():
    name_part = NAME or 'node'
    tls_param = 'tls' if meta_tls == 'tls' else 'none'
    ss_tls_param = 'tls;' if meta_tls == 'tls' else ''
    vls = (f"vless://{NODE_ID}@{meta_domain}:{meta_port}?encryption=none&security={tls_param}"
           f"&sni={meta_domain}&fp=chrome&type=ws&host={meta_domain}&path=%2F{WSPATH}#{name_part}")
    tro = (f"trojan://{NODE_ID}@{meta_domain}:{meta_port}?security={tls_param}"
           f"&sni={meta_domain}&fp=chrome&type=ws&host={meta_domain}&path=%2F{WSPATH}#{name_part}")
    ss_mp = base64.b64encode(f"none:{NODE_ID}".encode()).decode()
    ss = (f"ss://{ss_mp}@{meta_domain}:{meta_port}?plugin=v2ray-plugin;mode%3Dwebsocket;"
          f"host%3D{meta_domain};path%3D%2F{WSPATH};{ss_tls_param}sni%3D{meta_domain};"
          f"skip-cert-verify%3Dtrue;mux%3D0#{name_part}")
    return vls + '\n' + tro + '\n' + ss


async def deliver():
    if not meta_valid:
        print('DOMAIN not set; subscription skipped', file=sys.stderr)
        return
    sub = build_subscription()
    b64 = base64.b64encode(sub.encode()).decode()
    if TG_TOKEN and TG_CHAT:
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{TG_API_BASE}/bot{TG_TOKEN}/sendMessage",
                    json={'chat_id': TG_CHAT, 'text': b64},
                ) as r:
                    if r.status == 200:
                        print('subscription delivered via telegram')
                        return
                    print(f'telegram delivery failed (http {r.status}); printing fallback', file=sys.stderr)
        except Exception:
            print('telegram delivery error; printing fallback', file=sys.stderr)
    print('subscription (base64):\n' + b64)
    print(sub)


# ---- DNS -----------------------------------------------------------------
_DNS_CACHE = {}
_DNS_TTL = 10 * 60  # seconds
_DOH_ENDPOINTS = [
    'https://dns.google/resolve',
    'https://1.1.1.1/dns-query',
    'https://cloudflare-dns.com/dns-query',
]


def _pick_a_record(answer):
    if isinstance(answer, list):
        for a in answer:
            if a.get('type') == 1:
                return a.get('data')
    return None


async def resolve_host(host):
    if IP_RE.match(host):
        return host
    hit = _DNS_CACHE.get(host)
    now = asyncio.get_event_loop().time()
    if hit and hit[1] > now:
        return hit[0]
    # 系统 DNS 优先（53 端口，外观正常）
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        if infos:
            ip = infos[0][4][0]
            if len(_DNS_CACHE) >= 512:
                _DNS_CACHE.clear()
            _DNS_CACHE[host] = (ip, now + _DNS_TTL)
            return ip
    except Exception:
        pass  # 走 DoH 回退
    for base in _DOH_ENDPOINTS:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    base, params={'name': host, 'type': 'A'},
                    headers={'accept': 'application/dns-json', 'User-Agent': 'Mozilla/5.0'},
                ) as r:
                    d = await r.json(content_type=None)
                    ip = _pick_a_record(d.get('Answer'))
                    if ip:
                        if len(_DNS_CACHE) >= 512:
                            _DNS_CACHE.clear()
                        _DNS_CACHE[host] = (ip, now + _DNS_TTL)
                        return ip
        except Exception:
            continue  # 下一端点
    raise OSError(f'failed to resolve {host}')


# ---- tunnel --------------------------------------------------------------
async def open_tunnel(ws, host, port, payload):
    # 解析失败回退连原始 host（与 node 一致）
    try:
        target = await resolve_host(host)
    except Exception:
        target = host
    try:
        reader, writer = await asyncio.open_connection(target, port)
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass
        return
    if payload:
        try:
            writer.write(payload)
            await writer.drain()
        except Exception:
            pass

    async def ws_to_tcp():
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING,
                                  aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)
        except Exception:
            pass
        finally:
            try:
                await ws.close()
            except Exception:
                pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws(), return_exceptions=True)


# ---- binary readers ------------------------------------------------------
def _ipv6(buf):
    return ':'.join(f'{(buf[k] << 8) + buf[k + 1]:x}' for k in range(0, 16, 2))


def _read_address(msg, p):
    """atyp + host，按 ATYP 顺序读；返回 (host, next_p)。"""
    atyp = msg[p]
    p += 1
    if atyp == 1:
        host = '.'.join(str(b) for b in msg[p:p + 4])
        return host, p + 4
    if atyp == 3:
        n = msg[p]
        p += 1
        host = msg[p:p + n].decode('utf-8', 'ignore')
        return host, p + n
    if atyp == 4:
        host = _ipv6(msg[p:p + 16])
        return host, p + 16
    raise ValueError('bad address type')


# ---- protocol handlers (返回 True=接管连接, False=不是该协议继续试) -------
async def handle_vless(ws, msg):
    try:
        version = msg[0]
        for k in range(16):
            if msg[1 + k] != int(NODE_ID_HEX[k * 2:k * 2 + 2], 16):
                return False
        if len(msg) < 18:
            return False
        off = msg[17] + 19  # VLE-SS 偏移
        if len(msg) < off + 3:
            return False
        port = (msg[off] << 8) | msg[off + 1]
        atyp = msg[off + 2]
        if atyp == 1:
            if len(msg) < off + 7:
                return False
            host = '.'.join(str(b) for b in msg[off + 3:off + 7])
            end = off + 7
        elif atyp == 2:
            if len(msg) < off + 4:
                return False
            n = msg[off + 3]
            if len(msg) < off + 4 + n:
                return False
            host = msg[off + 4:off + 4 + n].decode('utf-8', 'ignore')
            end = off + 4 + n
        elif atyp == 3:
            if len(msg) < off + 19:
                return False
            host = _ipv6(msg[off + 3:off + 19])
            end = off + 19
        else:
            return False
        if is_protected_host(host):
            await ws.close()
            return True
        await ws.send_bytes(bytes([version, 0]))
        await open_tunnel(ws, host, port, msg[end:])
        return True
    except Exception:
        return False


_TROJAN_HASH = hashlib.sha224(NODE_ID.encode()).hexdigest()


async def handle_trojan(ws, msg):
    try:
        if len(msg) < 58:
            return False
        if _TROJAN_HASH != msg[0:56].decode('ascii', 'ignore'):
            return False
        off = 56
        if msg[off] == 0x0d and msg[off + 1] == 0x0a:
            off += 2
        if msg[off] != 0x01:  # cmd
            return False
        off += 1
        host, off = _read_address(msg, off)
        port = (msg[off] << 8) | msg[off + 1]
        off += 2
        if off + 1 < len(msg) and msg[off] == 0x0d and msg[off + 1] == 0x0a:
            off += 2
        if is_protected_host(host):
            await ws.close()
            return True
        await open_tunnel(ws, host, port, msg[off:])
        return True
    except Exception:
        return False


async def handle_ss(ws, msg):
    try:
        if len(msg) == 0:
            return False
        atyp = msg[0]
        if atyp not in (1, 3, 4):
            return False
        # SS(v2ray-plugin ws) 地址头后无 CRLF 分隔，紧跟 payload
        host, off = _read_address(msg, 0)
        port = (msg[off] << 8) | msg[off + 1]
        off += 2
        if is_protected_host(host):
            await ws.close()
            return True
        await open_tunnel(ws, host, port, msg[off:])
        return True
    except Exception:
        return False


_HANDLERS = [
    (lambda m: len(m) > 17 and m[0] == 0, handle_vless),
    (lambda m: len(m) >= 58, handle_trojan),
    (lambda m: len(m) > 0 and m[0] in (1, 3, 4), handle_ss),
]


async def dispatch(ws, msg):
    for guard, handle in _HANDLERS:
        if guard(msg) and await handle(ws, msg):
            return
    await ws.close()


# ---- themed front page ---------------------------------------------------
THEMES = [
    {'name': 'green', 'title': 'Green Network', 'slogan': 'Protect Our Planet, Preserve Our Future',
     'primary': '#2e7d32', 'secondary': '#4caf50', 'accent': '#8bc34a', 'dark': '#1b5e20', 'light': '#e8f5e9'},
    {'name': 'ocean', 'title': 'Blue Horizon', 'slogan': 'Safeguarding the Seas for Tomorrow',
     'primary': '#01579b', 'secondary': '#0288d1', 'accent': '#4fc3f7', 'dark': '#01378a', 'light': '#e1f5fe'},
    {'name': 'forest', 'title': 'Wildwood', 'slogan': 'Where Every Root Tells a Story',
     'primary': '#33691e', 'secondary': '#558b2f', 'accent': '#9ccc65', 'dark': '#1b5e20', 'light': '#f1f8e9'},
    {'name': 'sunset', 'title': 'Golden Dunes', 'slogan': 'Chasing Light Across the Sands',
     'primary': '#e65100', 'secondary': '#f57c00', 'accent': '#ffb74d', 'dark': '#bf360c', 'light': '#fff3e0'},
    {'name': 'meadow', 'title': 'Willow Fields', 'slogan': 'Cultivating Calm, One Meadow at a Time',
     'primary': '#4a148c', 'secondary': '#7b1fa2', 'accent': '#ba68c8', 'dark': '#311b92', 'light': '#f3e5f5'},
    {'name': 'glacier', 'title': 'Northlight', 'slogan': "Preserving the World's Last Frozen Frontiers",
     'primary': '#37474f', 'secondary': '#546e7a', 'accent': '#90a4ae', 'dark': '#263238', 'light': '#eceff1'},
]


def pick_theme():
    if SITE_THEME:
        for t in THEMES:
            if t['name'] == SITE_THEME:
                return t
        try:
            idx = int(SITE_THEME)
            return THEMES[((idx % len(THEMES)) + len(THEMES)) % len(THEMES)]
        except ValueError:
            pass
    return THEMES[random.randrange(len(THEMES))]


def render_home():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            raw = f.read()
    except OSError:
        raw = '<!doctype html><html><head><title>{{TITLE}}</title></head><body>{{SLOGAN}}</body></html>'
    t = pick_theme()
    return (raw
            .replace('{{TITLE}}', SITE_TITLE or t['title'])
            .replace('{{SLOGAN}}', t['slogan'])
            .replace('{{PRIMARY}}', t['primary'])
            .replace('{{SECONDARY}}', t['secondary'])
            .replace('{{ACCENT}}', t['accent'])
            .replace('{{DARK}}', t['dark'])
            .replace('{{LIGHT}}', t['light']))


HOME_HTML = render_home()
NOT_FOUND_HTML = ('<!DOCTYPE html>\n<html>\n<head><title>404 Not Found</title></head>\n<body>\n'
                  '<center><h1>404 Not Found</h1></center>\n<hr><center>' + SERVER_HEADER +
                  '</center>\n</body>\n</html>\n')


# ---- http + ws -----------------------------------------------------------
def _resp(status, body, ctype):
    data = body if isinstance(body, (bytes, bytearray)) else str(body).encode('utf-8')
    return web.Response(status=status, body=data,
                        headers={'Server': SERVER_HEADER, 'Content-Type': ctype})


async def handler(request):
    # WS upgrade：握手前仅校验 path 前缀（不校验 Host，保持 CDN 反代兼容）
    if request.headers.get('Upgrade', '').lower() == 'websocket':
        if not request.path.startswith('/' + WSPATH):
            return _resp(404, NOT_FOUND_HTML, 'text/html; charset=utf-8')
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            first = await ws.receive(timeout=10)
            if first.type == aiohttp.WSMsgType.BINARY:
                await dispatch(ws, first.data)
            else:
                await ws.close()
        except Exception:
            try:
                await ws.close()
            except Exception:
                pass
        return ws

    p = request.path
    if p == '/':
        return _resp(200, HOME_HTML, 'text/html; charset=utf-8')
    if p == '/favicon.ico':
        return web.Response(status=204, headers={'Server': SERVER_HEADER})
    if p == '/robots.txt':
        return _resp(200, 'User-agent: *\nDisallow: /\n', 'text/plain')
    if SUB_PATH and p == '/' + SUB_PATH:
        if not meta_valid:
            return _resp(503, 'Service Unavailable\n', 'text/plain')
        return _resp(200, base64.b64encode(build_subscription().encode()).decode() + '\n', 'text/plain')
    return _resp(404, NOT_FOUND_HTML, 'text/html; charset=utf-8')


# ---- self destruct -------------------------------------------------------
def _self_destruct():
    for f in ['app.py', 'index.html', 'requirements.txt', 'npm', 'config.yaml']:
        try:
            os.remove(f)
        except OSError:
            pass  # 平台差异/运行中文件，忽略
    try:
        shutil.rmtree('__pycache__', ignore_errors=True)
    except Exception:
        pass
    for k in SENSITIVE_ENV:
        try:
            os.environ.pop(k, None)  # CPython 调 unsetenv，更新 /proc/self/environ
        except Exception:
            pass
    logging.disable(logging.CRITICAL)
    sys.excepthook = lambda *a: None
    try:
        asyncio.get_event_loop().set_exception_handler(lambda loop, ctx: None)
    except Exception:
        pass
    try:
        devnull = open(os.devnull, 'w')
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass


def arm_self_destruct(loop):
    if not SELF_DESTRUCT:
        return
    loop.call_later(SELF_DESTRUCT_AFTER, _self_destruct)


# ---- boot ----------------------------------------------------------------
async def main():
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    print(f'listening on {PORT} (path /{WSPATH})')

    await deliver()
    arm_self_destruct(asyncio.get_event_loop())

    try:
        await asyncio.Future()
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
    for name in ('aiohttp.access', 'aiohttp.server', 'aiohttp.client', 'aiohttp.internal', 'aiohttp.websocket'):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
