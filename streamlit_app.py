#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit Cloud 入口 (python-xray-argo)

行为：
  1. 后台静默启动上游服务（HTTP 订阅服务 + cloudflared/argo + xray），
     不向页面输出任何订阅链接或日志。
  2. 前台只渲染 index.html 的内容，并把 Streamlit 自身的外壳（标题栏、
     页脚、内边距）全部隐藏，使访问域名看到的就是 index.html 页面本身。

环境变量与上游一致：UUID / ARGO_AUTH / ARGO_DOMAIN / SUB_PATH / ...
"""

import os
import sys
import socket
import threading
import traceback

import streamlit as st
import streamlit.components.v1 as components

_HERE = os.path.dirname(os.path.abspath(__file__))
_UPSTREAM = os.path.join(_HERE, "app.py")
_INDEX = os.path.join(_HERE, "index.html")

# ----------------------------------------------------------------- 后台服务
def _pick_free_port(preferred, avoid=(8501, 8502)):
    for port in [preferred] + list(range(preferred + 1, preferred + 50)):
        if port in avoid:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    return None


def _load_upstream():
    import importlib.util

    spec = importlib.util.spec_from_file_location("upstream_app", _UPSTREAM)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["upstream_app"] = mod
    spec.loader.exec_module(mod)
    return mod


@st.cache_resource(show_spinner=False)
def _boot_service():
    """整进程只执行一次；任何异常只写 stderr，不落到页面。"""
    try:
        port = _pick_free_port(int(os.environ.get("PORT") or 3000))
        if port is None:
            raise RuntimeError("no free port")
        os.environ["PORT"] = str(port)

        mod = _load_upstream()

        from http.server import ThreadingHTTPServer

        server = ThreadingHTTPServer(("0.0.0.0", port), mod.RequestHandler)
        threading.Thread(target=server.serve_forever, daemon=True, name="sub-http").start()

        def _run():
            try:
                mod.start_server()
            except Exception:
                print("[upstream] " + traceback.format_exc(limit=3), file=sys.stderr)

        threading.Thread(target=_run, daemon=True, name="upstream-main").start()
        return {"ok": True, "port": port}
    except Exception:
        print("[boot] " + traceback.format_exc(), file=sys.stderr)
        return {"ok": False}


_boot_service()


# ----------------------------------------------------------------- 前台页面
def _read_index():
    try:
        with open(_INDEX, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return (
            "<!doctype html><html><head><meta charset='utf-8'></head>"
            "<body style='font-family:system-ui;padding:2rem'>"
            "<h2>Not found</h2></body></html>"
        )


st.set_page_config(
    page_title="Freecat",
    page_icon="🌿",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# 抹掉 Streamlit 外壳：顶栏、页脚、侧边栏、容器内边距、右侧工具栏
st.markdown(
    """
    <style>
      #MainMenu, header[data-testid="stHeader"], footer,
      [data-testid="stToolbar"], [data-testid="stDecoration"],
      [data-testid="stStatusWidget"], [data-testid="stSidebar"] { display: none !important; }

      .stApp { background: #fff; }
      .block-container,
      [data-testid="stAppViewBlockContainer"],
      section.main > div { padding: 0 !important; margin: 0 !important; max-width: 100% !important; }

      [data-testid="stAppViewContainer"] { padding: 0 !important; }
      [data-testid="stVerticalBlock"] { gap: 0 !important; }
      [data-testid="stVerticalBlockBorderWrapper"] { padding: 0 !important; }
      iframe { border: 0 !important; display: block; width: 100% !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

components.html(_read_index(), height=3000, scrolling=True)
