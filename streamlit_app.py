#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit Cloud 适配入口 (python-xray-argo)

Streamlit Cloud 固定用 `streamlit run <main_file>` 启动，不会执行上游
app.py 里 `if __name__ == '__main__':` 的代码。本文件把上游的服务启动逻辑
搬进 Streamlit 的脚本生命周期：

  · @st.cache_resource 保证整个进程只启动一次
  · 上游 HTTP 订阅服务跑在后台线程，并自动避开 Streamlit 自己的 8501 端口
  · 上游 start_server() 负责下载内核 + 拉起 cloudflared(argo)/xray
  · 页面只做状态展示，绝不阻塞脚本线程

环境变量与上游完全一致（UUID / ARGO_AUTH / ARGO_DOMAIN / SUB_PATH / ...）。
"""

import os
import re
import sys
import socket
import threading
import traceback

import streamlit as st

_HERE = os.path.dirname(os.path.abspath(__file__))
_UPSTREAM = os.path.join(_HERE, "app.py")

# 记录启动过程，供页面展示
_LOG_LINES = []
_LOG_LOCK = threading.Lock()


def _note(msg):
    with _LOG_LOCK:
        _LOG_LINES.append(str(msg)[:500])
        del _LOG_LINES[:-120]


def _pick_free_port(preferred, avoid=(8501, 8502)):
    """选一个真正空闲、且不与 Streamlit 冲突的端口。"""
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
    """把 app.py 作为模块执行（不会触发它的 __main__ 分支）。"""
    import importlib.util

    if not os.path.exists(_UPSTREAM):
        raise FileNotFoundError(f"缺少 {_UPSTREAM}")

    spec = importlib.util.spec_from_file_location("upstream_app", _UPSTREAM)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["upstream_app"] = mod
    spec.loader.exec_module(mod)
    return mod


@st.cache_resource(show_spinner=False)
def _boot_service():
    state = {"ok": False, "error": "", "port": None, "argo": "", "sub": ""}

    try:
        # Streamlit 自身监听 8501，先把上游端口挪开，避免抢占导致 Streamlit 失联
        port = _pick_free_port(int(os.environ.get("PORT") or 3000))
        if port is None:
            raise RuntimeError("找不到可用端口")
        os.environ["PORT"] = str(port)
        state["port"] = port
        _note(f"订阅端口已选: {port}")

        mod = _load_upstream()
        _note("上游模块加载完成")

        from http.server import ThreadingHTTPServer

        server = ThreadingHTTPServer(("0.0.0.0", port), mod.RequestHandler)
        threading.Thread(
            target=server.serve_forever, daemon=True, name="sub-http"
        ).start()
        _note(f"订阅 HTTP 服务已监听 :{port}")

        # start_server() 内部用 Popen 拉子进程，是非阻塞的
        def _run():
            try:
                mod.start_server()
                _note("start_server 完成")
            except Exception:
                _note("start_server 异常: " + traceback.format_exc(limit=3))

        threading.Thread(target=_run, daemon=True, name="upstream-main").start()
        _note("argo/xray 主流程已启动")

        state["ok"] = True
    except Exception:
        state["error"] = traceback.format_exc()

    return state


def _read_sub():
    """读上游落盘的 sub.txt，用于在页面上展示节点。"""
    base = os.environ.get("FILE_PATH", ".cache")
    for p in (os.path.join(_HERE, base, "sub.txt"), os.path.join(base, "sub.txt")):
        try:
            if os.path.exists(p):
                return open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            pass
    return ""


def _find_argo_domain():
    """从上游日志/文件里提取 argo 域名。"""
    for line in reversed(_LOG_LINES):
        m = re.search(r"([a-z0-9-]+\.trycloudflare\.com)", line)
        if m:
            return m.group(1)
    txt = _read_sub()
    m = re.search(r"([a-z0-9-]+\.trycloudflare\.com)", txt)
    return m.group(1) if m else ""


# ---------------------------------------------------------------- 页面
st.set_page_config(page_title="python-xray-argo", page_icon="🛰️", layout="centered")
st.title("🛰️ python-xray-argo")

state = _boot_service()

if state["ok"]:
    st.success(f"后台服务已启动（订阅端口 {state['port']}）")
else:
    st.error("启动失败")
    st.code(state["error"] or "unknown")

sub_path = os.environ.get("SUB_PATH", "sub")
st.markdown(f"**订阅路径**：`/{sub_path}`")

argo = _find_argo_domain()
if argo:
    st.markdown(f"**Argo 隧道**：`{argo}`")

sub = _read_sub()
if sub.strip():
    with st.expander("节点内容（sub.txt）", expanded=True):
        st.text(sub.strip()[:4000])
else:
    st.info("节点文件尚未生成，构建日志里可看到实时进度。")

with st.expander("启动日志"):
    st.text("\n".join(_LOG_LINES) or "(空)")

st.caption(
    "Streamlit 只承载进程与出站隧道；订阅页由后台端口提供，"
    "在 App settings → Secrets 里配置 UUID / ARGO_AUTH / ARGO_DOMAIN。"
)
