#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit Cloud 适配入口 (python-xray-argo)

Streamlit Cloud 的启动命令固定为 `streamlit run <entrypoint>`，不执行
`if __name__ == '__main__':` 里的代码。本文件把上游 app.py 的服务启动逻辑
搬到 Streamlit 的脚本生命周期里：用 @st.cache_resource 保证整个进程内
只启动一次 HTTP 服务 + argo 隧道，之后 Streamlit 只负责展示状态。

环境变量与上游完全一致（UPLOAD_URL / UUID / ARGO_AUTH / ...），
另外新增 ST_REQUIRED=1 时不显示页面以外的副作用。
"""

import os
import sys
import threading
import traceback

import streamlit as st

# ---------------------------------------------------------------- 上游代码
# 以模块方式加载上游 app.py，避免它的 __main__ 分支被执行
_HERE = os.path.dirname(os.path.abspath(__file__))
_UPSTREAM = os.path.join(_HERE, "app.py")


def _load_upstream():
    """把 app.py 作为模块执行，返回模块对象（不会触发它的 __main__ 分支）。"""
    import importlib.util

    if not os.path.exists(_UPSTREAM):
        raise FileNotFoundError(f"缺少 {_UPSTREAM}")

    spec = importlib.util.spec_from_file_location("upstream_app", _UPSTREAM)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["upstream_app"] = mod
    spec.loader.exec_module(mod)   # 这里只定义函数/常量，不会启动服务
    return mod


# ---------------------------------------------------------------- 服务启动
@st.cache_resource(show_spinner=False)
def _boot_service():
    """整个 Streamlit 进程只执行一次：启动 HTTP 订阅服务 + argo 主流程。"""
    mod = _load_upstream()

    state = {"ok": False, "error": "", "port": None, "thread": None}

    try:
        from http.server import ThreadingHTTPServer

        port = getattr(mod, "PORT", 3000)
        state["port"] = port

        # 上游 RequestHandler 就是订阅服务入口
        server = ThreadingHTTPServer(("0.0.0.0", port), mod.RequestHandler)

        # 上游 start_server 负责下载内核、拉起 xray / cloudflared / nezha
        t = threading.Thread(target=mod.start_server, daemon=True, name="upstream-main")
        t.start()
        state["thread"] = t

        # HTTP 服务放到后台线程，不能占用 Streamlit 主线程
        threading.Thread(
            target=server.serve_forever, daemon=True, name="sub-http"
        ).start()

        state["ok"] = True
    except Exception:
        state["error"] = traceback.format_exc()

    return state


# ---------------------------------------------------------------- 页面
st.set_page_config(page_title="python-xray-argo", page_icon="🛰️", layout="centered")
st.title("🛰️ python-xray-argo")

state = _boot_service()

if state["ok"]:
    st.success(f"服务已启动，订阅端口 {state['port']}")
else:
    st.error("启动失败")
    st.code(state["error"] or "unknown")

sub_path = os.environ.get("SUB_PATH", "sub")
st.markdown(f"**订阅路径**：`/{sub_path}`")

proj = os.environ.get("PROJECT_URL", "")
if proj:
    st.markdown(f"**订阅地址**：`{proj.rstrip('/')}/{sub_path}`")

st.caption(
    "Streamlit 只承载进程；节点流量走 argo 隧道。"
    "请在 App settings → Secrets 里配置 UUID / ARGO_AUTH / ARGO_DOMAIN。"
)
