"""Mock 反向代理认证网关(给 dbx 的 proxy_header provider 做浏览器级联调).

分工说明:
    mock_proxy_header_auth.py = “被保护应用”教学示例(应用侧解析 X-Remote-* 头)
    mock_proxy_gateway.py     = 本文件, 给 dbx 联调用的迷你认证网关:
                                登录会话 + 剥离入站身份头 + 注入 dbx 约定头 + 反向代理

工作方式(dbx proxy_header provider, trusted_proxies 含 127.0.0.0/8):
    浏览器 → 本网关(:8114, 未登录则先出多用户登录页) → 注入身份头 → dbx(:4224)
    - 未认证请求: 渲染网关自己的登录页(账号来自共享用户集, 支持 MOCK_USERS_JSON);
      登录成功种网关会话 cookie(mock_gw_session, HttpOnly)。
    - 已认证请求: 转发前先剥离入站请求中的同名身份头(防外部伪造), 再注入会话用户的
      X-Forwarded-User / X-Forwarded-Email / X-Forwarded-Display-Name / X-Forwarded-Groups
      (组逗号拼接, 与 dbx 的分隔约定一致)。
    - GET /logout: 清除网关会话 → 后续请求不再注入身份头 → dbx 因无身份头返回 401,
      浏览器表现为回到网关登录页(dbx 侧另有 5 分钟登出宽限期, 换用户不受影响)。

已知限制: 不支持 WebSocket; HTTP/SSE 流式响应支持(逐块透传)。
请求/响应体整体缓冲后转发, 不适合超大文件联调。

环境变量 / CLI:
    PROXY_UPSTREAM       上游地址(默认 http://127.0.0.1:4224, 即 dbx)
    GW_USER_HEADER       用户头(默认 X-Forwarded-User, 即 dbx 默认值)
    GW_EMAIL_HEADER      邮箱头(默认 X-Forwarded-Email)
    GW_DISPLAY_NAME_HEADER  显示名头(默认 X-Forwarded-Display-Name)
    GW_GROUPS_HEADER     组头(默认 X-Forwarded-Groups, 逗号分隔)

运行:
    uv run python mock_proxy_gateway.py --port 8114 --upstream http://127.0.0.1:4224

测试:
    uv run pytest test_proxy_gateway.py -v
"""

from __future__ import annotations

import argparse
import os
from typing import Any, Dict, List, Optional, Tuple

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from starlette.background import BackgroundTask

from common.sessions import make_cookie_value, new_secret, parse_cookie_value
from common.users import get_users, profile, verify_password

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8114
DEFAULT_UPSTREAM = "http://127.0.0.1:4224"

SESSION_COOKIE = "mock_gw_session"
SESSION_TTL_SECONDS = 8 * 3600

LOGIN_PATH = "/__gw/login"
LOGOUT_PATH = "/logout"

# 逐跳头: 转发时剥离(由 httpx/uvicorn 重新生成)
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "expect",
}
# 上游响应头剥离(date/server 由 uvicorn 重新生成; content-encoding 因解码后转发需去掉)
RESPONSE_DROP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "date",
    "server",
}

_PAGE_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; background: #f5f6f8; margin: 0; }
  .card { max-width: 380px; margin: 8vh auto; background: #fff; border: 1px solid #e3e6ea;
          border-radius: 8px; padding: 28px 32px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .muted { color: #6b7280; font-size: 12px; line-height: 1.6; }
  .error { color: #b91c1c; background: #fef2f2; border: 1px solid #fecaca;
           border-radius: 6px; padding: 8px 10px; font-size: 13px; }
  label { display: block; font-size: 13px; margin: 14px 0 4px; color: #374151; }
  input { width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid #d1d5db;
          border-radius: 6px; font-size: 14px; }
  button { margin-top: 18px; width: 100%; padding: 9px 0; background: #2563eb; color: #fff;
           border: 0; border-radius: 6px; font-size: 14px; cursor: pointer; }
</style>
"""


def _safe_next(path: Optional[str]) -> str:
    """仅允许站内相对路径, 防开放重定向."""
    if path and path.startswith("/") and not path.startswith("//"):
        return path
    return "/"


class GatewayConfig:
    """网关配置: 上游 + 四个身份头名(默认值即 dbx proxy_header 约定)."""

    def __init__(
        self,
        upstream: str = DEFAULT_UPSTREAM,
        user_header: str = "X-Forwarded-User",
        email_header: str = "X-Forwarded-Email",
        display_name_header: str = "X-Forwarded-Display-Name",
        groups_header: str = "X-Forwarded-Groups",
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.user_header = user_header
        self.email_header = email_header
        self.display_name_header = display_name_header
        self.groups_header = groups_header

    @property
    def identity_headers(self) -> List[str]:
        return [self.user_header, self.email_header, self.display_name_header, self.groups_header]

    def identity_for(self, user: Dict[str, Any]) -> List[Tuple[str, str]]:
        values: List[Tuple[str, str]] = [(self.user_header, user["username"])]
        if user.get("email"):
            values.append((self.email_header, str(user["email"])))
        if user.get("display_name"):
            values.append((self.display_name_header, str(user["display_name"])))
        groups = user.get("groups") or []
        values.append((self.groups_header, ",".join(groups)))
        return values


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


def create_gateway_app(
    upstream: Optional[str] = None,
    user_header: Optional[str] = None,
    email_header: Optional[str] = None,
    display_name_header: Optional[str] = None,
    groups_header: Optional[str] = None,
    session_secret: Optional[str] = None,
) -> FastAPI:
    """构建网关应用(参数缺省时读取 GW_* / PROXY_UPSTREAM 环境变量)."""
    config = GatewayConfig(
        upstream=upstream or _env("PROXY_UPSTREAM", DEFAULT_UPSTREAM),
        user_header=user_header or _env("GW_USER_HEADER", "X-Forwarded-User"),
        email_header=email_header or _env("GW_EMAIL_HEADER", "X-Forwarded-Email"),
        display_name_header=display_name_header or _env("GW_DISPLAY_NAME_HEADER", "X-Forwarded-Display-Name"),
        groups_header=groups_header or _env("GW_GROUPS_HEADER", "X-Forwarded-Groups"),
    )
    secret = session_secret or new_secret()  # 进程随机, 重启后所有网关会话失效
    app = FastAPI(title="Mock Proxy Auth Gateway", docs_url=None, redoc_url=None)
    app.state.http = httpx.AsyncClient(base_url=config.upstream, follow_redirects=False, timeout=60.0)

    # ---------------- 登录页 ----------------

    def _render_login(next_path: str = "/", error: Optional[str] = None) -> HTMLResponse:
        accounts = "".join(
            f'<li><code>{name}</code> — {"、".join(info.get("groups") or ["(无组)"])}</li>'
            for name, info in get_users().items()
        )
        error_html = f'<p class="error">{error}</p>' if error else ""
        return HTMLResponse(
            f"""<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><title>Mock Gateway · 登录</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Mock 认证网关</h1>
  <p class="muted">上游: {config.upstream}<br>注入头: {config.user_header} / {config.groups_header} 等</p>
  {error_html}
  <form method="post" action="{LOGIN_PATH}">
    <input type="hidden" name="next" value="{next_path}">
    <label>用户名<input name="username" autofocus autocomplete="username"></label>
    <label>密码<input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">登录</button>
  </form>
  <p class="muted">账号列表(密码 = &lt;用户名&gt;-password):<ul>{accounts}</ul></p>
</div>
</body>
</html>"""
        )

    def _session_user(request: Request) -> Optional[str]:
        value = request.cookies.get(SESSION_COOKIE)
        if not value:
            return None
        return parse_cookie_value(value, secret)

    @app.get(LOGIN_PATH)
    def login_page(next: str = "/"):  # noqa: A002 (与 query 参数名对齐)
        return _render_login(next_path=_safe_next(next))

    @app.post(LOGIN_PATH)
    async def login_submit(request: Request):
        form = await request.form()
        next_path = _safe_next(str(form.get("next") or "/"))
        username = str(form.get("username") or "").strip()
        password = str(form.get("password") or "")
        info = verify_password(username, password)
        if info is None:
            return _render_login(next_path=next_path, error="用户名或密码错误")
        response = RedirectResponse(next_path, status_code=302)
        response.set_cookie(
            SESSION_COOKIE,
            make_cookie_value(username, secret, SESSION_TTL_SECONDS),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @app.get(LOGOUT_PATH)
    def logout(next: str = "/"):  # noqa: A002
        response = RedirectResponse(_safe_next(next), status_code=302)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # ---------------- 反向代理 ----------------

    def _strip_session_cookie(cookie_header: str) -> Optional[str]:
        parts = []
        for part in cookie_header.split(";"):
            name = part.strip().split("=", 1)[0].lower()
            if name == SESSION_COOKIE.lower():
                continue
            if part.strip():
                parts.append(part.strip())
        return "; ".join(parts) if parts else None

    def _forward_headers(request: Request, user: Dict[str, Any]) -> List[Tuple[str, str]]:
        drop = {name.lower() for name in HOP_BY_HOP_HEADERS}
        drop.update(name.lower() for name in config.identity_headers)
        forwarded: List[Tuple[str, str]] = []
        for name, value in request.headers.raw:
            name_str = name.decode("latin-1").lower()
            if name_str in drop:
                continue
            if name_str == "cookie":
                remaining = _strip_session_cookie(value.decode("latin-1"))
                if remaining:
                    forwarded.append((name, remaining.encode("latin-1")))
                continue
            forwarded.append((name, value))
        # 注入会话用户身份(覆盖顺序无关: 入站同名头已全部剥离)
        for header, value in config.identity_for(user):
            forwarded.append((header.encode("latin-1"), value.encode("latin-1")))
        return forwarded

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def proxy(request: Request, path: str):
        username = _session_user(request)
        user = profile(username) if username else None
        if user is None:
            # 未认证 → 网关登录页(带原始路径, 登录后跳回)
            return _render_login(next_path=_safe_next(f"/{path}{('?'+request.url.query) if request.url.query else ''}"))

        body = await request.body()
        target = path + (f"?{request.url.query}" if request.url.query else "")
        upstream_request = app.state.http.build_request(
            request.method, target, headers=_forward_headers(request, user), content=body or None
        )
        try:
            upstream_response = await app.state.http.send(upstream_request, stream=True)
        except httpx.HTTPError as exc:
            return JSONResponse(status_code=502, content={"detail": f"上游 {config.upstream} 不可达: {exc}"})

        response = StreamingResponse(
            upstream_response.aiter_bytes(),
            status_code=upstream_response.status_code,
            background=BackgroundTask(upstream_response.aclose),
        )
        for name, value in upstream_response.headers.raw:
            if name.decode("latin-1").lower() not in RESPONSE_DROP_HEADERS:
                response.raw_headers.append((name, value))
        return response

    return app


# 供 `uvicorn mock_proxy_gateway:app` 使用; 独立进程见 main()
app = create_gateway_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock 反向代理认证网关(dbx proxy_header 联调用)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--upstream", default=None, help="上游地址(默认读 PROXY_UPSTREAM, 再默认 %s)" % DEFAULT_UPSTREAM)
    args = parser.parse_args()
    gateway = create_gateway_app(upstream=args.upstream)
    print(f"Mock 认证网关已启动: http://{args.host}:{args.port}  →  上游 {gateway.state.http.base_url}")
    print("  注入头  : X-Forwarded-User / X-Forwarded-Email / X-Forwarded-Display-Name / X-Forwarded-Groups(逗号分隔)")
    print("  登录    : 任意未认证路径会先出登录页; 账号来自共享用户集(密码 = <用户名>-password)")
    print("  登出    : GET /logout 清除网关会话(dbx 侧随之 401)")
    print("  已知限制: 不支持 WebSocket")
    uvicorn.run(gateway, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
