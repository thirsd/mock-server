"""Mock 代理头(Proxy Header)认证服务(独立示例, 可直接运行).

适用场景: 应用部署在反向代理(nginx / Traefik / APISIX + SSO)之后,
由代理完成真实认证, 再通过受信任的 HTTP 头把用户身份传给应用。
应用只需解析这些头 —— 这是最简单的一种“边缘认证”集成方式。

本 mock 约定的头:
    X-Proxy-Auth-Secret : 共享密钥, 证明请求确实来自受信任代理(防外部直连伪造)
    X-Remote-User       : 必填, 登录名
    X-Remote-Email      : 可选, 邮箱
    X-Remote-Groups     : 可选, 逗号分隔的用户组
    X-Forwarded-For     : 记录用, 原始客户端 IP

端点:
    GET /public/health  无需认证
    GET /me             返回解析出的用户身份
    GET /admin          需要 admins 组

运行:
    uv run python mock_proxy_header_auth.py --host 127.0.0.1 --port 8113

nginx 侧参考配置(由代理上的 SSO / auth_request 生成头之后注入):

    location /app/ {
        proxy_pass http://app_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Remote-User   $remote_user;              # 必填
        proxy_set_header X-Remote-Email  $upstream_http_x_email;
        proxy_set_header X-Remote-Groups $upstream_http_x_groups;
        proxy_set_header X-Proxy-Auth-Secret "proxy-shared-secret"; # 共享密钥
    }

集成方参考客户端: ProxyHeaderAuthClient(基于 httpx)。
"""

from __future__ import annotations

import argparse
import hmac
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8113

PROXY_SECRET = "proxy-shared-secret"  # 应用与反向代理之间的共享密钥

SECRET_HEADER = "X-Proxy-Auth-Secret"
USER_HEADER = "X-Remote-User"
EMAIL_HEADER = "X-Remote-Email"
GROUPS_HEADER = "X-Remote-Groups"

app = FastAPI(title="Mock Proxy Header Auth App", docs_url=None, redoc_url=None)


@dataclass
class ProxyUser:
    """从代理头解析出的用户身份."""

    username: str
    email: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    client_ip: Optional[str] = None

    def has_group(self, group: str) -> bool:
        return group in self.groups


def extract_proxy_user(request: Request) -> ProxyUser:
    """把代理注入的头解析为 ProxyUser(注意: 必须只信任来自受信任代理的请求)."""
    groups = [g.strip() for g in request.headers.get(GROUPS_HEADER, "").split(",") if g.strip()]
    return ProxyUser(
        username=request.headers.get(USER_HEADER, ""),
        email=request.headers.get(EMAIL_HEADER) or None,
        groups=groups,
        client_ip=request.headers.get("X-Forwarded-For"),
    )


@app.middleware("http")
async def proxy_header_auth(request: Request, call_next):
    if request.url.path.startswith("/public"):
        return await call_next(request)

    # 1) 共享密钥: 防止绕过代理、直接伪造身份头
    secret = request.headers.get(SECRET_HEADER) or ""
    if not hmac.compare_digest(secret.encode(), PROXY_SECRET.encode()):
        return JSONResponse(status_code=403, content={"detail": "缺少或错误的代理共享密钥(请求未经过受信任代理)"})

    # 2) 代理必须提供登录名
    user = extract_proxy_user(request)
    if not user.username:
        return JSONResponse(status_code=401, content={"detail": f"代理未提供 {USER_HEADER} 头"})

    request.state.user = user
    return await call_next(request)


@app.get("/public/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
def me(request: Request) -> Dict[str, Any]:
    user: ProxyUser = request.state.user
    return {
        "username": user.username,
        "email": user.email,
        "groups": user.groups,
        "client_ip": user.client_ip,
    }


@app.get("/admin")
def admin(request: Request):
    user: ProxyUser = request.state.user
    if not user.has_group("admins"):
        return JSONResponse(status_code=403, content={"detail": "需要 admins 组"})
    return {"message": f"welcome to admin, {user.username}"}


@dataclass
class ProxyHeaderAuthConfig:
    """集成方(应用侧)的配置: 应用按此自动携带代理认证头.

    实际部署中这些头由反向代理注入; 本客户端用于直接联调/测试。
    """

    base_url: str
    proxy_secret: str = PROXY_SECRET
    user: str = ""
    email: Optional[str] = None
    groups: Sequence[str] = ()
    extra_headers: Dict[str, str] = field(default_factory=dict)

    def headers(self) -> Dict[str, str]:
        headers = {
            SECRET_HEADER: self.proxy_secret,
            USER_HEADER: self.user,
        }
        if self.email:
            headers[EMAIL_HEADER] = self.email
        if self.groups:
            headers[GROUPS_HEADER] = ",".join(self.groups)
        headers.update(self.extra_headers)
        return headers


class ProxyHeaderAuthClient:
    """集成方参考客户端: 按配置自动携带代理认证头(等价于“代理转发后的请求”)."""

    def __init__(self, config: ProxyHeaderAuthConfig, timeout: float = 10.0) -> None:
        self.config = config
        self._client = httpx.Client(base_url=config.base_url, headers=config.headers(), timeout=timeout)

    def me(self) -> Dict[str, Any]:
        resp = self._client.get("/me")
        resp.raise_for_status()
        return resp.json()

    def admin_panel(self) -> Dict[str, Any]:
        resp = self._client.get("/admin")
        resp.raise_for_status()
        return resp.json()

    def health(self) -> Dict[str, str]:
        resp = self._client.get("/public/health")
        resp.raise_for_status()
        return resp.json()

    def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        return self._client.request(method, path, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ProxyHeaderAuthClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock 代理头(Proxy Header)认证应用")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    print(f"Mock Proxy Header Auth 应用已启动: http://{args.host}:{args.port}")
    print(f"  约定头  : {USER_HEADER}(必填), {EMAIL_HEADER}, {GROUPS_HEADER}(逗号分隔)")
    print(f"  共享密钥: {SECRET_HEADER}: {PROXY_SECRET}")
    print("  端点    : GET /public/health | GET /me | GET /admin(需 admins 组)")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
