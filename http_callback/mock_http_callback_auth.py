"""Mock HTTP 回调认证服务(独立示例, 可直接运行) —— 支持多用户联调 dbx.

提供两套契约:

1. 原生 token introspection 契约(初版即有, 保持不变):
   - POST /auth/login   模拟用户登录, 返回 HMAC 签名 token(联调用)
   - POST /auth/verify  回调校验端点: {"token": ...} → {"active": true, "user": {...}}

2. dbx HttpCallbackProvider 原生契约(新增, 零字段路径映射直接对接):
   - POST /auth/callback 请求 {"username": "bob", "password": "bob-password"}
     成功 200: {"subject": "u-1002", "username": "bob", "display_name": "Bob Brown",
               "email": "bob@example.org", "groups": ["users", "admins"]}
     凭据错 401: {"error": "invalid_credentials", ...}
     密钥错 403: {"error": "invalid_secret", ...}(仅启用校验时)
     连通性探测(dbx test()): 请求体 {"ping": true} → 200 {"status": "ok"}

subject 为稳定 ID(u-1001 起按用户集顺序编号, 可用用户数据的 "subject" 字段覆盖):
同一用户反复登录得到相同 subject, 用于验证 dbx 对同 subject 的账号归并
(换组再登录时角色刷新、不重复建号)。

共享密钥校验(验证 dbx 的 X-DBX-Auth-Secret 注入路径):
    MOCK_CB_REQUIRE_SECRET=1        开启校验(默认关闭, 兼容现状)
    MOCK_CB_SHARED_SECRET=<value>   期望的密钥值(默认 dbx-mock-callback-secret);
                                    dbx 侧配置 shared_secret 后会自动携带该头
其他环境变量:
    MOCK_CB_TOKEN_TTL               /auth/login token 有效期秒数(默认 300)
    MOCK_USERS_JSON / MOCK_USERS_FILE   注入自定义用户集(见 common/users.py)

内置账号(密码约定 <username>-password): alice / bob / carol / dave

运行:
    uv run python mock_http_callback_auth.py --host 127.0.0.1 --port 8112

测试:
    uv run pytest test_http_callback_auth.py -v
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from common.users import get_users, profile, subject_id, verify_password

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8112

SIGNING_SECRET = "mock-callback-auth-signing-secret"  # 仅认证服务内部使用(login token)
DEFAULT_TOKEN_TTL = 300  # /auth/login token 默认有效期(秒), 可用 MOCK_CB_TOKEN_TTL 覆盖
VERIFY_TIMEOUT = 5.0     # 回调校验超时(秒)

SHARED_SECRET_HEADER = "X-DBX-Auth-Secret"  # 与 dbx HttpCallbackProvider 一致
DEFAULT_SHARED_SECRET = "dbx-mock-callback-secret"


def token_ttl() -> int:
    try:
        return int(os.environ.get("MOCK_CB_TOKEN_TTL", str(DEFAULT_TOKEN_TTL)))
    except ValueError:
        return DEFAULT_TOKEN_TTL


def secret_required() -> bool:
    return os.environ.get("MOCK_CB_REQUIRE_SECRET", "").strip().lower() in ("1", "true", "yes", "on")


def shared_secret() -> str:
    return os.environ.get("MOCK_CB_SHARED_SECRET", DEFAULT_SHARED_SECRET)


# ------------------------------------------------------------------ token 签发/校验(HMAC)


class AuthError(Exception):
    """token 校验失败基类."""


class InvalidTokenError(AuthError):
    pass


class ExpiredTokenError(AuthError):
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(body: str) -> str:
    mac = hmac.new(SIGNING_SECRET.encode(), body.encode(), hashlib.sha256)
    return _b64url_encode(mac.digest())


def issue_token(username: str, ttl: Optional[int] = None) -> str:
    """为用户签发 HMAC 签名 token(认证服务内部能力)."""
    user = profile(username)
    if user is None:
        raise KeyError(f"未知用户: {username}")
    effective_ttl = token_ttl() if ttl is None else ttl
    now = int(time.time())
    payload = {
        "sub": username,
        "email": user["email"],
        "iat": now,
        "exp": now + effective_ttl,
        "jti": secrets.token_hex(8),
    }
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_sign(body)}"


def verify_token(token: str) -> Dict[str, Any]:
    """校验 token, 失败抛 AuthError 子类; 成功返回 payload."""
    try:
        body, signature = token.split(".", 1)
    except ValueError as exc:
        raise InvalidTokenError("token 格式不正确") from exc
    if not hmac.compare_digest(signature, _sign(body)):
        raise InvalidTokenError("token 签名不匹配")
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError) as exc:
        raise InvalidTokenError("token payload 无法解析") from exc
    if not isinstance(payload, dict) or "sub" not in payload or "exp" not in payload:
        raise InvalidTokenError("token payload 字段缺失")
    if int(payload["exp"]) < int(time.time()):
        raise ExpiredTokenError("token 已过期")
    return payload


# ------------------------------------------------------------------ 认证服务(FastAPI)

auth_service_app = FastAPI(title="Mock HTTP Callback Auth Service", docs_url=None, redoc_url=None)


class LoginRequest(BaseModel):
    username: str
    password: str


class VerifyRequest(BaseModel):
    token: str


class CallbackRequest(BaseModel):
    """dbx HttpCallbackProvider 请求体: {"username", "password"}; test() 探测为 {"ping": true}."""

    model_config = ConfigDict(extra="ignore")

    username: Optional[str] = None
    password: Optional[str] = None
    ping: Optional[bool] = None


@auth_service_app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@auth_service_app.post("/auth/login")
def login(req: LoginRequest):
    info = verify_password(req.username, req.password)
    if info is None:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_credentials", "error_description": "用户名或密码错误"},
        )
    token = issue_token(req.username)
    payload = verify_token(token)
    return {
        "token": token,
        "token_type": "Bearer",
        "expires_in": token_ttl(),
        "user": info,
        "expires_at": payload["exp"],
    }


@auth_service_app.post("/auth/callback")
def auth_callback(request: Request, body: CallbackRequest):
    """dbx 原生契约: 用户名密码直接换顶层身份字段(零字段路径映射).

    - 可选 X-DBX-Auth-Secret 校验(MOCK_CB_REQUIRE_SECRET=1 开启);
    - {"ping": true} 为 dbx 管理端的连通性探测, 直接返回 200。
    """
    if body.ping and not body.username:
        return {"status": "ok", "service": "mock-http-callback-auth"}

    if secret_required():
        provided = request.headers.get(SHARED_SECRET_HEADER) or ""
        if not hmac.compare_digest(provided.encode(), shared_secret().encode()):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "invalid_secret",
                    "error_description": f"{SHARED_SECRET_HEADER} 缺失或不匹配",
                },
            )

    info = verify_password(body.username or "", body.password or "")
    if info is None:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_credentials", "error_description": "用户名或密码错误"},
        )
    return {
        "subject": subject_id(info["username"]),
        "username": info["username"],
        "display_name": info["display_name"],
        "email": info["email"],
        "groups": info["groups"],
    }


@auth_service_app.post("/auth/verify")
def verify(req: VerifyRequest):
    """回调校验端点(token introspection 契约): 集成方把用户请求中的 token POST 到这里."""
    try:
        payload = verify_token(req.token)
    except ExpiredTokenError as exc:
        return JSONResponse(
            status_code=401, content={"active": False, "error": "expired_token", "error_description": str(exc)}
        )
    except InvalidTokenError as exc:
        return JSONResponse(
            status_code=401, content={"active": False, "error": "invalid_token", "error_description": str(exc)}
        )
    info = profile(payload["sub"])
    user = info or {"username": payload["sub"]}
    return {
        "active": True,
        "user": user,
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    }


# ------------------------------------------------------------------ 集成方参考实现


def create_protected_app(callback_url: str, verify_timeout: float = VERIFY_TIMEOUT) -> FastAPI:
    """生成“被保护应用”示例: 中间件把 Bearer token 交给回调认证服务校验后再放行.

    生产建议: 复用 httpx.AsyncClient 连接池、按需缓存校验结果、回调走 HTTPS。
    """
    app = FastAPI(title="Protected App (HTTP callback auth demo)", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def verify_with_auth_service(request: Request, call_next):
        if request.url.path.startswith("/public"):
            return await call_next(request)

        authorization = request.headers.get("authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        if not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "缺少 Bearer token"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            async with httpx.AsyncClient(timeout=verify_timeout) as http:
                resp = await http.post(callback_url, json={"token": token})
        except httpx.HTTPError:
            return JSONResponse(status_code=503, content={"detail": "认证服务不可达"})

        if resp.status_code == 200:
            body = resp.json()
            if body.get("active"):
                request.state.user = body["user"]
                return await call_next(request)
            return JSONResponse(status_code=401, content={"detail": body.get("error_description", "token 校验失败")})
        if resp.status_code == 401:
            try:
                detail = resp.json().get("error_description", "token 校验失败")
            except Exception:
                detail = "token 校验失败"
            return JSONResponse(status_code=401, content={"detail": detail})
        return JSONResponse(status_code=502, content={"detail": "认证服务返回异常"})

    @app.get("/me")
    def me(request: Request):
        return {"user": request.state.user}

    @app.get("/public/ping")
    def ping():
        return {"pong": True}

    return app


@dataclass
class VerifyResult:
    """回调校验结果."""

    active: bool
    user: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_description: Optional[str] = None


class CallbackAuthClient:
    """集成方参考客户端: 登录换 token / 调用回调校验接口校验 token."""

    def __init__(self, base_url: str, timeout: float = VERIFY_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def login(self, username: str, password: str) -> Dict[str, Any]:
        resp = httpx.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def verify(self, token: str) -> VerifyResult:
        resp = httpx.post(
            f"{self.base_url}/auth/verify", json={"token": token}, timeout=self.timeout
        )
        if resp.status_code == 200:
            body = resp.json()
            return VerifyResult(active=bool(body.get("active")), user=body.get("user"))
        try:
            body = resp.json()
        except Exception:
            body = {}
        return VerifyResult(
            active=False,
            error=body.get("error", "unknown_error"),
            error_description=body.get("error_description"),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock HTTP 回调认证服务")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    print(f"Mock HTTP Callback Auth 服务已启动: http://{args.host}:{args.port}")
    print("  dbx 契约     : POST /auth/callback {\"username\",\"password\"} (X-DBX-Auth-Secret 可选)")
    print(f"  共享密钥校验 : {'开启' if secret_required() else '关闭'} (MOCK_CB_REQUIRE_SECRET=1 开启, 期望值 {shared_secret()})")
    print("  登录(联调)   : POST /auth/login  {\"username\": \"alice\", \"password\": \"alice-password\"}")
    print("  回调校验     : POST /auth/verify {\"token\": \"<token>\"}")
    print("  用户源       : common.users(MOCK_USERS_JSON / MOCK_USERS_FILE 可注入)")
    uvicorn.run(auth_service_app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
