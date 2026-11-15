"""Mock OIDC Provider(独立示例, 可直接运行) —— 支持多用户真实登录联调 dbx.

实现 OpenID Connect 1.0 核心端点:

- GET  /.well-known/openid-configuration   发现文档(含 end_session_endpoint)
- GET  /.well-known/jwks.json              RS256 公钥(JWKS)
- GET  /authorize                          授权端点: 无会话时返回真实 HTML 登录页
- POST /authorize                          登录表单提交: 校验密码 → 签发 code + IdP 会话
- POST /token                              令牌端点(authorization_code+PKCE / password / client_credentials / refresh_token)
- GET  /userinfo                           access_token → 用户信息(含 preferred_username / groups)
- GET  /logout                             清除 IdP 会话(SSO 语义: 登出后可换用户重登)

多用户 / SSO 语义:
- 首次 GET /authorize(无 IdP 会话) → 登录页; 登录成功种 HttpOnly 会话 cookie
  (mock_oidc_session); 同一浏览器再次 GET /authorize 免登录直接发 code ——
  即真实 IdP 的 SSO 行为; 访问 /logout 清除会话后可换另一个用户登录。
- 联调后门保留: GET /authorize?username=<user> 免密直通(仅无会话时生效,
  现有 pytest 与脚本联调依赖)。
- id_token / access_token / userinfo 均带 preferred_username 与 groups,
  dbx 默认用户名回退链 preferred_username → email → sub 与 groups_claim
  直接可用, 无需任何字段映射。

已注册客户端(可用环境变量扩展, 见 _load_clients):
    client_id=demo-client, client_secret=demo-secret
    redirect_uri 白名单 = http://127.0.0.1:9000/callback
                        + http://127.0.0.1:5173/api/auth/oidc/sso/callback (vite 代理)
                        + http://127.0.0.1:4224/api/auth/oidc/sso/callback (直连后端)

资源服务器验签参考实现: verify_access_token()(生产应从 jwks_uri 拉取公钥)。

环境变量:
    OIDC_MOCK_ISSUER           覆盖 issuer(默认 http://127.0.0.1:8111)
    OIDC_MOCK_REDIRECT_URIS    逗号分隔, 追加到 demo-client 白名单
    OIDC_MOCK_CLIENTS_FILE     JSON 文件, 整体替换 CLIENTS(结构同 CLIENTS)

运行:
    uv run python mock_oidc_auth.py --host 127.0.0.1 --port 8111

测试:
    uv run pytest test_oidc_auth.py -v
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.parse
from typing import Any, Dict, Optional

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from common.sessions import make_cookie_value, new_secret, parse_cookie_value
from common.users import get_users, profile, verify_password

ISSUER = os.environ.get("OIDC_MOCK_ISSUER", "http://127.0.0.1:8111")
KEY_ID = "mock-oidc-rs256-key"

ACCESS_TOKEN_TTL = 3600  # access_token 有效期(秒)
ID_TOKEN_TTL = 3600      # id_token 有效期(秒)
AUTHORIZATION_CODE_TTL = 120  # 授权码有效期(秒), 且一次性使用

SESSION_COOKIE = "mock_oidc_session"
SESSION_TTL_SECONDS = 8 * 3600
_SESSION_SECRET = new_secret()  # 进程随机, 重启后所有 IdP 会话失效(mock 语义)

# 授权端点需要透传/回填的 OAuth 参数(登录页隐藏字段)
_OAUTH_PARAM_NAMES = (
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
)


def _load_clients() -> Dict[str, Dict[str, Any]]:
    """CLIENTS 加载: 环境变量可追加/替换, 默认白名单含 dbx 开发常用回调."""
    file_path = os.environ.get("OIDC_MOCK_CLIENTS_FILE")
    if file_path and file_path.strip():
        with open(file_path.strip(), "r", encoding="utf-8") as handle:
            return json.load(handle)

    clients: Dict[str, Dict[str, Any]] = {
        "demo-client": {
            "client_secret": "demo-secret",
            "redirect_uris": [
                "http://127.0.0.1:9000/callback",
                "http://127.0.0.1:5173/api/auth/oidc/sso/callback",  # dbx 经 vite 代理
                "http://127.0.0.1:4224/api/auth/oidc/sso/callback",  # dbx 直连后端
                # localhost 变体: vite changeOrigin 会把 Host 改写为 vite target,
                # DBX_PUBLIC_URL 写 localhost 时 dbx 推导出的回调就是 localhost 形态
                "http://localhost:5173/api/auth/oidc/sso/callback",
                "http://localhost:4224/api/auth/oidc/sso/callback",
                # RP-initiated logout 回跳(post_logout_redirect_uri 也按此白名单校验)
                "http://localhost:5173/login",
                "http://127.0.0.1:5173/login",
                "http://127.0.0.1:4224/login",
            ],
        },
    }
    extra = os.environ.get("OIDC_MOCK_REDIRECT_URIS", "")
    for uri in extra.split(","):
        uri = uri.strip()
        if uri:
            clients["demo-client"]["redirect_uris"].append(uri)
    return clients


CLIENTS: Dict[str, Dict[str, Any]] = _load_clients()

USERS_SOURCE = "common.users(MOCK_USERS_JSON / MOCK_USERS_FILE 可注入)"

AUTHORIZATION_CODES: Dict[str, Dict[str, Any]] = {}
REFRESH_TOKENS: Dict[str, Dict[str, Any]] = {}

app = FastAPI(title="Mock OIDC Provider", docs_url=None, redoc_url=None)

# ------------------------------------------------------------------ 签名密钥(RSA)
# mock 在进程内生成密钥对, 重启后旧 token 全部失效; 真实 OP 会持久化密钥。

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwks() -> Dict[str, Any]:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(_private_key.public_key(), as_dict=True)
    jwk.update({"kid": KEY_ID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


# ------------------------------------------------------------------ 令牌签发/校验


def _now() -> int:
    return int(time.time())


def _encode_jwt(claims: Dict[str, Any]) -> str:
    return jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": KEY_ID})


def _user_claims(username: str) -> Dict[str, Any]:
    """把共享用户集条目整理成令牌签发所需的 claims 源."""
    info = profile(username) or {}
    return {
        "sub": username,
        "name": info.get("display_name"),
        "email": info.get("email"),
        "groups": info.get("groups", []),
    }


def _issue_tokens(
    client_id: str, user: Optional[Dict[str, Any]], scope: str, nonce: Optional[str] = None
) -> Dict[str, Any]:
    now = _now()
    subject = user["sub"] if user else f"service:{client_id}"
    access_claims: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": subject,
        "aud": client_id,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "jti": secrets.token_hex(8),
    }
    if user:
        access_claims["preferred_username"] = user["sub"]  # 与 id_token/userinfo 保持一致
        access_claims["email"] = user.get("email")
        access_claims["groups"] = user.get("groups", [])
    response: Dict[str, Any] = {
        "access_token": _encode_jwt(access_claims),
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL,
        "scope": scope,
    }

    if user:  # OIDC 用户流程才签发 id_token / refresh_token
        id_claims: Dict[str, Any] = {
            "iss": ISSUER,
            "sub": subject,
            "aud": client_id,
            "iat": now,
            "exp": now + ID_TOKEN_TTL,
            # dbx 默认用户名回退链: preferred_username → email → sub
            "preferred_username": subject,
            "groups": user.get("groups", []),
            "name": user.get("name"),
            "email": user.get("email"),
        }
        if nonce:
            id_claims["nonce"] = nonce
        response["id_token"] = _encode_jwt(id_claims)

        refresh_token = secrets.token_urlsafe(32)
        REFRESH_TOKENS[refresh_token] = {"client_id": client_id, "sub": subject, "scope": scope}
        response["refresh_token"] = refresh_token
    return response


def verify_access_token(
    token: str, jwks: Optional[Dict[str, Any]] = None, audience: Optional[str] = None
) -> Dict[str, Any]:
    """资源服务器(集成方)参考实现: 使用 JWKS 公钥校验 access_token.

    - 远程部署时: 从 discovery 的 jwks_uri 拉取公钥并缓存;
    - 同进程联调时: 缺省使用 mock 自带公钥;
    - 资源服务器应传入 audience 校验 aud 是否指向自己(iss/aud/exp 缺一不可)。
    """
    if jwks is None:
        jwks = public_jwks()
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    options: Dict[str, Any] = {"require": ["exp", "iss", "sub"]}
    if audience is None:
        # OP 侧(userinfo)只验签名/有效期, 不校验 aud;
        # PyJWT >= 2.10 在 audience=None 但 token 带 aud 时会直接报错, 需显式关闭。
        options["verify_aud"] = False
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=ISSUER,
        options=options,
    )


def _oidc_error(
    status_code: int, error: str, description: str, headers: Optional[dict] = None
) -> JSONResponse:
    """按 RFC 6749 的错误响应格式返回."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers=headers,
    )


# ------------------------------------------------------------------ 登录页 / 会话


def _session_username(request: Request) -> Optional[str]:
    value = request.cookies.get(SESSION_COOKIE)
    if not value:
        return None
    return parse_cookie_value(value, _SESSION_SECRET)


_PAGE_STYLE = """
<style>
  body { font-family: system-ui, sans-serif; background: #f5f6f8; margin: 0; }
  .card { max-width: 360px; margin: 8vh auto; background: #fff; border: 1px solid #e3e6ea;
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


def _login_page(error: Optional[str] = None, params: Optional[Dict[str, str]] = None) -> HTMLResponse:
    params = params or {}
    hidden = "".join(
        f'<input type="hidden" name="{name}" value="{html.escape(str(params.get(name) or ""))}">'
        for name in _OAUTH_PARAM_NAMES
    )
    accounts = ", ".join(f"{name}/{name}-password" for name in get_users())
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><title>Mock OIDC Provider · 登录</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>Mock OIDC Provider</h1>
  <p class="muted">模拟 IdP 登录页 · client_id: {html.escape(str(params.get("client_id") or ""))}</p>
  {error_html}
  <form method="post" action="/authorize">
    {hidden}
    <label>用户名<input name="username" autofocus autocomplete="username"></label>
    <label>密码<input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">登录</button>
  </form>
  <p class="muted">内置账号: {html.escape(accounts)}</p>
  <p class="muted">联调后门: GET /authorize?username=&lt;user&gt; 可免密直通(仅无 IdP 会话时生效)</p>
</div>
</body>
</html>"""
    return HTMLResponse(body)


_LOGOUT_HTML = f"""<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><title>Mock OIDC Provider · 已登出</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <h1>已登出</h1>
  <p class="muted">Mock OIDC IdP 会话已清除; 重新发起 SSO 时将再次出现登录页, 可换一个用户登录。</p>
  <p><a href="/authorize">重新登录</a></p>
</div>
</body>
</html>"""


def _all_redirect_uris() -> set:
    uris: set = set()
    for client in CLIENTS.values():
        uris.update(client.get("redirect_uris", []))
    return uris


def _validate_authorize_request(
    response_type: str, client_id: str, redirect_uri: str
) -> Optional[JSONResponse]:
    """client/redirect_uri/response_type 校验; 失败返回 OIDC 错误响应."""
    client = CLIENTS.get(client_id)
    if client is None:
        return _oidc_error(400, "invalid_client", "未注册的 client_id")
    if redirect_uri not in client["redirect_uris"]:
        return _oidc_error(400, "invalid_request", "redirect_uri 未在客户端注册")
    if response_type != "code":
        return _oidc_error(400, "unsupported_response_type", "mock 仅支持 response_type=code")
    return None


def _redirect_with_code(oauth_params: Dict[str, str], username: str) -> RedirectResponse:
    code = secrets.token_urlsafe(24)
    AUTHORIZATION_CODES[code] = {
        "client_id": oauth_params["client_id"],
        "redirect_uri": oauth_params["redirect_uri"],
        "username": username,
        "scope": oauth_params.get("scope") or "openid",
        "nonce": oauth_params.get("nonce") or None,
        "code_challenge": oauth_params.get("code_challenge") or None,
        "code_challenge_method": oauth_params.get("code_challenge_method") or None,
        "exp": _now() + AUTHORIZATION_CODE_TTL,
    }
    query = {"code": code}
    if oauth_params.get("state"):
        query["state"] = oauth_params["state"]
    return RedirectResponse(
        f"{oauth_params['redirect_uri']}?{urllib.parse.urlencode(query)}", status_code=302
    )


# ------------------------------------------------------------------ 端点


@app.get("/.well-known/openid-configuration")
def discovery() -> Dict[str, Any]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "end_session_endpoint": f"{ISSUER}/logout",
        "response_types_supported": ["code"],
        "subject_type": "public",
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "grant_types_supported": ["authorization_code", "password", "client_credentials", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub", "name", "preferred_username", "email", "groups", "iss", "aud", "exp", "iat",
        ],
    }


@app.get("/.well-known/jwks.json")
def jwks() -> Dict[str, Any]:
    return public_jwks()


@app.get("/authorize")
def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: Optional[str] = Query(None),
    nonce: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    username: Optional[str] = Query(None, description="联调后门: 免密直通(仅无 IdP 会话时生效)"),
):
    error = _validate_authorize_request(response_type, client_id, redirect_uri)
    if error is not None:
        return error

    oauth_params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    # 1) IdP 会话优先: 已登录用户免登录直接发 code(真实 IdP 的 SSO 语义)
    session_user = _session_username(request)
    if session_user and session_user in get_users():
        return _redirect_with_code(oauth_params, session_user)

    # 2) 联调后门: ?username= 免密直通(仅无会话时生效)
    if username is not None:
        if username not in get_users():
            return _oidc_error(400, "access_denied", f"未知用户: {username}")
        return _redirect_with_code(oauth_params, username)

    # 3) 无会话且无后门 → 渲染登录页
    return _login_page(params=oauth_params)


@app.post("/authorize")
async def authorize_login(request: Request):
    """登录表单提交: 校验密码 → 签发 code + 种 IdP 会话 cookie."""
    form = await request.form()
    oauth_params = {name: (str(form.get(name) or "") or None) for name in _OAUTH_PARAM_NAMES}
    oauth_params["client_id"] = oauth_params["client_id"] or ""
    oauth_params["redirect_uri"] = oauth_params["redirect_uri"] or ""
    oauth_params["response_type"] = oauth_params["response_type"] or ""

    error = _validate_authorize_request(
        oauth_params["response_type"], oauth_params["client_id"], oauth_params["redirect_uri"]
    )
    if error is not None:
        return error

    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")

    # 已有 IdP 会话时直接沿用(登录页 + 会话并存的竞态)
    session_user = _session_username(request)
    target = session_user if session_user and session_user in get_users() else None

    if target is None:
        info = verify_password(username, password)
        if info is None:
            # 凭据错误 → 重新渲染登录页并提示(OIDC 惯例: 不用 401)
            return _login_page(error="用户名或密码错误", params=oauth_params)
        target = username

    response = _redirect_with_code(oauth_params, target)
    response.set_cookie(
        SESSION_COOKIE,
        make_cookie_value(target, _SESSION_SECRET, SESSION_TTL_SECONDS),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.get("/logout")
def logout(
    post_logout_redirect_uri: Optional[str] = Query(None),
    post_logout_redirect: Optional[str] = Query(None),
):
    """清除 IdP 会话; 回跳参数接受 OIDC 标准名 post_logout_redirect_uri(dbx/RP 发送)
    与别名 post_logout_redirect, 仅当其命中 redirect_uri 白名单时才跳转."""
    target = post_logout_redirect_uri or post_logout_redirect
    if target and target in _all_redirect_uris():
        response: Response = RedirectResponse(target, status_code=302)
    else:
        response = HTMLResponse(_LOGOUT_HTML)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.post("/token")
async def token_endpoint(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")

    # 客户端认证: HTTP Basic 优先, 其次 client_secret_post(dbx 未配 secret 时只发 client_id)
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode()
            basic_id, _, basic_secret = decoded.partition(":")
        except Exception:
            return _oidc_error(401, "invalid_client", "无法解析 Basic 认证头")
        client_id, client_secret = basic_id, basic_secret

    client = CLIENTS.get(client_id or "")
    if client is None or not secrets.compare_digest(
        client["client_secret"].encode(), (client_secret or "").encode()
    ):
        return _oidc_error(401, "invalid_client", "client_id 或 client_secret 不正确")

    if grant_type == "authorization_code":
        code = form.get("code")
        record = AUTHORIZATION_CODES.pop(code, None) if code else None
        if record is None:
            return _oidc_error(400, "invalid_grant", "授权码无效或已被使用")
        if record["exp"] < _now():
            return _oidc_error(400, "invalid_grant", "授权码已过期")
        if record["client_id"] != client_id:
            return _oidc_error(400, "invalid_grant", "授权码与 client 不匹配")
        if form.get("redirect_uri") != record["redirect_uri"]:
            return _oidc_error(400, "invalid_grant", "redirect_uri 与授权请求不一致")

        # PKCE(S256): 授权请求带 code_challenge 时必须回传匹配的 code_verifier
        challenge = record.get("code_challenge")
        if challenge:
            verifier = str(form.get("code_verifier") or "")
            computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            computed = computed.rstrip(b"=").decode()
            if not secrets.compare_digest(computed, challenge):
                return _oidc_error(400, "invalid_grant", "PKCE code_verifier 不匹配")

        return _issue_tokens(
            client_id,
            _user_claims(record["username"]),
            record["scope"],
            nonce=record.get("nonce"),
        )

    if grant_type == "refresh_token":
        refresh = form.get("refresh_token")
        record = REFRESH_TOKENS.pop(refresh, None) if refresh else None
        if record is None or record["client_id"] != client_id:
            return _oidc_error(400, "invalid_grant", "refresh_token 无效")
        if profile(record["sub"]) is None:
            return _oidc_error(400, "invalid_grant", "refresh_token 对应的用户已不存在")
        return _issue_tokens(client_id, _user_claims(record["sub"]), record["scope"])  # 每次轮换新 refresh_token

    if grant_type == "password":  # ROPC, 便于联调; 密码约定 = <username>-password
        username = form.get("username")
        password = form.get("password") or ""
        info = verify_password(str(username or ""), password)
        if info is None:
            return _oidc_error(400, "invalid_grant", "用户名或密码错误")
        return _issue_tokens(client_id, _user_claims(info["username"]), form.get("scope", "openid"))

    if grant_type == "client_credentials":
        return _issue_tokens(client_id, None, form.get("scope", "api"))

    return _oidc_error(400, "unsupported_grant_type", f"不支持的 grant_type: {grant_type}")


@app.get("/userinfo")
def userinfo(authorization: str = Header(default="")):
    token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if not token:
        return _oidc_error(
            401, "invalid_request", "缺少 Bearer access_token", {"WWW-Authenticate": "Bearer"}
        )
    try:
        claims = verify_access_token(token)  # OP 侧校验签名/有效期, aud 由资源方按需校验
    except jwt.PyJWTError as exc:
        return _oidc_error(
            401, "invalid_token", f"access_token 校验失败: {exc}", {"WWW-Authenticate": "Bearer"}
        )

    info = profile(claims["sub"])
    if info is None:  # client_credentials 等服务主体
        return {"sub": claims["sub"], "client_id": claims.get("client_id")}
    return {
        "sub": info["username"],
        "preferred_username": info["username"],
        "name": info["display_name"],
        "email": info["email"],
        "groups": info["groups"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock OIDC Provider")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8111)
    args = parser.parse_args()
    print(f"Mock OIDC Provider: {ISSUER}")
    print("  discovery : /.well-known/openid-configuration (含 end_session_endpoint)")
    print("  jwks      : /.well-known/jwks.json (RS256)")
    print(f"  client    : demo-client / demo-secret, redirect 白名单:")
    for uri in CLIENTS["demo-client"]["redirect_uris"]:
        print(f"              {uri}")
    print("  流程      : GET /authorize(登录页, 支持 PKCE) -> POST /authorize -> 302?code -> POST /token -> GET /userinfo")
    print(f"  会话      : 登录后免登录直发 code; GET /logout 清除会话(可换用户重登)")
    print(f"  用户源    : {USERS_SOURCE}")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
