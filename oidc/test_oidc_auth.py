"""mock_oidc_auth.py 的端到端集成测试.

通过真实 HTTP(uvicorn) 访问 mock OP, 覆盖:
- 发现文档 / JWKS / end_session_endpoint
- 授权码流程(authorize -> code -> token -> userinfo)与授权码一次性
- 多用户真实登录页 + IdP 会话 SSO + 登出换用户
- PKCE(S256) 校验、密码模式(ROPC)、client_credentials、refresh_token 轮换
- id_token/access_token/userinfo 的 preferred_username / groups claims
- 资源服务器参考实现 verify_access_token() 及各种验签失败路径(含 issuer 不匹配)
- redirect_uri 白名单可配置(OIDC_MOCK_REDIRECT_URIS / OIDC_MOCK_CLIENTS_FILE)
"""

import base64
import hashlib
import json

import httpx
import jwt
import pytest

import mock_oidc_auth
from mock_oidc_auth import ISSUER, CLIENTS, verify_access_token

REDIRECT_URI = CLIENTS["demo-client"]["redirect_uris"][0]
CLIENT_AUTH = ("demo-client", "demo-secret")

# 无后门参数的授权请求(走登录页 / IdP 会话路径)
AUTH_PARAMS = {
    "response_type": "code",
    "client_id": "demo-client",
    "redirect_uri": REDIRECT_URI,
    "scope": "openid",
    "state": "state-sso",
    "nonce": "nonce-sso",
}


@pytest.fixture(scope="module")
def server(uvicorn_server_factory):
    srv = uvicorn_server_factory(mock_oidc_auth.app)
    # 让 issuer 与测试服务的实际地址保持一致(mock 的全局 ISSUER 可运行时调整)
    mock_oidc_auth.ISSUER = f"http://{srv.host}:{srv.port}"
    yield srv
    mock_oidc_auth.ISSUER = ISSUER  # 还原, 避免影响其他用例


@pytest.fixture(scope="module")
def base_url(server):
    return f"http://{server.host}:{server.port}"


@pytest.fixture(scope="module")
def client(base_url):
    with httpx.Client(base_url=base_url, timeout=10, follow_redirects=False) as http:
        yield http


def _jwks(client: httpx.Client) -> dict:
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    return resp.json()


def _decode(token: str, jwks: dict, audience: str = "demo-client") -> dict:
    key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    return jwt.decode(token, key, algorithms=["RS256"], audience=audience, issuer=mock_oidc_auth.ISSUER)


def _password_grant(client: httpx.Client, username: str) -> dict:
    resp = client.post(
        "/token",
        data={"grant_type": "password", "username": username, "password": f"{username}-password"},
        auth=CLIENT_AUTH,
    )
    assert resp.status_code == 200
    return resp.json()


def _exchange(client: httpx.Client, code: str) -> httpx.Response:
    return client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI},
        auth=CLIENT_AUTH,
    )


# ------------------------------------------------------------------ discovery / jwks


def test_discovery_document(client):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["issuer"] == mock_oidc_auth.ISSUER
    assert doc["authorization_endpoint"] == f"{mock_oidc_auth.ISSUER}/authorize"
    assert doc["token_endpoint"] == f"{mock_oidc_auth.ISSUER}/token"
    assert doc["jwks_uri"] == f"{mock_oidc_auth.ISSUER}/.well-known/jwks.json"
    assert doc["userinfo_endpoint"] == f"{mock_oidc_auth.ISSUER}/userinfo"
    assert "RS256" in doc["id_token_signing_alg_values_supported"]


def test_discovery_includes_end_session_endpoint(client):
    doc = client.get("/.well-known/openid-configuration").json()
    assert doc["end_session_endpoint"] == f"{mock_oidc_auth.ISSUER}/logout"
    assert "S256" in doc["code_challenge_methods_supported"]


def test_jwks_exposes_rs256_signing_key(client):
    jwks = _jwks(client)
    assert jwks["keys"][0]["alg"] == "RS256"
    assert jwks["keys"][0]["use"] == "sig"
    assert jwks["keys"][0]["kid"] == mock_oidc_auth.KEY_ID


# ------------------------------------------------------------------ authorize(校验)


def test_authorize_rejects_unknown_client(client):
    resp = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "nope", "redirect_uri": REDIRECT_URI},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client"


def test_authorize_rejects_unregistered_redirect_uri(client):
    resp = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "demo-client", "redirect_uri": "http://evil.example.com/cb"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_rejects_unknown_user(client):
    resp = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "demo-client", "redirect_uri": REDIRECT_URI, "username": "ghost"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"


# ------------------------------------------------------------------ authorization code flow(直通后门)


def test_authorization_code_flow_happy_path(client):
    # 1) 授权端点: 302 回 redirect_uri 并携带 code + state
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": "state-xyz",
            "nonce": "nonce-123",
            "username": "alice",
        },
    )
    assert resp.status_code == 302
    location = httpx.URL(resp.headers["location"])
    assert str(location).startswith(REDIRECT_URI)
    assert location.params["state"] == "state-xyz"
    code = location.params["code"]

    # 2) client_secret_basic 方式用 code 换 token
    token_resp = _exchange(client, code)
    assert token_resp.status_code == 200
    tokens = token_resp.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == mock_oidc_auth.ACCESS_TOKEN_TTL
    assert tokens["refresh_token"]

    # 3) 资源方用 JWKS 公钥验签 access_token / id_token
    jwks = _jwks(client)
    access_claims = _decode(tokens["access_token"], jwks)
    assert access_claims["iss"] == mock_oidc_auth.ISSUER
    assert access_claims["aud"] == "demo-client"
    assert access_claims["sub"] == "alice"
    assert access_claims["scope"] == "openid profile email"

    id_claims = _decode(tokens["id_token"], jwks)
    assert id_claims["nonce"] == "nonce-123"
    assert id_claims["email"] == "alice@example.org"

    # 4) 用 access_token 调 userinfo
    userinfo_resp = client.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert userinfo_resp.status_code == 200
    userinfo = userinfo_resp.json()
    assert userinfo["sub"] == "alice"
    assert userinfo["email"] == "alice@example.org"


def test_authorization_code_is_single_use(client):
    resp = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "demo-client", "redirect_uri": REDIRECT_URI, "username": "bob"},
    )
    code = httpx.URL(resp.headers["location"]).params["code"]
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI}

    assert client.post("/token", data=data, auth=CLIENT_AUTH).status_code == 200

    replay = client.post("/token", data=data, auth=CLIENT_AUTH)  # 重放同一授权码
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


def test_token_endpoint_rejects_wrong_client_secret(client):
    resp = client.post("/token", data={"grant_type": "client_credentials"}, auth=("demo-client", "wrong"))
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_token_endpoint_supports_client_secret_post(client):
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": "demo-client", "client_secret": "demo-secret"},
    )
    assert resp.status_code == 200


# ------------------------------------------------------------------ 多用户登录页 / IdP 会话


def test_login_page_rendered_without_session(base_url):
    """无 IdP 会话且无 username 后门 → 渲染 HTML 登录页(200, 非 401)."""
    with httpx.Client(base_url=base_url, timeout=10, follow_redirects=False) as http:
        resp = http.get("/authorize", params=AUTH_PARAMS)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert '<form method="post" action="/authorize">' in resp.text
    assert 'name="client_id" value="demo-client"' in resp.text  # OAuth 参数以隐藏字段回填
    assert 'name="state" value="state-sso"' in resp.text


def test_login_page_post_wrong_password_rerenders(base_url):
    """错误密码 → 200 重新渲染登录页并提示(不用 401), 且不发放 code."""
    with httpx.Client(base_url=base_url, timeout=10, follow_redirects=False) as http:
        resp = http.post("/authorize", data={**AUTH_PARAMS, "username": "carol", "password": "wrong"})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "用户名或密码错误" in resp.text
    assert "set-cookie" not in {k.lower() for k in resp.headers}


def test_login_page_flow_and_idp_session_sso(base_url, client):
    """真实登录 → code → id_token claims → 会话免登录 → 登出 → 可换用户."""
    with httpx.Client(base_url=base_url, timeout=10, follow_redirects=False) as http:
        # 1) 首次访问 → 登录页
        first = http.get("/authorize", params=AUTH_PARAMS)
        assert first.status_code == 200

        # 2) 以 carol 登录 → 302 + IdP 会话 cookie
        login = http.post(
            "/authorize", data={**AUTH_PARAMS, "username": "carol", "password": "carol-password"}
        )
        assert login.status_code == 302
        set_cookie = login.headers.get("set-cookie", "")
        assert "mock_oidc_session=" in set_cookie
        assert "HttpOnly" in set_cookie
        code = httpx.URL(login.headers["location"]).params["code"]
        tokens = _exchange(client, code).json()
        id_claims = _decode(tokens["id_token"], _jwks(client))
        assert id_claims["preferred_username"] == "carol"
        assert id_claims["groups"] == ["users", "ops-admin"]
        assert id_claims["nonce"] == "nonce-sso"

        # 3) SSO: 同一浏览器再次 authorize → 免登录直接 302 发 code
        sso = http.get("/authorize", params=AUTH_PARAMS)
        assert sso.status_code == 302

        # 4) 登出 IdP → 会话清除, 重走 SSO 需要重新登录
        logout = http.get("/logout")
        assert logout.status_code == 200
        assert "mock_oidc_session=" in logout.headers.get("set-cookie", "")  # 过期清除
        again = http.get("/authorize", params=AUTH_PARAMS)
        assert again.status_code == 200  # 回到登录页

        # 5) 换用户 bob 登录成功
        switch = http.post(
            "/authorize", data={**AUTH_PARAMS, "username": "bob", "password": "bob-password"}
        )
        assert switch.status_code == 302
        code2 = httpx.URL(switch.headers["location"]).params["code"]
        tokens2 = _exchange(client, code2).json()
        id_claims2 = _decode(tokens2["id_token"], _jwks(client))
        assert id_claims2["preferred_username"] == "bob"
        assert id_claims2["groups"] == ["users", "admins"]


def test_logout_redirects_only_to_whitelisted_uri(client):
    """post_logout_redirect 仅在命中 redirect_uri 白名单时才 302."""
    ok = client.get("/logout", params={"post_logout_redirect": REDIRECT_URI})
    assert ok.status_code == 302 and ok.headers["location"] == REDIRECT_URI
    bad = client.get("/logout", params={"post_logout_redirect": "http://evil.example.com/"})
    assert bad.status_code == 200  # 不跳转, 渲染登出页


def test_logout_accepts_standard_post_logout_redirect_uri(client):
    """dbx/RP 发送 OIDC 标准参数名 post_logout_redirect_uri, 必须同样生效."""
    ok = client.get("/logout", params={"post_logout_redirect_uri": REDIRECT_URI})
    assert ok.status_code == 302 and ok.headers["location"] == REDIRECT_URI
    bad = client.get("/logout", params={"post_logout_redirect_uri": "http://evil.example.com/"})
    assert bad.status_code == 200  # 白名单外不跳转


def test_id_token_and_userinfo_carry_preferred_username_groups(client):
    tokens = _password_grant(client, "alice")
    id_claims = _decode(tokens["id_token"], _jwks(client))
    assert id_claims["preferred_username"] == "alice"
    assert id_claims["groups"] == ["users"]

    access_claims = _decode(tokens["access_token"], _jwks(client))
    assert access_claims["preferred_username"] == "alice"
    assert access_claims["groups"] == ["users"]

    userinfo = client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    ).json()
    assert userinfo["preferred_username"] == "alice"
    assert userinfo["groups"] == ["users"]


def test_pkce_enforced_when_challenge_present(client):
    """dbx 恒定使用 PKCE(S256): 带 challenge 的授权码必须回传匹配的 code_verifier."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    pkce_params = {**AUTH_PARAMS, "code_challenge": challenge, "code_challenge_method": "S256"}

    resp = client.get("/authorize", params={**pkce_params, "username": "alice"})
    code = httpx.URL(resp.headers["location"]).params["code"]
    ok = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=CLIENT_AUTH,
    )
    assert ok.status_code == 200

    resp2 = client.get("/authorize", params={**pkce_params, "username": "alice"})
    code2 = httpx.URL(resp2.headers["location"]).params["code"]
    bad = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code2,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "wrong-verifier",
        },
        auth=CLIENT_AUTH,
    )
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"

    resp3 = client.get("/authorize", params={**pkce_params, "username": "alice"})
    code3 = httpx.URL(resp3.headers["location"]).params["code"]
    missing = client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": code3, "redirect_uri": REDIRECT_URI},
        auth=CLIENT_AUTH,
    )
    assert missing.status_code == 400 and missing.json()["error"] == "invalid_grant"


# ------------------------------------------------------------------ 其它 grant


def test_password_grant_ropc(client):
    tokens = _password_grant(client, "alice")
    assert "id_token" in tokens
    userinfo = client.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert userinfo.status_code == 200
    assert userinfo.json()["sub"] == "alice"


def test_password_grant_wrong_password(client):
    resp = client.post(
        "/token",
        data={"grant_type": "password", "username": "alice", "password": "bad"},
        auth=CLIENT_AUTH,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_client_credentials_grant(client):
    resp = client.post("/token", data={"grant_type": "client_credentials", "scope": "api"}, auth=CLIENT_AUTH)
    assert resp.status_code == 200
    tokens = resp.json()
    assert "id_token" not in tokens  # 服务主体没有 id_token

    claims = _decode(tokens["access_token"], _jwks(client))
    assert claims["sub"] == "service:demo-client"

    userinfo = client.get("/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert userinfo.status_code == 200
    assert userinfo.json()["sub"] == "service:demo-client"


def test_refresh_token_grant_rotates(client):
    first = _password_grant(client, "bob")

    refreshed = client.post(
        "/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}, auth=CLIENT_AUTH
    )
    assert refreshed.status_code == 200
    body = refreshed.json()
    assert body["access_token"] != first["access_token"]
    assert body["refresh_token"] != first["refresh_token"]

    replay = client.post(
        "/token", data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}, auth=CLIENT_AUTH
    )
    assert replay.status_code == 400  # 旧 refresh_token 已轮换失效


# ------------------------------------------------------------------ 验签失败路径


def test_userinfo_rejects_missing_token(client):
    resp = client.get("/userinfo")
    assert resp.status_code == 401


def test_userinfo_rejects_tampered_token(client):
    tokens = _password_grant(client, "alice")
    resp = client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token'][:-3]}abc"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


def test_resource_server_reference_verification(client):
    """资源服务器参考实现: 正确验签 access_token."""
    tokens = _password_grant(client, "alice")
    claims = verify_access_token(tokens["access_token"], audience="demo-client")
    assert claims["sub"] == "alice"
    assert claims["email"] == "alice@example.org"


def test_resource_server_reference_rejects_wrong_audience(client):
    tokens = _password_grant(client, "alice")
    with pytest.raises(jwt.InvalidAudienceError):
        verify_access_token(tokens["access_token"], audience="other-app")


def test_resource_server_reference_rejects_expired_token():
    from mock_oidc_auth import _encode_jwt, _now

    expired = _encode_jwt(
        {
            "iss": mock_oidc_auth.ISSUER,
            "sub": "alice",
            "aud": "demo-client",
            "iat": _now() - 7200,
            "exp": _now() - 3600,
        }
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_access_token(expired, audience="demo-client")


def test_issuer_mismatch_is_rejected():
    """dbx 的 issuer 配置与 mock 签发的 iss 不一致时, id_token 必须被拒绝."""
    from mock_oidc_auth import _encode_jwt, _now

    forged = _encode_jwt(
        {
            "iss": "https://attacker.example",
            "sub": "alice",
            "aud": "demo-client",
            "preferred_username": "alice",
            "iat": _now(),
            "exp": _now() + 600,
        }
    )
    with pytest.raises(jwt.InvalidIssuerError):
        verify_access_token(forged, audience="demo-client")


# ------------------------------------------------------------------ 客户端白名单可配置


def test_load_clients_appends_env_redirect_uris(monkeypatch):
    monkeypatch.setenv("OIDC_MOCK_REDIRECT_URIS", "http://127.0.0.1:9001/cb, http://127.0.0.1:9002/cb")
    clients = mock_oidc_auth._load_clients()
    uris = clients["demo-client"]["redirect_uris"]
    assert "http://127.0.0.1:9001/cb" in uris and "http://127.0.0.1:9002/cb" in uris
    # 默认白名单仍有效
    assert "http://127.0.0.1:9000/callback" in uris
    assert "http://127.0.0.1:5173/api/auth/oidc/sso/callback" in uris
    assert "http://127.0.0.1:4224/api/auth/oidc/sso/callback" in uris


def test_load_clients_replaced_by_file(monkeypatch, tmp_path):
    clients_file = tmp_path / "clients.json"
    clients_file.write_text(
        json.dumps({"acme": {"client_secret": "acme-secret", "redirect_uris": ["http://acme/cb"]}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("OIDC_MOCK_CLIENTS_FILE", str(clients_file))
    clients = mock_oidc_auth._load_clients()
    assert set(clients) == {"acme"}
    assert clients["acme"]["redirect_uris"] == ["http://acme/cb"]


def test_authorize_accepts_env_added_redirect_uri(client, monkeypatch):
    """运行时扩展白名单(测试通过替换模块 CLIENTS 模拟 OIDC_MOCK_REDIRECT_URIS 生效)."""
    custom = {
        "demo-client": {
            "client_secret": "demo-secret",
            "redirect_uris": [REDIRECT_URI, "http://127.0.0.1:9001/cb"],
        }
    }
    monkeypatch.setattr(mock_oidc_auth, "CLIENTS", custom)
    resp = client.get(
        "/authorize",
        params={**AUTH_PARAMS, "redirect_uri": "http://127.0.0.1:9001/cb", "username": "alice"},
    )
    assert resp.status_code == 302
    denied = client.get(
        "/authorize",
        params={**AUTH_PARAMS, "redirect_uri": "http://not-registered/cb", "username": "alice"},
    )
    assert denied.status_code == 400
