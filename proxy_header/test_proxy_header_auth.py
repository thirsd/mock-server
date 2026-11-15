"""mock_proxy_header_auth.py 的端到端集成测试.

通过真实 HTTP(uvicorn) 访问被保护应用, 覆盖:
- 代理头注入正确身份 -> 200 + 身份解析
- 缺失/错误的共享密钥 -> 403(疑似绕过代理)
- 缺少 X-Remote-User -> 401
- /admin 的用户组门控
- 集成方参考客户端 ProxyHeaderAuthClient
"""

import httpx
import pytest

import mock_proxy_header_auth
from mock_proxy_header_auth import PROXY_SECRET, ProxyHeaderAuthClient, ProxyHeaderAuthConfig

VALID_HEADERS = {
    "X-Proxy-Auth-Secret": PROXY_SECRET,
    "X-Remote-User": "alice",
    "X-Remote-Email": "alice@example.org",
    "X-Remote-Groups": "users,admins",
}


@pytest.fixture(scope="module")
def server(uvicorn_server_factory):
    return uvicorn_server_factory(mock_proxy_header_auth.app)


@pytest.fixture(scope="module")
def base_url(server):
    return f"http://{server.host}:{server.port}"


@pytest.fixture(scope="module")
def client(base_url):
    with httpx.Client(base_url=base_url, timeout=10) as http:
        yield http


# ------------------------------------------------------------------ 端点行为


def test_health_endpoint_needs_no_auth(client):
    resp = client.get("/public/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_me_with_valid_proxy_headers(client):
    resp = client.get("/me", headers={**VALID_HEADERS, "X-Forwarded-For": "10.0.0.8"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.org"
    assert body["groups"] == ["users", "admins"]
    assert body["client_ip"] == "10.0.0.8"


def test_me_without_any_headers_is_forbidden(client):
    """无任何头 = 请求未经过受信任代理, 应拒绝(403)."""
    assert client.get("/me").status_code == 403


def test_missing_proxy_secret_is_forbidden(client):
    headers = {"X-Remote-User": "alice"}
    assert client.get("/me", headers=headers).status_code == 403


def test_wrong_proxy_secret_is_forbidden(client):
    headers = {"X-Proxy-Auth-Secret": "wrong-secret", "X-Remote-User": "alice"}
    assert client.get("/me", headers=headers).status_code == 403


def test_missing_remote_user_is_unauthorized(client):
    """密钥正确但代理未提供登录名 -> 401."""
    headers = {"X-Proxy-Auth-Secret": PROXY_SECRET}
    assert client.get("/me", headers=headers).status_code == 401


def test_admin_requires_admins_group(client):
    user_only = {**VALID_HEADERS, "X-Remote-Groups": "users"}
    assert client.get("/admin", headers=user_only).status_code == 403
    assert client.get("/admin", headers=VALID_HEADERS).status_code == 200
    assert "alice" in client.get("/admin", headers=VALID_HEADERS).json()["message"]


# ------------------------------------------------------------------ 参考客户端


def test_reference_client_roundtrip(base_url):
    config = ProxyHeaderAuthConfig(
        base_url=base_url,
        user="bob",
        email="bob@example.org",
        groups=["users", "admins"],
    )
    with ProxyHeaderAuthClient(config) as api:
        me = api.me()
        assert me["username"] == "bob"
        assert me["groups"] == ["users", "admins"]
        assert "bob" in api.admin_panel()["message"]
        assert api.health()["status"] == "ok"


def test_reference_client_denied_without_admin_group(base_url):
    config = ProxyHeaderAuthConfig(base_url=base_url, user="bob", groups=["users"])
    with ProxyHeaderAuthClient(config) as api:
        with pytest.raises(httpx.HTTPStatusError) as exc:
            api.admin_panel()
    assert exc.value.response.status_code == 403
