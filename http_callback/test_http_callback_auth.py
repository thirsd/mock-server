"""mock_http_callback_auth.py 的端到端集成测试.

通过真实 HTTP(uvicorn) 同时启动“认证服务”和“被保护应用”, 覆盖:
- 登录换 token / 回调校验端点(有效/篡改/过期/垃圾 token)
- 被保护应用中间件: 放行 / 401 / 认证服务不可达 503
- token 签发与校验的单元路径
"""

import importlib
import json
import socket

import httpx
import pytest

import mock_http_callback_auth as mock_cb
from mock_http_callback_auth import (
    CallbackAuthClient,
    create_protected_app,
    issue_token,
    verify_token,
)


@pytest.fixture
def injected_users(monkeypatch):
    """用 MOCK_USERS_JSON 注入自定义用户集(重载 common.users, 结束后恢复默认)."""
    monkeypatch.setenv("MOCK_USERS_JSON", json.dumps({"erin": {"groups": ["ops-admin"]}}))
    import common.users as users_module

    importlib.reload(users_module)
    yield users_module
    monkeypatch.undo()
    importlib.reload(users_module)


def _dead_port() -> int:
    """取一个当前无人监听的端口(模拟认证服务不可达)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def auth_server(uvicorn_server_factory):
    return uvicorn_server_factory(mock_cb.auth_service_app)


@pytest.fixture(scope="module")
def auth_base_url(auth_server):
    return f"http://{auth_server.host}:{auth_server.port}"


@pytest.fixture(scope="module")
def auth_client(auth_base_url) -> CallbackAuthClient:
    return CallbackAuthClient(auth_base_url)


@pytest.fixture(scope="module")
def protected_server(uvicorn_server_factory, auth_base_url):
    """被保护应用, 回调校验地址指向 mock 认证服务."""
    return uvicorn_server_factory(create_protected_app(f"{auth_base_url}/auth/verify"))


@pytest.fixture(scope="module")
def http(protected_server):
    with httpx.Client(base_url=f"http://{protected_server.host}:{protected_server.port}", timeout=10) as http_client:
        yield http_client


# ------------------------------------------------------------------ 单元路径


def test_verify_token_valid_payload():
    payload = verify_token(issue_token("alice"))
    assert payload["sub"] == "alice"
    assert payload["email"] == "alice@example.org"
    assert payload["exp"] > payload["iat"]


def test_verify_token_rejects_tampered_signature():
    tampered = issue_token("alice")[:-4] + "beef"
    with pytest.raises(mock_cb.InvalidTokenError):
        verify_token(tampered)


def test_verify_token_rejects_expired():
    with pytest.raises(mock_cb.ExpiredTokenError):
        verify_token(issue_token("bob", ttl=-10))


def test_verify_token_rejects_garbage():
    with pytest.raises(mock_cb.InvalidTokenError):
        verify_token("not-a-token")


# ------------------------------------------------------------------ 认证服务端点


def test_health(auth_base_url):
    resp = httpx.get(f"{auth_base_url}/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_returns_token_and_user(auth_client):
    result = auth_client.login("alice", "alice-password")
    assert result["token"]
    assert result["token_type"] == "Bearer"
    assert result["user"]["email"] == "alice@example.org"


def test_login_wrong_password_returns_401(auth_client):
    with pytest.raises(httpx.HTTPStatusError) as exc:
        auth_client.login("alice", "wrong-password")
    assert exc.value.response.status_code == 401
    assert exc.value.response.json()["error"] == "invalid_credentials"


def test_verify_valid_token_roundtrip(auth_client):
    token = auth_client.login("bob", "bob-password")["token"]
    result = auth_client.verify(token)
    assert result.active is True
    assert result.user["username"] == "bob"
    assert result.user["groups"] == ["users", "admins"]
    assert result.error is None


def test_verify_invalid_token(auth_client):
    result = auth_client.verify("not-a-token")
    assert result.active is False
    assert result.error == "invalid_token"


def test_verify_expired_token(auth_client):
    result = auth_client.verify(issue_token("alice", ttl=-10))
    assert result.active is False
    assert result.error == "expired_token"


def test_verify_tampered_token(auth_client):
    result = auth_client.verify(issue_token("alice")[:-4] + "beef")
    assert result.active is False
    assert result.error == "invalid_token"


# ------------------------------------------------------------------ 被保护应用


def test_public_path_is_open(http):
    resp = http.get("/public/ping")
    assert resp.status_code == 200
    assert resp.json() == {"pong": True}


def test_me_requires_token(http):
    resp = http.get("/me")
    assert resp.status_code == 401


def test_me_with_valid_token(http, auth_client):
    token = auth_client.login("bob", "bob-password")["token"]
    resp = http.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()["user"]
    assert body["username"] == "bob"
    assert body["email"] == "bob@example.org"


def test_me_with_invalid_token(http):
    resp = http.get("/me", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


def test_me_with_expired_token(http):
    resp = http.get("/me", headers={"Authorization": f"Bearer {issue_token('alice', ttl=-10)}"})
    assert resp.status_code == 401


def test_me_when_auth_service_unreachable(uvicorn_server_factory):
    """回调地址无人监听时, 被保护应用应返回 503 而不是放行."""
    srv = uvicorn_server_factory(create_protected_app(f"http://127.0.0.1:{_dead_port()}/auth/verify"))
    with httpx.Client(base_url=f"http://{srv.host}:{srv.port}", timeout=10) as http_client:
        resp = http_client.get("/me", headers={"Authorization": f"Bearer {issue_token('alice')}"})
    assert resp.status_code == 503


# ================================================================== dbx 原生契约 /auth/callback


def test_auth_callback_contract_all_users(auth_base_url):
    """dbx HttpCallbackProvider 原生契约: 顶层字段零映射, subject 稳定编号."""
    expected = {
        "alice": {"subject": "u-1001", "groups": ["users"], "email": "alice@example.org", "display_name": "Alice Anderson"},
        "bob": {"subject": "u-1002", "groups": ["users", "admins"], "email": "bob@example.org", "display_name": "Bob Brown"},
        "carol": {"subject": "u-1003", "groups": ["users", "ops-admin"], "email": "carol@example.org", "display_name": "Carol Chen"},
        "dave": {"subject": "u-1004", "groups": [], "email": "dave@example.org", "display_name": "Dave Dai"},
    }
    for username, want in expected.items():
        resp = httpx.post(
            f"{auth_base_url}/auth/callback",
            json={"username": username, "password": f"{username}-password"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["subject"] == want["subject"]
        assert body["username"] == username
        assert body["display_name"] == want["display_name"]
        assert body["email"] == want["email"]
        assert body["groups"] == want["groups"]


def test_auth_callback_wrong_password_401(auth_base_url):
    resp = httpx.post(f"{auth_base_url}/auth/callback", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


def test_auth_callback_unknown_user_401(auth_base_url):
    resp = httpx.post(f"{auth_base_url}/auth/callback", json={"username": "ghost", "password": "whatever"})
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_credentials"


def test_auth_callback_ping_connectivity_probe(auth_base_url):
    """dbx 管理端 test() 发送 {"ping": true}, 不应按凭据错误处理."""
    resp = httpx.post(f"{auth_base_url}/auth/callback", json={"ping": True})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_auth_callback_subject_is_stable(auth_base_url):
    """同一用户反复登录 subject 不变 → dbx 账号归并(换组重登刷新角色、不重复建号)."""
    payloads = [
        httpx.post(f"{auth_base_url}/auth/callback", json={"username": "bob", "password": "bob-password"}).json()
        for _ in range(2)
    ]
    assert payloads[0]["subject"] == payloads[1]["subject"] == "u-1002"


def test_auth_callback_requires_secret_when_enabled(auth_base_url, monkeypatch):
    """MOCK_CB_REQUIRE_SECRET=1 时校验 X-DBX-Auth-Secret(dbx 配置 shared_secret 后自动携带)."""
    monkeypatch.setenv("MOCK_CB_REQUIRE_SECRET", "1")

    missing = httpx.post(f"{auth_base_url}/auth/callback", json={"username": "alice", "password": "alice-password"})
    assert missing.status_code == 403
    assert missing.json()["error"] == "invalid_secret"

    wrong = httpx.post(
        f"{auth_base_url}/auth/callback",
        json={"username": "alice", "password": "alice-password"},
        headers={"X-DBX-Auth-Secret": "not-the-secret"},
    )
    assert wrong.status_code == 403
    assert wrong.json()["error"] == "invalid_secret"

    ok = httpx.post(
        f"{auth_base_url}/auth/callback",
        json={"username": "alice", "password": "alice-password"},
        headers={"X-DBX-Auth-Secret": mock_cb.shared_secret()},
    )
    assert ok.status_code == 200
    assert ok.json()["username"] == "alice"


def test_login_token_ttl_is_configurable(auth_base_url, monkeypatch):
    monkeypatch.setenv("MOCK_CB_TOKEN_TTL", "60")
    result = CallbackAuthClient(auth_base_url).login("alice", "alice-password")
    assert result["expires_in"] == 60


def test_injected_user_can_login_via_auth_callback(auth_base_url, injected_users):
    """MOCK_USERS_JSON 注入的用户直接可登录(验收 1.1); 缺省字段按约定补齐."""
    resp = httpx.post(
        f"{auth_base_url}/auth/callback", json={"username": "erin", "password": "erin-password"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["subject"] == "u-1001"  # 注入后的用户集中 erin 是第 1 个
    assert body["username"] == "erin"
    assert body["display_name"] == "erin"
    assert body["email"] == "erin@example.org"
    assert body["groups"] == ["ops-admin"]
