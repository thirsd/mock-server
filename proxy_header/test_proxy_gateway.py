"""mock_proxy_gateway.py 的端到端集成测试.

用本地 echo 上游(记录收到的头/路径/请求体)验证网关行为, 覆盖:
- 未认证请求 → 登录页; 登录成功种会话
- 身份头注入(X-Forwarded-User/Email/Display-Name/Groups, 组逗号拼接)
- 入站伪造身份头剥离(防外部伪造)
- 登出后会话失效 → 不再注入身份头
- method/path/query/body 透传
- 头名可通过工厂参数/环境变量覆盖
"""

import httpx
import pytest
from fastapi import FastAPI, Request

import mock_proxy_gateway
from mock_proxy_gateway import create_gateway_app


def _make_echo_app() -> FastAPI:
    """echo 上游: 原样回显网关注入后的身份头与请求要素."""
    app = FastAPI(docs_url=None, redoc_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def echo(request: Request, path: str):
        return {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "body": (await request.body()).decode("utf-8", "replace"),
            "user": request.headers.get("x-forwarded-user"),
            "email": request.headers.get("x-forwarded-email"),
            "display_name": request.headers.get("x-forwarded-display-name"),
            "groups": request.headers.get("x-forwarded-groups"),
            "all_headers": {name.decode("latin-1").lower(): value.decode("latin-1") for name, value in request.headers.raw},
        }

    return app


@pytest.fixture(scope="module")
def echo_server(uvicorn_server_factory):
    return uvicorn_server_factory(_make_echo_app())


@pytest.fixture(scope="module")
def gateway_server(uvicorn_server_factory, echo_server):
    app = create_gateway_app(upstream=f"http://{echo_server.host}:{echo_server.port}")
    return uvicorn_server_factory(app)


def _login(http: httpx.Client, username: str, password: str, next_path: str = "/echo") -> httpx.Response:
    return http.post(
        "/__gw/login",
        data={"username": username, "password": password, "next": next_path},
        follow_redirects=False,
    )


def test_unauthenticated_request_gets_login_page(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        resp = http.get("/some/app/path?x=1")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert '<form method="post" action="/__gw/login">' in resp.text
    assert 'name="next" value="/some/app/path?x=1"' in resp.text  # 登录后跳回原路径


def test_login_sets_session_and_redirects_to_next(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        resp = _login(http, "alice", "alice-password")
    assert resp.status_code == 302
    assert resp.headers["location"] == "/echo"
    assert "mock_gw_session=" in resp.headers.get("set-cookie", "")
    assert "HttpOnly" in resp.headers.get("set-cookie", "")


def test_login_wrong_password_rerenders(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        resp = _login(http, "alice", "wrong")
    assert resp.status_code == 200
    assert "用户名或密码错误" in resp.text


def test_identity_headers_injected_for_alice(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        echo = http.get("/echo").json()
    assert echo["user"] == "alice"
    assert echo["email"] == "alice@example.org"
    assert echo["display_name"] == "Alice Anderson"
    assert echo["groups"] == "users"


def test_identity_headers_injected_for_bob(gateway_server):
    """bob 属于 users+admins 组 → 组头逗号拼接(dbx role_map 可映射出 admin)."""
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "bob", "bob-password")
        echo = http.get("/echo").json()
    assert echo["user"] == "bob"
    assert echo["groups"] == "users,admins"


def test_spoofed_identity_headers_are_stripped(gateway_server):
    """带会话的请求伪造 X-Forwarded-User/Groups → 入站头被剥离, 以会话用户为准."""
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        echo = http.get(
            "/echo",
            headers={"X-Forwarded-User": "mallory", "X-Forwarded-Groups": "admins"},
        ).json()
    assert echo["user"] == "alice"  # 伪造值被剥离
    assert echo["groups"] == "users"
    assert echo["email"] == "alice@example.org"


def test_gateway_session_cookie_is_not_forwarded(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        echo = http.get("/echo").json()
    assert "mock_gw_session" not in echo["all_headers"].get("cookie", "")


def test_logout_invalidates_session(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        logout = http.get("/logout", follow_redirects=False)
        assert logout.status_code == 302
        assert "mock_gw_session=" in logout.headers.get("set-cookie", "")  # 过期清除

        resp = http.get("/echo")
        assert resp.status_code == 200  # 回到登录页(无身份头可用)
        assert '<form method="post" action="/__gw/login">' in resp.text


def test_method_query_and_body_passthrough(gateway_server):
    with httpx.Client(base_url=f"http://{gateway_server.host}:{gateway_server.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        echo = http.post("/echo/api/items?marker=1", content=b'{"k": "v"}').json()
    assert echo["method"] == "POST"
    assert echo["path"] == "/echo/api/items"
    assert echo["query"] == "marker=1"
    assert echo["body"] == '{"k": "v"}'


def test_custom_header_names_via_factory(echo_server, uvicorn_server_factory):
    """工厂参数覆盖头名(GW_USER_HEADER 等环境变量同效, 工厂参数优先)."""
    gateway = uvicorn_server_factory(
        create_gateway_app(
            upstream=f"http://{echo_server.host}:{echo_server.port}",
            user_header="X-Mock-User",
            groups_header="X-Mock-Groups",
        )
    )
    with httpx.Client(base_url=f"http://{gateway.host}:{gateway.port}", timeout=10) as http:
        _login(http, "bob", "bob-password")
        echo = http.get("/echo").json()
    assert echo["all_headers"]["x-mock-user"] == "bob"
    assert echo["all_headers"]["x-mock-groups"] == "users,admins"
    assert "x-forwarded-user" not in echo["all_headers"]


def test_upstream_unreachable_returns_502(uvicorn_server_factory, monkeypatch):
    monkeypatch.setenv("PROXY_UPSTREAM", "http://127.0.0.1:9")  # 不可达端口
    gateway = uvicorn_server_factory(create_gateway_app())
    with httpx.Client(base_url=f"http://{gateway.host}:{gateway.port}", timeout=10) as http:
        _login(http, "alice", "alice-password")
        resp = http.get("/echo")
    assert resp.status_code == 502
    assert "不可达" in resp.json()["detail"]
