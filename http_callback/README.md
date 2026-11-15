# Mock HTTP 回调认证服务

把「用户是否合法」委托给外部认证服务(HTTP callback / token introspection)的集成模式。
本 mock 提供两套契约:

| 端点 | 契约 | 用途 |
| --- | --- | --- |
| `POST /auth/callback` | **dbx HttpCallbackProvider 原生契约**(顶层字段零映射) | dbx 表单登录直连 |
| `POST /auth/login` | 登录换 HMAC token(联调用) | 初版保留 |
| `POST /auth/verify` | token introspection: `{"token"}` → `{"active", "user"}` | 初版保留 |
| `GET /health` | 健康检查 | - |

- 默认监听: `http://127.0.0.1:8112`
- 运行: `uv run python mock_http_callback_auth.py --host 127.0.0.1 --port 8112`
- 测试: `uv run pytest test_http_callback_auth.py -v`

`/auth/callback` 契约:

```text
请求: {"username": "bob", "password": "bob-password"}
可选头: X-DBX-Auth-Secret: <shared_secret>(MOCK_CB_REQUIRE_SECRET=1 时校验)

成功 200: {"subject": "u-1002", "username": "bob", "display_name": "Bob Brown",
          "email": "bob@example.org", "groups": ["users", "admins"]}
凭据错 401: {"error": "invalid_credentials", ...}
密钥错 403: {"error": "invalid_secret", ...}(仅启用校验时)
连通性探测: {"ping": true} → 200 {"status": "ok"}(dbx 管理端 test())
```

`subject` 为稳定 ID(u-1001 起按用户集顺序编号; 用户数据可用 `"subject"` 显式覆盖):
同一用户反复登录 subject 不变, 用于验证 dbx 的账号归并(换组重登刷新角色、不重复建号)。

## 对接 DBX

`DBX_AUTH_CONFIG`(可直接复制, 零字段路径映射):

```json
[
  {
    "id": "http_callback",
    "kind": "http_callback",
    "label": "Mock HTTP Callback",
    "enabled": true,
    "config": {
      "url": "http://127.0.0.1:8112/auth/callback",
      "role_map": {
        "admins": "admin",
        "ops-admin": "admin",
        "*": "member"
      },
      "default_role": "member",
      "timeout_secs": 5
    }
  }
]
```

> 开启共享密钥校验时(mock 以 `MOCK_CB_REQUIRE_SECRET=1` 启动), config 增加:
> `"shared_secret": "dbx-mock-callback-secret"`(值由 `MOCK_CB_SHARED_SECRET` 决定),
> dbx 会在请求头自动携带 `X-DBX-Auth-Secret`。

### 多用户 × 期望角色验证矩阵

| 登录用户 | 返回 groups | 期望角色 |
| --- | --- | --- |
| alice | users | member |
| bob | users, admins | admin |
| carol | users, ops-admin | admin |
| dave | (无) | member(`*` 兜底) |

### 负向用例

| 用例 | 操作 | 期望 |
| --- | --- | --- |
| 密码错误 | alice + 错误密码 | mock 401 → dbx 报 invalid credentials |
| 用户不存在 | ghost | mock 401 → dbx 报 invalid credentials |
| 服务停止 | mock 进程停止 | dbx 报 502 provider unavailable |
| 密钥缺失 | MOCK_CB_REQUIRE_SECRET=1 且 dbx 未配 shared_secret | mock 403 → dbx 报凭据错误 |
| 密钥错误 | dbx shared_secret 配错值 | mock 403 → dbx 报凭据错误 |
| 账号归并 | 同一用户反复登录 | subject 恒为 u-100x, 不重复建号 |

### 环境变量

- `MOCK_CB_REQUIRE_SECRET=1`: 开启 X-DBX-Auth-Secret 校验(默认关闭, 兼容现状)
- `MOCK_CB_SHARED_SECRET`: 期望密钥值(默认 `dbx-mock-callback-secret`)
- `MOCK_CB_TOKEN_TTL`: /auth/login token 有效期秒数(默认 300)
- `MOCK_USERS_JSON` / `MOCK_USERS_FILE`: 注入自定义用户集
