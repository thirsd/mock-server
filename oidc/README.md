# Mock OIDC Provider(登录页 + IdP 会话 + PKCE)

实现 OpenID Connect 1.0 核心端点, 支撑 dbx「跳转模式」的多用户 × 多角色完整验收:

- `GET  /.well-known/openid-configuration`(含 `end_session_endpoint`)
- `GET  /.well-known/jwks.json`(RS256 公钥, kid=mock-oidc-rs256-key)
- `GET  /authorize` — 无 IdP 会话时返回真实 HTML 登录页(用户名+密码表单);
  支持并校验 PKCE(S256)
- `POST /authorize` — 登录表单提交; 错误密码 200 重渲染; 成功 → 302 回 redirect_uri
  带 code, 并种 HttpOnly IdP 会话 cookie(`mock_oidc_session`)
- `POST /token` — authorization_code(+PKCE 校验)/ password / client_credentials /
  refresh_token; 支持 client_secret_basic 与 client_secret_post
- `GET  /userinfo` — 返回 sub / preferred_username / name / email / groups
- `GET  /logout` — 清除 IdP 会话; 回跳参数接受 OIDC 标准名 `post_logout_redirect_uri`(dbx 发送)与别名 `post_logout_redirect`, 仅白名单内才跳转

SSO 语义: 登录成功后同一浏览器再次 `GET /authorize` **免登录直接发 code**;
`/logout` 后重走 SSO 需重新登录 —— 支撑 dbx「登出后再登入换用户」验证。

id_token / access_token / userinfo 三处均带 `preferred_username` 与 `groups`,
dbx 默认用户名回退链(preferred_username → email → sub)与 `groups_claim: "groups"`
直接可用, 无需任何字段映射。

- 默认监听: `http://127.0.0.1:8111`(issuer 可用 `OIDC_MOCK_ISSUER` 覆盖)
- 运行: `uv run python mock_oidc_auth.py --host 127.0.0.1 --port 8111`
- 测试: `uv run pytest test_oidc_auth.py -v`

## 对接 DBX

`DBX_AUTH_CONFIG`(可直接复制; redirect_uri 由 dbx 按 provider id 自动推导):

```json
[
  {
    "id": "sso",
    "kind": "oidc",
    "label": "Mock SSO",
    "enabled": true,
    "config": {
      "issuer": "http://127.0.0.1:8111",
      "client_id": "demo-client",
      "client_secret": "demo-secret",
      "groups_claim": "groups",
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

> `username_claim` 可省略(默认链 preferred_username → email → sub)。
> redirect_uri = `/api/auth/oidc/{id}/callback`: id=sso 时对应
> `http://127.0.0.1:5173/api/auth/oidc/sso/callback`(vite 代理)、
> `http://127.0.0.1:4224/api/auth/oidc/sso/callback`(直连后端)及
> 两者 `localhost` 变体(vite changeOrigin 会把 Host 改写为 vite target,
> `DBX_PUBLIC_URL` 写 localhost 时推导出的回调即 localhost 形态),
> 均已在默认白名单。
> **自定义 provider id 时必须把对应回调地址加入白名单**
> (`OIDC_MOCK_REDIRECT_URIS=...` 追加, 或 `OIDC_MOCK_CLIENTS_FILE` 整体替换)。

### 多用户 × 期望角色验证矩阵

| SSO 登录用户 | groups claim | 期望角色 |
| --- | --- | --- |
| alice | users | member |
| bob | users, admins | admin |
| carol | users, ops-admin | admin |
| dave | (无) | member(`*` 兜底) |

### 负向用例

| 用例 | 操作 | 期望 |
| --- | --- | --- |
| 登录页密码错误 | 登录页输错密码 | 200 重渲染 + 错误提示, 不发 code |
| 未注册 redirect_uri | dbx 回调地址未加白名单 | mock 返回 invalid_request |
| issuer 不一致 | dbx 的 issuer 配错 | dbx 拒绝 id_token(iss 校验, pytest 已覆盖) |
| 客户端密钥错误 | client_secret 不对 | dbx 报 token exchange 失败(401 invalid_client) |
| PKCE 篡改 | code_verifier 不匹配 | mock 返回 invalid_grant |
| 授权码重放 | 同一 code 换两次 token | 第二次 invalid_grant |
| 登出换用户 | dbx 登出 → 重走 SSO | 出登录页, 可用另一账号登录 |

### 环境变量

- `OIDC_MOCK_ISSUER`: issuer 覆盖
- `OIDC_MOCK_REDIRECT_URIS`: 逗号分隔追加白名单
- `OIDC_MOCK_CLIENTS_FILE`: JSON 文件整体替换 CLIENTS
- `MOCK_USERS_JSON` / `MOCK_USERS_FILE`: 注入自定义用户集
