# Mock 集成认证示例集(LDAP / OIDC / HTTP Callback / Proxy Header)

面向 **dbx 第三方统一认证** 的 4 个相互独立的集成认证 mock 示例: 多用户身份区分、
组 → 角色(role_map)映射、正负向用例全部可联调, 无需改动 mock 源码。

| 目录 | 认证方式 | dbx provider kind | mock 文件 | 测试文件 |
| --- | --- | --- | --- | --- |
| `ldap/` | LDAP 简单绑定 + memberOf 组 | `ldap`(表单模式) | `mock_ldap_auth.py` | `test_ldap_auth.py` |
| `oidc/` | OIDC 授权码 + 登录页 + SSO 会话 | `oidc`(跳转模式) | `mock_oidc_auth.py` | `test_oidc_auth.py` |
| `http_callback/` | HTTP 回调认证 | `http_callback`(表单模式) | `mock_http_callback_auth.py` | `test_http_callback_auth.py` |
| `proxy_header/` | 反向代理头注入 | `proxy_header`(代理模式) | `mock_proxy_header_auth.py` + `mock_proxy_gateway.py` | `test_proxy_header_auth.py` + `test_proxy_gateway.py` |

各目录 README 均有「对接 DBX」章节: 可直接复制的 `DBX_AUTH_CONFIG` JSON 与
多用户 × 期望角色验证矩阵。

```
├── common/                  共享模块
│   ├── users.py             统一用户数据(MOCK_USERS_JSON / MOCK_USERS_FILE 可注入)
│   └── sessions.py          HMAC 签名会话 cookie(OIDC IdP 会话 / 网关会话共用)
├── ldap/                    LDAP 内存目录树(真实协议, 组 + memberOf)
├── oidc/                    OIDC Provider(登录页 / 会话 / PKCE / logout)
├── http_callback/           认证服务(/auth/callback 契约 + /auth/login、/auth/verify)
├── proxy_header/
│   ├── mock_proxy_header_auth.py   “被保护应用”教学示例(X-Remote-* 头)
│   ├── mock_proxy_gateway.py       给 dbx 联调用的迷你认证网关(:8114 → 注入 X-Forwarded-* 头)
│   ├── test_proxy_header_auth.py
│   └── test_proxy_gateway.py
├── pyproject.toml           uv 项目定义 + pytest 配置
└── conftest.py              公共夹具(线程内启动真实 uvicorn 服务)
```

## 用户集(dbx role_map 验证矩阵)

统一账号源 `common/users.py`, 密码约定 `<username>-password`。
CI / 定制场景可用 `MOCK_USERS_JSON`(内联 JSON)或 `MOCK_USERS_FILE`(文件路径)
注入任意用户集, 未设置时用内置默认。

| 用户 | 密码 | groups | dbx 期望角色(role_map = `{"admins":"admin","ops-admin":"admin","*":"member"}`) |
| --- | --- | --- | --- |
| alice | alice-password | users | member |
| bob | bob-password | users, admins | admin |
| carol | carol-password | users, ops-admin | admin |
| dave | dave-password | (无) | member(`*` 兜底) |

## 快速开始

```bash
uv sync          # 创建 .venv 并安装依赖(首次)
uv run pytest    # 全量集成测试(86 个用例)

# 单独运行 mock 服务(默认端口)
uv run python ldap/mock_ldap_auth.py                     # ldap://127.0.0.1:13890
uv run python oidc/mock_oidc_auth.py                     # http://127.0.0.1:8111
uv run python http_callback/mock_http_callback_auth.py   # http://127.0.0.1:8112
uv run python proxy_header/mock_proxy_header_auth.py     # http://127.0.0.1:8113(被保护应用示例)
uv run python proxy_header/mock_proxy_gateway.py         # http://127.0.0.1:8114(→ 注入身份头到 dbx)
```

测试中服务监听随机空闲端口, 与默认端口不冲突。

## 统一启停脚本(`mocks.sh`)

```bash
bash mocks.sh start     [服务名...]   # 启动(缺省全部; 已在运行则跳过)
bash mocks.sh stop      [服务名...]   # 停止(缺省全部)
bash mocks.sh restart   [服务名...]   # 批量重启全部/指定服务(先停后起)
bash mocks.sh status    [服务名...]   # 查看运行状态
bash mocks.sh logs      <服务名> [行数]  # 查看服务日志(默认 40 行)
```

- 服务名: `ldap` / `oidc` / `http_callback` / `proxy_header` / `gateway`; 日志写入 `logs/<服务名>.log`。
- Windows 下按端口定位进程(`netstat -ano` + `taskkill //F`)跨会话可靠; 仅终止 python 进程,
  端口被其他程序占用时只提示不强杀。
- 由**管理员权限终端**启动的进程无法在普通终端停止(拒绝访问), 脚本会明确提示 —— 请在
  对应权限的终端执行 stop 或手动 `taskkill /F /PID <pid>`。
- 环境变量按调用方继承, 例如: `MOCK_CB_REQUIRE_SECRET=1 bash mocks.sh restart http_callback`。

## 环境变量总览

| 变量 | 作用 | 默认 |
| --- | --- | --- |
| `MOCK_USERS_JSON` / `MOCK_USERS_FILE` | 注入自定义用户集(见 common/users.py) | 内置 4 用户 |
| `OIDC_MOCK_ISSUER` | OIDC issuer | `http://127.0.0.1:8111` |
| `OIDC_MOCK_REDIRECT_URIS` | 逗号分隔, 追加 OIDC redirect_uri 白名单 | (追加 dbx 回调已在默认白名单) |
| `OIDC_MOCK_CLIENTS_FILE` | JSON 文件, 整体替换 OIDC 客户端注册表 | - |
| `GROUP_VALUE_STYLE` | LDAP memberOf 形态 `dn`(默认)/`short` | `dn` |
| `MOCK_CB_REQUIRE_SECRET` | 开启 `/auth/callback` 的 X-DBX-Auth-Secret 校验 | 关闭 |
| `MOCK_CB_SHARED_SECRET` | 期望的共享密钥值 | `dbx-mock-callback-secret` |
| `MOCK_CB_TOKEN_TTL` | /auth/login token 有效期秒数 | `300` |
| `PROXY_UPSTREAM` | 网关上游(dbx)地址 | `http://127.0.0.1:4224` |
| `GW_USER_HEADER` 等 | 网关注入头名(与 dbx 头配置对应) | `X-Forwarded-*` |

## 生产化提示(通用)

- mock 的密钥/账号/令牌/会话全部是进程内存态, 重启即失效; 仅供联调与集成测试。
- 生产环境: LDAP 用 TLS、OIDC 严格校验 iss/aud/exp 且只允许 RS256(本 mock 的
  `verify_access_token()` 即资源方参考实现)、回调配置重试与超时、代理头模式做网络隔离;
  均不要把完整 token 打进日志。
