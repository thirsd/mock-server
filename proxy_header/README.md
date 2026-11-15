# Mock Proxy Header 认证

本目录包含两个独立组件:

| 文件 | 角色 | 端口 |
| --- | --- | --- |
| `mock_proxy_header_auth.py` | “被保护应用”教学示例: 应用侧解析 `X-Remote-*` 头(共享密钥防伪造) | 8113 |
| `mock_proxy_gateway.py` | **给 dbx 联调用的迷你认证网关**: 登录会话 + 剥离伪造头 + 注入 `X-Forwarded-*` 头 + 反向代理 | 8114 |

dbx 的 `proxy_header` provider 是**验证方**(固定读取 `X-Forwarded-*` 四个头并校验
客户端 IP 在 `trusted_proxies` 内), 因此浏览器级多用户验证用网关:

```
浏览器 → 网关(:8114, 未登录先出登录页) → 注入 X-Forwarded-{User,Email,Display-Name,Groups} → dbx(:4224)
```

- 网关登录页账号来自共享用户集; 登录成功种 HttpOnly 会话(`mock_gw_session`)
- 转发前剥离入站同名身份头(防外部伪造), 再注入会话用户的身份(组逗号拼接)
- `GET /logout` 清除网关会话 → 后续请求不再注入身份头 → dbx 返回 401
  (dbx 侧另有 5 分钟登出宽限期, 期间同用户不被代理 SSO 自动重登; 换用户登录不受影响)
- 已知限制: 不支持 WebSocket; HTTP/SSE 流式响应支持

运行:
```bash
uv run python mock_proxy_header_auth.py --port 8113   # 被保护应用示例
uv run python mock_proxy_gateway.py --port 8114 --upstream http://127.0.0.1:4224
```

测试:
```bash
uv run pytest test_proxy_header_auth.py test_proxy_gateway.py -v
```

## 对接 DBX

`DBX_AUTH_CONFIG`(可直接复制; dbx 信任来自 127.0.0.0/8 的网关注入):

```json
[
  {
    "id": "proxy",
    "kind": "proxy_header",
    "label": "Mock Gateway",
    "enabled": true,
    "config": {
      "user_header": "X-Forwarded-User",
      "email_header": "X-Forwarded-Email",
      "display_name_header": "X-Forwarded-Display-Name",
      "groups_header": "X-Forwarded-Groups",
      "trusted_proxies": ["127.0.0.0/8", "::1/128"],
      "role_map": {
        "admins": "admin",
        "ops-admin": "admin",
        "*": "member"
      },
      "default_role": "member"
    }
  }
]
```

### 多用户 × 期望角色验证矩阵

| 网关登录用户 | 注入 X-Forwarded-Groups | 期望角色 |
| --- | --- | --- |
| alice | users | member |
| bob | users,admins | admin |
| carol | users,ops-admin | admin |
| dave | (空) | member(`*` 兜底) |

### 负向用例

| 用例 | 操作 | 期望 |
| --- | --- | --- |
| 未登录访问 | 直接打开 dbx 地址 | dbx 401(无身份头) → 网关登录页 |
| 登出 | GET 网关 /logout | 会话清除, 再访问 dbx API 返回 401 |
| 伪造身份头 | curl 直接带 X-Forwarded-User: mallory 访问网关 | 头被剥离, 注入值与会话用户一致 |
| 伪造 + 无会话 | 直接伪造头访问 | 网关返回登录页, 请求不会到达 dbx |
| 不可信来源 | 不经网关、从非 trusted_proxies IP 直连 dbx | dbx 视为匿名(dbx-web 中间件还会剥离这些头) |
| 网关停止 | mock 网关进程停止 | 浏览器无法访问(代理不可达), 不产生登录 |

### 环境变量

- `PROXY_UPSTREAM`: 网关上游(dbx)地址, 默认 `http://127.0.0.1:4224`
- `GW_USER_HEADER` / `GW_EMAIL_HEADER` / `GW_DISPLAY_NAME_HEADER` / `GW_GROUPS_HEADER`:
  注入头名(默认即 dbx 约定的 `X-Forwarded-*` 四头)
- `MOCK_USERS_JSON` / `MOCK_USERS_FILE`: 注入自定义用户集
