# Mock LDAP 认证服务(ldaptor 内存目录树)

基于 ldaptor + Twisted 运行一个**真实协议**的 LDAP 服务器(不是 mock 掉协议),
任何标准客户端(ldap3 / python-ldap / ldapsearch)都可按真实集成方式联调。

- 默认监听: `ldap://127.0.0.1:13890`
- Base DN: `dc=example,dc=org`; 用户容器 `ou=people`; 组容器 `ou=groups`(groupOfNames)
- 用户条目直接写有 `memberOf`(ldaptor 不会从 groupOfNames 反推)与
  `displayName`(dbx 的 display_name_attr 默认值)属性
- 组成员严格由共享用户集(`common/users.py`)推导; `GROUP_VALUE_STYLE=dn|short`
  控制 memberOf 值形态(默认 dn=完整组 DN, short=仅 cn 短名)

运行: `uv run python mock_ldap_auth.py --host 127.0.0.1 --port 13890`
测试: `uv run pytest test_ldap_auth.py -v`

集成参考实现: `LdapAuthClient`(ldap3) —— 与 dbx `LdapAuthProvider` 流程一致:
服务账号(或匿名)搜索定位用户 DN → 用户 DN + 密码绑定验证 → 读 uid/displayName/mail/memberOf。

## 对接 DBX

`DBX_AUTH_CONFIG`(dbx 侧环境变量, JSON 数组, 可直接复制):

```json
[
  {
    "id": "ldap",
    "kind": "ldap",
    "label": "Mock LDAP",
    "enabled": true,
    "config": {
      "url": "ldap://127.0.0.1:13890",
      "base_dn": "dc=example,dc=org",
      "user_filter": "(uid={username})",
      "username_attr": "uid",
      "display_name_attr": "displayName",
      "email_attr": "mail",
      "group_attr": "memberOf",
      "role_map": {
        "cn=admins,ou=groups,dc=example,dc=org": "admin",
        "cn=ops-admin,ou=groups,dc=example,dc=org": "admin",
        "*": "member"
      },
      "default_role": "member",
      "timeout_secs": 5
    }
  }
]
```

> 若 mock 以 `GROUP_VALUE_STYLE=short` 启动, role_map 键改用短名:
> `{"admins":"admin","ops-admin":"admin","*":"member"}`。

### 多用户 × 期望角色验证矩阵

| 登录用户 | memberOf | 期望角色 |
| --- | --- | --- |
| alice | cn=users | member |
| bob | cn=admins, cn=users | admin |
| carol | cn=ops-admin, cn=users | admin |
| dave | (无) | member(`*` 兜底) |

### 负向用例

| 用例 | 操作 | 期望 |
| --- | --- | --- |
| 密码错误 | alice + 错误密码 | dbx 报 invalid credentials(绑定失败) |
| 用户不存在 | ghost | dbx 报 invalid credentials(搜索 0 条) |
| 过滤器注入 | 用户名填 `alice)(objectClass=*` | 被转义为普通字符, 认证失败 |
| 服务未启动 | mock 进程停止 | dbx 报 provider unavailable |
| 角色刷新 | bob 退出重登 / 换组用户重登 | 同 subject 角色随之刷新 |

### 环境变量

- `MOCK_USERS_JSON` / `MOCK_USERS_FILE`: 注入自定义用户集(目录树随之重建)
- `GROUP_VALUE_STYLE=dn|short`: memberOf 值形态
