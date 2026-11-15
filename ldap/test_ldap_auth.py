"""mock_ldap_auth.py 的集成测试.

用标准 LDAP 客户端(ldap3)直接访问 mock LDAP 服务器, 验证:
- Simple Bind 成功 / 失败路径(密码错误、用户不存在)
- 用户信息搜索(uid/cn/mail)
- LDAP 过滤器注入防护(用户名转义)
"""

import ldap3
import pytest
from ldap3.utils.conv import escape_filter_chars

from mock_ldap_auth import LDAPMockService, LdapAuthClient, USER_BASE_DN


@pytest.fixture(scope="module")
def ldap_service():
    """模块级启动一次 mock LDAP 服务(随机空闲端口)."""
    service = LDAPMockService(host="127.0.0.1", port=0)
    port = service.start()
    yield {"service": service, "port": port}
    service.stop()


@pytest.fixture(scope="module")
def auth_client(ldap_service) -> LdapAuthClient:
    return LdapAuthClient(port=ldap_service["port"])


def _server(port: int) -> ldap3.Server:
    return ldap3.Server("127.0.0.1", port=port, get_info=ldap3.NONE)


# ------------------------------------------------------------------ simple bind


def test_authenticate_with_valid_credentials(auth_client):
    user = auth_client.authenticate("alice", "alice-password")
    assert user is not None
    assert user["dn"] == "uid=alice,ou=people,dc=example,dc=org"
    assert user["username"] == "alice"
    assert user["display_name"] == "Alice Anderson"
    assert user["email"] == "alice@example.org"


def test_authenticate_with_wrong_password(auth_client):
    assert auth_client.authenticate("alice", "not-the-password") is None


def test_authenticate_unknown_user(auth_client):
    assert auth_client.authenticate("ghost", "whatever") is None


def test_raw_bind_valid_credentials(ldap_service):
    """绕过参考客户端, 直接用 ldap3 验证 bob 绑定成功."""
    conn = ldap3.Connection(
        _server(ldap_service["port"]),
        user="uid=bob,ou=people,dc=example,dc=org",
        password="bob-password",
        raise_exceptions=False,
    )
    assert conn.bind() is True
    conn.unbind()


def test_raw_bind_invalid_credentials(ldap_service):
    """密码错误时服务端应返回 invalidCredentials."""
    conn = ldap3.Connection(
        _server(ldap_service["port"]),
        user="uid=alice,ou=people,dc=example,dc=org",
        password="wrong",
        raise_exceptions=False,
    )
    assert conn.bind() is False
    assert conn.result["description"] == "invalidCredentials"


# ------------------------------------------------------------------ search


def test_anonymous_search_all_people(ldap_service):
    conn = ldap3.Connection(
        _server(ldap_service["port"]), authentication=ldap3.ANONYMOUS, auto_bind=True
    )
    try:
        assert conn.search(USER_BASE_DN, "(objectClass=inetOrgPerson)", attributes=["uid", "mail"])
        assert {entry.uid.value for entry in conn.entries} == {"alice", "bob", "carol", "dave"}
        mails = {entry.uid.value: entry.mail.value for entry in conn.entries}
        assert mails["alice"] == "alice@example.org"
        assert mails["bob"] == "bob@example.org"
        assert mails["carol"] == "carol@example.org"
        assert mails["dave"] == "dave@example.org"
    finally:
        conn.unbind()


# ------------------------------------------------------------------ groups / memberOf


def test_member_of_values_per_user(ldap_service):
    """dbx 默认 group_attr=memberOf: 各用户的 memberOf 恰好等于其组集合(完整 DN)."""
    conn = ldap3.Connection(
        _server(ldap_service["port"]), authentication=ldap3.ANONYMOUS, auto_bind=True
    )
    try:
        assert conn.search(USER_BASE_DN, "(objectClass=inetOrgPerson)", attributes=["uid", "memberOf"])
        member_of = {
            entry.uid.value: sorted(entry.memberOf.values) if "memberOf" in entry.entry_attributes else []
            for entry in conn.entries
        }
        assert member_of["alice"] == ["cn=users,ou=groups,dc=example,dc=org"]
        assert member_of["bob"] == ["cn=admins,ou=groups,dc=example,dc=org", "cn=users,ou=groups,dc=example,dc=org"]
        assert member_of["carol"] == ["cn=ops-admin,ou=groups,dc=example,dc=org", "cn=users,ou=groups,dc=example,dc=org"]
        assert member_of["dave"] == []
    finally:
        conn.unbind()


def test_group_entries_with_members(ldap_service):
    """组容器内可搜到 groupOfNames 条目, member 反向指向用户 DN."""
    conn = ldap3.Connection(
        _server(ldap_service["port"]), authentication=ldap3.ANONYMOUS, auto_bind=True
    )
    try:
        assert conn.search(
            "ou=groups,dc=example,dc=org", "(objectClass=groupOfNames)", attributes=["cn", "member"]
        )
        members_by_cn = {entry.cn.value: set(entry.member.values) for entry in conn.entries}
        assert set(members_by_cn) == {"users", "admins", "ops-admin"}
        # 组成员严格由 common/users.py 的 groups 推导(单一数据源, 与其他 provider 一致);
        # dave 的 groups=[] 因此不属于任何组, dbx 侧经 role_map 的 "*" 兜底得 member。
        assert members_by_cn["users"] == {
            f"uid={name},ou=people,dc=example,dc=org" for name in ("alice", "bob", "carol")
        }
        assert members_by_cn["admins"] == {"uid=bob,ou=people,dc=example,dc=org"}
        assert members_by_cn["ops-admin"] == {"uid=carol,ou=people,dc=example,dc=org"}
    finally:
        conn.unbind()


def test_display_name_attribute(ldap_service):
    """dbx 的 display_name_attr 默认值是 displayName(非 cn), 条目必须直接提供."""
    conn = ldap3.Connection(
        _server(ldap_service["port"]), authentication=ldap3.ANONYMOUS, auto_bind=True
    )
    try:
        conn.search(USER_BASE_DN, "(uid=carol)", attributes=["displayName", "uid"])
        assert conn.entries[0].displayName.value == "Carol Chen"
    finally:
        conn.unbind()


def test_short_group_value_style(monkeypatch):
    """GROUP_VALUE_STYLE=short 时, memberOf 只返回 cn 短名(便于 dbx 短名 role_map)."""
    monkeypatch.setenv("GROUP_VALUE_STYLE", "short")
    service = LDAPMockService(host="127.0.0.1", port=0)
    port = service.start()
    try:
        conn = ldap3.Connection(_server(port), authentication=ldap3.ANONYMOUS, auto_bind=True)
        try:
            conn.search(USER_BASE_DN, "(uid=bob)", attributes=["uid", "memberOf"])
            # 多值属性的返回顺序不保证(与存储顺序/哈希无关), 按集合比较
            assert sorted(conn.entries[0].memberOf.values) == ["admins", "users"]
        finally:
            conn.unbind()
    finally:
        service.stop()


def test_search_filter_injection_is_escaped(auth_client):
    """用户名携带过滤器注入片段时, 参考客户端必须转义, 不能借机绕过认证."""
    assert auth_client.authenticate("alice)(objectClass=*", "alice-password") is None


def test_escaped_filter_matches_nothing(ldap_service):
    """转义后的恶意输入作为普通字符处理, 匹配不到任何用户.

    注: 本版本 ldap3 的 search() 仅在返回 >=1 条记录时为 True,
    故这里以 result 与 entries 断言, 而非 search() 返回值。
    """
    conn = ldap3.Connection(
        _server(ldap_service["port"]), authentication=ldap3.ANONYMOUS, auto_bind=True
    )
    try:
        malicious = "alice)(objectClass=*"
        conn.search(USER_BASE_DN, f"(uid={escape_filter_chars(malicious)})", attributes=["uid"])
        assert conn.result["description"] == "success"
        assert conn.entries == []
    finally:
        conn.unbind()
