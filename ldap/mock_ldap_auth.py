"""Mock LDAP 认证服务(独立示例, 可直接运行).

基于 ldaptor(LDAP 协议实现) + Twisted 在内存中运行一个“真实”的 LDAP 服务器,
因此任何标准 LDAP 客户端(ldap3 / python-ldap / OpenLDAP ldapsearch)都能按真实
集成方式联调, 而不是 mock 掉协议本身。

目录结构(由 common.users 的用户集动态生成, 支持多用户 + 组):

    dc=example,dc=org
    ├── ou=people,dc=example,dc=org
    │   ├── uid=alice  ... memberOf: cn=users,...                    → dbx member
    │   ├── uid=bob    ... memberOf: cn=admins,... cn=users,...      → dbx admin
    │   ├── uid=carol  ... memberOf: cn=ops-admin,... cn=users,...   → dbx admin
    │   └── uid=dave   ... (无 memberOf)                             → dbx member(* 兜底)
    └── ou=groups,dc=example,dc=org
        ├── cn=users     (groupOfNames, member: 全部用户)
        ├── cn=admins    (groupOfNames, member: bob)
        └── cn=ops-admin (groupOfNames, member: carol)

用户条目同时写有 displayName 属性(dbx 的 display_name_attr 默认值)与
memberOf 属性(ldaptor 不会从 groupOfNames 反推, 必须显式写入)。

环境变量:
    MOCK_USERS_JSON / MOCK_USERS_FILE  注入自定义用户集(见 common/users.py)
    GROUP_VALUE_STYLE=dn|short         memberOf 值形态: dn(默认)=完整组 DN,
                                       short=仅 cn 短名(admins/ops-admin/users)

集成方式(Simple Bind + 搜索):
    1. 服务账号(或匿名)按 (uid={username}) 过滤定位用户 DN;
    2. 用用户 DN + 密码绑定完成认证(= dbx LdapAuthProvider 的流程);
    3. 读取 uid/displayName/mail/memberOf 组装身份。

运行:
    uv run python mock_ldap_auth.py --host 127.0.0.1 --port 13890

测试:
    uv run pytest test_ldap_auth.py -v

集成方参考客户端: LdapAuthClient(基于 ldap3)。
"""

from __future__ import annotations

import argparse
import os
import threading
from io import BytesIO
from typing import Any, Dict, List, Optional

import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldaptor import interfaces as ldaptor_interfaces
from ldaptor.inmemory import fromLDIFFile
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.internet import protocol, reactor
from twisted.python.components import registerAdapter

from common.users import get_users

BASE_DN = "dc=example,dc=org"
USER_BASE_DN = "ou=people,dc=example,dc=org"
GROUPS_BASE_DN = "ou=groups,dc=example,dc=org"
USER_DN_TEMPLATE = "uid={username},ou=people,dc=example,dc=org"
USER_ATTRIBUTE_NAMES = ["uid", "cn", "displayName", "sn", "givenName", "mail", "memberOf"]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13890


def group_dn(group: str) -> str:
    return f"cn={group},{GROUPS_BASE_DN}"


def _group_value_style() -> str:
    return os.environ.get("GROUP_VALUE_STYLE", "dn").strip().lower() or "dn"


def _member_of_values(groups: List[str], style: str) -> List[str]:
    """memberOf 属性值: dn 模式=完整组 DN(默认); short 模式=cn 短名."""
    if style == "short":
        return list(groups)
    return [group_dn(group) for group in groups]


def _build_ldif() -> bytes:
    """由共享用户集动态生成目录 LDIF(用户条目 + 组条目)."""
    users = get_users()
    style = _group_value_style()

    lines: List[str] = [
        "version: 1",
        "",
        f"dn: {BASE_DN}",
        "objectClass: dcObject",
        "objectClass: organization",
        "dc: example",
        "o: Example Organization",
        "",
        f"dn: {USER_BASE_DN}",
        "objectClass: organizationalUnit",
        "ou: people",
        "",
        f"dn: {GROUPS_BASE_DN}",
        "objectClass: organizationalUnit",
        "ou: groups",
        "",
    ]

    for username, info in users.items():
        display_name = str(info.get("display_name") or username)
        parts = display_name.split()
        sn = parts[-1] if parts else username
        given_name = parts[0] if len(parts) > 1 else username
        groups = list(dict.fromkeys(info.get("groups", [])))
        lines += [
            f"dn: uid={username},{USER_BASE_DN}",
            "objectClass: inetOrgPerson",
            f"uid: {username}",
            f"cn: {display_name}",
            f"sn: {sn}",
            f"givenName: {given_name}",
            f"mail: {info.get('email') or f'{username}@example.org'}",
            f"displayName: {display_name}",
        ]
        if not info.get("disabled"):
            # 禁用用户不写 userPassword, 绑定必然失败
            lines.append(f"userPassword: {info.get('password') or f'{username}-password'}")
        lines += [f"memberOf: {value}" for value in _member_of_values(groups, style)]
        lines.append("")

    all_groups = sorted({g for info in users.values() for g in info.get("groups", [])})
    for group in all_groups:
        lines += [
            f"dn: cn={group},{GROUPS_BASE_DN}",
            "objectClass: groupOfNames",
            f"cn: {group}",
        ]
        lines += [
            f"member: uid={username},{USER_BASE_DN}"
            for username, info in users.items()
            if group in info.get("groups", [])
        ]
        lines.append("")

    return "\n".join(lines).encode() + b"\n"


class _LDAPServerFactory(protocol.ServerFactory):
    """把内存目录树挂到每一个 LDAP 连接上(ldaptor 官方用法)."""

    protocol = LDAPServer

    def __init__(self, root: Any) -> None:
        self.root = root

    def buildProtocol(self, addr) -> LDAPServer:  # noqa: N802 (Twisted 接口约定)
        proto = self.protocol()
        proto.debug = False
        proto.root = self.root
        proto.factory = self
        return proto


# ldaptor 的协议处理器通过 IConnectedLDAPEntry 适配器从 factory 拿根节点,
# 自定义 Factory 类必须自行注册(ldaptor 只在其文档示例中演示了这一步)。
registerAdapter(
    lambda factory: factory.root, _LDAPServerFactory, ldaptor_interfaces.IConnectedLDAPEntry
)


# Twisted reactor 是进程级单例: 多个 LDAPMockService 实例(如不同 GROUP_VALUE_STYLE 的
# 并行测试)必须共享同一条 reactor 线程, 因此守卫放在模块级而非实例级。
_REACTOR_THREAD: Optional[threading.Thread] = None
_REACTOR_LOCK = threading.Lock()


def _start_reactor_once() -> None:
    """确保进程内只调用一次 reactor.run()(重复调用会抛 ReactorAlreadyRunning)."""
    global _REACTOR_THREAD
    with _REACTOR_LOCK:
        if _REACTOR_THREAD is not None and _REACTOR_THREAD.is_alive():
            return
        _REACTOR_THREAD = threading.Thread(
            target=reactor.run, args=(False,), daemon=True, name="ldap-mock-reactor"
        )
        _REACTOR_THREAD.start()


class LDAPMockService:
    """内存 LDAP 服务, 支持进程内启动(测试)与独立进程运行(联调)."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = 0) -> None:
        self.host = host
        self.port = port
        self._listening: Any = None

    def start(self) -> int:
        """启动服务并阻塞到可接受连接, 返回实际监听端口(传 port=0 则随机分配)."""
        if self._listening is not None:
            raise RuntimeError("LDAPMockService 已经启动")

        _start_reactor_once()

        ready = threading.Event()
        outcome: Dict[str, Any] = {}

        def _setup() -> None:
            deferred = fromLDIFFile(BytesIO(_build_ldif()))
            deferred.addCallback(self._listen, outcome, ready)
            deferred.addErrback(self._fail, outcome, ready)

        reactor.callFromThread(_setup)
        if not ready.wait(timeout=15):
            raise RuntimeError("Mock LDAP 服务启动超时")
        if "error" in outcome:
            raise RuntimeError(f"Mock LDAP 服务启动失败: {outcome['error']!r}")
        return outcome["port"]

    def _listen(self, root: Any, outcome: Dict[str, Any], ready: threading.Event) -> None:
        factory = _LDAPServerFactory(root)
        try:
            self._listening = reactor.listenTCP(self.port, factory, interface=self.host)
        except Exception as exc:  # pragma: no cover - 端口占用等
            outcome["error"] = exc
            ready.set()
            return
        outcome["port"] = self._listening.getHost().port
        ready.set()

    def _fail(self, failure: Any, outcome: Dict[str, Any], ready: threading.Event) -> None:
        outcome["error"] = failure.value
        ready.set()

    def stop(self) -> None:
        listening, self._listening = self._listening, None
        if listening is not None:
            reactor.callFromThread(listening.stopListening)


class LdapAuthClient:
    """集成方参考实现: 用户名 + 密码 → LDAP 认证 → 用户信息(含组).

    流程与 dbx LdapAuthProvider 一致: 先定位用户 DN, 再用用户 DN 绑定验证密码,
    最后读取 uid/displayName/mail/memberOf。生产环境应使用 ldaps:// 或 starttls。
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        user_dn_template: str = USER_DN_TEMPLATE,
        user_base_dn: str = USER_BASE_DN,
        connect_timeout: float = 5.0,
    ) -> None:
        self.user_dn_template = user_dn_template
        self.user_base_dn = user_base_dn
        self._server = ldap3.Server(
            host,
            port=port,
            connect_timeout=connect_timeout,
            get_info=ldap3.NONE,  # 不请求 schema, 简化 mock 联调
        )

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """认证成功返回用户信息 dict(含 dn/username/display_name/email/groups), 失败返回 None."""
        user_dn = self.user_dn_template.format(username=username)
        try:
            conn = ldap3.Connection(
                self._server,
                user=user_dn,
                password=password,
                raise_exceptions=False,
                receive_timeout=10,
            )
        except LDAPException:
            return None

        try:
            if not conn.bind():
                return None
            # 过滤器中的特殊字符必须转义, 防止 LDAP 注入(与 dbx escape_ldap_filter 一致)
            search_filter = f"(uid={escape_filter_chars(username)})"
            if not conn.search(self.user_base_dn, search_filter, attributes=USER_ATTRIBUTE_NAMES):
                return None
            if not conn.entries:
                return None
            entry = conn.entries[0]
            attrs = set(entry.entry_attributes)
            member_of = list(entry.memberOf.values) if "memberOf" in attrs else []
            groups = [
                value.split(",", 1)[0][3:] if value[:3].upper() == "CN=" else value
                for value in member_of
            ]
            display_name = None
            if "displayName" in attrs:
                display_name = entry.displayName.value
            elif "cn" in attrs:
                display_name = entry.cn.value
            return {
                "dn": entry.entry_dn,
                "username": entry.uid.value if "uid" in attrs else username,
                "display_name": display_name,
                "email": entry.mail.value if "mail" in attrs else None,
                "groups": groups,
            }
        except LDAPException:
            return None
        finally:
            try:
                conn.unbind()
            except Exception:  # pragma: no cover
                pass


def run_standalone(host: str, port: int) -> None:
    """以独立进程方式运行(在主线程中启动 Twisted reactor)."""

    def _listen(root: Any) -> None:
        factory = _LDAPServerFactory(root)
        reactor.listenTCP(port, factory, interface=host)
        print(f"Mock LDAP 服务已启动: ldap://{host}:{port}")
        print(f"  Base DN   : {BASE_DN}")
        print(f"  用户 DN   : {USER_DN_TEMPLATE.format(username='<username>')}")
        print(f"  组容器    : {GROUPS_BASE_DN} (users / admins / ops-admin)")
        print(f"  memberOf  : {_group_value_style()} 形态 (GROUP_VALUE_STYLE=dn|short)")
        print("  账号      : " + ", ".join(f"{name}/{name}-password" for name in get_users()))

    deferred = fromLDIFFile(BytesIO(_build_ldif()))
    deferred.addCallback(_listen)
    deferred.addErrback(lambda failure: (failure.printTraceback(), reactor.stop()))
    reactor.run()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock LDAP 认证服务(内存目录)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    run_standalone(args.host, args.port)


if __name__ == "__main__":
    main()
