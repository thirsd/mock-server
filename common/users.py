"""共享用户数据: 四种 mock 认证服务统一的账号源(dbx 多用户联调).

- 内置默认用户: alice / bob / carol / dave, 密码约定 <username>-password
- 组集合固定为 users(普通) / admins / ops-admin, 恰好覆盖 dbx 典型 role_map:
  {"admins": "admin", "ops-admin": "admin", "*": "member"}
  alice/bob 行为与项目初版完全一致; carol/dave 为新增验证用户。
- 环境变量覆盖(供 CI / 定制场景注入任意用户集):
    MOCK_USERS_JSON   内联 JSON, 如 {"erin": {"groups": ["ops-admin"]}}
    MOCK_USERS_FILE   JSON 文件路径(结构与上面一致)
  缺省字段按约定补齐: password=<name>-password, display_name=<name>,
  email=<name>@example.org, groups=[]。可选 "subject"/"disabled" 字段。
"""

from __future__ import annotations

import hmac
import json
import os
from typing import Any, Dict, Optional

DEFAULT_USERS: Dict[str, Dict[str, Any]] = {
    "alice": {
        "password": "alice-password",
        "display_name": "Alice Anderson",
        "email": "alice@example.org",
        "groups": ["users"],
    },
    "bob": {
        "password": "bob-password",
        "display_name": "Bob Brown",
        "email": "bob@example.org",
        "groups": ["users", "admins"],
    },
    "carol": {
        "password": "carol-password",
        "display_name": "Carol Chen",
        "email": "carol@example.org",
        "groups": ["users", "ops-admin"],
    },
    "dave": {
        "password": "dave-password",
        "display_name": "Dave Dai",
        "email": "dave@example.org",
        "groups": [],
    },
}


def _load_users() -> Dict[str, Dict[str, Any]]:
    inline = os.environ.get("MOCK_USERS_JSON")
    path = os.environ.get("MOCK_USERS_FILE")
    raw: Optional[str] = None
    if inline and inline.strip():
        raw = inline
    elif path and path.strip():
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    if raw is None:
        return {name: dict(info) for name, info in DEFAULT_USERS.items()}

    data = json.loads(raw)
    users: Dict[str, Dict[str, Any]] = {}
    for username, info in data.items():
        info = dict(info)
        info.setdefault("password", f"{username}-password")
        info.setdefault("display_name", username)
        info.setdefault("email", f"{username}@example.org")
        info.setdefault("groups", [])
        users[username] = info
    return users


# 进程启动时加载一次; 测试可通过 importlib.reload(common.users) 配合
# 环境变量注入自定义用户集(各 mock 均在请求期调用 get_users(), 能感知重载)。
USERS: Dict[str, Dict[str, Any]] = _load_users()


def get_users() -> Dict[str, Dict[str, Any]]:
    """当前生效的用户集(逐条浅拷贝, 避免调用方误改全局)."""
    return {name: dict(info) for name, info in USERS.items()}


def profile(username: str) -> Optional[Dict[str, Any]]:
    """对外统一的用户信息(不含密码/内部字段)."""
    info = USERS.get(username)
    if info is None:
        return None
    return {
        "username": username,
        "display_name": info.get("display_name", username),
        "email": info.get("email"),
        "groups": list(info.get("groups", [])),
    }


def verify_password(username: str, password: str) -> Optional[Dict[str, Any]]:
    """用户名 + 密码校验; 成功返回用户信息, 失败(未知/禁用/密码错)返回 None."""
    info = USERS.get(username)
    if info is None or info.get("disabled"):
        return None
    expected = str(info.get("password") or f"{username}-password")
    if hmac.compare_digest(expected.encode(), (password or "").encode()):
        return profile(username)
    return None


def subject_id(username: str) -> str:
    """稳定 subject ID(u-1001 起按用户集顺序编号).

    MOCK_USERS_JSON 中可用显式 "subject": "u-xxx" 覆盖;
    同一用户反复登录得到相同 subject, 便于验证 dbx 的账号归并逻辑。
    """
    info = USERS.get(username)
    if info is None:
        return f"u-{username}"
    explicit = info.get("subject")
    if explicit:
        return str(explicit)
    for index, name in enumerate(USERS, start=1):
        if name == username:
            return f"u-{1000 + index}"
    return f"u-{username}"  # pragma: no cover
