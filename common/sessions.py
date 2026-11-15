"""HMAC 签名的无状态会话 cookie(OIDC IdP 会话与 mock 网关会话共用).

cookie 值格式: <base64url(username)>.<expires_at_epoch>.<hmac-sha256>

- HttpOnly + SameSite=Lax; 会话密钥每进程随机生成, 重启即全部失效(mock 语义)
- username 先做 base64url 编码, 避免用户名中出现 '.' 破坏解析
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Optional

DEFAULT_TTL_SECONDS = 8 * 3600


def new_secret() -> str:
    """为当前进程生成一次性会话签名密钥."""
    return secrets.token_hex(32)


def _sign(payload: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)
    return mac.hexdigest()


def make_cookie_value(username: str, secret: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    expires_at = int(time.time()) + int(ttl_seconds)
    encoded_user = base64.urlsafe_b64encode(username.encode()).rstrip(b"=").decode()
    payload = f"{encoded_user}.{expires_at}"
    return f"{payload}.{_sign(payload, secret)}"


def parse_cookie_value(value: str, secret: str) -> Optional[str]:
    """校验会话 cookie; 有效返回用户名, 无效/过期/签名不符返回 None."""
    try:
        encoded_user, expires_at, signature = value.split(".")
    except (ValueError, AttributeError):
        return None
    payload = f"{encoded_user}.{expires_at}"
    if not hmac.compare_digest(signature, _sign(payload, secret)):
        return None
    try:
        if int(expires_at) < int(time.time()):
            return None
        username = base64.urlsafe_b64decode(encoded_user + "=" * (-len(encoded_user) % 4)).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    return username or None
