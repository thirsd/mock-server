"""pytest 公共夹具: 在线程中启动真实 uvicorn 服务, 供各 mock 的端到端测试使用.

用法(在各 test_*.py 中):

    @pytest.fixture(scope="module")
    def server(uvicorn_server_factory):
        return uvicorn_server_factory(some_app)

"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Iterator, List

import pytest
import uvicorn


def free_port() -> int:
    """取一个当前空闲的 TCP 端口(存在理论竞态, 本地联调可接受)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class UvicornServerThread:
    """在守护线程中运行 uvicorn.Server, 绑定随机空闲端口."""

    def __init__(self, app, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port = free_port()
        config = uvicorn.Config(app, host=host, port=self.port, log_level="warning")
        self.server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> "UvicornServerThread":
        self._thread.start()
        deadline = time.time() + 15
        while time.time() < deadline and not self.server.started:
            time.sleep(0.05)
        if not self.server.started:
            raise RuntimeError("uvicorn 服务启动超时")
        return self

    def stop(self) -> None:
        self.server.should_exit = True
        self._thread.join(timeout=10)


@pytest.fixture(scope="session")
def uvicorn_server_factory() -> Iterator[Callable]:
    """按需启动多个 HTTP 服务的工厂夹具, 测试会话结束后统一关闭."""
    servers: List[UvicornServerThread] = []

    def factory(app) -> UvicornServerThread:
        server = UvicornServerThread(app).start()
        servers.append(server)
        return server

    try:
        yield factory
    finally:
        for server in servers:
            server.stop()
