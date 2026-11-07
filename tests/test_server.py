import json
import socket
import threading
import time

import anyio
import httpx
import pytest
import uvicorn

from nasmcp.server import build_app

from .test_core import nas  # noqa: F401  (fixture)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(nas):  # noqa: F811
    app, _ = build_app(nas)
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    th.join(5)


def test_health_is_open(server):
    r = httpx.get(f"{server}/health")
    assert r.status_code == 200 and r.json()["ok"]


def test_mcp_needs_token(server):
    r = httpx.post(f"{server}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    r = httpx.post(f"{server}/mcp", json={}, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_status_page_token_cookie(server):
    assert httpx.get(f"{server}/").status_code == 401
    r = httpx.get(f"{server}/?token=t")
    assert r.status_code == 200 and "rclone" in r.text
    assert httpx.get(f"{server}/", cookies={"nasmcp": "t"}).status_code == 200


def test_tool_call_over_http(server):
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    import httpx2

    async def go():
        async with httpx2.AsyncClient(headers={"Authorization": "Bearer t"}) as hc:
            async with streamable_http_client(f"{server}/mcp", http_client=hc) as streams:
                read, write = streams[0], streams[1]
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    names = {t.name for t in tools.tools}
                    res = await session.call_tool("container_diagnose", {"name": "rclone"})
                    return names, res

    names, res = anyio.run(go)
    assert {"nas_overview", "container_diagnose", "file_read"} <= names
    data = json.loads(res.content[0].text)
    assert any(p["code"] == "broke_after_update" for p in data["problems"])
