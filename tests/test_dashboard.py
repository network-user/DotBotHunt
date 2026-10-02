from __future__ import annotations

import asyncio

from honeybot.reconstruct import normalize, reconstruct
from tests.conftest import start_bot


async def test_dashboard_is_local_and_escapes(tmp_path):
    bot = await start_bot(tmp_path, set(), dashboard=True)
    try:
        sock = bot.listeners[0].sockets[0]
        assert sock.getsockname()[0] == "127.0.0.1"
        assert bot.bound["dashboard"] == sock.getsockname()[1]
        await bot.store.open_session("abc123def456", "203.0.113.9", 1, 80, "http")
        await bot.store.add_command(
            "abc123def456",
            "<script>alert(1)</script>",
            "exec",
            normalize("<script>alert(1)</script>"),
            0,
        )
        bundle = await bot.store.bundle("abc123def456")
        result = reconstruct(bundle)
        await bot.store.finish(
            "abc123def456",
            result.primary,
            result.summary,
            result.command_tags,
            result.http_tags,
        )
        page = await _get(bot.bound["dashboard"], "/")
        assert b"200" in page.split(b"\r\n", 1)[0]
        assert b"Content-Security-Policy:" in page
        assert b"frame-ancestors 'none'" in page
        assert "Сессий".encode() in page
        detail = await _get(bot.bound["dashboard"], "/session/abc123def456")
        assert b"<script>alert" not in detail
        assert b"&lt;script&gt;" in detail
    finally:
        await bot.stop()


async def _get(port: int, path: str) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data
