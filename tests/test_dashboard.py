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
        assert "Запись открыта".encode() in page
        assert b"203.0.113.9" in page
        assert b"<script>" not in page
        ip_page = await _get(bot.bound["dashboard"], "/ip/203.0.113.9")
        assert b"abc123def456" in ip_page
        assert b"<script>" not in ip_page
        junk = await _get(bot.bound["dashboard"], "/?since=%3Cscript%3E&intent=%3Cbad%3E")
        body = junk.split(b"\r\n\r\n", 1)[-1]
        assert b"<script>" not in body
        assert b"<bad>" not in body
        assert b"200" in junk.split(b"\r\n", 1)[0]
        assert b"/report.html" in page
        assert "Скачать отчёт".encode() in page
        downloaded = await _get(bot.bound["dashboard"], "/report.html")
        head, _, report_body = downloaded.partition(b"\r\n\r\n")
        assert b"200" in head.split(b"\r\n", 1)[0]
        assert b"Content-Disposition: attachment;" in head
        assert b"filename=\"honeybot-report.html\"" in head
        assert b"<script>" not in report_body
        assert b"&lt;script&gt;" in report_body
        assert "Отчёт по атакам".encode() in report_body
        exported = await _get(bot.bound["dashboard"], "/report.csv?since=24h&intent=miner")
        assert b"text/csv" in exported
        assert b"attachment;" in exported
        missing = await _get(bot.bound["dashboard"], "/report.pdf")
        assert b"404" in missing.split(b"\r\n", 1)[0]
    finally:
        await bot.stop()


async def _get(port: int, path: str) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data
