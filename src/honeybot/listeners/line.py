from __future__ import annotations

import asyncio
import base64
import logging

from honeybot.listeners.base import recv_line, recv_telnet_line, send, serve
from honeybot.reconstruct import normalize
from honeybot.reply import prompt, respond
from honeybot.vfs import VFS

log = logging.getLogger("honeybot")


async def _command(app, ctx, raw: str, exit_sent: int | None = None) -> None:
    await app.store.add_command(ctx.session_id, raw, "line", normalize(raw), exit_sent)


async def run_telnet(reader, writer, app, ctx) -> None:
    limit = app.cfg.limits.max_line_bytes
    need = app.cfg.listeners["telnet"].fail_before_accept
    fails = 0
    user = "root"
    while True:
        await send(ctx, writer, "login: ")
        username = await recv_telnet_line(ctx, reader, limit)
        if username is None:
            return
        await send(ctx, writer, "Password: ")
        password = await recv_telnet_line(ctx, reader, limit)
        if password is None:
            return
        accepted = fails >= need
        user = username.strip() or "root"
        await app.store.add_auth(ctx.session_id, user, password.strip(), "telnet", accepted)
        if accepted:
            break
        fails += 1
        await send(ctx, writer, "Login incorrect\r\n")
        if fails >= 6:
            return
    vfs = VFS(user)
    await send(ctx, writer, f"\r\nWelcome to Ubuntu 22.04.5 LTS\r\n\r\n{prompt(vfs)}")
    while True:
        line = await recv_telnet_line(ctx, reader, limit)
        if line is None:
            return
        if not line.strip():
            await send(ctx, writer, prompt(vfs))
            continue
        reply = respond(vfs, line)
        await _command(app, ctx, line, reply.exit_code)
        if reply.stdout:
            await send(ctx, writer, reply.stdout)
        if reply.close:
            return
        await send(ctx, writer, prompt(vfs))


async def run_ftp(reader, writer, app, ctx) -> None:
    limit = app.cfg.limits.max_line_bytes
    await send(ctx, writer, "220 (vsFTPd 3.0.5)\r\n")
    user = ""
    authed = False
    while True:
        line = await recv_line(ctx, reader, limit)
        if line is None:
            return
        if not line.strip():
            continue
        verb, _, arg = line.partition(" ")
        command = verb.upper()
        if command == "USER":
            user = arg.strip()
            await send(ctx, writer, "331 Please specify the password.\r\n")
            continue
        if command == "PASS":
            await app.store.add_auth(ctx.session_id, user, arg.strip(), "ftp", True)
            authed = True
            await send(ctx, writer, "230 Login successful.\r\n")
            continue
        if command == "QUIT":
            await _command(app, ctx, line, 0)
            await send(ctx, writer, "221 Goodbye.\r\n")
            return
        await _command(app, ctx, line, 5)
        if command in {"PASV", "EPSV"}:
            await send(ctx, writer, "425 Passive mode is disabled.\r\n")
            continue
        if command in {"PORT", "EPRT", "STOR", "RETR", "LIST", "NLST", "APPE", "STOU"}:
            await send(ctx, writer, "502 Command not implemented.\r\n")
            continue
        if command == "SYST":
            await send(ctx, writer, "215 UNIX Type: L8\r\n")
            continue
        if command == "FEAT":
            await send(ctx, writer, "211-Features:\r\n UTF8\r\n211 End\r\n")
            continue
        if command == "NOOP":
            await send(ctx, writer, "200 NOOP ok.\r\n")
            continue
        if command == "PWD":
            await send(ctx, writer, '257 "/"\r\n')
            continue
        if not authed:
            await send(ctx, writer, "530 Please login with USER and PASS.\r\n")
            continue
        await send(ctx, writer, "502 Command not implemented.\r\n")


def decode_smtp_plain(blob: str) -> tuple[str, str]:
    raw = blob.strip()[:500]
    if not raw:
        return "", ""
    try:
        data = base64.b64decode(raw, validate=False)
    except Exception:
        return "", raw[:200]
    text = data.decode("utf-8", "replace")
    parts = text.split("\x00")
    if len(parts) >= 3:
        return parts[-2][:120], parts[-1][:200]
    if len(parts) == 2:
        return parts[0][:120], parts[1][:200]
    return "", text.replace("\x00", "")[:200]


def decode_smtp_token(blob: str) -> str:
    raw = blob.strip()[:500]
    if not raw:
        return ""
    try:
        data = base64.b64decode(raw, validate=False)
    except Exception:
        return raw[:200]
    return data.decode("utf-8", "replace").replace("\x00", "")[:200]


async def run_smtp(reader, writer, app, ctx) -> None:
    limit = app.cfg.limits.max_line_bytes
    await send(ctx, writer, "220 mail.web-01 ESMTP Postfix\r\n")
    while True:
        line = await recv_line(ctx, reader, limit)
        if line is None:
            return
        if not line.strip():
            continue
        verb = line.split(" ", 1)[0].upper()
        if verb in {"HELO", "EHLO"}:
            host = line.split(" ", 1)[1].strip() if " " in line else ""
            if host and not ctx.banner:
                ctx.banner = host[:300]
            await _command(app, ctx, line, 250)
            await send(ctx, writer, "250-mail.web-01\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
            continue
        if verb == "AUTH":
            pieces = line.split(" ")
            mechanism = pieces[1].upper() if len(pieces) > 1 else ""
            argument = pieces[2] if len(pieces) > 2 else ""
            if mechanism == "PLAIN":
                if not argument:
                    await send(ctx, writer, "334 \r\n")
                    argument = await recv_line(ctx, reader, limit) or ""
                    if argument == "":
                        return
                username, secret = decode_smtp_plain(argument)
                await app.store.add_auth(ctx.session_id, username, secret, "smtp", True)
                await send(ctx, writer, "235 2.7.0 Authentication successful\r\n")
                continue
            if mechanism == "LOGIN":
                username = decode_smtp_token(argument) if argument else ""
                if not username:
                    await send(ctx, writer, "334 VXNlcm5hbWU6\r\n")
                    user_line = await recv_line(ctx, reader, limit)
                    if user_line is None:
                        return
                    username = decode_smtp_token(user_line)
                await send(ctx, writer, "334 UGFzc3dvcmQ6\r\n")
                pass_line = await recv_line(ctx, reader, limit)
                if pass_line is None:
                    await app.store.add_auth(ctx.session_id, username, "", "smtp", True)
                    return
                await app.store.add_auth(
                    ctx.session_id,
                    username,
                    decode_smtp_token(pass_line),
                    "smtp",
                    True,
                )
                await send(ctx, writer, "235 2.7.0 Authentication successful\r\n")
                continue
            await app.store.add_auth(ctx.session_id, "", line[:200], "smtp", True)
            await send(ctx, writer, "235 2.7.0 Authentication successful\r\n")
            continue
        if verb in {"MAIL", "RCPT", "NOOP", "RSET", "VRFY"}:
            await _command(app, ctx, line, 250)
            await send(ctx, writer, "250 OK\r\n")
            continue
        if verb == "DATA":
            await send(ctx, writer, "354 End data with <CR><LF>.<CR><LF>\r\n")
            collected: list[str] = []
            size = 0
            while True:
                piece = await recv_line(ctx, reader, limit)
                if piece is None or piece == ".":
                    break
                collected.append(piece)
                size += len(piece)
                if size > 4000:
                    break
            snippet = "\n".join(collected)[:500]
            await _command(app, ctx, "DATA " + snippet, 250)
            await send(ctx, writer, "250 2.0.0 Queued\r\n")
            continue
        if verb == "QUIT":
            await _command(app, ctx, line, 221)
            await send(ctx, writer, "221 Bye\r\n")
            return
        await _command(app, ctx, line, 500)
        await send(ctx, writer, "500 Command not recognized\r\n")


async def _read_redis(ctx, reader, limit: int) -> str | None:
    try:
        line = await reader.readline()
    except (ConnectionError, asyncio.IncompleteReadError):
        return None
    if not line:
        return None
    ctx.touch()
    ctx.bytes_in += len(line)
    if not line.startswith(b"*"):
        return line.decode("utf-8", "replace").strip()[:limit]
    try:
        count = int(line[1:].strip())
    except ValueError:
        return line.decode("utf-8", "replace").strip()[:limit]
    if count < 0 or count > 16:
        return None
    parts: list[str] = []
    for _ in range(count):
        header = await reader.readline()
        if not header:
            return None
        ctx.touch()
        ctx.bytes_in += len(header)
        if not header.startswith(b"$"):
            parts.append(header.decode("utf-8", "replace").strip())
            continue
        try:
            size = int(header[1:].strip())
        except ValueError:
            return None
        if size < 0:
            parts.append("")
            continue
        if size > limit:
            return None
        try:
            blob = await reader.readexactly(size + 2)
        except asyncio.IncompleteReadError:
            return None
        ctx.touch()
        ctx.bytes_in += len(blob)
        parts.append(blob[:-2].decode("utf-8", "replace"))
    return " ".join(parts)[:limit]


_REDIS_INFO = (
    "# Server\r\n"
    "redis_version:7.0.15\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 5.15.0-91-generic x86_64\r\n"
    "tcp_port:6379\r\n"
)


def _redis_bulk(text: str) -> str:
    payload = text.encode("utf-8")
    return f"${len(payload)}\r\n{text}\r\n"


def _redis_reply(command: str) -> tuple[str, bool]:
    verb = command.split(" ", 1)[0].upper()
    if verb == "PING":
        return "+PONG\r\n", False
    if verb == "QUIT":
        return "+OK\r\n", True
    if verb == "INFO":
        return _redis_bulk(_REDIS_INFO), False
    if verb in {"SLAVEOF", "REPLICAOF", "CONFIG", "MODULE"}:
        return "-ERR unknown command\r\n", False
    return "-ERR unknown command\r\n", False


async def run_redis(reader, writer, app, ctx) -> None:
    limit = app.cfg.limits.max_line_bytes
    while True:
        command = await _read_redis(ctx, reader, limit)
        if command is None:
            return
        if not command:
            continue
        reply, close = _redis_reply(command)
        await _command(app, ctx, command, 0 if reply.startswith("+") else 1)
        await send(ctx, writer, reply)
        if close:
            return


def _handler(app, proto: str, runner):
    async def handler(reader, writer):
        await serve(app, proto, reader, writer, runner)

    return handler


_RUNNERS = {
    "telnet": run_telnet,
    "ftp": run_ftp,
    "smtp": run_smtp,
    "redis": run_redis,
}


async def start_line(app, name: str):
    listener = app.cfg.listeners[name]
    if not listener.enabled:
        return None
    server = await asyncio.start_server(_handler(app, name, _RUNNERS[name]), "0.0.0.0", listener.port)
    port = server.sockets[0].getsockname()[1]
    log.info("%s слушает порт %s", name, port)
    return name, port, server
