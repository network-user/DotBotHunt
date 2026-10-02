from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from honeybot.closing import finalize_session
from honeybot.util import new_id, normalize_ip

log = logging.getLogger("honeybot")


@dataclass
class ConnCtx:
    session_id: str
    ip: str
    src_port: int
    dst_port: int
    bytes_in: int = 0
    bytes_out: int = 0
    banner: str = ""


async def accept_connection(app, proto: str, writer: asyncio.StreamWriter, dst_port: int) -> ConnCtx | None:
    peer = writer.get_extra_info("peername") or ("", 0)
    ip = normalize_ip(str(peer[0]))
    src_port = int(peer[1] or 0)
    if not app.limiter.try_acquire(ip):
        await app.store.add_event("", "limit", ip)
        writer.close()
        return None
    session_id = new_id()
    try:
        opened = await app.store.open_session(session_id, ip, src_port, dst_port, proto)
    except Exception:
        app.limiter.release(ip)
        writer.close()
        raise
    if not opened:
        app.limiter.release(ip)
        writer.close()
        return None
    try:
        app.enrich_queue.put_nowait(ip)
    except Exception:
        log.exception("очередь обогащения")
    return ConnCtx(session_id=session_id, ip=ip, src_port=src_port, dst_port=dst_port)


async def finish_connection(app, ctx: ConnCtx, writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    try:
        await finalize_session(app, ctx.session_id, ctx.bytes_in, ctx.bytes_out, ctx.banner)
    finally:
        app.limiter.release(ctx.ip)


async def serve(app, proto: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, runner) -> None:
    sock = writer.get_extra_info("sockname") or ("", 0)
    ctx = await accept_connection(app, proto, writer, int(sock[1] or 0))
    if ctx is None:
        return
    try:
        await asyncio.wait_for(runner(reader, writer, app, ctx), app.cfg.limits.session_seconds)
    except TimeoutError:
        pass
    except Exception:
        log.exception("сессия %s", ctx.session_id)
    finally:
        await finish_connection(app, ctx, writer)


async def send(ctx: ConnCtx, writer: asyncio.StreamWriter, text: str) -> None:
    data = text.encode("utf-8", "replace")
    ctx.bytes_out += len(data)
    writer.write(data)
    await writer.drain()


async def recv_line(ctx: ConnCtx, reader: asyncio.StreamReader, limit: int) -> str | None:
    try:
        data = await reader.readline()
    except (ConnectionError, asyncio.IncompleteReadError):
        return None
    if not data:
        return None
    ctx.bytes_in += len(data)
    if len(data) > limit:
        data = data[:limit]
    return data.decode("utf-8", "replace").rstrip("\r\n")


def strip_telnet(data: bytes) -> bytes:
    out = bytearray()
    index = 0
    size = len(data)
    while index < size:
        if data[index] != 255:
            out.append(data[index])
            index += 1
            continue
        if index + 1 >= size:
            break
        command = data[index + 1]
        if command == 255:
            out.append(255)
            index += 2
        elif command in (251, 252, 253, 254):
            index += 3 if index + 2 < size else size
        elif command == 250:
            end = data.find(bytes((255, 240)), index + 2)
            index = size if end < 0 else end + 2
        else:
            index += 2
    return bytes(out)


async def recv_telnet_line(ctx: ConnCtx, reader: asyncio.StreamReader, limit: int) -> str | None:
    try:
        data = await reader.readline()
    except (ConnectionError, asyncio.IncompleteReadError):
        return None
    if not data:
        return None
    ctx.bytes_in += len(data)
    cleaned = strip_telnet(data)
    if len(cleaned) > limit:
        cleaned = cleaned[:limit]
    return cleaned.decode("utf-8", "replace").rstrip("\r\n")
