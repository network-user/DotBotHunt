from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass

from honeybot.listeners.base import serve

log = logging.getLogger("honeybot")

_LOGIN_PATHS = {"/wp-login.php", "/admin", "/phpmyadmin", "/phpmyadmin/"}
_KEEP_HEADERS = ("host", "user-agent", "content-type", "authorization", "cookie")

_NGINX = """<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body></html>"""

_NOT_FOUND = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>"""

_LOGIN = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body><h1>Login</h1>
<form method="post"><label>User <input name="log"></label>
<label>Password <input type="password" name="pwd"></label>
<button type="submit">Sign in</button></form></body></html>"""

_PANEL = """<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body><h1>Dashboard</h1><p>No items.</p></body></html>"""


@dataclass
class HttpRequest:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


async def read_request(reader: asyncio.StreamReader, max_body: int, max_headers: int = 32768) -> HttpRequest | None:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(1024)
        if not chunk:
            return None
        data += chunk
        if len(data) > max_headers:
            return None
    head, rest = data.split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    if not lines or " " not in lines[0]:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    path, _, query = target.partition("?")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.lower().strip()] = value.strip()[:300]
    try:
        length = int(headers.get("content-length", "0") or 0)
    except ValueError:
        length = 0
    length = max(0, min(length, max_body))
    body = rest
    while len(body) < length:
        chunk = await reader.read(length - len(body))
        if not chunk:
            break
        body += chunk
    return HttpRequest(method=method.upper(), path=path or "/", query=query, headers=headers, body=body[:length])


def _response(status: int, reason: str, body: str, extra: tuple[str, ...] = ()) -> bytes:
    raw = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(raw)}",
        "Server: nginx/1.18.0 (Ubuntu)",
        "Connection: close",
        *extra,
        "",
        "",
    ]
    return "\r\n".join(headers).encode("ascii") + raw


def _route(request: HttpRequest) -> tuple[int, str, str, tuple[str, ...]]:
    path = request.path
    lowered = path.lower()
    login = lowered in _LOGIN_PATHS or lowered.rstrip("/") in _LOGIN_PATHS
    if request.method == "POST" and login:
        return (
            302,
            "Found",
            "",
            ("Location: /admin/dashboard", "Set-Cookie: honey_session=1; Path=/; HttpOnly"),
        )
    if lowered in {"/", "/index.html"}:
        return 200, "OK", _NGINX, ()
    if login:
        return 200, "OK", _LOGIN, ()
    if lowered.rstrip("/") == "/admin/dashboard":
        return 200, "OK", _PANEL, ()
    return 404, "Not Found", _NOT_FOUND, ()


def _header_json(headers: dict[str, str]) -> str:
    kept = {key: headers[key] for key in _KEEP_HEADERS if key in headers}
    return json.dumps(kept, ensure_ascii=False)


async def run_http(reader, writer, app, ctx) -> None:
    request = await read_request(reader, app.cfg.limits.max_http_body)
    if request is None:
        await app.store.add_event(ctx.session_id, "http_parse", "обрыв или слишком большой заголовок")
        return
    ctx.bytes_in += len(request.body) + len(request.path)
    agent = request.headers.get("user-agent", "")
    if agent:
        ctx.banner = agent[:300]
    status, reason, body, extra = _route(request)
    snippet = request.body.decode("utf-8", "replace").replace("\x00", "")[:500]
    await app.store.add_http(
        ctx.session_id,
        request.method,
        request.path,
        request.query,
        _header_json(request.headers),
        snippet,
        status,
    )
    payload = _response(status, reason, body, extra)
    ctx.bytes_out += len(payload)
    writer.write(payload)
    await writer.drain()


async def start_http(app):
    listener = app.cfg.listeners["http"]
    if not listener.enabled:
        return None

    async def handler(reader, writer):
        await serve(app, "http", reader, writer, run_http)

    server = await asyncio.start_server(handler, "0.0.0.0", listener.port)
    port = server.sockets[0].getsockname()[1]
    log.info("http слушает порт %s", port)
    return "http", port, server
