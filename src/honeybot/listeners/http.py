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


_USER_FIELDS = ("log", "username", "user", "email", "login")
_PASS_FIELDS = ("pwd", "password", "pass", "passwd")


@dataclass
class HttpRequest:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes
    version: str = "HTTP/1.1"


def _form_unescape(value: str) -> str:
    text = value.replace("+", " ")
    out: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == "%" and index + 2 < len(text):
            try:
                out.append(chr(int(text[index + 1 : index + 3], 16)))
            except ValueError:
                out.append(text[index])
                index += 1
                continue
            index += 3
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def login_from_body(body: str) -> tuple[str, str] | None:
    fields: dict[str, str] = {}
    for part in body.split("&"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        name = _form_unescape(key).strip().lower()
        if not name or name in fields:
            continue
        fields[name] = _form_unescape(value).strip()
    user = next((fields[key] for key in _USER_FIELDS if fields.get(key)), "")
    secret = next((fields[key] for key in _PASS_FIELDS if fields.get(key)), "")
    if not user and not secret:
        return None
    return user.replace("\x00", "")[:120], secret.replace("\x00", "")[:200]


def _is_login(path: str) -> bool:
    lowered = path.lower()
    return lowered in _LOGIN_PATHS or lowered.rstrip("/") in _LOGIN_PATHS


async def read_request(
    reader: asyncio.StreamReader,
    max_body: int,
    max_headers: int = 32768,
    pending: bytearray | None = None,
) -> HttpRequest | None:
    data = bytes(pending) if pending else b""
    if pending is not None:
        pending.clear()
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
    version = parts[2] if len(parts) > 2 else "HTTP/1.0"
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
    extra = b""
    if len(rest) > length:
        extra = rest[length:]
        rest = rest[:length]
    body = rest
    while len(body) < length:
        chunk = await reader.read(length - len(body))
        if not chunk:
            break
        body += chunk
    if len(body) > length:
        extra += body[length:]
        body = body[:length]
    if pending is not None and extra:
        pending.extend(extra)
    return HttpRequest(
        method=method.upper(),
        path=path or "/",
        query=query,
        headers=headers,
        body=body,
        version=version,
    )


def _response(
    status: int,
    reason: str,
    body: str,
    extra: tuple[str, ...] = (),
    close: bool = True,
) -> bytes:
    raw = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(raw)}",
        "Server: nginx/1.18.0 (Ubuntu)",
        "Connection: close" if close else "Connection: keep-alive",
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
    pending = bytearray()
    served = 0
    while True:
        request = await read_request(reader, app.cfg.limits.max_http_body, pending=pending)
        if request is None:
            if served == 0:
                await app.store.add_event(ctx.session_id, "http_parse", "обрыв или слишком большой заголовок")
            return
        served += 1
        ctx.touch()
        ctx.bytes_in += len(request.body) + len(request.path)
        agent = request.headers.get("user-agent", "")
        if agent and not ctx.banner:
            ctx.banner = agent[:300]
        status, reason, body, extra = _route(request)
        decoded = request.body.decode("utf-8", "replace").replace("\x00", "")
        snippet = decoded[:500]
        await app.store.add_http(
            ctx.session_id,
            request.method,
            request.path,
            request.query,
            _header_json(request.headers),
            snippet,
            status,
        )
        if request.method == "POST" and _is_login(request.path):
            found = login_from_body(decoded[:4000])
            if found is not None:
                username, secret = found
                await app.store.add_auth(ctx.session_id, username, secret, "http", True)
        client_close = request.headers.get("connection", "").lower() == "close"
        http10 = request.version.upper() != "HTTP/1.1"
        payload = _response(status, reason, body, extra, close=client_close or http10)
        ctx.bytes_out += len(payload)
        writer.write(payload)
        await writer.drain()
        if client_close or http10:
            return


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
