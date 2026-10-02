from __future__ import annotations

import asyncio
import logging
from html import escape

from honeybot.config import ConfigError
from honeybot.listeners.http import read_request
from honeybot.report import reputation_line

log = logging.getLogger("honeybot")

def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>{escape(title)}</title>
<style>
body {{ font: 15px/1.45 sans-serif; margin: 2rem; color: #1c1c1c; background: #f6f4ef; }}
h1 {{ font-size: 1.4rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.4rem; background: white; }}
th, td {{ border: 1px solid #ddd; padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #efeae2; }}
a {{ color: #1d4e89; }}
code {{ font-family: ui-monospace, monospace; }}
</style></head><body>
{body}
</body></html>"""


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{escape(item)}</th>" for item in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{escape(item)}</td>" for item in row)
        body.append(f"<tr>{cells}</tr>")
    if not body:
        body.append(f"<tr><td colspan='{len(headers)}'>пока пусто</td></tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_home(stats: dict) -> str:
    body = [
        "<h1>DotBotHunt</h1>",
        f"<p>Сессий: {stats['sessions']}. Уникальных IP: {stats['unique_ips']}. "
        f"В Spamhaus: {stats.get('spamhaus_listed', 0)}.</p>",
        "<h2>Страны</h2>",
        _table(
            ["Страна", "IP"],
            [[row["country"], str(row["n"])] for row in stats.get("top_countries") or []],
        ),
        "<h2>Города</h2>",
        _table(
            ["Город", "IP"],
            [[row["city"], str(row["n"])] for row in stats.get("top_cities") or []],
        ),
        "<h2>Сети и провайдеры</h2>",
        _table(
            ["Провайдер", "ASN", "IP"],
            [[row["org"], row["asn"] or "-", str(row["n"])] for row in stats["top_orgs"]],
        ),
        "<h2>Порты</h2>",
        _table(
            ["Протокол", "Порт", "Сессии"],
            [[row["proto"], str(row["port"]), str(row["n"])] for row in stats["top_ports"]],
        ),
        "<h2>Имена</h2>",
        _table(
            ["Имя", "Попытки"],
            [[row["username"], str(row["n"])] for row in stats["top_usernames"]],
        ),
        "<h2>Метки</h2>",
        _table(
            ["Метка", "Сессии"],
            [[row["intent"], str(row["n"])] for row in stats["top_intents"]],
        ),
        "<h2>Команды</h2>",
        _table(
            ["Команда", "Раз"],
            [[row["command"], str(row["n"])] for row in stats["top_commands"]],
        ),
        "<h2>HTTP</h2>",
        _table(
            ["Путь", "Раз"],
            [[row["path"], str(row["n"])] for row in stats["top_paths"]],
        ),
        "<h2>Последние сессии</h2>",
        _table(
            ["Сессия", "IP", "Протокол", "Метка"],
            [
                [
                    row["id"],
                    row["ip"],
                    row["proto"],
                    row.get("primary_intent") or "открыта",
                ]
                for row in stats["recent"]
            ],
        ),
    ]
    # Ссылки на сессии собираются отдельно, чтобы escape не сломал href.
    links = []
    for row in stats["recent"]:
        sid = escape(row["id"])
        links.append(
            "<tr>"
            f"<td><a href='/session/{sid}'><code>{sid}</code></a></td>"
            f"<td>{escape(row['ip'])}</td>"
            f"<td>{escape(row['proto'])}</td>"
            f"<td>{escape(row.get('primary_intent') or 'открыта')}</td>"
            "</tr>"
        )
    recent = (
        "<table><thead><tr><th>Сессия</th><th>IP</th><th>Протокол</th><th>Метка</th></tr></thead><tbody>"
        + ("".join(links) or "<tr><td colspan='4'>пока пусто</td></tr>")
        + "</tbody></table>"
    )
    # Последняя таблица из _table заменяется на версию со ссылками.
    html_body = "\n".join(body)
    html_body = html_body.rsplit("<h2>Последние сессии</h2>", 1)[0]
    html_body += "<h2>Последние сессии</h2>\n" + recent
    return _page("DotBotHunt", html_body)


def render_session(bundle: dict) -> str | None:
    session = bundle.get("session")
    if not session:
        return None
    info = bundle.get("ip_info") or {}
    lines = [
        "<p><a href='/'>К сводке</a></p>",
        f"<h1>Сессия {escape(session['id'])}</h1>",
        "<ul>",
        f"<li>Начало: {escape(str(session.get('started_at') or ''))}</li>",
        f"<li>Конец: {escape(str(session.get('ended_at') or 'ещё идёт'))}</li>",
        f"<li>IP: {escape(str(session.get('ip') or ''))}</li>",
        f"<li>Провайдер: {escape(str(info.get('org') or 'неизвестно'))}</li>",
        f"<li>ASN: {escape(str(info.get('asn') or '-'))}</li>",
        f"<li>Страна: {escape(str(info.get('country') or '-'))}</li>",
        f"<li>Город: {escape(str(info.get('city') or '-'))}</li>",
        f"<li>ISP: {escape(str(info.get('isp') or '-'))}</li>",
        f"<li>Репутация: {escape(reputation_line(info))}</li>",
        f"<li>Протокол: {escape(str(session.get('proto') or ''))} порт {escape(str(session.get('dst_port') or ''))}</li>",
        f"<li>Баннер: {escape(str(session.get('client_banner') or '-'))}</li>",
        f"<li>Вход: {escape(str(session.get('auth_result') or 'none'))} пользователь {escape(str(session.get('username') or '-'))}</li>",
        f"<li>Итог: {escape(str(session.get('summary') or 'ещё не собран'))}</li>",
        "</ul>",
        "<h2>Попытки входа</h2>",
        _table(
            ["Имя", "Метод", "Результат", "Секрет"],
            [
                [
                    row.get("username") or "-",
                    row.get("method") or "-",
                    "принят как настоящий" if row.get("fake_accepted") else "отклонён",
                    row.get("secret") or "",
                ]
                for row in bundle.get("auths") or []
            ],
        ),
        "<h2>Команды</h2>",
        _table(
            ["Команда", "Метки"],
            [[row.get("raw") or "", row.get("tags") or ""] for row in bundle.get("commands") or []],
        ),
        "<h2>HTTP</h2>",
        _table(
            ["Метод", "Путь", "Код"],
            [
                [row.get("method") or "", row.get("path") or "", str(row.get("status_sent") or "")]
                for row in bundle.get("http") or []
            ],
        ),
    ]
    return _page(f"Сессия {session['id']}", "\n".join(lines))


def _http(status: int, reason: str, body: str) -> bytes:
    raw = body.encode("utf-8")
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(raw)}\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    )
    return header.encode("ascii") + raw


async def _handle(reader, writer, app) -> None:
    try:
        request = await read_request(reader, 4096)
        if request is None or request.method != "GET":
            writer.write(_http(400, "Bad Request", _page("DotBotHunt", "<p>Только GET.</p>")))
            await writer.drain()
            return
        path = request.path
        if path == "/":
            stats = await app.store.stats()
            writer.write(_http(200, "OK", render_home(stats)))
        elif path.startswith("/session/"):
            session_id = path.removeprefix("/session/").strip("/")
            if not session_id.isalnum() or len(session_id) > 32:
                writer.write(_http(404, "Not Found", _page("DotBotHunt", "<p>Нет такой сессии.</p>")))
            else:
                bundle = await app.store.bundle(session_id)
                page = render_session(bundle)
                if page is None:
                    writer.write(_http(404, "Not Found", _page("DotBotHunt", "<p>Нет такой сессии.</p>")))
                else:
                    writer.write(_http(200, "OK", page))
        else:
            writer.write(_http(404, "Not Found", _page("DotBotHunt", "<p>Нет такой страницы.</p>")))
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_dashboard(app):
    if not app.cfg.dashboard.enabled:
        return None
    host = app.cfg.dashboard.host
    if host != "127.0.0.1":
        raise ConfigError("Панель можно слушать только на 127.0.0.1")

    async def handler(reader, writer):
        await _handle(reader, writer, app)

    server = await asyncio.start_server(handler, host, app.cfg.dashboard.port)
    for sock in server.sockets or []:
        bound = sock.getsockname()[0]
        if bound != "127.0.0.1":
            server.close()
            await server.wait_closed()
            raise ConfigError("Панель открылась не на 127.0.0.1")
    port = server.sockets[0].getsockname()[1]
    log.info("панель слушает 127.0.0.1:%s", port)
    return "dashboard", port, server
