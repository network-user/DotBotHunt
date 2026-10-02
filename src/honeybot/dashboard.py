from __future__ import annotations

import asyncio
import ipaddress
import logging
from html import escape

from honeybot.config import ConfigError
from honeybot.listeners.http import read_request
from honeybot.report import reputation_line
from honeybot.util import normalize_ip, parse_intent, parse_since

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


def _mb(size: int) -> str:
    return f"{size / (1024 * 1024):.1f}"


def _params(query: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for piece in query.split("&"):
        if not piece:
            continue
        key, _, value = piece.partition("=")
        name = _hex_unescape(key)
        if name in found:
            continue
        found[name] = _hex_unescape(value)
    return found


def _hex_unescape(value: str) -> str:
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


def _filters(query: str) -> tuple[str, str, str]:
    """Токен окна, ISO-граница и метка. Чужое значение отбрасывается и не печатается."""
    params = _params(query)
    token = params.get("since", "").strip().lower()
    try:
        since = parse_since(token) if token else ""
    except ValueError:
        token = ""
        since = ""
    if token == "all":
        token = ""
    try:
        intent = parse_intent(params.get("intent", ""))
    except ValueError:
        intent = ""
    return token, since, intent


def _href(since_token: str, intent: str) -> str:
    parts = []
    if since_token:
        parts.append("since=" + since_token)
    if intent:
        parts.append("intent=" + intent)
    if not parts:
        return "/"
    return "/?" + "&".join(parts)


def _ip_href(ip: str) -> str:
    try:
        cleaned = str(ipaddress.ip_address(normalize_ip(ip)))
    except ValueError:
        return ""
    return "/ip/" + cleaned


def render_home(stats: dict, since_token: str = "", intent: str = "") -> str:
    state = "открыта" if stats.get("recording", True) else "закрыта"
    cap = int(stats.get("db_cap_bytes") or 0)
    db_line = ""
    if cap:
        db_line = (
            f"<p>База: {_mb(int(stats.get('db_bytes') or 0))} МБ из {_mb(cap)}. "
            f"Запись {escape(state)}.</p>"
        )
    filter_bits = []
    if since_token:
        filter_bits.append(f"окно {escape(since_token)}")
    if intent:
        filter_bits.append(f"метка {escape(intent)}")
    filter_line = f"<p>Фильтр: {', '.join(filter_bits)}.</p>" if filter_bits else ""
    nav = (
        f"<p><a href='{_href('', intent)}'>всё время</a> · "
        f"<a href='{_href('24h', intent)}'>сутки</a> · "
        f"<a href='{_href(since_token, '')}'>все метки</a></p>"
    )
    intent_rows = []
    for row in stats.get("top_intents") or []:
        name = row.get("intent") or ""
        try:
            safe = parse_intent(name)
        except ValueError:
            safe = ""
        label = escape(name)
        if safe:
            label = f"<a href='{escape(_href(since_token, safe))}'>{escape(safe)}</a>"
        intent_rows.append(f"<tr><td>{label}</td><td>{escape(str(row.get('n') or 0))}</td></tr>")
    intent_table = (
        "<table><thead><tr><th>Метка</th><th>Сессии</th></tr></thead><tbody>"
        + ("".join(intent_rows) or "<tr><td colspan='2'>пока пусто</td></tr>")
        + "</tbody></table>"
    )
    recent_rows = []
    for row in stats.get("recent") or []:
        sid = str(row.get("id") or "")
        sid_html = escape(sid)
        if sid.isalnum() and len(sid) <= 32:
            sid_cell = f"<a href='/session/{sid_html}'><code>{sid_html}</code></a>"
        else:
            sid_cell = f"<code>{sid_html}</code>"
        ip = str(row.get("ip") or "")
        ip_href = _ip_href(ip)
        ip_cell = f"<a href='{escape(ip_href)}'>{escape(ip)}</a>" if ip_href else escape(ip)
        recent_rows.append(
            "<tr>"
            f"<td>{sid_cell}</td>"
            f"<td>{escape(str(row.get('started_at') or ''))}</td>"
            f"<td>{ip_cell}</td>"
            f"<td>{escape(str(row.get('country') or ''))}</td>"
            f"<td>{escape(str(row.get('proto') or ''))}</td>"
            f"<td>{escape(str(row.get('primary_intent') or 'открыта'))}</td>"
            "</tr>"
        )
    recent = (
        "<table><thead><tr><th>Сессия</th><th>Время</th><th>IP</th><th>Страна</th>"
        "<th>Протокол</th><th>Метка</th></tr></thead><tbody>"
        + ("".join(recent_rows) or "<tr><td colspan='6'>пока пусто</td></tr>")
        + "</tbody></table>"
    )
    body = [
        "<h1>DotBotHunt</h1>",
        db_line,
        filter_line,
        nav,
        f"<p>Сессий: {int(stats['sessions'])}. Уникальных IP: {int(stats['unique_ips'])}. "
        f"В Spamhaus: {int(stats.get('spamhaus_listed') or 0)}.</p>",
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
        intent_table,
        "<h2>Команды</h2>",
        _table(
            ["Команда", "Раз"],
            [[row["command"], str(row["n"])] for row in stats["top_commands"]],
        ),
        "<h2>Неразобранные команды</h2>",
        _table(
            ["Команда", "Раз"],
            [[row["command"], str(row["n"])] for row in stats.get("top_unclassified") or []],
        ),
        "<h2>HTTP</h2>",
        _table(
            ["Путь", "Раз"],
            [[row["path"], str(row["n"])] for row in stats["top_paths"]],
        ),
        "<h2>События</h2>",
        _events_table(stats.get("recent_events") or []),
        "<h2>Последние сессии</h2>",
        recent,
    ]
    return _page("DotBotHunt", "\n".join(item for item in body if item))


def _events_table(events: list[dict]) -> str:
    rows = []
    for row in events:
        sid = str(row.get("session_id") or "")
        if sid.isalnum() and len(sid) <= 32:
            sid_cell = f"<a href='/session/{escape(sid)}'><code>{escape(sid)}</code></a>"
        else:
            sid_cell = escape(sid or "-")
        rows.append(
            "<tr>"
            f"<td>{escape(str(row.get('ts') or ''))}</td>"
            f"<td>{sid_cell}</td>"
            f"<td>{escape(str(row.get('kind') or ''))}</td>"
            f"<td>{escape(str(row.get('detail') or ''))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Время</th><th>Сессия</th><th>Тип</th><th>Деталь</th></tr></thead><tbody>"
        + ("".join(rows) or "<tr><td colspan='4'>пока пусто</td></tr>")
        + "</tbody></table>"
    )


def render_session(bundle: dict) -> str | None:
    session = bundle.get("session")
    if not session:
        return None
    info = bundle.get("ip_info") or {}
    ip = str(session.get("ip") or "")
    ip_href = _ip_href(ip)
    ip_html = f"<a href='{escape(ip_href)}'>{escape(ip)}</a>" if ip_href else escape(ip)
    lines = [
        "<p><a href='/'>К сводке</a></p>",
        f"<h1>Сессия {escape(session['id'])}</h1>",
        "<ul>",
        f"<li>Начало: {escape(str(session.get('started_at') or ''))}</li>",
        f"<li>Конец: {escape(str(session.get('ended_at') or 'ещё идёт'))}</li>",
        f"<li>IP: {ip_html}</li>",
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


def render_ip(view: dict) -> str | None:
    sessions = view.get("sessions") or []
    info = view.get("ip_info") or {}
    if not sessions and not info:
        return None
    ip = str(view.get("ip") or "")
    rows = []
    for row in sessions:
        sid = str(row.get("id") or "")
        sid_html = escape(sid)
        if sid.isalnum() and len(sid) <= 32:
            link = f"<a href='/session/{sid_html}'><code>{sid_html}</code></a>"
        else:
            link = f"<code>{sid_html}</code>"
        rows.append(
            "<tr>"
            f"<td>{link}</td>"
            f"<td>{escape(str(row.get('started_at') or ''))}</td>"
            f"<td>{escape(str(row.get('proto') or ''))}</td>"
            f"<td>{escape(str(row.get('primary_intent') or 'открыта'))}</td>"
            f"<td>{escape(str(row.get('username') or '-'))}</td>"
            "</tr>"
        )
    session_table = (
        "<table><thead><tr><th>Сессия</th><th>Время</th><th>Протокол</th><th>Метка</th><th>Имя</th></tr></thead><tbody>"
        + ("".join(rows) or "<tr><td colspan='5'>пока пусто</td></tr>")
        + "</tbody></table>"
    )
    total = int(view.get("total") or 0)
    extra = ""
    if total > len(sessions):
        extra = f"<p>Показаны последние {len(sessions)} из {total}.</p>"
    lines = [
        "<p><a href='/'>К сводке</a></p>",
        f"<h1>IP {escape(ip)}</h1>",
        "<ul>",
        f"<li>Провайдер: {escape(str(info.get('org') or 'неизвестно'))}</li>",
        f"<li>ASN: {escape(str(info.get('asn') or '-'))}</li>",
        f"<li>Страна: {escape(str(info.get('country') or '-'))}</li>",
        f"<li>Город: {escape(str(info.get('city') or '-'))}</li>",
        f"<li>Репутация: {escape(reputation_line(info))}</li>",
        "</ul>",
        "<h2>Сессии</h2>",
        extra,
        session_table,
        "<h2>Попытки входа</h2>",
        _table(
            ["Сессия", "Имя", "Метод", "Результат", "Секрет"],
            [
                [
                    row.get("session_id") or "-",
                    row.get("username") or "-",
                    row.get("method") or "-",
                    "принят как настоящий" if row.get("fake_accepted") else "отклонён",
                    row.get("secret") or "",
                ]
                for row in view.get("auths") or []
            ],
        ),
    ]
    return _page(f"IP {ip}", "\n".join(item for item in lines if item))


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
            token, since, intent = _filters(request.query)
            stats = await app.store.stats(since, intent)
            writer.write(_http(200, "OK", render_home(stats, token, intent)))
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
        elif path.startswith("/ip/"):
            raw_ip = path.removeprefix("/ip/").strip("/")
            try:
                ip = str(ipaddress.ip_address(normalize_ip(raw_ip)))
            except ValueError:
                writer.write(_http(404, "Not Found", _page("DotBotHunt", "<p>Нет такого адреса.</p>")))
            else:
                page = render_ip(await app.store.ip_view(ip))
                if page is None:
                    writer.write(_http(404, "Not Found", _page("DotBotHunt", "<p>Нет такого адреса.</p>")))
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
