from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from html import escape

from honeybot.config import ConfigError
from honeybot.listeners.http import read_request
from honeybot.reconstruct import load_rules
from honeybot.report import intent_label, render_report, reputation_line
from honeybot.util import normalize_ip, parse_intent, parse_since

log = logging.getLogger("honeybot")

_PROTOS = ("ssh", "http", "telnet", "ftp", "smtp", "redis")
_VIEWS = {"commands", "http", "auth", "events"}
_HOT = {"miner", "reverse_shell", "fetch_and_run", "webshell", "persistence"}
_WARN = {"recon_host", "web_login_probe", "web_secret_probe", "auth_guess", "abuse_verb", "cleanup", "busybox", "unclassified"}
@dataclass
class PanelQuery:
    since_token: str = ""
    since: str = ""
    intent: str = ""
    proto: str = ""
    text: str = ""
    open_only: bool = False
    live: bool = False
    view: str = "all"


def _page(title: str, body: str, refresh: str = "") -> str:
    meta = ""
    if refresh:
        meta = f'<meta http-equiv="refresh" content="8;url={escape(refresh, quote=True)}">'
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{meta}<title>{escape(title)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #121612;
  --panel: #1b211b;
  --line: #314034;
  --ink: #e4ecdf;
  --muted: #93a396;
  --amber: #e0b15a;
  --hot: #e07a5f;
  --ok: #8fbf8a;
  --warn: #d2a15a;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font: 14px/1.45 "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
}}
a {{ color: var(--amber); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, pre, .mono {{ font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }}
header.top {{
  display: flex;
  flex-wrap: wrap;
  gap: 0.7rem 1.4rem;
  align-items: baseline;
  padding: 0.9rem 1.2rem;
  border-bottom: 1px solid var(--line);
  background: #161c16;
  position: sticky;
  top: 0;
}}
.brand {{ font-weight: 650; letter-spacing: 0.04em; }}
nav {{ display: flex; gap: 0.9rem; }}
nav a.on {{ color: var(--ink); border-bottom: 2px solid var(--amber); }}
.downloads {{ margin: 0; color: var(--muted); }}
main {{ padding: 1rem 1.2rem 2.5rem; max-width: 1180px; }}
.status {{ color: var(--muted); margin: 0 0 0.8rem; }}
.kpis {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.5rem;
  margin: 0 0 1rem;
}}
.kpi {{
  background: var(--panel);
  border: 1px solid var(--line);
  padding: 0.55rem 0.7rem;
}}
.kpi span {{ display: block; color: var(--muted); font-size: 12px; }}
.kpi strong {{ font-size: 1.25rem; font-weight: 640; }}
.filters {{ display: flex; flex-direction: column; gap: 0.35rem; margin: 0 0 1rem; }}
.filters p, .rowlinks {{ margin: 0; display: flex; flex-wrap: wrap; gap: 0.35rem 0.7rem; align-items: center; }}
.chip {{
  border: 1px solid var(--line);
  padding: 0.05rem 0.4rem;
  color: var(--muted);
}}
.chip.on {{ color: var(--ink); border-color: var(--amber); }}
form.search {{ display: flex; gap: 0.4rem; flex-wrap: wrap; }}
input[type="search"] {{
  background: #101510;
  color: var(--ink);
  border: 1px solid var(--line);
  padding: 0.3rem 0.45rem;
  min-width: 16rem;
}}
button {{
  background: #2a3328;
  color: var(--ink);
  border: 1px solid var(--line);
  padding: 0.3rem 0.6rem;
}}
h1 {{ font-size: 1.25rem; margin: 0 0 0.6rem; }}
h2 {{ font-size: 1rem; margin: 1.2rem 0 0.4rem; }}
.scroll {{ overflow-x: auto; border: 1px solid var(--line); }}
table {{ border-collapse: collapse; width: 100%; background: var(--panel); }}
th, td {{ padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }}
th {{ color: var(--muted); font-weight: 600; background: #202820; }}
tr.open td:first-child {{ box-shadow: inset 3px 0 0 var(--ok); }}
tr.hot td:first-child {{ box-shadow: inset 3px 0 0 var(--hot); }}
.tag {{ color: var(--muted); }}
.hot {{ color: var(--hot); }}
.warn {{ color: var(--warn); }}
.ok {{ color: var(--ok); }}
.hit {{
  border: 1px solid var(--line);
  background: var(--panel);
  margin: 0 0 0.45rem;
  padding: 0.45rem 0.6rem;
}}
.hit .meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 0.7rem;
  color: var(--muted);
  font-size: 12px;
}}
.hit pre {{
  margin: 0.35rem 0 0;
  white-space: pre-wrap;
  word-break: break-word;
}}
.hit.command {{ border-left: 3px solid var(--amber); }}
.hit.http {{ border-left: 3px solid #7ea0c4; }}
.hit.auth {{ border-left: 3px solid var(--hot); }}
.hit.event {{ border-left: 3px solid var(--ok); }}
.facts {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 0.35rem 1rem;
  margin: 0 0 1rem;
}}
.facts div {{ border-bottom: 1px solid var(--line); padding: 0.2rem 0; }}
.facts span {{ display: block; color: var(--muted); font-size: 12px; }}
.cols {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 0.8rem;
}}
.empty {{ color: var(--muted); }}
@media (max-width: 700px) {{
  header.top, main {{ padding-left: 0.7rem; padding-right: 0.7rem; }}
  input[type="search"] {{ min-width: 0; width: 100%; }}
}}
</style></head><body>
{body}
</body></html>"""


def _qenc(value: str) -> str:
    out = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        if char.isalnum() or char in "-_.":
            out.append(char)
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def _hex_unescape(value: str) -> str:
    text = value.replace("+", " ")
    raw = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "%" and index + 2 < len(text):
            try:
                raw.append(int(text[index + 1 : index + 3], 16))
            except ValueError:
                raw.extend(text[index].encode("utf-8"))
                index += 1
                continue
            index += 3
            continue
        raw.extend(text[index].encode("utf-8"))
        index += 1
    return raw.decode("utf-8", "replace")


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


def _clean_text(value: str) -> str:
    return "".join(ch for ch in value if ch >= " " and ch != "\x7f").strip()[:80]


def _filters(query: str) -> PanelQuery:
    """Чужое since и intent отбрасываются и на страницу не печатаются."""
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
    proto = params.get("proto", "").strip().lower()
    if proto not in _PROTOS:
        proto = ""
    view = params.get("view", "").strip().lower()
    if view not in _VIEWS:
        view = "all"
    return PanelQuery(
        since_token=token,
        since=since,
        intent=intent,
        proto=proto,
        text=_clean_text(params.get("q", "")),
        open_only=params.get("open", "") == "1",
        live=params.get("live", "") == "1",
        view=view,
    )


def _pairs(query: PanelQuery, **over: str) -> list[tuple[str, str]]:
    values = {
        "since": query.since_token,
        "intent": query.intent,
        "proto": query.proto,
        "q": query.text,
        "open": "1" if query.open_only else "",
        "live": "1" if query.live else "",
        "view": "" if query.view in {"", "all"} else query.view,
    }
    for key, value in over.items():
        values[key] = value
    pairs = []
    for key in ("since", "intent", "proto", "q", "open", "live", "view"):
        value = values.get(key) or ""
        if value:
            pairs.append((key, value))
    return pairs


def _href(path: str, query: PanelQuery, **over: str) -> str:
    parts = [f"{key}={_qenc(value)}" for key, value in _pairs(query, **over)]
    if not parts:
        return path
    return path + "?" + "&".join(parts)


def _report_href(fmt: str, query: PanelQuery) -> str:
    parts = []
    if query.since_token:
        parts.append("since=" + _qenc(query.since_token))
    if query.intent:
        parts.append("intent=" + _qenc(query.intent))
    path = "/report." + fmt
    if not parts:
        return path
    return path + "?" + "&".join(parts)


def _ip_href(ip: str) -> str:
    try:
        cleaned = str(ipaddress.ip_address(normalize_ip(ip)))
    except ValueError:
        return ""
    return "/ip/" + cleaned


def _sid_html(sid: object) -> str:
    text = str(sid or "")
    safe = escape(text)
    if text.isalnum() and len(text) <= 32:
        return f"<a href='/session/{safe}'><code>{safe}</code></a>"
    return f"<code>{safe}</code>"


def _ip_html(ip: object) -> str:
    text = str(ip or "")
    href = _ip_href(text)
    if not href:
        return escape(text)
    return f"<a href='{escape(href)}'>{escape(text)}</a>"


def _intent_html(name: object) -> str:
    text = str(name or "")
    if not text:
        return "<span class='ok'>открыта</span>"
    css = "hot" if text in _HOT else "warn" if text in _WARN else "tag"
    return f"<span class='{css}'>{escape(intent_label(text))}</span>"


def _short(value: object, limit: int = 500) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _size(value: object) -> str:
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        size = 0
    if size < 1024:
        return f"{size} Б"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} КБ"
    return f"{size / (1024 * 1024):.1f} МБ"


def _mb(size: int) -> str:
    return f"{size / (1024 * 1024):.1f}"


def _grid(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{escape(item)}</th>" for item in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{cell}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    if not body:
        body.append(f"<tr><td colspan='{len(headers)}'>пока пусто</td></tr>")
    return (
        "<div class='scroll'><table><thead><tr>"
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def _plain_grid(headers: list[str], rows: list[list[object]]) -> str:
    return _grid(headers, [[escape(str(cell)) for cell in row] for row in rows])


def _chrome(query: PanelQuery, here: str) -> str:
    home = " class='on'" if here == "home" else ""
    feed = " class='on'" if here == "feed" else ""
    reports = (
        "<p class='downloads'>Скачать отчёт: "
        f"<a href='{escape(_report_href('html', query))}'>HTML</a> · "
        f"<a href='{escape(_report_href('json', query))}'>JSON</a> · "
        f"<a href='{escape(_report_href('md', query))}'>Markdown</a> · "
        f"<a href='{escape(_report_href('csv', query))}'>CSV</a></p>"
    )
    return (
        "<header class='top'>"
        "<div class='brand'>DotBotHunt</div>"
        "<nav>"
        f"<a href='{escape(_href('/', query))}'{home}>Сводка</a>"
        f"<a href='{escape(_href('/feed', query))}'{feed}>Журнал</a>"
        "</nav>"
        f"{reports}"
        "</header>"
    )


def _status(data: dict, query: PanelQuery, path: str) -> str:
    state = "Запись открыта" if data.get("recording", True) else "Запись закрыта"
    cap = int(data.get("db_cap_bytes") or 0)
    db_line = ""
    if cap:
        db_line = f" База {_mb(int(data.get('db_bytes') or 0))} МБ из {_mb(cap)}."
    live = "Обновление каждые 8 с." if query.live else "Автообновление выключено."
    pause = _href(path, query, live="" if query.live else "1")
    pause_label = "пауза" if query.live else "следить"
    bits = []
    if query.since_token:
        bits.append(f"окно {escape(query.since_token)}")
    if query.intent:
        bits.append(f"метка {escape(query.intent)}")
    if query.proto:
        bits.append(f"протокол {escape(query.proto)}")
    if query.open_only:
        bits.append("только открытые")
    if query.text:
        bits.append(f"поиск {escape(query.text)}")
    active = f" Фильтр: {', '.join(bits)}." if bits else ""
    return (
        f"<p class='status'>{state}.{db_line} {live} "
        f"<a href='{escape(pause)}'>{pause_label}</a>.{active}</p>"
    )


def _kpis(data: dict) -> str:
    cards = [
        ("Сессий", data.get("sessions")),
        ("Открытых", data.get("open_sessions")),
        ("IP", data.get("unique_ips")),
        ("Spamhaus", data.get("spamhaus_listed")),
        ("Команд", data.get("n_commands")),
        ("HTTP", data.get("n_http")),
        ("Входов", data.get("n_auths")),
    ]
    parts = []
    for label, value in cards:
        parts.append(f"<div class='kpi'><span>{escape(label)}</span><strong>{int(value or 0)}</strong></div>")
    return "<section class='kpis'>" + "".join(parts) + "</section>"


def _chip(href: str, label: str, on: bool) -> str:
    css = "chip on" if on else "chip"
    return f"<a class='{css}' href='{escape(href)}'>{escape(label)}</a>"


def _filters_bar(query: PanelQuery, path: str) -> str:
    windows = [
        _chip(_href(path, query, since=""), "всё время", query.since_token == ""),
        _chip(_href(path, query, since="30m"), "30 мин", query.since_token == "30m"),
        _chip(_href(path, query, since="24h"), "сутки", query.since_token == "24h"),
        _chip(_href(path, query, since="7d"), "7 дней", query.since_token == "7d"),
    ]
    protos = [_chip(_href(path, query, proto=""), "все протоколы", query.proto == "")]
    protos.extend(
        _chip(_href(path, query, proto=name), name, query.proto == name) for name in _PROTOS
    )
    intents = [_chip(_href(path, query, intent=""), "все метки", query.intent == "")]
    for name in load_rules().order:
        intents.append(_chip(_href(path, query, intent=name), name, query.intent == name))
    opened = _chip(
        _href(path, query, open="" if query.open_only else "1"),
        "только открытые",
        query.open_only,
    )
    hidden = []
    for key, value in _pairs(query):
        if key == "q":
            continue
        hidden.append(
            f"<input type='hidden' name='{escape(key, quote=True)}' value='{escape(value, quote=True)}'>"
        )
    form = (
        "<form class='search' method='get' action='"
        + escape(path, quote=True)
        + "'>"
        + "".join(hidden)
        + f"<input type='search' name='q' value='{escape(query.text, quote=True)}' "
        + "placeholder='команда, путь или имя' maxlength='80'>"
        + "<button type='submit'>Найти</button></form>"
    )
    views = ""
    if path == "/feed":
        labels = [("all", "всё"), ("commands", "команды"), ("http", "HTTP"), ("auth", "входы"), ("events", "события")]
        links = [
            _chip(_href(path, query, view="" if name == "all" else name), label, query.view == name)
            for name, label in labels
        ]
        views = "<p>" + "".join(links) + "</p>"
    return (
        "<section class='filters'>"
        f"<p>{''.join(windows)}</p>"
        f"<p>{''.join(protos)}</p>"
        f"<p>{''.join(intents)}</p>"
        f"<p>{opened}</p>"
        f"{views}{form}"
        "</section>"
    )


def _session_rows(rows: list[dict]) -> str:
    body = []
    for row in rows:
        intent = str(row.get("primary_intent") or "")
        css = "open" if not row.get("ended_at") else "hot" if intent in _HOT else ""
        klass = f" class='{css}'" if css else ""
        place = ", ".join(
            part
            for part in (str(row.get("country") or ""), str(row.get("city") or ""))
            if part
        )
        org = str(row.get("org") or "")
        where = escape(place or "-")
        if org:
            where += "<br><span class='tag'>" + escape(org) + "</span>"
        user = escape(str(row.get("username") or "-"))
        summary = escape(_short(row.get("summary") or "", 180))
        body.append(
            f"<tr{klass}>"
            f"<td>{_sid_html(row.get('id'))}<br><span class='tag'>{escape(str(row.get('started_at') or ''))}</span></td>"
            f"<td>{_ip_html(row.get('ip'))}<br>{where}</td>"
            f"<td class='mono'>{escape(str(row.get('proto') or ''))}:{escape(str(row.get('dst_port') or ''))}</td>"
            f"<td>{user}</td>"
            f"<td>{_intent_html(intent)}<br><span class='tag'>{summary}</span></td>"
            f"<td>{int(row.get('command_count') or 0)}<br><span class='tag'>{escape(_size(row.get('bytes_in')))}</span></td>"
            "</tr>"
        )
    return (
        "<div class='scroll'><table><thead><tr>"
        "<th>Сессия</th><th>IP</th><th>Куда</th><th>Имя</th><th>Метка</th><th>Строк</th>"
        "</tr></thead><tbody>"
        + ("".join(body) or "<tr><td colspan='6'>пока пусто</td></tr>")
        + "</tbody></table></div>"
    )


def _command_hits(rows: list[dict], limit: int | None = None) -> str:
    chosen = rows if limit is None else rows[:limit]
    if not chosen:
        return "<p class='empty'>пока пусто</p>"
    parts = []
    for row in chosen:
        code = row.get("exit_sent")
        code_html = "" if code is None else f"<span>код {escape(str(code))}</span>"
        tags = escape(str(row.get("tags") or ""))
        tag_html = f"<span>{tags}</span>" if tags else ""
        parts.append(
            "<article class='hit command'>"
            "<div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time>"
            "<span>команда</span>"
            f"{_ip_html(row.get('ip'))}"
            f"{_sid_html(row.get('session_id'))}"
            f"<span>{escape(str(row.get('proto') or ''))}</span>"
            f"<span>{escape(str(row.get('channel') or ''))}</span>"
            f"{code_html}{tag_html}"
            "</div>"
            f"<pre>{escape(_short(row.get('raw') or '', 1200))}</pre>"
            "</article>"
        )
    return "".join(parts)


def _http_hits(rows: list[dict], limit: int | None = None) -> str:
    chosen = rows if limit is None else rows[:limit]
    if not chosen:
        return "<p class='empty'>пока пусто</p>"
    parts = []
    for row in chosen:
        query = str(row.get("query") or "")
        query_html = f"<pre>?{escape(_short(query, 400))}</pre>" if query else ""
        body = str(row.get("body_snippet") or "")
        body_html = f"<pre>{escape(_short(body, 500))}</pre>" if body else ""
        path = str(row.get("path") or "")
        parts.append(
            "<article class='hit http'>"
            "<div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time>"
            "<span>HTTP</span>"
            f"{_ip_html(row.get('ip'))}"
            f"{_sid_html(row.get('session_id'))}"
            f"<span>{escape(str(row.get('status_sent') or ''))}</span>"
            f"<span>{escape(str(row.get('tags') or ''))}</span>"
            "</div>"
            f"<pre>{escape(str(row.get('method') or ''))} {escape(_short(path, 600))}</pre>"
            f"{query_html}{body_html}"
            "</article>"
        )
    return "".join(parts)


def _auth_hits(rows: list[dict], limit: int | None = None) -> str:
    chosen = rows if limit is None else rows[:limit]
    if not chosen:
        return "<p class='empty'>пока пусто</p>"
    parts = []
    for row in chosen:
        mark = "принят как настоящий" if row.get("fake_accepted") else "отклонён"
        parts.append(
            "<article class='hit auth'>"
            "<div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time>"
            "<span>вход</span>"
            f"{_ip_html(row.get('ip'))}"
            f"{_sid_html(row.get('session_id'))}"
            f"<span>{escape(str(row.get('method') or ''))}</span>"
            f"<span>{escape(mark)}</span>"
            "</div>"
            f"<pre>{escape(str(row.get('username') or '-'))}  {escape(str(row.get('secret') or ''))}</pre>"
            "</article>"
        )
    return "".join(parts)


def _event_hits(rows: list[dict], limit: int | None = None) -> str:
    chosen = rows if limit is None else rows[:limit]
    if not chosen:
        return "<p class='empty'>пока пусто</p>"
    parts = []
    for row in chosen:
        parts.append(
            "<article class='hit event'>"
            "<div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time>"
            "<span>событие</span>"
            f"{_sid_html(row.get('session_id'))}"
            f"<span>{escape(str(row.get('kind') or ''))}</span>"
            "</div>"
            f"<pre>{escape(_short(row.get('detail') or '', 500))}</pre>"
            "</article>"
        )
    return "".join(parts)


def _merged(data: dict, view: str) -> str:
    items: list[tuple[str, str, str]] = []
    if view in {"all", "commands"}:
        items.extend(("command", str(row.get("ts") or ""), _command_hits([row])) for row in data.get("log_commands") or [])
    if view in {"all", "http"}:
        items.extend(("http", str(row.get("ts") or ""), _http_hits([row])) for row in data.get("log_http") or [])
    if view in {"all", "auth"}:
        items.extend(("auth", str(row.get("ts") or ""), _auth_hits([row])) for row in data.get("log_auths") or [])
    if view in {"all", "events"}:
        items.extend(("event", str(row.get("ts") or ""), _event_hits([row])) for row in data.get("recent_events") or [])
    items.sort(key=lambda item: item[1], reverse=True)
    if not items:
        return "<p class='empty'>пока пусто</p>"
    return "".join(html for _kind, _ts, html in items[:160])


def render_home(data: dict, query: PanelQuery) -> str:
    refresh = _href("/", query) if query.live else ""
    aggregates = (
        "<div class='cols'>"
        "<section><h2>Страны</h2>"
        + _plain_grid(
            ["Страна", "IP"],
            [[row.get("country") or "", row.get("n") or 0] for row in data.get("top_countries") or []],
        )
        + "</section><section><h2>Города</h2>"
        + _plain_grid(
            ["Город", "IP"],
            [[row.get("city") or "", row.get("n") or 0] for row in data.get("top_cities") or []],
        )
        + "</section><section><h2>Сети</h2>"
        + _plain_grid(
            ["Провайдер", "ASN", "IP"],
            [[row.get("org") or "", row.get("asn") or "-", row.get("n") or 0] for row in data.get("top_orgs") or []],
        )
        + "</section><section><h2>Порты</h2>"
        + _plain_grid(
            ["Протокол", "Порт", "Сессии"],
            [[row.get("proto") or "", row.get("port") or "", row.get("n") or 0] for row in data.get("top_ports") or []],
        )
        + "</section><section><h2>Имена</h2>"
        + _plain_grid(
            ["Имя", "Попытки"],
            [[row.get("username") or "", row.get("n") or 0] for row in data.get("top_usernames") or []],
        )
        + "</section><section><h2>Метки</h2>"
        + _grid(
            ["Метка", "Сессии"],
            [
                [_intent_html(row.get("intent")), escape(str(row.get("n") or 0))]
                for row in data.get("top_intents") or []
            ],
        )
        + "</section><section><h2>Команды</h2>"
        + _plain_grid(
            ["Команда", "Раз"],
            [[_short(row.get("command") or "", 240), row.get("n") or 0] for row in data.get("top_commands") or []],
        )
        + "</section><section><h2>Неразобранные</h2>"
        + _plain_grid(
            ["Команда", "Раз"],
            [[_short(row.get("command") or "", 240), row.get("n") or 0] for row in data.get("top_unclassified") or []],
        )
        + "</section><section><h2>Пути HTTP</h2>"
        + _plain_grid(
            ["Путь", "Раз"],
            [[_short(row.get("path") or "", 240), row.get("n") or 0] for row in data.get("top_paths") or []],
        )
        + "</section></div>"
    )
    body = (
        _chrome(query, "home")
        + "<main>"
        + _status(data, query, "/")
        + _kpis(data)
        + _filters_bar(query, "/")
        + "<h2>Последние сессии</h2>"
        + _session_rows(data.get("recent") or [])
        + "<h2>Лента команд</h2>"
        + _command_hits(data.get("log_commands") or [], 30)
        + "<h2>HTTP</h2>"
        + _http_hits(data.get("log_http") or [], 20)
        + "<h2>Входы</h2>"
        + _auth_hits(data.get("log_auths") or [], 20)
        + "<h2>События</h2>"
        + _event_hits(data.get("recent_events") or [], 20)
        + aggregates
        + "</main>"
    )
    return _page("DotBotHunt", body, refresh)


def render_feed(data: dict, query: PanelQuery) -> str:
    refresh = _href("/feed", query) if query.live else ""
    body = (
        _chrome(query, "feed")
        + "<main><h1>Журнал</h1>"
        + _status(data, query, "/feed")
        + _kpis(data)
        + _filters_bar(query, "/feed")
        + _merged(data, query.view)
        + "</main>"
    )
    return _page("Журнал", body, refresh)


def _fact(label: str, value: str) -> str:
    return f"<div><span>{escape(label)}</span>{value}</div>"


def render_session(bundle: dict) -> str | None:
    session = bundle.get("session")
    if not session:
        return None
    info = bundle.get("ip_info") or {}
    ip = str(session.get("ip") or "")
    facts = [
        _fact("Начало", escape(str(session.get("started_at") or ""))),
        _fact("Конец", escape(str(session.get("ended_at") or "ещё идёт"))),
        _fact("IP", _ip_html(ip)),
        _fact("Провайдер", escape(str(info.get("org") or "неизвестно"))),
        _fact("ASN", escape(str(info.get("asn") or "-"))),
        _fact("Префикс", escape(str(info.get("prefix") or "-"))),
        _fact("Страна", escape(str(info.get("country") or "-"))),
        _fact("Город", escape(str(info.get("city") or "-"))),
        _fact("ISP", escape(str(info.get("isp") or "-"))),
        _fact("rDNS", escape(str(info.get("rdns") or "-"))),
        _fact("Репутация", escape(reputation_line(info))),
        _fact(
            "Куда",
            escape(f"{session.get('proto') or ''} {session.get('dst_port') or ''} ← {session.get('src_port') or ''}"),
        ),
        _fact("Баннер", escape(str(session.get("client_banner") or "-"))),
        _fact(
            "Вход",
            escape(f"{session.get('auth_result') or 'none'} {session.get('username') or '-'}"),
        ),
        _fact("Байт", escape(f"вход {_size(session.get('bytes_in'))}, выход {_size(session.get('bytes_out'))}")),
        _fact("Строк", escape(str(session.get("command_count") or 0))),
        _fact("Итог", escape(str(session.get("summary") or "ещё не собран"))),
    ]
    steps: list[tuple[str, str]] = []
    for row in bundle.get("auths") or []:
        mark = "принят как настоящий" if row.get("fake_accepted") else "отклонён"
        html = (
            "<article class='hit auth'><div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time><span>вход</span>"
            f"<span>{escape(str(row.get('method') or ''))}</span><span>{escape(mark)}</span>"
            "</div>"
            f"<pre>{escape(str(row.get('username') or '-'))}  {escape(str(row.get('secret') or ''))}</pre>"
            "</article>"
        )
        steps.append((str(row.get("ts") or ""), html))
    for row in bundle.get("commands") or []:
        code = row.get("exit_sent")
        code_html = "" if code is None else f"<span>код {escape(str(code))}</span>"
        html = (
            "<article class='hit command'><div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time><span>команда</span>"
            f"<span>{escape(str(row.get('channel') or ''))}</span>{code_html}"
            f"<span>{escape(str(row.get('tags') or ''))}</span>"
            "</div><pre>"
            + escape(str(row.get("raw") or ""))
            + "</pre></article>"
        )
        steps.append((str(row.get("ts") or ""), html))
    for row in bundle.get("http") or []:
        query = str(row.get("query") or "")
        body = str(row.get("body_snippet") or "")
        headers = str(row.get("headers_json") or "")
        extra = ""
        if query:
            extra += f"<pre>?{escape(query)}</pre>"
        if body:
            extra += f"<pre>{escape(body)}</pre>"
        if headers:
            extra += f"<pre>{escape(_short(headers, 1500))}</pre>"
        html = (
            "<article class='hit http'><div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time><span>HTTP</span>"
            f"<span>{escape(str(row.get('status_sent') or ''))}</span>"
            f"<span>{escape(str(row.get('tags') or ''))}</span></div><pre>"
            + escape(f"{row.get('method') or ''} {row.get('path') or ''}")
            + f"</pre>{extra}</article>"
        )
        steps.append((str(row.get("ts") or ""), html))
    for row in bundle.get("events") or []:
        html = (
            "<article class='hit event'><div class='meta'>"
            f"<time>{escape(str(row.get('ts') or ''))}</time><span>событие</span>"
            f"<span>{escape(str(row.get('kind') or ''))}</span></div><pre>"
            + escape(str(row.get("detail") or ""))
            + "</pre></article>"
        )
        steps.append((str(row.get("ts") or ""), html))
    steps.sort(key=lambda item: item[0])
    trail = "".join(html for _ts, html in steps) or "<p class='empty'>пока пусто</p>"
    page = (
        _chrome(PanelQuery(), "")
        + "<main><p><a href='/'>К сводке</a> · <a href='/feed'>К журналу</a></p>"
        + f"<h1>Сессия {escape(str(session['id']))}</h1>"
        + "<section class='facts'>"
        + "".join(facts)
        + "</section><h2>Ход</h2>"
        + trail
        + "</main>"
    )
    return _page(f"Сессия {session['id']}", page)


def render_ip(view: dict) -> str | None:
    sessions = view.get("sessions") or []
    info = view.get("ip_info") or {}
    if not sessions and not info:
        return None
    ip = str(view.get("ip") or "")
    rows = []
    for row in sessions:
        rows.append(
            [
                _sid_html(row.get("id")),
                escape(str(row.get("started_at") or "")),
                escape(str(row.get("ended_at") or "идёт")),
                escape(f"{row.get('proto') or ''}:{row.get('dst_port') or ''}"),
                _intent_html(row.get("primary_intent")),
                escape(str(row.get("username") or "-")),
                escape(str(row.get("command_count") or 0)),
                escape(_short(row.get("summary") or "", 160)),
            ]
        )
    total = int(view.get("total") or 0)
    extra = ""
    if total > len(sessions):
        extra = f"<p class='status'>Показаны последние {len(sessions)} из {total}.</p>"
    score = info.get("abuse_score")
    reports = info.get("abuse_reports")
    abuse = "-"
    if isinstance(score, int) and not isinstance(score, bool):
        abuse = str(score)
        if isinstance(reports, int) and not isinstance(reports, bool):
            abuse += f", жалоб {reports}"
    facts = [
        _fact("Провайдер", escape(str(info.get("org") or "неизвестно"))),
        _fact("ASN", escape(str(info.get("asn") or "-"))),
        _fact("Префикс", escape(str(info.get("prefix") or "-"))),
        _fact("Страна", escape(str(info.get("country") or "-"))),
        _fact("Город", escape(str(info.get("city") or "-"))),
        _fact("ISP", escape(str(info.get("isp") or "-"))),
        _fact("rDNS", escape(str(info.get("rdns") or "-"))),
        _fact("Репутация", escape(reputation_line(info))),
        _fact("AbuseIPDB", escape(abuse)),
        _fact("Справка", escape(str(info.get("looked_up_at") or "-"))),
    ]
    page = (
        _chrome(PanelQuery(), "")
        + "<main><p><a href='/'>К сводке</a> · <a href='/feed'>К журналу</a></p>"
        + f"<h1>IP {escape(ip)}</h1>"
        + "<section class='facts'>"
        + "".join(facts)
        + "</section><h2>Сессии</h2>"
        + extra
        + _grid(
            ["Сессия", "Начало", "Конец", "Куда", "Метка", "Имя", "Строк", "Итог"],
            rows,
        )
        + "<h2>Входы</h2>"
        + _auth_hits(view.get("auths") or [])
        + "<h2>Команды</h2>"
        + _command_hits(view.get("commands") or [])
        + "<h2>HTTP</h2>"
        + _http_hits(view.get("http") or [])
        + "</main>"
    )
    return _page(f"IP {ip}", page)


_REPORT_FILES = {
    "/report.html": ("html", "text/html; charset=utf-8", "honeybot-report.html"),
    "/report.json": ("json", "application/json; charset=utf-8", "honeybot-report.json"),
    "/report.md": ("md", "text/markdown; charset=utf-8", "honeybot-report.md"),
    "/report.csv": ("csv", "text/csv; charset=utf-8", "honeybot-report.csv"),
}


def _download(content_type: str, filename: str, body: str) -> bytes:
    raw = body.encode("utf-8")
    header = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(raw)}\r\n"
        f"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    )
    return header.encode("ascii") + raw


def _http(status: int, reason: str, body: str) -> bytes:
    raw = body.encode("utf-8")
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(raw)}\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    )
    return header.encode("ascii") + raw


async def _panel(app, query: PanelQuery) -> dict:
    return await app.store.panel(query.since, query.intent, query.proto, query.text, query.open_only)


async def _handle(reader, writer, app) -> None:
    try:
        request = await read_request(reader, 4096)
        if request is None or request.method != "GET":
            writer.write(_http(400, "Bad Request", _page("DotBotHunt", "<p>Только GET.</p>")))
            await writer.drain()
            return
        path = request.path
        if path in {"/", "/feed"}:
            query = _filters(request.query)
            data = await _panel(app, query)
            if path == "/":
                page = render_home(data, query)
            else:
                page = render_feed(data, query)
            writer.write(_http(200, "OK", page))
        elif path in _REPORT_FILES:
            fmt, content_type, filename = _REPORT_FILES[path]
            query = _filters(request.query)
            body = render_report(fmt, await app.store.report(query.since, query.intent))
            writer.write(_download(content_type, filename, body))
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
