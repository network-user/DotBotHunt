from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from html import escape


def spamhaus_label(value: str) -> str:
    return {
        "listed": "в списке Spamhaus",
        "clean": "нет в Spamhaus",
        "unknown": "Spamhaus не ответил",
    }.get(value or "", "")


def reputation_line(info: dict) -> str:
    parts: list[str] = []
    label = spamhaus_label(str(info.get("spamhaus") or ""))
    if label:
        parts.append(label)
    score = info.get("abuse_score")
    if isinstance(score, int) and not isinstance(score, bool):
        reports = info.get("abuse_reports")
        extra = f", жалоб {reports}" if isinstance(reports, int) and not isinstance(reports, bool) else ""
        parts.append(f"AbuseIPDB {score}{extra}")
    return ", ".join(parts) if parts else "-"


def _plain(value: object) -> str:
    """Текст для терминала оператора: C0/C1 не доходят до интерпретатора."""
    text = "" if value is None else str(value)
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char in "\n\t":
            out.append(char)
        elif code < 32:
            out.append("^" + chr(64 + code))
        elif code == 127:
            out.append("^?")
        elif 0x80 <= code <= 0x9F:
            out.append("?")
        else:
            out.append(char)
    return "".join(out)


def _mb(size: int) -> str:
    return f"{size / (1024 * 1024):.1f}"


def format_stats(stats: dict) -> str:
    lines = []
    if stats.get("intent"):
        lines.append(f"Метка: {_plain(stats['intent'])}")
    if stats.get("since"):
        lines.append(f"Окно с: {_plain(stats['since'])}")
    if stats.get("db_cap_bytes"):
        state = "открыта" if stats.get("recording", True) else "закрыта"
        lines.append(
            f"База: {_mb(int(stats.get('db_bytes') or 0))} МБ из "
            f"{_mb(int(stats['db_cap_bytes']))}. Запись {state}."
        )
    lines.extend(
        [
            f"Сессий: {stats['sessions']}",
            f"Уникальных IP: {stats['unique_ips']}",
            f"IP в Spamhaus: {stats.get('spamhaus_listed', 0)}",
            "",
            "Страны:",
        ]
    )
    lines.extend(
        _rows(stats.get("top_countries") or [], lambda row: f"  {_plain(row['country'])}  {row['n']}")
    )
    lines.append("")
    lines.append("Города:")
    lines.extend(_rows(stats.get("top_cities") or [], lambda row: f"  {_plain(row['city'])}  {row['n']}"))
    lines.append("")
    lines.append("Сети и провайдеры:")
    lines.extend(
        _rows(
            stats["top_orgs"],
            lambda row: f"  {_plain(row['org'])} AS{_plain(row['asn'] or '?')}  {row['n']}",
        )
    )
    lines.append("")
    lines.append("Порты:")
    lines.extend(
        _rows(stats["top_ports"], lambda row: f"  {_plain(row['proto'])} {row['port']}  {row['n']}")
    )
    lines.append("")
    lines.append("Имена:")
    lines.extend(
        _rows(stats["top_usernames"], lambda row: f"  {_plain(row['username'])}  {row['n']}")
    )
    lines.append("")
    lines.append("Метки:")
    lines.extend(_rows(stats["top_intents"], lambda row: f"  {_plain(row['intent'])}  {row['n']}"))
    lines.append("")
    lines.append("Команды:")
    lines.extend(
        _rows(stats["top_commands"], lambda row: f"  {_plain(row['command'])}  {row['n']}")
    )
    lines.append("")
    lines.append("HTTP-пути:")
    lines.extend(_rows(stats["top_paths"], lambda row: f"  {_plain(row['path'])}  {row['n']}"))
    lines.append("")
    lines.append("Неразобранные команды:")
    lines.extend(
        _rows(
            stats.get("top_unclassified") or [],
            lambda row: f"  {_plain(row['command'])}  {row['n']}",
        )
    )
    lines.append("")
    lines.append("События:")
    events = stats.get("recent_events") or []
    if not events:
        lines.append("  пока пусто")
    else:
        for row in events:
            lines.append(
                f"  {_plain(row.get('ts') or '')}  {_plain(row.get('kind') or '')}"
                f"  {_plain(row.get('detail') or '')}"
            )
    lines.append("")
    lines.append("Последние сессии:")
    if not stats["recent"]:
        lines.append("  пока пусто")
    else:
        for row in stats["recent"]:
            intent = row.get("primary_intent") or "открыта"
            when = row.get("started_at") or ""
            country = row.get("country") or ""
            extra = f"  {_plain(when)}" if when else ""
            if country:
                extra += f"  {_plain(country)}"
            lines.append(
                f"  {_plain(row['id'])}  {_plain(row['ip'])}  {_plain(row['proto'])}  {_plain(intent)}{extra}"
            )
    return "\n".join(lines) + "\n"


def format_session(bundle: dict) -> str:
    session = bundle.get("session")
    if not session:
        return "Сессия не найдена\n"
    info = bundle.get("ip_info") or {}
    lines = [
        f"Сессия {_plain(session['id'])}",
        f"Начало: {_plain(session.get('started_at') or '')}",
        f"Конец: {_plain(session.get('ended_at') or 'ещё идёт')}",
        (
            f"IP: {_plain(session.get('ip'))}  провайдер: {_plain(info.get('org') or 'неизвестно')}"
            f"  ASN: {_plain(info.get('asn') or '-')}  страна: {_plain(info.get('country') or '-')}"
            f"  город: {_plain(info.get('city') or '-')}  ISP: {_plain(info.get('isp') or '-')}"
            f"  rdns: {_plain(info.get('rdns') or '-')}"
        ),
        f"Репутация: {_plain(reputation_line(info))}",
        f"Протокол: {_plain(session.get('proto'))}  порт {_plain(session.get('dst_port'))}",
        f"Баннер клиента: {_plain(session.get('client_banner') or '-')}",
        f"Вход: {_plain(session.get('auth_result') or 'none')}  пользователь: {_plain(session.get('username') or '-')}",
        f"Байт входящих: {session.get('bytes_in') or 0}  исходящих: {session.get('bytes_out') or 0}",
        f"Итог: {_plain(session.get('summary') or 'ещё не собран')}",
        "",
        "Попытки входа:",
    ]
    auths = bundle.get("auths") or []
    if not auths:
        lines.append("  нет")
    for row in auths:
        mark = "принят как настоящий" if row.get("fake_accepted") else "отклонён"
        lines.append(
            f"  {_plain(row.get('username') or '-')}  {_plain(row.get('method') or '-')}"
            f"  {mark}  {_plain(row.get('secret') or '')}"
        )
    lines.append("")
    lines.append("Команды:")
    commands = bundle.get("commands") or []
    if not commands:
        lines.append("  нет")
    for row in commands:
        tags = _plain(row.get("tags") or "")
        suffix = f"  [{tags}]" if tags else ""
        lines.append(f"  {_plain(row.get('raw'))}{suffix}")
    lines.append("")
    lines.append("HTTP:")
    http_rows = bundle.get("http") or []
    if not http_rows:
        lines.append("  нет")
    for row in http_rows:
        lines.append(
            f"  {_plain(row.get('method'))} {_plain(row.get('path'))}  {_plain(row.get('status_sent'))}"
        )
    return "\n".join(lines) + "\n"


def stats_json(stats: dict) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "sessions": stats["sessions"],
        "unique_ips": stats["unique_ips"],
        "spamhaus_listed": stats.get("spamhaus_listed", 0),
        "top_countries": stats.get("top_countries") or [],
        "top_cities": stats.get("top_cities") or [],
        "top_orgs": stats["top_orgs"],
        "top_ports": stats["top_ports"],
        "top_usernames": stats["top_usernames"],
        "top_intents": stats["top_intents"],
        "top_commands": stats["top_commands"],
        "top_paths": stats["top_paths"],
        "top_unclassified": stats.get("top_unclassified") or [],
        "db_bytes": stats.get("db_bytes", 0),
        "db_cap_bytes": stats.get("db_cap_bytes", 0),
        "recording": bool(stats.get("recording", True)),
        "since": stats.get("since") or "",
        "intent": stats.get("intent") or "",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _rows(items: list[dict], render) -> list[str]:
    if not items:
        return ["  пока пусто"]
    return [render(item) for item in items]


REPORT_FORMATS = ("html", "json", "md", "csv")

_INTENT_RU = {
    "banner_grab": "снятие баннера",
    "auth_guess": "подбор входа",
    "unclassified": "без метки",
    "web_login_probe": "проба веб-входа",
    "web_secret_probe": "поиск секретов на сайте",
    "recon_host": "разведка хоста",
    "cleanup": "зачистка",
    "abuse_verb": "вредная команда",
    "persistence": "закрепление",
    "busybox": "busybox",
    "webshell": "веб-шелл",
    "miner": "майнер",
    "reverse_shell": "обратная оболочка",
    "fetch_and_run": "скачать и запустить",
}

_CHANNEL_RU = {
    "shell": "оболочка",
    "exec": "запуск",
    "line": "строка протокола",
}

_AUTH_RU = {
    "none": "без входа",
    "fake_accept": "принят как настоящий",
    "fail": "отклонён",
}

_HOT = {"fetch_and_run", "reverse_shell", "miner"}
_WARM = {"webshell", "persistence", "abuse_verb"}

_REPORT_CSS = """
:root {
  --ink: #1a1916;
  --muted: #5e584e;
  --line: #e3dcd0;
  --paper: #f6f3ec;
  --card: #fffdf9;
  --accent: #1e4d3a;
  --hot: #8d2f2a;
  --warm: #8a5a12;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 15px/1.5 "Segoe UI", "Helvetica Neue", sans-serif;
}
.sheet { max-width: 980px; margin: 0 auto; padding: 2.4rem 1.4rem 4rem; }
.brand {
  margin: 0;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  font-size: 0.72rem;
  color: var(--muted);
}
h1 { font-size: 2rem; line-height: 1.15; margin: 0.25rem 0 0.4rem; font-weight: 560; }
h2 { font-size: 1.08rem; margin: 2rem 0 0.55rem; }
h3 { font-size: 0.95rem; margin: 0 0 0.35rem; }
a { color: var(--accent); }
.meta, .empty, footer { color: var(--muted); }
.lead { font-size: 1.02rem; max-width: 42rem; }
.toc { margin: 0.8rem 0 0; padding: 0; }
.toc a { margin-right: 0.9rem; white-space: nowrap; }
.kpis {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.65rem;
  margin-top: 1.2rem;
}
.kpi { background: var(--card); border: 1px solid var(--line); padding: 0.75rem 0.85rem; }
.kpi b {
  display: block;
  font-size: 1.4rem;
  font-weight: 560;
  font-variant-numeric: tabular-nums;
}
.kpi span { color: var(--muted); font-size: 0.78rem; }
.split { display: grid; grid-template-columns: 1fr 1fr; gap: 1.2rem; }
.bar {
  display: grid;
  grid-template-columns: minmax(8rem, 14rem) 1fr 3.2rem;
  gap: 0.55rem;
  align-items: center;
  margin: 0.22rem 0;
}
.bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.track { background: #efeae2; height: 0.5rem; }
.fill { display: block; height: 100%; background: var(--accent); }
.fill.hot { background: var(--hot); }
.fill.warm { background: var(--warm); }
.bar-n { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
table { width: 100%; border-collapse: collapse; background: var(--card); margin: 0.3rem 0 0.6rem; }
th, td { border-bottom: 1px solid var(--line); padding: 0.38rem 0.5rem; text-align: left; vertical-align: top; }
th {
  font-size: 0.72rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--muted);
  font-weight: 600;
}
code, pre { font-family: ui-monospace, Consolas, monospace; }
pre {
  margin: 0.15rem 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12.5px;
  line-height: 1.45;
}
.attack { background: var(--card); border: 1px solid var(--line); padding: 0.85rem 1rem; margin: 0.65rem 0; }
.attack header { display: flex; gap: 0.7rem; align-items: baseline; flex-wrap: wrap; }
.tag { font-size: 0.75rem; border: 1px solid currentColor; padding: 0.02rem 0.4rem; }
.attack-hot .tag { color: var(--hot); }
.attack-warm .tag { color: var(--warm); }
footer { margin-top: 2.4rem; border-top: 1px solid var(--line); padding-top: 0.8rem; font-size: 0.88rem; }
@media (max-width: 720px) {
  .split, .bar { grid-template-columns: 1fr; }
  .sheet { padding: 1.3rem 0.9rem 3rem; }
}
@media print {
  body { background: white; }
  .sheet { max-width: none; padding: 0; }
  a { color: inherit; text-decoration: none; }
  .attack, .kpi, tr { break-inside: avoid; }
}
"""


def render_report(fmt: str, stats: dict) -> str:
    writer = {
        "html": render_html,
        "json": report_json,
        "md": render_markdown,
        "csv": render_csv,
    }.get(fmt)
    if writer is None:
        raise ValueError("Формат отчёта: html, json, md или csv")
    return writer(stats)


def intent_label(name: object) -> str:
    key = "" if name is None else str(name).strip()
    gloss = _INTENT_RU.get(key)
    if gloss is None:
        return _plain(key) or "открыта"
    return f"{gloss} ({key})"


def render_html(stats: dict) -> str:
    when = _generated()
    body = "\n".join(
        [
            "<header>",
            "<p class='brand'>DotBotHunt</p>",
            "<h1>Отчёт по атакам</h1>",
            "<p class='meta'>Команды клиентов записаны и не исполнялись.</p>",
            f"<p class='meta'>Собран {_h(when)}. {_h(_window_line(stats))}.</p>",
            _toc(),
            f"<p class='lead'>{_h(_lead(stats))}</p>",
            _kpis(stats),
            "</header>",
            "<section id='timeline'><h2>Ход</h2>",
            f"<p class='meta'>{_h(_timeline_caption(stats))}</p>",
            _bars(
                [
                    (_bucket_label(row.get("bucket"), stats.get("timeline_unit")), int(row.get("n") or 0), "")
                    for row in stats.get("timeline") or []
                ]
            ),
            "</section>",
            "<section id='intents'><h2>Метки</h2>",
            _bars(
                [
                    (intent_label(row.get("intent")), int(row.get("n") or 0), _heat(row.get("intent")))
                    for row in stats.get("top_intents") or []
                ]
            ),
            "</section>",
            "<section id='actors'><h2>Адреса</h2>",
            _htable(
                ["IP", "Сессии", "Страна", "Город", "Провайдер", "ASN", "Репутация"],
                [
                    [
                        row.get("ip"),
                        row.get("n"),
                        row.get("country") or "-",
                        row.get("city") or "-",
                        row.get("org") or "неизвестно",
                        row.get("asn") or "-",
                        reputation_line(row),
                    ]
                    for row in stats.get("top_ips") or []
                ],
            ),
            "<div class='split'>",
            "<div><h3>Страны</h3>",
            _htable(
                ["Страна", "IP"],
                [[row.get("country"), row.get("n")] for row in stats.get("top_countries") or []],
            ),
            "</div><div><h3>Города</h3>",
            _htable(
                ["Город", "IP"],
                [[row.get("city"), row.get("n")] for row in stats.get("top_cities") or []],
            ),
            "</div></div>",
            "<h3>Сети</h3>",
            _htable(
                ["Провайдер", "ASN", "IP"],
                [
                    [row.get("org"), row.get("asn") or "-", row.get("n")]
                    for row in stats.get("top_orgs") or []
                ],
            ),
            "</section>",
            "<section id='traffic'><h2>Куда стучались</h2>",
            "<div class='split'><div><h3>Порты</h3>",
            _htable(
                ["Протокол", "Порт", "Сессии"],
                [
                    [row.get("proto"), row.get("port"), row.get("n")]
                    for row in stats.get("top_ports") or []
                ],
            ),
            "</div><div><h3>Каналы команд</h3>",
            _htable(
                ["Канал", "Раз"],
                [
                    [_channel_label(row.get("channel")), row.get("n")]
                    for row in stats.get("top_channels") or []
                ],
            ),
            "</div></div>",
            "<div class='split'><div><h3>Имена при входе</h3>",
            _htable(
                ["Имя", "Попытки"],
                [[row.get("username"), row.get("n")] for row in stats.get("top_usernames") or []],
            ),
            "</div><div><h3>Методы HTTP</h3>",
            _htable(
                ["Метод", "Раз"],
                [[row.get("method"), row.get("n")] for row in stats.get("top_methods") or []],
            ),
            "</div></div>",
            "<h3>Команды</h3>",
            _htable(
                ["Команда", "Раз"],
                [[row.get("command"), row.get("n")] for row in stats.get("top_commands") or []],
            ),
            "<h3>Неразобранные команды</h3>",
            _htable(
                ["Команда", "Раз"],
                [[row.get("command"), row.get("n")] for row in stats.get("top_unclassified") or []],
            ),
            "<h3>Пути HTTP</h3>",
            _htable(
                ["Путь", "Раз"],
                [[row.get("path"), row.get("n")] for row in stats.get("top_paths") or []],
            ),
            "</section>",
            "<section id='notable'><h2>Опасные сессии</h2>",
            _notable_block(stats),
            "</section>",
            "<section id='sessions'><h2>Сессии</h2>",
            _session_note(stats),
            _htable(
                ["Время", "Сессия", "IP", "Страна", "Протокол", "Метка", "Имя", "Команд"],
                [
                    [
                        row.get("started_at"),
                        row.get("id"),
                        row.get("ip"),
                        row.get("country") or "-",
                        f"{row.get('proto') or ''} {row.get('dst_port') or ''}".strip(),
                        intent_label(row.get("primary_intent")),
                        row.get("username") or "-",
                        row.get("command_count") or 0,
                    ]
                    for row in stats.get("session_rows") or stats.get("recent") or []
                ],
            ),
            "</section>",
            "<section id='events'><h2>Журнал событий</h2>",
            "<p class='meta'>Сюда пишутся предел соединений, сбой разбора HTTP и ошибка обогащения. Команды клиентов в этот журнал не входят.</p>",
            _htable(
                ["Время", "Сессия", "Тип", "Деталь"],
                [
                    [
                        row.get("ts"),
                        row.get("session_id") or "-",
                        row.get("kind"),
                        row.get("detail"),
                    ]
                    for row in stats.get("events") or stats.get("recent_events") or []
                ],
            ),
            "</section>",
            "<footer>",
            "<p>Пароли, ключи и секреты попыток входа в этот файл не попадают. "
            "Их видно в панели на 127.0.0.1 и в команде honeybot session. "
            "Фрагмент команды в карточке обрезан до 240 символов, полный текст лежит в базе.</p>",
            f"<p>DotBotHunt, {_h(when)}</p>",
            "</footer>",
        ]
    )
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"ru\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; "
        "base-uri 'none'; form-action 'none'\">"
        f"<title>DotBotHunt, отчёт {_h(when)}</title>"
        f"<style>{_REPORT_CSS}</style></head><body><main class=\"sheet\">"
        f"{body}</main></body></html>\n"
    )


def render_markdown(stats: dict) -> str:
    when = _generated()
    lines = [
        "# Отчёт по атакам",
        "",
        "DotBotHunt. Команды клиентов записаны и не исполнялись.",
        "",
        f"Собран: {_md(when)}",
        f"Срез: {_md(_window_line(stats))}",
        "",
        _lead(stats),
        "",
        "## Сводка",
        "",
    ]
    auth = stats.get("auth") or {}
    for label, value in (
        ("Сессий", stats.get("sessions") or 0),
        ("Уникальных IP", stats.get("unique_ips") or 0),
        ("IP в Spamhaus", stats.get("spamhaus_listed") or 0),
        ("Опасных сессий", len(stats.get("notable") or [])),
        ("Попыток входа", auth.get("attempts") or 0),
        ("Принято как настоящие", auth.get("accepted") or 0),
        ("Отклонено", auth.get("rejected") or 0),
        ("Байт входящих", stats.get("bytes_in") or 0),
        ("Байт исходящих", stats.get("bytes_out") or 0),
    ):
        lines.append(f"- {label}: {value}")
    lines.extend(["", "## Ход", ""])
    lines.extend(
        _md_table(
            ["Время", "Сессии"],
            [
                [_bucket_label(row.get("bucket"), stats.get("timeline_unit")), row.get("n")]
                for row in stats.get("timeline") or []
            ],
        )
    )
    lines.extend(["", "## Метки", ""])
    lines.extend(
        _md_table(
            ["Метка", "Сессии"],
            [[intent_label(row.get("intent")), row.get("n")] for row in stats.get("top_intents") or []],
        )
    )
    lines.extend(["", "## Адреса", ""])
    lines.extend(
        _md_table(
            ["IP", "Сессии", "Страна", "Город", "Провайдер", "ASN", "Репутация"],
            [
                [
                    row.get("ip"),
                    row.get("n"),
                    row.get("country"),
                    row.get("city"),
                    row.get("org"),
                    row.get("asn"),
                    reputation_line(row),
                ]
                for row in stats.get("top_ips") or []
            ],
        )
    )
    lines.extend(["", "## Порты", ""])
    lines.extend(
        _md_table(
            ["Протокол", "Порт", "Сессии"],
            [[row.get("proto"), row.get("port"), row.get("n")] for row in stats.get("top_ports") or []],
        )
    )
    lines.extend(["", "## Имена", ""])
    lines.extend(
        _md_table(
            ["Имя", "Попытки"],
            [[row.get("username"), row.get("n")] for row in stats.get("top_usernames") or []],
        )
    )
    lines.extend(["", "## Команды", ""])
    lines.extend(
        _md_table(
            ["Команда", "Раз"],
            [[row.get("command"), row.get("n")] for row in stats.get("top_commands") or []],
        )
    )
    lines.extend(["", "## Пути HTTP", ""])
    lines.extend(
        _md_table(
            ["Путь", "Раз"],
            [[row.get("path"), row.get("n")] for row in stats.get("top_paths") or []],
        )
    )
    lines.extend(["", "## Опасные сессии", ""])
    notable = stats.get("notable") or []
    if not notable:
        lines.append("В этом срезе нет сессий с метками скачивания, обратной оболочки, майнера, веб-шелла и закрепления.")
        lines.append("")
    for row in notable:
        lines.append(f"### {_md(intent_label(row.get('primary_intent')))} `{_md(row.get('id'))}`")
        lines.append("")
        lines.append(
            f"- {_md(row.get('started_at'))}, {_md(row.get('ip'))}, "
            f"{_md(row.get('proto'))} {_md(row.get('dst_port'))}, {_md(reputation_line(row))}"
        )
        lines.append(f"- Вход: {_md(_auth_label(row.get('auth_result')))}, имя {_md(row.get('username') or '-')}")
        lines.append(f"- Итог: {_md(row.get('summary') or '-')}")
        commands = row.get("commands") or []
        http_rows = row.get("http") or []
        if commands:
            lines.append("- Команды:")
            lines.extend(f"  - {_md(item)}" for item in commands)
        if http_rows:
            lines.append("- HTTP:")
            lines.extend(f"  - {_md(item)}" for item in http_rows)
        if not commands and not http_rows:
            lines.append("- Команд и HTTP-запросов в карточке нет.")
        lines.append("")
    lines.extend(["## Сессии", ""])
    if stats.get("session_rows_capped"):
        lines.append(f"Показаны {len(stats.get('session_rows') or [])} последних из {stats.get('sessions') or 0}.")
        lines.append("")
    lines.extend(
        _md_table(
            ["Время", "Сессия", "IP", "Страна", "Протокол", "Метка", "Имя", "Команд"],
            [
                [
                    row.get("started_at"),
                    row.get("id"),
                    row.get("ip"),
                    row.get("country"),
                    f"{row.get('proto') or ''} {row.get('dst_port') or ''}".strip(),
                    intent_label(row.get("primary_intent")),
                    row.get("username"),
                    row.get("command_count") or 0,
                ]
                for row in stats.get("session_rows") or []
            ],
        )
    )
    lines.extend(["", "## Журнал событий", ""])
    lines.extend(
        _md_table(
            ["Время", "Сессия", "Тип", "Деталь"],
            [
                [row.get("ts"), row.get("session_id"), row.get("kind"), row.get("detail")]
                for row in stats.get("events") or stats.get("recent_events") or []
            ],
        )
    )
    lines.extend(
        [
            "",
            "## Что в файл не входит",
            "",
            "Пароли, ключи и секреты попыток входа остаются в панели на 127.0.0.1 и в команде honeybot session.",
            "Фрагмент команды в карточке обрезан до 240 символов.",
            "",
        ]
    )
    return "\n".join(lines)


def report_json(stats: dict) -> str:
    auth = stats.get("auth") or {}
    payload = {
        "kind": "honeybot-report",
        "generated_at": _generated(),
        "since": _plain(stats.get("since") or ""),
        "intent": _plain(stats.get("intent") or ""),
        "recording": bool(stats.get("recording", True)),
        "db_bytes": _as_int(stats.get("db_bytes")),
        "db_cap_bytes": _as_int(stats.get("db_cap_bytes")),
        "summary": {
            "sessions": _as_int(stats.get("sessions")),
            "unique_ips": _as_int(stats.get("unique_ips")),
            "spamhaus_listed": _as_int(stats.get("spamhaus_listed")),
            "bytes_in": _as_int(stats.get("bytes_in")),
            "bytes_out": _as_int(stats.get("bytes_out")),
            "auth": {
                "attempts": _as_int(auth.get("attempts")),
                "accepted": _as_int(auth.get("accepted")),
                "rejected": _as_int(auth.get("rejected")),
            },
        },
        "timeline_unit": _plain(stats.get("timeline_unit") or ""),
        "timeline": [
            {"bucket": _plain(row.get("bucket")), "n": _as_int(row.get("n"))}
            for row in stats.get("timeline") or []
        ],
        "top_countries": _pairs(stats.get("top_countries"), "country"),
        "top_cities": _pairs(stats.get("top_cities"), "city"),
        "top_orgs": [
            {"org": _plain(row.get("org")), "asn": _plain(row.get("asn")), "n": _as_int(row.get("n"))}
            for row in stats.get("top_orgs") or []
        ],
        "top_ports": [
            {
                "proto": _plain(row.get("proto")),
                "port": row.get("port"),
                "n": _as_int(row.get("n")),
            }
            for row in stats.get("top_ports") or []
        ],
        "top_usernames": _pairs(stats.get("top_usernames"), "username"),
        "top_intents": [
            {"intent": _plain(row.get("intent")), "n": _as_int(row.get("n"))}
            for row in stats.get("top_intents") or []
        ],
        "top_commands": _pairs(stats.get("top_commands"), "command"),
        "top_paths": _pairs(stats.get("top_paths"), "path"),
        "top_unclassified": _pairs(stats.get("top_unclassified"), "command"),
        "top_channels": [
            {"channel": _plain(row.get("channel")), "n": _as_int(row.get("n"))}
            for row in stats.get("top_channels") or []
        ],
        "top_methods": _pairs(stats.get("top_methods"), "method"),
        "top_ips": [_ip_record(row) for row in stats.get("top_ips") or []],
        "notable": [_notable_record(row) for row in stats.get("notable") or []],
        "sessions": [_session_record(row) for row in stats.get("session_rows") or []],
        "sessions_truncated": bool(stats.get("session_rows_capped")),
        "events": [
            {
                "ts": _plain(row.get("ts")),
                "session_id": _plain(row.get("session_id")),
                "kind": _plain(row.get("kind")),
                "detail": _plain(row.get("detail")),
            }
            for row in stats.get("events") or stats.get("recent_events") or []
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def render_csv(stats: dict) -> str:
    """Одна строка на сессию. Ячейка, похожая на формулу, начинается с апострофа."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "id",
            "started_at",
            "ended_at",
            "ip",
            "country",
            "org",
            "asn",
            "spamhaus",
            "abuse_score",
            "proto",
            "dst_port",
            "intent",
            "username",
            "auth_result",
            "command_count",
            "summary",
        ]
    )
    for row in stats.get("session_rows") or []:
        score = row.get("abuse_score")
        port = row.get("dst_port")
        writer.writerow(
            [
                _csv_cell(row.get("id")),
                _csv_cell(row.get("started_at")),
                _csv_cell(row.get("ended_at")),
                _csv_cell(row.get("ip")),
                _csv_cell(row.get("country")),
                _csv_cell(row.get("org")),
                _csv_cell(row.get("asn")),
                _csv_cell(row.get("spamhaus")),
                score if isinstance(score, int) and not isinstance(score, bool) else "",
                _csv_cell(row.get("proto")),
                port if isinstance(port, int) and not isinstance(port, bool) else "",
                _csv_cell(row.get("primary_intent")),
                _csv_cell(row.get("username")),
                _csv_cell(row.get("auth_result")),
                _as_int(row.get("command_count")),
                _csv_cell(row.get("summary")),
            ]
        )
    return "\ufeff" + buffer.getvalue()


def _generated() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _h(value: object) -> str:
    return escape(_plain(value), quote=True)


def _md(value: object) -> str:
    return _plain(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _csv_cell(value: object) -> str:
    text = _plain(value).replace("\r", " ").replace("\n", " ")
    if text[:1] in "=+-@\t":
        return "'" + text
    return text


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _as_optional_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _heat(name: object) -> str:
    key = "" if name is None else str(name).strip()
    if key in _HOT:
        return "hot"
    if key in _WARM:
        return "warm"
    return ""


def _channel_label(name: object) -> str:
    key = "" if name is None else str(name).strip()
    gloss = _CHANNEL_RU.get(key)
    if gloss is None:
        return _plain(key) or "-"
    return gloss


def _auth_label(name: object) -> str:
    key = "" if name is None else str(name).strip()
    return _AUTH_RU.get(key, _plain(key) or "-")


def _window_line(stats: dict) -> str:
    bits = []
    if stats.get("intent"):
        bits.append("метка " + intent_label(stats.get("intent")))
    if stats.get("since"):
        bits.append("с " + _plain(stats.get("since")))
    else:
        bits.append("вся история")
    if stats.get("recording", True):
        bits.append("запись открыта")
    else:
        bits.append("запись закрыта, база достигла предела")
    cap = _as_int(stats.get("db_cap_bytes"))
    if cap:
        bits.append(f"база {_mb(_as_int(stats.get('db_bytes')))} МБ из {_mb(cap)}")
    return ", ".join(bits)


def _lead(stats: dict) -> str:
    auth = stats.get("auth") or {}
    return (
        f"В срезе {int(stats.get('sessions') or 0)} сессий с {int(stats.get('unique_ips') or 0)} адресов. "
        f"Сессий с опасной меткой: {len(stats.get('notable') or [])}. "
        f"Адресов в списке Spamhaus: {int(stats.get('spamhaus_listed') or 0)}. "
        f"Попыток входа: {int(auth.get('attempts') or 0)}, "
        f"из них приняты как настоящие: {int(auth.get('accepted') or 0)}."
    )


def _timeline_caption(stats: dict) -> str:
    if stats.get("timeline_unit") == "hour":
        return "Столбцы по часам. Окно короче двух суток, поэтому день разбит."
    return "Столбцы по дням. Показаны последние 48 непустых интервалов."


def _bucket_label(bucket: object, unit: object) -> str:
    text = _plain(bucket)
    if unit == "hour" and len(text) >= 13 and text[10] == "T":
        return text[:10] + " " + text[11:13] + ":00"
    return text


def _toc() -> str:
    links = [
        ("#timeline", "Ход"),
        ("#intents", "Метки"),
        ("#actors", "Адреса"),
        ("#traffic", "Куда стучались"),
        ("#notable", "Опасные сессии"),
        ("#sessions", "Сессии"),
        ("#events", "Журнал"),
    ]
    return "<p class='toc'>" + "".join(f"<a href='{href}'>{label}</a>" for href, label in links) + "</p>"


def _kpis(stats: dict) -> str:
    auth = stats.get("auth") or {}
    cards = [
        (stats.get("sessions") or 0, "сессий"),
        (stats.get("unique_ips") or 0, "адресов"),
        (stats.get("spamhaus_listed") or 0, "в Spamhaus"),
        (len(stats.get("notable") or []), "опасных"),
        (auth.get("attempts") or 0, "попыток входа"),
        (auth.get("accepted") or 0, "приняты как настоящие"),
        (_size(_as_int(stats.get("bytes_in"))), "входящих"),
    ]
    parts = []
    for value, label in cards:
        parts.append(f"<div class='kpi'><b>{_h(value)}</b><span>{_h(label)}</span></div>")
    return "<div class='kpis'>" + "".join(parts) + "</div>"


def _size(size: int) -> str:
    if size < 1024:
        return f"{size} Б"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} КБ"
    return f"{size / (1024 * 1024):.1f} МБ"


def _bars(rows: list[tuple[object, int, str]]) -> str:
    if not rows:
        return "<p class='empty'>пока пусто</p>"
    peak = max(item[1] for item in rows) or 1
    parts = []
    for label, count, heat in rows:
        width = round(100 * count / peak)
        klass = f" {heat}" if heat in {"hot", "warm"} else ""
        parts.append(
            "<div class='bar'>"
            f"<span class='bar-label'>{_h(label)}</span>"
            f"<span class='track'><span class='fill{klass}' style='width:{width}%'></span></span>"
            f"<span class='bar-n'>{count}</span>"
            "</div>"
        )
    return "".join(parts)


def _htable(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{_h(item)}</th>" for item in headers)
    if not rows:
        body = f"<tr><td colspan='{len(headers)}'>пока пусто</td></tr>"
    else:
        body = "".join(
            "<tr>" + "".join(f"<td>{_h(cell)}</td>" for cell in row) + "</tr>" for row in rows
        )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _notable_block(stats: dict) -> str:
    rows = stats.get("notable") or []
    if not rows:
        return (
            "<p class='empty'>В этом срезе нет сессий с метками скачивания, "
            "обратной оболочки, майнера, веб-шелла и закрепления.</p>"
        )
    parts = []
    for row in rows:
        intent = str(row.get("primary_intent") or "")
        heat = _heat(intent)
        klass = f" attack-{heat}" if heat else ""
        commands = row.get("commands") or []
        http_rows = row.get("http") or []
        card = [
            f"<article class='attack{klass}'>",
            "<header>",
            f"<span class='tag'>{_h(intent_label(intent))}</span>",
            f"<code>{_h(row.get('id'))}</code>",
            "</header>",
            "<p class='meta'>",
            _h(row.get("started_at") or ""),
            " · ",
            _h(row.get("ip") or ""),
            ", ",
            _h(row.get("country") or "-"),
            ", ",
            _h(row.get("org") or "неизвестно"),
            ", ",
            _h(str(row.get("proto") or "")),
            " ",
            _h(row.get("dst_port") or ""),
            ", ",
            _h(reputation_line(row)),
            "</p>",
            f"<p>Вход: {_h(_auth_label(row.get('auth_result')))}, имя {_h(row.get('username') or '-')}.</p>",
            f"<p>{_h(row.get('summary') or 'Итог ещё не собран.')}</p>",
        ]
        if commands:
            card.append("<h3>Команды</h3>")
            card.extend(f"<pre>{_h(item)}</pre>" for item in commands)
        if http_rows:
            card.append("<h3>HTTP</h3>")
            card.extend(f"<pre>{_h(item)}</pre>" for item in http_rows)
        if not commands and not http_rows:
            card.append("<p class='empty'>Команд и HTTP-запросов в карточке нет.</p>")
        card.append("</article>")
        parts.append("".join(card))
    return "".join(parts)


def _session_note(stats: dict) -> str:
    if not stats.get("session_rows_capped"):
        return ""
    shown = len(stats.get("session_rows") or [])
    total = int(stats.get("sessions") or 0)
    return f"<p class='meta'>Показаны {shown} последних из {total}. Полный список этой длины есть в CSV и JSON.</p>"


def _md_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    head = "| " + " | ".join(_md(item) for item in headers) + " |"
    rule = "| " + " | ".join("---" for _ in headers) + " |"
    if not rows:
        return [head, rule, "| " + " | ".join("пока пусто" if index == 0 else "" for index in range(len(headers))) + " |"]
    body = [
        "| " + " | ".join(_md(cell) for cell in row) + " |"
        for row in rows
    ]
    return [head, rule, *body]


def _pairs(rows: object, key: str) -> list[dict]:
    found = rows or []
    return [{key: _plain(row.get(key)), "n": _as_int(row.get("n"))} for row in found]


def _ip_record(row: dict) -> dict:
    return {
        "ip": _plain(row.get("ip")),
        "n": _as_int(row.get("n")),
        "country": _plain(row.get("country")),
        "city": _plain(row.get("city")),
        "org": _plain(row.get("org")),
        "asn": _plain(row.get("asn")),
        "isp": _plain(row.get("isp")),
        "spamhaus": _plain(row.get("spamhaus")),
        "abuse_score": _as_optional_int(row.get("abuse_score")),
        "abuse_reports": _as_optional_int(row.get("abuse_reports")),
    }


def _session_record(row: dict) -> dict:
    return {
        "id": _plain(row.get("id")),
        "started_at": _plain(row.get("started_at")),
        "ended_at": _plain(row.get("ended_at")),
        "ip": _plain(row.get("ip")),
        "country": _plain(row.get("country")),
        "org": _plain(row.get("org")),
        "asn": _plain(row.get("asn")),
        "spamhaus": _plain(row.get("spamhaus")),
        "abuse_score": _as_optional_int(row.get("abuse_score")),
        "proto": _plain(row.get("proto")),
        "dst_port": _as_optional_int(row.get("dst_port")),
        "intent": _plain(row.get("primary_intent") or row.get("intent")),
        "username": _plain(row.get("username")),
        "auth_result": _plain(row.get("auth_result")),
        "command_count": _as_int(row.get("command_count")),
        "summary": _plain(row.get("summary")),
    }


def _notable_record(row: dict) -> dict:
    record = _session_record(row)
    record["commands"] = [_plain(item) for item in row.get("commands") or []]
    record["http"] = [_plain(item) for item in row.get("http") or []]
    return record
