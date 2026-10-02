from __future__ import annotations

import json
from datetime import datetime, timezone


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


def format_stats(stats: dict) -> str:
    lines = [
        f"Сессий: {stats['sessions']}",
        f"Уникальных IP: {stats['unique_ips']}",
        f"IP в Spamhaus: {stats.get('spamhaus_listed', 0)}",
        "",
        "Страны:",
    ]
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
    lines.append("Последние сессии:")
    if not stats["recent"]:
        lines.append("  пока пусто")
    else:
        for row in stats["recent"]:
            intent = row.get("primary_intent") or "открыта"
            lines.append(
                f"  {_plain(row['id'])}  {_plain(row['ip'])}  {_plain(row['proto'])}  {_plain(intent)}"
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
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _rows(items: list[dict], render) -> list[str]:
    if not items:
        return ["  пока пусто"]
    return [render(item) for item in items]
