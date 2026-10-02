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


def format_stats(stats: dict) -> str:
    lines = [
        f"Сессий: {stats['sessions']}",
        f"Уникальных IP: {stats['unique_ips']}",
        f"IP в Spamhaus: {stats.get('spamhaus_listed', 0)}",
        "",
        "Страны:",
    ]
    lines.extend(_rows(stats.get("top_countries") or [], lambda row: f"  {row['country']}  {row['n']}"))
    lines.append("")
    lines.append("Города:")
    lines.extend(_rows(stats.get("top_cities") or [], lambda row: f"  {row['city']}  {row['n']}"))
    lines.append("")
    lines.append("Сети и провайдеры:")
    lines.extend(_rows(stats["top_orgs"], lambda row: f"  {row['org']} AS{row['asn'] or '?'}  {row['n']}"))
    lines.append("")
    lines.append("Порты:")
    lines.extend(
        _rows(stats["top_ports"], lambda row: f"  {row['proto']} {row['port']}  {row['n']}")
    )
    lines.append("")
    lines.append("Имена:")
    lines.extend(_rows(stats["top_usernames"], lambda row: f"  {row['username']}  {row['n']}"))
    lines.append("")
    lines.append("Метки:")
    lines.extend(_rows(stats["top_intents"], lambda row: f"  {row['intent']}  {row['n']}"))
    lines.append("")
    lines.append("Команды:")
    lines.extend(_rows(stats["top_commands"], lambda row: f"  {row['command']}  {row['n']}"))
    lines.append("")
    lines.append("HTTP-пути:")
    lines.extend(_rows(stats["top_paths"], lambda row: f"  {row['path']}  {row['n']}"))
    lines.append("")
    lines.append("Последние сессии:")
    if not stats["recent"]:
        lines.append("  пока пусто")
    else:
        for row in stats["recent"]:
            intent = row.get("primary_intent") or "открыта"
            lines.append(f"  {row['id']}  {row['ip']}  {row['proto']}  {intent}")
    return "\n".join(lines) + "\n"


def format_session(bundle: dict) -> str:
    session = bundle.get("session")
    if not session:
        return "Сессия не найдена\n"
    info = bundle.get("ip_info") or {}
    lines = [
        f"Сессия {session['id']}",
        f"Начало: {session.get('started_at') or ''}",
        f"Конец: {session.get('ended_at') or 'ещё идёт'}",
        (
            f"IP: {session.get('ip')}  провайдер: {info.get('org') or 'неизвестно'}"
            f"  ASN: {info.get('asn') or '-'}  страна: {info.get('country') or '-'}"
            f"  город: {info.get('city') or '-'}  ISP: {info.get('isp') or '-'}"
            f"  rdns: {info.get('rdns') or '-'}"
        ),
        f"Репутация: {reputation_line(info)}",
        f"Протокол: {session.get('proto')}  порт {session.get('dst_port')}",
        f"Баннер клиента: {session.get('client_banner') or '-'}",
        f"Вход: {session.get('auth_result') or 'none'}  пользователь: {session.get('username') or '-'}",
        f"Байт входящих: {session.get('bytes_in') or 0}  исходящих: {session.get('bytes_out') or 0}",
        f"Итог: {session.get('summary') or 'ещё не собран'}",
        "",
        "Попытки входа:",
    ]
    auths = bundle.get("auths") or []
    if not auths:
        lines.append("  нет")
    for row in auths:
        mark = "принят как настоящий" if row.get("fake_accepted") else "отклонён"
        lines.append(
            f"  {row.get('username') or '-'}  {row.get('method') or '-'}  {mark}  {row.get('secret') or ''}"
        )
    lines.append("")
    lines.append("Команды:")
    commands = bundle.get("commands") or []
    if not commands:
        lines.append("  нет")
    for row in commands:
        tags = row.get("tags") or ""
        suffix = f"  [{tags}]" if tags else ""
        lines.append(f"  {row.get('raw')}{suffix}")
    lines.append("")
    lines.append("HTTP:")
    http_rows = bundle.get("http") or []
    if not http_rows:
        lines.append("  нет")
    for row in http_rows:
        lines.append(f"  {row.get('method')} {row.get('path')}  {row.get('status_sent')}")
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
