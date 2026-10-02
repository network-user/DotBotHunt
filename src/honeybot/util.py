from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone

_SINCE = re.compile(r"^(\d{1,4})([mhd])$")
_INTENT = re.compile(r"^[a-z0-9_]{1,40}$")


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def normalize_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(addr)


def parse_since(value: str, now: datetime | None = None) -> str:
    """Пустая строка или all - вся история. Иначе 30m, 24h или 7d."""
    text = value.strip().lower()
    if not text or text == "all":
        return ""
    match = _SINCE.fullmatch(text)
    if match is None:
        raise ValueError("Окно задаётся как 30m, 24h или 7d")
    amount = int(match.group(1))
    if amount <= 0:
        raise ValueError("Окно задаётся как 30m, 24h или 7d")
    unit = match.group(2)
    delta = {
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
    }[unit]
    moment = (now or datetime.now(timezone.utc)) - delta
    return moment.replace(microsecond=0).isoformat()


def parse_intent(value: str) -> str:
    text = value.strip().lower()
    if not text:
        return ""
    if _INTENT.fullmatch(text) is None:
        raise ValueError("Метка содержит только строчные латинские буквы, цифры и _")
    return text


def is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(normalize_ip(ip))
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )
