from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_FETCH_TOOL = re.compile(r"(^|[\s;/])(curl|wget|tftp)(\s|$)")
_SHELL_WORD = re.compile(r"(^|[\s|;/`])(sh|bash)(\s|$)")
_SHELL_PIPE = re.compile(r"\|\s*(sh|bash)\b")
_BASE64_PIPE = re.compile(r"\bbase64\b")
_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RECON_TOKENS = {"id", "df", "free", "ps", "uname", "whoami", "hostname", "lscpu", "nproc"}


@dataclass
class Rule:
    tag: str
    kind: str
    needles: list[str] = field(default_factory=list)


@dataclass
class Rules:
    order: list[str]
    summary: dict[str, str]
    rules: list[Rule]


@dataclass
class Result:
    tags: list[str]
    primary: str
    summary: str
    command_tags: dict[int, list[str]]
    http_tags: dict[int, list[str]]


def normalize(raw: str) -> str:
    text = raw.strip().lower()
    text = _URL.sub("<url>", text)
    text = _IP.sub("<ip>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:500]


def is_fetch(text: str) -> bool:
    low = text.lower()
    has_tool = _FETCH_TOOL.search(low) is not None
    has_shell = _SHELL_WORD.search(low) is not None or _SHELL_PIPE.search(low) is not None
    if has_tool and has_shell:
        return True
    return _BASE64_PIPE.search(low) is not None and _SHELL_PIPE.search(low) is not None


def _session_fetch(commands: list[str]) -> bool:
    if any(is_fetch(item) for item in commands):
        return True
    blob = "\n".join(commands).lower()
    has_tool = re.search(r"\b(curl|wget|tftp)\b", blob) is not None
    has_run = re.search(r"(^|\n)\s*(sh|bash)\s+\S+", blob) is not None
    return has_tool and has_run


@lru_cache(maxsize=1)
def load_rules() -> Rules:
    path = Path(__file__).with_name("rules.toml")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    rules = [
        Rule(
            tag=item["tag"],
            kind=item.get("kind", "text"),
            needles=list(item.get("needles", [])),
        )
        for item in data.get("rule", [])
    ]
    return Rules(
        order=list(data.get("order", [])),
        summary=dict(data.get("summary", {})),
        rules=rules,
    )


def tags_for_text(text: str, rules: Rules | None = None) -> list[str]:
    rules = rules or load_rules()
    low = text.lower()
    found: list[str] = []
    first = low.split(" ", 1)[0]
    for rule in rules.rules:
        if rule.kind != "text":
            continue
        if any(needle in low for needle in rule.needles):
            found.append(rule.tag)
        elif rule.tag == "recon_host" and first in _RECON_TOKENS and rule.tag not in found:
            found.append(rule.tag)
    if is_fetch(text) and "fetch_and_run" not in found:
        found.append("fetch_and_run")
    return found


def tags_for_path(path: str, rules: Rules | None = None) -> list[str]:
    rules = rules or load_rules()
    found: list[str] = []
    for rule in rules.rules:
        if rule.kind != "path":
            continue
        if any(_path_hit(path, needle) for needle in rule.needles):
            found.append(rule.tag)
    return found


def _path_hit(path: str, needle: str) -> bool:
    low = path.lower()
    item = needle.lower()
    if item == "/admin":
        base = low.split("?", 1)[0]
        return base == "/admin" or base.startswith("/admin/")
    if item == ".env":
        return re.search(r"(^|/)\.env(\.|$)", low) is not None
    if item == ".git":
        return re.search(r"(^|/)\.git(/|$)", low) is not None
    return item in low


def reconstruct(bundle: dict, rules: Rules | None = None) -> Result:
    rules = rules or load_rules()
    commands = bundle.get("commands") or []
    http_rows = bundle.get("http") or []
    auths = bundle.get("auths") or []
    command_tags: dict[int, list[str]] = {}
    http_tags: dict[int, list[str]] = {}
    tags: set[str] = set()
    raw_commands = [row.get("raw") or "" for row in commands]
    for row in commands:
        found = tags_for_text(row.get("raw") or "", rules)
        command_tags[int(row["id"])] = found
        tags.update(found)
    for row in http_rows:
        found = tags_for_path(row.get("path") or "", rules)
        http_tags[int(row["id"])] = found
        tags.update(found)
    if _session_fetch(raw_commands):
        tags.add("fetch_and_run")
    if not tags:
        if raw_commands or http_rows:
            tags.add("unclassified")
        elif auths:
            tags.add("auth_guess")
        else:
            tags.add("banner_grab")
    elif auths and not raw_commands and not (tags - {"web_login_probe", "web_secret_probe"}):
        # Пароли без команд остаются отдельной меткой, даже если рядом была веб-проба.
        if not http_rows:
            tags.add("auth_guess")
    ordered = [name for name in rules.order if name in tags]
    for name in tags:
        if name not in ordered:
            ordered.append(name)
    primary = ordered[-1]
    sentence = rules.summary.get(primary, "Команды записаны.")
    evidence = _evidence(primary, commands, http_rows, rules)
    if evidence:
        snippet = re.sub(r"\s+", " ", evidence).strip()[:120]
        sentence = f"{sentence} Фрагмент: {snippet}"
    labels = ", ".join(ordered)
    summary = f"Метки: {labels}. {sentence}"
    return Result(
        tags=ordered,
        primary=primary,
        summary=summary,
        command_tags=command_tags,
        http_tags=http_tags,
    )


def _evidence(primary: str, commands: list[dict], http_rows: list[dict], rules: Rules) -> str:
    if primary in {"banner_grab", "auth_guess"}:
        return ""
    for row in commands:
        found = set(tags_for_text(row.get("raw") or "", rules))
        if primary == "fetch_and_run" and (
            is_fetch(row.get("raw") or "") or "fetch_and_run" in found
        ):
            return row.get("raw") or ""
        if primary in found:
            return row.get("raw") or ""
    for row in http_rows:
        if primary in tags_for_path(row.get("path") or "", rules):
            return row.get("path") or ""
    if primary == "fetch_and_run":
        for row in commands:
            raw = row.get("raw") or ""
            if re.search(r"\b(curl|wget|tftp|sh|bash)\b", raw.lower()):
                return raw
    return ""
