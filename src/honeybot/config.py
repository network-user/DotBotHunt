from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

LISTENER_NAMES = ("ssh", "http", "telnet", "ftp", "smtp", "redis")

DEFAULT_PORTS = {
    "ssh": 2222,
    "http": 8080,
    "telnet": 2323,
    "ftp": 2121,
    "smtp": 2525,
    "redis": 6379,
}


class ConfigError(ValueError):
    pass


@dataclass
class Limits:
    max_conn_per_ip: int = 30
    max_global: int = 200
    session_seconds: int = 90
    max_line_bytes: int = 8192
    max_http_body: int = 65536
    max_db_mb: int = 512


@dataclass
class Enrich:
    dns_timeout_seconds: float = 2.0
    cache_hours: int = 24
    dns_server: str = "1.1.1.1"
    mmdb_city: str = ""
    enable_spamhaus: bool = True
    enable_geo: bool = True
    ip_api_key: str = ""
    abuseipdb_api_key: str = ""


@dataclass
class Dashboard:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8787


@dataclass
class Listener:
    enabled: bool = True
    port: int = 0
    fail_before_accept: int = 0


@dataclass
class Config:
    limits: Limits = field(default_factory=Limits)
    enrich: Enrich = field(default_factory=Enrich)
    dashboard: Dashboard = field(default_factory=Dashboard)
    listeners: dict[str, Listener] = field(default_factory=dict)
    db_path: Path = Path("data/honeybot.db")


def default_config() -> Config:
    listeners = {
        name: Listener(enabled=True, port=DEFAULT_PORTS[name], fail_before_accept=0)
        for name in LISTENER_NAMES
    }
    cfg = Config(listeners=listeners)
    validate(cfg)
    return cfg


def _take(cls, raw: dict | None):
    data = raw or {}
    known = {item.name for item in fields(cls)}
    return cls(**{key: value for key, value in data.items() if key in known})


def load_config(path: Path) -> Config:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    listeners_raw = raw.get("listeners") or {}
    listeners: dict[str, Listener] = {}
    for name in LISTENER_NAMES:
        base = {
            "enabled": True,
            "port": DEFAULT_PORTS[name],
            "fail_before_accept": 0,
        }
        base.update(listeners_raw.get(name) or {})
        listeners[name] = _take(Listener, base)
    cfg = Config(
        limits=_take(Limits, raw.get("limits")),
        enrich=_take(Enrich, raw.get("enrich")),
        dashboard=_take(Dashboard, raw.get("dashboard")),
        listeners=listeners,
    )
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    if cfg.dashboard.enabled and cfg.dashboard.host != "127.0.0.1":
        raise ConfigError("Панель можно слушать только на 127.0.0.1")
    if not 0 <= cfg.dashboard.port <= 65535:
        raise ConfigError("Порт панели вне диапазона")
    for name, listener in cfg.listeners.items():
        if not 0 <= listener.port <= 65535:
            raise ConfigError(f"Порт {name} вне диапазона")
        if listener.fail_before_accept < 0:
            raise ConfigError(f"fail_before_accept у {name} меньше нуля")
    if cfg.limits.session_seconds <= 0:
        raise ConfigError("session_seconds должен быть больше нуля")
    if cfg.limits.max_global <= 0 or cfg.limits.max_conn_per_ip <= 0:
        raise ConfigError("Лимиты соединений должны быть больше нуля")
