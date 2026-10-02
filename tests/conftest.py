from __future__ import annotations

import asyncio

from honeybot.app import HoneyBot
from honeybot.config import LISTENER_NAMES, Config, Dashboard, Enrich, Limits, Listener

FORBIDDEN_IP = "203.0.113.5"


def make_config(tmp_path, services: set[str], dashboard: bool = False) -> Config:
    listeners = {
        name: Listener(enabled=name in services, port=0, fail_before_accept=0)
        for name in LISTENER_NAMES
    }
    return Config(
        limits=Limits(
            max_conn_per_ip=10,
            max_global=20,
            session_seconds=15,
            max_line_bytes=8192,
            max_http_body=65536,
            max_db_mb=32,
        ),
        enrich=Enrich(dns_timeout_seconds=0.3, cache_hours=24, dns_server="127.0.0.1"),
        dashboard=Dashboard(enabled=dashboard, host="127.0.0.1", port=0),
        listeners=listeners,
        db_path=tmp_path / "honey.db",
    )


async def start_bot(tmp_path, services: set[str], dashboard: bool = False) -> HoneyBot:
    bot = HoneyBot(make_config(tmp_path, services, dashboard))
    await bot.start()
    return bot


async def wait_intent(bot: HoneyBot, proto: str) -> str:
    last = None
    for _ in range(80):
        stats = await bot.store.stats()
        last = stats["recent"]
        for row in stats["recent"]:
            if row["proto"] == proto and row.get("primary_intent"):
                return row["id"]
        await asyncio.sleep(0.05)
    raise AssertionError(f"сессия {proto} не закрылась: {last}")
