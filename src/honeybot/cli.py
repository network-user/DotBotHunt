from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from honeybot.app import HoneyBot
from honeybot.config import ConfigError, default_config, load_config
from honeybot.reconstruct import reconstruct
from honeybot.report import format_session, format_stats, stats_json
from honeybot.store import Store
from honeybot.util import parse_intent, parse_since


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeybot",
        description="DotBotHunt записывает, что присылают клиенты, и не исполняет это.",
    )
    parser.add_argument("--config", default="config.toml", help="путь к config.toml")
    parser.add_argument("--db", default="", help="файл SQLite, по умолчанию data/honeybot.db")
    commands = parser.add_subparsers(dest="cmd", required=True)
    commands.add_parser("run", help="поднять приманку")
    stats = commands.add_parser("stats", help="сводка по базе")
    stats.add_argument("--since", default="", help="окно: 30m, 24h или 7d")
    stats.add_argument("--intent", default="", help="только эта метка")
    session = commands.add_parser("session", help="одна сессия")
    session.add_argument("id")
    export = commands.add_parser("export", help="сводка в JSON")
    export.add_argument("path")
    export.add_argument("--since", default="", help="окно: 30m, 24h или 7d")
    export.add_argument("--intent", default="", help="только эта метка")
    commands.add_parser("rebuild", help="заново проставить метки")
    args = parser.parse_args(argv)
    try:
        cfg = _load(args)
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2
    try:
        if args.cmd == "run":
            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
            asyncio.run(_run(cfg))
            return 0
        return asyncio.run(_offline(cfg, args))
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


def _load(args) -> object:
    path = Path(args.config)
    if path.is_file():
        cfg = load_config(path)
    else:
        example = Path("config.example.toml")
        if example.is_file():
            print(f"Нет {path.name}, читаю {example.name}", file=sys.stderr)
            cfg = load_config(example)
        else:
            print("Нет файла конфигурации, порты по умолчанию", file=sys.stderr)
            cfg = default_config()
    if args.db:
        cfg.db_path = Path(args.db)
    return cfg


async def _run(cfg) -> None:
    bot = HoneyBot(cfg)
    await bot.start()
    print("DotBotHunt слушает. Команды клиентов не исполняются. Остановка: Ctrl+C.")
    for name, port in bot.bound.items():
        host = "127.0.0.1" if name == "dashboard" else "0.0.0.0"
        print(f"  {name}: {host}:{port}")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list = []

    def _stop(*_args) -> None:
        loop.call_soon_threadsafe(stop.set)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
            installed.append(sig)
        except NotImplementedError:
            if sig == signal.SIGTERM:
                signal.signal(sig, _stop)
    try:
        await stop.wait()
    finally:
        for sig in installed:
            loop.remove_signal_handler(sig)
        await bot.stop()


def _window(args) -> tuple[str, str]:
    try:
        since = parse_since(getattr(args, "since", "") or "")
        intent = parse_intent(getattr(args, "intent", "") or "")
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    return since, intent


async def _offline(cfg, args) -> int:
    store = Store(cfg.db_path, cfg.limits.max_db_mb)
    await store.start()
    try:
        if args.cmd == "stats":
            since, intent = _window(args)
            print(format_stats(await store.stats(since, intent)), end="")
            return 0
        if args.cmd == "export":
            since, intent = _window(args)
            Path(args.path).write_text(stats_json(await store.stats(since, intent)), encoding="utf-8")
            print(f"Записано {args.path}")
            return 0
        if args.cmd == "session":
            return await _show_session(store, args.id)
        if args.cmd == "rebuild":
            return await _rebuild(store)
    finally:
        await store.stop()
    return 2


async def _show_session(store: Store, session_id: str) -> int:
    bundle = await store.bundle(session_id)
    if not bundle.get("session"):
        print("Сессия не найдена")
        return 1
    result = reconstruct(bundle)
    ended = bool(bundle["session"].get("ended_at"))
    if ended:
        await store.finish(
            session_id,
            primary=result.primary,
            summary=result.summary,
            command_tags=result.command_tags,
            http_tags=result.http_tags,
            stamp=False,
        )
        bundle = await store.bundle(session_id)
    else:
        bundle["session"]["primary_intent"] = result.primary
        bundle["session"]["summary"] = result.summary
        for row in bundle["commands"]:
            row["tags"] = ",".join(result.command_tags.get(row["id"], []))
        for row in bundle["http"]:
            row["tags"] = ",".join(result.http_tags.get(row["id"], []))
    print(format_session(bundle), end="")
    return 0


async def _rebuild(store: Store) -> int:
    count = 0
    for session_id in await store.session_ids():
        bundle = await store.bundle(session_id)
        if not bundle.get("session"):
            continue
        result = reconstruct(bundle)
        await store.finish(
            session_id,
            primary=result.primary,
            summary=result.summary,
            command_tags=result.command_tags,
            http_tags=result.http_tags,
            stamp=False,
        )
        count += 1
    print(f"Пересчитано сессий: {count}")
    return 0
