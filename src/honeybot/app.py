from __future__ import annotations

import asyncio

from honeybot.config import Config, validate
from honeybot.dashboard import start_dashboard
from honeybot.enrich import dns_txt, enrich_worker, system_rdns
from honeybot.limits import Limiter
from honeybot.listeners.http import start_http
from honeybot.listeners.line import start_line
from honeybot.listeners.ssh import start_ssh
from honeybot.store import Store


class HoneyBot:
    def __init__(self, cfg: Config, txt_query=None, rdns_query=None) -> None:
        self.cfg = cfg
        self.store = Store(cfg.db_path, cfg.limits.max_db_mb)
        self.limiter = Limiter(cfg.limits.max_conn_per_ip, cfg.limits.max_global)
        self.enrich_queue: asyncio.Queue = asyncio.Queue()
        dns_server = cfg.enrich.dns_server

        async def _txt(name: str, timeout: float, _server: str = dns_server) -> str:
            return await dns_txt(name, timeout, _server)

        self.txt_query = txt_query or _txt
        self.rdns_query = rdns_query or system_rdns
        self.listeners = []
        self.bound: dict[str, int] = {}
        self.enrich_task: asyncio.Task | None = None

    async def start(self) -> None:
        validate(self.cfg)
        await self.store.start()
        self.enrich_task = asyncio.create_task(enrich_worker(self))
        starters = (
            start_ssh(self),
            start_http(self),
            start_line(self, "telnet"),
            start_line(self, "ftp"),
            start_line(self, "smtp"),
            start_line(self, "redis"),
            start_dashboard(self),
        )
        try:
            for starter in starters:
                started = await starter
                if started is None:
                    continue
                name, port, server = started
                self.bound[name] = port
                self.listeners.append(server)
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        for server in self.listeners:
            server.close()
        for server in self.listeners:
            try:
                await asyncio.wait_for(server.wait_closed(), 2)
            except TimeoutError:
                pass
        self.listeners.clear()
        if self.enrich_task is not None:
            await self.enrich_queue.put(None)
            try:
                await asyncio.wait_for(self.enrich_task, 2)
            except TimeoutError:
                self.enrich_task.cancel()
            self.enrich_task = None
        if self.store._task is not None and not self.store._stopped:
            await self.store.stop()
