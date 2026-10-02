from __future__ import annotations

import asyncio


class SessionClock:
    """Простой сбрасывается от активности клиента. Потолок сессии не сдвигается."""

    def __init__(self, idle_seconds: float, max_seconds: float) -> None:
        now = asyncio.get_running_loop().time()
        self.idle_seconds = idle_seconds
        self.max_seconds = max_seconds
        self.started = now
        self.touched = now

    def touch(self) -> None:
        self.touched = asyncio.get_running_loop().time()

    def expired(self) -> bool:
        now = asyncio.get_running_loop().time()
        if now - self.started >= self.max_seconds:
            return True
        return now - self.touched >= self.idle_seconds


class Limiter:
    """Считает живые соединения. Без очереди ожидания: лишние сразу закрываются."""

    def __init__(self, max_per_ip: int, max_global: int) -> None:
        self.max_per_ip = max_per_ip
        self.max_global = max_global
        self.global_count = 0
        self.per_ip: dict[str, int] = {}

    def try_acquire(self, ip: str) -> bool:
        if self.global_count >= self.max_global:
            return False
        if self.per_ip.get(ip, 0) >= self.max_per_ip:
            return False
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        self.global_count += 1
        return True

    def release(self, ip: str) -> None:
        self.global_count = max(0, self.global_count - 1)
        left = self.per_ip.get(ip, 0) - 1
        if left <= 0:
            self.per_ip.pop(ip, None)
        else:
            self.per_ip[ip] = left
