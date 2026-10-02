from __future__ import annotations


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
