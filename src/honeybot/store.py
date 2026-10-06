from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from honeybot.util import utcnow

log = logging.getLogger("honeybot")

# Сессии, которые в отчёте разбираются по командам. Слабые метки остаются в общих таблицах.
_NOTABLE = (
    "fetch_and_run",
    "reverse_shell",
    "miner",
    "webshell",
    "persistence",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  ip TEXT NOT NULL,
  src_port INTEGER,
  dst_port INTEGER,
  proto TEXT NOT NULL,
  client_banner TEXT,
  username TEXT,
  auth_result TEXT NOT NULL DEFAULT 'none',
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  command_count INTEGER NOT NULL DEFAULT 0,
  primary_intent TEXT,
  summary TEXT
);
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  username TEXT,
  secret TEXT,
  method TEXT,
  fake_accepted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  raw TEXT NOT NULL,
  normalized TEXT,
  channel TEXT,
  exit_sent INTEGER,
  tags TEXT
);
CREATE TABLE IF NOT EXISTS http_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  method TEXT,
  path TEXT,
  query TEXT,
  headers_json TEXT,
  body_snippet TEXT,
  status_sent INTEGER,
  tags TEXT
);
CREATE TABLE IF NOT EXISTS ip_info (
  ip TEXT PRIMARY KEY,
  rdns TEXT,
  asn TEXT,
  prefix TEXT,
  org TEXT,
  country TEXT,
  city TEXT,
  isp TEXT,
  spamhaus TEXT,
  abuse_score INTEGER,
  abuse_reports INTEGER,
  looked_up_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  session_id TEXT,
  kind TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);
CREATE INDEX IF NOT EXISTS idx_http_session ON http_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);
"""


def _clip(text: object, limit: int = 240) -> str:
    raw = "" if text is None else str(text)
    if len(raw) <= limit:
        return raw
    return raw[: limit - 3] + "..."


def _bucket_width(since: str) -> int:
    """13 символов ISO - час, 10 - день. Узкое окно рисуется по часам."""
    if not since:
        return 10
    try:
        moment = datetime.fromisoformat(since)
    except ValueError:
        return 10
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - moment <= timedelta(hours=48):
        return 13
    return 10


class Store:
    """Одна очередь записи в SQLite, чтобы не ловить database is locked."""

    def __init__(self, path: Path, max_db_mb: int) -> None:
        self.path = path
        self.max_db_mb = max_db_mb
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._conn: sqlite3.Connection | None = None
        self._stopped = False

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=3000")
        self._conn.executescript(_SCHEMA)
        self._ensure_ip_columns()
        self._conn.commit()
        self._tighten()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        await self._call({"op": "stop"})
        if self._task is not None:
            await self._task

    async def open_session(
        self,
        session_id: str,
        ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
    ) -> bool:
        return bool(
            await self._call(
                {
                    "op": "open_session",
                    "session_id": session_id,
                    "ip": ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "proto": proto,
                }
            )
        )

    async def add_auth(
        self,
        session_id: str,
        username: str,
        secret: str,
        method: str,
        fake_accepted: bool,
    ) -> None:
        await self._call(
            {
                "op": "add_auth",
                "session_id": session_id,
                "username": username[:120],
                "secret": secret[:200],
                "method": method,
                "fake_accepted": int(fake_accepted),
            }
        )

    async def add_command(
        self,
        session_id: str,
        raw: str,
        channel: str,
        normalized: str,
        exit_sent: int | None = None,
    ) -> int:
        return int(
            await self._call(
                {
                    "op": "add_command",
                    "session_id": session_id,
                    "raw": raw[:4000],
                    "normalized": normalized[:500],
                    "channel": channel,
                    "exit_sent": exit_sent,
                }
            )
        )

    async def add_http(
        self,
        session_id: str,
        method: str,
        path: str,
        query: str,
        headers_json: str,
        body_snippet: str,
        status_sent: int,
    ) -> int:
        return int(
            await self._call(
                {
                    "op": "add_http",
                    "session_id": session_id,
                    "method": method[:16],
                    "path": path[:1000],
                    "query": query[:1000],
                    "headers_json": headers_json[:4000],
                    "body_snippet": body_snippet[:500],
                    "status_sent": status_sent,
                }
            )
        )

    async def add_event(self, session_id: str, kind: str, detail: str) -> None:
        await self._call(
            {
                "op": "add_event",
                "session_id": session_id,
                "kind": kind[:40],
                "detail": detail[:500],
            }
        )

    async def upsert_ip(self, info: dict) -> None:
        await self._call({"op": "upsert_ip", "info": info})

    async def ip_fresh(self, ip: str, cache_hours: int) -> bool:
        return bool(await self._call({"op": "ip_fresh", "ip": ip, "cache_hours": cache_hours}))

    async def bundle(self, session_id: str) -> dict:
        return await self._call({"op": "bundle", "session_id": session_id})

    async def finish(
        self,
        session_id: str,
        primary: str,
        summary: str,
        command_tags: dict[int, list[str]],
        http_tags: dict[int, list[str]],
        bytes_in: int | None = None,
        bytes_out: int | None = None,
        banner: str = "",
        stamp: bool = True,
    ) -> None:
        await self._call(
            {
                "op": "finish",
                "session_id": session_id,
                "primary": primary,
                "summary": summary,
                "command_tags": command_tags,
                "http_tags": http_tags,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "banner": banner,
                "stamp": stamp,
            }
        )

    async def stats(self, since: str = "", intent: str = "") -> dict:
        return await self._call({"op": "stats", "since": since, "intent": intent})

    async def report(self, since: str = "", intent: str = "") -> dict:
        """Сводка плюс срезы для файла отчёта. Секреты попыток входа не выбираются."""
        return await self._call({"op": "report", "since": since, "intent": intent})

    async def ip_view(self, ip: str) -> dict:
        return await self._call({"op": "ip_view", "ip": ip})

    async def session_ids(self) -> list[str]:
        return list(await self._call({"op": "session_ids"}))

    async def _call(self, op: dict):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        await self._queue.put((op, future))
        return await future

    async def _run(self) -> None:
        assert self._conn is not None
        while True:
            op, future = await self._queue.get()
            try:
                if op["op"] == "stop":
                    self._conn.commit()
                    if not future.done():
                        future.set_result(None)
                    return
                result = self._handle(op)
                self._conn.commit()
                self._tighten()
                if not future.done():
                    future.set_result(result)
            except Exception as exc:
                self._conn.rollback()
                if not future.done():
                    future.set_exception(exc)

    def _tighten(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix) if suffix else self.path
            try:
                if candidate.exists():
                    candidate.chmod(0o600)
            except OSError:
                continue

    def _size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix) if suffix else self.path
            try:
                total += candidate.stat().st_size
            except OSError:
                continue
        return total

    def _over_cap(self) -> bool:
        return self._size_bytes() > self.max_db_mb * 1024 * 1024

    def _shrink(self) -> None:
        assert self._conn is not None
        self._conn.commit()
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")
        except sqlite3.DatabaseError:
            log.exception("сжатие базы")

    def _delete_session(self, session_id: str) -> None:
        assert self._conn is not None
        for table in ("auth_attempts", "commands", "http_requests", "events"):
            self._conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
        self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))

    def _prune_if_needed(self) -> int:
        assert self._conn is not None
        if not self._over_cap():
            return 0
        self._shrink()
        if not self._over_cap():
            return 0
        removed = 0
        while self._over_cap() and removed < 100000:
            row = self._conn.execute(
                """
                SELECT id FROM sessions
                WHERE ended_at IS NOT NULL
                ORDER BY started_at, id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                row = self._conn.execute(
                    "SELECT id FROM sessions ORDER BY started_at, id LIMIT 1"
                ).fetchone()
            if row is not None:
                self._delete_session(row["id"])
                removed += 1
            else:
                event = self._conn.execute("SELECT id FROM events ORDER BY id LIMIT 1").fetchone()
                if event is None:
                    break
                self._conn.execute("DELETE FROM events WHERE id = ?", (event["id"],))
                removed += 1
            if removed % 50 == 0:
                self._shrink()
        if removed:
            self._shrink()
            log.info("база упёрлась в лимит, удалено старых записей: %s", removed)
        return removed

    def _handle(self, op: dict):
        name = op["op"]
        if name == "open_session":
            return self._open_session(op)
        if name == "add_auth":
            return self._add_auth(op)
        if name == "add_command":
            return self._add_command(op)
        if name == "add_http":
            return self._add_http(op)
        if name == "add_event":
            return self._add_event(op)
        if name == "upsert_ip":
            return self._upsert_ip(op)
        if name == "ip_fresh":
            return self._ip_fresh(op)
        if name == "bundle":
            return self._bundle(op["session_id"])
        if name == "finish":
            return self._finish(op)
        if name == "stats":
            return self._stats(op.get("since") or "", op.get("intent") or "")
        if name == "report":
            since = op.get("since") or ""
            intent = op.get("intent") or ""
            data = self._stats(since, intent)
            self._attach_report(data, since, intent)
            return data
        if name == "ip_view":
            return self._ip_view(op["ip"])
        if name == "session_ids":
            rows = self._conn.execute("SELECT id FROM sessions ORDER BY started_at").fetchall()
            return [row["id"] for row in rows]
        raise RuntimeError(f"неизвестная операция {name}")

    def _open_session(self, op: dict) -> bool:
        self._prune_if_needed()
        if self._over_cap():
            return False
        self._conn.execute(
            """
            INSERT INTO sessions (id, started_at, ip, src_port, dst_port, proto, auth_result)
            VALUES (?, ?, ?, ?, ?, ?, 'none')
            """,
            (op["session_id"], utcnow(), op["ip"], op["src_port"], op["dst_port"], op["proto"]),
        )
        return True

    def _add_auth(self, op: dict) -> None:
        self._prune_if_needed()
        if self._over_cap():
            return None
        self._conn.execute(
            """
            INSERT INTO auth_attempts (session_id, ts, username, secret, method, fake_accepted)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                op["session_id"],
                utcnow(),
                op["username"],
                op["secret"],
                op["method"],
                op["fake_accepted"],
            ),
        )
        return None

    def _add_command(self, op: dict) -> int:
        self._prune_if_needed()
        if self._over_cap():
            return 0
        cursor = self._conn.execute(
            """
            INSERT INTO commands (session_id, ts, raw, normalized, channel, exit_sent)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                op["session_id"],
                utcnow(),
                op["raw"],
                op["normalized"],
                op["channel"],
                op["exit_sent"],
            ),
        )
        return int(cursor.lastrowid or 0)

    def _add_http(self, op: dict) -> int:
        self._prune_if_needed()
        if self._over_cap():
            return 0
        cursor = self._conn.execute(
            """
            INSERT INTO http_requests (
              session_id, ts, method, path, query, headers_json, body_snippet, status_sent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                op["session_id"],
                utcnow(),
                op["method"],
                op["path"],
                op["query"],
                op["headers_json"],
                op["body_snippet"],
                op["status_sent"],
            ),
        )
        return int(cursor.lastrowid or 0)

    def _add_event(self, op: dict) -> None:
        self._prune_if_needed()
        if self._over_cap():
            return None
        self._conn.execute(
            "INSERT INTO events (ts, session_id, kind, detail) VALUES (?, ?, ?, ?)",
            (utcnow(), op["session_id"], op["kind"], op["detail"]),
        )
        return None

    def _ensure_ip_columns(self) -> None:
        have = {row[1] for row in self._conn.execute("PRAGMA table_info(ip_info)")}
        for name, kind in (
            ("city", "TEXT"),
            ("isp", "TEXT"),
            ("spamhaus", "TEXT"),
            ("abuse_score", "INTEGER"),
            ("abuse_reports", "INTEGER"),
        ):
            if name not in have:
                self._conn.execute(f"ALTER TABLE ip_info ADD COLUMN {name} {kind}")

    def _upsert_ip(self, op: dict) -> None:
        info = op["info"]
        self._conn.execute(
            """
            INSERT INTO ip_info (
              ip, rdns, asn, prefix, org, country, city, isp, spamhaus,
              abuse_score, abuse_reports, looked_up_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              rdns=excluded.rdns,
              asn=excluded.asn,
              prefix=excluded.prefix,
              org=excluded.org,
              country=excluded.country,
              city=excluded.city,
              isp=excluded.isp,
              spamhaus=excluded.spamhaus,
              abuse_score=excluded.abuse_score,
              abuse_reports=excluded.abuse_reports,
              looked_up_at=excluded.looked_up_at
            """,
            (
                info.get("ip", ""),
                info.get("rdns", ""),
                info.get("asn", ""),
                info.get("prefix", ""),
                info.get("org", ""),
                info.get("country", ""),
                info.get("city", ""),
                info.get("isp", ""),
                info.get("spamhaus", ""),
                info.get("abuse_score"),
                info.get("abuse_reports"),
                utcnow(),
            ),
        )
        return None

    def _ip_fresh(self, op: dict) -> bool:
        row = self._conn.execute(
            "SELECT looked_up_at FROM ip_info WHERE ip = ?",
            (op["ip"],),
        ).fetchone()
        if row is None or not row["looked_up_at"]:
            return False
        seen = row["looked_up_at"]
        try:
            moment = datetime.fromisoformat(seen)
        except ValueError:
            return False
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - moment < timedelta(hours=int(op["cache_hours"]))

    def _bundle(self, session_id: str) -> dict:
        session = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if session is None:
            return {"session": None, "ip_info": {}, "auths": [], "commands": [], "http": []}
        ip_info = self._conn.execute(
            "SELECT * FROM ip_info WHERE ip = ?",
            (session["ip"],),
        ).fetchone()
        auths = self._conn.execute(
            "SELECT * FROM auth_attempts WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        commands = self._conn.execute(
            "SELECT * FROM commands WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        http_rows = self._conn.execute(
            "SELECT * FROM http_requests WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        return {
            "session": dict(session),
            "ip_info": dict(ip_info) if ip_info else {},
            "auths": [dict(row) for row in auths],
            "commands": [dict(row) for row in commands],
            "http": [dict(row) for row in http_rows],
        }

    def _finish(self, op: dict) -> None:
        session_id = op["session_id"]
        for command_id, tags in op["command_tags"].items():
            self._conn.execute(
                "UPDATE commands SET tags = ? WHERE id = ?",
                (",".join(tags), int(command_id)),
            )
        for http_id, tags in op["http_tags"].items():
            self._conn.execute(
                "UPDATE http_requests SET tags = ? WHERE id = ?",
                (",".join(tags), int(http_id)),
            )
        auth_rows = self._conn.execute(
            """
            SELECT username, fake_accepted FROM auth_attempts
            WHERE session_id = ? ORDER BY id
            """,
            (session_id,),
        ).fetchall()
        username = ""
        auth_result = "none"
        if auth_rows:
            accepted = [row for row in auth_rows if row["fake_accepted"]]
            if accepted:
                auth_result = "fake_accept"
                username = accepted[-1]["username"] or ""
            else:
                auth_result = "fail"
                username = auth_rows[-1]["username"] or ""
        assignments = ["primary_intent = ?", "summary = ?", "username = ?", "auth_result = ?"]
        values: list = [op["primary"], op["summary"], username, auth_result]
        if op.get("stamp", True):
            assignments.append("ended_at = ?")
            values.append(utcnow())
        if op.get("banner"):
            assignments.append("client_banner = ?")
            values.append(op["banner"][:300])
        if op.get("bytes_in") is not None:
            assignments.append("bytes_in = ?")
            values.append(int(op["bytes_in"]))
        if op.get("bytes_out") is not None:
            assignments.append("bytes_out = ?")
            values.append(int(op["bytes_out"]))
        command_count = self._conn.execute(
            "SELECT COUNT(*) AS n FROM commands WHERE session_id = ?",
            (session_id,),
        ).fetchone()["n"]
        command_count += self._conn.execute(
            "SELECT COUNT(*) AS n FROM http_requests WHERE session_id = ?",
            (session_id,),
        ).fetchone()["n"]
        assignments.append("command_count = ?")
        values.append(command_count)
        values.append(session_id)
        self._conn.execute(
            f"UPDATE sessions SET {', '.join(assignments)} WHERE id = ?",
            values,
        )
        return None

    def _where(self, since: str, intent: str, extra: list[str] | None = None) -> tuple[str, list]:
        clauses: list[str] = []
        params: list = []
        if since:
            clauses.append("s.started_at >= ?")
            params.append(since)
        if intent:
            clauses.append("s.primary_intent = ?")
            params.append(intent)
        clauses.extend(extra or [])
        if not clauses:
            return "", params
        return " WHERE " + " AND ".join(clauses), params

    def _stats(self, since: str = "", intent: str = "") -> dict:
        assert self._conn is not None
        where, params = self._where(since, intent)
        totals = self._conn.execute(
            f"SELECT COUNT(*) AS sessions, COUNT(DISTINCT s.ip) AS ips FROM sessions s{where}",
            params,
        ).fetchone()
        orgs = self._conn.execute(
            f"""
            SELECT COALESCE(NULLIF(i.org, ''), 'неизвестно') AS org,
                   COALESCE(i.asn, '') AS asn,
                   COUNT(DISTINCT s.ip) AS n
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {where}
            GROUP BY org, asn
            ORDER BY n DESC
            LIMIT 10
            """,
            params,
        ).fetchall()
        ports = self._conn.execute(
            f"""
            SELECT s.dst_port AS port, s.proto AS proto, COUNT(*) AS n
            FROM sessions s
            {where}
            GROUP BY s.dst_port, s.proto
            ORDER BY n DESC
            LIMIT 10
            """,
            params,
        ).fetchall()
        user_where, user_params = self._where(
            since,
            intent,
            ["a.username IS NOT NULL", "a.username != ''"],
        )
        users = self._conn.execute(
            f"""
            SELECT a.username AS username, COUNT(*) AS n
            FROM auth_attempts a
            JOIN sessions s ON s.id = a.session_id
            {user_where}
            GROUP BY a.username
            ORDER BY n DESC
            LIMIT 10
            """,
            user_params,
        ).fetchall()
        intent_where, intent_params = self._where(
            since,
            intent,
            ["s.primary_intent IS NOT NULL", "s.primary_intent != ''"],
        )
        intents = self._conn.execute(
            f"""
            SELECT s.primary_intent AS intent, COUNT(*) AS n
            FROM sessions s
            {intent_where}
            GROUP BY s.primary_intent
            ORDER BY n DESC
            """,
            intent_params,
        ).fetchall()
        command_where, command_params = self._where(
            since,
            intent,
            ["c.normalized IS NOT NULL", "c.normalized != ''"],
        )
        commands = self._conn.execute(
            f"""
            SELECT c.normalized AS command, COUNT(*) AS n
            FROM commands c
            JOIN sessions s ON s.id = c.session_id
            {command_where}
            GROUP BY c.normalized
            ORDER BY n DESC
            LIMIT 10
            """,
            command_params,
        ).fetchall()
        paths = self._conn.execute(
            f"""
            SELECT h.path AS path, COUNT(*) AS n
            FROM http_requests h
            JOIN sessions s ON s.id = h.session_id
            {where}
            GROUP BY h.path
            ORDER BY n DESC
            LIMIT 10
            """,
            params,
        ).fetchall()
        countries = self._conn.execute(
            f"""
            SELECT COALESCE(NULLIF(i.country, ''), 'неизвестно') AS country,
                   COUNT(DISTINCT s.ip) AS n
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {where}
            GROUP BY country
            ORDER BY n DESC
            LIMIT 10
            """,
            params,
        ).fetchall()
        city_where, city_params = self._where(
            since,
            intent,
            ["i.city IS NOT NULL", "i.city != ''"],
        )
        cities = self._conn.execute(
            f"""
            SELECT i.city AS city, COUNT(DISTINCT s.ip) AS n
            FROM sessions s
            JOIN ip_info i ON i.ip = s.ip
            {city_where}
            GROUP BY i.city
            ORDER BY n DESC
            LIMIT 10
            """,
            city_params,
        ).fetchall()
        listed_where, listed_params = self._where(since, intent, ["i.spamhaus = 'listed'"])
        listed = self._conn.execute(
            f"""
            SELECT COUNT(DISTINCT s.ip) AS n
            FROM sessions s
            JOIN ip_info i ON i.ip = s.ip
            {listed_where}
            """,
            listed_params,
        ).fetchone()
        recent = self._conn.execute(
            f"""
            SELECT s.id, s.started_at, s.ip, s.proto, s.dst_port, s.primary_intent, s.summary,
                   COALESCE(i.country, '') AS country
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {where}
            ORDER BY s.started_at DESC
            LIMIT 20
            """,
            params,
        ).fetchall()
        plain_clauses = ["s.primary_intent = 'unclassified'", "c.normalized IS NOT NULL", "c.normalized != ''"]
        plain_params: list = []
        if since:
            plain_clauses.append("s.started_at >= ?")
            plain_params.append(since)
        plain_where = " WHERE " + " AND ".join(plain_clauses)
        unclassified = self._conn.execute(
            f"""
            SELECT c.normalized AS command, COUNT(*) AS n
            FROM commands c
            JOIN sessions s ON s.id = c.session_id
            {plain_where}
            GROUP BY c.normalized
            ORDER BY n DESC
            LIMIT 10
            """,
            plain_params,
        ).fetchall()
        if since:
            events = self._conn.execute(
                """
                SELECT ts, session_id, kind, detail
                FROM events
                WHERE ts >= ?
                ORDER BY id DESC
                LIMIT 15
                """,
                (since,),
            ).fetchall()
        else:
            events = self._conn.execute(
                """
                SELECT ts, session_id, kind, detail
                FROM events
                ORDER BY id DESC
                LIMIT 15
                """
            ).fetchall()
        return {
            "sessions": totals["sessions"],
            "unique_ips": totals["ips"],
            "spamhaus_listed": listed["n"],
            "top_countries": [dict(row) for row in countries],
            "top_cities": [dict(row) for row in cities],
            "top_orgs": [dict(row) for row in orgs],
            "top_ports": [dict(row) for row in ports],
            "top_usernames": [dict(row) for row in users],
            "top_intents": [dict(row) for row in intents],
            "top_commands": [dict(row) for row in commands],
            "top_paths": [dict(row) for row in paths],
            "top_unclassified": [dict(row) for row in unclassified],
            "recent": [dict(row) for row in recent],
            "recent_events": [dict(row) for row in events],
            "db_bytes": self._size_bytes(),
            "db_cap_bytes": self.max_db_mb * 1024 * 1024,
            "recording": not self._over_cap(),
            "since": since,
            "intent": intent,
        }

    def _attach_report(self, data: dict, since: str, intent: str) -> None:
        assert self._conn is not None
        where, params = self._where(since, intent)
        ips = self._conn.execute(
            f"""
            SELECT s.ip AS ip,
                   COUNT(*) AS n,
                   COALESCE(i.country, '') AS country,
                   COALESCE(i.city, '') AS city,
                   COALESCE(i.org, '') AS org,
                   COALESCE(i.asn, '') AS asn,
                   COALESCE(i.isp, '') AS isp,
                   COALESCE(i.spamhaus, '') AS spamhaus,
                   i.abuse_score AS abuse_score,
                   i.abuse_reports AS abuse_reports
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {where}
            GROUP BY s.ip
            ORDER BY n DESC, s.ip
            LIMIT 15
            """,
            params,
        ).fetchall()
        width = _bucket_width(since)
        buckets = self._conn.execute(
            f"""
            SELECT substr(s.started_at, 1, {width}) AS bucket, COUNT(*) AS n
            FROM sessions s
            {where}
            GROUP BY bucket
            ORDER BY bucket DESC
            LIMIT 48
            """,
            params,
        ).fetchall()
        auth = self._conn.execute(
            f"""
            SELECT COUNT(*) AS attempts,
                   COALESCE(SUM(CASE WHEN a.fake_accepted != 0 THEN 1 ELSE 0 END), 0) AS accepted
            FROM auth_attempts a
            JOIN sessions s ON s.id = a.session_id
            {where}
            """,
            params,
        ).fetchone()
        channels = self._conn.execute(
            f"""
            SELECT COALESCE(NULLIF(c.channel, ''), 'неизвестно') AS channel, COUNT(*) AS n
            FROM commands c
            JOIN sessions s ON s.id = c.session_id
            {where}
            GROUP BY channel
            ORDER BY n DESC
            """,
            params,
        ).fetchall()
        methods = self._conn.execute(
            f"""
            SELECT COALESCE(NULLIF(h.method, ''), '-') AS method, COUNT(*) AS n
            FROM http_requests h
            JOIN sessions s ON s.id = h.session_id
            {where}
            GROUP BY method
            ORDER BY n DESC
            LIMIT 8
            """,
            params,
        ).fetchall()
        traffic = self._conn.execute(
            f"""
            SELECT COALESCE(SUM(s.bytes_in), 0) AS bytes_in,
                   COALESCE(SUM(s.bytes_out), 0) AS bytes_out
            FROM sessions s
            {where}
            """,
            params,
        ).fetchone()
        names = ",".join(f"'{name}'" for name in _NOTABLE)
        notable_where, notable_params = self._where(
            since,
            intent,
            [f"s.primary_intent IN ({names})"],
        )
        notable_rows = self._conn.execute(
            f"""
            SELECT s.id, s.started_at, s.ended_at, s.ip, s.proto, s.dst_port,
                   s.primary_intent, s.summary, s.username, s.auth_result, s.command_count,
                   COALESCE(i.country, '') AS country,
                   COALESCE(i.org, '') AS org,
                   COALESCE(i.spamhaus, '') AS spamhaus,
                   i.abuse_score AS abuse_score
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {notable_where}
            ORDER BY s.started_at DESC
            LIMIT 25
            """,
            notable_params,
        ).fetchall()
        notable_ids = [row["id"] for row in notable_rows]
        # Тело HTTP и секрет входа не берём: отчёт можно переслать, пароль остаётся в панели.
        command_lines = self._grouped_lines(notable_ids, "commands", "raw", 8)
        http_lines = self._grouped_lines(
            notable_ids,
            "http_requests",
            "COALESCE(method, '') || ' ' || COALESCE(path, '')"
            " || CASE WHEN COALESCE(query, '') != '' THEN '?' || query ELSE '' END",
            6,
        )
        notable = []
        for row in notable_rows:
            item = dict(row)
            item["commands"] = command_lines.get(row["id"], [])
            item["http"] = http_lines.get(row["id"], [])
            notable.append(item)
        session_rows = self._conn.execute(
            f"""
            SELECT s.id, s.started_at, s.ended_at, s.ip, s.proto, s.dst_port,
                   s.primary_intent, s.summary, s.username, s.auth_result, s.command_count,
                   COALESCE(i.country, '') AS country,
                   COALESCE(i.org, '') AS org,
                   COALESCE(i.asn, '') AS asn,
                   COALESCE(i.spamhaus, '') AS spamhaus,
                   i.abuse_score AS abuse_score
            FROM sessions s
            LEFT JOIN ip_info i ON i.ip = s.ip
            {where}
            ORDER BY s.started_at DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
        if since:
            events = self._conn.execute(
                """
                SELECT ts, session_id, kind, detail
                FROM events
                WHERE ts >= ?
                ORDER BY id DESC
                LIMIT 50
                """,
                (since,),
            ).fetchall()
        else:
            events = self._conn.execute(
                """
                SELECT ts, session_id, kind, detail
                FROM events
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()
        attempts = int(auth["attempts"] or 0)
        accepted = int(auth["accepted"] or 0)
        rows = [dict(row) for row in session_rows]
        data["top_ips"] = [dict(row) for row in ips]
        data["timeline"] = [dict(row) for row in reversed(buckets)]
        data["timeline_unit"] = "hour" if width == 13 else "day"
        data["auth"] = {
            "attempts": attempts,
            "accepted": accepted,
            "rejected": attempts - accepted,
        }
        data["top_channels"] = [dict(row) for row in channels]
        data["top_methods"] = [dict(row) for row in methods]
        data["bytes_in"] = int(traffic["bytes_in"] or 0)
        data["bytes_out"] = int(traffic["bytes_out"] or 0)
        data["notable"] = notable
        data["session_rows"] = rows
        data["session_rows_capped"] = int(data["sessions"]) > len(rows)
        data["events"] = [dict(row) for row in events]

    def _grouped_lines(
        self,
        ids: list[str],
        table: str,
        expr: str,
        limit_each: int,
    ) -> dict[str, list[str]]:
        grouped = {item: [] for item in ids}
        if not ids:
            return grouped
        if table not in {"commands", "http_requests"}:
            raise RuntimeError("неизвестная таблица отчёта")
        assert self._conn is not None
        marks = ",".join("?" for _ in ids)
        found = self._conn.execute(
            f"SELECT session_id, {expr} AS line FROM {table} WHERE session_id IN ({marks}) ORDER BY id",
            ids,
        ).fetchall()
        for row in found:
            bucket = grouped.get(row["session_id"])
            if bucket is None or len(bucket) >= limit_each:
                continue
            bucket.append(_clip(row["line"]))
        return grouped

    def _ip_view(self, ip: str) -> dict:
        assert self._conn is not None
        info = self._conn.execute("SELECT * FROM ip_info WHERE ip = ?", (ip,)).fetchone()
        total = self._conn.execute(
            "SELECT COUNT(*) AS n FROM sessions WHERE ip = ?",
            (ip,),
        ).fetchone()["n"]
        sessions = self._conn.execute(
            """
            SELECT id, started_at, ended_at, proto, dst_port, primary_intent, summary,
                   username, auth_result, command_count
            FROM sessions
            WHERE ip = ?
            ORDER BY started_at DESC
            LIMIT 100
            """,
            (ip,),
        ).fetchall()
        ids = [row["id"] for row in sessions]
        auths = []
        if ids:
            marks = ",".join("?" for _ in ids)
            auths = self._conn.execute(
                f"""
                SELECT session_id, username, secret, method, fake_accepted
                FROM auth_attempts
                WHERE session_id IN ({marks})
                ORDER BY id
                """,
                ids,
            ).fetchall()
        return {
            "ip": ip,
            "ip_info": dict(info) if info else {},
            "sessions": [dict(row) for row in sessions],
            "auths": [dict(row) for row in auths],
            "total": total,
        }
