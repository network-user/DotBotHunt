from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import asyncssh

from honeybot.closing import finalize_session
from honeybot.reconstruct import normalize
from honeybot.reply import prompt, respond
from honeybot.util import new_id, normalize_ip
from honeybot.vfs import VFS

log = logging.getLogger("honeybot")

# Потолок на одно SSH-соединение. Перевод строки его не снимает:
# иначе клиент копит строки в памяти, пока не кончится session_seconds.
_MAX_SSH_LINES = 128
_MAX_SSH_INTAKE = 256 * 1024


def take_shell_lines(buf: str, limit: int, max_lines: int) -> tuple[str, list[str], bool]:
    """Законченные строки, остаток и флаг «канал пора закрыть».

    Слишком длинная строка обрезается до limit и закрывает канал.
    max_lines отсчитывается от уже принятых в этой сессии строк.
    """
    if max_lines <= 0 or limit <= 0:
        return "", [], True
    lines: list[str] = []
    while len(lines) < max_lines:
        if "\n" not in buf:
            if len(buf) > limit:
                lines.append(buf[:limit])
                return "", lines, True
            return buf, lines, False
        line, buf = buf.split("\n", 1)
        line = line.rstrip("\r")
        if len(line) > limit:
            lines.append(line[:limit])
            return "", lines, True
        lines.append(line)
    if buf:
        return "", lines, True
    return "", lines, False


def load_host_key(data_dir: Path):
    path = data_dir / "ssh_host_ed25519"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return asyncssh.read_private_key(path)
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.write_bytes(key.export_private_key())
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


class HoneySession(asyncssh.SSHServerSession):
    def __init__(self, server: "HoneySSHServer") -> None:
        self.server = server
        self.chan = None
        self.exec_command: str | None = None
        self.buf = ""
        self.mode = ""
        self.closing = False

    def connection_made(self, chan) -> None:
        self.chan = chan

    def pty_requested(self, term_type, term_size, term_modes) -> bool:
        del term_type, term_size, term_modes
        return True

    def shell_requested(self) -> bool:
        self.mode = "shell"
        return True

    def exec_requested(self, command: str) -> bool:
        self.mode = "exec"
        limit = self.server.app.cfg.limits.max_line_bytes
        self.exec_command = command[:limit]
        return True

    def session_started(self) -> None:
        if self.mode == "exec":
            self.server.spawn(self._run_remote())
        elif self.mode == "shell" and self.chan is not None:
            text = prompt(self.server.vfs_for())
            self.server.bytes_out += len(text)
            self.chan.write(text)

    def data_received(self, data, datatype) -> None:
        del datatype
        if self.closing or self.chan is None:
            return
        text = data if isinstance(data, str) else data.decode("utf-8", "replace")
        room = _MAX_SSH_INTAKE - self.server.intake
        if room <= 0:
            self._drop()
            return
        overflow = len(text) > room
        if overflow:
            text = text[:room]
        self.server.intake += len(text)
        self.buf += text
        limit = self.server.app.cfg.limits.max_line_bytes
        left = _MAX_SSH_LINES - self.server.line_count
        self.buf, lines, close = take_shell_lines(self.buf, limit, left)
        self.server.line_count += len(lines)
        if lines:
            self.server.spawn(self._run_lines(lines))
        if close or overflow or self.server.line_count >= _MAX_SSH_LINES:
            self._drop()

    def _drop(self) -> None:
        self.closing = True
        self.buf = ""
        if self.chan is not None:
            self.chan.close()

    async def _run_remote(self) -> None:
        command = self.exec_command or ""
        async with self.server.lock:
            reply = respond(self.server.vfs_for(), command)
            await self.server.write_command(command, "exec", reply.exit_code)
            if self.chan is not None:
                if reply.stdout:
                    self.server.bytes_out += len(reply.stdout)
                    self.chan.write(reply.stdout)
                self.chan.exit(reply.exit_code)
                self.chan.close()

    async def _run_lines(self, lines: list[str]) -> None:
        async with self.server.lock:
            for line in lines:
                if not line.strip():
                    if self.chan is not None and not self.closing:
                        text = prompt(self.server.vfs_for())
                        self.server.bytes_out += len(text)
                        self.chan.write(text)
                    continue
                reply = respond(self.server.vfs_for(), line)
                await self.server.write_command(line, "shell", reply.exit_code)
                if self.closing or self.chan is None:
                    continue
                if reply.stdout:
                    self.server.bytes_out += len(reply.stdout)
                    self.chan.write(reply.stdout)
                if reply.close:
                    self.chan.exit(0)
                    self.chan.close()
                    return
                text = prompt(self.server.vfs_for())
                self.server.bytes_out += len(text)
                self.chan.write(text)


class HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, app) -> None:
        self.app = app
        self.conn = None
        self.ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.session_id = ""
        self.username = ""
        self.vfs: VFS | None = None
        self.auth_fails = 0
        self.lock = asyncio.Lock()
        self.pending: set[asyncio.Task] = set()
        self.opened = False
        self.acquired = False
        self.released = False
        self.shutting = False
        self.bytes_in = 0
        self.bytes_out = 0
        self.line_count = 0
        self.intake = 0
        self.timer = None

    def vfs_for(self) -> VFS:
        if self.vfs is None:
            self.vfs = VFS(self.username or "root")
        return self.vfs

    def spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    def connection_made(self, conn) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("", 0)
        sock = conn.get_extra_info("sockname") or ("", 0)
        self.ip = normalize_ip(str(peer[0]))
        self.src_port = int(peer[1] or 0)
        self.dst_port = int(sock[1] or 0)
        if not self.app.limiter.try_acquire(self.ip):
            self.spawn(self.app.store.add_event("", "limit", self.ip))
            conn.close()
            return
        self.acquired = True
        self.session_id = new_id()
        self.timer = asyncio.get_running_loop().call_later(
            self.app.cfg.limits.session_seconds,
            conn.close,
        )
        self.spawn(self._open())

    def connection_lost(self, exc) -> None:
        del exc
        if self.shutting:
            return
        self.shutting = True
        if self.timer is not None:
            self.timer.cancel()
        asyncio.create_task(self._shutdown())

    async def _open(self) -> None:
        async with self.lock:
            opened = await self.app.store.open_session(
                self.session_id,
                self.ip,
                self.src_port,
                self.dst_port,
                "ssh",
            )
            self.opened = bool(opened)
            if self.opened:
                try:
                    self.app.enrich_queue.put_nowait(self.ip)
                except Exception:
                    log.exception("очередь обогащения")
            elif self.conn is not None:
                self.conn.close()

    def begin_auth(self, username: str) -> bool:
        self.username = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        need = self.app.cfg.listeners["ssh"].fail_before_accept
        accepted = self.auth_fails >= need
        if not accepted:
            self.auth_fails += 1
        else:
            self.username = username
            self.vfs = VFS(username)
        self.spawn(self._auth(username, password, "password", accepted))
        return accepted

    def validate_public_key(self, username: str, key) -> bool:
        try:
            fingerprint = key.get_fingerprint()
        except Exception:
            fingerprint = "publickey"
        self.spawn(self._auth(username, fingerprint, "publickey", False))
        return False

    async def _auth(self, username: str, secret: str, method: str, accepted: bool) -> None:
        async with self.lock:
            if not self.opened:
                return
            await self.app.store.add_auth(self.session_id, username, secret, method, accepted)

    def session_requested(self):
        return HoneySession(self)

    def connection_requested(self, dest_host: str, dest_port: int, orig_host: str, orig_port: int) -> bool:
        del orig_host, orig_port
        self.spawn(self.record(f"direct-tcpip {dest_host}:{dest_port}", "exec", 1))
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        self.spawn(self.record(f"tcpip-forward {listen_host}:{listen_port}", "exec", 1))
        return False

    async def record(self, raw: str, channel: str, exit_sent: int) -> None:
        async with self.lock:
            await self.write_command(raw, channel, exit_sent)

    async def write_command(self, raw: str, channel: str, exit_sent: int) -> None:
        if not self.opened:
            return
        self.bytes_in += len(raw)
        await self.app.store.add_command(
            self.session_id,
            raw,
            channel,
            normalize(raw),
            exit_sent,
        )

    async def _shutdown(self) -> None:
        while self.pending:
            current = list(self.pending)
            if not current:
                break
            await asyncio.gather(*current, return_exceptions=True)
        try:
            if self.opened:
                banner = ""
                if self.conn is not None:
                    banner = self.conn.get_extra_info("client_version") or ""
                await finalize_session(self.app, self.session_id, self.bytes_in, self.bytes_out, banner)
        finally:
            if self.acquired and not self.released:
                self.released = True
                self.app.limiter.release(self.ip)


async def start_ssh(app):
    listener = app.cfg.listeners["ssh"]
    if not listener.enabled:
        return None
    key = load_host_key(app.cfg.db_path.parent)
    acceptor = await asyncssh.create_server(
        lambda: HoneySSHServer(app),
        "0.0.0.0",
        listener.port,
        server_host_keys=[key],
        server_version="OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        rdns_lookup=False,
        line_editor=False,
        x11_forwarding=False,
        agent_forwarding=False,
        allow_scp=False,
        password_auth=True,
        public_key_auth=True,
        encoding="utf-8",
        errors="replace",
        login_timeout=30,
    )
    port = acceptor.get_port()
    log.info("ssh слушает порт %s", port)
    return "ssh", port, acceptor
