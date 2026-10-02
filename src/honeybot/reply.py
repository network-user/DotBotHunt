from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from honeybot.vfs import FAKE_UNAME, HOSTNAME, VFS, _IFCONFIG, _IP_ADDR, _IP_ROUTE

_META = ("|", ";", "&", "`", "$(", "\n", ">", "<")
_DOWNLOAD = {"wget", "curl", "tftp"}
_SIMPLE = {
    "uname",
    "id",
    "whoami",
    "pwd",
    "ls",
    "cat",
    "echo",
    "hostname",
    "df",
    "free",
    "ps",
    "cd",
    "wget",
    "curl",
    "tftp",
    "exit",
    "env",
    "history",
    "ip",
    "ifconfig",
}


@dataclass
class Reply:
    stdout: str
    exit_code: int
    close: bool = False


def has_shell_meta(line: str) -> bool:
    return any(token in line for token in _META)


def first_segment(line: str) -> str:
    """Текст до первого метасимвола. Хвост с подстановкой и конвейером не исполняется."""
    indexes = [line.find(mark) for mark in _META if mark in line]
    if not indexes:
        return line
    return line[: min(indexes)]


def prompt(vfs: VFS) -> str:
    if vfs.cwd == vfs.home:
        shown = "~"
    elif vfs.cwd.startswith(vfs.home + "/"):
        shown = "~" + vfs.cwd[len(vfs.home) :]
    else:
        shown = vfs.cwd
    sigil = "#" if vfs.user == "root" else "$"
    return f"{vfs.user}@{HOSTNAME}:{shown}{sigil} "


def respond(vfs: VFS, line: str) -> Reply:
    """Ответ на одну строку. Метасимволы оболочки не разбираются и не запускаются."""
    raw = line.strip()
    if not raw:
        return Reply("", 0)
    segment = first_segment(raw).strip() if has_shell_meta(raw) else raw
    if not segment:
        return Reply("", 0)
    try:
        parts = shlex.split(segment, posix=True)
    except ValueError:
        return Reply("", 0)
    if not parts:
        return Reply("", 0)
    command = parts[0]
    if command not in _SIMPLE:
        return Reply(f"bash: {command}: command not found\n", 127)
    handler = _HANDLERS[command]
    return handler(vfs, parts)


def _uname(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    return Reply(FAKE_UNAME + "\n", 0)


def _id(vfs: VFS, parts: list[str]) -> Reply:
    del parts
    if vfs.user == "root":
        text = "uid=0(root) gid=0(root) groups=0(root)\n"
    else:
        text = f"uid=1000({vfs.user}) gid=1000({vfs.user}) groups=1000({vfs.user})\n"
    return Reply(text, 0)


def _whoami(vfs: VFS, parts: list[str]) -> Reply:
    del parts
    return Reply(vfs.user + "\n", 0)


def _pwd(vfs: VFS, parts: list[str]) -> Reply:
    del parts
    return Reply(vfs.cwd + "\n", 0)


def _hostname(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    return Reply(HOSTNAME + "\n", 0)


def _echo(vfs: VFS, parts: list[str]) -> Reply:
    del vfs
    return Reply(" ".join(parts[1:]) + "\n", 0)


def _ls(vfs: VFS, parts: list[str]) -> Reply:
    target = "."
    for arg in parts[1:]:
        if not arg.startswith("-"):
            target = arg
            break
    names = vfs.list_dir(target)
    if names is None:
        return Reply(f"ls: cannot access '{target}': No such file or directory\n", 2)
    return Reply("\n".join(names) + ("\n" if names else ""), 0)


def _cat(vfs: VFS, parts: list[str]) -> Reply:
    paths = [arg for arg in parts[1:] if not arg.startswith("-")]
    if not paths:
        return Reply("", 0)
    chunks: list[str] = []
    code = 0
    for path in paths:
        content = vfs.read_file(path)
        if content is None:
            chunks.append(f"cat: {path}: No such file or directory\n")
            code = 1
        else:
            chunks.append(content if content.endswith("\n") or content == "" else content + "\n")
    return Reply("".join(chunks), code)


def _cd(vfs: VFS, parts: list[str]) -> Reply:
    target = vfs.home if len(parts) == 1 else parts[1]
    resolved = vfs.resolve(target)
    if resolved == "" or not vfs.is_dir(resolved):
        return Reply(f"bash: cd: {target}: No such file or directory\n", 1)
    vfs.cwd = resolved
    return Reply("", 0)


def _df(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    text = (
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "/dev/sda1       51200000 8123456  40654320  17% /\n"
    )
    return Reply(text, 0)


def _free(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    text = (
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         2048000      512000     1400000        1200      136000     1536000\n"
        "Swap:              0           0           0\n"
    )
    return Reply(text, 0)


def _ps(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    text = (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  812 ?        00:00:00 sshd\n"
        "  940 ?        00:00:01 nginx\n"
    )
    return Reply(text, 0)


def _download(vfs: VFS, parts: list[str]) -> Reply:
    url = ""
    for arg in parts[1:]:
        if "://" in arg:
            url = arg
            break
    leaf = "download"
    if url:
        name = url.split("/")[-1].split("?")[0]
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "", name)[:40]
        if cleaned not in ("", ".", ".."):
            leaf = cleaned
    elif len(parts) > 1:
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "", parts[-1])[:40]
        if cleaned not in ("", ".", ".."):
            leaf = cleaned
    path = vfs.write_file("/tmp/" + leaf, "")
    if not path:
        path = "/tmp/" + leaf
    return Reply(f"-- saved to '{path}'\n", 0)


def _exit(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    return Reply("", 0, close=True)


def _env(vfs: VFS, parts: list[str]) -> Reply:
    del parts
    text = (
        f"USER={vfs.user}\n"
        f"HOME={vfs.home}\n"
        f"PWD={vfs.cwd}\n"
        "SHELL=/bin/bash\n"
        f"HOSTNAME={HOSTNAME}\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
    )
    return Reply(text, 0)


def _history(vfs: VFS, parts: list[str]) -> Reply:
    del parts
    content = vfs.read_file(vfs.home + "/.bash_history") or ""
    lines = [item for item in content.splitlines() if item]
    shown = [f"  {index}  {item}" for index, item in enumerate(lines, start=1)]
    return Reply("\n".join(shown) + ("\n" if shown else ""), 0)


def _ip(vfs: VFS, parts: list[str]) -> Reply:
    del vfs
    if len(parts) > 1 and parts[1] in {"route", "r"}:
        return Reply(_IP_ROUTE, 0)
    if len(parts) > 1 and parts[1] not in {"a", "addr", "address", "link"}:
        return Reply(f"Command \"{parts[1]}\" is unknown, try \"ip help\".\n", 1)
    return Reply(_IP_ADDR, 0)


def _ifconfig(vfs: VFS, parts: list[str]) -> Reply:
    del vfs, parts
    return Reply(_IFCONFIG, 0)


_HANDLERS = {
    "uname": _uname,
    "id": _id,
    "whoami": _whoami,
    "pwd": _pwd,
    "ls": _ls,
    "cat": _cat,
    "echo": _echo,
    "hostname": _hostname,
    "df": _df,
    "free": _free,
    "ps": _ps,
    "cd": _cd,
    "wget": _download,
    "curl": _download,
    "tftp": _download,
    "exit": _exit,
    "env": _env,
    "history": _history,
    "ip": _ip,
    "ifconfig": _ifconfig,
}
