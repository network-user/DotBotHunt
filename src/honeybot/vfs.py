from __future__ import annotations

import re

HOSTNAME = "web-01"
FAKE_UNAME = (
    "Linux web-01 5.15.0-91-generic #101-Ubuntu SMP "
    "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
)

_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""

_CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
cpu cores\t: 2
"""

_ISSUE = "Ubuntu 22.04.5 LTS \\n \\l\n"
_HOSTS = "127.0.0.1 localhost\n127.0.1.1 web-01\n"
_OS_RELEASE = 'NAME="Ubuntu"\nVERSION="22.04.5 LTS (Jammy Jellyfish)"\nID=ubuntu\n'
_AUTH_LOG = "sshd[812]: Server listening on 0.0.0.0 port 22.\n"


def _safe_user(username: str) -> str:
    if username == "root":
        return "root"
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "", username)[:32]
    return cleaned or "user"


class VFS:
    """Дерево файлов в памяти. Путь с `..` остаётся внутри этого дерева."""

    def __init__(self, username: str) -> None:
        self.user = _safe_user(username or "root")
        self.home = "/root" if self.user == "root" else f"/home/{self.user}"
        self.cwd = self.home
        self.dirs = {
            "/",
            "/bin",
            "/etc",
            "/home",
            "/home/ubuntu",
            "/proc",
            "/root",
            "/tmp",
            "/usr",
            "/usr/bin",
            "/var",
            "/var/log",
            "/var/www",
        }
        self.files = {
            "/etc/passwd": _PASSWD,
            "/etc/hostname": HOSTNAME + "\n",
            "/etc/issue": _ISSUE,
            "/etc/hosts": _HOSTS,
            "/etc/os-release": _OS_RELEASE,
            "/proc/cpuinfo": _CPUINFO,
            "/proc/meminfo": "MemTotal:        2048000 kB\nMemFree:         1536000 kB\n",
            "/var/log/auth.log": _AUTH_LOG,
        }
        self.dirs.add(self.home)

    def resolve(self, path: str) -> str:
        if "\x00" in path:
            return ""
        parts = [] if path.startswith("/") else [item for item in self.cwd.split("/") if item]
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        if not parts:
            return "/"
        return "/" + "/".join(parts)

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def list_dir(self, path: str) -> list[str] | None:
        resolved = self.resolve(path)
        if resolved == "":
            return None
        if resolved not in self.dirs:
            return None
        names: set[str] = set()
        for directory in self.dirs:
            if directory == "/":
                continue
            parent, _, name = directory.rpartition("/")
            parent = parent or "/"
            if parent == resolved and name:
                names.add(name)
        for file_path in self.files:
            parent, _, name = file_path.rpartition("/")
            parent = parent or "/"
            if parent == resolved and name:
                names.add(name)
        return sorted(names)

    def read_file(self, path: str) -> str | None:
        resolved = self.resolve(path)
        if resolved == "":
            return None
        return self.files.get(resolved)

    def write_file(self, path: str, content: str) -> str:
        resolved = self.resolve(path)
        if resolved in ("", "/"):
            return ""
        parent, _, name = resolved.rpartition("/")
        parent = parent or "/"
        if not name or parent not in self.dirs:
            return ""
        self.files[resolved] = content
        return resolved
