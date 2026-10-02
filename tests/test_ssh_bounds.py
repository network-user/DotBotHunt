from __future__ import annotations

from honeybot.listeners.ssh import HoneySession, take_shell_lines


def test_newline_does_not_lift_the_byte_cap():
    buf, lines, close = take_shell_lines("\n" + ("A" * 50), 8, 10)
    assert buf == ""
    assert lines == ["", "AAAAAAAA"]
    assert close is True


def test_too_many_lines_closes():
    buf, lines, close = take_shell_lines("id\n" * 5, 100, 3)
    assert buf == ""
    assert lines == ["id", "id", "id"]
    assert close is True


def test_partial_line_is_kept():
    buf, lines, close = take_shell_lines("una", 8, 10)
    assert (buf, lines, close) == ("una", [], False)
    buf, lines, close = take_shell_lines(buf + "me\n", 8, 10)
    assert (buf, lines, close) == ("", ["uname"], False)


class _Chan:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Limits:
    max_line_bytes = 8


class _Cfg:
    limits = _Limits()


class _App:
    cfg = _Cfg()


class _Server:
    def __init__(self) -> None:
        self.app = _App()
        self.line_count = 0
        self.intake = 0
        self.spawned: list = []

    def spawn(self, coro) -> None:
        self.spawned.append(coro)
        coro.close()


def test_data_received_closes_on_padded_long_line():
    server = _Server()
    session = HoneySession(server)
    session.chan = _Chan()
    session.data_received("\n" + ("A" * 50), None)
    assert session.chan.closed
    assert server.line_count == 2
    assert session.closing is True
