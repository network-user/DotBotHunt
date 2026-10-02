from __future__ import annotations

import os
import stat

from honeybot.config import ConfigError, default_config, validate
from honeybot.enrich import (
    enrich_ip,
    fetch_geo,
    interpret_spamhaus,
    parse_abuse,
    parse_geo,
    parse_origin,
    place_from_mmdb,
    reverse_origin,
)
from honeybot.limits import Limiter
from honeybot.reconstruct import normalize, reconstruct
from honeybot.report import format_session, format_stats
from honeybot.store import Store


def test_origin_name_is_reversed():
    assert reverse_origin("203.0.113.5") == "5.113.0.203.origin.asn.cymru.com"
    assert parse_origin("15169 | 8.8.8.0/24 | US | arin | 1992-12-01") == (
        "15169",
        "8.8.8.0/24",
        "US",
    )


async def test_enrich_uses_injected_dns_only():
    called = []

    async def txt(name, timeout):
        called.append(name)
        if "origin" in name:
            return "64496 | 203.0.113.0/24 | US | arin | 2000-01-01"
        return "64496 | US | arin | 2000-01-01 | Example Hosting, US"

    async def rdns(ip, timeout):
        called.append(ip)
        return "scanner.example"

    async def geo(ip, timeout):
        return {"country": "Нидерланды", "city": "Амстердам", "isp": "Example ISP"}

    async def spamhaus(ip, timeout):
        return "listed"

    async def abuse(ip, timeout):
        return {"abuse_score": 80, "abuse_reports": 4}

    info = await enrich_ip(
        "8.8.8.8",
        1,
        txt,
        rdns,
        geo_query=geo,
        spamhaus_query=spamhaus,
        abuse_query=abuse,
    )
    assert info["asn"] == "64496"
    assert info["org"] == "Example Hosting, US"
    assert info["country"] == "Нидерланды"
    assert info["city"] == "Амстердам"
    assert info["isp"] == "Example ISP"
    assert info["spamhaus"] == "listed"
    assert info["abuse_score"] == 80
    assert info["rdns"] == "scanner.example"
    local = await enrich_ip("127.0.0.1", 1, txt, rdns)
    assert local["org"] == "local"
    assert called[0] == "8.8.8.8"


def test_fetch_geo_without_key_stays_offline(monkeypatch):
    def explode(request, timeout):
        raise AssertionError(getattr(request, "full_url", request))

    monkeypatch.setattr("honeybot.enrich.urlopen", explode)
    assert fetch_geo("203.0.113.5", 1, "") == {}
    assert fetch_geo("203.0.113.5", 1, "   ") == {}


def test_fetch_geo_with_key_uses_https_only(monkeypatch):
    seen = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            del limit
            return b'{"status":"success","country":"US","city":"X","isp":"Y"}'

    def fake_open(request, timeout):
        del timeout
        seen["url"] = request.full_url
        return _Response()

    monkeypatch.setattr("honeybot.enrich.urlopen", fake_open)
    parsed = fetch_geo("203.0.113.5", 1, "pro-key")
    assert seen["url"].startswith("https://pro.ip-api.com/json/203.0.113.5?")
    assert "http://" not in seen["url"]
    assert parsed["city"] == "X"


def test_reputation_parsers():
    assert interpret_spamhaus(["127.0.0.4"]) == "listed"
    assert interpret_spamhaus(["127.0.0.1"]) == "clean"
    assert interpret_spamhaus(["127.255.255.254"]) == "unknown"
    assert parse_geo({"status": "success", "country": "Германия", "city": "Берлин", "isp": "X"})[
        "city"
    ] == "Берлин"
    assert parse_geo({"status": "fail"}) == {}
    assert parse_abuse({"data": {"abuseConfidenceScore": 15, "totalReports": 2}}) == {
        "abuse_score": 15,
        "abuse_reports": 2,
    }


def test_place_from_mmdb_without_file_is_empty():
    assert place_from_mmdb("", "203.0.113.5") == ("", "")
    assert place_from_mmdb("no-such-file.mmdb", "203.0.113.5") == ("", "")


def test_session_ceiling_is_at_least_idle():
    cfg = default_config()
    cfg.limits.max_session_seconds = 10
    cfg.limits.session_seconds = 90
    try:
        validate(cfg)
    except ConfigError as exc:
        assert "max_session_seconds" in str(exc)
    else:
        raise AssertionError("потолок короче простоя не должен проходить проверку")


def test_dashboard_host_is_locked():
    cfg = default_config()
    cfg.dashboard.host = "0.0.0.0"
    try:
        validate(cfg)
    except ConfigError as exc:
        assert "127.0.0.1" in str(exc)
    else:
        raise AssertionError("панель на 0.0.0.0 не должна проходить проверку")


def test_limiter_drops_extra():
    limiter = Limiter(1, 2)
    assert limiter.try_acquire("a")
    assert not limiter.try_acquire("a")
    limiter.release("a")
    assert limiter.try_acquire("a")
    assert limiter.try_acquire("b")
    assert not limiter.try_acquire("c")


async def test_stats_omit_secrets_session_keeps_them(tmp_path):
    store = Store(tmp_path / "t.db", 8)
    await store.start()
    try:
        assert await store.open_session("abc123", "203.0.113.9", 40000, 22, "ssh")
        await store.add_auth("abc123", "root", "s3cr3t", "password", True)
        await store.add_command("abc123", "uname -a", "exec", normalize("uname -a"), 0)
        await store.upsert_ip(
            {
                "ip": "203.0.113.9",
                "rdns": "scanner.example",
                "asn": "64496",
                "prefix": "203.0.113.0/24",
                "org": "Example Hosting",
                "country": "US",
            }
        )
        bundle = await store.bundle("abc123")
        result = reconstruct(bundle)
        await store.finish(
            "abc123",
            result.primary,
            result.summary,
            result.command_tags,
            result.http_tags,
            bytes_in=10,
            bytes_out=20,
            banner="SSH-2.0-libssh2",
        )
        text = format_stats(await store.stats())
        assert "s3cr3t" not in text
        assert "Example Hosting" in text
        assert "US" in text
        assert "recon_host" in text
        detail = format_session(await store.bundle("abc123"))
        assert "s3cr3t" in detail
        assert "libssh2" in detail
    finally:
        await store.stop()
    if os.name != "nt":
        mode = stat.S_IMODE((tmp_path / "t.db").stat().st_mode)
        assert mode == 0o600


def test_reports_neutralize_terminal_controls():
    stats = {
        "sessions": 1,
        "unique_ips": 1,
        "spamhaus_listed": 0,
        "top_countries": [{"country": "US\x1b[2J", "n": 1}],
        "top_cities": [],
        "top_orgs": [{"org": "Example", "asn": "1", "n": 1}],
        "top_ports": [{"proto": "ssh", "port": 22, "n": 1}],
        "top_usernames": [],
        "top_intents": [],
        "top_commands": [{"command": "id\x1b[0m", "n": 1}],
        "top_paths": [],
        "recent": [],
    }
    text = format_stats(stats)
    assert "\x1b" not in text
    assert "US^[" in text
    bundle = {
        "session": {
            "id": "abc123",
            "started_at": "t",
            "ended_at": "t",
            "ip": "203.0.113.9",
            "proto": "ssh",
            "dst_port": 22,
            "client_banner": "SSH\x1b[2J",
            "auth_result": "fake_accept",
            "username": "root",
            "bytes_in": 1,
            "bytes_out": 1,
            "summary": "ok",
        },
        "ip_info": {
            "org": "Example",
            "asn": "1",
            "country": "US",
            "city": "",
            "isp": "",
            "rdns": "a\x1b]0;x\x07b",
        },
        "auths": [
            {"username": "root", "method": "password", "fake_accepted": 1, "secret": "s3cr3t"}
        ],
        "commands": [{"raw": "uname\x1b[31m", "tags": "recon_host"}],
        "http": [],
    }
    detail = format_session(bundle)
    assert "\x1b" not in detail
    assert "s3cr3t" in detail
    assert "uname^[" in detail
    assert "a^[" in detail

