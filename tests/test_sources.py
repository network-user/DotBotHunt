from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "honeybot"
BANNED = ("subprocess", "os.system", "os.popen", "eval(", "exec(", "urllib", "http.client")


def test_sources_do_not_execute_client_input():
    files = list(ROOT.rglob("*.py"))
    assert files
    for path in files:
        text = path.read_text(encoding="utf-8")
        banned = BANNED
        if path.name == "enrich.py":
            banned = tuple(item for item in BANNED if item != "urllib")
        for item in banned:
            assert item not in text, f"{path.name} содержит {item}"
