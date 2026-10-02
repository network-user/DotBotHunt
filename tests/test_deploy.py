from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_license_is_all_rights_reserved():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "All Rights Reserved" in text
    assert 'license = { file = "LICENSE" }' in project


def test_lockfile_pins_runtime_with_hashes():
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert "name = \"asyncssh\"" in lock
    assert "2.24.0" in lock
    assert "hash = " in lock or "hashes = " in lock


def test_image_is_not_root_and_has_no_latest_tag():
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "USER honey" in docker
    assert ":latest" not in docker
    assert "ARG" not in docker
    assert "config.toml" in ignore
    assert ".env" in ignore


def test_ci_cannot_run_untrusted_code_with_write_token():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in workflow
    assert "contents: read" in workflow
    assert "uv sync --frozen" in workflow
