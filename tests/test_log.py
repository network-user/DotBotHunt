from __future__ import annotations

import logging
import os
import stat
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

from honeybot.cli import configure_logging
from honeybot.config import ConfigError, default_config, load_config, validate

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def _isolated_logging():
    root = logging.getLogger()
    saved = list(root.handlers)
    level = root.level
    for handler in saved:
        root.removeHandler(handler)
    try:
        yield root
    finally:
        for handler in list(root.handlers):
            handler.close()
            root.removeHandler(handler)
        for handler in saved:
            root.addHandler(handler)
        root.setLevel(level)


def test_example_config_sets_a_log_file():
    cfg = load_config(ROOT / "config.example.toml")
    assert cfg.log.path == "data/honeybot.log"
    assert cfg.log.level == "INFO"
    assert cfg.log.max_mb == 10
    assert cfg.log.backups == 5


def test_log_settings_are_checked():
    cfg = default_config()
    cfg.log.level = "verbose"
    try:
        validate(cfg)
    except ConfigError as exc:
        assert "DEBUG" in str(exc)
    else:
        raise AssertionError("чужой уровень лога не должен проходить")
    cfg = default_config()
    cfg.log.max_mb = 0
    try:
        validate(cfg)
    except ConfigError as exc:
        assert "max_mb" in str(exc)
    else:
        raise AssertionError("нулевой размер лога не должен проходить")
    cfg = default_config()
    cfg.log.backups = 51
    try:
        validate(cfg)
    except ConfigError as exc:
        assert "архив" in str(exc)
    else:
        raise AssertionError("слишком много архивов не должно проходить")


def test_file_log_keeps_operator_lines(tmp_path):
    cfg = default_config()
    cfg.log.path = str(tmp_path / "honeybot.log")
    cfg.log.level = "info"
    cfg.log.max_mb = 1
    cfg.log.backups = 2
    with _isolated_logging() as root:
        configure_logging(cfg)
        logging.getLogger("honeybot").info("тест журнала")
        for handler in root.handlers:
            handler.flush()
        files = [handler for handler in root.handlers if isinstance(handler, RotatingFileHandler)]
        assert len(files) == 1
        assert files[0].maxBytes == 1024 * 1024
        assert files[0].backupCount == 2
        text = (tmp_path / "honeybot.log").read_text(encoding="utf-8")
    assert "тест журнала" in text
    assert "журнал открыт" in text
    if os.name != "nt":
        mode = stat.S_IMODE((tmp_path / "honeybot.log").stat().st_mode)
        assert mode == 0o600


def test_empty_log_path_does_not_create_a_file(tmp_path):
    cfg = default_config()
    cfg.log.path = ""
    with _isolated_logging() as root:
        configure_logging(cfg)
        logging.getLogger("honeybot").warning("только stderr")
        assert not any(isinstance(handler, RotatingFileHandler) for handler in root.handlers)
    assert list(tmp_path.iterdir()) == []


def test_log_path_rejects_a_directory(tmp_path):
    cfg = default_config()
    cfg.log.path = str(tmp_path)
    with _isolated_logging():
        try:
            configure_logging(cfg)
        except ConfigError as exc:
            assert "каталог" in str(exc)
        else:
            raise AssertionError("каталог не должен становиться файлом лога")
