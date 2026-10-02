# AGENTS.md

> Инструкции для AI coding agents. Человеческий обзор - в [README.md](README.md).
> Источник правды - код репозитория.

## Профиль проекта

- **Тип:** cli
- **Аудитория:** internal
- **Runtime:** Python >=3.12
- **Монорепо:** нет
- **Пакет:** `honeybot` 0.1.0, точка входа `honeybot = honeybot.cli:main`

## Быстрый старт

```bash
uv sync --frozen --extra dev
uv run --frozen honeybot run
```

Нет `config.toml` - CLI берёт `config.example.toml`. Ключи `ip_api_key` и `abuseipdb_api_key` пиши только в `config.toml`. Этот файл не читай и не коммить.

Панель: http://127.0.0.1:8787. Слушатели на `0.0.0.0`: SSH 2222, HTTP 8080, telnet 2323, FTP 2121, SMTP 2525, redis 6379. База: `data/honeybot.db`.

## Сборка и проверки

| Действие | Команда |
|----------|---------|
| Установка | `uv sync --frozen --extra dev` |
| Dev | `uv run --frozen honeybot run` |
| Тесты | `uv run --frozen pytest -q` |
| Lint / typecheck | нет |
| Build | `docker build --pull -t honeybot:ci .` |

Команды сверены с `pyproject.toml` и `.github/workflows/ci.yml`. В CI перед тестами: `pip install uv==0.9.15`, затем `uv sync --frozen --extra dev`.

Флаги: `--config` (по умолчанию `config.toml`), `--db` (по умолчанию `data/honeybot.db`). Подкоманды: `run`, `stats`, `session <id>`, `export <path>`, `rebuild`. У `stats` и `export` есть `--since` (`30m`, `24h`, `7d`) и `--intent`.

## Структура репозитория

```
src/honeybot/
├── cli.py
├── app.py
├── config.py
├── store.py
├── enrich.py
├── dashboard.py
├── reconstruct.py
├── reply.py
├── vfs.py
├── report.py
├── rules.toml
└── listeners/
    ├── ssh.py
    ├── http.py
    └── line.py
tests/
config.example.toml
Dockerfile
pyproject.toml
uv.lock
.github/workflows/ci.yml
```

## Соглашения

- **Язык документации:** русский.
- **Стиль кода:** следуй существующим файлам. Отдельного ruff, mypy или black в репозитории нет.
- **Именование:** модули `snake_case`, пакет `honeybot`, тесты `tests/test_*.py`.
- **Монорепо:** нет.

## Конфигурация

Отдельного `.env.example` нет. Рабочий файл - `config.toml`, образец имён - `config.example.toml`.

| Ключ | Назначение |
|------|------------|
| `limits.*` | лимиты соединений, длина строки, тело HTTP, размер базы |
| `limits.session_seconds` | простой без данных клиента |
| `limits.max_session_seconds` | потолок сессии, не короче простоя |
| `enrich.dns_server` | DNS для Team Cymru и Spamhaus, по умолчанию `1.1.1.1` |
| `enrich.ip_api_key` | город и ISP, только HTTPS Pro; пусто - сеть не открывается |
| `enrich.abuseipdb_api_key` | AbuseIPDB; пусто - запрос выключен |
| `enrich.enable_geo` / `enable_spamhaus` | флаги обогащения |
| `dashboard.host` / `dashboard.port` | только `127.0.0.1`, порт 8787 |
| `listeners.<name>.port` | ssh, http, telnet, ftp, smtp, redis |

Не читай `config.toml`, `.env`, `*.pem`, `*.key` и файлы, в имени которых есть secret, token, credential или password.

## Что делать агенту

- Перед правками прочитай затронутые файлы и соседний код.
- После изменений запусти `uv run --frozen pytest -q`.
- **README-sync:** при глобальных изменениях функционала (новые или удалённые команды, модули, зависимости, смена архитектуры или runtime) обнови `README.md` через `generate-readme` и `AGENTS.md` через `sync-project-rules`, включая пересчёт LoC. Мелкие правки (опечатки, внутренний рефактор) README не трогают.
- Не латай разметку README вручную. Перегенерируй скиллом.
- Минимальный diff. Числа, пути и версии бери только из репозитория.
- Блок `<!-- audit:start -->` … `<!-- audit:end -->` не правь. Его обновляет `pre-deploy-audit`. Каталог `docs/audit/` из `generate-readme` не меняй.

## Чего не делать

- Не выдумывать команды, зависимости, env и порты.
- Не менять `LICENSE` без явного запроса пользователя.
- Не коммитить секреты, токены, `.env`, `config.toml`.
- Не удалять маркеры `<!-- loc:start -->` / `<!-- loc:end -->` в README.
- Не исполнять строки клиента, не скачивать URL из сессий и не открывать исходящие сокеты кроме обогащения в `enrich.py`.
- Не добавлять `urllib` или `http.client` никуда, кроме `src/honeybot/enrich.py`. Это проверяет `tests/test_sources.py`.
- Не переносить панель с `127.0.0.1` и не менять привязку слушателей с `0.0.0.0` без явного запроса.
- Не читать `config.toml` и не копировать его в образ. `.dockerignore` уже исключает этот файл.

## Приманка

DotBotHunt пишет ввод клиента и отвечает так, будто команда прошла. `reply` и `vfs` держат файлы в памяти. В строке с метасимволами оболочки отвечаем на первую команду, хвост не запускается. SQL в `store` с параметрами. Когда база больше `limits.max_db_mb`, удаляются самые старые завершённые сессии. Образ запускается не от root (`USER honey`). CI ставит `permissions.contents: read` и не использует `pull_request_target`.

## Документация

- [README.md](README.md) - запуск, команды, стек, архитектура
- [config.example.toml](config.example.toml) - порты и имена ключей
- [docs/audit/latest.md](docs/audit/latest.md) - последний отчёт аудита

## DotCore

Проект следует стандарту DotCore: плоский технический README, SVG-обложка DotBioSite, LoC-бейдж. «Обнови README» ведёт к `generate-readme`. «Обнови правила» ведёт к `sync-project-rules`.

Правила Cursor: [.cursor/rules/dotcore-project.mdc](.cursor/rules/dotcore-project.mdc). Claude Code читает [CLAUDE.md](CLAUDE.md). Канон для всех агентов - этот файл.
