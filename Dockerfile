FROM python:3.12.15-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_SYSTEM_PYTHON=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin honey \
    && pip install --no-cache-dir "uv==0.9.15"

WORKDIR /app

COPY pyproject.toml uv.lock LICENSE README.md ./
COPY src ./src
COPY config.example.toml ./config.example.toml

RUN uv export --frozen --no-dev --no-emit-project --no-header -o /tmp/requirements.txt \
    && uv pip install --system --require-hashes -r /tmp/requirements.txt \
    && uv pip install --system --no-deps . \
    && rm -rf /tmp/requirements.txt /root/.cache \
    && mkdir -p /app/data \
    && chown honey:honey /app/data

USER honey

EXPOSE 2222 2121 2323 2525 6379 8080

VOLUME ["/app/data"]

CMD ["honeybot", "run"]
