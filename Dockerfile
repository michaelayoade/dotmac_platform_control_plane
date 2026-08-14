# syntax=docker/dockerfile:1.7

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

ENV POETRY_HOME=/opt/poetry \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:/opt/poetry/bin:$PATH

COPY .github/bootstrap/poetry-requirements.txt /tmp/poetry-requirements.txt
RUN python -m venv "$POETRY_HOME" \
    && "$POETRY_HOME/bin/pip" install --disable-pip-version-check \
        --require-hashes --only-binary=:all: \
        --requirement /tmp/poetry-requirements.txt \
    && python -m venv "$VIRTUAL_ENV" \
    && poetry config virtualenvs.create false

WORKDIR /app

COPY pyproject.toml poetry.lock README.md ./
# Private Forgejo credentials are a BuildKit secret: they never become an ARG,
# ENV value, image label, or filesystem layer.
RUN --mount=type=secret,id=forgejo_token \
    POETRY_HTTP_BASIC_FORGEJO_USERNAME=ci-reader \
    POETRY_HTTP_BASIC_FORGEJO_PASSWORD="$(cat /run/secrets/forgejo_token)" \
    poetry install --only main --no-root --no-interaction --no-ansi

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/michaelayoade/dotmac_vendor_control_plane" \
      org.opencontainers.image.revision="$SOURCE_REVISION"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 vendor \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin vendor

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 src ./src
COPY --chown=10001:10001 scripts ./scripts
COPY --chown=10001:10001 alembic ./alembic
COPY --chown=10001:10001 alembic.ini ./alembic.ini

USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "vendor_cp.main:app", "--host", "0.0.0.0", "--port", "8000"]
