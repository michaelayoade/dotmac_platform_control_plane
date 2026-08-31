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

# The assembly is INSTALLED, not put on an import path. Building the wheel here
# and installing it into the same virtual environment is what makes
# `dotmac-platform` a console script with distribution metadata behind it —
# which is what `dotmac-platform diagnose self --strict` proves at runtime, and
# what lets every version this process reports come from the installer rather
# than from a literal in a source file.
#
# `--no-deps` because the resolver already ran, against the lock, above. A
# second resolution here could pick a different version from the one the lock
# pinned, and the image would then contain something the lock does not describe.
COPY --chown=root:root src ./src
RUN poetry build --format wheel --no-interaction --no-ansi \
    && "$VIRTUAL_ENV/bin/pip" install --no-deps --no-index dist/*.whl \
    && "$VIRTUAL_ENV/bin/dotmac-platform" --version

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/michaelayoade/dotmac_platform_control_plane" \
      org.opencontainers.image.revision="$SOURCE_REVISION"

# There is deliberately no PYTHONPATH. `vendor_cp` is imported from
# site-packages because the wheel is installed, and the runtime stage copies no
# `src` and no `scripts` at all — so a checkout-relative invocation has nothing
# to resolve against and fails loudly instead of quietly running whatever bytes
# were last copied into /app.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENDOR_MIGRATION_ROOT=/app

RUN groupadd --gid 10001 vendor \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin vendor

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
# The migration lineage travels as DATA, not as code. Packaging it into the
# wheel would put a top-level `alembic` directory at the wheel root, colliding
# with the Alembic distribution's own import name; `VENDOR_MIGRATION_ROOT` above
# names where it landed instead.
COPY --chown=10001:10001 alembic ./alembic
COPY --chown=10001:10001 alembic.ini ./alembic.ini

USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "vendor_cp.main:app", "--host", "0.0.0.0", "--port", "8000"]
