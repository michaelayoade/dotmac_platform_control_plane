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
#
# Both formats are built. The wheel is what gets installed; the sdist exists so
# the release receipt can carry a digest for it, and so that "which source
# archive corresponds to this image?" has an answer that is not a rebuild.
COPY --chown=root:root src ./src
RUN poetry build --no-interaction --no-ansi \
    && "$VIRTUAL_ENV/bin/pip" install --no-deps --no-index dist/*.whl \
    && "$VIRTUAL_ENV/bin/dotmac-platform" --version

# Per-file digests of the distributions this image was assembled from, computed
# in the SAME stage that built and installed them, and carried into the image.
#
# The release receipt recorded identity at bundle granularity only — the image
# config digest and the layer chain. Those name the container; they say nothing
# about the artifacts inside it, so "which wheel is in this image?" had no
# answer that did not involve rebuilding and hoping `poetry build` is
# deterministic. It is not: a zip carries timestamps, so a wheel measured beside
# the image describes bytes the image does not contain.
#
# Computing them here and shipping the result makes the receipt's claim
# re-checkable by anyone who can pull the image, against the same bytes `pip`
# installed one instruction earlier.
RUN python3 <<'DIGESTS'
import hashlib
import json
import pathlib

files = sorted(p for p in pathlib.Path("/app/dist").iterdir() if p.is_file())
names = [p.name for p in files]
# The receipt promises a digest per distribution. If poetry ever stops emitting
# one of the two formats the receipt would silently narrow instead of failing,
# so the requirement is asserted where it is produced rather than where it is
# read.
if not any(n.endswith(".whl") for n in names):
    raise SystemExit(f"no wheel was built: {names}")
if not any(n.endswith(".tar.gz") for n in names):
    raise SystemExit(f"no sdist was built: {names}")

document = {
    "contract": "dotmac-distribution-digests/1",
    "files": [
        {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in files
    ],
}
pathlib.Path("/app/distributions.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
DIGESTS

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
# The per-file distribution digests travel WITH the artifact they describe, so
# the receipt's claim about the wheel and the sdist can be re-derived from a
# pulled image rather than trusted.
COPY --from=builder --chown=10001:10001 /app/distributions.json ./distributions.json

USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "vendor_cp.main:app", "--host", "0.0.0.0", "--port", "8000"]
