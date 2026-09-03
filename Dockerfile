# syntax=docker/dockerfile:1.7

ARG SOURCE_REVISION=unknown

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

ARG SOURCE_REVISION

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
COPY deploy/foundation-candidate.json /tmp/foundation-candidate.json
COPY .candidate-build/ /tmp/foundation-candidate/
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

# Assemble a complete OFFLINE deployment-tool bundle from the exact locked
# application closure, the exact Platform wheel built above, and the separately
# accepted Foundation a5 wheel. The target installs every verified wheel with
# `--no-index`; it never needs a package-index credential and never rebuilds
# the Platform provider from a checkout.
RUN --mount=type=secret,id=forgejo_token \
    mkdir -p /opt/dotmac/deployment-wheelhouse \
    && "$VIRTUAL_ENV/bin/python" -m pip list --format freeze \
        --exclude dotmac-vendor-control-plane --exclude pip \
        > /tmp/deployment-tool-requirements.txt \
    && PIP_EXTRA_INDEX_URL="https://ci-reader:$(cat /run/secrets/forgejo_token)@registry.dotmac.io/api/packages/dotmac/pypi/simple" \
        "$VIRTUAL_ENV/bin/pip" download \
        --disable-pip-version-check --no-deps --only-binary=:all: \
        --requirement /tmp/deployment-tool-requirements.txt \
        --dest /opt/dotmac/deployment-wheelhouse \
    && cp dist/*.whl /tmp/foundation-candidate/*.whl \
        /opt/dotmac/deployment-wheelhouse/

RUN python3 - "$SOURCE_REVISION" <<'TOOL_BUNDLE'
import datetime as dt
import hashlib
import json
import pathlib
import sys

root = pathlib.Path("/opt/dotmac/deployment-wheelhouse")
coordinate = json.loads(
    pathlib.Path("/tmp/foundation-candidate.json").read_text(encoding="utf-8")
)
foundation = root / coordinate["wheel_filename"]
if not foundation.is_file():
    raise SystemExit(f"Foundation candidate {foundation.name} is missing")
if foundation.stat().st_size != coordinate["wheel_size_bytes"]:
    raise SystemExit("Foundation candidate size changed inside the image build")
if hashlib.sha256(foundation.read_bytes()).hexdigest() != coordinate["wheel_sha256"]:
    raise SystemExit("Foundation candidate digest changed inside the image build")
if dt.datetime.now(dt.UTC) >= dt.datetime.fromisoformat(coordinate["expires_at"]):
    raise SystemExit("Foundation candidate expired before the image was built")

files = sorted(root.glob("*.whl"))
if not files:
    raise SystemExit("deployment-tool wheelhouse is empty")
document = {
    "contract": "dotmac-deployment-tool-bundle/1",
    "source_revision": sys.argv[1],
    "foundation": {
        key: coordinate[key]
        for key in (
            "source_repository",
            "source_sha",
            "run_id",
            "artifact_id",
            "expires_at",
            "version",
            "wheel_filename",
            "wheel_sha256",
            "wheel_size_bytes",
        )
    },
    "files": [
        {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in files
    ],
}
(root / "bundle.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
TOOL_BUNDLE

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

ARG SOURCE_REVISION
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
# The external deployment-tool environment installs the assembly binding from
# the EXACT wheel this image was built from. Keeping the wheel as inert data in
# the image does not put the Foundation in the application interpreter; it
# gives the target a byte-identical provider artifact instead of asking it to
# rebuild a wheel from a checkout and hope the zip timestamps reproduce.
COPY --from=builder --chown=0:0 /opt/dotmac/deployment-wheelhouse /opt/dotmac/deployment-wheelhouse

USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "vendor_cp.main:app", "--host", "0.0.0.0", "--port", "8000"]
