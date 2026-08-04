#!/usr/bin/env bash
# Regenerate .github/bootstrap/poetry-requirements.txt — the ONE command.
#
#   .github/bootstrap/regenerate.sh [poetry==<version>]
#
# Run this whenever the pinned Poetry version moves. A stale lock fails closed
# (loudly, in every job at once) rather than silently installing something
# unpinned, which is the intended trade — but it means bumping Poetry is a
# deliberate two-step: change the version here, commit the regenerated file.
#
# WHY A CONTAINER, and why linux/amd64 cp312 specifically:
#
# pip evaluates environment markers against the RUNNING interpreter. Its
# --platform/--python-version flags select wheel TAGS only; they do not change
# marker evaluation. Resolving on macOS therefore produces a genuinely
# different dependency SET than CI needs — it pulls `xattr`
# (sys_platform == "darwin") and omits `SecretStorage`/`jeepney`/`cryptography`
# (sys_platform == "linux"), which keyring needs. That bootstrap would install
# and then misbehave, so the resolution has to happen on the target platform.
#
# Both CI runners are linux x86_64 on Python 3.12 (`ubuntu-latest` and the
# self-hosted `dotmac-s3`), so this pins the same.
#
# The generated file records the sha256 of EVERY distribution PyPI publishes
# for each resolved version, not only the wheel this run selected: a runner
# image with a different glibc or a newer manylinux tag may legitimately pick a
# different wheel of the same version, and failing the hash check for that
# would be a false alarm rather than a security signal.
set -euo pipefail

POETRY_PIN="${1:-poetry==2.4.1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/poetry-requirements.txt"

if ! docker info >/dev/null 2>&1; then
  echo "error: this needs a usable Docker daemon (linux/amd64 container)." >&2
  echo "       No local Docker? Run it on a throwaway Linux host — NOT on a" >&2
  echo "       production box and NOT on the self-hosted CI runner." >&2
  exit 1
fi

docker run --rm -i --platform linux/amd64 python:3.12-slim python - "${POETRY_PIN}" \
  <"${HERE}/generate.py" >"${OUT}.tmp"

mv "${OUT}.tmp" "${OUT}"
echo "wrote ${OUT} ($(grep -c '^[a-zA-Z]' "${OUT}") pinned packages)"
echo
echo "Verify before committing, INTO A FRESH VENV:"
echo
echo "  The venv is not a nicety. Installing into the image's site-packages"
echo "  lets anything already present satisfy a requirement, so a lock with a"
echo "  MISSING package still appears to install — which is exactly how a lock"
echo "  omitting 'packaging' passed local verification and then failed on a CI"
echo "  runner, where nothing is pre-installed."
echo
echo "  docker run --rm -i --platform linux/amd64 -v ${OUT}:/r.txt:ro python:3.12-slim \\"
echo "    sh -c 'python -m venv /v && /v/bin/pip install -q --require-hashes \\"
echo "           --only-binary=:all: -r /r.txt && /v/bin/poetry --version'"
