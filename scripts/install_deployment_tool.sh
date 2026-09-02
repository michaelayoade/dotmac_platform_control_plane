#!/usr/bin/env bash
# Install the deployment-tool Foundation from an UNPUBLISHED, digest-bound
# candidate, into an environment this repository's application never sees.
#
# ## Why not a version
#
# `0.3.0a3` is on no index and carries no tag. It is the first Foundation
# artifact anywhere that can produce an `ExecutionPlanDigestV1`: published
# `0.2.0a2` and the frozen `0.3.0a2` candidate both predate `execution_plan.py`.
# So the pin is a build coordinate plus a digest, recorded in
# `deploy/foundation-candidate.json`, and the digest is checked BEFORE any
# installer runs.
#
# ## The three refusals, and why each is structural rather than a habit
#
# 1. NO INDEX FALLBACK. `pip --no-index` cannot reach Forgejo or PyPI. Without
#    it, a wrong artifact id or a corrupt download would silently resolve
#    `dotmac-deployment-foundation` to published `0.2.0a2` — which has no
#    `execution_plan` module at all — and the failure would surface later as
#    "the digest is absent" rather than as "you installed the wrong wheel".
#    That is the worst available shape: a wrong answer wearing a missing one's
#    clothes. `--no-deps` closes the same door on a transitive resolve; the
#    Foundation declares zero runtime dependencies, so it costs nothing.
#
# 2. NO SOURCE-TREE FALLBACK. The proof runs with `-P` (the interpreter never
#    prepends the working directory to `sys.path`), with `PYTHONPATH` cleared
#    and with the working directory outside every checkout, then asserts the
#    module resolved under this environment's own `site-packages` and that no
#    `sys.path` entry lies inside a checkout. A `git archive` extraction on
#    `PYTHONPATH` is exactly how a receipt came to name a version whose bytes
#    nobody could retrieve (`docs/adr/0017` s 5); asserting the absence is the
#    only way to know it did not happen again.
#
# 3. NO REBUILD. `--only-binary=:all:` against an absolute path to the exact
#    `.whl`. Never a source tree, never the sdist. A rebuild produces bytes
#    nobody verified, under a name somebody did.
#
# ## It does not enter the application image
#
# The environment is created OUTSIDE this repository and refused if it is not.
# Nothing here touches `pyproject.toml` or `poetry.lock`, and the Dockerfile
# installs only the `main` dependency group, so no group membership exists that
# could carry the wheel into the image.
#
# ## Usage
#
#   scripts/install_deployment_tool.sh            # install and prove
#   TOOL_ROOT=/some/dir scripts/install_deployment_tool.sh
#
# Prints the resolved `dotmac-deploy` path on success. Every value is a knob
# with a documented default; nothing here is hardcoded to one machine.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly COORDINATES="${COORDINATES:-${REPO_ROOT}/deploy/foundation-candidate.json}"
readonly TOOL_ROOT="${TOOL_ROOT:-${XDG_STATE_HOME:-${HOME}/.local/state}/dotmac/platform-cp-deployment-tool}"
readonly PYTHON="${PYTHON:-python3.12}"

die() { printf '%s\n' "$*" >&2; exit 1; }

command -v gh >/dev/null || die "gh is required to fetch the candidate artifact"
command -v "$PYTHON" >/dev/null || die "PYTHON=$PYTHON is not on PATH"
[[ -f "$COORDINATES" ]] || die "$COORDINATES is missing"

# The environment must live outside the repository. This is refusal 2 as a
# property of the filesystem rather than of the caller's care: an environment
# inside the tree is one the tree could shadow, and one a build could copy.
case "$TOOL_ROOT" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        die "TOOL_ROOT ($TOOL_ROOT) is inside the repository. The deployment
tool must not live in the tree it deploys: that tree is the INPUT, and an input
that supplies its own tooling is not an input that was verified." ;;
esac

field() { "$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))['$1'])" "$COORDINATES"; }

SOURCE_REPOSITORY="$(field source_repository)"
ARTIFACT_ID="$(field artifact_id)"
WHEEL_FILENAME="$(field wheel_filename)"
WHEEL_SHA256="$(field wheel_sha256)"
WHEEL_SIZE="$(field wheel_size_bytes)"
EXPIRES_AT="$(field expires_at)"
VERSION="$(field version)"
readonly SOURCE_REPOSITORY ARTIFACT_ID WHEEL_FILENAME WHEEL_SHA256 WHEEL_SIZE EXPIRES_AT VERSION

[[ "$WHEEL_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "wheel_sha256 is not 64 lowercase hex"

# The lease, refused explicitly. GitHub deletes the artifact at `expires_at`,
# and a 404 from a deleted artifact reads like a network problem.
"$PYTHON" - "$EXPIRES_AT" <<'PY' || die "the candidate artifact lease has expired; a3 must be published, or a new candidate built and this file replaced"
import datetime as dt, sys
sys.exit(0 if dt.datetime.now(dt.UTC) < dt.datetime.fromisoformat(sys.argv[1]) else 1)
PY

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

gh api "/repos/${SOURCE_REPOSITORY}/actions/artifacts/${ARTIFACT_ID}/zip" > "${WORK}/artifact.zip" \
    || die "could not download artifact ${ARTIFACT_ID} from ${SOURCE_REPOSITORY}"
unzip -o -q "${WORK}/artifact.zip" -d "${WORK}/unpacked" \
    || die "the downloaded artifact is not a readable zip"

readonly WHEEL="${WORK}/unpacked/${WHEEL_FILENAME}"
[[ -f "$WHEEL" ]] || die "the artifact does not contain ${WHEEL_FILENAME}"

# BEFORE pip. A digest checked after installation has already run whatever it
# was going to run.
actual_size="$(wc -c < "$WHEEL" | tr -d ' ')"
[[ "$actual_size" == "$WHEEL_SIZE" ]] \
    || die "wheel is ${actual_size} bytes, expected ${WHEEL_SIZE}"
actual_sha="$("$PYTHON" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$WHEEL")"
[[ "$actual_sha" == "$WHEEL_SHA256" ]] \
    || die "wheel sha256 ${actual_sha} != pinned ${WHEEL_SHA256}. These are not
the bytes this repository accepted. Nothing has been installed."

rm -rf -- "$TOOL_ROOT"
mkdir -p "$(dirname "$TOOL_ROOT")"
"$PYTHON" -m venv "$TOOL_ROOT" || die "could not create the tool environment"

env -u PYTHONPATH -u PIP_INDEX_URL -u PIP_EXTRA_INDEX_URL \
    "${TOOL_ROOT}/bin/pip" install \
        --no-index --no-deps --only-binary=:all: \
        --disable-pip-version-check --quiet \
        "$WHEEL" \
    || die "installing the verified wheel failed"

# Refusal 2, asserted rather than assumed. Run from `/` so the working
# directory is outside every checkout, with `-P` so it could not have been
# added to `sys.path` even if it were.
( cd / && env -u PYTHONPATH "${TOOL_ROOT}/bin/python" -P - "$VERSION" <<'PY' )
import importlib.metadata as md
import sys, sysconfig

from dotmac_deployment_foundation import execution_plan as ep

expected_version = sys.argv[1]
purelib = sysconfig.get_paths()["purelib"]
installed = md.version("dotmac-deployment-foundation")

print(f"  interpreter    {sys.executable}")
print(f"  execution_plan {ep.__file__}")
print(f"  version        {installed}")
print(f"  site-packages  {purelib}")

if not ep.__file__.startswith(purelib):
    raise SystemExit(
        f"execution_plan resolved to {ep.__file__}, which is outside this "
        f"environment's site-packages ({purelib}). Something is shadowing the "
        "installed wheel, and the whole point of pinning by digest is that the "
        "bytes that run are the bytes that were verified."
    )
shadowed = [entry for entry in sys.path if entry and "/Downloads/management/" in entry]
if shadowed:
    raise SystemExit(f"a source checkout is on sys.path: {shadowed}")
if installed != expected_version:
    raise SystemExit(f"installed {installed}, pinned {expected_version}")
for name in ("render_execution_plan", "require_execution_plan_digest"):
    if not hasattr(ep, name):
        raise SystemExit(
            f"the installed Foundation has no {name}. This is the capability "
            "the candidate pin exists for; a wheel without it is the wrong wheel."
        )
print(f"  schemas        {ep.EXECUTION_PLAN_SCHEMA} / {ep.EXECUTION_PLAN_DIGEST_SCHEMA}")
PY

printf '%s\n' "${TOOL_ROOT}/bin/dotmac-deploy"
