#!/usr/bin/env bash
# Install the Foundation and this assembly's execution bindings from the
# complete wheelhouse carried by one immutable Platform candidate image.
#
# Nothing is fetched and nothing is rebuilt on the target. The image must
# already be present by digest. Every wheel is size- and digest-checked before
# pip sees it, installation happens in a new versioned directory, and `current`
# moves atomically only after the installed CLI discovers exactly the
# `platform-cp` binding and loads both fixed, root-owned trust roots.
set -euo pipefail
umask 077

readonly IMAGE_REFERENCE="${1:-${IMAGE_REFERENCE:-}}"
readonly TOOL_ROOT="${TOOL_ROOT:-/opt/dotmac/platform-cp-deployment-tool}"
readonly PYTHON="${PYTHON:-python3.12}"
readonly DOCKER="${DOCKER:-/usr/bin/docker}"
readonly BUNDLE_PATH="/opt/dotmac/deployment-wheelhouse"

die() { printf '%s\n' "$*" >&2; exit 1; }

[[ "$IMAGE_REFERENCE" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] \
    || die "usage: $0 <repository@sha256:digest>"
[[ "$TOOL_ROOT" = /* ]] || die "TOOL_ROOT must be an absolute path"
command -v "$PYTHON" >/dev/null || die "PYTHON=$PYTHON is not on PATH"
[[ -x "$DOCKER" ]] || die "DOCKER=$DOCKER is not executable"

# No implicit pull. The caller already admitted and pulled this exact image;
# resolving a tag or fetching something newer inside the installer would make
# the tool environment come from different bytes than the execution plan.
"$DOCKER" image inspect "$IMAGE_REFERENCE" >/dev/null 2>&1 \
    || die "the digest-pinned image is not present locally; refusing to pull"

work="$(mktemp -d)"
container_id=""
release_created=""
release_ready=""
cleanup() {
    if [[ -n "$container_id" ]]; then
        "$DOCKER" rm -f "$container_id" >/dev/null 2>&1 || true
    fi
    if [[ -n "$release_created" && -z "$release_ready" && -d "$RELEASE" ]]; then
        rm -rf -- "$RELEASE"
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

container_id="$("$DOCKER" create "$IMAGE_REFERENCE")" \
    || die "could not create a stopped container from the admitted image"
mkdir -p "$work/wheelhouse"
"$DOCKER" cp "$container_id:${BUNDLE_PATH}/." "$work/wheelhouse" \
    || die "the candidate image carries no deployment-tool bundle"
"$DOCKER" rm -f "$container_id" >/dev/null
container_id=""

bundle_id="$($PYTHON - "$work/wheelhouse" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
manifest_path = root / "bundle.json"
try:
    raw = manifest_path.read_bytes()
    document = json.loads(raw)
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"deployment-tool bundle manifest is unreadable: {error}")
required = {"contract", "source_revision", "foundation", "files"}
if not isinstance(document, dict) or set(document) != required:
    raise SystemExit("deployment-tool bundle manifest has unknown or missing keys")
if document["contract"] != "dotmac-deployment-tool-bundle/1":
    raise SystemExit(f"unknown deployment-tool bundle {document['contract']!r}")
if not re.fullmatch(r"[0-9a-f]{40}", document["source_revision"]):
    raise SystemExit("deployment-tool bundle source_revision is not a full commit")
foundation = document["foundation"]
foundation_required = {
    "source_repository",
    "source_sha",
    "run_id",
    "artifact_id",
    "expires_at",
    "version",
    "wheel_filename",
    "wheel_sha256",
    "wheel_size_bytes",
}
if not isinstance(foundation, dict) or set(foundation) != foundation_required:
    raise SystemExit("deployment-tool Foundation coordinate is incomplete")
if dt.datetime.now(dt.UTC) >= dt.datetime.fromisoformat(foundation["expires_at"]):
    raise SystemExit("the Foundation candidate lease has expired")
if not re.fullmatch(r"[0-9a-f]{64}", foundation["wheel_sha256"]):
    raise SystemExit("Foundation wheel digest is malformed")

files = document["files"]
if not isinstance(files, list) or not files:
    raise SystemExit("deployment-tool bundle lists no wheels")
expected_names = set()
for entry in files:
    if not isinstance(entry, dict) or set(entry) != {
        "filename", "size_bytes", "sha256"
    }:
        raise SystemExit("deployment-tool bundle has a malformed file row")
    name = entry["filename"]
    if (
        not isinstance(name, str)
        or pathlib.PurePath(name).name != name
        or not name.endswith(".whl")
        or name in expected_names
    ):
        raise SystemExit(f"invalid or duplicate wheel name {name!r}")
    expected_names.add(name)
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"wheel {name!r} is absent or not a regular file")
    actual_size = path.stat().st_size
    actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_size != entry["size_bytes"]:
        raise SystemExit(f"wheel {name!r} size differs from its manifest")
    if actual_sha != entry["sha256"]:
        raise SystemExit(f"wheel {name!r} digest differs from its manifest")
actual_names = {path.name for path in root.iterdir() if path.name != "bundle.json"}
if actual_names != expected_names:
    raise SystemExit(
        "deployment-tool bundle contains unmanifested or missing files: "
        f"extra={sorted(actual_names - expected_names)}, "
        f"missing={sorted(expected_names - actual_names)}"
    )
if foundation["wheel_filename"] not in expected_names:
    raise SystemExit("the accepted Foundation wheel is absent from the bundle")
foundation_row = next(
    entry for entry in files if entry["filename"] == foundation["wheel_filename"]
)
if (
    foundation_row["size_bytes"] != foundation["wheel_size_bytes"]
    or foundation_row["sha256"] != foundation["wheel_sha256"]
):
    raise SystemExit("the bundle and Foundation coordinate identify different bytes")
print(hashlib.sha256(raw).hexdigest())
PY
)" || die "the deployment-tool bundle failed verification"
[[ "$bundle_id" =~ ^[0-9a-f]{64}$ ]] || die "bundle id is not sha256"

readonly RELEASES="$TOOL_ROOT/releases"
readonly RELEASE="$RELEASES/$bundle_id"
readonly CURRENT="$TOOL_ROOT/current"
mkdir -p "$RELEASES"
exec 9>"$TOOL_ROOT/.install.lock"
flock -x 9
if [[ -e "$TOOL_ROOT/bin/python" || -e "$TOOL_ROOT/pyvenv.cfg" ]]; then
    die "TOOL_ROOT is a legacy in-place environment; refusing to overwrite it"
fi

if [[ ! -d "$RELEASE" ]]; then
    # A venv cannot be moved after installation: every console-script shebang
    # names the absolute interpreter path that existed when pip wrote it. The
    # final versioned path is never current while it is built, and the lock
    # makes an incomplete directory unobservable to another installer.
    mkdir -- "$RELEASE"
    release_created=1
    "$PYTHON" -m venv "$RELEASE" || die "could not create deployment tool environment"
    env -u PYTHONPATH -u PIP_INDEX_URL -u PIP_EXTRA_INDEX_URL \
        "$RELEASE/bin/pip" install \
        --no-index --no-deps --only-binary=:all: \
        --disable-pip-version-check --quiet \
        "$work"/wheelhouse/*.whl \
        || die "installing the verified offline wheelhouse failed"

    # Metadata enumeration happens before import. Loading the binding then
    # proves the fixed trust roots exist and satisfy their purpose contracts.
    ( cd / && env -u PYTHONPATH "$RELEASE/bin/python" -P - <<'PY' ) \
        || die "the deployment tool failed installed-artifact discovery"
import importlib.metadata as md
import pathlib

from dotmac_deployment_foundation.execution_bindings import (
    declared_provider_names,
    discover_bindings,
)

names = declared_provider_names()
if names != ("platform-cp",):
    raise SystemExit(f"execution binding declarations are {names!r}, expected platform-cp")
bindings = discover_bindings()
if bindings is None or bindings.provider != "platform-cp":
    raise SystemExit("the installed Platform wheel did not load its execution bindings")
if md.version("dotmac-deployment-foundation") != "0.3.0a5":
    raise SystemExit("the installed Foundation is not the accepted a5 candidate")
provider = pathlib.Path(md.distribution("dotmac-vendor-control-plane").locate_file(""))
if not provider.is_dir():
    raise SystemExit("the Platform provider has no installed distribution root")
PY
    "$RELEASE/bin/dotmac-deploy" --version >/dev/null \
        || die "the installed dotmac-deploy console script is not executable"
    printf '%s\n' "$bundle_id" > "$RELEASE/.bundle-id"
    chmod 0444 "$RELEASE/.bundle-id"
    release_ready=1
else
    [[ ! -L "$RELEASE" ]] || die "the versioned deployment tool is a symlink"
    [[ -f "$RELEASE/.bundle-id" ]] \
        || die "the existing versioned deployment tool has no bundle identity"
    [[ "$(cat "$RELEASE/.bundle-id")" == "$bundle_id" ]] \
        || die "the existing versioned deployment tool has a different identity"
    ( cd / && env -u PYTHONPATH "$RELEASE/bin/python" -P - <<'PY' ) \
        || die "the existing deployment tool no longer discovers its provider"
from dotmac_deployment_foundation.execution_bindings import (
    declared_provider_names,
    discover_bindings,
)

if declared_provider_names() != ("platform-cp",):
    raise SystemExit("the existing deployment tool provider set changed")
bindings = discover_bindings()
if bindings is None or bindings.provider != "platform-cp":
    raise SystemExit("the existing Platform provider no longer loads")
PY
    "$RELEASE/bin/dotmac-deploy" --version >/dev/null \
        || die "the existing dotmac-deploy console script is not executable"
fi

link="$TOOL_ROOT/.current.$bundle_id"
rm -f -- "$link"
ln -s "releases/$bundle_id" "$link"
mv -Tf -- "$link" "$CURRENT"

printf '%s\n' "$CURRENT/bin/dotmac-deploy"
