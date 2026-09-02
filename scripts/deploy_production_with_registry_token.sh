#!/usr/bin/env bash
set -euo pipefail
umask 077

DIGEST="${1:-}"
GHCR_ACTOR="${2:-}"
AUTHORIZATION_REF="${3:-}"

if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Usage: $0 sha256:<64 lowercase hex> <github-actor> <authorization-ref>" >&2
  exit 64
fi

# Carried through rather than defaulted. A wrapper that supplied its own
# reference would be a second authority, which is the shape being removed.
if [[ -z "${AUTHORIZATION_REF// }" ]]; then
  echo "An authorization reference is required; this wrapper does not invent one." >&2
  exit 64
fi

if [[ ! "$GHCR_ACTOR" =~ ^[A-Za-z0-9-]+$ ]]; then
  echo "GitHub actor has an unsafe shape." >&2
  exit 64
fi

DOCKER_CONFIG="$(mktemp -d /run/vendor-cp-docker.XXXXXX)"
export DOCKER_CONFIG

cleanup() {
  docker logout ghcr.io >/dev/null 2>&1 || true
  rm -rf -- "$DOCKER_CONFIG"
}
trap cleanup EXIT HUP INT TERM

docker login ghcr.io --username "$GHCR_ACTOR" --password-stdin >/dev/null
bash scripts/deploy_production.sh "$DIGEST" "$AUTHORIZATION_REF"
