#!/usr/bin/env bash
# Issue a per-app read-only Forgejo token into a GitHub environment secret. Runs on the operator's Mac.
# Dry-run unless --apply. The value only flows ssh stdout -> audit.py shape-gate stdin -> gh stdin.
# Never argv, variable, file or terminal.
# Reviewed-bytes pin: EXPECTED_MANIFEST is the sha256 of SHA256SUMS, which lists every other source file.
# issue.sh itself is not in SHA256SUMS (it would be circular); the reviewer records `shasum -a 256 issue.sh`.
set -o pipefail -o errexit -o nounset
set +o xtrace
case ":${SHELLOPTS:-}:" in *:xtrace:*) echo 'REFUSED: xtrace is enabled' >&2; exit 1;; esac
unset BASH_XTRACEFD BASH_ENV ENV HISTFILE
set +o history 2>/dev/null || true
ulimit -c 0
umask 077
EXPECTED_MANIFEST=11ca737dc5f634b14cc43470745a18670f0187c5e011e80afaa4deaa0074b585

HERE=$(cd "$(dirname "$0")" && pwd -P)

verify_source() {
  python3 -I -S - "$HERE" <<'PY' || { echo 'REFUSED: unsafe source directory or files' >&2; exit 1; }
import os, stat, sys
from pathlib import Path
p = Path(sys.argv[1])
s = p.lstat()
if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
    raise SystemExit('source dir must be owned by you with mode 700')
names = ['SHA256SUMS', 'issue.sh']
for line in (p / 'SHA256SUMS').read_text().splitlines():
    n = line.split('  ', 1)[1]
    if not n or n != Path(n).name:
        raise SystemExit('bad manifest path')
    names.append(n)
for n in names:
    s = (p / n).lstat()
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) not in (0o600, 0o700)
            or s.st_nlink != 1):
        raise SystemExit('unsafe source file (symlink/owner/mode): ' + n)
allowed = set(names) | {'receipts', '__pycache__'}
for e in p.iterdir():
    if e.name not in allowed:
        raise SystemExit('unexpected entry in source dir: ' + e.name)
    if e.name in ('receipts', '__pycache__') and not stat.S_ISDIR(e.lstat().st_mode):
        raise SystemExit('unexpected non-directory: ' + e.name)
PY
  local actual
  actual=$(shasum -a 256 "$HERE/SHA256SUMS"); actual=${actual%% *}
  [ "$actual" = "$EXPECTED_MANIFEST" ] || { echo 'REFUSED: reviewed manifest pin mismatch' >&2; exit 1; }
  (cd "$HERE" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || { echo 'REFUSED: source bytes differ from reviewed manifest' >&2; exit 1; }
}
verify_source

AUDIT=(python3 -I -S "$HERE/audit.py")
CFG=${1:-}; APPLY=no
[ -n "$CFG" ] && [ -f "$CFG" ] || { echo "usage: issue.sh <config.json> [--apply]" >&2; exit 64; }
[ "${2:-}" = "--apply" ] && APPLY=yes
[ "$#" -le 2 ] || { echo 'usage: issue.sh <config.json> [--apply]' >&2; exit 64; }

APP= REPO= ENVN= SECRET= FUSER= TOKEN_BASE= ALIAS= CONTAINER= CUSER= CLI= REVOKE_VERIFIED= KNOWN_HOSTS=
while IFS== read -r k v; do
  case $k in
    APP) APP=$v;; REPO) REPO=$v;; ENVN) ENVN=$v;; SECRET) SECRET=$v;; FUSER) FUSER=$v;; TOKEN_BASE) TOKEN_BASE=$v;;
    ALIAS) ALIAS=$v;; CONTAINER) CONTAINER=$v;; CUSER) CUSER=$v;; CLI) CLI=$v;;
    REVOKE_VERIFIED) REVOKE_VERIFIED=$v;; KNOWN_HOSTS) KNOWN_HOSTS=$v;;
  esac
done < <("${AUDIT[@]}" config-shell --config "$CFG")
[ -n "$APP" ] && [ -n "$REPO" ] && [ -n "$SECRET" ] && [ -n "$ALIAS" ] && [ -n "$KNOWN_HOSTS" ] \
  || { echo 'REFUSED: config not accepted' >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TOKEN_NAME="$TOKEN_BASE-$STAMP"
OUT=${REGISTRY_READER_OUT:-$HERE/receipts}/$APP/$STAMP
mkdir -p -m 700 "$OUT"

echo "== pin check =="; "${AUDIT[@]}" pin --config "$CFG" >/dev/null || { echo 'REFUSED: ssh pin' >&2; exit 1; }
echo "== fresh pre-audit =="
"${AUDIT[@]}" pre --config "$CFG" --out "$OUT/pre.json" >/dev/null \
  || { echo "REFUSED: pre-audit failed; see $OUT/pre.json (or ssh/config error above). Nothing minted." >&2; exit 1; }
echo "== GitHub environment names-only read-back =="
"${AUDIT[@]}" env pre --config "$CFG" --out "$OUT/env-pre.json" >/dev/null \
  || { echo "REFUSED: environment/workflow drift or secret already present; see $OUT/env-pre.json. Nothing minted." >&2; exit 1; }
if [ "$APPLY" != yes ]; then
  echo "DRY-RUN OK: would mint '$TOKEN_NAME' (read:package) for $FUSER into $REPO env $ENVN secret $SECRET. Re-run with --apply."
  exit 0
fi
[ "$REVOKE_VERIFIED" = yes ] || { echo 'REFUSED: revoke_verified is not true; prove token revocation first.' >&2; exit 1; }
verify_source   # re-check the reviewed bytes immediately before audit.py is used for the mint run

SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Use the same reviewed no-config direct route as every metadata connection.
SSH=()
while IFS= read -r -d '' arg; do SSH+=("$arg"); done < <("${AUDIT[@]}" ssh-argv --config "$CFG")
[ "${#SSH[@]}" -gt 10 ] || { echo 'REFUSED: SSH route not accepted' >&2; exit 1; }

fail_after_mint() {
  trap - INT TERM HUP
  echo "FAILED after the mint step: $1" >&2
  echo "A token '$TOKEN_NAME' may exist. Revoke it (names/IDs only):" >&2
  "${AUDIT[@]}" revoke-cmd --config "$CFG" --name "$TOKEN_NAME" >&2 || true
  echo "List its ID: python3 -I -S $HERE/audit.py tokens --config $CFG" >&2
  echo "Then delete the secret if set: gh secret delete $SECRET --env $ENVN --repo $REPO" >&2
  exit 1
}
trap 'fail_after_mint "interrupted by signal"' INT TERM HUP

echo "== mint -> gh (value stays in the pipe) =="
set +o errexit
# Flags per upstream docs only (verify with --help on the installed version).
"${SSH[@]}" docker --host unix:///var/run/docker.sock exec -u "$CUSER" "$CONTAINER" "$CLI" admin user \
    generate-access-token --username "$FUSER" --token-name "$TOKEN_NAME" --scopes read:package --raw </dev/null \
  | "${AUDIT[@]}" shape-gate -- gh secret set "$SECRET" --env "$ENVN" --repo "$REPO"
RC=("${PIPESTATUS[@]}")
set -o errexit
if [ "${RC[0]}" -ne 0 ] || [ "${RC[1]}" -ne 0 ]; then
  fail_after_mint "mint=${RC[0]} gate+gh=${RC[1]} (10 = shape check, 11 = gh set)"
fi

echo "== post read-backs =="
"${AUDIT[@]}" env post --config "$CFG" --since "$SINCE" --pre-file "$OUT/env-pre.json" --out "$OUT/env-post.json" >/dev/null \
  || fail_after_mint "environment read-back mismatch (see $OUT/env-post.json)"
"${AUDIT[@]}" post --config "$CFG" --since "$SINCE" --name "$TOKEN_NAME" --out "$OUT/post.json" >/dev/null \
  || fail_after_mint "post-audit mismatch (see $OUT/post.json)"
"${AUDIT[@]}" compare "$OUT/pre.json" "$OUT/post.json" > "$OUT/compare.json" \
  || fail_after_mint "pre/post compare mismatch (see $OUT/compare.json)"
trap - INT TERM HUP
echo "OK: $TOKEN_NAME issued into $REPO env $ENVN secret $SECRET."
( cd "$OUT" && shasum -a 256 pre.json post.json env-pre.json env-post.json compare.json )
echo "Next: non-main dispatch must be refused; record rotate-by in the register."
