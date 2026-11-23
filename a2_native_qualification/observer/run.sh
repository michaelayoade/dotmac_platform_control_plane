#!/usr/bin/env bash
# Native proof of the observer SQL (REVIEW-P2-L1 r4 ruling 1) on the CI-only,
# throwaway PostgreSQL 16. Runs the VENDORED, sha-pinned snippet and templates
# unchanged: create -> readback -> login checks -> drop -> absence, N=999.
# Never edits SQL to make it pass; every failed row is recorded by name.
set -uo pipefail
here="$GITHUB_WORKSPACE/a2_native_qualification/observer"
out="$RUNNER_TEMP/out"
work="$(mktemp -d)"
N=999
DB=vendor_cp_test
CONTAINER="${COMPOSE_PROJECT_NAME}-postgres-1"
ENVF=/dev/shm/a2obs/general.env
TMPD=/dev/shm/a2obs-run
: > "$work/stages.txt"
stage() { echo "$1 $2" >> "$work/stages.txt"; }
snip() { sudo python3 -I "$here/a2-observer-secret.py" "$@"; }

# 1. pins
(cd "$here" && grep -v '^#' PINS | sha256sum -c - >/dev/null 2>&1); stage pins $?

# 2. root-only fixtures (a stand-in for the session env file) on tmpfs
sudo install -d -m 700 -o root -g root /dev/shm/a2obs "$TMPD"
printf 'DATABASE_URL=postgresql://u@localhost:5439/%s?sslmode=require\n' "$DB" | sudo tee "$ENVF" >/dev/null
sudo chown root:root "$ENVF"; sudo chmod 600 "$ENVF"

# 3. CI-only: TLS on (the snippet refuses sslmode disable/prefer) and SCRAM for
#    the observer role, so the login really exercises the snippet's password.
tls=0
docker exec -u postgres "$CONTAINER" sh -c "openssl req -new -x509 -days 1 -nodes -subj /CN=localhost -out /var/lib/postgresql/data/server.crt -keyout /var/lib/postgresql/data/server.key && chmod 600 /var/lib/postgresql/data/server.key && sed -i '1i hostssl all a2_recovery_observer_r${N} all scram-sha-256' /var/lib/postgresql/data/pg_hba.conf" >/dev/null 2>&1 || tls=1
docker exec -u postgres "$CONTAINER" psql -U postgres -d "$DB" -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET ssl = 'on'" -c "ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/data/server.crt'" -c "ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/data/server.key'" -c "SELECT pg_reload_conf()" >/dev/null 2>&1 || tls=1
sleep 2
stage tls_setup $tls

# 4. materialize the four templates (N=999, VALID UNTIL now + 10 minutes)
mat=0
valid_until="$(date -u -d '+10 minutes' '+%Y-%m-%d %H:%M:%S+00')"
declare -A MSHA
for kind in create readback drop absence; do
  tsha="$(grep "a2-observer-${kind}.sql.tmpl" "$here/PINS" | cut -d' ' -f1)"
  extra=()
  [ "$kind" = create ] && extra=(--valid-until "$valid_until")
  res="$(snip materialize --template "$here/a2-observer-${kind}.sql.tmpl" --template-sha256 "$tsha" --n "$N" "${extra[@]}" --out "/dev/shm/a2obs/${kind}.sql" 2>"$work/mat-${kind}.err")" || mat=1
  MSHA[$kind]="$(echo "$res" | sed -n 's/^materialized_sha256=//p')"
done
stage materialize $mat
common() { echo --n "$N" --materialized "/dev/shm/a2obs/$1.sql" --materialized-sha256 "${MSHA[$1]:-none}" --env-file "$ENVF" --container "$CONTAINER" --superuser postgres --dbname "$DB"; }

# 5. create, readback
snip create $(common create) --tmpfs-dir "$TMPD" --service-host localhost --port 5439 >"$work/create.out" 2>"$work/create.err"; stage create $?
snip readback $(common readback) >"$work/readback.txt" 2>"$work/readback.err"; stage readback $?

# 6. log in with the snippet-written DSN
dsn="$(sudo grep '^A2_OBSERVER_DSN=' "$ENVF" | cut -d= -f2-)"
if [ -n "$dsn" ]; then
  pw="$(printf '%s' "$dsn" | python3 -I -c 'import sys,urllib.parse as u; print(u.urlsplit(sys.stdin.read()).password or "")')"
  [ -n "$pw" ] && echo "::add-mask::$pw"
  (cd "$GITHUB_WORKSPACE/cp-src" && OBS_DSN="$dsn" OUT="$work/login.json" poetry run python -I "$here/observer_login.py"); stage login $?
  dsn=""; pw=""
else
  stage login 1
fi

# 7. drop, absence (always attempted)
snip drop $(common drop) --tmpfs-dir "$TMPD" >"$work/drop.out" 2>"$work/drop.err"; stage drop $?
snip absence $(common absence) --tmpfs-dir "$TMPD" >"$work/absence.txt" 2>"$work/absence.err"; stage absence $?

# Names of STOPs only (no values) for the log
for f in create drop; do sed -n 's/^a2-observer-secret: STOP /STOP /p' "$work/$f.err" 2>/dev/null; done
for f in "$work"/readback.err "$work"/absence.err; do sed -n 's/^a2-observer-secret: STOP /STOP /p' "$f" 2>/dev/null; done
python3 -I "$here/observer_result.py" "$work" "$out/observer-sql-native.json"
sudo rm -rf /dev/shm/a2obs "$TMPD"
exit 0
