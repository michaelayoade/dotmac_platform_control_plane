#!/usr/bin/env bash
# Synthetic native privilege proof against these exact candidate bytes.
set -euo pipefail
umask 077
[[ $# -eq 2 && "${GITHUB_ACTIONS:-}" == true ]]
image=$1
output=$2
[[ "$image" =~ ^[a-zA-Z0-9_./:@-]+$ ]]
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ && "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]]
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]]
workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ -f "$workspace/conformance/test_gate0_network_privileges.py" ]]
name="gate0-native-netpriv-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
existing="$(docker container ls -aq --filter "name=^${name}$")"
[[ -z "$existing" ]]
task="$(mktemp -d "${RUNNER_TEMP:?}/gate0-native-netpriv.XXXXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  if [[ -f "$task/container.id" && ! -L "$task/container.id" ]]; then
    [[ "$(wc -c <"$task/container.id")" -le 65 ]]
    owned_id="$(cat "$task/container.id")"
    if [[ ! "$owned_id" =~ ^[0-9a-f]{64}$ ]]; then
      echo 'Native qualification container ownership is unconfirmed' >&2
      exit 1
    fi
    docker container rm -f "$owned_id" >/dev/null 2>&1 || true
    if ! remaining="$(docker container ls -aq --filter "id=$owned_id")" || [[ -n "$remaining" ]]; then
      echo 'Native qualification container cleanup is unconfirmed' >&2
      exit 1
    fi
    rm "$task/container.id"
  elif ! remaining="$(docker container ls -aq --filter "name=^${name}$")" || [[ -n "$remaining" ]]; then
    echo 'Native qualification container ownership is unconfirmed' >&2
    exit 1
  fi
  rmdir "$task"
  exit "$status"
}
trap cleanup EXIT
set -C
exec 3>"$output"
timeout --signal=TERM --kill-after=5s 60s docker run --rm --name "$name" --cidfile "$task/container.id" \
  --network none --read-only --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add KILL \
  --cap-add SETGID --cap-add SETUID --cap-add SYS_CHROOT \
  --cap-add SETPCAP --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  --pids-limit 96 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --tmpfs /run:rw,nosuid,nodev,noexec,size=16m,mode=0755 \
  --mount "type=bind,src=$workspace/conformance/test_gate0_network_privileges.py,dst=/qualification.py,readonly" \
  --env GITHUB_ACTIONS=true --entrypoint /opt/venv/bin/python "$image" \
  -I -B /qualification.py >&3
exec 3>&-
remaining="$(docker container ls -aq --filter "name=^${name}$")"
[[ -z "$remaining" ]]
jq -e '.schema == "Gate0NativeNetworkPrivilegeProof.v1" and .passed == true
  and .wrong_principal_refused_under_k == true and .refused_authentication_boundary_empty == true
  and .full_wireguard_installation_qualified == false and .live_readiness == false' \
  "$output" >/dev/null
