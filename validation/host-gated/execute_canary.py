"""One-shot local owner for the separately approved exact canary packet."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def guarded(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022 or st.st_nlink != 1:
        raise Refused("input_protection")
    return path.read_bytes()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_new(root, name, data):
    with (root / name).open("x") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(root)


def summarize_receipt(data, packet):
    """Closed successful-canary contract; never return arbitrary receipt fields."""
    keys = {"schema", "run", "phase", "source_pins", "container_pins", "started_at", "status", "events", "failure"}
    if (type(data) is not dict or set(data) != keys or data["schema"] != "cp_host_gated_receipt.v1"
            or data["status"] != "CANARY_PASSED" or data["failure"] is not None
            or data["run"] != packet["expected_run"] or data["phase"] != "canary"
            or data["source_pins"] != packet["source_pins"] or data["container_pins"] != packet["container_pins"]
            or type(data["started_at"]) is not str or len(data["started_at"]) > 64):
        return None
    stages = ["exclusive_attempt_recorded", "pinned_runtime_ready", "before_create_canary", "canary_created",
              "before_mint_canary", "canary_token_bound", "canary_same_token_200", "before_exact_revocation",
              "revocation_committed_absence", "same_token_401", "finished"]
    events = data["events"]
    if type(events) is not list or len(events) != len(stages) or any(type(e) is not dict or e.get("stage") != s for e, s in zip(events, stages)):
        return None
    uid = events[3].get("user_id")
    binding = events[5].get("binding")
    if type(uid) is not int or uid <= 5 or type(binding) is not dict:
        return None
    if set(binding) != {"kind", "token_id", "user_id", "username", "token_name", "scope", "created_unix"}:
        return None
    if (binding["kind"] != "canary" or type(binding["token_id"]) is not int or binding["token_id"] <= 0
            or binding["token_id"] in (2, 16, 26, 28) or type(binding["user_id"]) is not int or binding["user_id"] != uid
            or binding["username"] != packet["canary_username"] or binding["token_name"] != packet["canary_token_name"]
            or binding["scope"] != "read:user" or type(binding["created_unix"]) is not int or binding["created_unix"] <= 0):
        return None
    for index, event in enumerate(events):
        expected = {"stage": stages[index]}
        if index == 2:
            expected["username"] = packet["canary_username"]
        elif index == 3:
            expected["user_id"] = uid
        elif index == 4:
            expected.update(token_name=packet["canary_token_name"], scope="read:user")
        elif index in (5, 7, 8, 9):
            expected["binding"] = binding
        if event != expected:
            return None
    return {"schema": "cp_canary_public_summary.v1", "status": "CANARY_PASSED", "run": packet["expected_run"],
            "phase": "canary", "source_pins": packet["source_pins"], "container_pins": packet["container_pins"],
            "user_id": uid, "token_id": binding["token_id"], "token_name": packet["canary_token_name"],
            "scope": "read:user", "proof_stages": stages}


def safe_observation(observation, label, packet):
    """Return only a closed public transport object; unexpected output is hashed."""
    if type(observation) is not dict:
        return None
    if label == "staging":
        expected = {"status": "SOURCE_STAGED_NO_CANARY_EXECUTED", "source_pins": packet["staged_file_pins"], "run": packet["expected_run"]}
        return expected if observation == expected else None
    allowed = {"status", "run", "helper_exit_code", "stderr_sha256", "receipt_sha256", "receipt_summary"}
    if set(observation) - allowed or observation.get("run") != packet["expected_run"]:
        return None
    if observation.get("status") not in ("CANARY_PASSED", "STOPPED_NATIVE_CANARY_NO_RETRY", "UNKNOWN_HELPER_OUTCOME_NO_RETRY"):
        return None
    clean = {"status": observation["status"], "run": packet["expected_run"]}
    for key in ("stderr_sha256", "receipt_sha256"):
        if key in observation:
            value = observation[key]
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                return None
            clean[key] = value
    if "helper_exit_code" in observation:
        if type(observation["helper_exit_code"]) is not int or not -255 <= observation["helper_exit_code"] <= 255:
            return None
        clean["helper_exit_code"] = observation["helper_exit_code"]
    if observation["status"] == "CANARY_PASSED":
        summary = observation.get("receipt_summary")
        if type(summary) is not dict:
            return None
        # Reconstruct the successful source receipt contract to validate all
        # summary fields without allowing arbitrary remote strings into storage.
        stages = ["exclusive_attempt_recorded", "pinned_runtime_ready", "before_create_canary", "canary_created",
                  "before_mint_canary", "canary_token_bound", "canary_same_token_200", "before_exact_revocation",
                  "revocation_committed_absence", "same_token_401", "finished"]
        expected_keys = {"schema", "status", "run", "phase", "source_pins", "container_pins", "user_id", "token_id", "token_name", "scope", "proof_stages"}
        if (set(summary) != expected_keys or summary.get("schema") != "cp_canary_public_summary.v1"
                or summary.get("status") != "CANARY_PASSED" or summary.get("phase") != "canary"
                or summary.get("run") != packet["expected_run"] or summary.get("source_pins") != packet["source_pins"]
                or summary.get("container_pins") != packet["container_pins"] or summary.get("token_name") != packet["canary_token_name"]
                or summary.get("scope") != "read:user" or summary.get("proof_stages") != stages
                or type(summary.get("user_id")) is not int or summary["user_id"] <= 5
                or type(summary.get("token_id")) is not int or summary["token_id"] <= 0 or summary["token_id"] in (2, 16, 26, 28)
                or clean.get("helper_exit_code") != 0 or "receipt_sha256" not in clean):
            return None
        clean["receipt_summary"] = summary
    elif "receipt_summary" in observation:
        return None
    return clean


def execute(root, packet, packet_hash, authority):
    """Never called by default. No retry; existing attempt refuses all contacts."""
    if (root / "live-canary-attempt.json").exists():
        raise Refused("attempt_already_recorded_no_retry")
    when = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save_new(root, "live-canary-approval.json", {"recorded_at": when, "packet_sha256": packet_hash,
                                               "authority_reference": authority, "phase": "CANARY_ONLY"})
    save_new(root, "live-canary-attempt.json", {"started_at": when, "packet_sha256": packet_hash,
                                              "maximum_attempts": 1, "retry": False})
    for label, argv, source, timeout in (
            ("staging", packet["staging_ssh_argv"], packet["staging_python_source"], 60),
            ("canary", packet["canary_ssh_argv"], packet["canary_python_source"], 300)):
        save_new(root, "live-" + label + "-intent.json", {"packet_sha256": packet_hash, "phase": label,
                                                        "source_sha256": sha(source.encode())})
        result = {"packet_sha256": packet_hash, "phase": label, "status": "UNKNOWN_OUTCOME_NO_RETRY"}
        try:
            child = subprocess.run(argv, input=source, text=True, capture_output=True, timeout=timeout)
            result["ssh_exit_code"] = child.returncode
            result["stderr_sha256"] = sha(child.stderr.encode())
            try:
                observation = json.loads(child.stdout)
            except (ValueError, TypeError):
                observation = None
            observation = safe_observation(observation, label, packet)
            if observation is not None:
                result["observation"] = observation
                if label == "staging":
                    success = (child.returncode == 0 and observation.get("status") == "SOURCE_STAGED_NO_CANARY_EXECUTED"
                               and observation.get("source_pins") == packet["staged_file_pins"]
                               and observation.get("run") == packet["expected_run"])
                else:
                    receipt = observation.get("receipt_summary", {})
                    success = (child.returncode == 0 and observation.get("status") == "CANARY_PASSED"
                               and observation.get("helper_exit_code") == 0 and observation.get("run") == packet["expected_run"]
                               and receipt.get("status") == "CANARY_PASSED" and receipt.get("phase") == "canary"
                               and receipt.get("run") == packet["expected_run"]
                               and receipt.get("source_pins") == packet["source_pins"])
                if success:
                    result["status"] = "STAGING_VERIFIED" if label == "staging" else "CANARY_PASSED_REVIEW_REQUIRED"
            else:
                result["stdout_sha256"] = sha(child.stdout.encode())
        except subprocess.TimeoutExpired:
            result["status"] = "UNKNOWN_TIMEOUT_NO_RETRY"
        except BaseException:
            result["status"] = "UNKNOWN_INTERRUPTION_OR_TRANSPORT_NO_RETRY"
        save_new(root, "live-" + label + "-result.json", result)
        if result["status"] not in ("STAGING_VERIFIED", "CANARY_PASSED_REVIEW_REQUIRED"):
            return 2
    return 0


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-packet-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approval-reference")
    parser.add_argument("--approve-registry-docker-exception", action="store_true")
    parser.add_argument("--approve-exact-token-row-write", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    raw = guarded(root / "canary-execution-packet.json")
    if sha(raw) != args.expect_packet_sha256:
        raise Refused("packet_drift")
    packet = json.loads(raw)
    if packet.get("phase") != "CANARY_ONLY_NO_BOOTSTRAP" or packet.get("maximum_execution_attempts") != 1 or not packet.get("no_automatic_retry"):
        raise Refused("scope")
    if sha(guarded(Path(__file__))) != packet["launcher_sha256"]:
        raise Refused("launcher_drift")
    for source_key, pin_key in (("staging_python_source", "staging_source_sha256"),
                                ("canary_python_source", "canary_wrapper_source_sha256")):
        if sha(packet[source_key].encode()) != packet[pin_key]:
            raise Refused("remote_source_drift")
    known_hosts = Path("/Users/michaelayoade/Documents/projects/.cutover-private/erp-registry-verification-20261029/registry_known_hosts")
    if sha(guarded(known_hosts)) != packet["known_hosts_sha256"]:
        raise Refused("host_key_pin_drift")
    if not args.apply:
        print(json.dumps({"status": "PLAN_ONLY_NO_CONTACT", "packet_sha256": sha(raw)}))
        return 0
    if (not args.approval_reference or not args.approval_reference.strip()
            or not args.approve_registry_docker_exception or not args.approve_exact_token_row_write):
        raise Refused("explicit_live_scope_unbound")
    return execute(root, packet, sha(raw), args.approval_reference)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("STOP: local packet/receipt refusal; preserve state, no retry", file=sys.stderr)
        raise SystemExit(2)
