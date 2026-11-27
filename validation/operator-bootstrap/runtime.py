"""Operator-only isolated Forgejo revocation proof. Source preparation, not authority."""
import argparse
import base64
import datetime
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import warnings

AUDIT_SHA256 = "86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9"
ORIGIN_HOST = "registry.dotmac.io"
HOSTNAME = "dotmac-s3"


class Refused(Exception):
    pass


class ReceiptWriteFailed(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def guarded_bytes(path):
    path = Path(path)
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o022 or st.st_nlink != 1):
        raise Refused("unsafe_input_file")
    data = path.read_bytes()
    after = path.lstat()
    if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise Refused("input_changed")
    return data


def trusted_root_parents(path):
    for parent in Path(path).absolute().parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("unsafe_root_input_parent")


def load_config(path):
    raw = guarded_bytes(path)
    cfg = json.loads(raw)
    expected = {"schema", "run", "host", "forgejo_container_id", "database_container_id",
                "username", "user_id", "admin_username", "operator_profile_reference",
                "authorization_reference", "forgejo_image_id", "database_image_id",
                "helper_source_sha256", "exclusive_user_mutation_window_reference"}
    if not isinstance(cfg, dict) or set(cfg) != expected:
        raise Refused("config_schema")
    if cfg["schema"] != "cp_reader_revocation_proof.v1" or cfg["host"] != HOSTNAME:
        raise Refused("config_target")
    for key in ("run", "username"):
        if not isinstance(cfg[key], str) or not re.fullmatch(r"cp-revoke-proof-[a-z0-9-]{8,48}", cfg[key]):
            raise Refused("config_isolation_name")
    for key in ("forgejo_container_id", "database_container_id"):
        if cfg[key] is not None and (not isinstance(cfg[key], str) or not re.fullmatch(r"[0-9a-f]{64}", cfg[key])):
            raise Refused("config_container")
    return cfg, digest(raw)


def apply_ready(cfg):
    for key in ("forgejo_container_id", "database_container_id"):
        if not isinstance(cfg[key], str) or not re.fullmatch(r"[0-9a-f]{64}", cfg[key]):
            raise Refused("container_identity_unbound")
    for key in ("forgejo_image_id", "database_image_id"):
        if not isinstance(cfg[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", cfg[key]):
            raise Refused("container_image_unbound")
    if cfg["helper_source_sha256"] != digest(guarded_bytes(__file__)):
        raise Refused("helper_source_drift")
    if type(cfg["user_id"]) is not int or cfg["user_id"] <= 0:
        raise Refused("disposable_uid_unbound")
    for key in ("operator_profile_reference", "authorization_reference",
                "exclusive_user_mutation_window_reference"):
        value = cfg[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            raise Refused("operator_authority_unbound")
    admin = cfg["admin_username"]
    if not isinstance(admin, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", admin):
        raise Refused("admin_identity_unbound")
    if admin.lower() == cfg["username"].lower():
        raise Refused("operator_must_not_be_disposable_user")


def load_audit():
    parent = Path(__file__).parent
    for path in (parent, *parent.parents):
        st = path.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("unsafe_source_parent")
    data = guarded_bytes(Path(__file__).with_name("audit.py"))
    if digest(data) != AUDIT_SHA256:
        raise Refused("audit_source_drift")
    namespace = {"__name__": "reviewed_audit", "__file__": "/reviewed/audit.py"}
    exec(compile(data, "<reviewed-audit>", "exec"), namespace)
    return namespace


def check_metadata(meta, cfg, tokens):
    if (meta.get("database") != "forgejo" or meta.get("transaction_read_only") != "on"
            or not isinstance(meta.get("database_container_id"), str)
            or not re.fullmatch(r"[0-9a-f]{12,64}", meta["database_container_id"])
            or not cfg["database_container_id"].startswith(meta["database_container_id"])):
        raise Refused("metadata_database")
    users = meta.get("users", [])
    if len(users) != 1:
        raise Refused("metadata_user_count")
    user = users[0]
    expected = {"id": cfg["user_id"], "name": cfg["username"], "type": 0,
                "is_admin": False, "is_restricted": True, "is_active": True,
                "prohibit_login": False, "must_change_password": False,
                "login_type": 0, "login_source": 0}
    if any(type(user.get(k)) is not type(v) or user[k] != v for k, v in expected.items()):
        raise Refused("metadata_user_state")
    for key in ("public_keys", "gpg_keys", "owned_repos", "collaborations", "access_rows",
                "org_memberships", "team_memberships", "teams"):
        if meta.get(key) != []:
            raise Refused("disposable_user_has_access")
    rows = meta.get("tokens")
    if not isinstance(rows, list) or len(rows) != tokens:
        raise Refused("metadata_token_count")


def without_tokens(meta):
    return {k: v for k, v in meta.items() if k != "tokens"}


def minted_row(meta, cfg, name, started, finished):
    check_metadata(meta, cfg, 1)
    row = meta["tokens"][0]
    if (type(row.get("id")) is not int or row["id"] <= 0
            or row.get("uid") != cfg["user_id"] or row.get("name") != name
            or row.get("scope") != "read:user" or type(row.get("created_unix")) is not int
            or not started - 120 <= row["created_unix"] <= finished + 120):
        raise Refused("minted_token_identity")
    return row["id"]


def docker(args, *, sensitive=False):
    with tempfile.TemporaryDirectory(prefix="cp-revoke-docker-") as config:
        result = subprocess.run(
            ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", config, *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=30, env={"PATH": "/usr/bin:/bin"}, check=False)
    if result.returncode or len(result.stdout) > 8192:
        raise Refused("docker_failed")
    return result.stdout


def http_status(method, path, header):
    # http.client does not consume proxy/netrc environment or follow redirects.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    connection = http.client.HTTPSConnection(ORIGIN_HOST, 443,
                                            context=context, timeout=15)
    try:
        connection.request(method, path, headers={"Authorization": header, "Accept": "application/json"})
        response = connection.getresponse()
        status_code = response.status
        response.close()  # Never inspect or persist bodies (including /user PII).
        return status_code
    finally:
        connection.close()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_container(cfg, kind):
    observed = docker(["inspect", "--format", "{{.Id}} {{.Image}}", cfg[kind + "_container_id"]])
    expected = cfg[kind + "_container_id"] + " " + cfg[kind + "_image_id"]
    if observed.decode("ascii").strip() != expected:
        raise Refused("container_identity_or_image_drift")


def run_proof(cfg, config_hash, output, audit, password):
    """Effectful owner. No retries, no account creation, no implicit cleanup/remint."""
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    fsync_directory(output.parent)
    receipt = {"schema": "cp_reader_revocation_receipt.v1", "run": cfg["run"],
               "config_sha256": config_hash, "username": cfg["username"],
               "user_id": cfg["user_id"], "started_at": now(), "stages": [],
               "token_name": cfg["run"], "scope": "read:user",
               "status": "STARTED", "mint_attempted": False, "delete_attempted": False}

    def record(stage):
        receipt["stages"].append(stage)
        temporary = output / ".receipt.tmp"
        try:
            with temporary.open("x") as handle:
                json.dump(receipt, handle, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(output / "receipt.json")
            fsync_directory(output)
        except OSError:
            raise ReceiptWriteFailed() from None

    def stopped(code, record_failure=False):
        receipt["status"] = "STOPPED_RETAINED_STATE_NO_RETRY"
        receipt["refusal"] = code
        if not record_failure:
            try:
                record("stopped")
                return 2
            except ReceiptWriteFailed:
                pass
        # Preserve partial temp files and the last durable intent; never retry a
        # failed receipt write or claim that a final stopped status was persisted.
        print("STOP: receipt_write_failed; retain partial files and reconcile state", file=sys.stderr)
        return 2

    def collect():
        check_container(cfg, "database")
        return audit["collect_remote"](cfg["username"], "dotmac", "cp-revoke-proof-unused-20261125")

    token = None
    try:
        record("attempt_recorded_no_retry")
        check_container(cfg, "forgejo")
        version = docker(["exec", "-u", "git", cfg["forgejo_container_id"], "forgejo", "--version"])
        if not re.search(rb"\b11\.0\.16\b", version):
            raise Refused("forgejo_version")
        before = collect()
        check_metadata(before, cfg, 0)
        record("isolated_zero_token_baseline")
        token_name = cfg["run"]
        started = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        receipt["mint_attempted"] = True
        record("before_single_mint")
        check_container(cfg, "forgejo")
        fresh = collect()
        check_metadata(fresh, cfg, 0)
        if fresh != before:
            raise Refused("metadata_drift_before_mint")
        raw = docker(["exec", "-u", "git", cfg["forgejo_container_id"], "forgejo", "admin", "user",
                      "generate-access-token", "--username", cfg["username"], "--token-name", token_name,
                      "--scopes", "read:user", "--raw"], sensitive=True)
        if not re.fullmatch(rb"[0-9a-f]{40}\n?", raw):
            raise Refused("mint_output_shape")
        token = raw.strip().decode("ascii")
        raw = None
        after_mint = collect()
        token_id = minted_row(after_mint, cfg, token_name, started,
                              int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
        if without_tokens(before) != without_tokens(after_mint):
            raise Refused("metadata_drift_after_mint")
        receipt["token_id"] = token_id
        receipt["token_name"] = token_name
        record("single_token_identity_bound")
        if http_status("GET", "/api/v1/user", "token " + token) != 200:
            raise Refused("baseline_token_get_not_200")
        record("same_token_get_200")
        basic = "Basic " + base64.b64encode((cfg["admin_username"] + ":" + password).encode()).decode()
        receipt["delete_attempted"] = True
        record("before_single_exact_id_delete")
        code = http_status("DELETE", "/api/v1/users/" + cfg["username"] + "/tokens/" + str(token_id), basic)
        basic = None
        if code != 204:
            raise Refused("delete_not_204")
        record("delete_204")
        after = collect()
        check_metadata(after, cfg, 0)
        if without_tokens(before) != without_tokens(after):
            raise Refused("metadata_drift_after_delete")
        record("exact_token_absent_metadata_unchanged")
        if http_status("GET", "/api/v1/user", "token " + token) != 401:
            raise Refused("revoked_token_get_not_401")
        receipt["status"] = "REVOCATION_PROOF_PASSED_DISPOSABLE_USER_RETAINED"
        record("same_token_get_401")
        return 0
    except Refused as error:
        return stopped(str(error))
    except ReceiptWriteFailed:
        return stopped("receipt_write_failed", record_failure=True)
    except BaseException:
        # Never serialize exception text, HTTP headers, subprocess output or secrets.
        return stopped("unexpected_or_interrupted")
    finally:
        token = None  # Python cannot promise memory zeroization; no persistence/printing.
        password = None


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expect-digest")
    parser.add_argument("--receipt-dir")
    args = parser.parse_args()
    if args.apply:
        if os.geteuid() != 0 or socket.gethostname() != HOSTNAME:
            raise Refused("registry_host_only")
        trusted_root_parents(args.config)
    cfg, sha = load_config(args.config)
    if not args.apply:
        print(json.dumps({"status": "PLAN_ONLY_NO_CONTACT", "config_sha256": sha,
                          "run": cfg["run"], "live_authority_inferred": False}))
        return 0
    apply_ready(cfg)
    if args.expect_digest != sha:
        raise Refused("config_digest_mismatch")
    if os.geteuid() != 0 or socket.gethostname() != HOSTNAME:
        raise Refused("registry_host_only")
    trusted_root_parents(args.config)
    # Re-read from trusted ancestors before accepting the earlier digest/config.
    checked_cfg, checked_sha = load_config(args.config)
    if checked_sha != sha or checked_cfg != cfg:
        raise Refused("config_changed")
    if not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
        raise Refused("require_system_python_isolated_no_site_no_bytecode")
    if Path(sys.executable).resolve() != Path("/usr/bin/python3").resolve():
        raise Refused("system_python_required")
    if not args.receipt_dir or args.receipt_dir != "/root/cp-reader-revocation-receipts/" + cfg["run"]:
        raise Refused("receipt_path")
    parent = Path(args.receipt_dir).parent
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused("receipt_parent")
    audit = load_audit()
    if not sys.stdin.isatty():
        raise Refused("operator_tty_required")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Approved Forgejo operator password (never recorded): ")
    if not password:
        raise Refused("operator_password_missing")
    return run_proof(cfg, sha, Path(args.receipt_dir), audit, password)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refused as error:
        print("REFUSED: " + str(error), file=sys.stderr)
        raise SystemExit(2)
    except Exception:
        print("REFUSED: unexpected_configuration_or_io", file=sys.stderr)
        raise SystemExit(2)
