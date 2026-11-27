"""Prepared host-gated canary/bootstrap owner. Live operations require exact authority."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import socket
import stat
import subprocess
import sys
import tempfile

FIXED_PINS = {
    "audit.py": "86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9",
    "runtime.py": "ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a",
}


class Refused(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def guarded(path):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o022 or st.st_nlink != 1):
        raise Refused("file_protection")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns):
            raise Refused("file_open_race")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read()
        after = os.fstat(fd)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Refused("file_read_race")
        return data
    finally:
        os.close(fd)


def root_ancestors(path):
    for parent in path.absolute().parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("root_ancestry")


def load_module(name, expected):
    path = Path(__file__).with_name(name)
    data = guarded(path)
    if sha(data) != expected:
        raise Refused("source_drift")
    namespace = {"__name__": "reviewed_" + name.replace(".", "_"), "__file__": str(path)}
    exec(compile(data, str(path), "exec"), namespace)
    return namespace


def load_config(path):
    raw = guarded(path)
    cfg = json.loads(raw)
    keys = {"schema", "run", "host", "canary_username", "canary_token_name", "bootstrap_token_name",
            "forgejo_container_id", "forgejo_image_id", "database_container_id", "database_image_id",
            "source_pins", "operator_reference", "authorization_reference", "exclusive_window_reference",
            "cp_require_restricted", "restricted_account_decision_reference", "accepted_canary_receipt_sha256"}
    if not isinstance(cfg, dict) or set(cfg) != keys or cfg["schema"] != "cp_host_gated.v1":
        raise Refused("config_schema")
    if cfg["host"] != "dotmac-s3" or not isinstance(cfg["run"], str):
        raise Refused("config_host")
    match = re.fullmatch(r"cp-host-([a-z0-9][a-z0-9-]{7,30}[a-z0-9])", cfg["run"])
    if not match:
        raise Refused("run_name")
    suffix = match.group(1)
    for key, prefix in (("canary_username", "cp-revoke-proof-"), ("canary_token_name", "cp-canary-read-"),
                        ("bootstrap_token_name", "cp-org-bootstrap-")):
        if cfg[key] != prefix + suffix or len(cfg[key]) > 64:
            raise Refused("run_name_binding")
    if type(cfg["cp_require_restricted"]) is not bool:
        raise Refused("restricted_flag")
    return cfg, sha(raw)


def require_apply(cfg, phase):
    for key in ("operator_reference", "authorization_reference", "exclusive_window_reference"):
        if not isinstance(cfg[key], str) or not cfg[key].strip() or len(cfg[key]) > 200:
            raise Refused("authority_unbound")
    for kind in ("forgejo", "database"):
        if not isinstance(cfg[kind + "_container_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", cfg[kind + "_container_id"]):
            raise Refused("container_unbound")
        if not isinstance(cfg[kind + "_image_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", cfg[kind + "_image_id"]):
            raise Refused("image_unbound")
    pins = cfg["source_pins"]
    expected_names = {"host_gate.py", "orchestrator.py", "revocation_sql.py", "bootstrap_api.py", *FIXED_PINS}
    if not isinstance(pins, dict) or set(pins) != expected_names:
        raise Refused("source_pin_set")
    for name, pin in pins.items():
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise Refused("source_pin_unbound")
        if name in FIXED_PINS and pin != FIXED_PINS[name]:
            raise Refused("fixed_source_pin_drift")
        if sha(guarded(Path(__file__).with_name(name))) != pin:
            raise Refused("source_pin_drift")
    if phase == "bootstrap":
        if not isinstance(cfg["restricted_account_decision_reference"], str) or not cfg["restricted_account_decision_reference"].strip():
            raise Refused("restricted_decision_unbound")
        if not isinstance(cfg["accepted_canary_receipt_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", cfg["accepted_canary_receipt_sha256"]):
            raise Refused("accepted_canary_unbound")


class Journal:
    def __init__(self, directory, cfg, phase):
        self.failed = False
        self.directory = directory
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.sync(directory.parent)
        self.data = {"schema": "cp_host_gated_receipt.v1", "run": cfg["run"], "phase": phase,
                     "source_pins": cfg["source_pins"], "container_pins": {
                         k: cfg[k] for k in ("forgejo_container_id", "forgejo_image_id", "database_container_id", "database_image_id")},
                     "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     "status": "STARTED", "events": []}
        self.write("exclusive_attempt_recorded")

    @staticmethod
    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, stage, **fields):
        if self.failed:
            raise Refused("journal_already_failed")
        self.data["events"].append({"stage": stage, **fields})
        try:
            temporary = self.directory / ".receipt.tmp"
            with temporary.open("x") as stream:
                json.dump(self.data, stream, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.directory / "receipt.json")
            self.sync(self.directory)
        except BaseException:
            self.failed = True
            raise Refused("journal_write_failed") from None

    def finish(self, status, failure=None):
        if self.failed:
            print("STOP: journal unavailable; retain partial files and reconcile exact run", file=sys.stderr)
            return
        self.data["status"] = status
        self.data["failure"] = failure
        try:
            self.write("finished")
        except Refused:
            print("STOP: final receipt unavailable; retain prior durable intent", file=sys.stderr)


class Backend:
    def __init__(self, cfg, runtime, audit, api, sql):
        self.cfg, self.runtime, self.audit, self.api, self.sql = cfg, runtime, audit, api, sql
        self.revocation_attempts = set()

    def check_container(self, kind):
        self.runtime["check_container"](self.cfg, kind)

    def metadata(self, username):
        self.check_container("database")
        team = ("cp-revoke-proof-unused-20261125" if username == self.cfg["canary_username"]
                else "Owners" if username == "dotmac-admin" else "cp-bundle-readers")
        meta = self.audit["collect_remote"](username, "dotmac", team)
        if (meta.get("database") != "forgejo" or meta.get("transaction_read_only") != "on"
                or not isinstance(meta.get("database_container_id"), str)
                or not re.fullmatch(r"[0-9a-f]{12,64}", meta["database_container_id"])
                or not self.cfg["database_container_id"].startswith(meta["database_container_id"])):
            raise Refused("metadata_identity")
        return meta

    def require_absent(self, username, team_absent=False):
        meta = self.metadata(username)
        if any(meta.get(k) != [] for k in ("users", "tokens", "public_keys", "gpg_keys", "owned_repos",
                                           "collaborations", "access_rows", "org_memberships", "team_memberships")):
            raise Refused("principal_not_fresh")
        if team_absent and meta.get("teams") != []:
            raise Refused("cp_team_not_fresh")

    def quiet_docker(self, args, sql_input=None):
        with tempfile.TemporaryDirectory(prefix="cp-host-docker-") as config:
            input_args = {"stdin": subprocess.DEVNULL} if sql_input is None else {"input": sql_input}
            result = subprocess.run(
                ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config", config, *args],
                **input_args, stdout=subprocess.PIPE if sql_input is not None else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=30,
                env={"PATH": "/usr/bin:/bin"}, check=False)
        if result.returncode or (sql_input is not None and len(result.stdout) > 8192):
            raise Refused("docker_step_failed")
        return result.stdout

    def create_user(self, username, *, restricted):
        if username not in (self.cfg["canary_username"], "cp-bundle-reader"):
            raise Refused("create_principal_scope")
        self.check_container("forgejo")
        # Suppress BOTH streams at the originating Docker client, before the CLI
        # prints its generated password. No password capture or argv value.
        self.quiet_docker(["exec", "-u", "git", self.cfg["forgejo_container_id"], "forgejo", "admin", "user", "create",
                           "--username", username, "--email", username + "@invalid.invalid", "--random-password",
                           "--admin=false", "--restricted=" + ("true" if restricted else "false"),
                           "--must-change-password=false", "--access-token=false"])

    def schema_probe(self):
        self.check_container("database")
        query = b'''BEGIN TRANSACTION READ ONLY;
SET LOCAL search_path = public, pg_catalog;
SET LOCAL statement_timeout = '10s';
SELECT id, name, lower_name, type FROM "user" LIMIT 0;
SELECT id, uid, name, scope, created_unix FROM access_token LIMIT 0;
SELECT json_build_object('cleanup_schema', 'ready', 'server_version_num', current_setting('server_version_num'));
ROLLBACK;
'''
        raw = self.quiet_docker(["exec", "-i", "-u", "postgres", self.cfg["database_container_id"], "env", "-i",
                                 "PATH=/usr/local/bin:/usr/bin:/bin", "PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null",
                                 "psql", "-X", "-qAt", "--no-password", "-h", "/var/run/postgresql", "-p", "5432",
                                 "-U", "forgejo", "-d", "forgejo", "--set", "ON_ERROR_STOP=1", "-f", "-"], sql_input=query)
        data = json.loads(raw)
        if data.get("cleanup_schema") != "ready" or not 160000 <= int(data["server_version_num"]) < 170000:
            raise Refused("cleanup_schema_version")

    def require_canary(self, meta):
        users = meta.get("users", [])
        if len(users) != 1 or type(users[0].get("id")) is not int or users[0]["id"] in (1, 2, 3, 4, 5):
            raise Refused("canary_uid")
        c = {**self.cfg, "username": self.cfg["canary_username"], "user_id": users[0]["id"]}
        self.runtime["check_metadata"](meta, c, 0)

    def require_cp_ungranted(self, meta):
        self.require_cp_identity(meta)
        if any(meta.get(k) != [] for k in ("tokens", "teams", "org_memberships", "team_memberships", "owned_repos",
                                           "public_keys", "gpg_keys", "collaborations", "access_rows")):
            raise Refused("cp_pregrants_not_empty")

    def require_cp_identity(self, meta, expected_uid=None):
        users = meta.get("users", [])
        if len(users) != 1 or type(users[0].get("id")) is not int or users[0]["id"] <= 5:
            raise Refused("cp_uid")
        user = users[0]
        if expected_uid is not None and (type(expected_uid) is not int or user["id"] != expected_uid):
            raise Refused("cp_uid_changed")
        expected = {"name": "cp-bundle-reader", "type": 0, "is_admin": False, "is_active": True,
                    "is_restricted": self.cfg["cp_require_restricted"], "prohibit_login": False,
                    "must_change_password": False, "login_type": 0, "login_source": 0}
        if any(type(user.get(k)) is not type(v) or user[k] != v for k, v in expected.items()):
            raise Refused("cp_user_state")

    def require_owner(self, meta):
        users = meta.get("users", [])
        if len(users) != 1:
            raise Refused("owner_count")
        expected = {"id": 1, "name": "dotmac-admin", "type": 0, "is_admin": True, "is_active": True,
                    "is_restricted": False, "prohibit_login": False, "must_change_password": False,
                    "login_type": 0, "login_source": 0}
        if any(type(users[0].get(k)) is not type(v) or users[0][k] != v for k, v in expected.items()):
            raise Refused("owner_state")
        teams = meta.get("team_memberships", [])
        if (len(teams) != 1 or type(teams[0].get("team_id")) is not int or teams[0]["team_id"] != 1
                or type(teams[0].get("org_id")) is not int or teams[0]["org_id"] != 2
                or teams[0].get("team_name") != "Owners" or teams[0].get("org_name") != "dotmac"
                or type(teams[0].get("authorization")) is not int or teams[0]["authorization"] != 4):
            raise Refused("owner_membership")
        detail = meta.get("teams", [])
        expected_team = {"team_id": 1, "team_name": "Owners", "org_id": 2, "org_name": "dotmac",
                         "authorization": 4, "member_count": 1}
        if len(detail) != 1 or any(type(detail[0].get(k)) is not type(v) or detail[0][k] != v for k, v in expected_team.items()):
            raise Refused("sole_owner_team_state")
        orgs = meta.get("org_memberships", [])
        if (len(orgs) != 1 or type(orgs[0].get("org_id")) is not int
                or orgs[0]["org_id"] != 2 or orgs[0].get("org_name") != "dotmac"):
            raise Refused("owner_org_membership")
        if not isinstance(meta.get("tokens"), list):
            raise Refused("owner_token_metadata")

    def mint(self, username, name, scope):
        expected = {self.cfg["canary_username"]: (self.cfg["canary_token_name"], "read:user"),
                    "dotmac-admin": (self.cfg["bootstrap_token_name"], "write:organization")}
        if expected.get(username) != (name, scope):
            raise Refused("mint_scope")
        self.check_container("forgejo")
        return self.runtime["docker"](["exec", "-u", "git", self.cfg["forgejo_container_id"], "forgejo", "admin", "user",
                                      "generate-access-token", "--username", username, "--token-name", name,
                                      "--scopes", scope, "--raw"], sensitive=True)

    def request(self, kind, value, **kwargs):
        return self.api["request"](kind, value, **kwargs)

    def revoke(self, binding):
        identifier = (binding["user_id"], binding["token_id"])
        if identifier in self.revocation_attempts:
            raise Refused("revocation_retry_forbidden")
        text = self.sql["build_revocation_sql"](binding)
        self.check_container("database")
        self.revocation_attempts.add(identifier)
        self.quiet_docker(["exec", "-i", "-u", "postgres", self.cfg["database_container_id"], "env", "-i",
                           "PATH=/usr/local/bin:/usr/bin:/bin", "PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null",
                           "psql", "-X", "-qAt", "--no-password", "-h", "/var/run/postgresql", "-p", "5432",
                           "-U", "forgejo", "-d", "forgejo", "--set", "ON_ERROR_STOP=1", "-f", "-"], sql_input=text.encode())

    def require_cp_join_target(self, meta, team_id, cp_uid):
        self.require_cp_identity(meta, cp_uid)
        for key in ("tokens", "org_memberships", "team_memberships", "owned_repos", "public_keys", "gpg_keys", "collaborations", "access_rows"):
            if meta.get(key) != []:
                raise Refused("cp_before_join_not_isolated")
        self.require_cp_team(meta, team_id, member_count=0)

    @staticmethod
    def require_cp_team(meta, team_id, member_count):
        teams = meta.get("teams", [])
        expected = {"team_id": team_id, "team_name": "cp-bundle-readers", "org_id": 2, "org_name": "dotmac",
                    "authorization": 1, "member_count": member_count, "team_repo_count": 0,
                    "can_create_org_repo": False, "includes_all_repositories": False}
        if type(team_id) is not int or team_id <= 0 or len(teams) != 1:
            raise Refused("cp_team_target")
        if any(type(teams[0].get(k)) is not type(v) or teams[0][k] != v for k, v in expected.items()):
            raise Refused("cp_team_grants")
        units = teams[0].get("units")
        if (not isinstance(units, list) or len([u for u in units if u.get("type") == 9 and u.get("access_mode") == 1]) != 1
                or any(type(u.get("type")) is not int or type(u.get("access_mode")) is not int
                       or (u["type"] != 9 and u["access_mode"] != 0) or (u["type"] == 9 and u["access_mode"] != 1) for u in units)):
            raise Refused("cp_team_units")

    def require_cp_ready(self, meta, team_id, cp_uid):
        self.require_cp_identity(meta, cp_uid)
        self.require_cp_team(meta, team_id, member_count=1)
        orgs = meta.get("org_memberships", [])
        memberships = meta.get("team_memberships", [])
        if (len(orgs) != 1 or type(orgs[0].get("org_id")) is not int or orgs[0]["org_id"] != 2
                or orgs[0].get("org_name") != "dotmac" or len(memberships) != 1):
            raise Refused("cp_org_or_team_membership")
        expected = {"team_id": team_id, "org_id": 2, "org_name": "dotmac", "team_name": "cp-bundle-readers", "authorization": 1}
        if any(type(memberships[0].get(k)) is not type(v) or memberships[0][k] != v for k, v in expected.items()):
            raise Refused("cp_exact_membership")
        cfg = {"forgejo_user": "cp-bundle-reader", "forgejo_org": "dotmac", "forgejo_team": "cp-bundle-readers",
               "require_restricted": self.cfg["cp_require_restricted"]}
        checks = self.audit["evaluate"](meta, cfg, "pre")
        if not checks or not all(c["ok"] for c in checks):
            raise Refused("cp_grant_audit")


def validate_accepted_canary(cfg, path):
    raw = guarded(path)
    if sha(raw) != cfg["accepted_canary_receipt_sha256"]:
        raise Refused("canary_receipt_hash")
    receipt = json.loads(raw)
    images = {k: cfg[k] for k in ("forgejo_container_id", "forgejo_image_id", "database_container_id", "database_image_id")}
    if (receipt.get("schema") != "cp_host_gated_receipt.v1" or receipt.get("status") != "CANARY_PASSED"
            or receipt.get("phase") != "canary" or receipt.get("run") != cfg["run"]
            or receipt.get("source_pins") != cfg["source_pins"] or receipt.get("container_pins") != images):
        raise Refused("canary_receipt_binding")


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--phase", choices=("canary", "bootstrap"), default="canary")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expect-config-sha256")
    parser.add_argument("--accepted-canary-receipt")
    args = parser.parse_args()
    path = Path(args.config)
    if args.apply:
        if os.geteuid() != 0 or socket.gethostname() != "dotmac-s3":
            raise Refused("registry_host_only")
        root_ancestors(path)
        root_ancestors(Path(__file__))
    cfg, config_hash = load_config(path)
    if not args.apply:
        print(json.dumps({"status": "PLAN_ONLY_NO_CONTACT", "config_sha256": config_hash, "phase": args.phase}))
        return 0
    if (not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or Path(sys.executable).resolve() != Path("/usr/bin/python3").resolve()):
        raise Refused("isolated_system_python_required")
    if args.expect_config_sha256 != config_hash:
        raise Refused("config_hash")
    require_apply(cfg, args.phase)
    if args.phase == "bootstrap":
        if not args.accepted_canary_receipt:
            raise Refused("canary_receipt_required")
        canary_path = Path(args.accepted_canary_receipt)
        root_ancestors(canary_path)
        validate_accepted_canary(cfg, canary_path)
    parent = Path("/root/cp-reader-host-gated-receipts") / cfg["run"]
    st = parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused("receipt_parent")
    modules = {name: load_module(name, pin) for name, pin in cfg["source_pins"].items() if name != "host_gate.py"}
    journal = Journal(parent / args.phase, cfg, args.phase)
    backend = Backend(cfg, modules["runtime.py"], modules["audit.py"], modules["bootstrap_api.py"], modules["revocation_sql.py"])
    backend.check_container("forgejo")
    backend.check_container("database")
    backend.schema_probe()
    version = modules["runtime.py"]["docker"](["exec", "-u", "git", cfg["forgejo_container_id"], "forgejo", "--version"])
    if not re.search(rb"\b11\.0\.16\b", version):
        raise Refused("version")
    journal.write("pinned_runtime_ready")
    fn = modules["orchestrator.py"]["run_canary" if args.phase == "canary" else "run_bootstrap"]
    return 0 if fn(cfg, backend, journal) and not journal.failed else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("STOP: protected preflight or I/O refusal; retain exact run, no retry", file=sys.stderr)
        raise SystemExit(2)
