#!/usr/bin/env python3
"""C5 observer-role secret handling (architect r3, P2b part 2). stdlib only. Run as root on the CP host:
`python3 -I a2-observer-secret.py <subcommand> ...`.

  materialize --template T --template-sha256 H --n N [--valid-until 'YYYY-MM-DD HH:MM:SS+00'] --out FILE
        Substitute ONLY <N> (digits) and <VALID_UNTIL> (create template only) into a per-run copy; verify the template
        sha first; write O_EXCL 0600; print `materialized_sha256=<hex>`. That sha is what goes into the A-text.
  create --n N --materialized FILE --materialized-sha256 H --env-file F --tmpfs-dir D --container C --superuser U
         --dbname DB --service-host HOST --port P [--sslmode-key KEY]
        Generates the password into a per-run root-only tmpfs directory (D/a2-observer-r<N>), computes the SCRAM-SHA-256
        verifier and feeds ONLY the verifier to psql on STDIN as a psql `set scram_verifier` command prepended to the sha-verified SQL
        bytes (never on argv), appends A2_OBSERVER_DSN to the env file atomically (0600 root), then deletes the password file
        and its per-run directory (every exit path). The DSN's sslmode is the one of the session's general DSN (KEY, default
        DATABASE_URL in the env file); `disable` and `prefer` are refused.
  readback --n N --materialized FILE --materialized-sha256 H --env-file F --container C --superuser U --dbname DB
        Runs the read-back SQL (names and t/f only); checks the env file is 0600 root with exactly one observer line.
  drop --n N --materialized FILE --materialized-sha256 H --env-file F --tmpfs-dir D --container C --superuser U --dbname DB
        Runs the drop SQL, removes the A2_OBSERVER_DSN line atomically, re-checks the mode and asserts the per-run tmpfs
        password directory is absent.
  secdef-names --n N --materialized FILE --materialized-sha256 H --container C --superuser U --dbname DB
        P1 helper only (not in the sitting or the A-text): prints the NAMES of reachable SECURITY DEFINER functions.
  absence --n N --materialized FILE --materialized-sha256 H --env-file F --tmpfs-dir D --container C --superuser U --dbname DB
        Runs the absence SQL (`role_absent|true` required) and asserts the env line and the tmpfs directory are absent.

Output is names and digests only. The plaintext password exists only in the tmpfs file (0600) and, after create, inside the
root-only env file. It never reaches argv, stdout, stderr, logs or SQL. Exit 0 ok, 2 STOP (a name on stderr).
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import os
import re
import secrets
import signal
import stat
import subprocess
import sys

ROOT_UID = 0                 # the owner every protected file must have (tests override)
ITERATIONS = 4096
KEY = "A2_OBSERVER_DSN"
SSLMODES = ("verify-full", "verify-ca", "require")        # `disable` and `prefer` are refused (S-4)
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
ABS = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
VALID_UNTIL = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\+00$")
MAX_VALID_SECONDS = 3 * 3600 + 300
SQL_LIMIT = 65536


class Stop(Exception):
    pass


def need(ok, name):
    if not ok:
        raise Stop(name)


def say(*parts):
    print(*parts)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


# ── SCRAM-SHA-256 (RFC 5802 / RFC 7677; PostgreSQL stored form) ───────────────────────────────────────────────
def scram_parts(password: bytes, salt: bytes, iterations: int = ITERATIONS):
    salted = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return salted, client_key, stored_key, server_key


def scram_verifier(password: bytes, salt: bytes, iterations: int = ITERATIONS) -> str:
    _, _, stored, server = scram_parts(password, salt, iterations)
    b = lambda raw: base64.b64encode(raw).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{b(salt)}${b(stored)}:{b(server)}"


# ── file helpers ──────────────────────────────────────────────────────────────────────────────────────────────
def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_regular(path, limit, owner_only=False):
    need(isinstance(path, str) and ABS.match(path) and ".." not in path and "//" not in path, "path_shape")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Stop("file_unreadable") from None
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit, "file_shape")
        if owner_only:
            need(st.st_uid == ROOT_UID and stat.S_IMODE(st.st_mode) == 0o600, "file_owner_or_mode")
        else:
            need(not st.st_mode & 0o022, "file_writable_by_others")
        raw = os.read(fd, limit + 1)
        need(len(raw) == st.st_size, "file_changed")
        return raw
    finally:
        os.close(fd)


def parent_ok(path):
    st = os.stat(os.path.dirname(path))
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == ROOT_UID and not st.st_mode & 0o022, "parent_not_root_owned_or_writable")


def write_exclusive(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def is_tmpfs(path):
    """True only if the path lies on a tmpfs/ramfs mount (longest mount-point prefix in /proc/mounts)."""
    best, fstype = "", ""
    try:
        with open("/proc/mounts") as handle:
            for line in handle:
                f = line.split()
                if len(f) >= 3 and (path == f[1] or path.startswith(f[1].rstrip("/") + "/")) and len(f[1]) > len(best):
                    best, fstype = f[1], f[2]
    except OSError:
        return False
    return fstype in ("tmpfs", "ramfs")


def run_psql(argv, sql: bytes):
    """Run the psql command with the SQL on stdin. Output is captured and returned (never the secret)."""
    proc = subprocess.run(argv, input=sql, capture_output=True, check=False, shell=False)
    return proc.returncode, proc.stdout


# ── template handling ─────────────────────────────────────────────────────────────────────────────────────────
def materialize(template_path, template_sha, n, valid_until):
    raw = read_regular(template_path, SQL_LIMIT)
    need(HEX.match(template_sha or "") and sha256_bytes(raw) == template_sha, "template_sha256_differs")
    need(isinstance(n, str) and re.fullmatch(r"[1-9][0-9]{0,5}", n), "run_number")
    text = raw.decode("ascii")
    has_valid = "<VALID_UNTIL>" in text
    if has_valid:
        need(isinstance(valid_until, str) and VALID_UNTIL.match(valid_until), "valid_until_form")
        when = datetime.datetime.strptime(valid_until[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        delta = (when - now_utc()).total_seconds()
        need(0 < delta <= MAX_VALID_SECONDS, "valid_until_out_of_bounds")
        text = text.replace("<VALID_UNTIL>", valid_until)
    else:
        need(valid_until is None, "valid_until_not_applicable")
    text = text.replace("<N>", n)
    need("<" not in text and ">" not in text, "unresolved_placeholder")
    return text.encode("ascii")


def load_materialized(path, expect_sha, n, kind):
    raw = read_regular(path, SQL_LIMIT)
    need(HEX.match(expect_sha or "") and sha256_bytes(raw) == expect_sha, "materialized_sha256_differs")
    role = f"a2_recovery_observer_r{n}"
    text = raw.decode("ascii")
    need(re.fullmatch(r"[1-9][0-9]{0,5}", n or "") and role in text, "materialized_not_for_this_run")
    other = set(re.findall(r"a2_recovery_observer_r([0-9]+)", text)) - {n}
    need(not other, "materialized_mentions_another_run")
    if kind == "create":
        need(":'scram_verifier'" in text and "PASSWORD '" not in text.replace("PASSWORD :'scram_verifier'", ""), "create_sql_password_shape")
    return raw


# ── env file ──────────────────────────────────────────────────────────────────────────────────────────────────
def rewrite_env(env_path, new_lines_fn):
    """Atomically replace the env file: read, transform, write a sibling O_EXCL 0600 file, fsync, rename. The file and its
    directory must be root-owned (ROOT_UID); the result is 0600 root."""
    parent_ok(env_path)
    raw = read_regular(env_path, 1 << 20, owner_only=True)
    lines = raw.decode("utf-8").split("\n")
    new = new_lines_fn(lines)
    out = ("\n".join(new)).encode("utf-8")
    tmp = f"{env_path}.a2obs{secrets.token_hex(4)}"
    try:
        write_exclusive(tmp, out)
        os.replace(tmp, env_path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)
    st = os.stat(env_path)
    need(st.st_uid == ROOT_UID and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, "env_file_owner_or_mode_after")
    return sha256_bytes(out)


def env_observer_count(env_path):
    raw = read_regular(env_path, 1 << 20, owner_only=True)
    return sum(1 for l in raw.decode("utf-8").split("\n") if l.startswith(KEY + "="))


def session_sslmode(env_path, key):
    """The sslmode of the session's general DSN (testbed): read from the root-only env file, never printed."""
    need(re.fullmatch(r"[A-Z][A-Z0-9_]{0,62}", key or ""), "sslmode_key")
    raw = read_regular(env_path, 1 << 20, owner_only=True).decode("utf-8")
    for line in raw.split("\n"):
        if line.startswith(key + "="):
            m = re.search(r"[?&]sslmode=([a-z-]+)", line)
            need(m is not None, "general_dsn_has_no_sslmode")
            need(m.group(1) in SSLMODES, "sslmode_not_acceptable_refuses_disable_and_prefer")
            return m.group(1)
    raise Stop("general_dsn_key_not_in_env_file")


def run_dir(a):
    need(ABS.match(a.tmpfs_dir or ""), "tmpfs_dir")
    return os.path.join(a.tmpfs_dir, f"a2-observer-r{a.n}")


def psql_argv(a, extra):
    need(NAME.match(a.container) and NAME.match(a.superuser) and NAME.match(a.dbname), "psql_inputs")
    return (["docker", "exec", "-i", a.container, "psql", "-v", "ON_ERROR_STOP=1"] + extra +
            ["-v", f"dbname={a.dbname}", "-U", a.superuser, "-d", a.dbname, "-f", "-"])


# ── subcommands ───────────────────────────────────────────────────────────────────────────────────────────────
def cmd_materialize(a):
    raw = materialize(a.template, a.template_sha256, a.n, a.valid_until)
    need(ABS.match(a.out or ""), "out_path")
    write_exclusive(a.out, raw)
    say(f"materialized_sha256={sha256_bytes(raw)}")
    say(f"materialized_file_mode=0600")


def cmd_create(a):
    n = a.n
    need(re.fullmatch(r"[1-9][0-9]{0,5}", n or ""), "run_number")
    sslmode = session_sslmode(a.env_file, a.sslmode_key)
    need(HOST.match(a.service_host or "") and not re.fullmatch(r"[0-9.]+|.*:.*", a.service_host), "service_host_must_be_an_alias")
    need(re.fullmatch(r"[0-9]{2,5}", a.port or "") and 1 <= int(a.port) <= 65535, "port")
    need(NAME.match(a.dbname), "dbname")
    sql = load_materialized(a.materialized, a.materialized_sha256, n, "create")
    need(ABS.match(a.tmpfs_dir or "") and os.path.isdir(a.tmpfs_dir), "tmpfs_dir")
    st = os.stat(a.tmpfs_dir)
    need(st.st_uid == ROOT_UID and stat.S_IMODE(st.st_mode) & 0o077 == 0, "tmpfs_dir_not_root_only")
    need(is_tmpfs(os.path.realpath(a.tmpfs_dir)), "tmpfs_dir_not_tmpfs")
    need(env_observer_count(a.env_file) == 0, "env_file_already_has_observer_dsn")
    rdir = run_dir(a)
    need(not os.path.lexists(rdir), "tmpfs_run_dir_already_exists")
    pw_path = os.path.join(rdir, "pw")
    created = False
    try:
        os.mkdir(rdir, 0o700)
        os.chmod(rdir, 0o700)
        created = True
        password = secrets.token_urlsafe(32).encode("ascii")           # URL-safe, DSN-safe, 43 chars
        write_exclusive(pw_path, password)
        salt = secrets.token_bytes(16)
        verifier = scram_verifier(password, salt)
        # S-1: the verifier travels on psql's STDIN (after the sha check of the file), never on docker's argv.
        stdin_sql = ("\\set scram_verifier '" + verifier + "'\n").encode("ascii") + sql
        code, _out = run_psql(psql_argv(a, []), stdin_sql)
        need(code == 0, "psql_create_failed")                           # output is never printed: it could echo SQL
        dsn = (f"postgresql://a2_recovery_observer_r{n}:{password.decode('ascii')}@{a.service_host}:{a.port}/{a.dbname}"
               f"?sslmode={sslmode}&application_name=a2-recovery-observe")

        def add(lines):
            keep = [l for l in lines if l != ""]
            need(not any(l.startswith(KEY + "=") for l in keep), "env_file_already_has_observer_dsn")
            return keep + [f"{KEY}={dsn}", ""]
        try:
            digest = rewrite_env(a.env_file, add)
        except Stop as error:
            raise Stop(f"{error}_role_exists_run_the_drop") from None
        say(f"observer_role=a2_recovery_observer_r{n}")
        say("verifier_scheme=SCRAM-SHA-256 iterations=4096")
        say(f"env_file_sha256={digest} mode=0600 owner=root key={KEY}")
    finally:
        if created:
            try:
                if os.path.lexists(pw_path):
                    fd = os.open(pw_path, os.O_WRONLY | os.O_NOFOLLOW)
                    try:
                        os.write(fd, b"\0" * 64)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                        os.unlink(pw_path)
            finally:
                if os.path.isdir(rdir):
                    os.rmdir(rdir)
            need(not os.path.lexists(rdir), "tmpfs_copy_not_removed")


def cmd_readback(a):
    sql = load_materialized(a.materialized, a.materialized_sha256, a.n, "readback")
    code, out = run_psql(psql_argv(a, ["-A", "-t"]), sql)
    need(code == 0, "psql_readback_failed")
    rows = [l for l in out.decode("utf-8", "replace").splitlines() if l.strip()]
    need(rows and all(re.fullmatch(r"[a-z0-9_]+\|(true|false)", r) for r in rows), "readback_output_shape")
    for r in rows:
        say(r)
    need(all(r.endswith("|true") for r in rows), "readback_check_failed")
    need(env_observer_count(a.env_file) == 1, "env_file_observer_line_count")
    say("env_file_mode=0600 owner=root observer_line=present")


def cmd_drop(a):
    sql = load_materialized(a.materialized, a.materialized_sha256, a.n, "drop")
    code, _out = run_psql(psql_argv(a, []), sql)
    need(code == 0, "psql_drop_failed")
    digest = rewrite_env(a.env_file, lambda lines: [l for l in lines if not l.startswith(KEY + "=")])
    need(env_observer_count(a.env_file) == 0, "env_line_still_present")
    need(not os.path.lexists(run_dir(a)), "tmpfs_password_dir_present_after_drop")
    say(f"observer_role_dropped=a2_recovery_observer_r{a.n}")
    say(f"env_file_sha256={digest} mode=0600 owner=root observer_line=absent")


def cmd_absence(a):
    sql = load_materialized(a.materialized, a.materialized_sha256, a.n, "absence")
    code, out = run_psql(psql_argv(a, ["-A", "-t"]), sql)
    need(code == 0, "psql_absence_failed")
    rows = [l for l in out.decode("utf-8", "replace").splitlines() if l.strip()]
    need(rows == ["role_absent|true"], "role_not_absent")
    need(env_observer_count(a.env_file) == 0, "env_line_still_present")
    need(not os.path.lexists(run_dir(a)), "tmpfs_password_dir_present")
    say("role_absent|true")
    say("env_line=absent tmpfs_password_dir=absent")


def cmd_secdef_names(a):
    sql = load_materialized(a.materialized, a.materialized_sha256, a.n, "secdef")
    code, out = run_psql(psql_argv(a, ["-A", "-t"]), sql)
    need(code == 0, "psql_secdef_names_failed")
    rows = [l for l in out.decode("utf-8", "replace").splitlines() if l.strip()]
    need(rows and all(re.fullmatch(r"secdef_reachable\|[ -~]{1,300}", r) for r in rows), "secdef_names_output_shape")
    need("secdef_reachable|none" not in rows or rows == ["secdef_reachable|none"], "secdef_names_output_shape")
    for r in rows:
        say(r)


def build_parser():
    p = argparse.ArgumentParser(allow_abbrev=False)
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("materialize")
    for k in ("template", "template-sha256", "n", "out"):
        m.add_argument("--" + k, required=True)
    m.add_argument("--valid-until")
    c = sub.add_parser("create")
    for k in ("n", "materialized", "materialized-sha256", "env-file", "tmpfs-dir", "container", "superuser", "dbname",
              "service-host", "port"):
        c.add_argument("--" + k, required=True)
    c.add_argument("--sslmode-key", default="DATABASE_URL")
    for name in ("readback", "drop", "absence", "secdef-names"):
        r = sub.add_parser(name)
        for k in ("n", "materialized", "materialized-sha256", "container", "superuser", "dbname"):
            r.add_argument("--" + k, required=True)
        if name != "secdef-names":
            r.add_argument("--env-file", required=True)
        if name in ("drop", "absence"):
            r.add_argument("--tmpfs-dir", required=True)
    return p


def on_signal(signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, on_signal)
    a = build_parser().parse_args(argv)
    try:
        {"materialize": cmd_materialize, "create": cmd_create, "readback": cmd_readback, "drop": cmd_drop, "absence": cmd_absence, "secdef-names": cmd_secdef_names}[a.cmd](a)
    except Stop as stop:
        print(f"a2-observer-secret: STOP {stop}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("a2-observer-secret: STOP signalled", file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError) as error:
        print(f"a2-observer-secret: STOP {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
