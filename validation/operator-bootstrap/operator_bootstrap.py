"""One operator bootstrap, composing pinned owners; no invocation is approval.

This entrypoint never impersonates a protected GitHub producer. Its output stays
quarantined until the lifecycle and a separate independent acceptance complete.
Run only through the separately approved, hash-pinned operator packet.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import socket
import ssl
import stat
import sys
import types

RUN = "cp-artifact-bootstrap-20261127-r2"
SOURCE_ROOT = Path("/root") / RUN
PRESERVED_ROOT = Path("/root/cp-reader-host-gated-20261125")
OUTPUT_ROOT = Path("/root/cp-artifact-bootstrap-receipts")
GET_PATH = "/api/packages/dotmac/pypi/simple/dotmac-kernel/"
CORE_PINS = {
    "host_gate.py": "6a7f5175f7e3ec5c2f4dbcf4acde036a3f308c75772d82242cafad4305f98a5a",
    "orchestrator.py": "a8f67bd4a32ba65abc7bb68e7c6129b18b7135c71bd8b73fb5a28a8446a4309e",
    "revocation_sql.py": "0e6733f2032173338b611b087530790d144a3403bcdff2418c21836e637b969a",
    "bootstrap_api.py": "377f7379c2aa838197bce511736e6af5a2854a25b5b3d0d53dfd9e7de710e172",
    "audit.py": "86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9",
    "runtime.py": "ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a",
}
TOOL_PINS = {
    "kernel_lock.py": "ef80e927e1aefba218ec528ac165d2b2c590645dfa9ab1f24b080e2b186ed27d",
    "warm_reviewed_private_artifacts.py": "568870bc0e1fbd9be262490ac9022a97240569feb0dcf6c58be45676f505ba12",
}
BOOTSTRAP_RECEIPT = Path("/root/cp-reader-host-gated-receipts/cp-host-20261125-r1/bootstrap/receipt.json")
BOOTSTRAP_SHA = "2ed457abbaf47d3039b4df56cbe4970382b39e19391b9d9524ab1b72c1c2d130"
CANARY_RECEIPT = BOOTSTRAP_RECEIPT.parent.parent / "canary/receipt.json"
CANARY_SHA = "5fa7c752952ad63dc4b0f5a9f188910c65397bc4d55cc568dabb9aefbf1bb3f7"
ADAPTER_NAMES = {"operator_bootstrap.py", "reader_lifecycle.py", "reader_revocation_sql.py",
                 "operator_acquisition.py", "warm_reviewed_private_artifacts.py"}
DATA_NAMES = {"pyproject.toml", "poetry.lock"}


class Refused(Exception):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def protected_bytes(path, *, private=True, max_bytes=8 * 1024 * 1024):
    """Read regular root-owned bytes without following links or trusting pyc."""
    for parent in path.absolute().parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise Refused("input_parent")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or first.st_nlink != 1
                or first.st_mode & (0o077 if private else 0o022) or first.st_size > max_bytes):
            raise Refused("input_protection")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) > max_bytes or any(getattr(first, k) != getattr(after, k) for k in fields):
            raise Refused("input_changed")
        return raw
    finally:
        os.close(fd)


def request_status(kind, token):
    if kind != "reader_get":
        raise Refused("http_scope")
    headers = {"Accept": "text/html"}
    if token is not None:
        # Token is never a URL, argument, environment variable, or receipt field.
        if type(token) is not str or len(token) != 40 or any(c not in "0123456789abcdef" for c in token):
            raise Refused("credential_shape")
        basic = base64.b64encode(("cp-bundle-reader:" + token).encode("ascii")).decode("ascii")
        headers["Authorization"] = "Basic " + basic
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    connection = http.client.HTTPSConnection("registry.dotmac.io", 443, context=context, timeout=15)
    try:
        connection.request("GET", GET_PATH, headers=headers)
        response = connection.getresponse()
        status = response.status
        response.close()  # Never emit or retain even an error body; no redirects.
        return {"status": status}
    finally:
        connection.close()


def verified_inputs(cfg, source=SOURCE_ROOT, preserved=PRESERVED_ROOT):
    names = {*CORE_PINS, *TOOL_PINS, *ADAPTER_NAMES, *DATA_NAMES}
    pins = cfg.get("source_pins")
    if type(pins) is not dict or set(pins) != names:
        raise Refused("source_pin_set")
    for name, digest in {**CORE_PINS, **TOOL_PINS}.items():
        if pins[name] != digest:
            raise Refused("frozen_owner_pin")
    payloads = {}
    for name in sorted(names):
        raw = protected_bytes(source / name)
        if sha(raw) != pins[name]:
            raise Refused("source_hash")
        if name in CORE_PINS and protected_bytes(preserved / name) != raw:
            raise Refused("preserved_owner_drift")
        payloads[name] = raw
    for path, digest in ((BOOTSTRAP_RECEIPT, BOOTSTRAP_SHA), (CANARY_RECEIPT, CANARY_SHA)):
        if sha(protected_bytes(path)) != digest:
            raise Refused("accepted_receipt_drift")
    return payloads


def load_verified(payloads, source=SOURCE_ROOT):
    """All bytes verified first, modules evaluated before any credential exists."""
    modules = {}
    order = ["kernel_lock.py", "warm_reviewed_private_artifacts.py", "host_gate.py",
             "runtime.py", "audit.py", "orchestrator.py", "reader_revocation_sql.py",
             "reader_lifecycle.py", "operator_acquisition.py"]
    for filename in order:
        name = filename[:-3]
        module = types.ModuleType(name)
        module.__file__ = str(source / filename)
        # Dataclasses and the producer's trusted kernel_lock import need the
        # explicit already-verified module, never a candidate sys.path entry.
        sys.modules[name] = module
        exec(compile(payloads[filename], module.__file__, "exec"), module.__dict__)
        modules[name] = module
    return modules


def require_runtime():
    if (os.geteuid() != 0 or socket.gethostname() != "dotmac-s3" or sys.version_info < (3, 11)
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or Path(sys.executable).resolve() != Path("/usr/bin/python3").resolve()):
        raise Refused("isolated_registry_system_runtime")
    for binary in (Path("/usr/bin/python3").resolve(), Path("/usr/bin/curl").resolve()):
        protected_bytes(binary, private=False, max_bytes=64 * 1024 * 1024)
    protected_bytes(Path("/etc/ssl/certs/ca-certificates.crt"), private=False)


def apply(cfg, config_hash):
    require_runtime()
    keys = {"schema", "run", "host", "reader_token_name", "canary_username", "source_pins",
            "forgejo_container_id", "forgejo_image_id", "database_container_id", "database_image_id",
            "authorization_reference", "operator_reference", "exclusive_window_reference", "cp_require_restricted"}
    if (type(cfg) is not dict or set(cfg) != keys
            or cfg.get("schema") != "cp_operator_artifact_bootstrap_config.v1" or cfg.get("run") != RUN
            or cfg.get("host") != "dotmac-s3" or cfg.get("reader_token_name") != RUN
            or cfg.get("cp_require_restricted") is not False):
        raise Refused("config_scope")
    for field in ("authorization_reference", "operator_reference", "exclusive_window_reference"):
        value = cfg.get(field)
        if type(value) is not str or not value or len(value) > 200 or value.startswith("PENDING"):
            raise Refused("authority_reference")
    payloads = verified_inputs(cfg)
    modules = load_verified(payloads)
    owner, producer = modules["kernel_lock"], modules["warm_reviewed_private_artifacts"]
    _, expected = producer.closed_plan(payloads["pyproject.toml"], payloads["poetry.lock"])
    if len(expected) != 14:
        raise Refused("artifact_count")
    OUTPUT_ROOT.mkdir(mode=0o700, exist_ok=True)
    st = OUTPUT_ROOT.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Refused("output_parent")
    host, lifecycle = modules["host_gate"], modules["reader_lifecycle"]
    host.Journal.sync(OUTPUT_ROOT.parent)
    run = OUTPUT_ROOT / RUN
    run.mkdir(mode=0o700, exist_ok=False)  # An interrupted run is never adopted.
    host.Journal.sync(OUTPUT_ROOT)
    journal = host.Journal(run / "lifecycle", cfg, "operator-artifact-bootstrap")
    journal.write("operator_baseline_bound", config_sha256=config_hash,
                  manifest_sha256=sha(payloads["pyproject.toml"]), lock_sha256=sha(payloads["poetry.lock"]))
    acquired = []

    def acquire(token):
        evidence = modules["operator_acquisition"].acquire_baseline(
            owner, producer, payloads["pyproject.toml"], payloads["poetry.lock"], run / "quarantine", token)
        if type(evidence) is not dict or evidence.get("artifacts") != expected or evidence.get("artifact_count") != 14:
            raise Refused("acquisition_attestation")
        acquired.append(evidence)
        return evidence

    backend = lifecycle.make_reader_backend(cfg, host.__dict__, modules["runtime"].__dict__,
        modules["audit"].__dict__, modules["reader_revocation_sql"].__dict__,
        modules["orchestrator"].__dict__, request_status, acquire)
    backend.check_container("forgejo")
    backend.check_container("database")
    backend.schema_probe()
    passed = lifecycle.run_reader(cfg, backend, journal)
    if not passed or journal.failed or len(acquired) != 1:
        return 2
    # Deliberately NOT an admission/release marker. Bytes remain quarantined;
    # independent receipt acceptance and reviewed transfer are separate gates.
    journal.data["operator_provenance"] = {
        "kind": "explicit-one-time-operator-bootstrap", "approval": cfg["authorization_reference"],
        "host": "dotmac-s3", "run": RUN, "source_pins": cfg["source_pins"],
        "normal_protected_producer": False, "artifacts": expected,
        "independent_acceptance_pending": True,
    }
    journal.write("quarantine_retained_pending_independent_acceptance")
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expect-config-sha256")
    args = parser.parse_args()
    # Even plan mode is not a connectivity/credential probe.
    if not args.apply:
        print("PLAN_ONLY_NO_CONTACT_NO_AUTHORITY")
        return 0
    raw = protected_bytes(Path(args.config))
    if sha(raw) != args.expect_config_sha256 or Path(args.config) != SOURCE_ROOT / "config.json":
        raise Refused("config_binding")
    return apply(json.loads(raw), sha(raw))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("STOP: operator bootstrap refused; retain state and reconcile, no retry", file=sys.stderr)
        raise SystemExit(2)
