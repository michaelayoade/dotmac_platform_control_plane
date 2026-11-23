"""OpenBao one-use / cleanup / purpose-separation / audit proof (values-free).

Drives a DISPOSABLE OpenBao server (file storage, initialised here, loopback
address, never a real OpenBao) over its HTTP API with the standard library. Root
and one-use tokens live only in this process's memory: they are never printed,
logged or written, and the audit file is checked for their absence. The output is
`checks[]` with names and booleans only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXPECTED_VERSION = "2.5.3"
DISPATCHES = 3

POLICY_RECOVERY = 'path "kv/data/recovery/*" { capabilities = ["read"] }\n'
POLICY_NORMAL = 'path "kv/data/normal/*" { capabilities = ["read"] }\n'


class Bao:
    def __init__(self, addr: str) -> None:
        if not addr.startswith("http://127.0.0.1:"):
            raise SystemExit("refusing a non-loopback OpenBao address")
        self.addr = addr

    def call(
        self, method: str, path: str, token: str | None = None, body: Any = None
    ) -> tuple[int, dict[str, Any]]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(  # noqa: S310 - loopback http only, checked above
            f"{self.addr}/v1/{path}", data=data, method=method
        )
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else {}
            except ValueError:
                return exc.code, {}


def wait_ready(bao: Bao) -> dict[str, Any]:
    for _ in range(60):
        try:
            # 501 = uninitialised, 503 = sealed: both mean the listener is up.
            code, doc = bao.call(
                "GET", "sys/health?standbyok=true&uninitcode=200&sealedcode=200"
            )
            if code == 200:
                return doc
        except OSError:
            pass
        time.sleep(1)
    raise SystemExit("OpenBao did not come up")


def mint(bao: Bao, root: str, policy: str, num_uses: int) -> tuple[str, str]:
    code, doc = bao.call(
        "POST",
        "auth/token/create",
        root,
        {"policies": [policy], "num_uses": num_uses, "ttl": "10m", "renewable": False},
    )
    if code != 200:
        raise SystemExit(f"token mint failed: http {code}")
    return doc["auth"]["client_token"], doc["auth"]["accessor"]


def accessor_gone(bao: Bao, root: str, accessor: str) -> bool:
    code, _ = bao.call(
        "POST", "auth/token/lookup-accessor", root, {"accessor": accessor}
    )
    return code != 200


def check(name: str, ok: bool, **facts: Any) -> dict[str, Any]:
    return {"check": name, "status": "PASS" if ok else "FAIL", **facts}


def run(addr: str, audit_container_path: str, audit_host_path: Path) -> dict[str, Any]:
    bao = Bao(addr)
    health = wait_ready(bao)
    code, init = bao.call(
        "POST", "sys/init", None, {"secret_shares": 1, "secret_threshold": 1}
    )
    if code != 200:
        raise SystemExit(f"init failed: http {code}")
    root = init["root_token"]
    code, _ = bao.call("POST", "sys/unseal", None, {"key": init["keys"][0]})
    if code != 200:
        raise SystemExit(f"unseal failed: http {code}")
    code, health = bao.call("GET", "sys/health")
    version = str(health.get("version", ""))
    not_dev = bool(health.get("initialized")) and not health.get("sealed", True)

    secrets_used: list[str] = [root, init["keys"][0]]
    for step, (method, path, body) in {
        "mount": ("POST", "sys/mounts/kv", {"type": "kv", "options": {"version": "2"}}),
        "audit": (
            "PUT",
            "sys/audit/file",
            {
                "type": "file",
                "options": {"file_path": audit_container_path, "mode": "0644"},
            },
        ),
        "pol-recovery": (
            "PUT",
            "sys/policies/acl/purpose-recovery",
            {"policy": POLICY_RECOVERY},
        ),
        "pol-normal": (
            "PUT",
            "sys/policies/acl/purpose-normal",
            {"policy": POLICY_NORMAL},
        ),
        "seed-recovery": (
            "POST",
            "kv/data/recovery/marker",
            {"data": {"marker": "synthetic"}},
        ),
        "seed-normal": (
            "POST",
            "kv/data/normal/marker",
            {"data": {"marker": "synthetic"}},
        ),
    }.items():
        code, doc = bao.call(method, path, root, body)
        if code not in (200, 204):
            # Server error TEXT only (never a token or request body).
            errors = "; ".join(str(e) for e in doc.get("errors", []))[:300]
            raise SystemExit(f"setup step {step} failed: http {code}: {errors}")
    for i in range(DISPATCHES):
        code, _ = bao.call(
            "POST", f"kv/data/recovery/dispatch-{i}", root, {"data": {"n": str(i)}}
        )
        if code not in (200, 204):
            raise SystemExit("dispatch seed failed")

    checks: list[dict[str, Any]] = []

    # 1. a one-use token is exhausted after one use.
    tok, acc = mint(bao, root, "purpose-recovery", 1)
    secrets_used.append(tok)
    first, _ = bao.call("GET", "kv/data/recovery/marker", tok)
    second, _ = bao.call("GET", "kv/data/recovery/marker", tok)
    checks.append(
        check(
            "one_use_token_exhausted",
            first == 200 and second != 200 and accessor_gone(bao, root, acc),
            first_use_ok=first == 200,
            second_use_refused=second != 200,
            accessor_gone_after_exhaustion=accessor_gone(bao, root, acc),
        )
    )

    # 2. cleanup revokes the token and its accessor (read back by outcome only).
    tok, acc = mint(bao, root, "purpose-recovery", 1)
    secrets_used.append(tok)
    revoked, _ = bao.call("POST", "auth/token/revoke-accessor", root, {"accessor": acc})
    use_after, _ = bao.call("GET", "kv/data/recovery/marker", tok)
    tok2, acc2 = mint(bao, root, "purpose-recovery", 0)
    secrets_used.append(tok2)
    live, _ = bao.call("GET", "kv/data/recovery/marker", tok2)
    revoked2, _ = bao.call(
        "POST", "auth/token/revoke-accessor", root, {"accessor": acc2}
    )
    use_after2, _ = bao.call("GET", "kv/data/recovery/marker", tok2)
    checks.append(
        check(
            "cleanup_revokes_token_and_accessor",
            revoked in (200, 204)
            and use_after != 200
            and accessor_gone(bao, root, acc)
            and live == 200
            and revoked2 in (200, 204)
            and use_after2 != 200
            and accessor_gone(bao, root, acc2),
            unused_one_use_revoked=revoked in (200, 204) and use_after != 200,
            used_token_revoked=revoked2 in (200, 204) and use_after2 != 200,
            accessors_gone=accessor_gone(bao, root, acc)
            and accessor_gone(bao, root, acc2),
        )
    )

    # 3. purpose-separated policy denies cross-purpose access.
    rec, rec_acc = mint(bao, root, "purpose-recovery", 0)
    nor, nor_acc = mint(bao, root, "purpose-normal", 0)
    secrets_used += [rec, nor]
    rec_own, _ = bao.call("GET", "kv/data/recovery/marker", rec)
    rec_cross, _ = bao.call("GET", "kv/data/normal/marker", rec)
    rec_write, _ = bao.call(
        "POST", "kv/data/recovery/marker", rec, {"data": {"x": "y"}}
    )
    rec_mint, _ = bao.call(
        "POST", "auth/token/create", rec, {"policies": ["purpose-normal"]}
    )
    nor_own, _ = bao.call("GET", "kv/data/normal/marker", nor)
    nor_cross, _ = bao.call("GET", "kv/data/recovery/marker", nor)
    for accessor in (rec_acc, nor_acc):
        bao.call("POST", "auth/token/revoke-accessor", root, {"accessor": accessor})
    checks.append(
        check(
            "purpose_separated_policy_denies_cross_purpose",
            rec_own == 200
            and rec_cross == 403
            and rec_write == 403
            and rec_mint == 403
            and nor_own == 200
            and nor_cross == 403,
            recovery_own_path_allowed=rec_own == 200,
            recovery_denied_normal_path=rec_cross == 403,
            recovery_denied_write=rec_write == 403,
            recovery_denied_minting=rec_mint == 403,
            normal_own_path_allowed=nor_own == 200,
            normal_denied_recovery_path=nor_cross == 403,
        )
    )

    # 4. one audit line per dispatch: each dispatch is one one-use token and one read.
    for i in range(DISPATCHES):
        tok, acc = mint(bao, root, "purpose-recovery", 1)
        secrets_used.append(tok)
        code, _ = bao.call("GET", f"kv/data/recovery/dispatch-{i}", tok)
        if code != 200:
            raise SystemExit("dispatch read failed")
        bao.call("POST", "auth/token/revoke-accessor", root, {"accessor": acc})
    time.sleep(1)
    text = audit_host_path.read_text(encoding="utf-8")
    entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    per_dispatch = []
    for i in range(DISPATCHES):
        path = f"kv/data/recovery/dispatch-{i}"
        reqs = [
            e
            for e in entries
            if e.get("type") == "request"
            and e.get("request", {}).get("path") == path
            and e.get("request", {}).get("operation") == "read"
        ]
        per_dispatch.append(len(reqs))
    leaked = any(secret in text for secret in secrets_used)
    checks.append(
        check(
            "one_audit_request_line_per_dispatch",
            per_dispatch == [1] * DISPATCHES and not leaked,
            dispatches=DISPATCHES,
            request_lines_per_dispatch=per_dispatch,
            no_raw_token_in_audit_log=not leaked,
        )
    )

    return {
        "server_version": version,
        "not_dev_mode": not_dev,
        "checks": [
            check(
                "server_version_is_pinned",
                version == EXPECTED_VERSION,
                observed=version,
            ),
            *checks,
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--addr", required=True)
    p.add_argument("--audit-container-path", required=True)
    p.add_argument("--audit-host-path", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    results = run(args.addr, args.audit_container_path, Path(args.audit_host_path))
    Path(args.out).write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for c in results["checks"]:
        print(f"{c['check']}: {c['status']}")
    return 0 if all(c["status"] == "PASS" for c in results["checks"]) else 1


if __name__ == "__main__":
    sys.exit(main())
