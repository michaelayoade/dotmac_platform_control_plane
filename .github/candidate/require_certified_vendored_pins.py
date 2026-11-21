"""Refuse PRODUCTION-IMAGE PUBLICATION unless the vendored pin is E5-certified.

`src/vendor_cp/vendored_foundation/PINS.json` records Foundation source copied before
E5 is certified (status `PROVISIONAL-PENDING-E5`). That is acceptable for the
unpublished PR-head image dry runs use and for ordinary CI, and it must never reach
a published production image. This runs only on the publication path
(`production-image.yml`), never in `ci.yml`.

Admission needs ALL of:
 1. PINS.json `status == "CERTIFIED"` and an `e5_record_digest` (`sha256:<64 hex>`);
 2. a committed certification record (`e5-certification.json`) whose sha256 IS that
    digest, so the digest names real bytes rather than a format;
 3. the record is exactly `{schema, certifies}` (fixed schema, no duplicate keys) and
    `certifies` carries the PINS `source_commit`, `foundation_src_tree`, per-file sha256
    and the `wheel_only_checks` (`__init__.py`) hash;
 4. a detached OpenSSH SSHSIG over the record (`e5-certification.json.sig`) that
    `ssh-keygen -Y verify` accepts against the committed `allowed_signers`, which must
    hold exactly one line: the fixed principal, exactly the fixed namespace option, an
    allowed key type. See `signers_problem`.

The record, signature and a non-empty `allowed_signers` are committed AT E5; until
then the gate refuses. No key is invented here: the shipped `allowed_signers` has no
signer, so nothing verifies. Exit 0 admits; 1 refuses (with the reason); 2 unreadable.
Standard library plus `ssh-keygen`; no network.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DIR = Path(".github/vendored-foundation")
DEFAULT = Path("src/vendor_cp/vendored_foundation/PINS.json")
RECORD = DIR / "e5-certification.json"
SIGNATURE = DIR / "e5-certification.json.sig"
ALLOWED_SIGNERS = DIR / "allowed_signers"
#: Fixed, purpose-bound. Deliberately NOT Gate 2's rehearsal-verification namespace.
NAMESPACE = "dotmac-vendored-foundation-e5-certification-v1@dotmac.io"
PRINCIPAL = "e5-certifier@dotmac.io"
#: The record's fixed schema constant; the record is `{schema, certifies}` only.
SCHEMA = "dotmac.vendored-foundation.e5-certification.v1"
CERTIFIES_KEYS = frozenset(
    {"source_commit", "foundation_src_tree", "files", "wheel_only_checks"}
)
KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)
_KEY_BLOB = re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}")
SSH_KEYGEN = "/usr/bin/ssh-keygen"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX = 1 << 20


def _signers_present(raw: bytes) -> bool:
    return any(
        line.strip() and not line.lstrip().startswith(b"#") for line in raw.splitlines()
    )


def signers_problem(raw: bytes) -> str | None:
    """Exactly one entry: the literal principal, exactly the one namespace option
    (no cert-authority, no wildcards, no other option), an allowed key type."""
    lines = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.lstrip().startswith(b"#")
    ]
    if not lines:
        return "allowed_signers pins no signer, so no signature can verify"
    if len(lines) != 1:
        return "allowed_signers must contain exactly one signer line"
    fields = lines[0].split()
    if len(fields) < 4:
        return "allowed_signers line is malformed"
    principal, options, key_type, blob = fields[:4]
    if principal != PRINCIPAL.encode():
        return "allowed_signers principal is not the fixed E5 certifier principal"
    if options != f'namespaces="{NAMESPACE}"'.encode():
        return "allowed_signers options must be exactly the one fixed E5 namespace"
    if key_type.decode("ascii", "replace") not in KEY_TYPES:
        return "allowed_signers key type is not an allowed type"
    if not _KEY_BLOB.fullmatch(blob):
        return "allowed_signers key is malformed"
    return None


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("duplicate JSON key")
        found[key] = value
    return found


def problems(
    pins: object,
    *,
    record: Path = RECORD,
    signature: Path = SIGNATURE,
    allowed_signers: Path = ALLOWED_SIGNERS,
) -> list[str]:
    if not isinstance(pins, dict):
        return ["the vendored Foundation pin file is not a JSON object"]
    found: list[str] = []
    if pins.get("status") != "CERTIFIED":
        found.append(
            f"vendored Foundation pin status is {pins.get('status')!r}, not "
            "'CERTIFIED': E5 has not certified this source"
        )
    digest = pins.get("e5_record_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        found.append("vendored Foundation pin carries no valid e5_record_digest")
        return found
    if found:
        return found
    try:
        raw = record.read_bytes()
        sig = signature.read_bytes()
        signers = allowed_signers.read_bytes()
    except OSError as error:
        return [f"E5 certification material unreadable: {error.filename}"]
    if max(len(raw), len(sig), len(signers)) > _MAX:
        return ["E5 certification material is oversized"]
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        return ["e5_record_digest is not the sha256 of the E5 certification record"]
    try:
        document = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        certifies = document["certifies"]
        same = (
            set(document) == {"schema", "certifies"}
            and document["schema"] == SCHEMA
            and set(certifies) == CERTIFIES_KEYS
            and certifies["source_commit"] == pins["source_commit"]
            and certifies["foundation_src_tree"] == pins["foundation_src_tree"]
            and certifies["files"] == {n: f["sha256"] for n, f in pins["files"].items()}
            and certifies["wheel_only_checks"]
            == {n: f["sha256"] for n, f in pins["wheel_only_checks"].items()}
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return ["the E5 certification record or the pins are malformed"]
    if not same:
        return [
            "the E5 certification record does not certify exactly the pinned source"
        ]
    problem = signers_problem(signers)
    if problem:
        return [problem]
    try:
        with tempfile.TemporaryDirectory(prefix="e5-cert-") as directory:
            signers_path = Path(directory) / "allowed_signers"
            sig_path = Path(directory) / "record.sig"
            signers_path.write_bytes(signers)
            sig_path.write_bytes(sig)
            completed = subprocess.run(  # noqa: S603
                [
                    SSH_KEYGEN,
                    "-Y",
                    "verify",
                    "-f",
                    str(signers_path),
                    "-I",
                    PRINCIPAL,
                    "-n",
                    NAMESPACE,
                    "-s",
                    str(sig_path),
                ],
                input=raw,
                capture_output=True,
                timeout=10,
                check=False,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
    except (OSError, subprocess.TimeoutExpired):
        return ["ssh-keygen is unavailable, so the E5 signature cannot be verified"]
    if completed.returncode != 0:
        return ["the E5 certification record's SSH signature does not verify"]
    return []


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    base = Path(argv[2]) if len(argv) > 2 else DIR
    try:
        pins = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"refused: {path} unreadable: {error}", file=sys.stderr)
        return 2
    reasons = problems(
        pins,
        record=base / RECORD.name,
        signature=base / SIGNATURE.name,
        allowed_signers=base / ALLOWED_SIGNERS.name,
    )
    for reason in reasons:
        print(f"refused: {reason}", file=sys.stderr)
    if not reasons:
        print("vendored Foundation pin is CERTIFIED and its E5 record verifies")
    return 1 if reasons else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
