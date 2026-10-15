"""Hosted test-only SSH/library adapter; never included in the CP wheel.

This exercises real sshd authentication and installed library proof exchange.
It deliberately does not qualify installed bootstrap/custody or select the
production CLI entrypoint, whose finite-custody requirements remain intact.
"""

import base64
import fcntl
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://x:x@127.0.0.1/gate0_synthetic"
)
os.environ.setdefault(
    "PLATFORM_DATABASE_URL", "postgresql+psycopg://x:x@127.0.0.1/gate0_synthetic"
)

from vendor_cp.deployment import gate0_services  # noqa: E402
from vendor_cp.deployment.gate0_composition import AdmissionExpectation  # noqa: E402
from vendor_cp.deployment.gate0_framing import FramedChannel  # noqa: E402
from vendor_cp.deployment.gate0_runtime import AdmittedOperation  # noqa: E402
from vendor_cp.deployment.gate0_session import (  # noqa: E402
    AttesterSession,
    SshdSessionReader,
)
from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,  # noqa: E402
)


def run_session(config):
    # One fixture-local original bound, never a new production clock/capability.
    started_at, origin = datetime.now(UTC), monotonic()
    expires_at = datetime.fromisoformat(config["expires_at"])
    remaining = (expires_at - started_at).total_seconds()
    if not 0 < remaining <= 300:
        raise ValueError("synthetic_startup_refused")
    deadline = origin + min(remaining, 30)
    operation = AdmittedOperation(**config["operation"])
    expected = AdmissionExpectation(
        operation, UUID(int=2), "rehearsal", UUID(int=3), "synthetic-policy", 1
    )
    private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(config["attester_seed"])
    )
    public = base64.b64decode(config["attester_public"])
    trust = RehearsalIssuerTrustState.start(
        minimum_version=1, read_record=lambda: config["trust"]
    )

    class SyntheticAdmission:
        def admit(self, token, phase, plan_id, authorization_document=None):
            if (
                token != "synthetic-job"  # noqa: S105 -- synthetic workload fixture only
                or phase != operation.phase
                or plan_id != UUID(operation.plan_id)
                or authorization_document is not None
            ):
                raise ValueError("synthetic_admission_refused")
            return expected

        def window_record_digest(self, value):
            if value != expected:
                raise ValueError("synthetic_admission_refused")
            return config["record_digest"]

    session = AttesterSession(
        SyntheticAdmission(),
        base64.b64decode(config["ca_public"]),
        "synthetic-attester",
        public,
        trust,
        private.sign,
        expires_at,
    )
    directory = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY)  # noqa: S108 -- real daemon fixture mount
    try:
        # Explicit synthetic library composition, not a production override.
        # Real sshd ExposeAuthInfo and all cryptographic checks remain active.
        channel = FramedChannel(
            sys.stdin.fileno(),
            sys.stdout.fileno(),
            deadline=deadline,
            maximum_frames=3,
        )
        gate0_services.serve_attester(
            session,
            SshdSessionReader(directory, os.geteuid()),
            channel,
            os.environ,
        )
        return 0
    finally:
        os.close(directory)


def main():
    # Synthetic fixture supervisor admission; never installed in the CP wheel.
    # Root owns the fixed ForceCommand, parent directory, config and lock.
    path = Path(sys.argv[1])
    lock_fd = None
    descriptor = None
    try:
        parent = path.parent.stat()
        if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
            raise ValueError("synthetic_startup_refused")
        lock_fd = os.open(path.with_suffix(".lock"), os.O_RDONLY | os.O_NOFOLLOW)
        lock = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock.st_mode)
            or lock.st_uid != 0
            or stat.S_IMODE(lock.st_mode) != 0o444
            or lock.st_nlink != 1
        ):
            raise ValueError("synthetic_startup_refused")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != os.getegid()
            or stat.S_IMODE(before.st_mode) != 0o440
            or before.st_nlink != 1
            or not 0 < before.st_size <= 65536
        ):
            raise ValueError("synthetic_startup_refused")
        raw = os.read(descriptor, 65537)
        after = os.fstat(descriptor)
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            any(getattr(before, key) != getattr(after, key) for key in fields)
            or len(raw) != before.st_size
        ):
            raise ValueError("synthetic_startup_refused")
        return run_session(json.loads(raw))
    except gate0_services.ServiceCancelled:
        return 5
    except Exception:
        return 3
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if lock_fd is not None:
            os.close(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
