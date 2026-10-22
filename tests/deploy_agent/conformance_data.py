"""Fixed public test fixtures, never deployment key material."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deploy_agent import contracts as c


class TestSigner:
    __test__ = False

    def __init__(
        self,
        key_id="test-cp",
        deployment_ref="dotmac_sub/staging/dotmac-sub-staging",
        seed=1,
    ):
        self.key_id, self.deployment_ref = key_id, deployment_ref
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        self.public_key_b64 = c.b64(
            self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def sign(self, payload):
        return self.key.sign(payload)


def desired():
    files = {name: "sha256:" + "c" * 64 for name in c.CONFIG_PATHS}
    doc = {
        "schema": c.DESIRED,
        "product": "dotmac_sub",
        "environment": "staging",
        "host": "dotmac-sub-staging",
        "deployment_ref": "dotmac_sub/staging/dotmac-sub-staging",
        "image_reference": "ghcr.io/michaelayoade/dotmac_sub",
        "image_digest": "sha256:" + "a" * 64,
        "from_image_digest": "sha256:" + "b" * 64,
        "source_revision": "d" * 40,
        "source_tree": "e" * 40,
        "product_manifest_digest": "sha256:" + "f" * 64,
        "build_run_id": 1,
        "evidence_run_id": 2,
        "config_digest": c.digest(files),
        "config_files": files,
        "migration_policy": {"mode": "upgrade_heads", "expected_heads": ["head1"]},
        "plan_digest": "",
        "approvals": [
            {"environment": "staging", "actor": "test-approver", "run_id": 3}
        ],
        "nonce": c.b64(bytes(range(24))),
        "issued_at": "2026-10-21T10:00:00Z",
        "expires_at": "2026-10-21T14:00:00Z",
        "signer_key_id": "test-cp",
    }
    doc["plan_digest"] = c.plan_digest(doc)
    return doc


def applied(doc=None):
    doc = doc or desired()
    return {
        "schema": c.APPLIED,
        "report_id": "00000000-0000-4000-8000-000000000001",
        "deployment_ref": doc["deployment_ref"],
        "host_key_id": "test-host",
        "signer_keyring_generation": 1,
        "desired": {
            key: doc[key]
            for key in (
                "nonce",
                "plan_digest",
                "image_digest",
                "source_revision",
                "config_digest",
            )
        },
        "disposition": "applied",
        "reason": None,
        "observed": {
            "running_image": doc["image_reference"] + "@" + doc["image_digest"],
            "running_revision_label": doc["source_revision"],
            "pinned_image": doc["image_reference"] + "@" + doc["image_digest"],
            "pinned_git_sha": doc["source_revision"],
            "config_files": doc["config_files"],
            "migration_heads": ["head1"],
        },
        "health": {
            "live": {
                "url": "http://127.0.0.1/health",
                "status": 200,
                "checked_at": "2026-10-21T10:01:00Z",
            },
            "ready": {
                "url": "http://127.0.0.1/ready",
                "status": 200,
                "body_status": "ready",
                "checked_at": "2026-10-21T10:01:00Z",
            },
            "background": {
                "celery_inspect_ok": True,
                "containers": {"app": "running"},
                "restart_counts_zero": True,
            },
        },
        "deploy_receipt": {
            "exit_code": 0,
            "receipt_line": "DEPLOY RECEIPT: test fixture",
        },
        "observed_at": "2026-10-21T10:01:00Z",
        "agent": {"version": "test-1", "artifact_digest": "sha256:" + "1" * 64},
    }
