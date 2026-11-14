"""Release-evidence trust policy and verifier for the target (E6, scope (c)).

Foundation's `VERIFY_RELEASE_EVIDENCE` step is always planned and refuses unless
the bindings carry an `evidence_policy` (`TrustPolicy`) and an
`evidence_verifier` (`SignatureVerifier`). This module supplies both from what
the custody ceremony installs on the host and nothing it could default:

* the verifier is Ed25519 over the pinned `platform_release_evidence` PUBLIC
  identity (`verification_identities`);
* the policy accepts exactly that identity's key id, exactly the declared
  repository, and the protected refs Foundation's `TrustPolicy` defaults to
  (the host cannot widen them from configuration).

Fail closed, with typed refusals naming what is missing: no identity file, no
declared repository, an identity that does not load. There is no permissive
default, and an unset input is never replaced by a value read from the evidence
being judged.

Environment names (values are deployment facts and are never echoed):

* `RELEASE_EVIDENCE_VERIFICATION_IDENTITY` - path of the installed identity;
* `RELEASE_EVIDENCE_REPOSITORY` - `owner/name` the evidence must come from.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from vendor_cp.deployment.signers import RELEASE_EVIDENCE_PURPOSE
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)
from vendor_cp.deployment.verification_identities import (
    PinnedVerificationIdentity,
    ReleaseEvidenceEd25519Verifier,
)

__all__ = [
    "RELEASE_EVIDENCE_IDENTITY_ENV",
    "RELEASE_EVIDENCE_REPOSITORY_ENV",
    "release_evidence_trust",
]

RELEASE_EVIDENCE_IDENTITY_ENV: Final = "RELEASE_EVIDENCE_VERIFICATION_IDENTITY"
RELEASE_EVIDENCE_REPOSITORY_ENV: Final = "RELEASE_EVIDENCE_REPOSITORY"

_REPOSITORY: Final = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")


def release_evidence_trust(
    env: Mapping[str, str], *, owner_uid: int = 0
) -> tuple[Any, ReleaseEvidenceEd25519Verifier]:
    """`(TrustPolicy, verifier)` for the installed release-evidence identity."""
    missing = [
        name
        for name in (RELEASE_EVIDENCE_IDENTITY_ENV, RELEASE_EVIDENCE_REPOSITORY_ENV)
        if not env.get(name, "").strip()
    ]
    if missing:
        raise FoundationBindingsUnavailable(
            "release-evidence trust policy cannot be composed; missing: "
            + "; ".join(missing),
            code=TargetRefusal.EVIDENCE_POLICY_INCOMPLETE,
        )
    repository = env[RELEASE_EVIDENCE_REPOSITORY_ENV].strip()
    if not _REPOSITORY.match(repository):
        raise FoundationBindingsUnavailable(
            f"{RELEASE_EVIDENCE_REPOSITORY_ENV} is not an owner/name repository",
            code=TargetRefusal.EVIDENCE_POLICY_INCOMPLETE,
        )
    identity = PinnedVerificationIdentity.read(
        env[RELEASE_EVIDENCE_IDENTITY_ENV].strip(),
        purpose=RELEASE_EVIDENCE_PURPOSE,
        what="release-evidence verification identity "
        f"({RELEASE_EVIDENCE_IDENTITY_ENV})",
        owner_uid=owner_uid,
    )
    try:
        from dotmac_deployment_foundation import TrustPolicy
    except ImportError:
        raise FoundationBindingsUnavailable(
            "dotmac-deployment-foundation is not installed in this environment; "
            "release-evidence trust cannot be composed",
            code=TargetRefusal.FOUNDATION_MISSING,
        ) from None
    return (
        TrustPolicy(
            accepted_key_ids=frozenset({identity.key_id}),
            repository=repository,
        ),
        ReleaseEvidenceEd25519Verifier(identity),
    )
