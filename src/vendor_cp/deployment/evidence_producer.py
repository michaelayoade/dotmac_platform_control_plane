"""Sign what THIS repository's CI ran, and refuse to sign anything else.

The target verifies a signed release-evidence envelope before it will accept a
deployment's provenance. Nothing produced one. This is the producer, and it is
the half that can be built before the signing identity exists: it never touches
key material.

## It is handed a signing function, never a key

`sign_release_evidence` takes `sign: Callable[[bytes], bytes]`. No path, no
pointer, no PEM, and nothing this module could log. The identity lives at
`secret/dotmac/platform-cp/release-evidence-signing/primary` under purpose
`platform_release_evidence`, and whatever resolves it hands this function a
closure. That keeps the module on the right side of ADR-0009 and lets every test
below run against a throwaway key.

## The stringified-document prohibition is inherited, not restated

Foundation's `Effects.release_evidence` was once typed `Mapping[str, str]`, and
a conforming provider dutifully did `str(value)` over a dict — flattening the
very document the signature covers into a Python repr. The type at the seam did
not merely permit that bug, it REQUIRED it: every conforming implementation had
to stringify, so the gate could never pass against a genuine envelope.

`SignedEvidenceEnvelope.document` is now `Mapping[str, Any]` and refuses a
string at construction. This producer therefore CANNOT reintroduce the defect —
not because it is careful, but because the contract it must satisfy makes the
corruption unrepresentable. It emits the document as a nested object and signs
the canonical bytes of that same object. It is the clearest case in this
programme of a lesson encoded rather than documented, and the reason to say so
here is that the next author of a producer will not have read the incident.

## `from_a_fork` is derived from the run, or the evidence is refused

`repository_id != head_repository_id` is the single discriminator between "our
CI ran this" and "someone else's CI ran something and told us about it". This
module will not sign a foreign run, and will not sign at all when the two ids
cannot be read. **A defaulted `false` is a trust claim nobody made** — the same
failure as recording `system` where the truth is that nobody was identified.

## The contract is restated and compared against the authority

`dotmac-deployment-foundation` is deliberately not a dependency of this
assembly, so the schema string, the field set and the canonical form are
restated here rather than imported. `test_the_evidence_contract_matches_the
_installed_foundation` compares them against the installed distribution and
skips loudly, naming the version it saw, wherever the facility is absent — the
same shape as the purpose-constant check the signer seams already carry.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from typing import Any, Final

# The ONE import outside the pure-stdlib set, and it is deliberate. `signers`
# imports only `collections.abc`, `dataclasses`, `enum` and `typing` — it has no
# filesystem, environment, process, network, crypto or secret source — so
# admitting it preserves the allowlist's premise exactly rather than weakening
# it. The alternative was restating the purpose string here, which is the second
# statement that drifts from the thing it describes.
from vendor_cp.deployment.signers import (
    RELEASE_EVIDENCE_PURPOSE,
    ReleaseEvidenceSignerPointer,
)

__all__ = [
    "RELEASE_EVIDENCE_SCHEMA",
    "RUN_FACTS",
    "EvidenceRefusal",
    "EvidenceRefused",
    "canonical_bytes",
    "release_evidence_document",
    "sign_release_evidence",
]

#: Foundation's own schema string, restated. Compared with the installed
#: distribution by the contract test rather than trusted.
RELEASE_EVIDENCE_SCHEMA: Final = "ReleaseEvidence.v1"

#: The run facts the evidence is made of. `schema` is not here: this module
#: supplies it, and a caller that could pass one could name a different
#: contract than the one it is being verified against.
RUN_FACTS: Final[tuple[str, ...]] = (
    "revision",
    "repository",
    "repository_id",
    "head_repository_id",
    "ref",
    "run_id",
    "workflow",
    "conclusion",
)

_REVISION: Final = re.compile(r"^[0-9a-f]{40}$")


class EvidenceRefusal(StrEnum):
    """Why release evidence was not produced, as a value rather than a sentence."""

    #: One or more run facts are absent or blank. The refusal names them.
    MISSING_FACT = "MISSING_FACT"
    #: `revision` is not a full 40-hex commit.
    NOT_A_COMMIT = "NOT_A_COMMIT"
    #: The run came from a fork. This key does not attest other people's runs.
    FOREIGN_RUN = "FOREIGN_RUN"
    #: No key id, so no policy could ever select a key to check the signature.
    UNUSABLE_KEY_ID = "UNUSABLE_KEY_ID"
    #: The signing function returned something that is not a signature.
    UNUSABLE_SIGNATURE = "UNUSABLE_SIGNATURE"
    #: The identity handed to the producer is not a release-evidence signer.
    #: Its own refusal rather than a shared one: being handed the AUTHORIZATION
    #: key with a release-evidence key id and being handed no key id at all are
    #: different mistakes, and a caller cannot tell them apart from one code.
    PURPOSE_MISMATCH = "PURPOSE_MISMATCH"


class EvidenceRefused(ValueError):
    """Release evidence that must not be signed, and why.

    Carries the machine-readable `refusal` and, where the refusal is about
    particular run facts, every fact it is about rather than the first found.
    """

    refusal: EvidenceRefusal
    facts: tuple[str, ...]

    def __init__(
        self,
        refusal: EvidenceRefusal,
        message: str,
        *,
        facts: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.refusal = refusal
        self.facts = tuple(facts)


def release_evidence_document(facts: Mapping[str, str]) -> dict[str, Any]:
    """Build the document, or refuse. Never a partial or defaulted one."""
    absent = [name for name in RUN_FACTS if not str(facts.get(name, "")).strip()]
    if absent:
        raise EvidenceRefused(
            EvidenceRefusal.MISSING_FACT,
            f"the run supplies no {', '.join(absent)}. Evidence assembled "
            "around a missing fact asserts something nobody measured",
            facts=absent,
        )

    values = {name: str(facts[name]).strip() for name in RUN_FACTS}

    revision = values["revision"].lower()
    if not _REVISION.match(revision):
        raise EvidenceRefused(
            EvidenceRefusal.NOT_A_COMMIT,
            f"revision {values['revision']!r} is not a full 40-hex commit, so "
            "it does not identify the bytes this evidence is about",
            facts=["revision"],
        )
    values["revision"] = revision

    # The fork discriminator. Absence is refused ABOVE, as a missing fact,
    # which is what keeps this comparison honest: two blank ids would compare
    # EQUAL and report `from_a_fork == False` -- a confident claim that this was
    # our own run, assembled from two facts nobody supplied.
    #
    # There is deliberately no separate "undetermined" refusal. A blank id is
    # already a missing fact and never reaches here, so a code for it would name
    # a branch that cannot execute -- which is the shape this repository has now
    # removed four times.
    if values["repository_id"] != values["head_repository_id"]:
        raise EvidenceRefused(
            EvidenceRefusal.FOREIGN_RUN,
            f"repository_id {values['repository_id']!r} is not "
            f"head_repository_id {values['head_repository_id']!r}, so this run "
            "came from a fork. Signing it would attest someone else's CI as "
            "ours, which is the distinction the discriminator exists to make",
            facts=["repository_id", "head_repository_id"],
        )

    return {"schema": RELEASE_EVIDENCE_SCHEMA, **values}


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers.

    Sorted keys and tight separators, so the same facts always produce the same
    message. Signing the raw file bytes instead would make an innocent
    re-serialisation look like tampering, and would let two byte strings with
    identical meaning have different standings.
    """
    return json.dumps(dict(document), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def sign_release_evidence(
    facts: Mapping[str, str],
    *,
    signer: ReleaseEvidenceSignerPointer,
    sign: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Produce the on-disk envelope: `{document, signature, key_id}`.

    `document` is the nested object the signature covers and is never
    stringified; `key_id` sits OUTSIDE it, because a document carrying its own
    key id would let a forger nominate the key that verifies it.

    ## Why this takes an identity rather than a key id

    It used to take `key_id: str` beside an unrelated signing callable, so
    nothing structurally prevented the AUTHORIZATION key being handed a
    release-evidence key id: two arguments that had to agree, with no type
    saying so. `ReleaseEvidenceSignerPointer` binds the purpose and the key id
    into one value that has already refused the wrong purpose, which moves that
    check from a review to this call site.

    It does not close the coupling entirely, and says so rather than implying
    otherwise: the pointer cannot carry the signing callable, because a pointer
    able to reach material would be the thing it exists not to be. Pairing the
    callable with the identity is the custody adapter's single job. What changed
    is that it is now ONE job in one place instead of every caller's.
    """
    purpose = getattr(signer, "purpose", None)
    if purpose != RELEASE_EVIDENCE_PURPOSE:
        raise EvidenceRefused(
            EvidenceRefusal.PURPOSE_MISMATCH,
            f"release evidence must be signed by a {RELEASE_EVIDENCE_PURPOSE!r} "
            f"identity; this one declares {purpose!r}",
        )
    key_id = signer.key_id
    if not key_id.strip():
        raise EvidenceRefused(
            EvidenceRefusal.UNUSABLE_KEY_ID,
            "release evidence must name the key that signed it, or no policy "
            "can select one to check it against",
        )

    document = release_evidence_document(facts)
    raw = sign(canonical_bytes(document))
    if not isinstance(raw, bytes) or not raw:
        raise EvidenceRefused(
            EvidenceRefusal.UNUSABLE_SIGNATURE,
            "the signing function returned no signature bytes",
        )

    # Canonical UNPADDED base64url, which is what the verifier's decoder
    # accepts: it refuses padding, surrounding whitespace, and any encoding
    # that does not round-trip to itself.
    signature = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return {
        "document": document,
        "signature": signature,
        "key_id": key_id.strip(),
    }
