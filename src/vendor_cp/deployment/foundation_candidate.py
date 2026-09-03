"""The Foundation build this cutover runs on, pinned by its immutable coordinates.

This is a **candidate**, not a release. `published` and `tagged` are both false
and that is correct rather than a gap: publication is step 6 of the bootstrap
sequence, behind Lane 3, and the cutover runs on these candidate bytes. A pin
that required `published` to be true would be pinning something that does not
exist yet and refusing the thing that does.

## Why a pin rather than a presence check

A readiness term that accepts any value an operator typed is the same defect as
a refusal that fires for any reason: it looks like a check and discriminates
nothing. So the Foundation coordinate is compared field by field against what
the authoritative record says, and a wrong digest or a wrong artifact id is
refused by name.

## The oracle

Read from `docs/inventories/foundation-candidate-0.3.0a5.json` on
`michaelayoade/dotmac_starter_mt` at commit
`d096e64c13fe3cd8ab89f4a15edd1ce1bc046e2a`, schema `CandidateArtifact.v1`.
`source_sha` is the immutable commit the bytes were built from and `run_id` /
`artifact_id` identify the run that produced them — immutable coordinates, as a
release-or-registry claim requires. Nothing here is derived from this
repository's own files, because this repository cannot see another repository's
build.

## What is deliberately NOT here

The artifact-ZIP digest. The record does not carry it — only its size — because
it exists in a pull request body and nowhere pinnable. Adding it here would
create a binding to a value nothing can verify. Do not reintroduce it.

## Scope of what is being pinned

The record's `item_scope` states that these bytes carry nine of the eleven items
in the 2026-09-03 a5 audit, plus item 4 which landed earlier. **Item 10 —
executable authorized recovery support — is ABSENT BY DECISION**, and is
visible at this cutover's level as "no authorized restore executor or deadman".
It is held for Michael's ruling on the operations vocabulary, and it is the
reason the readiness packet's rollback term must declare restoration
inexecutable. Pinning these bytes is pinning that scope too.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Final

__all__ = ["FOUNDATION_CANDIDATE", "CandidateCoordinate", "coordinate_fields"]


@dataclass(frozen=True, slots=True)
class CandidateCoordinate:
    """One built artifact, identified by coordinates that cannot be re-pointed."""

    facility: str
    version: str
    source_sha: str
    run_id: str
    artifact_id: str
    wheel_sha256: str
    sdist_sha256: str
    published: bool
    tagged: bool


FOUNDATION_CANDIDATE: Final = CandidateCoordinate(
    facility="dotmac-deployment-foundation",
    version="0.3.0a5",
    source_sha="27bee8fc43919a5ed7f4853ccdedc2f996ad8d86",
    run_id="33780438726",
    artifact_id="9903418260",
    wheel_sha256="17b3464ede04a182958753b493d08c5f06e2b5643960c113ecf6584d4ed56e1b",
    sdist_sha256="df9753e0ab6dddbfbbbaa6f468d3d633fa66088fb3b89d0d9f4cc7c7d969ab18",
    published=False,
    tagged=False,
)


def coordinate_fields() -> tuple[str, ...]:
    """Every field a coordinate must state, in declaration order."""
    return tuple(field.name for field in fields(CandidateCoordinate))
