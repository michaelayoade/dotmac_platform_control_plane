"""Every refusal Platform's local profile dialect can produce, as fixtures.

## Why this exists, and why it is not a test file

Michael redirected the architecture on 2026-09-05: Foundation becomes the single
canonical owner of `ApplicationFoundationProfile.v1` — the concern vocabulary,
contribution validation, canonical encoding and digest, admission rules,
artifact verification. Platform CP supplies DECLARATIONS and no profile
semantics. `vendor_cp.deployment.profile` and
`vendor_cp.deployment.profile_readback` are therefore superseded rather than
adapted: translating between two canonical contracts is compatibility plumbing,
not composition.

Superseded is not the same as wrong, and it is not the same as gone. The
accepted migration sequence is:

1. preserve this implementation's behaviour and NEGATIVE CASES as parity
   fixtures — this module;
2. Foundation lands the canonical contract and a generic verifier;
3. prove the generic path produces AT LEAST these refusals against real artifact
   bytes;
4. replace Platform's acceptance invocation;
5. delete the builder and verifier IN THAT SAME COMPOSED CHANGE;
6. add a ratchet proving the local dialect cannot return.

*"That avoids a temporary state with neither verifier."* Nothing here deletes
anything, and nothing may, until the replacement goes in.

## What a row is

One PLANTED DEFECT and the exact outcome it must produce. A description of a
refusal is not an acceptance bar; an input that triggers it is. Each row plants
exactly ONE thing against an otherwise-valid artifact, because the verifier
checks in a declared precedence order and a fixture broken in two places only
ever demonstrates the earlier one.

`tests/unit/test_profile_refusal_parity.py` drives every row against the local
implementation, so this matrix is checked rather than described — a stale
acceptance bar is worse than none, because the successor is measured against it.

## The escape hatch, and a correction worth recording

The migration brief attributed to this lane a live defect in
`test_this_images_own_absence_proof_is_accepted` — a proof carrying only a
concern name, a revision and free text being ADMITTED. **That is not the state
of the code.** #166 already found and repaired it: that test now passes a proof
that fully establishes, and the shapeless shape is recorded as its own named
refusal in
`test_the_shape_that_used_to_be_admitted_is_the_escape_hatch_and_is_refused`.

The REQUIREMENT stands regardless of the citation, which is why
:data:`SHAPELESS_ESCAPE_HATCH` is a row here: the generic path must refuse a
document whose whole absence proof is a concern name, this revision and a
sentence. It is carried as an active requirement, not as an open defect.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from vendor_cp.deployment.profile import ASSEMBLY, CONCERN_SPECS, ConcernSpec
from vendor_cp.deployment.profile_readback import (
    DISTRIBUTIONS_CONTRACT,
    FOUNDATION_CONCERNS,
    INTEGRATION_ABSENCE_SCHEMA,
    INTEGRATION_SURFACE_FAMILIES,
    PROFILE_CONTRACT,
    ProfileVerdict,
)

__all__ = [
    "BUILDER_CASES",
    "FOUNDATION_ADDED_CASES",
    "FOUNDATION_REFUSAL_CODES",
    "FROZEN_ROW_IDS",
    "RETIRED_ROW_IDS",
    "ROW_IDS",
    "UNMAPPED_ROWS_BLOCKING_DELETION",
    "EXPECTED_REVISION",
    "EXPECTED_WHEEL",
    "OTHER_DIGEST",
    "SHAPELESS_ESCAPE_HATCH",
    "VERIFIER_CASES",
    "Artifact",
    "BuilderCase",
    "Surface",
    "VerifierCase",
    "absent_profile",
    "good_artifact",
    "raw_profile",
    "reseal",
    "row_id",
]

EXPECTED_REVISION: Final = "39ef16af191dda3afee3086aa1bcb9263fd539f0"
EXPECTED_WHEEL: Final = "sha256:" + "a1" * 32
OTHER_DIGEST: Final = "sha256:" + "b2" * 32
SDIST_DIGEST: Final = "sha256:" + "c3" * 32

WHEEL_NAME: Final = "dotmac_vendor_control_plane-0.1.0-py3-none-any.whl"
SDIST_NAME: Final = "dotmac_vendor_control_plane-0.1.0.tar.gz"


class Surface(StrEnum):
    """Which half of the local dialect a row exercises."""

    #: `verify_embedded_profile` — reads an artifact, returns a `ProfileVerdict`.
    VERIFIER = "verifier"
    #: `build_profile_document` — constructs a document, raises on refusal.
    BUILDER = "builder"
    #: A constructor that refuses at the type boundary, before any I/O.
    TYPE_BOUNDARY = "type_boundary"


class _Absent:
    """The profile file is not written at all."""


class _Raw:
    """Exact bytes on disk, so a decode or parse failure can be planted."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload


def absent_profile() -> _Absent:
    return _Absent()


def raw_profile(payload: bytes) -> _Raw:
    return _Raw(payload)


def _canonical(document: dict[str, Any]) -> str:
    """The digest specification, implemented HERE rather than imported.

    A third implementation, and deliberately so: importing the verifier's would
    make every sealed fixture agree with the verifier by construction, and the
    digest rows below would then be unable to fail.
    """
    body = {key: value for key, value in document.items() if key != "profile_digest"}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def reseal(document: dict[str, Any]) -> None:
    """Recompute the document's own digest, as a builder would."""
    document["profile_digest"] = _canonical(document)


def _absence_proof() -> dict[str, Any]:
    """A proof that ESTABLISHES, so a row can break exactly one thing in it."""
    return {
        "schema": INTEGRATION_ABSENCE_SCHEMA,
        "state": "absent_proven",
        "concern": "integration",
        "source_revision": EXPECTED_REVISION,
        "image_digest": EXPECTED_WHEEL,
        "observed_inventory_digest": _inventory_digest(),
        "families": {name: [] for name in sorted(INTEGRATION_SURFACE_FAMILIES)},
        "positive_control": ["dotmac_integration.connectors:paystack"],
    }


#: The shape ruled out on 2026-09-04 — a concern name, a revision and a sentence.
#: Carried as an ACTIVE REQUIREMENT for the successor, not as an open defect
#: here: #166 already refuses it. See this module's docstring.
SHAPELESS_ESCAPE_HATCH: Final[dict[str, Any]] = {
    "concern": "integration",
    "source_revision": EXPECTED_REVISION,
    "statement": "no integration provider is installed",
}


def _inventory_files(wheel: str = EXPECTED_WHEEL) -> list[dict[str, Any]]:
    return [
        {"filename": SDIST_NAME, "size_bytes": 2, "sha256": SDIST_DIGEST},
        {"filename": WHEEL_NAME, "size_bytes": 1, "sha256": wheel},
    ]


def _inventory_digest(wheel: str = EXPECTED_WHEEL) -> str:
    """The inventory-digest specification, implemented here for the same reason
    `_canonical` is: a fixture that imported it could not fail the row that
    plants a mismatch."""
    pairs = sorted(
        (entry["filename"], entry["sha256"]) for entry in _inventory_files(wheel)
    )
    encoded = json.dumps(
        [list(pair) for pair in pairs], separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass
class Artifact:
    """What a row hands the verifier: the two files, and the caller's expectation.

    `profile` is normally a document `dict`; a row may replace it with
    :func:`absent_profile` or :func:`raw_profile` to plant a defect that cannot
    be expressed as a document at all.
    """

    profile: Any
    inventory: dict[str, Any] | None
    expected_revision: str = EXPECTED_REVISION
    expected_wheel: str = EXPECTED_WHEEL

    def write(self, directory: Path) -> dict[str, Path]:
        profile_path = directory / "application_foundation_profile.json"
        if isinstance(self.profile, _Absent):
            pass
        elif isinstance(self.profile, _Raw):
            profile_path.write_bytes(self.profile.payload)
        else:
            profile_path.write_text(
                json.dumps(self.profile, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        distributions_path = directory / "distributions.json"
        if self.inventory is not None:
            distributions_path.write_text(
                json.dumps(self.inventory, indent=2), encoding="utf-8"
            )
        return {
            "profile_path": profile_path,
            "distributions_path": distributions_path,
        }


def good_artifact() -> Artifact:
    """A complete, internally consistent, admissible artifact.

    Thirteen declared bindings and no absence proof: the local dialect's ADMITTED
    state. Every row below is this, with exactly one thing broken.
    """
    document: dict[str, Any] = {
        "contract": PROFILE_CONTRACT,
        "source_revision": EXPECTED_REVISION,
        "wheel_sha256": EXPECTED_WHEEL,
        "concerns": {
            name: {"provider": f"provider.{name}", "version": "1.0"}
            for name in FOUNDATION_CONCERNS
        },
        "absence_proofs": [],
    }
    reseal(document)
    return Artifact(
        profile=document,
        inventory={"contract": DISTRIBUTIONS_CONTRACT, "files": _inventory_files()},
    )


@dataclass(frozen=True, slots=True)
class VerifierCase:
    """One planted defect and the verdict it must produce."""

    case: str
    plant: Callable[[Artifact], None]
    expected: ProfileVerdict
    #: What a successor is being held to, in one sentence. Rendered into the
    #: inventory document, so the two cannot disagree about what a row is for.
    requirement: str


def _with_proof(artifact: Artifact, proof: dict[str, Any]) -> None:
    """Twelve declared bindings and one concern left to an absence proof."""
    document = artifact.profile
    document["concerns"] = {
        name: value
        for name, value in document["concerns"].items()
        if name != "integration"
    }
    document["absence_proofs"] = [proof]
    reseal(document)


def _proof_row(
    case: str, expected: ProfileVerdict, requirement: str, **over: Any
) -> VerifierCase:
    def plant(artifact: Artifact) -> None:
        proof = _absence_proof()
        proof.update(over)
        _with_proof(artifact, proof)

    return VerifierCase(case, plant, expected, requirement)


def _document_row(
    case: str,
    expected: ProfileVerdict,
    requirement: str,
    mutate: Callable[[dict[str, Any]], None],
    *,
    seal: bool = True,
) -> VerifierCase:
    def plant(artifact: Artifact) -> None:
        mutate(artifact.profile)
        if seal:
            reseal(artifact.profile)

    return VerifierCase(case, plant, expected, requirement)


def _inventory_row(
    case: str,
    expected: ProfileVerdict,
    requirement: str,
    mutate: Callable[[Artifact], None],
) -> VerifierCase:
    return VerifierCase(case, mutate, expected, requirement)


def _drop_concern(document: dict[str, Any]) -> None:
    document["concerns"] = {
        name: value
        for name, value in document["concerns"].items()
        if name != FOUNDATION_CONCERNS[-1]
    }


def _empty_binding(document: dict[str, Any]) -> None:
    document["concerns"]["data_governance"] = {}


def _both_declared_and_proven(artifact: Artifact) -> None:
    """A concern declared bound AND proven absent. Two of the four states a
    concern may be in, asserted at once."""
    artifact.profile["absence_proofs"] = [_absence_proof()]
    reseal(artifact.profile)


#: EVERY verdict the verifier can return, each reached by at least one row, and
#: every distinct TRIGGER for a verdict listed separately — a successor that
#: refuses "somewhere in absence-proof validation" is not the same as one that
#: refuses an unregistered family.
VERIFIER_CASES: Final[tuple[VerifierCase, ...]] = (
    # ── the artifact makes no claim, or one that cannot be read ─────────────
    _inventory_row(
        "document_absent",
        ProfileVerdict.DOCUMENT_ABSENT,
        "an artifact carrying no profile document is refused, not admitted by "
        "default",
        lambda artifact: setattr(artifact, "profile", absent_profile()),
    ),
    _inventory_row(
        "document_not_utf8",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "an undecodable document is UNREADABLE, never MISMATCHED: a corrupt "
        "build and an unauthorized artifact have different repairs",
        lambda artifact: setattr(artifact, "profile", raw_profile(b"\xff\xfe\x00")),
    ),
    _inventory_row(
        "document_not_json",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "a truncated or malformed document is unreadable rather than empty",
        lambda artifact: setattr(artifact, "profile", raw_profile(b'{"contract":')),
    ),
    _inventory_row(
        "document_not_an_object",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "valid JSON that is not an object is not a document",
        lambda artifact: setattr(artifact, "profile", ["not", "a", "document"]),
    ),
    # ── the second witness ──────────────────────────────────────────────────
    _inventory_row(
        "second_witness_absent",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "with no independent per-file record, the document's wheel claim has no "
        "second witness — an artifact that describes itself is not evidence "
        "about itself",
        lambda artifact: setattr(artifact, "inventory", None),
    ),
    _inventory_row(
        "second_witness_wrong_contract",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "a distribution record of an unknown contract is unusable, not empty",
        lambda artifact: artifact.inventory.__setitem__("contract", "something/9"),
    ),
    _inventory_row(
        "second_witness_no_files",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "an empty inventory is a truncated capture, and treating it as zero "
        "files would make every digest over it agree",
        lambda artifact: artifact.inventory.__setitem__("files", []),
    ),
    _inventory_row(
        "second_witness_entry_missing_digest",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "ONE malformed entry makes the WHOLE inventory unusable; silently "
        "skipping it produces a digest over the wrong set",
        lambda artifact: artifact.inventory["files"][0].pop("sha256"),
    ),
    _inventory_row(
        "second_witness_two_wheels",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "two wheels means no single second witness, and picking one would be "
        "choosing which witness to believe",
        lambda artifact: artifact.inventory["files"].append(
            {"filename": "other-0.1.0-py3-none-any.whl", "sha256": OTHER_DIGEST}
        ),
    ),
    _inventory_row(
        "second_witness_no_wheel",
        ProfileVerdict.DOCUMENT_UNREADABLE,
        "an inventory naming no wheel cannot witness a wheel claim",
        lambda artifact: artifact.inventory.__setitem__(
            "files", [artifact.inventory["files"][0]]
        ),
    ),
    # ── the document is readable and says the wrong thing ───────────────────
    _document_row(
        "contract_unknown",
        ProfileVerdict.CONTRACT_UNKNOWN,
        "a verifier does not guess at the meaning of a schema it does not know",
        lambda document: document.__setitem__("contract", "some-other-profile/2"),
    ),
    _document_row(
        "profile_digest_absent",
        ProfileVerdict.PROFILE_DIGEST_MISMATCHED,
        "a document with no digest of its own is not self-covering",
        lambda document: document.pop("profile_digest"),
        seal=False,
    ),
    _document_row(
        "profile_digest_stale",
        ProfileVerdict.PROFILE_DIGEST_MISMATCHED,
        "content edited after sealing is detected — this is the whole point of "
        "the digest, and it fails only if producer and verifier encode "
        "independently",
        lambda document: document.__setitem__("source_revision", "f" * 40),
        seal=False,
    ),
    _document_row(
        "revision_mismatch",
        ProfileVerdict.ARTIFACT_COORDINATES_MISMATCHED,
        "a profile describing a different revision is refused even when it is "
        "internally perfect",
        lambda document: document.__setitem__("source_revision", "e" * 40),
    ),
    _document_row(
        "wheel_claim_mismatch",
        ProfileVerdict.WHEEL_DIGEST_MISMATCHED,
        "the document's own wheel claim must equal what the caller expects",
        lambda document: document.__setitem__("wheel_sha256", OTHER_DIGEST),
    ),
    _inventory_row(
        "wheel_carried_mismatch",
        ProfileVerdict.WHEEL_DIGEST_MISMATCHED,
        "the IMAGE's independent record must agree too — a document that is "
        "right about a wheel the image does not carry is still refused",
        lambda artifact: artifact.inventory["files"][1].__setitem__(
            "sha256", OTHER_DIGEST
        ),
    ),
    # ── absence proofs: admissibility ───────────────────────────────────────
    _proof_row(
        "absence_proof_foreign",
        ProfileVerdict.ABSENCE_PROOF_FOREIGN,
        "a well-formed proof produced for ANOTHER artifact says nothing about "
        "this one",
        source_revision="e" * 40,
    ),
    _proof_row(
        "absence_proof_unknown_schema",
        ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
        "an unrecognised proof schema is REFUSED, never ignored — ignoring it "
        "lets a document carry a certification nobody rejected",
        schema="SomeOtherAbsenceProofV1",
    ),
    _proof_row(
        "absence_proof_wrong_concern",
        ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
        "a schema may certify only the concern it is granted; absence is not a "
        "general 'nothing applies' route",
        concern="data_governance",
    ),
    VerifierCase(
        "absence_proof_shapeless_escape_hatch",
        lambda artifact: _with_proof(artifact, dict(SHAPELESS_ESCAPE_HATCH)),
        ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
        "a concern name, a revision and a sentence must NOT satisfy anything. "
        "This shape was admitted before #166 and is the escape hatch the ruling "
        "closed; the successor must refuse it and will not know to unless it is "
        "written down",
    ),
    _inventory_row(
        "absence_proof_and_declared_binding",
        ProfileVerdict.ABSENCE_PROOF_INADMISSIBLE,
        "a concern declared bound AND proven absent has not decided which is "
        "true; accepting either would be the verifier deciding for it",
        _both_declared_and_proven,
    ),
    # ── absence proofs: what ESTABLISHES ────────────────────────────────────
    _proof_row(
        "absence_proof_wrong_state",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "a proof that does not declare the proven-absent state is not making "
        "the claim",
        state="assumed_absent",
    ),
    _proof_row(
        "absence_proof_inventory_digest_mismatch",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "the observed inventory digest must equal one the VERIFIER derives from "
        "the image's own record — this is the half a caller cannot manufacture",
        observed_inventory_digest=OTHER_DIGEST,
    ),
    _proof_row(
        "absence_proof_artifact_digest_mismatch",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "the proof must bind to the artifact being judged",
        image_digest=OTHER_DIGEST,
    ),
    _proof_row(
        "absence_proof_no_family_map",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "no family mapping means nothing was enumerated",
        families="none found",
    ),
    _proof_row(
        "absence_proof_incomplete_enumeration",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "a family never visited is not a family found empty; a subset is the "
        "shape complete enumeration exists to refuse",
        families={
            name: []
            for name in sorted(INTEGRATION_SURFACE_FAMILIES)
            if name != "inbound_webhook"
        },
    ),
    _proof_row(
        "absence_proof_unregistered_family",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "a family outside the closed inventory silently satisfies 'none "
        "present', which is the failure mode absence proofs actually have",
        families={
            **{name: [] for name in sorted(INTEGRATION_SURFACE_FAMILIES)},
            "carrier_pigeon": [],
        },
    ),
    _proof_row(
        "absence_proof_occupied_family",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "a scan that FOUND something means the concern is unbound and needs a "
        "provider, not a proof",
        families={
            **{name: [] for name in sorted(INTEGRATION_SURFACE_FAMILIES)},
            "outbound_connector": ["vendor_cp.relay:dispatch"],
        },
    ),
    _proof_row(
        "absence_proof_no_positive_control",
        ProfileVerdict.ABSENCE_PROOF_UNESTABLISHED,
        "without the instrument shown finding something known to exist, a scan "
        "that never finds anything and an artifact that has nothing are the "
        "same colour",
        positive_control=[],
    ),
    # ── completeness ────────────────────────────────────────────────────────
    _document_row(
        "concerns_incomplete_missing_slot",
        ProfileVerdict.CONCERNS_INCOMPLETE,
        "there is no partial admission, and the refusal NAMES what is missing",
        _drop_concern,
    ),
    _document_row(
        "concerns_incomplete_empty_binding",
        ProfileVerdict.CONCERNS_INCOMPLETE,
        "a placeholder is not an owner — an empty binding does not fill a slot",
        _empty_binding,
    ),
    _document_row(
        "concerns_not_a_mapping",
        ProfileVerdict.CONCERNS_INCOMPLETE,
        "a document whose concerns are not a mapping satisfies none of them",
        lambda document: document.__setitem__("concerns", []),
    ),
    # ── the control ─────────────────────────────────────────────────────────
    _inventory_row(
        "admitted_control",
        ProfileVerdict.ADMITTED,
        "NON-VACUITY. Every row above asserts a refusal, and a verifier that "
        "refused everything would satisfy all of them",
        lambda artifact: None,
    ),
)


@dataclass(frozen=True, slots=True)
class BuilderCase:
    """One planted defect in the BUILD inputs, and the message it must name.

    The builder raises rather than returning a verdict, so a row states a
    required fragment of the refusal. A refusal that names nothing costs a whole
    run to diagnose, which is why the fragment is part of the contract.
    """

    case: str
    #: `(specs, source_revision, lock_text, wheel_names) -> the same, mutated`
    plant: Callable[[_BuildInputs], None]
    fragment: str
    requirement: str


@dataclass
class _BuildInputs:
    """Everything `build_profile_document` is handed, so a row can break one."""

    specs: list[ConcernSpec]
    source_revision: str = EXPECTED_REVISION
    lock_text: str = ""
    wheel_names: list[str] = field(default_factory=lambda: [WHEEL_NAME])
    #: Replace the lock with a synthetic one that omits a named distribution.
    synthetic_lock: str = ""


def _replace_spec(inputs: _BuildInputs, concern: str, **over: Any) -> None:
    inputs.specs = [
        replace(spec, **over) if spec.concern == concern else spec
        for spec in inputs.specs
    ]


#: A lock naming ONE real package and not `dotmac-kernel`. Used to plant a
#: provider the builder can find installed and cannot give a coordinate.
LOCK_WITHOUT_KERNEL: Final = """\
[[package]]
name = "sqlalchemy"
version = "2.0.0"
files = [
    {file = "SQLAlchemy-2.0.0-py3-none-any.whl", hash = "sha256:%s"},
]
""" % ("d4" * 32)

#: A syntactically valid lock with no packages at all.
LOCK_WITH_NO_PACKAGES: Final = 'lock-version = "2.1"\n'


BUILDER_CASES: Final[tuple[BuilderCase, ...]] = (
    BuilderCase(
        "builder_probe_module_missing",
        lambda inputs: _replace_spec(
            inputs, "audit_telemetry", probes=("vendor_cp.no_such_module:anything",)
        ),
        "does not import",
        "a concern whose provider module is gone must fail the BUILD, not ship "
        "a document claiming it",
    ),
    BuilderCase(
        "builder_probe_symbol_missing",
        lambda inputs: _replace_spec(
            inputs,
            "audit_telemetry",
            probes=("dotmac_kernel.audit:write_platform_audit_event_REMOVED",),
        ),
        "has no",
        "a provider that moved is the same failure as one that vanished, and "
        "the refusal must name the symbol",
    ),
    BuilderCase(
        "builder_lock_unreadable",
        lambda inputs: setattr(inputs, "synthetic_lock", "this is not toml ["),
        "missing or unreadable",
        "with no coordinate source, no provider can be given an immutable "
        "coordinate",
    ),
    BuilderCase(
        "builder_lock_has_no_packages",
        lambda inputs: setattr(inputs, "synthetic_lock", LOCK_WITH_NO_PACKAGES),
        "no single-wheel package",
        "an empty coordinate source produces a document with no coordinates and "
        "no complaint — the vacuous pass",
    ),
    BuilderCase(
        "builder_distribution_absent_from_lock",
        lambda inputs: setattr(inputs, "synthetic_lock", LOCK_WITHOUT_KERNEL),
        "no single wheel for it",
        "a provider that is installed but uncoordinated must not be claimed",
    ),
    BuilderCase(
        "builder_lock_version_disagrees_with_installed",
        lambda inputs: setattr(
            inputs,
            "lock_text",
            inputs.lock_text.replace(
                'name = "dotmac-kernel"\nversion = "0.1.0a98"',
                'name = "dotmac-kernel"\nversion = "0.1.0a97"',
            ),
        ),
        "not the one in this image",
        "a lock/image disagreement would hand every binding a hash for some "
        "other build while reporting agreement",
    ),
    BuilderCase(
        "builder_distribution_not_installed",
        lambda inputs: _replace_spec(
            inputs, "audit_telemetry", distributions=("not-a-real-distribution",)
        ),
        "is not installed",
        "a profile naming a provider the image does not carry describes another "
        "image",
    ),
    BuilderCase(
        "builder_revision_is_a_branch_name",
        lambda inputs: setattr(inputs, "source_revision", "main"),
        "peeled",
        "a document built from a branch name describes an artifact the deploy "
        "then rejects, because the deploy already refuses that shape",
    ),
    BuilderCase(
        "builder_revision_is_abbreviated",
        lambda inputs: setattr(inputs, "source_revision", EXPECTED_REVISION[:7]),
        "peeled",
        "an abbreviated commit is not an immutable coordinate",
    ),
    BuilderCase(
        "builder_no_wheel_built",
        lambda inputs: setattr(inputs, "wheel_names", []),
        "exactly one",
        "a profile binds to THE artifact; with none there is nothing to bind to",
    ),
    BuilderCase(
        "builder_two_wheels_built",
        lambda inputs: inputs.wheel_names.append("other-0.1.0-py3-none-any.whl"),
        "exactly one",
        "picking one of several would be choosing which artifact to describe",
    ),
    BuilderCase(
        "builder_concern_specified_twice",
        lambda inputs: inputs.specs.append(inputs.specs[0]),
        "specified twice",
        "two specs for one slot is two answers, and whichever won would be "
        "arbitrary",
    ),
    BuilderCase(
        "builder_slot_has_no_spec",
        lambda inputs: inputs.specs.pop(),
        "no spec covers",
        "a slot with no spec produces a document short by one and silent about " "why",
    ),
    BuilderCase(
        "builder_spec_names_an_unknown_concern",
        lambda inputs: inputs.specs.append(
            ConcernSpec(
                concern="telepathy",
                distributions=(ASSEMBLY,),
                probes=("vendor_cp.identity",),
                consumer="nobody",
            )
        ),
        "not concerns this profile has slots for",
        "the verifier ignores an unknown key, so a document carrying one claims "
        "something nobody reads",
    ),
)


#: Refusals taken at the TYPE BOUNDARY, before any file is read. Listed because
#: a successor that accepted these would be admitting an expectation nobody
#: could have held.
TYPE_BOUNDARY_CASES: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "expected_artifact_without_a_revision",
        "there is nothing to bind to",
        "an expectation with no revision cannot bind a document to an artifact",
    ),
    (
        "expected_artifact_wheel_not_a_digest",
        "must be a `sha256:`-prefixed digest",
        "a wheel expectation that is not a digest cannot be compared with one",
    ),
    (
        "concern_spec_unbound_and_provided",
        "has not decided which it is",
        "a slot cannot be both declared unbound and given a provider",
    ),
    (
        "concern_spec_bound_without_a_probe",
        "at least one probe",
        "a binding with nothing to resolve is bound because a table said so",
    ),
    (
        "concern_spec_bound_without_a_coordinate",
        "needs a coordinate",
        "a version alone can be re-pointed; a binding needs an immutable " "coordinate",
    ),
    (
        "concern_spec_bound_without_a_consumer",
        "runtime consumer",
        "a provider nothing discovers is inert",
    ),
)


def all_case_names() -> tuple[str, ...]:
    """Every row's identifier, for the document that renders this matrix."""
    return (
        tuple(case.case for case in VERIFIER_CASES)
        + tuple(case.case for case in BUILDER_CASES)
        + tuple(name for name, _fragment, _why in TYPE_BOUNDARY_CASES)
    )


def build_inputs(lock_text: str) -> _BuildInputs:
    """Fresh, unbroken build inputs for a row to plant one defect in."""
    return _BuildInputs(specs=list(CONCERN_SPECS), lock_text=lock_text)


def rendered_rows() -> tuple[tuple[str, str, str], ...]:
    """`(case, surface, outcome)` for every row, in document order."""
    rows: list[tuple[str, str, str]] = []
    rows.extend(
        (case.case, str(Surface.VERIFIER), str(case.expected))
        for case in VERIFIER_CASES
    )
    rows.extend(
        (case.case, str(Surface.BUILDER), f"ProfileBuildRefusal: …{case.fragment}…")
        for case in BUILDER_CASES
    )
    rows.extend(
        (name, str(Surface.TYPE_BOUNDARY), f"ValueError: …{fragment}…")
        for name, fragment, _why in TYPE_BOUNDARY_CASES
    )
    return tuple(rows)


#: Sequence protection. This matrix exists to be handed to a successor, and the
#: hard constraint on this lane is that NOTHING comes out until the replacement
#: goes in, in one composed change. Recorded here rather than only in prose so a
#: deletion that skipped a step trips a check that lives beside the fixtures.
MIGRATION_SEQUENCE: Final[tuple[str, ...]] = (
    "preserve behaviour and negative cases as parity fixtures",
    "Foundation lands the canonical contract and generic verifier",
    "prove the generic path produces at least these refusals against real bytes",
    "replace Platform's acceptance invocation",
    "delete the builder and verifier in that same composed change",
    "add a ratchet proving the local dialect cannot return",
)


# ── stable row identity ─────────────────────────────────────────────────────
#
# Foundation's § 11 parity map joins on THESE, not on the descriptive case
# names, and the join is two-directional on both sides. A name is documentation
# and may be improved; an identifier is a contract and may not. So the two are
# separated, and the identifier set is frozen below rather than derived — a
# derived set moves silently when a row moves, which is exactly what a
# two-directional map is supposed to make impossible.
#
# Format: `PCP-<surface>-<ordinal>`. Ordinals are allocated once and never
# reused. A row that is retired moves its identifier into
# :data:`RETIRED_ROW_IDS` and the identifier is spent for good — reusing it
# would silently re-point a foreign reference at a different property, and the
# foreign side is in another repository where nothing would notice.

ROW_IDS: Final[dict[str, str]] = {
    "document_absent": "PCP-V-01",
    "document_not_utf8": "PCP-V-02",
    "document_not_json": "PCP-V-03",
    "document_not_an_object": "PCP-V-04",
    "second_witness_absent": "PCP-V-05",
    "second_witness_wrong_contract": "PCP-V-06",
    "second_witness_no_files": "PCP-V-07",
    "second_witness_entry_missing_digest": "PCP-V-08",
    "second_witness_two_wheels": "PCP-V-09",
    "second_witness_no_wheel": "PCP-V-10",
    "contract_unknown": "PCP-V-11",
    "profile_digest_absent": "PCP-V-12",
    "profile_digest_stale": "PCP-V-13",
    "revision_mismatch": "PCP-V-14",
    "wheel_claim_mismatch": "PCP-V-15",
    "wheel_carried_mismatch": "PCP-V-16",
    "absence_proof_foreign": "PCP-V-17",
    "absence_proof_unknown_schema": "PCP-V-18",
    "absence_proof_wrong_concern": "PCP-V-19",
    "absence_proof_shapeless_escape_hatch": "PCP-V-20",
    "absence_proof_and_declared_binding": "PCP-V-21",
    "absence_proof_wrong_state": "PCP-V-22",
    "absence_proof_inventory_digest_mismatch": "PCP-V-23",
    "absence_proof_artifact_digest_mismatch": "PCP-V-24",
    "absence_proof_no_family_map": "PCP-V-25",
    "absence_proof_incomplete_enumeration": "PCP-V-26",
    "absence_proof_unregistered_family": "PCP-V-27",
    "absence_proof_occupied_family": "PCP-V-28",
    "absence_proof_no_positive_control": "PCP-V-29",
    "concerns_incomplete_missing_slot": "PCP-V-30",
    "concerns_incomplete_empty_binding": "PCP-V-31",
    "concerns_not_a_mapping": "PCP-V-32",
    "admitted_control": "PCP-V-33",
    "builder_probe_module_missing": "PCP-B-01",
    "builder_probe_symbol_missing": "PCP-B-02",
    "builder_lock_unreadable": "PCP-B-03",
    "builder_lock_has_no_packages": "PCP-B-04",
    "builder_distribution_absent_from_lock": "PCP-B-05",
    "builder_lock_version_disagrees_with_installed": "PCP-B-06",
    "builder_distribution_not_installed": "PCP-B-07",
    "builder_revision_is_a_branch_name": "PCP-B-08",
    "builder_revision_is_abbreviated": "PCP-B-09",
    "builder_no_wheel_built": "PCP-B-10",
    "builder_two_wheels_built": "PCP-B-11",
    "builder_concern_specified_twice": "PCP-B-12",
    "builder_slot_has_no_spec": "PCP-B-13",
    "builder_spec_names_an_unknown_concern": "PCP-B-14",
    "expected_artifact_without_a_revision": "PCP-T-01",
    "expected_artifact_wheel_not_a_digest": "PCP-T-02",
    "concern_spec_unbound_and_provided": "PCP-T-03",
    "concern_spec_bound_without_a_probe": "PCP-T-04",
    "concern_spec_bound_without_a_coordinate": "PCP-T-05",
    "concern_spec_bound_without_a_consumer": "PCP-T-06",
}

#: The identifier set, written out rather than computed from `ROW_IDS`. Two
#: independent statements that must agree: a row added to the matrix without a
#: line here fails, and a line here with no row fails. Deriving one from the
#: other would make the check a statement that one dict agrees with itself.
FROZEN_ROW_IDS: Final[tuple[str, ...]] = (
    "PCP-V-01",
    "PCP-V-02",
    "PCP-V-03",
    "PCP-V-04",
    "PCP-V-05",
    "PCP-V-06",
    "PCP-V-07",
    "PCP-V-08",
    "PCP-V-09",
    "PCP-V-10",
    "PCP-V-11",
    "PCP-V-12",
    "PCP-V-13",
    "PCP-V-14",
    "PCP-V-15",
    "PCP-V-16",
    "PCP-V-17",
    "PCP-V-18",
    "PCP-V-19",
    "PCP-V-20",
    "PCP-V-21",
    "PCP-V-22",
    "PCP-V-23",
    "PCP-V-24",
    "PCP-V-25",
    "PCP-V-26",
    "PCP-V-27",
    "PCP-V-28",
    "PCP-V-29",
    "PCP-V-30",
    "PCP-V-31",
    "PCP-V-32",
    "PCP-V-33",
    "PCP-B-01",
    "PCP-B-02",
    "PCP-B-03",
    "PCP-B-04",
    "PCP-B-05",
    "PCP-B-06",
    "PCP-B-07",
    "PCP-B-08",
    "PCP-B-09",
    "PCP-B-10",
    "PCP-B-11",
    "PCP-B-12",
    "PCP-B-13",
    "PCP-B-14",
    "PCP-T-01",
    "PCP-T-02",
    "PCP-T-03",
    "PCP-T-04",
    "PCP-T-05",
    "PCP-T-06",
)

#: Spent identifiers. Empty today — nothing has been retired, and nothing may be
#: until the generic replacement is composed in the same change. A retirement
#: adds the identifier here AND removes its row, in one edit.
RETIRED_ROW_IDS: Final[frozenset[str]] = frozenset()


def row_id(case: str) -> str:
    """The stable identifier Foundation's parity map joins on."""
    return ROW_IDS[case]


#: Rows for which Foundation's contract revision 2 names NO code and states no
#: mechanism. Under Michael's rule an unmapped row BLOCKS deletion of this
#: dialect, so the set is frozen and compared in both directions: closing one
#: requires lowering this tuple in the same change, and a row that quietly
#: became unmapped fails rather than reading as a gap that was always there.
#:
#: All five are about the DOCUMENT rather than about a concern — the artifact
#: carrying no profile at all, three ways of being undecodable, and a document
#: declaring a schema the verifier does not know. `PCP-V-01` is the sharpest:
#: it is the only verdict this programme has ever observed against a real image.
UNMAPPED_ROWS_BLOCKING_DELETION: Final[tuple[str, ...]] = (
    "PCP-V-01",
    "PCP-V-02",
    "PCP-V-03",
    "PCP-V-04",
    "PCP-V-11",
)

#: Foundation's closed refusal vocabulary, as read from contract revision 2 —
#: § 3.3's eleven codes plus the four § 10 introduces. Restated rather than
#: imported because `dotmac-deployment-foundation` is deliberately not a
#: dependency of this assembly and must not become one to satisfy a test. A
#: code in the map that is not here is a typo or an invention, and either would
#: make the map join against nothing.
FOUNDATION_REFUSAL_CODES: Final[frozenset[str]] = frozenset(
    {
        # § 3.3
        "unresolvable",
        "uninjected",
        "contract_mismatch",
        "unexercised",
        "wrong_site",
        "broken_shut",
        "answers_everything",
        "wrong_assembly",
        "foreign_inventory",
        "unknown_key",
        "readback_drift",
        # § 10
        "duplicate",
        "missing",
        "absence_proof.wrong_concern",
    }
)

#: The nine cases Foundation's § 11 step 3 adds. Restated for the same reason.
#:
#: The migration brief handed to this lane listed EIGHT and omitted
#: `answers_everything` — the one refusal revision 2 exists to add, and the dual
#: of `broken_shut`. Recorded here rather than silently corrected, because a
#: count that a two-directional map is built on must not be wrong on either
#: side.
FOUNDATION_ADDED_CASES: Final[tuple[str, ...]] = (
    "uninjected",
    "wrong_site",
    "nonce_only",
    "all_negative",
    "answers_everything",
    "wrong_assembly",
    "foreign_inventory",
    "unknown_key",
    "retirement_round_trip",
)
