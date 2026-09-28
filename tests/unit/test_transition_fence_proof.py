"""`TransitionFenceProof.v1` — the portable wire form of `FenceProof`.

Pure Python throughout — no database, no clock read at test time; every
`fenced_at` is a fixed, hand-constructed `datetime`, which is what makes the
golden canonical-bytes literal and its digest reproducible byte-for-byte.

`from_document` crosses a process boundary as untrusted JSON (PR 2), so this
file's real weight is the refusal matrix: each documented invalid shape
raises `FenceRefused(FenceRefusalCode.PROOF_INVALID)`, proven against a near
miss of the same document that is accepted, so a refusal is never mistaken
for "this whole shape is unsupported". `expected_digest` is the sharpest
edge of that matrix: a document that is structurally perfect but
semantically laundered (an added grant, an escalated `is_grantable`) passes
every OTHER check here and is caught only by the digest comparison — that is
the property this file's digest-laundering tests exist to prove.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from vendor_cp.deployment.transition_fence import (
    FENCE_PROOF_SCHEMA,
    MIGRATION_ROLE,
    WRITER_ROLES,
    FenceProof,
    FenceRefusalCode,
    FenceRefused,
)

#: The exact literal this FILE's golden digest was derived from — see this
#: docstring above: `printf '<the literal below>' | shasum -a 256`, never by
#: running the code under test.
_GOLDEN_CANONICAL_BYTES = (
    b'{"absent_roles":["outbox_dispatcher"],"database":"db1",'
    b'"fence_id":"fence-1",'
    b'"fenced_at":"2026-01-02T03:04:05.678901Z","fenced_roles":["app_user"],'
    b'"member_roles":["app_user_member"],'
    b'"prior_acl":"app_admin=CTc/app_admin",'
    b'"prior_grants":[["","CONNECT",false,"app_admin"],'
    b'["app_user","CONNECT",true,"app_admin"]],'
    b'"schema":"TransitionFenceProof.v1","terminated_count":2}'
)
#: `shasum -a 256` over exactly `_GOLDEN_CANONICAL_BYTES`, computed by hand —
#: not by calling `digest()` and trusting it. Derivation: `fence_id` sorts
#: between `database` and `fenced_at` (`json.dumps(sort_keys=True)` compares
#: byte-for-byte, and `"fence_id"[5]` is `_` (0x5F) vs `"fenced_at"[5]` `d`
#: (0x64), so `fence_id` < `fenced_at`), and the literal above was hand-typed
#: with it inserted exactly there before hashing:
#: `printf '%s' '<the literal above, minified>' | shasum -a 256`.
_GOLDEN_DIGEST = (
    "sha256:e428fb6f5a872f3e5f19d4b0d277da4b16938ca6e3b074dcd152dffc841df394"
)

#: A digest that matches nothing, used as the `expected_digest` for every
#: refusal test whose refusal fires long before the digest check runs.
_UNUSED_DIGEST = "sha256:" + "0" * 64


def _golden_proof() -> FenceProof:
    return FenceProof(
        database="db1",
        fence_id="fence-1",
        prior_acl="app_admin=CTc/app_admin",
        prior_grants=frozenset(
            {
                ("", "CONNECT", False, "app_admin"),
                ("app_user", "CONNECT", True, "app_admin"),
            }
        ),
        fenced_roles=("app_user",),
        member_roles=("app_user_member",),
        absent_roles=("outbox_dispatcher",),
        terminated_count=2,
        fenced_at=datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC),
    )


def _golden_document() -> dict[str, Any]:
    return _golden_proof().to_document()


def _proof_matching_document(doc: dict[str, Any]) -> FenceProof:
    """Reconstruct the `FenceProof` a (well-formed) document represents,
    purely to compute that document's `expected_digest` for a near-miss test
    — via the already golden-tested `digest()`, never via `from_document`
    itself, which is what every test in this file is exercising."""
    return FenceProof(
        database=doc["database"],
        fence_id=doc["fence_id"],
        prior_acl=doc["prior_acl"],
        prior_grants=frozenset(tuple(g) for g in doc["prior_grants"]),
        fenced_roles=tuple(doc["fenced_roles"]),
        member_roles=tuple(doc["member_roles"]),
        absent_roles=tuple(doc["absent_roles"]),
        terminated_count=doc["terminated_count"],
        fenced_at=datetime.fromisoformat(doc["fenced_at"].replace("Z", "+00:00")),
    )


def _digest_for(doc: dict[str, Any]) -> str:
    return _proof_matching_document(doc).digest()


# ── the golden literal, derived by hand, not by running the code ───────────


def test_canonical_bytes_match_the_hand_derived_golden_literal() -> None:
    assert _golden_proof().canonical_bytes() == _GOLDEN_CANONICAL_BYTES


def test_digest_matches_the_hand_derived_golden_digest() -> None:
    assert _golden_proof().digest() == _GOLDEN_DIGEST


# ── round trip ────────────────────────────────────────────────────────────


def test_round_trip_through_a_document_reproduces_the_identical_proof() -> None:
    proof = _golden_proof()
    assert (
        FenceProof.from_document(proof.to_document(), expected_digest=proof.digest())
        == proof
    )


def test_round_trip_preserves_a_zero_terminated_count_and_empty_role_tuples() -> None:
    proof = FenceProof(
        database="db2",
        fence_id="fence-2",
        prior_acl="",
        prior_grants=frozenset(),
        fenced_roles=(),
        member_roles=(),
        absent_roles=tuple(WRITER_ROLES),
        terminated_count=0,
        fenced_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    assert (
        FenceProof.from_document(proof.to_document(), expected_digest=proof.digest())
        == proof
    )


# ── digest stability across key order ───────────────────────────────────


def test_digest_is_stable_across_document_key_insertion_order() -> None:
    """`json.dumps(..., sort_keys=True)` is what makes this true — a document
    built with keys inserted in the OPPOSITE order must still decode to a
    proof with the identical digest."""
    forward = _golden_document()
    reversed_doc = dict(reversed(list(forward.items())))
    assert list(reversed_doc.keys()) != list(forward.keys())
    assert (
        FenceProof.from_document(
            reversed_doc, expected_digest=_golden_proof().digest()
        ).digest()
        == _golden_proof().digest()
    )


def test_digest_is_stable_across_repeated_calls() -> None:
    proof = _golden_proof()
    assert proof.digest() == proof.digest()


# ── expected_digest: the actual defence against a laundered grant ──────────


def test_a_wrong_expected_digest_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_golden_document(), expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_the_correct_expected_digest_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(
        _golden_document(), expected_digest=_golden_proof().digest()
    )


def test_an_added_public_grant_passes_every_structural_check_but_fails_the_digest() -> (
    None
):
    """The whole point of `expected_digest`: this document is well-typed,
    every privilege is known, there is no duplicate, no unsafe identifier —
    every OTHER check in `from_document` passes it. Only the digest, computed
    against the digest of the proof BEFORE this grant was added, catches
    it."""
    doc = _golden_document()
    doc["prior_grants"] = sorted(
        [*doc["prior_grants"], ["", "TEMPORARY", False, "app_admin"]]
    )
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_golden_proof().digest())
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_escalated_is_grantable_passes_structural_checks_but_fails_the_digest() -> (
    None
):
    doc = _golden_document()
    doc["prior_grants"] = sorted(
        [
            ["", "CONNECT", True, "app_admin"],  # was False in the golden proof
            ["app_user", "CONNECT", True, "app_admin"],
        ]
    )
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_golden_proof().digest())
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


# ── from_document refusal matrix: each refusal, with a near miss ───────────


def _mutate(**overrides: Any) -> dict[str, Any]:
    doc = copy.deepcopy(_golden_document())
    doc.update(overrides)
    return doc


def test_the_golden_document_itself_round_trips_without_refusal() -> None:
    """The near miss shared by every refusal test below: the exact valid
    baseline every mutation in this file starts from."""
    FenceProof.from_document(
        _golden_document(), expected_digest=_golden_proof().digest()
    )


def test_wrong_schema_is_refused() -> None:
    """`_digest_for(doc)` — not `_UNUSED_DIGEST` — because `_proof_matching_
    document` builds a proof straight from the doc's OTHER fields regardless
    of `schema`, so this digest is exactly what `from_document` would accept
    if the schema check were deleted: only the schema check itself, not a
    trailing digest mismatch, is what makes this test raise."""
    doc = _mutate(schema="TransitionFenceProof.v2")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "schema" in str(refused.value)


def test_the_correct_schema_is_the_near_miss_accepted() -> None:
    doc = _mutate(schema=FENCE_PROOF_SCHEMA)
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_an_unknown_key_is_refused() -> None:
    """`_digest_for(doc)`: `_proof_matching_document` ignores the extra key
    entirely and builds the identical proof the other fields describe, so a
    deleted unknown-key check would otherwise be masked by a digest
    mismatch alone."""
    doc = _mutate()
    doc["unexpected"] = "value"
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "unknown keys" in str(refused.value)


def test_a_missing_key_is_refused() -> None:
    """No matching digest is possible here — `_proof_matching_document`
    itself needs `absent_roles` and would raise `KeyError`, not silently
    build a plausible near-miss proof. The message substring is what proves
    the MISSING-KEY check specifically fired, not a generic invalid-shape
    catch-all."""
    doc = _mutate()
    del doc["absent_roles"]
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "missing keys" in str(refused.value)
    assert "absent_roles" in str(refused.value)


def test_a_non_string_database_is_refused() -> None:
    doc = _mutate(database=123)
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_empty_database_name_is_refused() -> None:
    doc = _mutate(database="")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "database" in str(refused.value) and "empty" in str(refused.value)


def test_a_database_name_with_a_nul_byte_is_refused() -> None:
    doc = _mutate(database="db\x001")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_database_name_with_a_lone_surrogate_is_refused() -> None:
    doc = _mutate(database="db\ud800")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_empty_database_name_is_the_near_miss_accepted() -> None:
    doc = _mutate(database="db1")
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


# ── fence_id: the run binding, refused with the same discipline as database


def test_a_missing_fence_id_key_is_refused() -> None:
    doc = _mutate()
    del doc["fence_id"]
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_string_fence_id_is_refused() -> None:
    doc = _mutate(fence_id=123)
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_empty_fence_id_is_refused() -> None:
    doc = _mutate(fence_id="")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "fence_id is an empty string" in str(refused.value)


def test_a_fence_id_with_a_nul_byte_is_refused() -> None:
    doc = _mutate(fence_id="fence\x001")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_fence_id_with_a_lone_surrogate_is_refused() -> None:
    doc = _mutate(fence_id="fence\ud800")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_fence_id_with_leading_whitespace_is_refused() -> None:
    doc = _mutate(fence_id=" fence-1")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "whitespace" in str(refused.value)


def test_a_fence_id_with_trailing_whitespace_is_refused() -> None:
    doc = _mutate(fence_id="fence-1 ")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "whitespace" in str(refused.value)


def test_an_overlong_fence_id_is_refused() -> None:
    doc = _mutate(fence_id="f" * 129)
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "129 characters" in str(refused.value)


def test_a_128_character_fence_id_is_the_near_miss_accepted() -> None:
    """128 characters exactly is the boundary this module accepts; 129 (the
    test above) is refused."""
    doc = _mutate(fence_id="f" * 128)
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_prior_grants_not_a_list_is_refused() -> None:
    doc = _mutate(prior_grants={"not": "a list"})
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_malformed_prior_grants_entry_is_refused() -> None:
    """A 3-element entry — missing the grantor — is the near miss of the
    valid 4-element form."""
    doc = _mutate(prior_grants=[["", "CONNECT", False]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_bool_is_grantable_value_is_refused() -> None:
    """`is_grantable` (position 2) must itself be a bool; a string there is
    refused as the near miss of the correct bool."""
    doc = _mutate(prior_grants=[["", "CONNECT", "false", "app_admin"]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_duplicate_grant_is_refused() -> None:
    """`_digest_for(doc)`: `_proof_matching_document` builds `prior_grants`
    as a `frozenset`, which silently DEDUPES the two identical entries — so
    the digest computed from it is exactly what `from_document` would
    accept if the duplicate check were deleted (the constructed proof
    itself can never distinguish "one entry" from "the same entry listed
    twice"). Only the duplicate check itself, not a trailing digest
    mismatch, is what makes this test raise."""
    doc = _mutate(
        prior_grants=[
            ["", "CONNECT", False, "app_admin"],
            ["", "CONNECT", False, "app_admin"],
        ]
    )
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "duplicate grant" in str(refused.value)


def test_distinct_grants_are_the_near_miss_accepted() -> None:
    doc = _mutate(
        prior_grants=[
            ["", "CONNECT", False, "app_admin"],
            ["app_user", "CONNECT", True, "app_admin"],
        ]
    )
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_an_unknown_privilege_in_prior_grants_is_refused() -> None:
    doc = _mutate(prior_grants=[["", "DROP", False, "app_admin"]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "DROP" in str(refused.value)


def test_a_known_privilege_in_prior_grants_is_the_near_miss_accepted() -> None:
    doc = _mutate(prior_grants=[["", "CREATE", False, "app_admin"]])
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_a_prior_grants_grantee_with_a_nul_byte_is_refused() -> None:
    doc = _mutate(prior_grants=[["ro\x00le", "CONNECT", False, "app_admin"]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_empty_prior_grants_grantee_is_the_near_miss_accepted_as_public() -> None:
    doc = _mutate(prior_grants=[["", "CONNECT", False, "app_admin"]])
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_an_empty_prior_grants_grantor_is_refused() -> None:
    doc = _mutate(prior_grants=[["", "CONNECT", False, ""]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "empty string" in str(refused.value)


def test_a_grantable_public_grant_in_prior_grants_is_refused() -> None:
    """PostgreSQL never allows a grant option to PUBLIC — `is_grantable=True`
    on a PUBLIC (empty-grantee) entry cannot have come from a real
    `aclexplode` read, so it is refused as `PROOF_INVALID` rather than
    treated as merely another shape the digest alone would catch. The near
    miss is `test_an_empty_prior_grants_grantee_is_the_near_miss_accepted_as_public`
    just above: the identical PUBLIC grantee with `is_grantable=False` is
    accepted. `_digest_for(doc)`, not `_UNUSED_DIGEST`: `_proof_matching_
    document` builds this exact (illegal) proof with no validation, so this
    is what `from_document` would accept if the PUBLIC-grant-option check
    were deleted."""
    doc = _mutate(prior_grants=[["", "CONNECT", True, "app_admin"]])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "grant option to PUBLIC" in str(refused.value)


def test_fenced_roles_not_a_subset_of_allowed_writer_roles_is_refused() -> None:
    doc = _mutate(fenced_roles=["not_a_writer_role"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "not a subset" in str(refused.value)


def test_fenced_roles_within_allowed_writer_roles_is_the_near_miss_accepted() -> None:
    doc = _mutate(fenced_roles=["app_user"])
    FenceProof.from_document(
        doc, expected_digest=_digest_for(doc), allowed_writer_roles=WRITER_ROLES
    )


def test_fenced_roles_not_a_list_of_strings_is_refused() -> None:
    doc = _mutate(fenced_roles=["app_user", 1])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_duplicate_within_fenced_roles_is_refused() -> None:
    """`_digest_for(doc)`: `_proof_matching_document` stores `fenced_roles`
    via `tuple(doc[key])`, which preserves the duplicate unlike the
    `prior_grants` frozenset above — but the CHECK under test here is the
    `len(value) != len(set(value))` one, which fires before `from_document`
    ever constructs a proof, so `_UNUSED_DIGEST` really would mask a deleted
    check (the mutated doc, being otherwise well-formed, would decode and
    then fail only the trailing digest compare). Using the matching digest
    is what proves THIS check, not the digest compare, is what raises."""
    doc = _mutate(fenced_roles=["app_user", "app_user"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "duplicate role" in str(refused.value)


def test_a_duplicate_within_member_roles_is_refused() -> None:
    doc = _mutate(member_roles=["app_user_member", "app_user_member"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "duplicate role" in str(refused.value)


def test_a_duplicate_within_absent_roles_is_refused() -> None:
    doc = _mutate(absent_roles=["outbox_dispatcher", "outbox_dispatcher"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "duplicate role" in str(refused.value)


def test_distinct_absent_roles_are_the_near_miss_accepted() -> None:
    doc = _mutate(absent_roles=["outbox_dispatcher", "platform_outbox_dispatcher"])
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_a_role_name_with_a_lone_surrogate_is_refused() -> None:
    doc = _mutate(fenced_roles=["app_us\ud800er"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_role_name_with_a_nul_byte_is_refused() -> None:
    doc = _mutate(member_roles=["app_user\x00member"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_empty_role_name_is_refused() -> None:
    doc = _mutate(absent_roles=["outbox_dispatcher", ""])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_member_roles_overlapping_fenced_roles_is_refused() -> None:
    doc = _mutate(fenced_roles=["app_user"], member_roles=["app_user"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "overlaps" in str(refused.value)


def test_member_roles_disjoint_from_fenced_roles_is_the_near_miss_accepted() -> None:
    doc = _mutate(fenced_roles=["app_user"], member_roles=["some_other_member"])
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_member_roles_naming_the_migration_role_is_refused() -> None:
    """An "unconstrained" `member_roles` entry: `MIGRATION_ROLE` can never
    legitimately be a member of a fenced writer (it would already have been
    refused as `SHARED_WRITER_ROLE` at fence time), so a document naming it
    there did not come from a real fence."""
    doc = _mutate(member_roles=[MIGRATION_ROLE])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert MIGRATION_ROLE in str(refused.value)


def test_absent_roles_overlapping_fenced_roles_is_refused() -> None:
    doc = _mutate(fenced_roles=["app_user"], absent_roles=["app_user"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "overlaps" in str(refused.value)


def test_absent_roles_overlapping_member_roles_is_refused() -> None:
    doc = _mutate(member_roles=["app_user_member"], absent_roles=["app_user_member"])
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "overlaps" in str(refused.value)


def test_absent_roles_disjoint_from_fenced_and_member_is_the_near_miss_accepted() -> (
    None
):
    doc = _mutate(absent_roles=["platform_outbox_dispatcher"])
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_terminated_count_as_bool_is_refused() -> None:
    doc = _mutate(terminated_count=True)
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_terminated_count_as_a_plain_int_is_the_near_miss_accepted() -> None:
    doc = _mutate(terminated_count=1)
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_terminated_count_as_a_string_is_refused() -> None:
    doc = _mutate(terminated_count="2")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_negative_terminated_count_is_refused() -> None:
    doc = _mutate(terminated_count=-1)
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "must not be negative" in str(refused.value)


def test_a_zero_terminated_count_is_the_near_miss_accepted() -> None:
    doc = _mutate(terminated_count=0)
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


# ── fenced_at: exact canonical round trip, not merely "parses to UTC" ──────


def test_the_canonical_z_suffixed_fenced_at_is_the_near_miss_accepted() -> None:
    doc = _mutate(fenced_at="2026-01-02T03:04:05.678901Z")
    FenceProof.from_document(doc, expected_digest=_digest_for(doc))


def test_a_naive_fenced_at_timestamp_is_refused() -> None:
    """No matching digest here: `_proof_matching_document` would parse this
    into a NAIVE `datetime`, and `datetime.astimezone()` on a naive value
    assumes the SYSTEM's local timezone — not a portable, reproducible
    digest to assert against across machines. The message substring proves
    the naive-timestamp check specifically fired."""
    doc = _mutate(fenced_at="2026-01-02T03:04:05.678901")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "naive" in str(refused.value)


def test_a_non_utc_fenced_at_timestamp_is_refused() -> None:
    doc = _mutate(fenced_at="2026-01-02T03:04:05.678901+02:00")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "canonical UTC form" in str(refused.value)


def test_a_plus_zero_offset_fenced_at_timestamp_is_refused() -> None:
    """Same UTC instant as the canonical form, spelled `+00:00` instead of
    `Z` — parses fine, but is not the exact byte form `to_document()` ever
    writes, so the canonical round trip refuses it."""
    doc = _mutate(fenced_at="2026-01-02T03:04:05.678901+00:00")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "canonical UTC form" in str(refused.value)


def test_a_minus_zero_offset_fenced_at_timestamp_is_refused() -> None:
    doc = _mutate(fenced_at="2026-01-02T03:04:05.678901-00:00")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_digest_for(doc))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
    assert "canonical UTC form" in str(refused.value)


def test_a_fenced_at_missing_microseconds_is_refused() -> None:
    doc = _mutate(fenced_at="2026-01-02T03:04:05Z")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_unparseable_fenced_at_timestamp_is_refused() -> None:
    doc = _mutate(fenced_at="not-a-timestamp")
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc, expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_dict_document_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(["not", "a", "dict"], expected_digest=_UNUSED_DIGEST)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
