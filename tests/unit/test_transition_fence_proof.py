"""`TransitionFenceProof.v1` — the portable wire form of `FenceProof`.

Pure Python throughout — no database, no clock read at test time; every
`fenced_at` is a fixed, hand-constructed `datetime`, which is what makes the
golden canonical-bytes literal and its digest reproducible byte-for-byte.

`from_document` crosses a process boundary as untrusted JSON (PR 2), so this
file's real weight is the refusal matrix: each documented invalid shape
raises `FenceRefused(FenceRefusalCode.PROOF_INVALID)`, proven against a near
miss of the same document that is accepted, so a refusal is never mistaken
for "this whole shape is unsupported".
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from vendor_cp.deployment.transition_fence import (
    FENCE_PROOF_SCHEMA,
    WRITER_ROLES,
    FenceProof,
    FenceRefusalCode,
    FenceRefused,
)

#: The exact literal this file's golden digest was derived from — see the
#: module docstring: `printf '<the literal below>' | shasum -a 256`, never by
#: running the code under test.
_GOLDEN_CANONICAL_BYTES = (
    b'{"absent_roles":["outbox_dispatcher"],"database":"db1",'
    b'"fenced_at":"2026-01-02T03:04:05.678901Z","fenced_roles":["app_user"],'
    b'"member_roles":["app_user_member"],'
    b'"prior_acl":"app_admin=CTc/app_admin",'
    b'"prior_grants":[["","CONNECT",false,"app_admin"],'
    b'["app_user","CONNECT",true,"app_admin"]],'
    b'"schema":"TransitionFenceProof.v1","terminated_count":2}'
)
#: `shasum -a 256` over exactly `_GOLDEN_CANONICAL_BYTES`, computed by hand —
#: not by calling `digest()` and trusting it.
_GOLDEN_DIGEST = (
    "sha256:31356a43177ea8f8202780c309feeed138e821f92fba546b8179f1fcb206d839"
)


def _golden_proof() -> FenceProof:
    return FenceProof(
        database="db1",
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


# ── the golden literal, derived by hand, not by running the code ───────────


def test_canonical_bytes_match_the_hand_derived_golden_literal() -> None:
    assert _golden_proof().canonical_bytes() == _GOLDEN_CANONICAL_BYTES


def test_digest_matches_the_hand_derived_golden_digest() -> None:
    assert _golden_proof().digest() == _GOLDEN_DIGEST


# ── round trip ────────────────────────────────────────────────────────────


def test_round_trip_through_a_document_reproduces_the_identical_proof() -> None:
    proof = _golden_proof()
    assert FenceProof.from_document(proof.to_document()) == proof


def test_round_trip_preserves_a_zero_terminated_count_and_empty_role_tuples() -> None:
    proof = FenceProof(
        database="db2",
        prior_acl="",
        prior_grants=frozenset(),
        fenced_roles=(),
        member_roles=(),
        absent_roles=tuple(WRITER_ROLES),
        terminated_count=0,
        fenced_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    assert FenceProof.from_document(proof.to_document()) == proof


# ── digest stability across key order ───────────────────────────────────


def test_digest_is_stable_across_document_key_insertion_order() -> None:
    """`json.dumps(..., sort_keys=True)` is what makes this true — a document
    built with keys inserted in the OPPOSITE order must still decode to a
    proof with the identical digest."""
    forward = _golden_document()
    reversed_doc = dict(reversed(list(forward.items())))
    assert list(reversed_doc.keys()) != list(forward.keys())
    assert FenceProof.from_document(reversed_doc).digest() == _golden_proof().digest()


def test_digest_is_stable_across_repeated_calls() -> None:
    proof = _golden_proof()
    assert proof.digest() == proof.digest()


# ── from_document refusal matrix: each refusal, with a near miss ───────────


def _mutate(**overrides: Any) -> dict[str, Any]:
    doc = copy.deepcopy(_golden_document())
    doc.update(overrides)
    return doc


def test_the_golden_document_itself_round_trips_without_refusal() -> None:
    """The near miss shared by every refusal test below: the exact valid
    baseline every mutation in this file starts from."""
    FenceProof.from_document(_golden_document())


def test_wrong_schema_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(schema="TransitionFenceProof.v2"))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_the_correct_schema_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(_mutate(schema=FENCE_PROOF_SCHEMA))


def test_an_unknown_key_is_refused() -> None:
    doc = _mutate()
    doc["unexpected"] = "value"
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_missing_key_is_refused() -> None:
    doc = _mutate()
    del doc["absent_roles"]
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(doc)
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_string_database_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(database=123))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_an_empty_database_name_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(database=""))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_empty_database_name_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(_mutate(database="db1"))


def test_prior_grants_not_a_list_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(prior_grants={"not": "a list"}))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_malformed_prior_grants_entry_is_refused() -> None:
    """A 3-element entry — missing the grantor — is the near miss of the
    valid 4-element form."""
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(prior_grants=[["", "CONNECT", False]]))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_bool_is_grantable_value_is_refused() -> None:
    """`is_grantable` (position 2) must itself be a bool; a string there is
    refused as the near miss of the correct bool."""
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(
            _mutate(prior_grants=[["", "CONNECT", "false", "app_admin"]])
        )
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_duplicate_grant_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(
            _mutate(
                prior_grants=[
                    ["", "CONNECT", False, "app_admin"],
                    ["", "CONNECT", False, "app_admin"],
                ]
            )
        )
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_distinct_grants_are_the_near_miss_accepted() -> None:
    FenceProof.from_document(
        _mutate(
            prior_grants=[
                ["", "CONNECT", False, "app_admin"],
                ["app_user", "CONNECT", True, "app_admin"],
            ]
        )
    )


def test_fenced_roles_not_a_subset_of_allowed_writer_roles_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(fenced_roles=["not_a_writer_role"]))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_fenced_roles_within_allowed_writer_roles_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(
        _mutate(fenced_roles=["app_user"]), allowed_writer_roles=WRITER_ROLES
    )


def test_fenced_roles_not_a_list_of_strings_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(fenced_roles=["app_user", 1]))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_member_roles_overlapping_fenced_roles_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(
            _mutate(fenced_roles=["app_user"], member_roles=["app_user"])
        )
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_member_roles_disjoint_from_fenced_roles_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(
        _mutate(fenced_roles=["app_user"], member_roles=["some_other_member"])
    )


def test_terminated_count_as_bool_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(terminated_count=True))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_terminated_count_as_a_plain_int_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(_mutate(terminated_count=1))


def test_terminated_count_as_a_string_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(terminated_count="2"))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_naive_fenced_at_timestamp_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(fenced_at="2026-01-02T03:04:05.678901"))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_utc_fenced_at_timestamp_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(fenced_at="2026-01-02T03:04:05.678901+02:00"))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_z_suffixed_utc_fenced_at_timestamp_is_the_near_miss_accepted() -> None:
    FenceProof.from_document(_mutate(fenced_at="2026-01-02T03:04:05.678901Z"))


def test_an_unparseable_fenced_at_timestamp_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(_mutate(fenced_at="not-a-timestamp"))
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID


def test_a_non_dict_document_is_refused() -> None:
    with pytest.raises(FenceRefused) as refused:
        FenceProof.from_document(["not", "a", "dict"])
    assert refused.value.code == FenceRefusalCode.PROOF_INVALID
