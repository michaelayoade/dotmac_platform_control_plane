"""Closed raw-catalogue comparison proof bindings; parser facts are fixtures."""

from __future__ import annotations

import copy
import hashlib

import pytest

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_catalogue as module

CONTEXT = dict(
    request_digest="sha256:" + "a" * 64,
    host_nonce="b" * 64,
    expected_source_cluster="100",
    expected_source_database="source_db",
)


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def catalogues(changed=True):
    value = {name: [] for name in module.CATALOGUE_QUERIES}
    value["relations"] = [
        ["public", "proof", "r", "app_admin", False, False, None, None]
    ]
    value["constraints"] = [
        [
            "public",
            "proof",
            "ck",
            "CHECK(source)",
            "c",
            True,
            False,
            False,
            False,
            True,
            0,
            "source_expression",
        ]
    ]
    restored = copy.deepcopy(value)
    if changed:
        restored["constraints"][0][3] = "CHECK(restored)"
        restored["constraints"][0][11] = "restored_expression"
    return value, restored


def proof_fixture(source, restored):
    entries = []
    if source["constraints"] != restored["constraints"]:
        entries = [
            dict(
                identity=["public", "proof", "ck"],
                source_row_digest=digest(canonical_json(source["constraints"][0])),
                restored_row_digest=digest(canonical_json(restored["constraints"][0])),
                source_view_definition=" SELECT actual_parser_fixture;",
                restored_view_definition=" SELECT actual_parser_fixture;",
            )
        ]
    return dict(
        schema="dotmac.cp_catalogue_restore_comparison/1",
        request_digest=CONTEXT["request_digest"],
        host_nonce=CONTEXT["host_nonce"],
        source_cluster_system_identifier="100",
        source_database="source_db",
        source_catalogue_digest=digest(canonical_json(source)),
        restored_catalogue_digest=digest(canonical_json(restored)),
        method="postgres16-temp-view-parse/1",
        parser=dict(
            server_version_num=160004,
            cluster_system_identifier="200",
            database="restored_db",
            search_path="pg_catalog",
            standard_conforming_strings="on",
        ),
        checks=entries,
        restored_catalogue_after_digest=digest(canonical_json(restored)),
    )


def verify(source, restored, proof):
    module.verify_restore_comparison(
        canonical_json(proof),
        canonical_json(source),
        canonical_json(restored),
        **CONTEXT,
    )


@pytest.mark.parametrize("changed", [False, True])
def test_closed_proof_preserves_distinct_raw_observations(changed):
    source, restored = catalogues(changed)
    proof = proof_fixture(source, restored)
    verify(source, restored, proof)
    assert (
        proof["source_catalogue_digest"] != proof["restored_catalogue_digest"]
    ) is changed
    assert len(proof["checks"]) == int(changed)


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "host_nonce",
        "source_cluster_system_identifier",
        "source_database",
        "source_catalogue_digest",
        "restored_catalogue_digest",
        "restored_catalogue_after_digest",
    ],
)
def test_proof_refuses_replay_or_replaced_artifact_binding(field):
    source, restored = catalogues()
    proof = proof_fixture(source, restored)
    proof[field] = "sha256:" + "f" * 64 if "digest" in field else "foreign"
    with pytest.raises(ContractError):
        verify(source, restored, proof)


@pytest.mark.parametrize(
    "case",
    [
        "missing-root",
        "extra-root",
        "extra-parser",
        "wrong-method",
        "wrong-version",
        "bool-version",
        "wrong-search-path",
        "wrong-strings",
        "empty-cluster",
        "missing-coverage",
        "duplicate-coverage",
        "unknown-coverage",
        "bad-row-hash",
        "empty-view",
        "different-view",
        "bad-identity",
        "missing-category",
        "extra-category",
        "duplicate-constraint",
    ],
)
def test_proof_closed_shapes_and_exact_changed_check_coverage(case):
    source, restored = catalogues()
    proof = proof_fixture(source, restored)
    if case == "missing-root":
        del proof["checks"]
    elif case == "extra-root":
        proof["unchecked"] = True
    elif case == "extra-parser":
        proof["parser"]["unchecked"] = True
    elif case == "wrong-method":
        proof["method"] = "text-rewrite/1"
    elif case == "wrong-version":
        proof["parser"]["server_version_num"] = 170001
    elif case == "bool-version":
        proof["parser"]["server_version_num"] = True
    elif case == "wrong-search-path":
        proof["parser"]["search_path"] = "public"
    elif case == "wrong-strings":
        proof["parser"]["standard_conforming_strings"] = "off"
    elif case == "empty-cluster":
        proof["parser"]["cluster_system_identifier"] = ""
    elif case == "missing-coverage":
        proof["checks"] = []
    elif case == "duplicate-coverage":
        proof["checks"] *= 2
    elif case == "unknown-coverage":
        proof["checks"][0]["identity"][2] = "other"
    elif case == "bad-row-hash":
        proof["checks"][0]["source_row_digest"] = "sha256:" + "c" * 64
    elif case == "empty-view":
        proof["checks"][0]["source_view_definition"] = " "
    elif case == "different-view":
        proof["checks"][0]["restored_view_definition"] += "changed"
    elif case == "bad-identity":
        proof["checks"][0]["identity"] = ["public"]
    elif case == "missing-category":
        del source["roles"]
    elif case == "extra-category":
        source["unchecked"] = []
    elif case == "duplicate-constraint":
        source["constraints"] *= 2
    if case in {"missing-category", "extra-category", "duplicate-constraint"}:
        proof["source_catalogue_digest"] = digest(canonical_json(source))
    with pytest.raises(ContractError):
        verify(source, restored, proof)


@pytest.mark.parametrize(
    ("index", "value"),
    [
        (4, "f"),
        (5, False),
        (6, True),
        (7, True),
        (8, True),
        (9, False),
        (10, 1),
        (10, True),
        (11, None),
        (11, ""),
    ],
)
def test_changed_check_requires_exact_all_flags_and_real_expression(index, value):
    source, restored = catalogues()
    source["constraints"][0][index] = value
    with pytest.raises(ContractError):
        verify(source, restored, proof_fixture(source, restored))


@pytest.mark.parametrize("case", ["role", "relation-kind", "noncheck", "inventory"])
def test_no_noncheck_metadata_difference_can_use_parse_equivalence(case):
    source, restored = catalogues()
    if case == "role":
        source["roles"] = [["app_admin", "drift"]]
    elif case == "relation-kind":
        source["relations"][0][2] = restored["relations"][0][2] = "p"
    elif case == "noncheck":
        source["constraints"][0][4] = restored["constraints"][0][4] = "u"
    else:
        restored["constraints"][0][2] = "different_constraint"
    with pytest.raises(ContractError):
        verify(source, restored, proof_fixture(source, restored))


@pytest.mark.parametrize(
    ("cluster", "database", "accepted"),
    [
        ("100", "source_db", False),
        ("100", "different_db", True),
        ("200", "source_db", True),
    ],
)
def test_generic_comparison_excludes_exact_source_pair(cluster, database, accepted):
    source, restored = catalogues(False)
    proof = proof_fixture(source, restored)
    proof["parser"].update(cluster_system_identifier=cluster, database=database)
    if accepted:
        verify(source, restored, proof)
    else:
        with pytest.raises(ContractError, match="catalogue_parser_is_source_database"):
            verify(source, restored, proof)
