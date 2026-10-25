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
        schema="dotmac.cp_catalogue_restore_comparison/2",
        request_digest=CONTEXT["request_digest"],
        host_nonce=CONTEXT["host_nonce"],
        source_cluster_system_identifier="100",
        source_database="source_db",
        source_catalogue_digest=digest(canonical_json(source)),
        restored_catalogue_digest=digest(canonical_json(restored)),
        method="postgres16-check-parse-table-acldefault/2",
        parser=dict(
            server_version_num=160004,
            cluster_system_identifier="200",
            database="restored_db",
            search_path="pg_catalog",
            standard_conforming_strings="on",
        ),
        checks=entries,
        relation_acls=[],
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


DEFAULT_ACL = "{app_admin=arwdDxt/app_admin}"


def acl_pair(reverse=False):
    source, restored = catalogues(False)
    source["relations"][0][6] = DEFAULT_ACL
    if reverse:
        source, restored = restored, source
    proof = proof_fixture(source, restored)
    proof["relation_acls"] = [
        dict(
            identity=["public", "proof"],
            source_row_digest=digest(canonical_json(source["relations"][0])),
            restored_row_digest=digest(canonical_json(restored["relations"][0])),
            server_default_acl=DEFAULT_ACL,
        )
    ]
    return source, restored, proof


@pytest.mark.parametrize("reverse", [False, True])
def test_explicit_server_default_and_null_keep_distinct_raw_digests(reverse):
    source, restored, proof = acl_pair(reverse)
    verify(source, restored, proof)
    assert proof["source_catalogue_digest"] != proof["restored_catalogue_digest"]


@pytest.mark.parametrize(
    "explicit",
    [
        "",
        "{}",
        "{app_admin=arwdDx/app_admin}",
        "{app_admin=arwdDxt/app_admin,other=r/app_admin}",
        "{app_admin=arwdDxt/other}",
        "{app_admin=arwdDxt*/app_admin}",
    ],
)
def test_acl_text_must_exactly_match_server_default(explicit):
    source, restored, proof = acl_pair()
    source["relations"][0][6] = explicit
    proof["source_catalogue_digest"] = digest(canonical_json(source))
    proof["relation_acls"][0]["source_row_digest"] = digest(
        canonical_json(source["relations"][0])
    )
    with pytest.raises(ContractError):
        verify(source, restored, proof)


@pytest.mark.parametrize(
    "case",
    [
        "owner",
        "kind",
        "rls",
        "options",
        "inventory",
        "duplicate-relation",
        "both-explicit",
        "missing",
        "duplicate",
        "extra",
        "row-digest",
        "default",
        "extra-entry-field",
        "missing-entry-field",
    ],
)
def test_acl_equivalence_is_closed_and_exactly_covered(case):
    source, restored, proof = acl_pair()
    if case in {"owner", "kind", "rls", "options"}:
        index, value = {
            "owner": (3, "other"),
            "kind": (2, "p"),
            "rls": (4, True),
            "options": (7, ["fillfactor=70"]),
        }[case]
        source["relations"][0][index] = value
    elif case == "inventory":
        source["relations"][0][1] = "other"
    elif case == "duplicate-relation":
        source["relations"] *= 2
    elif case == "both-explicit":
        restored["relations"][0][6] = "{}"
    elif case == "missing":
        proof["relation_acls"] = []
    elif case == "duplicate":
        proof["relation_acls"] *= 2
    elif case == "extra":
        entry = copy.deepcopy(proof["relation_acls"][0])
        entry["identity"][1] = "unknown"
        proof["relation_acls"].append(entry)
    elif case == "row-digest":
        proof["relation_acls"][0]["restored_row_digest"] = "sha256:" + "f" * 64
    elif case == "default":
        proof["relation_acls"][0]["server_default_acl"] = "{}"
    elif case == "extra-entry-field":
        proof["relation_acls"][0]["unchecked"] = True
    else:
        del proof["relation_acls"][0]["server_default_acl"]
    proof["source_catalogue_digest"] = digest(canonical_json(source))
    proof["restored_catalogue_digest"] = proof["restored_catalogue_after_digest"] = (
        digest(canonical_json(restored))
    )
    with pytest.raises(ContractError):
        verify(source, restored, proof)


@pytest.mark.parametrize("kind", ["p", "v", "m", "S", "f"])
def test_default_acl_equivalence_refuses_every_nonordinary_relation_kind(kind):
    source, restored, proof = acl_pair()
    source["relations"][0][2] = restored["relations"][0][2] = kind
    proof["source_catalogue_digest"] = digest(canonical_json(source))
    proof["restored_catalogue_digest"] = proof["restored_catalogue_after_digest"] = (
        digest(canonical_json(restored))
    )
    with pytest.raises(ContractError, match="catalogue_relation_nonacl_mismatch"):
        verify(source, restored, proof)


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "host_nonce",
        "source_database",
        "source_cluster_system_identifier",
    ],
)
def test_acl_proof_cannot_be_replayed_in_another_context(field):
    source, restored, proof = acl_pair()
    proof[field] = "sha256:" + "c" * 64 if field == "request_digest" else "foreign"
    with pytest.raises(ContractError):
        verify(source, restored, proof)
