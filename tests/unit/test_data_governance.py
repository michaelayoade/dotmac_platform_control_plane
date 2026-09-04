"""`PlatformDataGovernanceV1`'s decisions, driven in both directions.

Every test here fails before `src/vendor_cp/data_governance.py` exists, and not
merely at import: each names a specific way the ruling could be implemented
wrongly and drives that case.

The live half — the revoke, the read-back and the admission refusal against a
real composed database — is `tests/migration/test_data_governance_catalogue.py`,
which needs Postgres. What is provable without one is provable here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vendor_cp.data_governance import (
    CONTRACT,
    DELETION_SITES,
    GOVERNED_TABLES,
    ONLINE_ROLES,
    POLICY_BY_TABLE,
    WITHHELD_PRIVILEGES,
    DeletionSite,
    Disposition,
    GovernanceVerdict,
    Reachability,
    TablePolicy,
    admission_refusal,
    effective_privileges_sql,
    govern_observation,
    policy_for,
    tables_permitting_online_deletion,
    tables_withholding_online_deletion,
    unclassified,
    unobserved,
)
from vendor_cp.deployment.table_inventory import (
    ObservationBinding,
    ReadOutcome,
    TableInventoryObservation,
    TableObservation,
)

BINDING = ObservationBinding(
    database_identity="vendor-cp-prod/vendor_control_plane",
    image_reference="ghcr.io/example/platform@sha256:" + "0" * 64,
    source_revision="f" * 40,
    migration_heads=("v019_relay_heartbeat",),
    observed_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
)


def _census(
    *, unknown: tuple[str, ...] = (), extra: tuple[str, ...] = ()
) -> TableInventoryObservation:
    """A census of the whole classification, with named tables made UNKNOWN."""
    tables = []
    for qualified in sorted([*POLICY_BY_TABLE, *extra]):
        schema, _, table = qualified.partition(".")
        if qualified in unknown:
            tables.append(TableObservation(schema, table, ReadOutcome.UNKNOWN))
        else:
            tables.append(TableObservation(schema, table, ReadOutcome.COUNTED, 3))
    return TableInventoryObservation(binding=BINDING, tables=tuple(tables))


# ── requirement 1: an enumeration, not a default ────────────────────────────


def test_every_classification_is_named_once_and_carries_a_rationale() -> None:
    """A duplicate would make a lookup return whichever was written last, and a
    classification with no rationale is an omission wearing a decision's shape."""
    qualified = [policy.qualified for policy in GOVERNED_TABLES]
    assert len(qualified) == len(set(qualified))
    assert all(policy.rationale.strip() for policy in GOVERNED_TABLES)
    assert len(POLICY_BY_TABLE) == len(GOVERNED_TABLES)


def test_a_classification_without_a_rationale_is_refused() -> None:
    with pytest.raises(ValueError, match="rationale"):
        TablePolicy("public", "x", Disposition.ENFORCED_RETAIN, "   ")


def test_the_classification_is_not_a_single_disposition_applied_broadly() -> None:
    """The ruling asked for an enumeration, and an enumeration whose every entry
    says the same thing has not classified anything — it has applied a default
    and written it out longhand.

    Three of the four dispositions are in use, and the two that are not
    `ENFORCED_RETAIN` are the ones requirement 3 is about.
    """
    used = {policy.disposition for policy in GOVERNED_TABLES}
    assert Disposition.ENFORCED_RETAIN in used
    assert Disposition.LIFECYCLE_DELETE in used
    assert Disposition.SUPERSEDED_IN_PLACE in used
    assert Disposition.MIGRATION_BOOKKEEPING in used


# ── requirement 3: a transient table gets a policy of its own ───────────────


def test_a_transient_policy_must_name_its_deleting_owner_and_the_trigger() -> None:
    """'Something deletes this' is the inherited policy requirement 3 refuses.

    Without this, a table could be moved out of retain — and out of the revoke —
    by writing one word, with nobody named and no trigger described.
    """
    with pytest.raises(ValueError, match="deleting owner"):
        TablePolicy(
            "public", "x", Disposition.LIFECYCLE_DELETE, "because", deleting_owner="a"
        )
    with pytest.raises(ValueError, match="deleting owner"):
        TablePolicy("public", "x", Disposition.LIFECYCLE_DELETE, "because")


def test_a_retained_table_may_not_name_a_deleting_owner() -> None:
    """The other direction. A policy that both retains and names a deleter has
    not decided which it is, and reading either half would be this type
    deciding for it."""
    with pytest.raises(ValueError, match="cannot carry a deleting owner"):
        TablePolicy(
            "public",
            "x",
            Disposition.ENFORCED_RETAIN,
            "because",
            deleting_owner="someone",
            trigger="something",
        )


def test_the_transient_table_is_named_with_its_owner_and_trigger() -> None:
    policy = policy_for("public.feature_flag_overrides")
    assert policy is not None
    assert policy.disposition is Disposition.LIFECYCLE_DELETE
    assert policy.deleting_owner == "dotmac_kernel.platform_web.set_flag"
    assert "action=clear" in policy.trigger


def test_only_the_transient_table_permits_an_online_deletion() -> None:
    """The two halves partition the enumeration, so a table cannot fall out of
    both and be governed by nothing."""
    withheld = set(tables_withholding_online_deletion())
    permitted = set(tables_permitting_online_deletion())
    assert permitted == {"public.feature_flag_overrides"}
    assert not (withheld & permitted)
    assert withheld | permitted == set(POLICY_BY_TABLE)


def test_a_gauge_is_not_recorded_as_retained() -> None:
    """`SUPERSEDED_IN_PLACE` reaches the same grant by a different route, and
    the route is the point: calling a liveness reading 'retained' would make
    retention the answer to a question nobody asked."""
    for qualified in ("public.relay_heartbeats", "public.domain_settings"):
        policy = policy_for(qualified)
        assert policy is not None
        assert policy.disposition is Disposition.SUPERSEDED_IN_PLACE
        assert policy.withholds_online_deletion


# ── requirement 4: a new unclassified table fails admission ─────────────────


def test_the_real_classification_admits_the_catalogue_it_describes() -> None:
    """Non-vacuity. Every test below asserts a REFUSAL, and a function that
    refused everything would pass all of them."""
    assert admission_refusal(POLICY_BY_TABLE) == ""


def test_a_new_unclassified_table_is_refused_by_name() -> None:
    """It does not inherit retain, and it does not pass. The refusal names the
    table and the file to classify it in, because a refusal an operator cannot
    act on is a different failure."""
    refusal = admission_refusal([*POLICY_BY_TABLE, "public.brand_new_thing"])
    assert "public.brand_new_thing" in refusal
    assert "data_governance.py" in refusal
    assert unclassified([*POLICY_BY_TABLE, "public.brand_new_thing"]) == (
        "public.brand_new_thing",
    )


def test_a_classified_table_the_database_no_longer_has_is_also_refused() -> None:
    """The direction that is usually left out. A policy describing nothing keeps
    reading as a decision, which is how a dropped table stops being noticed —
    the exemption shape `dotmac_starter_mt` ADR-0018 refuses."""
    without = [q for q in POLICY_BY_TABLE if q != "public.vendor_accounts"]
    refusal = admission_refusal(without)
    assert "public.vendor_accounts" in refusal
    assert unobserved(without) == ("public.vendor_accounts",)


# ── the census owner, consumed ──────────────────────────────────────────────


def test_a_census_that_could_not_read_a_table_never_becomes_a_clean_verdict() -> None:
    """`ReadOutcome.UNKNOWN` is a member of the type, not a zero — and this is
    the layer where that guarantee is usually lost. A retention verdict that
    rendered 'I could not look' as 'nothing to govern' would justify a
    disposition against a table that is full."""
    report = govern_observation(_census(unknown=("public.platform_audit_events",)))
    assert report.verdict is GovernanceVerdict.UNESTABLISHED
    assert not report.governed
    assert report.unknown == ("public.platform_audit_events",)


def test_the_same_census_with_every_table_read_is_governed() -> None:
    """The sensitivity half. Without it the test above passes for a verdict
    function that never returns GOVERNED at all."""
    report = govern_observation(_census())
    assert report.verdict is GovernanceVerdict.GOVERNED
    assert report.governed
    assert len(report.counted) == len(POLICY_BY_TABLE)
    assert report.unknown == ()


def test_a_census_holding_an_unclassified_table_is_inadmissible() -> None:
    report = govern_observation(_census(extra=("public.arrived_from_nowhere",)))
    assert report.verdict is GovernanceVerdict.INADMISSIBLE
    assert "public.arrived_from_nowhere" in report.detail


def test_the_report_carries_counts_and_never_a_row() -> None:
    """A count is a fact about governance; a row is the data being governed.
    The census type already refuses to carry one, and the judgement built on it
    must not reintroduce it."""
    report = govern_observation(_census())
    for qualified, disposition, count in report.counted:
        assert qualified in POLICY_BY_TABLE
        assert disposition in {str(d) for d in Disposition}
        assert isinstance(count, int)


# ── the code half's own declarations ────────────────────────────────────────


def test_an_online_deletion_site_must_target_a_table_classified_for_it() -> None:
    """The two enforcements are made to agree at construction. A site that
    deletes on a request from a table the grant withholds is a disagreement
    production would discover, so it cannot be written down."""
    with pytest.raises(ValueError, match="LIFECYCLE_DELETE"):
        DeletionSite(
            distribution="dotmac-kernel",
            module="dotmac_kernel.somewhere",
            symbol="wipe",
            target="public.platform_audit_events",
            reachability=Reachability.ONLINE_MOUNTED,
            premise="a premise",
        )


def test_the_same_site_is_accepted_against_the_transient_table() -> None:
    """The near-miss. Without it the refusal above could be a constructor that
    rejects every online site."""
    site = DeletionSite(
        distribution="dotmac-kernel",
        module="dotmac_kernel.somewhere",
        symbol="wipe",
        target="public.feature_flag_overrides",
        reachability=Reachability.ONLINE_MOUNTED,
        premise="a premise",
    )
    assert site.identity == ("dotmac_kernel.somewhere", "wipe")


def test_every_declared_site_carries_a_premise() -> None:
    assert all(site.premise.strip() for site in DELETION_SITES)
    with pytest.raises(ValueError, match="premise"):
        DeletionSite(
            distribution="d",
            module="m",
            symbol="s",
            target="t",
            reachability=Reachability.NOT_COMPOSED,
            premise="  ",
        )


def test_exactly_one_declared_site_is_reachable_online() -> None:
    online = [
        site.identity
        for site in DELETION_SITES
        if site.reachability is Reachability.ONLINE_MOUNTED
    ]
    assert online == [("dotmac_kernel.platform_web", "set_flag")]


# ── the statement the grant is actually made of ─────────────────────────────


def test_the_privilege_reading_asks_about_both_online_roles_and_both_verbs() -> None:
    """Built from the module's own constants so the statement and the contract
    cannot drift, and asserted so a narrowed statement is not a quiet
    narrowing of the check."""
    statement = effective_privileges_sql()
    for role in ONLINE_ROLES:
        assert f"'{role}'" in statement
    for privilege in WITHHELD_PRIVILEGES:
        assert f"('{privilege}')" in statement
    # `has_table_privilege`, never `information_schema`: the direct-grant view
    # misses a privilege reached through role membership, and an isolation gate
    # built on it is the mistake vendor `v012`/`v013`/`v014` each refused.
    assert "has_table_privilege" in statement
    assert "information_schema.role_table_grants" not in statement


def test_truncate_is_withheld_beside_delete() -> None:
    """`TRUNCATE` destroys rows without issuing a `DELETE`, which is the gap a
    DELETE-only revoke leaves open."""
    assert set(WITHHELD_PRIVILEGES) == {"DELETE", "TRUNCATE"}


def test_the_migration_role_is_not_an_online_role() -> None:
    """`app_admin` runs the enforcement itself. A rule that revoked its own
    ability to act would be self-defeating rather than strict, and a disposal
    decided later runs there under an operator rather than on a request."""
    assert "app_admin" not in ONLINE_ROLES
    assert set(ONLINE_ROLES) == {"platform_api", "app_user"}


def test_the_contract_name_is_declared_once() -> None:
    assert CONTRACT == "PlatformDataGovernanceV1"
