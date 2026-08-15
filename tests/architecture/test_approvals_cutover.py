"""ADR-0004 is enforced, not just written down.

A cutover contract that lives only in a document decays the moment someone adds
a caller in a hurry. The parts a guard can hold are held here:

* the **ratchet** — the exact set of modules outside the legacy package that use
  the legacy decision surface, two-directional, scanned with every import form;
* **Ruling 2** — the facts a pre-watermark record has and lacks are disjoint,
  and the unrecoverable ones stay unrecoverable;
* **scope** — six shared safety properties, and the module capabilities Vendor
  never expressed are named as uncompared rather than silently ignored;
* **no composition** — this contract authorises none, so a guard fails if the
  module is pinned, imported or composed while it stands.

The scanner comes from `import_scanner`, which is exactly the class of guard it
was written for: the legacy surface is a plain module, reachable as
`import vendor_cp.approvals.service`, `from vendor_cp.approvals import service`,
`from . import service` and several more. A single-form guard would be worthless
here.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from uuid import UUID

import pytest
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp.approvals_cutover import (
    ACTOR_MAPPING,
    ADAPTER_OBLIGATIONS,
    COARSE_ELIGIBILITY_RULE,
    DIGEST_REJECTION_REASONS,
    LEGACY_COMPOSITION_SITES,
    LEGACY_DECISION_CALL_SITES,
    LEGACY_DECISION_MODULE,
    LEGACY_PACKAGE,
    MODULE_DIGEST_PREFIX,
    NEW_AUTHORITY,
    OLD_AUTHORITY,
    PLATFORM_ADMIN_ROLE_ID,
    POLICY_DIGEST_FIELDS,
    RECORD_DIGEST_FIELDS,
    RECOVERABLE_FACTS,
    RESTART_CONDITIONS,
    REVOKED_LEGACY_PRIVILEGES,
    SEAL_LOCK_MODE,
    SEAL_TABLE,
    SEAL_TRANSACTION_STEPS,
    SEALED_AGAINST_ROLES,
    SEALED_LEGACY_TABLES,
    SHARED_SAFETY_PROPERTIES,
    SHARED_SAFETY_PROPERTY_COUNT,
    UNCOMPARED_MODULE_CAPABILITIES,
    UNRECOVERABLE_FACTS,
    VENDOR_DIGEST_LENGTH,
    Disposition,
    LegacyFact,
    digest_rejection_reason,
    translate_digest,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"
LEGACY_DIR = PACKAGE / "approvals"
ADR = ROOT / "docs" / "adr" / "0004-approvals-authority-cutover.md"


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


def adr_text() -> str:
    """The ADR with runs of whitespace collapsed to single spaces.

    Prose assertions must survive reflow. `begins at the watermark` was split
    across a line break by the 80-column wrap, so a literal substring search
    failed on text that says exactly what it is supposed to — a guard failing
    for a typographical reason, which teaches everyone to loosen the guard.
    Normalising once here keeps the assertions about MEANING.
    """
    return " ".join(ADR.read_text().split())


def _outside_legacy_package() -> list[Path]:
    """Source files that are not part of the legacy owner itself."""
    return [path for path in source_files(PACKAGE) if LEGACY_DIR not in path.parents]


# ── The ratchet ─────────────────────────────────────────────────────────────


def test_no_new_call_sites_against_the_legacy_decision_surface() -> None:
    """Two-directional, and the direction that surprises people is DOWN.

    A new caller fails because new work must not deepen a dependency scheduled
    for retirement. A removed caller fails because that is cutover progress, and
    a declaration that quietly shrinks would let the migration look unfinished
    long after it was done — or finished long before it was.
    """
    actual = {
        path.relative_to(SRC).as_posix()
        for path in _outside_legacy_package()
        if reaches_module(_refs(path), LEGACY_DECISION_MODULE)
    }
    assert actual == LEGACY_DECISION_CALL_SITES, (
        "the set of modules calling the legacy approval decision surface "
        "changed. A new caller needs justifying against ADR-0004 § 9; a removed "
        "one is cutover progress and must lower the declaration in the same "
        f"change: {sorted(actual ^ LEGACY_DECISION_CALL_SITES)}"
    )


def test_composition_is_not_counted_as_a_call_site() -> None:
    """`assembly.py` mounts the feature manifest and never asks it for a
    decision. Conflating the two would make the ratchet impossible to drive to
    empty: retirement removes DECISION callers, and composition goes last."""
    assembly = PACKAGE / "assembly.py"
    assert reaches_module(_refs(assembly), f"{LEGACY_PACKAGE}.feature")
    assert not reaches_module(_refs(assembly), LEGACY_DECISION_MODULE)
    assert LEGACY_COMPOSITION_SITES == {"vendor_cp/assembly.py"}


def test_the_ratchet_is_not_vacuous() -> None:
    """NON-VACUITY. The equality above is satisfied by an empty scan meeting an
    empty declaration, which is exactly what retirement will look like — so
    while the declaration is non-empty, prove the scanner really found it."""
    assert LEGACY_DECISION_CALL_SITES, "the declaration is empty before retirement"

    outside = _outside_legacy_package()
    assert len(outside) > 20, "the sweep found almost no files outside the package"
    assert any(_refs(path) for path in outside), "the scanner found no imports at all"

    consumer = PACKAGE / "contracts" / "service.py"
    assert reaches_module(_refs(consumer), LEGACY_DECISION_MODULE), (
        "the one known consumer was not detected, so the ratchet is measuring "
        "nothing"
    )


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import vendor_cp.approvals.service\n", id="import-dotted"),
        pytest.param(
            "import vendor_cp.approvals.service as approvals\n", id="import-aliased"
        ),
        pytest.param(
            "from vendor_cp.approvals.service import evaluate\n", id="from-module"
        ),
        pytest.param(
            "from vendor_cp.approvals.service import evaluate as ev\n",
            id="from-module-aliased",
        ),
        pytest.param(
            "from vendor_cp.approvals import service\n", id="from-package-submodule"
        ),
    ],
)
def test_the_ratchet_would_see_a_new_caller_in_any_form(
    tmp_path: Path, source: str
) -> None:
    """SENSITIVITY, one case per spelling a new caller could use.

    The legacy surface is a plain module, so every one of these introduces a
    real dependency. A guard blind to any of them would let the cutover's
    workload grow silently.
    """
    package_dir = tmp_path / "src" / "vendor_cp" / "somewhere"
    package_dir.mkdir(parents=True)
    probe = package_dir / "probe.py"
    probe.write_text(source)
    refs = scan_imports(probe, source_root=tmp_path / "src")
    assert reaches_module(refs, LEGACY_DECISION_MODULE), source


def test_the_ratchet_does_not_cry_wolf(tmp_path: Path) -> None:
    """NON-VACUITY for the sensitivity cases: a scanner that matched everything
    would pass all five above and flag every innocent module in the tree."""
    package_dir = tmp_path / "src" / "vendor_cp" / "somewhere"
    package_dir.mkdir(parents=True)
    probe = package_dir / "probe.py"
    probe.write_text(
        "from vendor_cp.contracts.models import Contract\n"
        "from vendor_cp.approvals.schemas import PolicyResponse\n"
    )
    refs = scan_imports(probe, source_root=tmp_path / "src")
    assert not reaches_module(refs, LEGACY_DECISION_MODULE)


# ── Ruling 2: unknown facts stay unknown ────────────────────────────────────


def test_recoverable_and_unrecoverable_facts_are_disjoint_and_complete() -> None:
    assert RECOVERABLE_FACTS & UNRECOVERABLE_FACTS == frozenset()
    assert RECOVERABLE_FACTS | UNRECOVERABLE_FACTS == set(LegacyFact)


def test_request_identity_is_never_recoverable() -> None:
    """The three facts a pre-watermark record does not have, pinned exactly.

    Moving any of these into `RECOVERABLE_FACTS` is the decision Ruling 2
    refused: it would mean a migration inventing a value that afterwards looks
    exactly like a recorded one.
    """
    assert UNRECOVERABLE_FACTS == {
        LegacyFact.REQUEST_ID,
        LegacyFact.REQUESTER,
        LegacyFact.TERMINAL_STATE,
    }


def test_the_adr_states_the_absence_of_a_request_mapping() -> None:
    """The document and the declarations must agree. A contract whose prose and
    whose enforced constants disagree is worse than either alone."""
    text = adr_text()
    assert "Request identity does not map" in text
    assert "begins at the watermark" in text
    for fact in UNRECOVERABLE_FACTS:
        assert fact.value.replace("_", " ") in text.lower(), fact


# ── Scope of the shadow comparison ──────────────────────────────────────────


def test_exactly_the_five_shared_safety_properties_are_declared() -> None:
    assert len(SHARED_SAFETY_PROPERTIES) == SHARED_SAFETY_PROPERTY_COUNT == 5
    assert {prop.code for prop in SHARED_SAFETY_PROPERTIES} == {
        "immutable_policy_versions",
        "content_digest_binding",
        "fail_closed_missing_policy",
        "distinct_actor_quorum",
        "self_approval_excluded",
    }


def test_idempotency_is_an_adapter_obligation_not_a_compared_property() -> None:
    """Refusal is not replay.

    Vendor's `process_once_platform` REPLAYS a duplicate command and returns the
    original answer; the module RAISES `DuplicateDecision`. Both stop
    double-counting, which is why they look alike — but a retried HTTP request
    gets 200 from one and an error from the other. Comparing them as one
    property would report an agreement that does not exist, so the difference is
    carried as an obligation on the new adapter instead.
    """
    assert "command_idempotency" not in {prop.code for prop in SHARED_SAFETY_PROPERTIES}
    assert ADAPTER_OBLIGATIONS
    assert any("at_most_once" in obligation for obligation in ADAPTER_OBLIGATIONS)
    assert any("replay" in obligation for obligation in ADAPTER_OBLIGATIONS)

    text = adr_text()
    assert "Vendor REPLAYS" in text
    assert "The module REFUSES" in text
    assert "NEW-ADAPTER OBLIGATION" in text


def test_every_property_names_both_mechanisms() -> None:
    """A property with only one side named is not a comparison; it is a claim."""
    for prop in SHARED_SAFETY_PROPERTIES:
        assert prop.legacy_mechanism.strip(), prop.code
        assert prop.module_mechanism.strip(), prop.code
        assert prop.summary.strip(), prop.code


def test_the_uncompared_capabilities_are_named_not_forgotten() -> None:
    """Vendor never expressed these, so there is nothing to compare them
    against. Naming them keeps the omission a decision on the record rather than
    a gap someone later reads as coverage."""
    assert UNCOMPARED_MODULE_CAPABILITIES
    assert not UNCOMPARED_MODULE_CAPABILITIES & {
        prop.code for prop in SHARED_SAFETY_PROPERTIES
    }


def test_the_adr_documents_every_declared_property() -> None:
    """The document and the declaration carry the SAME six codes.

    Matched on the code verbatim, not on prose: a summary reworded in one place
    and not the other would otherwise look like a contract change, and matching
    loosely would let a property quietly disappear from the table.
    """
    text = adr_text()
    for prop in SHARED_SAFETY_PROPERTIES:
        assert f"`{prop.code}`" in text, prop.code


# ── Watermark and disposition ───────────────────────────────────────────────


def test_the_boundary_is_a_sealed_set_not_a_cursor() -> None:
    """`ApprovalRecord.id` is `uuid_pk()` -> `default=uuid4`, i.e. RANDOM, so a
    high-water mark over it orders nothing. The seal removes the boundary
    question instead of answering it."""
    assert SEAL_TABLE == "approval_cutover_seal"
    assert set(SEALED_LEGACY_TABLES) == {"approval_policies", "approval_records"}

    text = adr_text()
    assert "default=uuid4" in text
    assert "pre-cutover by construction" in text or "no later legacy row" in text


def test_the_lock_is_taken_before_anything_is_read() -> None:
    """Operational quiescence is a plan, not a guarantee.

    Without a lock an in-flight writer commits AFTER the count and digest are
    read, and the seal attests to a set that already changed — which is the
    boundary question again, wearing a different hat. SHARE conflicts with the
    ROW EXCLUSIVE that INSERT/UPDATE/DELETE take, so PostgreSQL waits for
    in-flight writers and blocks new ones for the transaction.
    """
    assert SEAL_LOCK_MODE == "SHARE"

    steps = list(SEAL_TRANSACTION_STEPS)
    lock = steps.index("lock_both_legacy_tables_in_share_mode")
    assert lock == 0, "the lock is not the first thing the transaction does"
    for reader in (
        "preflight_digest_translatability_over_the_locked_set",
        "parity_comparison_over_the_locked_set",
        "compute_complete_content_digests",
    ):
        assert steps.index(reader) > lock, reader

    text = adr_text()
    assert "IN SHARE MODE" in text
    assert "sql-lock" in text


def test_parity_runs_before_the_transaction_can_commit() -> None:
    """An earlier draft sealed first and compared afterwards, while forbidding
    rollback after sealing — a parity failure with no legal exit. Every check
    that could justify aborting must precede every irreversible step."""
    steps = list(SEAL_TRANSACTION_STEPS)
    parity = steps.index("parity_comparison_over_the_locked_set")
    preflight = steps.index("preflight_digest_translatability_over_the_locked_set")
    for irreversible in (
        "revoke_online_dml_on_both_legacy_tables",
        "insert_the_seal_row",
        "grant_the_module_platform_tables_to_the_online_role",
    ):
        assert steps.index(irreversible) > parity, irreversible
        assert steps.index(irreversible) > preflight, irreversible

    text = adr_text()
    assert "rollback is free and total" in text.lower()


def test_the_privileges_are_verified_after_being_revoked() -> None:
    """Issuing a REVOKE is not proof the privilege is gone: a grant reaching the
    role through PUBLIC or through a role it inherits survives it. Assert the
    outcome, never the action."""
    steps = list(SEAL_TRANSACTION_STEPS)
    assert steps.index("verify_effective_privileges_are_gone") > steps.index(
        "revoke_online_dml_on_both_legacy_tables"
    )
    assert steps.index("verify_effective_privileges_are_gone") < steps.index(
        "insert_the_seal_row"
    ), "the seal must not be written before the revoke is proven effective"

    assert set(SEALED_AGAINST_ROLES) == {"platform_api", "app_user"}
    assert (
        "TRUNCATE" in REVOKED_LEGACY_PRIVILEGES
    ), "TRUNCATE empties a table without being INSERT/UPDATE/DELETE"

    text = adr_text()
    assert "has_any_column_privilege" in text
    assert "sql-revoke" in text


def test_the_digests_cover_every_column_of_both_tables() -> None:
    """INDEPENDENT EXPECTED TRUTH, read from the ORM rather than from the
    declaration that claims to describe it.

    Counts and unique constraints detect inserts and deletes; neither detects an
    UPDATE — and `platform_api` holds UPDATE and DELETE on both tables today, so
    a silent change to `quorum` or a `content_hash` is a live capability. A
    column added without being added to its digest fails here.
    """
    from vendor_cp.approvals.models import ApprovalPolicy, ApprovalRecord

    assert set(POLICY_DIGEST_FIELDS) == {
        column.name for column in ApprovalPolicy.__table__.columns
    }
    assert set(RECORD_DIGEST_FIELDS) == {
        column.name for column in ApprovalRecord.__table__.columns
    }


def test_the_digests_include_the_id_and_the_mutable_columns() -> None:
    """Reversing the earlier exclusion, which was a category error.

    A random value cannot ORDER a set — that is why it fails as a cursor — but it
    identifies a row perfectly well within one. Excluding it made a
    source-identity replacement invisible: delete a row, insert a replacement
    with different content under a new id, and count plus content-without-id
    could be made to agree.
    """
    assert "id" in POLICY_DIGEST_FIELDS
    assert "id" in RECORD_DIGEST_FIELDS
    assert "updated_at" in POLICY_DIGEST_FIELDS
    assert "updated_at" in RECORD_DIGEST_FIELDS
    # The policy contents an UPDATE could change silently.
    assert {"quorum", "allow_self_approval"} <= set(POLICY_DIGEST_FIELDS)
    assert "content_hash" in RECORD_DIGEST_FIELDS


def test_the_update_capability_this_defends_against_is_real() -> None:
    """SENSITIVITY for the reasoning above: the migration really does grant
    UPDATE to the online role, so this is a live capability rather than a
    theoretical one. If v003 ever stops granting it, this test says so and the
    justification can be revisited deliberately."""
    migration = (
        ROOT / "alembic" / "versions" / "v003_approval_policies.py"
    ).read_text()
    assert "GRANT SELECT, INSERT, UPDATE, DELETE" in migration
    assert "platform_api" in migration


def test_no_id_cursor_survives_anywhere_in_the_contract() -> None:
    """MUTATION PROOF. The invalid design was confidently argued, so the
    reasoning is what has to be blocked — not just the constant."""
    declaration = (SRC / "vendor_cp" / "approvals_cutover.py").read_text()
    assert "last_legacy_record_id" not in declaration, (
        "the id cursor is back; `ApprovalRecord.id` is random (uuid4) and "
        "orders nothing"
    )
    assert "SCALAR_CURSOR_REQUIREMENT" in declaration
    assert "enforced_monotonic_bigint_column" in declaration


# ── Coarse eligibility mapping ──────────────────────────────────────────────


def test_coarse_eligibility_is_mapped_not_declared_absent() -> None:
    """Vendor DOES express eligibility — `require_platform_admin` — so declaring
    it uncompared overstated the gap. And the module's `approver_kind` /
    `approver_id` are required fields with no defaults, so the mapping cannot be
    left implicit even if one wanted to."""
    assert COARSE_ELIGIBILITY_RULE == "any_authenticated_platform_admin"
    assert PLATFORM_ADMIN_ROLE_ID
    assert ACTOR_MAPPING

    assert "fine_grained_approver_eligibility" in UNCOMPARED_MODULE_CAPABILITIES
    assert "per_level_approver_eligibility" not in UNCOMPARED_MODULE_CAPABILITIES

    text = adr_text()
    assert "any authenticated platform admin may approve" in text
    assert "ApproverKind.ROLE" in text


def test_the_declared_role_id_is_a_stable_uuid() -> None:
    """A value that differed between shadow runs would silently change what the
    comparison compared."""
    parsed = UUID(PLATFORM_ADMIN_ROLE_ID)
    assert str(parsed) == PLATFORM_ADMIN_ROLE_ID


def test_the_router_really_enforces_the_coarse_rule() -> None:
    """INDEPENDENT EXPECTED TRUTH. The mapping claims Vendor's eligibility rule
    is `require_platform_admin`; this reads the router rather than trusting the
    declaration that describes it."""
    router = (SRC / "vendor_cp" / "approvals" / "router.py").read_text()
    assert "require_platform_admin" in router
    assert "approver_id=admin.id" in router


# ── Digest translation and its fail-closed preflight ────────────────────────


def test_a_valid_vendor_digest_translates() -> None:
    """NON-VACUITY: the rejection cases below must not pass because everything
    is rejected."""
    vendor = "a" * VENDOR_DIGEST_LENGTH
    assert digest_rejection_reason(vendor) is None
    assert translate_digest(vendor) == f"{MODULE_DIGEST_PREFIX}{vendor}"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param("", "empty", id="empty"),
        pytest.param(f"sha256:{'a' * 64}", "already_prefixed", id="already-prefixed"),
        pytest.param("a" * 63, "wrong_length", id="too-short"),
        pytest.param("a" * 65, "wrong_length", id="too-long"),
        pytest.param("A" * 64, "uppercase", id="uppercase"),
        pytest.param("g" * 64, "non_hex", id="non-hex"),
    ],
)
def test_every_untranslatable_digest_is_refused(value: str, reason: str) -> None:
    """SENSITIVITY, one case per declared rejection reason.

    Fail closed: an approval whose bound content cannot be expressed in the new
    system is exactly the case where proceeding would silently drop the binding
    that makes the approval mean anything. Nothing is normalised into validity.
    """
    assert digest_rejection_reason(value) == reason
    with pytest.raises(ValueError, match="not translatable"):
        translate_digest(value)


def test_every_declared_rejection_reason_is_reachable() -> None:
    """A reason nobody can produce is documentation pretending to be a branch."""
    produced = {
        digest_rejection_reason(value)
        for value in ("", f"sha256:{'a' * 64}", "a" * 63, "A" * 64, "g" * 64)
    }
    assert produced == set(DIGEST_REJECTION_REASONS)


def test_the_preflight_is_fail_closed_in_the_contract() -> None:
    text = adr_text()
    assert "any untranslatable digest stops the cutover" in text.lower()
    assert "not translated on a best-effort basis" in text


def test_incomplete_groups_have_exactly_two_dispositions() -> None:
    assert set(Disposition) == {Disposition.DRAIN, Disposition.RESTART}


def test_the_restart_rule_is_data_not_judgement() -> None:
    """Stated as an ordered list of conditions so the choice cannot quietly
    become case-by-case reasoning about a particular customer or contract."""
    assert RESTART_CONDITIONS
    assert len(set(RESTART_CONDITIONS)) == len(RESTART_CONDITIONS)
    text = adr_text()
    assert "DRAIN" in text and "RESTART" in text
    assert "drain window is bounded" in text


# ── This contract authorises no composition ─────────────────────────────────


def test_the_module_is_not_pinned_while_this_contract_stands() -> None:
    """MUTATION PROOF for the ADR's closing section. Composition is the next
    phase and needs the published locator release; a pin appearing here would
    mean the phases had merged without anyone deciding to merge them."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "dotmac-approvals" not in config["tool"]["poetry"]["dependencies"]


def test_no_source_file_imports_the_new_authority() -> None:
    """Including this contract module itself, which references the module only
    as a string for exactly this reason."""
    importers = sorted(
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), NEW_AUTHORITY)
    )
    assert not importers, (
        f"{NEW_AUTHORITY} is not a dependency of this assembly yet; the cutover "
        f"contract precedes the composition: {importers}"
    )


def test_the_authorities_are_the_ones_the_adr_names() -> None:
    text = adr_text()
    assert OLD_AUTHORITY.rsplit(".", 1)[0] in text
    assert NEW_AUTHORITY.replace("_", "-") in text


def test_the_prose_assertions_survive_reflow() -> None:
    """MUTATION PROOF for the normaliser.

    Every ADR assertion above reads through `adr_text()`. If that ever went back
    to a raw read, a wrapped phrase would fail again and the tempting fix is to
    weaken the assertion rather than the matching. This proves the normaliser
    joins across newlines, and that it is actually being used.
    """
    assert "begins at the watermark" in adr_text()
    assert "begins at the watermark" not in ADR.read_text(), (
        "the phrase is no longer wrapped, so this proof has stopped proving "
        "anything — pick another wrapped phrase or delete it deliberately"
    )
