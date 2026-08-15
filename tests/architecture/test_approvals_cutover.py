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
    EVIDENCE_DIGEST_FIELDS,
    LEGACY_COMPOSITION_SITES,
    LEGACY_DECISION_CALL_SITES,
    LEGACY_DECISION_MODULE,
    LEGACY_PACKAGE,
    MODULE_DIGEST_PREFIX,
    NEW_AUTHORITY,
    OLD_AUTHORITY,
    PLATFORM_ADMIN_ROLE_ID,
    RECOVERABLE_FACTS,
    RESTART_CONDITIONS,
    SEAL_TABLE,
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
    question instead of answering it: online DML is revoked first, so every
    legacy row is pre-cutover by construction."""
    assert SEAL_TABLE == "approval_cutover_seal"
    assert set(SEALED_LEGACY_TABLES) == {"approval_policies", "approval_records"}

    text = adr_text()
    assert "default=uuid4" in text
    assert "pre-cutover by construction" in text or "**pre-cutover**" in text
    assert "legacy_record_count" in text
    assert "evidence_digest" in text


def test_no_id_cursor_survives_anywhere_in_the_contract() -> None:
    """MUTATION PROOF. The invalid design was confidently argued, so the
    reasoning is what has to be blocked — not just the constant."""
    declaration = (SRC / "vendor_cp" / "approvals_cutover.py").read_text()
    assert "last_legacy_record_id" not in declaration, (
        "the id cursor is back; `ApprovalRecord.id` is random (uuid4) and "
        "orders nothing"
    )
    # The replacement rule must stay stated, or the next author reaches for the
    # same wrong tool with the same confident reasoning.
    assert "SCALAR_CURSOR_REQUIREMENT" in declaration
    assert "enforced_monotonic_bigint_column" in declaration


def test_the_evidence_digest_excludes_the_random_primary_key() -> None:
    """Including `id` would make the digest depend on a value nothing else in
    this contract trusts."""
    assert "id" not in EVIDENCE_DIGEST_FIELDS
    assert EVIDENCE_DIGEST_FIELDS == (
        "policy_code",
        "policy_version",
        "subject_type",
        "subject_id",
        "content_hash",
        "approver_id",
    )


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
