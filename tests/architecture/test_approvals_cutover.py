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

import pytest
from import_scanner import reaches_module, scan_imports, source_files

from vendor_cp.approvals_cutover import (
    LEGACY_COMPOSITION_SITES,
    LEGACY_DECISION_CALL_SITES,
    LEGACY_DECISION_MODULE,
    LEGACY_PACKAGE,
    NEW_AUTHORITY,
    OLD_AUTHORITY,
    RECOVERABLE_FACTS,
    RESTART_CONDITIONS,
    SHARED_SAFETY_PROPERTIES,
    SHARED_SAFETY_PROPERTY_COUNT,
    UNCOMPARED_MODULE_CAPABILITIES,
    UNRECOVERABLE_FACTS,
    WATERMARK_BOUNDARY_COLUMN,
    WATERMARK_TABLE,
    Disposition,
    LegacyFact,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"
LEGACY_DIR = PACKAGE / "approvals"
ADR = ROOT / "docs" / "adr" / "0004-approvals-authority-cutover.md"


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


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
    text = ADR.read_text()
    assert "Request identity does not map" in text
    assert "begins at the watermark" in text
    for fact in UNRECOVERABLE_FACTS:
        assert fact.value.replace("_", " ") in text.lower()


# ── Scope of the shadow comparison ──────────────────────────────────────────


def test_exactly_the_six_shared_safety_properties_are_declared() -> None:
    assert len(SHARED_SAFETY_PROPERTIES) == SHARED_SAFETY_PROPERTY_COUNT == 6
    assert {prop.code for prop in SHARED_SAFETY_PROPERTIES} == {
        "immutable_policy_versions",
        "content_digest_binding",
        "fail_closed_missing_policy",
        "command_idempotency",
        "distinct_actor_quorum",
        "self_approval_excluded",
    }


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
    text = ADR.read_text()
    for prop in SHARED_SAFETY_PROPERTIES:
        assert f"`{prop.code}`" in text, prop.code


# ── Watermark and disposition ───────────────────────────────────────────────


def test_the_watermark_boundary_is_an_id_not_a_clock() -> None:
    """A retried transaction can commit a legacy row whose timestamp precedes a
    watermark written moments earlier. An id high-water mark is unambiguous
    under exactly that race, so the boundary column is not negotiable."""
    assert WATERMARK_BOUNDARY_COLUMN == "last_legacy_record_id"
    text = ADR.read_text()
    assert WATERMARK_TABLE in text
    assert "not wall-clock time" in text


def test_incomplete_groups_have_exactly_two_dispositions() -> None:
    assert set(Disposition) == {Disposition.DRAIN, Disposition.RESTART}


def test_the_restart_rule_is_data_not_judgement() -> None:
    """Stated as an ordered list of conditions so the choice cannot quietly
    become case-by-case reasoning about a particular customer or contract."""
    assert RESTART_CONDITIONS
    assert len(set(RESTART_CONDITIONS)) == len(RESTART_CONDITIONS)
    text = ADR.read_text()
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
    text = ADR.read_text()
    assert OLD_AUTHORITY.rsplit(".", 1)[0] in text
    assert NEW_AUTHORITY.replace("_", "-") in text
