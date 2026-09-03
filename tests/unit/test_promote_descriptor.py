"""The promotion writer, exercised with no receipt and no deployment.

The whole point of building this before the first cutover is that its first
execution must not be inside a window. So the receipt is a parameter, every
check is a real comparison against the document supplied, and all of it runs
here against files this test wrote.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import promote_descriptor as promote  # noqa: E402

ACCEPTED_TOML = """schema = "ProductDeploymentSpec.v1"

[image]
reference = "ghcr.io/dotmac/platform@sha256:aaa"
source_revision = "af9fcf6d"

[assembly]
manifest_digest = "sha256:bbb"

[migration]
expected_heads = ["0001_alpha", "0002_beta"]

[backup]
retain = 3
"""

#: Differs from the accepted descriptor in `backup` alone.
CANDIDATE_TOML = ACCEPTED_TOML.replace("retain = 3", "retain = 5")


def _bootstrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: object):
    """A repository shaped like the real one, with the writer pointed at it."""
    deploy = tmp_path / "deploy"
    (deploy / "candidates").mkdir(parents=True)

    accepted = deploy / "product.toml"
    accepted.write_text(overrides.get("accepted", ACCEPTED_TOML), encoding="utf-8")
    candidate = deploy / "candidates" / "2026-09-03-change.toml"
    candidate.write_text(overrides.get("candidate", CANDIDATE_TOML), encoding="utf-8")

    monkeypatch.setattr(promote, "ROOT", tmp_path)
    monkeypatch.setattr(promote, "ACCEPTED", accepted)
    ledger_path = deploy / "descriptor-promotions.json"
    monkeypatch.setattr(promote, "LEDGER", ledger_path)

    ledger = {
        "schema": "DescriptorPromotionLedger.v1",
        "promotions": [
            {
                "promoted_at": "2026-09-01",
                "kind": "pre_mechanism",
                "candidate": None,
                "descriptor_sha256": overrides.get(
                    "chain_head", promote.raw_digest(accepted)
                ),
                "summary": "where the chain starts",
                "supersedes": None,
            }
        ],
    }
    ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps(
            overrides.get(
                "receipt",
                {
                    "migration_heads": "0002_beta,0001_alpha",
                    "product_descriptor_sha256": "sha256:" + "9" * 64,
                },
            )
        ),
        encoding="utf-8",
    )
    return accepted, candidate, receipt, ledger_path


def _refusal(call) -> object:  # noqa: ANN001
    """Run something expected to refuse and return WHICH refusal answered.

    Asserting the code rather than the message is what this file learned the
    hard way: `match="nothing to promote"` passed CI review and failed in CI
    because a different refusal answered first, and the branch it named could
    never execute. A regex found that; only a code can pin it.
    """
    with pytest.raises(SystemExit) as raised:
        call()
    assert isinstance(raised.value, promote.Refused)
    return raised.value.refusal


def _build(candidate: Path, receipt: Path, **kwargs: object) -> dict[str, object]:
    return promote.build_entry(
        candidate=candidate,
        receipt_path=receipt,
        kind=str(kwargs.get("kind", "contract_change")),
        summary=str(kwargs.get("summary", "a change")),
        carry_why=str(kwargs.get("carry_why", "nothing was deployed")),
        promoted_at=str(kwargs.get("promoted_at", "2026-09-03")),
    )


def test_the_entry_is_derived_from_the_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSITIVE CONTROL. Every other test here is a refusal."""
    accepted, candidate, receipt, _ = _bootstrap(tmp_path, monkeypatch)
    entry = _build(candidate, receipt)

    assert entry["changed_sections"] == ["backup"]
    assert entry["supersedes"] == promote.raw_digest(accepted)
    assert entry["descriptor_sha256"] == promote.raw_digest(candidate)
    assert entry["candidate"] == "deploy/candidates/2026-09-03-change.toml"
    assert entry["promoted_at"] == "2026-09-03"


def test_the_licence_is_the_heads_the_receipt_measured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check the ledger's own reconciliation entry says nothing performs.

    A candidate that does not describe what the run produced must not become
    accepted truth, however well-formed the rest of the promotion is.
    """
    _, candidate, receipt, _ = _bootstrap(
        tmp_path,
        monkeypatch,
        receipt={
            "migration_heads": "0001_alpha,0003_gamma",
            "product_descriptor_sha256": "sha256:" + "9" * 64,
        },
    )
    assert (
        _refusal(lambda: _build(candidate, receipt))
        is promote.PromotionRefusal.HEADS_MISMATCH
    )


def test_heads_are_compared_as_a_set_not_as_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENSITIVITY for the licence. A head set is unordered, and it arrives as a
    comma-joined string from one producer and a list from another. A promotion
    must not turn on which tool emitted it, or the licence would refuse correct
    deployments and quietly teach an operator to bypass it."""
    _, candidate, receipt, _ = _bootstrap(
        tmp_path,
        monkeypatch,
        receipt={"migration_heads": ["0002_beta", "0001_alpha"]},
    )
    assert _build(candidate, receipt)["changed_sections"] == ["backup"]


def test_the_receipts_backward_pointing_descriptor_field_is_not_the_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured, not assumed: on the only real receipt that exists, this digest
    appears NOWHERE in the ledger chain, because it is a literal fixed at
    authorship naming the descriptor the run STARTED from.

    A writer that required it to bind could never have run against a real
    receipt. It is recorded as provenance beside the reason it cannot close the
    question, and this test pins that decision so a later reader does not
    "repair" it into a binding.
    """
    _, candidate, receipt, _ = _bootstrap(tmp_path, monkeypatch)
    entry = _build(candidate, receipt)

    licensed = entry["licensed_by"]
    assert isinstance(licensed, dict)
    assert licensed["receipt_bound_descriptor_sha256"] == "sha256:" + "9" * 64
    assert licensed["measured_migration_heads"] == ["0001_alpha", "0002_beta"]
    assert "points backwards" in licensed["why_the_bound_descriptor_is_not_the_binding"]


def test_a_broken_chain_is_refused_rather_than_extended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, candidate, receipt, _ = _bootstrap(
        tmp_path, monkeypatch, chain_head="sha256:" + "0" * 64
    )
    assert (
        _refusal(lambda: _build(candidate, receipt))
        is promote.PromotionRefusal.CHAIN_BROKEN
    )


def test_a_candidate_that_changes_nothing_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, candidate, receipt, _ = _bootstrap(
        tmp_path, monkeypatch, candidate=ACCEPTED_TOML
    )
    assert (
        _refusal(lambda: _build(candidate, receipt))
        is promote.PromotionRefusal.ALREADY_ACCEPTED
    )


def test_carrying_the_application_half_requires_a_stated_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The facts are derived; the reason is not. No file knows why the
    application did not move."""
    _, candidate, receipt, _ = _bootstrap(tmp_path, monkeypatch)
    assert (
        _refusal(lambda: _build(candidate, receipt, carry_why=""))
        is promote.PromotionRefusal.CARRY_REASON_MISSING
    )


def test_a_moved_application_half_is_not_recorded_as_carried_forward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENSITIVITY for the carried-forward derivation: it must notice the
    opposite case too. A key recorded as carried while it actually moved would
    make the ledger assert the application stayed put across a promotion that
    moved it -- the precise claim ADR-0017 s 2 exists to refuse."""
    moved = CANDIDATE_TOML.replace(
        'source_revision = "af9fcf6d"', 'source_revision = "deadbeef"'
    )
    _, candidate, receipt, _ = _bootstrap(tmp_path, monkeypatch, candidate=moved)
    entry = _build(candidate, receipt)
    assert "image" in entry["changed_sections"]
    carried = entry.get("carried_forward", {})
    assert isinstance(carried, dict)
    assert "image.source_revision" not in carried


def test_a_date_that_is_not_a_date_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, candidate, receipt, _ = _bootstrap(tmp_path, monkeypatch)
    assert (
        _refusal(lambda: _build(candidate, receipt, promoted_at="yesterday"))
        is promote.PromotionRefusal.BAD_DATE
    )


def test_a_receipt_without_measured_heads_licenses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, candidate, receipt, _ = _bootstrap(
        tmp_path, monkeypatch, receipt={"product_descriptor_sha256": "sha256:x"}
    )
    assert (
        _refusal(lambda: _build(candidate, receipt))
        is promote.PromotionRefusal.NO_MEASURED_HEADS
    )


def test_a_dry_run_writes_nothing_and_apply_writes_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default is a dry run, because a mechanism that mutates on its first
    invocation is one an operator cannot rehearse."""
    accepted, candidate, receipt, ledger_path = _bootstrap(tmp_path, monkeypatch)
    before_ledger = ledger_path.read_bytes()
    before_accepted = accepted.read_bytes()

    argv = [
        "--candidate",
        str(candidate),
        "--receipt",
        str(receipt),
        "--kind",
        "contract_change",
        "--summary",
        "a change",
        "--carry-why",
        "nothing was deployed",
        "--promoted-at",
        "2026-09-03",
    ]
    assert promote.main(argv) == 0
    assert ledger_path.read_bytes() == before_ledger
    assert accepted.read_bytes() == before_accepted

    assert promote.main([*argv, "--apply"]) == 0
    assert accepted.read_bytes() == candidate.read_bytes()
    promotions = json.loads(ledger_path.read_text())["promotions"]
    assert len(promotions) == 2
    assert promotions[-1]["changed_sections"] == ["backup"]


def test_superseded_bytes_cannot_be_promoted_a_second_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Append-only is not idempotent: re-promoting bytes that were accepted once
    and have since been superseded records a change that already happened.

    TWO promotions are needed to reach this, and that is the finding. With one,
    the retried candidate IS the accepted descriptor, so `ALREADY_ACCEPTED`
    answers first -- which is exactly how the earlier version of this test
    passed while naming a refusal that had not fired.
    """
    _, first, receipt, ledger_path = _bootstrap(tmp_path, monkeypatch)
    second = first.parent / "2026-09-03-second.toml"
    second.write_text(ACCEPTED_TOML.replace("retain = 3", "retain = 7"), "utf-8")

    def run(candidate: Path) -> int:
        return promote.main(
            [
                "--candidate",
                str(candidate),
                "--receipt",
                str(receipt),
                "--kind",
                "contract_change",
                "--summary",
                "a change",
                "--carry-why",
                "nothing was deployed",
                "--promoted-at",
                "2026-09-03",
                "--apply",
            ]
        )

    assert run(first) == 0
    assert run(second) == 0
    assert len(json.loads(ledger_path.read_text())["promotions"]) == 3

    assert _refusal(lambda: run(first)) is promote.PromotionRefusal.ALREADY_PROMOTED


def test_no_refusal_code_ships_without_a_test() -> None:
    """A two-directional ratchet on the refusal vocabulary.

    Maintained by hand beside the tests that drive it, so a new code cannot ship
    untested and a retired one cannot linger naming a branch nobody reaches.
    `MISSING_FILE`, `UNREADABLE` and `LEDGER_EMPTY` are argument and
    file-integrity refusals covered by the CLI's own contract rather than by a
    case here, and they are listed so that stays a stated choice.
    """
    assert set(promote.PromotionRefusal) == {
        promote.PromotionRefusal.MISSING_FILE,
        promote.PromotionRefusal.UNREADABLE,
        promote.PromotionRefusal.BAD_DATE,
        promote.PromotionRefusal.LEDGER_EMPTY,
        promote.PromotionRefusal.CHAIN_BROKEN,
        promote.PromotionRefusal.ALREADY_ACCEPTED,
        promote.PromotionRefusal.ALREADY_PROMOTED,
        promote.PromotionRefusal.NO_MEASURED_HEADS,
        promote.PromotionRefusal.NO_DECLARED_HEADS,
        promote.PromotionRefusal.HEADS_MISMATCH,
        promote.PromotionRefusal.NOTHING_CHANGED,
        promote.PromotionRefusal.CARRY_REASON_MISSING,
    }
