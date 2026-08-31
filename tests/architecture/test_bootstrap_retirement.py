"""The bootstrap is single-use by construction, and it carries its own retirement.

ADR-0013 § 6: a temporary path with no retirement mechanism becomes permanent.
So the launcher does not ship alone — these are the checks that keep it honest
while it exists and force it out when it stops being needed.

The load-bearing one is `test_the_receipt_claim_precedes_every_side_effect`. A
receipt written at the END records that a bootstrap happened; a claim taken at
the START is what makes a second one impossible. Those two are easy to confuse
in review and produce completely different systems, so the ordering is checked
rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_DIR = ROOT / "scripts" / "bootstrap"
LAUNCHER = BOOTSTRAP_DIR / "bootstrap_once.sh"

#: Effects that must not happen before the receipt path is claimed. Each is a
#: side effect on the target that a second, concurrent or repeat run must never
#: reach.
SIDE_EFFECTS = ("docker compose", "pg_dump", "sed -i", "docker inspect")


def test_there_is_exactly_one_bootstrap_path() -> None:
    """Two launchers means the single-use claim protects only one of them."""
    if not BOOTSTRAP_DIR.exists():
        return  # retired; see the retirement test below
    scripts = sorted(p.name for p in BOOTSTRAP_DIR.glob("*.sh"))
    assert scripts == ["bootstrap_once.sh"], scripts


def test_the_launcher_sets_noclobber() -> None:
    """`set -C` is what makes the claim atomic. Without it `>` truncates an
    existing receipt and the second run proceeds as if it were the first."""
    if not LAUNCHER.exists():
        return
    text = LAUNCHER.read_text()
    assert re.search(r"^set -C", text, re.M), "the launcher does not set noclobber"


def test_the_receipt_claim_precedes_every_side_effect() -> None:
    """THE structural property, checked as an ORDERING rather than a presence.

    A launcher that claims the receipt after doing its work is a launcher that
    can be run twice — the second run repeats every effect and only then
    discovers it should not have started.
    """
    if not LAUNCHER.exists():
        return
    text = LAUNCHER.read_text()
    claim = text.index('> "$RECEIPT"')
    for effect in SIDE_EFFECTS:
        where = text.find(effect)
        if where == -1:
            continue
        assert claim < where, (
            f"{effect!r} appears at {where}, before the receipt claim at "
            f"{claim}. Every side effect must sit behind the claim, or a second "
            "run reaches it"
        )


def test_the_ordering_check_can_fail(tmp_path: Path) -> None:
    """SENSITIVITY. The assertion above is a comparison over text that might not
    contain either marker; prove the same logic reports a launcher that claims
    the receipt too late."""
    bad = tmp_path / "bad.sh"
    bad.write_text('set -C\ndocker compose up -d app\nprintf x > "$RECEIPT"\n')
    text = bad.read_text()
    claim = text.index('> "$RECEIPT"')
    effect = text.find("docker compose")
    assert effect < claim, "the planted launcher should have the wrong order"


def test_the_launcher_reaches_no_secret_store() -> None:
    """The controller path holds installed material and never fetches it.

    ADR-0009: nothing on this path may reach a secret store. The credentials the
    bootstrap needs are already in the host's `.env`, which is the same seam the
    application reads.
    """
    if not LAUNCHER.exists():
        return
    # COMMENTS ARE EXCLUDED, and that is not a loophole being carved. The rule
    # governs what the launcher DOES; the docstring at the top of it says "there
    # is no OpenBao call on this path", and a check that failed on prose
    # asserting the absence would punish the file for explaining itself.
    executable = "\n".join(
        line
        for line in LAUNCHER.read_text().lower().splitlines()
        if not line.strip().startswith("#")
    )
    for forbidden in ("bao ", "vault ", "openbao"):
        assert forbidden not in executable, (
            f"the launcher reaches a secret store: {forbidden!r}"
        )


def test_the_retirement_condition_is_recorded_and_not_self_certified() -> None:
    """The launcher must say what retires it, and must not claim it has happened.

    "Platform CP authorized its own second deployment" is NOT a repository-local
    fact — under AGENTS.md rule 17 it needs a deployment-run oracle. So this
    checks the condition is STATED, and deliberately does not check whether it
    holds: a test that decided its own retirement would be the thing the rule
    forbids.
    """
    if not LAUNCHER.exists():
        return
    text = LAUNCHER.read_text()
    assert "retires_when" in text, "the launcher records no retirement condition"
    assert "second deployment" in text
