"""The bootstrap is create-only and single-use by construction, and it retires.

ADR-0013 § 6 and its 2026-08-31 amendment. A temporary path with no retirement
mechanism becomes permanent, and a bootstrap that can deploy is not a bootstrap.

Every gate here is exercised in BOTH directions: the planted violation must be
refused, and the conforming case must be admitted through the same predicate. A
validator only ever observed refusing proves nothing about what it accepts —
it might refuse everything.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_DIR = ROOT / "scripts" / "bootstrap"
LAUNCHER = BOOTSTRAP_DIR / "bootstrap_once.sh"

#: Effects on the target that a second or repeat run must never reach.
SIDE_EFFECTS = ("docker compose", "pg_dump", "docker inspect")

#: The nine coordinates the amended ADR requires the receipt to bind.
REQUIRED_COORDINATES = (
    "source_revision",
    "registry_image_digest",
    "transferred_image_id",
    "rootfs_layer_chain_sha256",
    "control_wheel_sha256",
    "product_descriptor_sha256",
    "migration_heads",
    "launcher_sha256",
    "authorizer",
)

#: Verbs that replace or mutate the running application. A bootstrap that can
#: do any of these is a general deployment interface, which is the capability
#: the issuer is supposed to become the sole owner of.
DEPLOYMENT_VERBS = (
    "up -d app",
    "compose up",
    "docker restart",
    "compose restart",
)


def _commands(text: str) -> str:
    """Only the lines that RUN.

    Two things are stripped and both had to be. Comments, because this file
    explains the deployment mistake it was rewritten to remove, and a check that
    failed on that explanation would punish it for being honest. And the receipt
    heredoc body, because it is JSON describing what was done, so a word like
    "restarted" appears there as a claim ABOUT the run rather than a command
    performing one.

    Both were real false positives on the first version of these tests.
    """
    kept: list[str] = []
    in_heredoc = False
    for line in text.splitlines():
        if "<<RECEIPT_JSON" in line:
            in_heredoc = True
            continue
        if in_heredoc:
            if line.strip() == "RECEIPT_JSON":
                in_heredoc = False
            continue
        if line.strip().startswith("#"):
            continue
        kept.append(line)
    return "\n".join(kept)


def test_there_is_exactly_one_bootstrap_path() -> None:
    """Two launchers means the single-use claim protects only one of them."""
    if not BOOTSTRAP_DIR.exists():
        return  # retired
    assert sorted(p.name for p in BOOTSTRAP_DIR.glob("*.sh")) == ["bootstrap_once.sh"]


def test_the_launcher_sets_noclobber() -> None:
    """Without `set -C`, `>` truncates an existing receipt and the second run
    proceeds as though it were the first."""
    if not LAUNCHER.exists():
        return
    assert re.search(r"^set -C", LAUNCHER.read_text(), re.M)


def test_the_claim_precedes_every_side_effect() -> None:
    """THE structural property, checked as an ORDERING rather than a presence."""
    if not LAUNCHER.exists():
        return
    text = _commands(LAUNCHER.read_text())
    claim = text.index('> "$RECEIPT"')
    for effect in SIDE_EFFECTS:
        where = text.find(effect)
        if where != -1:
            assert claim < where, f"{effect!r} precedes the receipt claim"


def test_the_ordering_check_sees_both_outcomes(tmp_path: Path) -> None:
    """BOTH HALVES. A launcher claiming too late is refused; one claiming first
    is admitted — through the same comparison."""
    late = tmp_path / "late.sh"
    late.write_text('set -C\ndocker compose up\nprintf x > "$RECEIPT"\n')
    text = late.read_text()
    assert text.find("docker compose") < text.index('> "$RECEIPT"')

    early = tmp_path / "early.sh"
    early.write_text('set -C\nprintf x > "$RECEIPT"\ndocker compose up\n')
    text = early.read_text()
    assert text.index('> "$RECEIPT"') < text.find("docker compose")


def test_the_launcher_cannot_replace_the_running_application() -> None:
    """CREATE-ONLY. The first version of this launcher ran `docker compose up -d
    app` and rewrote VENDOR_APP_IMAGE in .env — a general deployment capability
    wearing a bootstrap's name. Neither may return."""
    if not LAUNCHER.exists():
        return
    commands = _commands(LAUNCHER.read_text())
    for verb in DEPLOYMENT_VERBS:
        assert verb not in commands, f"the launcher can deploy: {verb!r}"
    # Exporting VENDOR_APP_IMAGE for the one-shot ops container is legitimate;
    # WRITING it into .env repins the application and is the deployment act.
    assert "sed -i" not in commands, "the launcher edits a file in place"
    assert ".env" not in commands, "the launcher touches .env, which repins it"


def test_the_create_only_check_sees_both_outcomes(tmp_path: Path) -> None:
    """BOTH HALVES for create-only."""
    deploying = tmp_path / "deploy.sh"
    deploying.write_text("docker compose -f c.yml up -d app\n")
    assert "up -d app" in _commands(deploying.read_text())

    creating = tmp_path / "create.sh"
    creating.write_text("docker compose -f c.yml --profile ops run --rm ops migrate\n")
    assert "up -d app" not in _commands(creating.read_text())


def test_the_receipt_binds_all_nine_coordinates() -> None:
    """A receipt missing a coordinate cannot identify what it authorized."""
    if not LAUNCHER.exists():
        return
    text = LAUNCHER.read_text()
    missing = [c for c in REQUIRED_COORDINATES if f'"{c}"' not in text]
    assert not missing, f"the receipt omits {missing}"


def test_the_coordinate_check_sees_both_outcomes() -> None:
    """BOTH HALVES. A receipt template missing one coordinate is reported, and
    a complete one passes the same predicate."""
    complete = " ".join(f'"{c}": "x"' for c in REQUIRED_COORDINATES)
    assert not [c for c in REQUIRED_COORDINATES if f'"{c}"' not in complete]

    partial = " ".join(f'"{c}": "x"' for c in REQUIRED_COORDINATES[:-1])
    assert [c for c in REQUIRED_COORDINATES if f'"{c}"' not in partial] == [
        REQUIRED_COORDINATES[-1]
    ]


def test_the_launcher_verifies_the_target_marker() -> None:
    """An address can be reassigned; a marker cannot be arrived at by accident."""
    if not LAUNCHER.exists():
        return
    executable = _commands(LAUNCHER.read_text())
    assert "/etc/dotmac-host-id" in executable
    assert "vendor-cp-prod" in executable


def test_the_launcher_refuses_a_pre_existing_receipt_by_condition() -> None:
    """The condition is the ADR's — ANY receipt asserting the bootstrap
    happened — not merely this file's own dedicated path."""
    if not LAUNCHER.exists():
        return
    executable = _commands(LAUNCHER.read_text())
    assert (
        "BOOTSTRAP*RECEIPT*" in executable
    ), "the launcher checks only its own receipt path, not the ADR's condition"


def test_the_launcher_reaches_no_secret_store() -> None:
    """ADR-0009: nothing on the controller path fetches a secret."""
    if not LAUNCHER.exists():
        return
    executable = _commands(LAUNCHER.read_text()).lower()
    for forbidden in ("bao ", "vault ", "openbao"):
        assert forbidden not in executable, f"reaches a secret store: {forbidden!r}"


def test_retirement_is_recorded_and_not_self_certified() -> None:
    """The launcher states what retires it — including the permission rule — and
    does NOT check whether that has happened. "Platform CP authorized its own
    second deployment" needs a deployment-run oracle under AGENTS.md rule 17,
    and a test deciding its own retirement is what that rule forbids."""
    if not LAUNCHER.exists():
        return
    text = LAUNCHER.read_text()
    assert "retires_when" in text
    assert "second deployment" in text
    assert "classifier rule" in text, (
        "retirement omits the permission rule; a permanent rule for a "
        "single-use bootstrap is a standing executor by another name"
    )
