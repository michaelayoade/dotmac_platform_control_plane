"""The preflight must be able to say NO, and must not confuse unknown with satisfied.

A preflight that only ever reports ready is the failure this programme keeps
finding, so the tests that matter here are the ones that plant a broken
precondition and require a refusal. The happy path is the easy half and is
asserted last, as a non-vacuity control.

It must also be genuinely READ-ONLY. That is not a promise in a docstring: the
packet is driven with a planted tree and with no database configured, and it
must produce the same answer either way.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vendor_cp.deployment.relay_preflight import (
    TARGET_ONLY,
    Finding,
    Precondition,
    Verdict,
    build_preflight_packet,
)

ROOT = Path(__file__).resolve().parents[2]

#: The files the packet reads. Copied into a scratch tree so a plant can be made
#: without touching the repository.
_SOURCES = (
    "deploy/product.toml",
    "deploy/descriptor-promotions.json",
    "deploy/candidates/2026-09-04-activation-relay-service.toml",
    "docker-compose.production.yml",
    ".env.production.example",
    "src/vendor_cp/production_secrets.py",
    "alembic/versions/v019_relay_heartbeat.py",
)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for relative in _SOURCES:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return tmp_path


def _patch(tree: Path, relative: str, old: str, new: str) -> None:
    path = tree / relative
    text = path.read_text(encoding="utf-8")
    assert old in text, f"the plant's anchor is gone from {relative}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ── it can say no ───────────────────────────────────────────────────────────


def test_a_hand_edited_descriptor_is_refused(tree: Path) -> None:
    """The rule-23 violation, planted. If the accepted descriptor stops being
    its candidate byte for byte, nothing downstream of it can be trusted."""
    _patch(tree, "deploy/product.toml", "postgres_major = 16", "postgres_major = 17")
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.ACCEPTED_DESCRIPTOR_IS_A_PROMOTED_CANDIDATE).finding
        is Finding.REFUSED
    )


def test_a_descriptor_without_the_relay_role_is_refused(tree: Path) -> None:
    _patch(tree, "deploy/product.toml", 'code = "relay"', 'code = "not-the-relay"')
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.DESCRIPTOR_DECLARES_THE_RELAY_ROLE).finding
        is Finding.REFUSED
    )


def test_a_descriptor_still_naming_the_old_head_is_refused(tree: Path) -> None:
    """The precondition that would otherwise be discovered on the host, as the
    relay fails every heartbeat write against a table that is not there."""
    _patch(
        tree,
        "deploy/product.toml",
        '"v019_relay_heartbeat"',
        '"v018_licence_delivery_intents"',
    )
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.DESCRIPTOR_HEAD_IS_THE_HEARTBEAT_REVISION).finding
        is Finding.REFUSED
    )


def test_a_compose_file_without_the_relay_service_is_refused(tree: Path) -> None:
    _patch(tree, "docker-compose.production.yml", "\n  relay:\n", "\n  relayed:\n")
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.COMPOSE_DECLARES_THE_RELAY_SERVICE).finding
        is Finding.REFUSED
    )


def test_a_committed_dispatcher_value_is_refused(tree: Path) -> None:
    """The pointer-only rule, planted. A value assigned anywhere in a committed
    file is the one failure that cannot be undone by editing it afterwards."""
    _patch(
        tree,
        ".env.production.example",
        "VENDOR_DB_DISPATCHER_PASSWORD=\n",
        "VENDOR_DB_DISPATCHER_PASSWORD=not-a-real-value\n",
    )
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.DISPATCHER_MATERIAL_IS_A_POINTER_ONLY).finding
        is Finding.REFUSED
    )


def test_a_grant_to_the_dispatcher_is_refused(tree: Path) -> None:
    """The dispatcher's whole isolation is that it holds no table privilege. A
    heartbeat table that granted it one would erode that for the convenience of
    a single write."""
    _patch(
        tree,
        "alembic/versions/v019_relay_heartbeat.py",
        'op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_TABLE} TO platform_api;")',
        'op.execute(f"GRANT SELECT ON {_TABLE} TO platform_outbox_dispatcher;")',
    )
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(
            Precondition.HEARTBEAT_MIGRATION_GRANTS_THE_DISPATCHER_NOTHING
        ).finding
        is Finding.REFUSED
    )


def test_the_dispatcher_credential_leaking_into_another_service_is_refused(
    tree: Path,
) -> None:
    """Co-hosting it would put a lease-and-settle credential in a
    request-serving process, which is why the relay is a separate role."""
    _patch(
        tree,
        "docker-compose.production.yml",
        "  ops:\n",
        "  ops:\n    environment:\n"
        "      VENDOR_RELAY_DISPATCHER_DATABASE_URL: ${SOMETHING}\n",
    )
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.REFUSED
    assert (
        packet.of(Precondition.ONLY_THE_RELAY_HOLDS_THE_DISPATCHER_MATERIAL).finding
        is Finding.REFUSED
    )


# ── unknown is not satisfied ────────────────────────────────────────────────


def test_an_unreadable_file_is_unknown_and_never_satisfied(tree: Path) -> None:
    """A precondition that could not be READ is not one that was met, and it is
    not a refusal either — reporting a missing file as a violation would be a
    false accusation about the thing the file describes."""
    (tree / "docker-compose.production.yml").unlink()
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.INCOMPLETE
    result = packet.of(Precondition.COMPOSE_DECLARES_THE_RELAY_SERVICE)
    assert result.finding is Finding.UNKNOWN
    assert result.finding is not Finding.SATISFIED


def test_incomplete_is_not_reported_as_locally_satisfied(tree: Path) -> None:
    """The specific confusion worth refusing. A packet that could not read one
    of its inputs must not answer with the verdict that means everything local
    was decided."""
    (tree / "src/vendor_cp/production_secrets.py").unlink()
    packet = build_preflight_packet(tree)
    assert packet.verdict is not Verdict.LOCALLY_SATISFIED_TARGET_UNVERIFIED
    assert packet.verdict is Verdict.INCOMPLETE


def test_a_refusal_outranks_an_unknown(tree: Path) -> None:
    """Both at once. Something being actually wrong is more urgent than
    something being unread, and the verdict must say the urgent thing."""
    (tree / "src/vendor_cp/production_secrets.py").unlink()
    _patch(tree, "deploy/product.toml", 'code = "relay"', 'code = "gone"')
    assert build_preflight_packet(tree).verdict is Verdict.REFUSED


# ── the target-only class stays honest ──────────────────────────────────────


def test_every_target_only_precondition_is_unknown_and_names_who_can_answer(
    tree: Path,
) -> None:
    """These are UNKNOWN by construction. A local answer to a target question
    would be an assertion about a host nothing has contacted."""
    packet = build_preflight_packet(tree)
    assert TARGET_ONLY, "the target-only set is empty, so this asserts nothing"
    for precondition, answered_by in TARGET_ONLY.items():
        result = packet.of(precondition)
        assert result.finding is Finding.UNKNOWN, precondition
        assert result.detail == answered_by
        assert result.detail.strip(), precondition


def test_the_packet_has_no_ready_verdict() -> None:
    """A read-only packet cannot establish that a host is ready, so the word is
    deliberately absent from the vocabulary rather than reachable and unused."""
    assert "ready" not in {member.value for member in Verdict}


def test_every_precondition_is_reported_and_every_report_is_a_precondition(
    tree: Path,
) -> None:
    """Both directions. A precondition declared and never checked is one nobody
    is answering; a result with no declared precondition cannot be reported."""
    packet = build_preflight_packet(tree)
    reported = {result.precondition for result in packet.results}
    assert reported == set(Precondition)
    assert len(packet.results) == len(Precondition)


# ── non-vacuity, and the read-only constraint ───────────────────────────────


def test_the_unmodified_tree_is_locally_satisfied(tree: Path) -> None:
    """NON-VACUITY for every plant above: a packet that refused unconditionally
    would pass all of them."""
    packet = build_preflight_packet(tree)
    assert packet.verdict is Verdict.LOCALLY_SATISFIED_TARGET_UNVERIFIED
    assert packet.refused == ()
    local = [r for r in packet.results if r.precondition not in TARGET_ONLY]
    assert local, "no locally decidable preconditions, so the verdict means nothing"
    assert all(r.finding is Finding.SATISFIED for r in local)


def test_the_repository_itself_passes_its_own_preflight() -> None:
    """The packet run against the real tree rather than a copy. If this fails,
    the slice is not dispatchable and the plants above were testing a fiction."""
    packet = build_preflight_packet()
    assert packet.verdict is Verdict.LOCALLY_SATISFIED_TARGET_UNVERIFIED, [
        (r.precondition.value, r.finding.value, r.detail) for r in packet.refused
    ]


def test_the_packet_contacts_nothing(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """READ-ONLY, enforced rather than described.

    Every outbound socket is made to raise. A packet that resolved a secret,
    dialled OpenBao or opened the database would fail here rather than in an
    incident review, and the answer must be identical to the one produced with
    the network available.
    """
    import socket

    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the preflight packet opened a socket")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)

    with_network = build_preflight_packet(tree).verdict
    assert with_network is Verdict.LOCALLY_SATISFIED_TARGET_UNVERIFIED
