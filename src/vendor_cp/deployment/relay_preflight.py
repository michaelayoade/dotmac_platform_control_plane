"""Read-only preflight for the relay-enablement plan.

What holds here, and what only the target can answer.

Dispatching an authorized execution plan whose preconditions were never checked
is how a cutover discovers, at the one moment it cannot help, that the migration
had not run or the compose file on the host predates the service the plan starts.
This module establishes what is establishable BEFORE dispatch.

## Genuinely read-only, and that is a constraint rather than a description

It opens no socket, connects to no database, resolves no secret and contacts no
host. Every finding below is derived from files in this repository. That is
enforced rather than promised: `tests/architecture/test_relay_preflight.py`
drives the packet with the network and the database runtime made unavailable,
and it must produce the same answer.

Consequently it cannot tell you the deployment will succeed. It can tell you
which preconditions are already false — and those are worth knowing before a
signed plan is dispatched rather than after.

## Three findings, because two would force a lie

`SATISFIED`, `REFUSED`, `UNKNOWN`. The third exists because a precondition that
could not be read is not a precondition that was met, and a packet with only two
findings has to call one of those the other. Every preflight this programme has
found broken was broken in exactly that way.

## Two classes of precondition, separated by WHO CAN ANSWER

* **Locally decidable** — the descriptor, the compose file, the migration
  lineage, the material declarations. This repository holds the whole truth, so
  the finding is `SATISFIED` or `REFUSED` and never `UNKNOWN` unless a file
  could not be read.
* **Target-only** — whether the OpenBao record exists, whether the role has a
  credential, whether the migration is applied there, whether the host's compose
  file is this one, whether anything is queued to settle. This repository cannot
  see any of it, so each is `UNKNOWN` **by construction** and carries who can
  answer it.

Collapsing the two would be the defect. A packet that reported `READY` from
local files alone would be asserting facts about a host it has never contacted,
and a packet that reported `REFUSED` for them would be indistinguishable from
one that had found something actually wrong.

So the verdict vocabulary has no `READY`. The best available answer is
`LOCALLY_SATISFIED_TARGET_UNVERIFIED`, and the target-only list is not a caveat
attached to it — it IS the remaining work, enumerated.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final

__all__ = [
    "Finding",
    "Precondition",
    "PreflightPacket",
    "PreflightResult",
    "TARGET_ONLY",
    "Verdict",
    "build_preflight_packet",
]

#: Repository root, resolved from this module rather than from a caller's cwd.
_ROOT: Final = Path(__file__).resolve().parents[3]

_DISPATCHER_ROLE: Final = "platform_outbox_dispatcher"
_DISPATCHER_MATERIAL: Final = "VENDOR_RELAY_DISPATCHER_DATABASE_URL"
_DISPATCHER_ENV: Final = "VENDOR_DB_DISPATCHER_PASSWORD"
_SECRET_PATH: Final = "secret/dotmac/vendor-control-plane/production/relay-dispatcher"
_HEARTBEAT_REVISION: Final = "v019_relay_heartbeat"


class Finding(StrEnum):
    """What one precondition's check concluded."""

    SATISFIED = "satisfied"
    REFUSED = "refused"
    #: Could not be established from here. NEVER a synonym for satisfied.
    UNKNOWN = "unknown"


class Precondition(StrEnum):
    """The closed vocabulary. A precondition not named here is not checked, and
    a check with no name here cannot be reported — both directions matter."""

    # ── locally decidable ───────────────────────────────────────────────────
    ACCEPTED_DESCRIPTOR_IS_A_PROMOTED_CANDIDATE = (
        "accepted_descriptor_is_a_promoted_candidate"
    )
    DESCRIPTOR_DECLARES_THE_RELAY_ROLE = "descriptor_declares_the_relay_role"
    DESCRIPTOR_DECLARES_THE_DISPATCHER_MATERIAL = (
        "descriptor_declares_the_dispatcher_material"
    )
    DESCRIPTOR_HEAD_IS_THE_HEARTBEAT_REVISION = (
        "descriptor_head_is_the_heartbeat_revision"
    )
    COMPOSE_DECLARES_THE_RELAY_SERVICE = "compose_declares_the_relay_service"
    ONLY_THE_RELAY_HOLDS_THE_DISPATCHER_MATERIAL = (
        "only_the_relay_holds_the_dispatcher_material"
    )
    DISPATCHER_MATERIAL_IS_A_POINTER_ONLY = "dispatcher_material_is_a_pointer_only"
    OPENBAO_PATH_IS_A_DECLARED_RECORD = "openbao_path_is_a_declared_record"
    HEARTBEAT_MIGRATION_GRANTS_THE_DISPATCHER_NOTHING = (
        "heartbeat_migration_grants_the_dispatcher_nothing"
    )

    # ── target-only ─────────────────────────────────────────────────────────
    OPENBAO_RECORD_EXISTS = "openbao_record_exists"
    DATABASE_ROLE_HAS_A_CREDENTIAL = "database_role_has_a_credential"
    HEARTBEAT_MIGRATION_IS_APPLIED_ON_THE_TARGET = (
        "heartbeat_migration_is_applied_on_the_target"
    )
    TARGET_COMPOSE_CARRIES_THE_RELAY_SERVICE = (
        "target_compose_carries_the_relay_service"
    )
    AN_OUTBOX_EVENT_EXISTS_TO_SETTLE = "an_outbox_event_exists_to_settle"


#: Preconditions this repository structurally cannot answer, each with WHO can.
#:
#: Declared as data rather than discovered, so a check that starts answering one
#: of these locally is a visible edit here. A local answer to a target question
#: is the exact defect this split exists to prevent: it would be an assertion
#: about a host nothing had contacted.
TARGET_ONLY: Final[dict[Precondition, str]] = {
    Precondition.OPENBAO_RECORD_EXISTS: (
        "OpenBao. Read the record's existence and field set; never its value."
    ),
    Precondition.DATABASE_ROLE_HAS_A_CREDENTIAL: (
        "The target database. `pg_authid.rolpassword IS NOT NULL` for "
        f"{_DISPATCHER_ROLE}, or an authenticated connection attempt. Never a "
        "value comparison."
    ),
    Precondition.HEARTBEAT_MIGRATION_IS_APPLIED_ON_THE_TARGET: (
        f"The target database. `{_HEARTBEAT_REVISION}` present in "
        "`alembic_version`. Without it every heartbeat write fails and health "
        "reports a stopped relay about a relay that is running."
    ),
    Precondition.TARGET_COMPOSE_CARRIES_THE_RELAY_SERVICE: (
        "The target host. The deployed compose file must be the one declaring "
        "the `relay` service, or starting it names a service that does not "
        "exist."
    ),
    Precondition.AN_OUTBOX_EVENT_EXISTS_TO_SETTLE: (
        "The target database, and an operator decision. Verification requires "
        "one real settlement, and nothing is queued: an emitting operation must "
        "be chosen first. Inserting a row by hand would verify the relay "
        "against a fact no owner emitted."
    ),
}


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """One precondition and what was concluded about it."""

    precondition: Precondition
    finding: Finding
    #: Why, in one line. Free text is acceptable HERE and nowhere that a value
    #: could reach: this packet is read by an operator before dispatch, it
    #: carries no secret, and a refusal that cannot say what is wrong sends its
    #: reader round the loop once per precondition.
    detail: str


class Verdict(StrEnum):
    """The packet's overall answer. There is deliberately no `READY`.

    A read-only packet cannot establish that a host is ready; the best true
    statement it can make is that everything IT can decide is decided and the
    rest is named.
    """

    #: Something is actually wrong, here, now. Do not dispatch.
    REFUSED = "refused"
    #: Every local precondition holds; the target-only ones remain open.
    LOCALLY_SATISFIED_TARGET_UNVERIFIED = "locally_satisfied_target_unverified"
    #: A local precondition could not be read. Not a pass.
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class PreflightPacket:
    """Every precondition, its finding, and the one verdict over them."""

    verdict: Verdict
    results: tuple[PreflightResult, ...] = field(default_factory=tuple)

    def of(self, precondition: Precondition) -> PreflightResult:
        for result in self.results:
            if result.precondition is precondition:
                return result
        raise KeyError(precondition)

    @property
    def refused(self) -> tuple[PreflightResult, ...]:
        return tuple(r for r in self.results if r.finding is Finding.REFUSED)

    @property
    def unknown(self) -> tuple[PreflightResult, ...]:
        return tuple(r for r in self.results if r.finding is Finding.UNKNOWN)


def _read(root: Path, relative: str) -> str | None:
    """File text, or `None` if it could not be read. `None` becomes UNKNOWN,
    never a refusal: a file this packet cannot open is a packet that does not
    know, and reporting that as a violation would be a false accusation."""
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError:
        return None


def _check_promoted(root: Path) -> PreflightResult:
    accepted = _read(root, "deploy/product.toml")
    ledger_text = _read(root, "deploy/descriptor-promotions.json")
    where = Precondition.ACCEPTED_DESCRIPTOR_IS_A_PROMOTED_CANDIDATE
    if accepted is None or ledger_text is None:
        return PreflightResult(
            where, Finding.UNKNOWN, "descriptor or ledger unreadable"
        )
    try:
        promotions = json.loads(ledger_text)["promotions"]
        candidate = promotions[-1]["candidate"]
    except (ValueError, KeyError, IndexError):
        return PreflightResult(where, Finding.UNKNOWN, "ledger could not be parsed")
    if candidate is None:
        return PreflightResult(
            where, Finding.REFUSED, "the last promotion names no candidate"
        )
    bytes_ = _read(root, candidate)
    if bytes_ is None:
        return PreflightResult(
            where, Finding.UNKNOWN, f"candidate {candidate} unreadable"
        )
    if bytes_ != accepted:
        return PreflightResult(
            where,
            Finding.REFUSED,
            "the accepted descriptor is not its candidate byte for byte",
        )
    return PreflightResult(where, Finding.SATISFIED, f"promoted from {candidate}")


def _descriptor(root: Path) -> dict[str, object] | None:
    text = _read(root, "deploy/product.toml")
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def _check_descriptor(root: Path) -> list[PreflightResult]:
    document = _descriptor(root)
    checks = (
        Precondition.DESCRIPTOR_DECLARES_THE_RELAY_ROLE,
        Precondition.DESCRIPTOR_DECLARES_THE_DISPATCHER_MATERIAL,
        Precondition.DESCRIPTOR_HEAD_IS_THE_HEARTBEAT_REVISION,
    )
    if document is None:
        return [
            PreflightResult(check, Finding.UNKNOWN, "descriptor unreadable")
            for check in checks
        ]

    roles = document.get("roles", [])
    relay = next(
        (
            r
            for r in (roles if isinstance(roles, list) else [])
            if isinstance(r, dict) and r.get("code") == "relay"
        ),
        None,
    )
    if relay is None:
        role_result = PreflightResult(
            checks[0], Finding.REFUSED, "no [[roles]] entry with code 'relay'"
        )
    elif _DISPATCHER_MATERIAL not in tuple(relay.get("materials", ())):
        role_result = PreflightResult(
            checks[0],
            Finding.REFUSED,
            f"the relay role does not list {_DISPATCHER_MATERIAL} in its materials",
        )
    else:
        role_result = PreflightResult(
            checks[0], Finding.SATISFIED, "declared, with its dispatcher material"
        )

    materials = document.get("runtime_materials", {})
    names = tuple(materials.get("names", ())) if isinstance(materials, dict) else ()
    material_result = PreflightResult(
        checks[1],
        Finding.SATISFIED if _DISPATCHER_MATERIAL in names else Finding.REFUSED,
        f"{_DISPATCHER_MATERIAL} in [runtime_materials].names",
    )

    migration = document.get("migration", {})
    heads = (
        tuple(migration.get("expected_heads", ()))
        if isinstance(migration, dict)
        else ()
    )
    head_result = PreflightResult(
        checks[2],
        Finding.SATISFIED if _HEARTBEAT_REVISION in heads else Finding.REFUSED,
        f"{_HEARTBEAT_REVISION} in [migration].expected_heads",
    )
    return [role_result, material_result, head_result]


def _check_compose(root: Path) -> list[PreflightResult]:
    text = _read(root, "docker-compose.production.yml")
    declared = Precondition.COMPOSE_DECLARES_THE_RELAY_SERVICE
    only = Precondition.ONLY_THE_RELAY_HOLDS_THE_DISPATCHER_MATERIAL
    if text is None:
        return [
            PreflightResult(declared, Finding.UNKNOWN, "compose file unreadable"),
            PreflightResult(only, Finding.UNKNOWN, "compose file unreadable"),
        ]
    if "\n  relay:\n" not in text:
        return [
            PreflightResult(declared, Finding.REFUSED, "no `relay` service"),
            PreflightResult(
                only, Finding.UNKNOWN, "no `relay` service to compare against"
            ),
        ]
    relay_block = text.split("\n  relay:\n", 1)[1].split("\n  ops:\n", 1)[0]
    if _DISPATCHER_MATERIAL not in relay_block:
        first = PreflightResult(
            declared, Finding.REFUSED, "the relay service declares no dispatcher DSN"
        )
    else:
        first = PreflightResult(declared, Finding.SATISFIED, "declared with its DSN")

    # Every OTHER service must not carry it. Co-hosting the dispatcher
    # credential would put a lease-and-settle credential in a request-serving
    # process, which is the reason the relay is a separate role at all.
    elsewhere = text.replace(relay_block, "")
    second = PreflightResult(
        only,
        Finding.SATISFIED if _DISPATCHER_MATERIAL not in elsewhere else Finding.REFUSED,
        "no other service carries the dispatcher DSN",
    )
    return [first, second]


def _check_pointer_only(root: Path) -> PreflightResult:
    """No committed file may ASSIGN the dispatcher password a value."""
    where = Precondition.DISPATCHER_MATERIAL_IS_A_POINTER_ONLY
    sources = (
        "docker-compose.production.yml",
        ".env.production.example",
        "deploy/product.toml",
        "deploy/descriptor-promotions.json",
    )
    unread: list[str] = []
    offenders: list[str] = []
    for relative in sources:
        text = _read(root, relative)
        if text is None:
            unread.append(relative)
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if _DISPATCHER_ENV not in line:
                continue
            stripped = line.strip()
            if stripped.startswith("#") or "${" in line:
                continue
            if "=" in stripped and stripped.partition("=")[2].strip():
                offenders.append(f"{relative}:{number}")
    if offenders:
        return PreflightResult(
            where, Finding.REFUSED, f"a value is assigned at {', '.join(offenders)}"
        )
    if unread:
        return PreflightResult(
            where, Finding.UNKNOWN, f"unreadable: {', '.join(unread)}"
        )
    return PreflightResult(where, Finding.SATISFIED, "every occurrence is a reference")


def _check_secret_path(root: Path) -> PreflightResult:
    where = Precondition.OPENBAO_PATH_IS_A_DECLARED_RECORD
    text = _read(root, "src/vendor_cp/production_secrets.py")
    if text is None:
        return PreflightResult(
            where, Finding.UNKNOWN, "production_secrets.py unreadable"
        )
    if _SECRET_PATH not in text:
        return PreflightResult(
            where, Finding.REFUSED, "the relay-dispatcher path is not a declared record"
        )
    return PreflightResult(where, Finding.SATISFIED, _SECRET_PATH)


def _check_migration_grants(root: Path) -> PreflightResult:
    """`v019` must grant the dispatcher NOTHING.

    The dispatcher's whole isolation is that it holds EXECUTE on two kernel
    functions and no table privilege of any kind. A heartbeat table that granted
    it access would erode that for the convenience of one write.
    """
    where = Precondition.HEARTBEAT_MIGRATION_GRANTS_THE_DISPATCHER_NOTHING
    text = _read(root, f"alembic/versions/{_HEARTBEAT_REVISION}.py")
    if text is None:
        return PreflightResult(
            where, Finding.UNKNOWN, "the migration could not be read"
        )
    granting = [
        line.strip()
        for line in text.splitlines()
        if "GRANT" in line and _DISPATCHER_ROLE in line
    ]
    if granting:
        return PreflightResult(
            where, Finding.REFUSED, f"{len(granting)} grant(s) to {_DISPATCHER_ROLE}"
        )
    return PreflightResult(where, Finding.SATISFIED, "no grant to the dispatcher")


def build_preflight_packet(root: Path | None = None) -> PreflightPacket:
    """Every precondition, decided from files alone.

    `root` is injected so a test can point the packet at a planted tree; it
    defaults to this repository. Nothing here opens a socket or a database.
    """
    base = root if root is not None else _ROOT
    results: list[PreflightResult] = [
        _check_promoted(base),
        *_check_descriptor(base),
        *_check_compose(base),
        _check_pointer_only(base),
        _check_secret_path(base),
        _check_migration_grants(base),
        *(
            PreflightResult(precondition, Finding.UNKNOWN, answered_by)
            for precondition, answered_by in TARGET_ONLY.items()
        ),
    ]
    local = [r for r in results if r.precondition not in TARGET_ONLY]
    if any(r.finding is Finding.REFUSED for r in local):
        verdict = Verdict.REFUSED
    elif any(r.finding is Finding.UNKNOWN for r in local):
        verdict = Verdict.INCOMPLETE
    else:
        verdict = Verdict.LOCALLY_SATISFIED_TARGET_UNVERIFIED
    return PreflightPacket(verdict=verdict, results=tuple(results))
