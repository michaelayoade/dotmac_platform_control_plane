"""Compare an accepted descriptor with a catalogue capture, in BOTH directions.

## Why both directions, and why the second one is the point

A conformance check almost always asks one question: *does everything the
declaration names exist?* That question is blind to the failure that actually
happened here. The bootstrap CREATED `mod_deploy` and applied two revisions the
descriptor did not mention; every declared schema still existed, every declared
head was still an ancestor of an applied one, and a declared-only check would
have reported green on a database that had moved out from under its contract.

So a finding has a DIRECTION:

* `DECLARED_ABSENT` — the descriptor names something the database does not have.
  A deployment that half-ran, a restore that lost an object, a declaration
  written ahead of its migration.
* `PRESENT_UNDECLARED` — the database holds something no declaration names. An
  operation that advanced the database without promoting a descriptor, a manual
  change, a module composed on the target and nowhere else.

Privileges fold onto the same axis rather than getting a third direction, and
the fold is exact: a role that HOLDS a privilege the descriptor denies is an
ability nobody declared (`PRESENT_UNDECLARED`), and a role that LACKS one the
descriptor permits is a declared capability the database does not have
(`DECLARED_ABSENT`). Reading a broken seal and an over-revoked role as the same
kind of finding would lose the distinction between "it can do more than we said"
and "it can do less than it needs".

## What it does NOT compare, stated rather than implied

Only the database half. `[image]`, `[assembly]` and `[roles]` describe the
running application, and a catalogue capture is not evidence about any of them —
the image digest comes from the container, the manifest digest from the composed
assembly. Those halves advance on different events, which is exactly how this
descriptor came to be half true (ADR-0017 § 8), so the check names its scope
instead of letting a green result imply more than it examined.

## Vacuity

A comparison that examined nothing returns no findings, which is also what a
conforming database returns. `DriftReport.compared` carries how many subjects of
each kind were actually put side by side, so the two are distinguishable by the
caller and in the CLI's own output — a report with `schemas: 0` is not a pass.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

#: Keys the capture must carry for this comparison to mean anything. A capture
#: missing one is INCOMPLETE EVIDENCE, never a clean report: treating an absent
#: key as an empty list would turn a truncated capture into a green verdict, and
#: `effective_schema_privileges` is exactly the key whose silent absence would
#: make every isolation claim pass.
CAPTURE_KEYS: Final[tuple[str, ...]] = (
    "schemas",
    "migration_heads",
    "roles",
    "effective_privileges",
    "effective_schema_privileges",
)


class IncompleteCapture(ValueError):
    """The capture cannot answer the question. No verdict is computed."""


class Direction(StrEnum):
    """Which side of the comparison holds the thing the other does not."""

    DECLARED_ABSENT = "declared_but_absent"
    PRESENT_UNDECLARED = "present_but_undeclared"


class Subject(StrEnum):
    """What kind of thing the finding is about."""

    SCHEMA = "schema"
    MIGRATION_HEAD = "migration_head"
    ROLE = "role"
    PRIVILEGE = "privilege"


@dataclass(frozen=True, slots=True, order=True)
class Finding:
    """One disagreement, in one direction, about one identity."""

    subject: Subject
    direction: Direction
    identity: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "subject": str(self.subject),
            "direction": str(self.direction),
            "identity": self.identity,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Every disagreement, plus what was compared to find them."""

    findings: tuple[Finding, ...]
    compared: Mapping[Subject, int]

    @property
    def clean(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "compared": {
                str(subject): count for subject, count in self.compared.items()
            },
            "findings": [finding.as_dict() for finding in sorted(self.findings)],
        }


def _strings(value: object, *, what: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise IncompleteCapture(f"{what} is not a list")
    return tuple(str(item) for item in value)


def _mappings(value: object, *, what: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise IncompleteCapture(f"{what} is not a list")
    out: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise IncompleteCapture(f"{what} holds a non-object entry")
        out.append({str(key): item[key] for key in item})
    return tuple(out)


def _database(descriptor: Mapping[str, object]) -> Mapping[str, object]:
    section = descriptor.get("database")
    if not isinstance(section, Mapping):
        raise IncompleteCapture(
            "the descriptor carries no [database] contract, so there is nothing "
            "to compare a catalogue against"
        )
    return {str(key): section[key] for key in section}


def _migration(descriptor: Mapping[str, object]) -> Mapping[str, object]:
    section = descriptor.get("migration")
    if not isinstance(section, Mapping):
        raise IncompleteCapture("the descriptor carries no [migration] section")
    return {str(key): section[key] for key in section}


def _require_capture(capture: Mapping[str, object]) -> None:
    missing = [key for key in CAPTURE_KEYS if key not in capture]
    if missing:
        raise IncompleteCapture(
            "the catalogue capture is missing "
            + ", ".join(missing)
            + ". An absent key is not an empty one: reading it as empty would "
            "turn a truncated capture into a clean report."
        )


def _set_findings(
    *,
    subject: Subject,
    declared: Iterable[str],
    present: Iterable[str],
    declared_absent_detail: str,
    present_undeclared_detail: str,
) -> list[Finding]:
    """Both directions of one set comparison, computed the same way each time."""
    declared_set = set(declared)
    present_set = set(present)
    findings = [
        Finding(subject, Direction.DECLARED_ABSENT, name, declared_absent_detail)
        for name in sorted(declared_set - present_set)
    ]
    findings += [
        Finding(subject, Direction.PRESENT_UNDECLARED, name, present_undeclared_detail)
        for name in sorted(present_set - declared_set)
    ]
    return findings


def _effective(
    capture: Mapping[str, object],
) -> dict[tuple[str, str, str], bool]:
    """`(role, scope, identity, privilege) -> holds`, over both privilege scopes.

    Table and schema readings are merged the way the recovery bundle merges
    them, because they answer the same question — what a role can ACTUALLY do —
    and `information_schema`'s direct-grant view answers a different one that an
    isolation gate must not be built on.
    """
    holds: dict[tuple[str, str, str], bool] = {}
    for key in ("effective_privileges", "effective_schema_privileges"):
        for fact in _mappings(capture[key], what=key):
            holds[
                (
                    str(fact.get("role", "")),
                    str(fact.get("identity", "")),
                    str(fact.get("privilege", "")).upper(),
                )
            ] = bool(fact.get("holds"))
    return holds


def _isolation_findings(
    database: Mapping[str, object],
    holds: Mapping[tuple[str, str, str], bool],
) -> tuple[list[Finding], int]:
    entries = database.get("isolation", ())
    findings: list[Finding] = []
    compared = 0
    for entry in _mappings(entries, what="[[database.isolation]]"):
        role = str(entry.get("role", ""))
        code = str(entry.get("code", ""))
        denied = bool(entry.get("denied"))
        objects = _strings(entry.get("objects", ()), what=f"{code}.objects")
        privileges = _strings(entry.get("privileges", ()), what=f"{code}.privileges")
        for identity in objects:
            for privilege in privileges:
                name = f"{role} {privilege} on {identity}"
                observed = holds.get((role, identity, privilege.upper()))
                if observed is None:
                    # Unobserved is DECLARED_ABSENT, never a quiet pass. The
                    # declaration names a role/object pair the capture has no
                    # reading for, so the claim is unsupported rather than met.
                    findings.append(
                        Finding(
                            Subject.PRIVILEGE,
                            Direction.DECLARED_ABSENT,
                            name,
                            f"{code}: the capture carries no effective-privilege "
                            "reading for this role and object",
                        )
                    )
                    continue
                compared += 1
                if denied and observed:
                    findings.append(
                        Finding(
                            Subject.PRIVILEGE,
                            Direction.PRESENT_UNDECLARED,
                            name,
                            f"{code}: the descriptor denies this privilege and "
                            "the role effectively holds it",
                        )
                    )
                elif not denied and not observed:
                    findings.append(
                        Finding(
                            Subject.PRIVILEGE,
                            Direction.DECLARED_ABSENT,
                            name,
                            f"{code}: the descriptor requires this privilege and "
                            "the role does not effectively hold it",
                        )
                    )
    return findings, compared


def compare(
    descriptor: Mapping[str, object], capture: Mapping[str, object]
) -> DriftReport:
    """Every disagreement between a descriptor's database half and a capture.

    Neither argument is read from anywhere by this function: the descriptor is
    parsed TOML the caller supplied and the capture is JSON the caller obtained
    from the target. Nothing here opens a connection.
    """
    _require_capture(capture)
    database = _database(descriptor)
    migration = _migration(descriptor)

    declared_schemas = _strings(
        database.get("expected_schemas", ()), what="database.expected_schemas"
    )
    present_schemas = _strings(capture["schemas"], what="capture.schemas")
    declared_heads = _strings(
        migration.get("expected_heads", ()), what="migration.expected_heads"
    )
    present_heads = _strings(capture["migration_heads"], what="capture.migration_heads")

    # Superusers are excluded on BOTH sides. The descriptor deliberately carries
    # no superuser — the recovery bundle refuses to hold one, because a cluster
    # owner is not part of a product's role closure — so comparing against a
    # capture that includes it would report the cluster owner as undeclared
    # drift on every run and train a reader to ignore the role section.
    role_facts = _mappings(capture["roles"], what="capture.roles")
    present_roles = tuple(
        str(role.get("name", "")) for role in role_facts if not role.get("superuser")
    )
    declared_roles = tuple(
        str(role.get("name", ""))
        for role in _mappings(database.get("roles", ()), what="[[database.roles]]")
    )

    findings = _set_findings(
        subject=Subject.SCHEMA,
        declared=declared_schemas,
        present=present_schemas,
        declared_absent_detail=(
            "declared in expected_schemas and absent from the database"
        ),
        present_undeclared_detail=(
            "present in the database and named by no expected_schemas entry"
        ),
    )
    findings += _set_findings(
        subject=Subject.MIGRATION_HEAD,
        declared=declared_heads,
        present=present_heads,
        declared_absent_detail="declared in expected_heads and not applied",
        present_undeclared_detail=(
            "applied on the target and named by no expected_heads entry"
        ),
    )
    findings += _set_findings(
        subject=Subject.ROLE,
        declared=declared_roles,
        present=present_roles,
        declared_absent_detail=(
            "declared in [[database.roles]] and absent from the cluster"
        ),
        present_undeclared_detail=(
            "a non-superuser role in the cluster that no [[database.roles]] entry "
            "declares"
        ),
    )
    isolation_findings, privileges_compared = _isolation_findings(
        database, _effective(capture)
    )
    findings += isolation_findings

    return DriftReport(
        findings=tuple(sorted(findings)),
        compared={
            Subject.SCHEMA: len(set(declared_schemas) | set(present_schemas)),
            Subject.MIGRATION_HEAD: len(set(declared_heads) | set(present_heads)),
            Subject.ROLE: len(set(declared_roles) | set(present_roles)),
            Subject.PRIVILEGE: privileges_compared,
        },
    )


__all__ = [
    "CAPTURE_KEYS",
    "Direction",
    "DriftReport",
    "Finding",
    "IncompleteCapture",
    "Subject",
    "compare",
]
