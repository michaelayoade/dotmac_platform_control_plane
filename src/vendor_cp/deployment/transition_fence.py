"""Fence every writer role off a database, hold the fence, then release it.

Today `scripts/deploy_production.sh` backs up, migrates, then replaces the
relay and the app WHILE the old writers stay connected (deploy_production.sh
lines 438, 446-447). A backend that opens between the backup and the schema
change observes a database mid-migration and can write through it. D16 fences
every writer role for the whole transition; PR 2 wires that fence into the
deploy script's maintenance window. This module is that fence, on its own: a
pure library over a caller-supplied connection, no process and no environment
access.

## Why REVOKE CONNECT rather than a lock or a flag

A row-level flag only stops writers that check it. `REVOKE CONNECT ON
DATABASE ... FROM <role>` stops a NEW backend from authenticating as that role
against this database at all, independently of what the application does or
does not check, and `has_database_privilege` lets the fence PROVE the revoke
took rather than merely issuing it and hoping. A backend already connected
when the fence closes is a separate hazard REVOKE CONNECT does not touch,
which is why `fence_writers` also terminates and waits for every open writer
session.

## The connection must be AUTOCOMMIT

On a transactional connection the REVOKE is invisible to every OTHER backend
until this connection commits, and a rollback silently erases the fence while
a `FenceProof` claiming otherwise still exists. `fence_writers` and
`restore_writers` both refuse (`connection_not_autocommit`) before touching
anything unless the DRIVER connection's own `autocommit` flag is True
(`Connection.get_isolation_level()` is not used: it reports the server's
isolation level, which still reads "read committed" under autocommit).

## D1: the owner topology

`conn` is the database owner or a superuser, on both `fence_writers` and
`restore_writers`: the ACL work — REVOKE/GRANT CONNECT, `aclexplode`,
`pg_auth_members`, `has_database_privilege`, `pg_stat_activity` reads — needs
no privilege beyond that (`_require_owner_member_or_superuser`, checked
before any change on both entry points). Terminating another role's open
backends is a SEPARATE privilege ownership does not grant, so it never rides
`conn`: it goes through the `Terminator` seam instead (`None` for the default
`pg_terminate_backend` adapter over `conn` itself, or a caller-supplied
no-argument callable — see `Terminator`'s own docstring for that seam's lower
and upper bounds). This is the "D1 topology" the `Terminator` docstring and
the grantor-preservation comments elsewhere in this module refer to: one
owner-privileged connection for every ACL read/write, one separately
privileged (and separately untrusted) channel for termination.

## Two required bindings a restore must present: `database` and `fence_id`

`restore_writers` never trusts a `FenceProof` on its own claimed content
alone. It requires the caller to also state, out of band, which database the
proof should apply to (`database`) and which run this restore is completing
(`expected_fence_id`), and refuses `PROOF_MISMATCH` — checked first, before
`_require_owner_member_or_superuser` and before every other query that
depends on the proof, and so before any GRANT — unless `database ==
proof.database` and `expected_fence_id == proof.fence_id`. A caller holding a
stale or misdirected proof (one for a different database, or one from a
superseded fencing run against the same database — a replay) is refused
rather than silently restoring the wrong ACL under the wrong run's authority.

Every `FenceProof` therefore also carries `fence_id`: a non-empty,
caller-supplied run identifier `fence_writers` requires and records,
refusing `PROOF_INVALID` if it is empty or unsafe. A re-fence with `prior=`
records the NEW caller's `fence_id` on the resulting proof, never the prior
proof's (whose own `fence_id` must itself be non-empty, or `fence_writers`
refuses `PROOF_INVALID`). The wire form (`to_document`/`from_document`)
treats `fence_id` as a required key that must be non-empty, free of NUL bytes
and lone surrogates, free of leading or trailing whitespace, and at most 128
characters — the identical discipline every other identifier on this proof
already gets, and, like `digest()`, only a defence when `expected_fence_id`
itself crossed a trust boundary the proof's own channel does not control.

`restore_writers`'s remaining pre-checks, run in order after both bindings
above have been proven, are unchanged by this: re-deriving live membership
against `proof.member_roles` (`PROOF_MISMATCH` on drift), then bounding
`to_add` (the entries this call would actually GRANT) to a CONNECT grant made
by the database's CURRENT owner to an effective role or PUBLIC — never
checked against the whole of `prior_grants`, only the entries this call would
act on (see "The prior ACL is the thing being protected" below for why a
restore must never refuse an ACL `fence_writers` itself already accepted).

## The prior ACL is the thing being protected, not the fence's own state

`restore_writers` puts the database back to EXACTLY the ACL that was there
before the fence closed — never a hardcoded default, and never "whatever
GRANT CONNECT TO PUBLIC would produce" — because a database's prior ACL can
carry privileges (CREATE, TEMPORARY, a narrower grant to a third role) this
module never touched and has no business re-deriving. Re-fencing an
already-fenced database (`fence_writers(..., prior=proof)`) keeps that same
original ACL rather than recording the already-revoked one as "prior",
because the second call's own view of `pg_database.datacl` is the fence's own
handiwork, not evidence about what the database looked like before anyone
fenced it. A `prior=` a caller passes is bound, and the binding has two
layers. First, identity: `prior` must name the same database and the same
fenced-role set this call resolved, or `fence_writers` refuses
(`prior_mismatch`) before any change — a mismatched `prior` would let one
database's proof restore a different one's ACL. Second, content: the live
ACL this call is about to re-fence must be a SUBSET of `prior.prior_grants`
(nothing currently granted may be silently missing from what `prior` claims
the original ACL was), and every entry `prior` claims BEYOND that live
subset must be a CONNECT grant to an effective role or PUBLIC made by the
database's CURRENT owner — the identical bound `restore_writers` applies to
what it is about to GRANT. A `prior=` that fails either layer is refused
(`prior_mismatch`) before any change; a caller cannot smuggle an arbitrary
grant back into circulation by wrapping it in a `prior=` a later restore
would otherwise trust.

## The ACL is compared as decomposed grants, GRANTOR INCLUDED, never as text

`pg_database.datacl::text` is PostgreSQL's own rendering, and a grantee that
needs quoting (a capital letter, a space, a literal `,` `=` or `/`) renders
quoted in ways that are easy to mis-parse by hand. Every comparison in this
module instead reads `aclexplode()` — the server's own decomposition of the
ACL into `(grantee, privilege_type, is_grantable, grantor)` rows, with
PUBLIC's grantee oid (0) resolved to `""` — and compares frozensets of that
4-tuple. `FenceProof.prior_acl` keeps the raw text for the human record, but
nothing compares it. Ruled 2026-09-27: the grantor is part of the comparison,
not dropped from it — see "Grantor-exact restore" below for why a grant whose
grantor differs from the owner cannot be fenced or restored faithfully at
all, and is refused before either happens.

## Unknown is not absent

A writer role named in `WRITER_ROLES` that does not exist in this cluster is
recorded in `FenceProof.absent_roles`, never silently dropped from the roles
the fence reports on. A role that exists and keeps CONNECT is a fence that did
not hold; a role that was never there is a different fact, and collapsing the
two would let a typo'd role name pass as "fenced" when nothing was ever
checked.

## The effective set: a writer's own members are fenced too

`WRITER_ROLES` names login roles, but PostgreSQL role membership is
transitive: a role M that is a member of a fenced writer W can `SET ROLE W`
from an already-open session and keep writing, and if M holds its own CONNECT
grant it can reconnect on its own identity regardless of what happens to W's.
Ruled 2026-09-27: `fence_writers` resolves the EFFECTIVE set once, after the
named writers are resolved against the cluster — every role that is a
(transitive) member of a fenced writer, found by walking `pg_auth_members`
explicitly (`_member_roles`), never `pg_has_role(r, w, 'MEMBER')`: that
built-in answers true for EVERY superuser against every role, which would
pull `postgres` itself into the effective set of any fence in this cluster
and refuse it as a shared writer role. A superuser that was actually
GRANTed a writer role is still found by the explicit `pg_auth_members` walk,
and is refused as it should be. The members found this way are recorded on
`FenceProof.member_roles` (never silently dropped, the same
`absent_roles` discipline as unknown roles). Every pre-check (superuser,
shared identity with `MIGRATION_ROLE`, inherited CONNECT), the REVOKE, the
`has_database_privilege` verification and the drain all run over this
effective set, not only the named writers. `restore_writers` re-derives the
same effective set from `fenced_roles + member_roles` on the proof, so
`allowed_grantees` and a `prior=` binding both cover it too.

## Grantor-exact restore

An owner-or-superuser `REVOKE CONNECT ON DATABASE ... FROM <role>` only ever
removes grants whose recorded GRANTOR is the owner — a grant some other role
made (holding its own GRANT OPTION) survives that REVOKE untouched, and if it
did not, `restore_writers` could not recreate it afterwards with its original
grantor, because a GRANT this module issues records ITS OWN executing
identity as grantor (the owner, when that identity is a superuser — see the
grantor-preservation test). Ruled 2026-09-27: before any change,
`fence_writers` requires every CONNECT grant held by an effective role or by
PUBLIC to have the database owner as grantor, and refuses
(`grant_not_owner_granted`) otherwise, naming the grantee and the actual
grantor. `restore_writers` compares the full 4-tuple, grantor included, so
"restored exactly" means the grantor too.

## Inherited CONNECT cannot be revoked away, so it is refused up front

`REVOKE CONNECT ON DATABASE ... FROM <role>` only ever touches that role's own
ACL entry. `has_database_privilege` still resolves role membership and
ownership when it answers "can this role connect" — PostgreSQL grants a
database's owner (and every member of the owner) an implicit CONNECT that no
`REVOKE` on the database's ACL removes, and a role that is a member of another
role holding CONNECT keeps it through that membership regardless of what its
own ACL entry says. Ruled 2026-09-26: a writer that is the database owner, a
member of the owner, or a member of `MIGRATION_ROLE` cannot be fenced by
revoking, so `fence_writers` REFUSES (`writer_inherits_connect`) before
touching the ACL at all, rather than revoking, "verifying" against a
privilege check that was never going to change, and returning a proof that
lies.

## A writer role sharing identity with the migrator is refused, not fenced

Fencing "the migrator" would defeat the migration it is meant to protect. If a
role named in `WRITER_ROLES` IS `MIGRATION_ROLE`, or the two share role
membership in either direction (`pg_has_role` both ways), there is no ACL
state that fences one without the other — so `fence_writers` refuses
(`shared_writer_role`) before any change, the same as the inherited-CONNECT
case above. The identical check also catches one login role appearing twice
in the writer set after resolution, which is the same hazard by a different
route: revoking and re-granting the same role under two names would race with
itself.

## Every exception after the first ACL change is compensated

Once `_apply_fence` has issued its first REVOKE, any exception at all —
another `FenceRefused`, a driver error, a timeout, `KeyboardInterrupt` — is
caught, the ACL is restored to what this call started from, and only then is
the failure reported. If the compensating restore itself fails, the caller
gets `FenceRefused(COMPENSATION_FAILED)` chained from the original exception,
with `before_acl` set on it, so an operator always holds the exact ACL to
restore by hand rather than a stack trace alone.

## A restore that reopens and then fails re-drains before reporting

`restore_writers` briefly reopens the ACL (issuing its GRANTs) before it can
prove the restore matches `prior_grants` exactly. If that GRANT loop fails
part-way, or the final comparison mismatches, a writer could have reconnected
during that reopened window — so on EITHER path `restore_writers` re-revokes
CONNECT from PUBLIC and every role in the EFFECTIVE set (`_refence`) and then
TERMINATES AND DRAINS that same set again with the caller's
`session_wait_seconds` (the required keyword `restore_writers` takes for
exactly this) before reporting anything. Ruled 2026-09-27: `_refence` acts on
the EFFECTIVE set from the proof — `fenced_roles + member_roles`, the ground
truth of what this fence ever touched — never on the Python list of what this
particular restore attempt happened to grant before failing, since a failure
can leave that list short of the full effective set or empty outright. The
re-revoke is then VERIFIED with `has_database_privilege`, the same discipline
`_apply_fence` uses for the original REVOKE: if PUBLIC or any effective role
still has CONNECT afterwards, that is `COMPENSATION_FAILED`, chained from the
original failure, before the drain is even attempted — only once the
re-fence is verified may anything downstream claim "stays fenced" or
"re-revoked". If the verified re-fence's drain converges, the original
`ACL_NOT_RESTORED` is raised, unchanged. If writers survive the re-drain,
`WRITER_SESSIONS_SURVIVED` is raised instead, chained from the original
failure, naming that the re-fence happened but the drain did not converge. A
non-`FenceRefused` exception from the drain (a driver error, not a timeout)
is wrapped as `COMPENSATION_FAILED` too, chained from the original failure,
rather than escaping raw. `KeyboardInterrupt`/`SystemExit` caught while
restoring are re-raised as themselves once the re-fence-and-redrain attempt
has run, mirroring `fence_writers`. If the re-fence itself raises,
`COMPENSATION_FAILED` is raised, chained from the original failure, carrying
`prior_acl` as the ACL to restore by hand — never a claim that zero writers
remain when that was never re-proven.

## No query after the ACL is restored

Once a mutation has succeeded and every verification it needs has already run
(the drain that confirms zero writer backends; the `_current_grants` compare
against `prior_grants`), `FenceProof.fenced_at` and `UnfenceProof.restored_at`
are stamped with `datetime.now(UTC)` — a local timestamp, never a further
query. A `SELECT now()` at that point would be a non-essential query: one that
could fail for a reason having nothing to do with the fence or restore (a
dropped connection, a statement timeout) and, by raising, flip an outcome that
genuinely succeeded into a reported exception. Every remaining query after a
successful mutation in this module is load-bearing verification (a
`has_database_privilege` check, a drain poll, the post-GRANT
`_current_grants` comparison) — never a courtesy read whose only job was a
timestamp.

## Known limits, carried into PR 2 as inputs — not solved here

- **The startup race.** A backend that has already passed the CONNECT check
  (so it holds an open socket) but has not yet appeared in
  `pg_stat_activity` is invisible to `_writer_pids`, and so to the drain, to
  `fence_is_holding`'s backend check, and to whatever PR 2 does with either.
  The fence proves no writer backend it could SEE was left open; it cannot
  prove one was never mid-authentication when the drain or the
  holding-check ran.
- **Membership is frozen at fence time.** `FenceProof.member_roles` is the
  effective set as `fence_writers` resolved it at that moment; a role
  granted membership in a writer AFTER that moment is invisible to the
  revoke, the verification and the drain that already ran, and is only
  caught later if something re-derives membership (`fence_is_holding` does,
  by comparing a fresh `_member_roles` call against the recorded set). This
  is why PR 2 must call `fence_is_holding` right before AND right after
  migrating — a fence proven to hold at t0 is not evidence it still holds at
  t1.
- **`WRITER_ROLES` completeness is not proven.** This module fences exactly
  the roles it is told about; nothing here derives or verifies that
  `WRITER_ROLES` actually names every role in the cluster capable of writing
  to the database.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import NoResultFound

__all__ = [
    "FENCE_PROOF_SCHEMA",
    "MIGRATION_ROLE",
    "WRITER_ROLES",
    "FenceProof",
    "FenceRefusalCode",
    "FenceRefused",
    "Terminator",
    "UnfenceProof",
    "fence_is_holding",
    "fence_writers",
    "restore_writers",
]


class Terminator(Protocol):
    """A callable that requests termination of every writer backend on the
    fenced database, taking no arguments and returning nothing.

    The production broker re-derives the writer set itself, server-side, over
    its own superuser channel — this module never passes a pid or a role name
    across the seam, because a caller-supplied list is exactly what a
    superuser channel must not accept. The library never trusts a
    terminator's claim that termination happened; its own poll of
    `pg_stat_activity` is the only proof it acts on.

    **The broker's contract has a LOWER bound and an UPPER bound.** The
    production broker's fixed, checked-in statement (no arguments — see the
    module docstring's D1 topology note) must terminate a SUPERSET of every
    EFFECTIVE set this library may ever drain: every named writer role AND
    every role transitively holding membership in one (`_member_roles`),
    scoped to the SAME database this call is fencing — that is the LOWER
    bound, and a broker statement scoped to fewer roles, or to a different
    database, is not a partial defence: it is silently indistinguishable
    from "the broker did nothing this poll", and the drain simply fails safe
    with `WRITER_SESSIONS_SURVIVED` once the deadline passes, exactly as if
    no terminator had been supplied at all.

    The UPPER bound is exactly as strict: the broker's statement must
    terminate ONLY writer and member login roles on the CONFIGURED database
    — NEVER `MIGRATION_ROLE`, and never the fence's own backend (the
    connection `fence_writers`/`restore_writers` themselves are running
    over). A broker statement scoped too WIDE is not merely imprecise — it
    can terminate the very migration the fence exists to protect, or the
    library's own connection mid-drain. PR 2 must test the broker's actual
    statement against BOTH bounds, not only the lower one.

    A `terminator` that raises is never trusted at face value either —
    including a `FenceRefused` it raises itself, which this module re-wraps
    (see `_TerminatorFailed`) so it can never be mistaken for a refusal this
    library produced.

    **The broker must bound its OWN call time.** Python cannot interrupt a
    blocking callable: if `terminator()` itself blocks longer than
    `session_wait_seconds`, this library only notices AFTER the call
    finally returns (see `_request_termination`), by which point the
    deadline it was supposed to respect has already passed. The broker's
    own statement — not this library — is the only thing that can actually
    bound how long a single termination attempt takes.
    """

    def __call__(self) -> None: ...


class _TerminatorFailed(RuntimeError):
    """Wraps ANY exception a caller-supplied `Terminator` raises, `FenceRefused`
    included, before it ever reaches `fence_writers`'/`restore_writers`'
    exception handling.

    A terminator is untrusted code running on the library's behalf: if it
    raised `FenceRefused(FenceRefusalCode.UNKNOWN_DATABASE)` and that
    exception were allowed to propagate as-is, the outer `except
    BaseException` in `fence_writers` would see a genuine-looking
    `FenceRefused` and could report `UNKNOWN_DATABASE` — a code this module
    never actually determined, spoofed by the terminator. Wrapping in a
    private, non-`FenceRefused` type forces the existing compensation path to
    classify the failure itself (as `FENCE_INTERRUPTED` or
    `COMPENSATION_FAILED`), the same treatment any other terminator failure
    gets."""


#: The portable wire schema `FenceProof.to_document()`/`from_document()`
#: read and write. The proof crosses processes as JSON on stdout (PR 2), so
#: this is its only wire form; a document naming any other schema is refused
#: (`FenceRefusalCode.PROOF_INVALID`).
FENCE_PROOF_SCHEMA: Final = "TransitionFenceProof.v1"

#: The long-running application, relay and dispatcher identities (see
#: `docker-compose.production.yml` and the deploy script's role list). Every
#: one of these is a role that can hold an open session against the database
#: while a migration runs.
WRITER_ROLES: Final[tuple[str, ...]] = (
    "app_user",
    "platform_api",
    "platform_outbox_dispatcher",
    "outbox_dispatcher",
)

#: The migrator. Never fenced, and its CONNECT privilege is part of what
#: `fence_writers` verifies rather than merely assumes.
MIGRATION_ROLE: Final = "app_admin"

#: How often to re-poll `pg_stat_activity` while waiting for terminated writer
#: backends to actually disappear.
_POLL_INTERVAL_SECONDS: Final = 0.05

#: The only database privilege types this module's ACL ever holds an
#: opinion about. A `prior_grants` entry naming anything else did not come
#: from a real `aclexplode(pg_database.datacl)` read and is refused by
#: `FenceProof.from_document`.
_KNOWN_DATABASE_PRIVILEGES: Final = frozenset({"CONNECT", "CREATE", "TEMPORARY"})


class FenceRefusalCode(StrEnum):
    """A closed set. Exception messages carry one of these plus role names —
    never a DSN, never a query result beyond a role or database name."""

    WRITER_STILL_HAS_CONNECT = "writer_still_has_connect"
    MIGRATION_ROLE_LOST_CONNECT = "migration_role_lost_connect"
    WRITER_SESSIONS_SURVIVED = "writer_sessions_survived"
    ACL_NOT_RESTORED = "acl_not_restored"
    UNKNOWN_DATABASE = "unknown_database"
    #: A writer owns the database, or is a member of its owner or of
    #: `MIGRATION_ROLE`: CONNECT it holds through that path survives every
    #: REVOKE this module can issue, so nothing is changed and this is raised
    #: instead.
    WRITER_INHERITS_CONNECT = "writer_inherits_connect"
    #: A writer role is `MIGRATION_ROLE` itself, shares role membership with
    #: it in either direction, or the same login role was named twice in the
    #: writer set.
    SHARED_WRITER_ROLE = "shared_writer_role"
    #: `conn` is not AUTOCOMMIT. Checked before any change.
    CONNECTION_NOT_AUTOCOMMIT = "connection_not_autocommit"
    #: `conn`'s `current_user` is not the database owner, a member of the
    #: owner, or a superuser. Checked before any change: any GRANT such a
    #: connection issued would record a grantor `restore_writers` could
    #: never bind against the current owner.
    CONNECTION_NOT_OWNER = "connection_not_owner"
    #: A `prior=` proof named a different database, or a different fenced-role
    #: set, than this call resolved. Checked before any change.
    PRIOR_MISMATCH = "prior_mismatch"
    #: An exception (not itself a `FenceRefused`) interrupted fencing after the
    #: first ACL change; the ACL was successfully restored.
    FENCE_INTERRUPTED = "fence_interrupted"
    #: The compensating restore after an interrupted fence itself failed. The
    #: database may still be fenced; `before_acl` is the ACL to restore by
    #: hand.
    COMPENSATION_FAILED = "compensation_failed"
    #: An effective role or PUBLIC holds a CONNECT grant whose recorded
    #: grantor is not the database owner. An owner/superuser REVOKE cannot
    #: remove such a grant, and a restore could not recreate it with its
    #: original grantor. Checked before any change.
    GRANT_NOT_OWNER_GRANTED = "grant_not_owner_granted"
    #: `FenceProof.from_document` refused a document: the wrong schema,
    #: unknown or missing keys, a wrong type anywhere (including bool-as-int
    #: for `terminated_count`), a negative `terminated_count`, a `fenced_at`
    #: that is not the exact canonical UTC form, a duplicate grant or role, an
    #: unknown privilege, an unsafe (empty/NUL/lone-surrogate) identifier,
    #: `fenced_roles` not a subset of the allowed writer roles, `member_roles`
    #: naming `MIGRATION_ROLE` or overlapping `fenced_roles`, `absent_roles`
    #: overlapping either, or a digest that does not match `expected_digest`.
    #: Fail closed: never construct a `FenceProof` from a document that does
    #: not strictly conform.
    PROOF_INVALID = "proof_invalid"
    #: `restore_writers` refused a structurally-valid `FenceProof` because it
    #: does not match LIVE state: re-deriving `_member_roles` from
    #: `proof.fenced_roles` right now disagrees with `proof.member_roles`, or
    #: an entry this restore would actually need to GRANT (`prior_grants`
    #: minus the current ACL) is not a CONNECT grant to an effective role or
    #: PUBLIC made by the database's CURRENT owner. Checked before any GRANT
    #: — never against the whole of `prior_grants`, only the entries this
    #: call would act on, so a restore never refuses an ACL `fence_writers`
    #: itself already accepted.
    PROOF_MISMATCH = "proof_mismatch"


class FenceRefused(Exception):
    """Raised instead of returning a proof that lies about the fence state.

    `before_acl` is set on every refusal raised after the pre-checks (i.e.
    once `fence_writers` has read the database's starting ACL) — an operator
    who sees this exception always has the exact ACL to restore to, even when
    the automatic compensation itself failed.
    """

    def __init__(
        self,
        code: FenceRefusalCode,
        detail: str,
        *,
        before_acl: str | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.before_acl = before_acl
        super().__init__(f"{code}: {detail}")


#: A decomposed ACL: `(grantee, privilege_type, is_grantable, grantor)`.
#: PUBLIC's grantee is `""`. The grantor IS part of this comparison — see the
#: module docstring's "Grantor-exact restore" section.
_Grants = frozenset[tuple[str, str, bool, str]]


def _reject_unsafe_identifier(
    value: str, field: str, *, allow_empty: bool = False
) -> None:
    """`PROOF_INVALID`, checked on every role/database/grantee/grantor name a
    `FenceProof` document carries.

    An empty string is refused everywhere except a `prior_grants` grantee
    (where it is the PUBLIC sentinel, `allow_empty=True`). A NUL byte or a
    lone (unpaired) UTF-16 surrogate codepoint can never come from a real
    `pg_roles.rolname`/`pg_database.datname` read — PostgreSQL identifiers
    cannot contain a NUL, and a real database string is always valid
    Unicode — so either is refused as evidence the document did not
    originate from a real fence."""
    if value == "":
        if allow_empty:
            return
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID,
            f"fence proof document's {field} is an empty string",
        )
    if "\x00" in value:
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID,
            f"fence proof document's {field} contains a NUL character",
        )
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID,
            f"fence proof document's {field} contains a lone surrogate",
        )


def _reject_invalid_fence_id(fence_id: str) -> None:
    """`PROOF_INVALID`: `fence_id` must be a non-empty run identifier — not
    unsafe (a NUL byte or a lone surrogate, the same discipline as every
    other identifier this module carries), not padded with leading or
    trailing whitespace, and no longer than 128 characters. Applied
    identically whether the value came from a caller's
    `fence_writers`/`restore_writers` argument or from a wire document
    `from_document` is parsing."""
    if fence_id == "":
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID, "fence_id is an empty string"
        )
    if "\x00" in fence_id:
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID, "fence_id contains a NUL character"
        )
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in fence_id):
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID, "fence_id contains a lone surrogate"
        )
    if fence_id != fence_id.strip():
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID,
            "fence_id has leading or trailing whitespace",
        )
    if len(fence_id) > 128:
        raise FenceRefused(
            FenceRefusalCode.PROOF_INVALID,
            f"fence_id is {len(fence_id)} characters, exceeding the 128 "
            "character limit",
        )


@dataclass(frozen=True, slots=True)
class FenceProof:
    """What the fence did, verified rather than assumed.

    `prior_acl` is the database's ACL exactly as `pg_database.datacl::text`
    read it (or the materialised `acldefault('d', datdba)` when that was
    NULL) before this fence's first REVOKE — kept for the human record, but
    `prior_grants` (the identical ACL decomposed into `(grantee,
    privilege_type, is_grantable, grantor)` tuples via `aclexplode`) is what
    `restore_writers` actually compares against; see the module docstring for
    why text comparison is refused and why the grantor is part of the
    comparison.

    `fence_id` is the caller-supplied identifier of the run that produced
    this proof — required, non-empty, and bound by `restore_writers` against
    the caller's `expected_fence_id` before any GRANT, so a proof from a
    superseded run cannot be replayed against a live fence of the same
    database (see the module docstring's "Two required bindings" section)."""

    database: str
    fence_id: str
    prior_acl: str
    prior_grants: _Grants
    fenced_roles: tuple[str, ...]
    #: Every role, other than a named writer itself, that transitively holds
    #: membership in a named writer, found by walking `pg_auth_members`
    #: explicitly (`_member_roles`) — never `pg_has_role(role, writer,
    #: 'MEMBER')`, which answers true for every superuser against every role
    #: and would wrongly pull every superuser in the cluster into this set.
    #: These roles can `SET ROLE` to a fenced writer and keep writing, or
    #: reconnect under their own CONNECT grant, so every pre-check and the
    #: revoke/verify/drain all run over `fenced_roles + member_roles`
    #: together (see the module docstring's "effective set" section).
    member_roles: tuple[str, ...]
    absent_roles: tuple[str, ...]
    terminated_count: int
    fenced_at: datetime

    def to_document(self) -> dict[str, object]:
        """`TransitionFenceProof.v1`: the portable wire form of this proof.

        `prior_grants` becomes a sorted list of 4-element
        `[grantee, privilege, is_grantable, grantor]` lists (JSON has no
        tuple or set — a list is both), and `fenced_at` becomes an ISO-8601
        UTC string with a `Z` suffix. `from_document` is this method's exact
        inverse: `FenceProof.from_document(proof.to_document()) == proof`."""
        return {
            "schema": FENCE_PROOF_SCHEMA,
            "database": self.database,
            "fence_id": self.fence_id,
            "prior_acl": self.prior_acl,
            "prior_grants": sorted(
                [grantee, privilege, is_grantable, grantor]
                for grantee, privilege, is_grantable, grantor in self.prior_grants
            ),
            "fenced_roles": list(self.fenced_roles),
            "member_roles": list(self.member_roles),
            "absent_roles": list(self.absent_roles),
            "terminated_count": self.terminated_count,
            "fenced_at": _iso_utc(self.fenced_at),
        }

    def canonical_bytes(self) -> bytes:
        """`to_document()`, serialised with sorted keys, `(",", ":")`
        separators, `ensure_ascii=True`, encoded as UTF-8 — the exact bytes
        `digest()` hashes, and the only byte-stable form this proof has."""
        return json.dumps(
            self.to_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def digest(self) -> str:
        """`"sha256:" + hex` over `canonical_bytes()`."""
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_document(
        cls,
        doc: dict[str, object],
        *,
        expected_digest: str,
        allowed_writer_roles: tuple[str, ...] = WRITER_ROLES,
    ) -> FenceProof:
        """The strict inverse of `to_document()`. Fails closed with
        `FenceRefused(FenceRefusalCode.PROOF_INVALID)`.

        `expected_digest` is REQUIRED and is the only actual defence against
        a document that is structurally well-formed but semantically
        laundered — a flipped `is_grantable`, an added PUBLIC grant, an
        escalated privilege — none of which live database state can reveal
        once the ACL has been revoked and later restored. This method
        recomputes the digest of what it parsed and refuses unless it
        matches EXACTLY, as the LAST check, after every structural check
        below has already passed (so a digest mismatch is never confused
        with a shape problem the caller could otherwise fix by re-encoding).

        **`digest()` is a plain, UNKEYED sha256.** It protects a document
        ONLY when the host orchestrator (PR 2) captures `expected_digest`
        itself, per run, at the moment `fence_writers` returns, on a
        channel the fenced process's own document CANNOT ALSO WRITE — and
        then never re-derives that expected value by re-reading anything
        from the container/process whose output it is validating. An
        orchestrator that captured both the document AND its "expected"
        digest from the SAME untrusted channel (e.g. both read back from a
        container's stdout) would be comparing a value to itself; the
        digest is only a defence when it crossed a trust boundary the
        document's own channel does not control. PR 2 owns building and
        proving that channel — this method only ever compares two byte
        strings.

        Every other check here is defence in depth against a document that
        is simply malformed (not necessarily maliciously tampered — nothing
        can compute `digest()` on invalid input in the first place): the
        wrong schema; unknown or missing keys; a wrong type anywhere,
        including bool-as-int for `terminated_count`; a negative
        `terminated_count`; a `fenced_at` that is not the EXACT canonical
        `_iso_utc` form (naive, non-UTC, a non-`Z` UTC offset like `+00:00`
        or `-00:00`, or missing/extra precision are all refused, since none
        of them is what `to_document()` ever writes); a duplicate entry
        within `prior_grants`, or within `fenced_roles`, `member_roles`, or
        `absent_roles`; any role name, grantor, or non-PUBLIC grantee that is
        empty, contains a NUL byte, or contains a lone surrogate; a
        `prior_grants` privilege outside `CONNECT`/`CREATE`/`TEMPORARY`;
        `fenced_roles` not a subset of `allowed_writer_roles` — the SAME
        `writer_roles` tuple the fence that produced this proof was called
        with; `member_roles` containing `MIGRATION_ROLE` or overlapping
        `fenced_roles`; or `absent_roles` overlapping either.

        **What this method cannot bound.** A `prior_grants` grantee may
        legitimately be the database OWNER itself (PostgreSQL's own default
        ACL always includes an owner-granted entry for the owner — see
        `_current_grants`), and the owner's name is not carried on this
        document at all. This method therefore does not attempt to restrict
        `prior_grants` grantees to a closed role set; `restore_writers`
        bounds that instead, from LIVE state: it only ever GRANTs to `{"",
        *effective}` (never the owner), and separately refuses a proof whose
        `prior_grants` records any grantor other than the database's CURRENT
        owner.
        """
        if not isinstance(doc, dict):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"a fence proof document must be a JSON object, got "
                f"{type(doc).__name__}",
            )
        keys = set(doc.keys())
        if keys != _FENCE_PROOF_DOCUMENT_KEYS:
            missing = sorted(_FENCE_PROOF_DOCUMENT_KEYS - keys)
            unknown = sorted(keys - _FENCE_PROOF_DOCUMENT_KEYS)
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document has missing keys {missing} and "
                f"unknown keys {unknown}",
            )
        if doc["schema"] != FENCE_PROOF_SCHEMA:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document has schema {doc['schema']!r}, "
                f"expected {FENCE_PROOF_SCHEMA!r}",
            )

        database = doc["database"]
        if not isinstance(database, str):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's database must be a string",
            )
        _reject_unsafe_identifier(database, "database")

        fence_id = doc["fence_id"]
        if not isinstance(fence_id, str):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's fence_id must be a string",
            )
        _reject_invalid_fence_id(fence_id)

        prior_acl = doc["prior_acl"]
        if not isinstance(prior_acl, str):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's prior_acl must be a string",
            )

        prior_grants_doc = doc["prior_grants"]
        if not isinstance(prior_grants_doc, list):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's prior_grants must be a list",
            )
        prior_grants_list: list[tuple[str, str, bool, str]] = []
        for entry in prior_grants_doc:
            if (
                not isinstance(entry, list)
                or len(entry) != 4
                or not isinstance(entry[0], str)
                or not isinstance(entry[1], str)
                or not isinstance(entry[2], bool)
                or not isinstance(entry[3], str)
            ):
                raise FenceRefused(
                    FenceRefusalCode.PROOF_INVALID,
                    "fence proof document has a malformed prior_grants "
                    f"entry: {entry!r}",
                )
            grantee, privilege, is_grantable, grantor = entry
            _reject_unsafe_identifier(grantee, "prior_grants grantee", allow_empty=True)
            _reject_unsafe_identifier(grantor, "prior_grants grantor")
            if privilege not in _KNOWN_DATABASE_PRIVILEGES:
                raise FenceRefused(
                    FenceRefusalCode.PROOF_INVALID,
                    f"fence proof document's prior_grants names privilege "
                    f"{privilege!r}, which is not one of "
                    f"{sorted(_KNOWN_DATABASE_PRIVILEGES)}",
                )
            if grantee == "" and is_grantable:
                # PostgreSQL never allows a grant option to PUBLIC — no real
                # `aclexplode` read can ever produce this entry, so its
                # presence here is evidence the document did not originate
                # from a real fence.
                raise FenceRefused(
                    FenceRefusalCode.PROOF_INVALID,
                    "fence proof document's prior_grants names a grant "
                    "option to PUBLIC, which PostgreSQL never allows",
                )
            prior_grants_list.append((grantee, privilege, is_grantable, grantor))
        if len(prior_grants_list) != len(set(prior_grants_list)):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's prior_grants contains a duplicate grant",
            )
        prior_grants: _Grants = frozenset(prior_grants_list)

        def _role_list(key: str) -> tuple[str, ...]:
            value = doc[key]
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise FenceRefused(
                    FenceRefusalCode.PROOF_INVALID,
                    f"fence proof document's {key} must be a list of strings",
                )
            for item in value:
                _reject_unsafe_identifier(item, f"{key} entry")
            if len(value) != len(set(value)):
                raise FenceRefused(
                    FenceRefusalCode.PROOF_INVALID,
                    f"fence proof document's {key} contains a duplicate role",
                )
            return tuple(value)

        fenced_roles = _role_list("fenced_roles")
        member_roles = _role_list("member_roles")
        absent_roles = _role_list("absent_roles")

        if not set(fenced_roles) <= set(allowed_writer_roles):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's fenced_roles {sorted(fenced_roles)} "
                "is not a subset of the allowed writer roles "
                f"{sorted(allowed_writer_roles)}",
            )
        if MIGRATION_ROLE in member_roles:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's member_roles names the migration "
                f"role {MIGRATION_ROLE!r}, which can never be a member of a "
                "fenced writer without also being refused as shared",
            )
        role_overlap = set(member_roles) & set(fenced_roles)
        if role_overlap:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's member_roles overlaps its "
                f"fenced_roles: {sorted(role_overlap)}",
            )
        absent_overlap = set(absent_roles) & (set(fenced_roles) | set(member_roles))
        if absent_overlap:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's absent_roles overlaps its "
                f"fenced_roles/member_roles: {sorted(absent_overlap)}",
            )

        terminated_count = doc["terminated_count"]
        if not isinstance(terminated_count, int) or isinstance(terminated_count, bool):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's terminated_count must be an int, not a bool",
            )
        if terminated_count < 0:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's terminated_count must not be negative",
            )

        fenced_at_raw = doc["fenced_at"]
        if not isinstance(fenced_at_raw, str):
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "fence proof document's fenced_at must be a string",
            )
        try:
            fenced_at = datetime.fromisoformat(fenced_at_raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's fenced_at {fenced_at_raw!r} is not "
                "a valid ISO-8601 timestamp",
            ) from exc
        if fenced_at.tzinfo is None:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's fenced_at {fenced_at_raw!r} is "
                "naive; it must be UTC and offset-aware",
            )
        fenced_at = fenced_at.astimezone(UTC)
        # The exact round trip, not just "parses to a UTC instant": a naive
        # timestamp, a non-UTC offset, or a UTC offset spelled any way other
        # than `to_document()`'s own `Z` suffix (`+00:00`, `-00:00`, missing
        # or extra fractional digits) all parse successfully above but are
        # not what this module ever writes, and are refused here.
        if _iso_utc(fenced_at) != fenced_at_raw:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's fenced_at {fenced_at_raw!r} is not "
                f"the canonical UTC form this module writes "
                f"({_iso_utc(fenced_at)!r} would be)",
            )

        proof = cls(
            database=database,
            fence_id=fence_id,
            prior_acl=prior_acl,
            prior_grants=prior_grants,
            fenced_roles=fenced_roles,
            member_roles=member_roles,
            absent_roles=absent_roles,
            terminated_count=terminated_count,
            fenced_at=fenced_at,
        )
        actual_digest = proof.digest()
        if actual_digest != expected_digest:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                f"fence proof document's digest {actual_digest!r} does not "
                f"match the expected digest {expected_digest!r}; the "
                "document does not match what the fence recorded when it "
                "closed",
            )
        return proof


_FENCE_PROOF_DOCUMENT_KEYS: Final = frozenset(
    {
        "schema",
        "database",
        "fence_id",
        "prior_acl",
        "prior_grants",
        "fenced_roles",
        "member_roles",
        "absent_roles",
        "terminated_count",
        "fenced_at",
    }
)


def _iso_utc(dt: datetime) -> str:
    """ISO-8601 UTC with a `Z` suffix — the only timestamp form
    `FenceProof.to_document()` writes. `from_document` treats this as the
    CANONICAL form of `fenced_at`: it refuses any document string for which
    `_iso_utc(parsed) != raw`, which is what actually rejects a naive
    timestamp, a non-UTC offset, or a UTC offset spelled as anything other
    than this exact `Z`-suffixed, microsecond-precision form."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


@dataclass(frozen=True, slots=True)
class UnfenceProof:
    """The result of `restore_writers`: the ACL is back, verified equal."""

    database: str
    restored_at: datetime
    roles_restored: tuple[str, ...]


def _quote_ident(conn: Connection, name: str) -> str:
    """Delegate quoting to PostgreSQL itself rather than reimplementing it.

    `quote_ident` is the server's own answer to "how do I write this
    identifier back into SQL safely" — no format-string interpolation of a
    role or database name ever happens in this module."""
    return str(
        conn.execute(text("SELECT quote_ident(:name)"), {"name": name}).scalar_one()
    )


def _role_ref_sql(conn: Connection, grantee: str) -> str:
    """`""` (PUBLIC, from `aclexplode`) or a quoted role identifier."""
    return "PUBLIC" if grantee == "" else _quote_ident(conn, grantee)


def _require_autocommit(conn: Connection) -> None:
    """`connection_not_autocommit`, checked before any change.

    On a transactional connection the REVOKE is invisible to every other
    backend until this connection commits, and a rollback would erase the
    fence while a `FenceProof` claiming otherwise still exists."""
    # The DRIVER connection's own autocommit flag, not
    # `Connection.get_isolation_level()`: that queries the server's isolation
    # level, which still reads "read committed" under autocommit.
    dbapi_connection = conn.connection.dbapi_connection
    if getattr(dbapi_connection, "autocommit", False) is not True:
        raise FenceRefused(
            FenceRefusalCode.CONNECTION_NOT_AUTOCOMMIT,
            "the connection is not AUTOCOMMIT; a REVOKE issued on it is "
            "invisible to other backends until commit, and a rollback would "
            "erase the fence while a proof of it exists",
        )


def _database_exists(conn: Connection, database: str) -> bool:
    return (
        conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :db"), {"db": database}
        ).first()
        is not None
    )


def _existing_roles(conn: Connection, roles: tuple[str, ...]) -> set[str]:
    if not roles:
        return set()
    rows = conn.execute(
        text("SELECT rolname FROM pg_roles WHERE rolname = ANY(:roles)"),
        {"roles": list(roles)},
    )
    return {row[0] for row in rows}


def _duplicates(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    dupes: set[str] = set()
    for value in values:
        if value in seen:
            dupes.add(value)
        seen.add(value)
    return tuple(sorted(dupes))


#: Explicit, transitive membership through `pg_auth_members` — NOT
#: `pg_has_role(..., 'MEMBER')`, which answers true for every superuser against
#: every role and would pull `postgres` into every effective set (and so refuse
#: every fence as a superuser writer). A superuser that was actually GRANTed a
#: writer role still appears here, and is refused.
_MEMBER_ROLES_QUERY: Final = text(
    "WITH RECURSIVE members(oid) AS ("
    " SELECT r.oid FROM pg_roles r WHERE r.rolname = ANY(CAST(:writers AS text[]))"
    " UNION"
    " SELECT am.member FROM pg_auth_members am JOIN members m ON am.roleid = m.oid"
    ") "
    "SELECT DISTINCT r.rolname FROM members m JOIN pg_roles r ON r.oid = m.oid "
    "WHERE r.rolname <> ALL(CAST(:writers AS text[]))"
)


def _member_roles(conn: Connection, fenced: tuple[str, ...]) -> tuple[str, ...]:
    """Every role, other than a fenced writer itself, that is a (transitive)
    member of any fenced writer — the roles that inherit a writer's CONNECT
    through `SET ROLE` and are therefore part of the effective set (see the
    module docstring)."""
    if not fenced:
        return ()
    rows = conn.execute(_MEMBER_ROLES_QUERY, {"writers": list(fenced)})
    return tuple(sorted({str(row[0]) for row in rows}))


def _database_owner(conn: Connection, database: str) -> str:
    """The database owner's role name, resolved from `pg_database.datdba`.

    `UNKNOWN_DATABASE`, never a raw `NoResultFound`, if the database no
    longer exists — a caller deep inside `restore_writers` or a `prior=`
    bind should see this module's own closed refusal vocabulary, not a
    driver-level exception it never wrapped."""
    try:
        row = conn.execute(
            text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :db"),
            {"db": database},
        ).scalar_one()
    except NoResultFound as exc:
        raise FenceRefused(
            FenceRefusalCode.UNKNOWN_DATABASE,
            f"no database named {database!r} exists in this cluster",
        ) from exc
    return str(row)


def _require_owner_member_or_superuser(conn: Connection, database: str) -> None:
    """`CONNECTION_NOT_OWNER`, checked before any change.

    Every GRANT this module ever issues (the restore path's re-grant) or
    relies on having been issued by (the fence path's pre-check) records the
    EXECUTING identity as grantor. If `conn`'s `current_user` is not the
    database owner, a member of the owner, or a superuser, any GRANT it
    issued would record a grantor `restore_writers` could never bind against
    the CURRENT owner — so this is refused up front, before either function
    does anything else."""
    try:
        is_authorized = conn.execute(
            text(
                "SELECT r.rolsuper OR pg_has_role(r.rolname, d.datdba, 'MEMBER') "
                "FROM pg_roles r, pg_database d "
                "WHERE r.rolname = current_user AND d.datname = :db"
            ),
            {"db": database},
        ).scalar_one()
    except NoResultFound as exc:
        raise FenceRefused(
            FenceRefusalCode.UNKNOWN_DATABASE,
            f"no database named {database!r} exists in this cluster",
        ) from exc
    if not is_authorized:
        raise FenceRefused(
            FenceRefusalCode.CONNECTION_NOT_OWNER,
            f"this connection's current_user is not database {database!r}'s "
            "owner, a member of the owner, or a superuser; a GRANT it issued "
            "would record a grantor restore_writers could never bind against "
            "the current owner",
        )


def _is_member_of(conn: Connection, member: str, role: str) -> bool:
    """`pg_has_role(member, role, 'MEMBER')` — resolves the full membership
    chain, not only a direct GRANT."""
    return bool(
        conn.execute(
            text("SELECT pg_has_role(:member, :role, 'MEMBER')"),
            {"member": member, "role": role},
        ).scalar_one()
    )


def _reject_shared_writer_roles(
    conn: Connection, effective: tuple[str, ...], writer_roles: tuple[str, ...]
) -> None:
    """`shared_writer_role`, checked before any ACL change, against every
    EFFECTIVE role (named writers plus every role that is a member of one —
    see the module docstring's "effective set" section).

    Fencing a role that IS the migrator, or that shares membership with it in
    either direction, would fence the migration it exists to protect. The
    identical hazard shows up as one login role named twice in the writer set,
    so that is checked here too.
    """
    duplicates = _duplicates(writer_roles)
    if duplicates:
        raise FenceRefused(
            FenceRefusalCode.SHARED_WRITER_ROLE,
            f"{duplicates} named more than once in the writer set — the same "
            "login role fenced under two names would race with itself",
        )
    for role in effective:
        if role == MIGRATION_ROLE:
            raise FenceRefused(
                FenceRefusalCode.SHARED_WRITER_ROLE,
                f"effective writer role {role!r} IS the migration role "
                f"{MIGRATION_ROLE!r}",
            )
        if _is_member_of(conn, MIGRATION_ROLE, role) or _is_member_of(
            conn, role, MIGRATION_ROLE
        ):
            raise FenceRefused(
                FenceRefusalCode.SHARED_WRITER_ROLE,
                f"effective writer role {role!r} shares role membership with "
                f"the migration role {MIGRATION_ROLE!r}",
            )


def _reject_superuser_writers(conn: Connection, effective: tuple[str, ...]) -> None:
    """A superuser keeps CONNECT through every REVOKE (and is a member of every
    role, so it would otherwise surface as a shared role): refused first.

    Runs over the EFFECTIVE role set (named writers plus every role that is a
    member of one), not only the named writers.
    """
    for role in effective:
        is_superuser = conn.execute(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = :role"),
            {"role": role},
        ).scalar_one()
        if is_superuser:
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"effective writer role {role!r} is a superuser; no REVOKE "
                "removes its CONNECT",
            )


def _require_migration_connect_without_public(
    conn: Connection, database: str, grants: _Grants
) -> None:
    """`migration_role_lost_connect`, checked before any ACL change.

    The fence revokes PUBLIC. If the migration role's CONNECT rests only on
    PUBLIC (it neither owns the database, nor is a member of the owner, nor is
    a member of any explicit non-PUBLIC grantee), the fence would lock the
    migrator out with the writers. Production's contract is that `app_admin`
    owns the database, so this refuses anything else up front."""
    owner = _database_owner(conn, database)
    if MIGRATION_ROLE == owner or _is_member_of(conn, MIGRATION_ROLE, owner):
        return
    grantees = (
        grantee
        for grantee, priv, _, _grantor in grants
        if priv == "CONNECT" and grantee
    )
    if any(_is_member_of(conn, MIGRATION_ROLE, grantee) for grantee in grantees):
        return
    raise FenceRefused(
        FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
        f"migration role {MIGRATION_ROLE!r} holds CONNECT on {database!r} only "
        "through PUBLIC; fencing would lock the migrator out too",
    )


def _reject_inherited_connect(
    conn: Connection, effective: tuple[str, ...], database: str, grants: _Grants
) -> None:
    """`writer_inherits_connect`, checked before any ACL change, against every
    EFFECTIVE role (named writers plus every role that is a member of one —
    see the module docstring's "effective set" section).

    `REVOKE CONNECT ON DATABASE ... FROM <role>` only ever edits that role's
    own ACL entry. A database owner (and every member of the owner) holds an
    implicit CONNECT no such REVOKE removes, and a member of `MIGRATION_ROLE`
    inherits that role's CONNECT the same way — so this cannot be fenced by
    revoking, and is refused instead of revoked, "verified", and returned as a
    proof that lies.
    """
    owner = _database_owner(conn, database)
    # Every explicit CONNECT grantee in the ACL this call starts from, other
    # than PUBLIC (revoked) and every effective role itself (each revoked). An
    # effective role that is a member of ANY such grantee keeps CONNECT
    # through that membership after every REVOKE this module issues.
    other_grantees = tuple(
        grantee
        for grantee, priv, _, _grantor in grants
        if priv == "CONNECT" and grantee and grantee not in effective
    )
    for role in effective:
        for grantee in other_grantees:
            if _is_member_of(conn, role, grantee):
                raise FenceRefused(
                    FenceRefusalCode.WRITER_INHERITS_CONNECT,
                    f"writer role {role!r} is a member of {grantee!r}, which "
                    f"holds its own CONNECT on {database!r}; that inherited "
                    "CONNECT survives every REVOKE this module can issue",
                )
        if role == owner:
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} owns database {database!r}; CONNECT "
                "through ownership survives every REVOKE this module can issue",
            )
        if _is_member_of(conn, role, owner):
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} is a member of database owner "
                f"{owner!r}; CONNECT inherited through membership survives "
                "every REVOKE this module can issue",
            )
        if _is_member_of(conn, role, MIGRATION_ROLE):
            raise FenceRefused(
                FenceRefusalCode.WRITER_INHERITS_CONNECT,
                f"writer role {role!r} is a member of the migration role "
                f"{MIGRATION_ROLE!r}; CONNECT inherited through membership "
                "survives every REVOKE this module can issue",
            )


def _reject_grants_not_owner_granted(
    conn: Connection, database: str, effective: tuple[str, ...], grants: _Grants
) -> None:
    """`grant_not_owner_granted`, checked before any ACL change.

    An owner-or-superuser `REVOKE ... FROM role` only removes grants whose
    recorded grantor is the owner (see the module docstring's "Grantor-exact
    restore" section). A CONNECT grant recorded with a different grantor
    survives every REVOKE this module issues, and a restore could not recreate
    it afterwards with its original grantor — so it is refused instead of
    silently kept fenced-in or silently dropped on restore.
    """
    owner = _database_owner(conn, database)
    checked_grantees = {"", *effective}
    for grantee, priv, _is_grantable, grantor in grants:
        if priv != "CONNECT" or grantee not in checked_grantees:
            continue
        if grantor != owner:
            display_grantee = "PUBLIC" if grantee == "" else grantee
            raise FenceRefused(
                FenceRefusalCode.GRANT_NOT_OWNER_GRANTED,
                f"CONNECT on {database!r} granted to {display_grantee!r} by "
                f"{grantor!r}, not the database owner {owner!r}; an owner or "
                "superuser REVOKE cannot remove this grant, and restore could "
                "not recreate it with its original grantor",
            )


def _current_acl_text(conn: Connection, database: str) -> str:
    """`pg_database.datacl::text`, or the materialised default when NULL.

    NULL `datacl` means "nobody has ever explicitly GRANTed or REVOKEd" —
    PostgreSQL answers privilege checks against the implicit default in that
    case, and `acldefault('d', datdba)` is that default made explicit so the
    prior state this module restores to is never a guess. Kept for the human
    record on `FenceProof.prior_acl`; see `_current_grants` for the form
    every comparison in this module actually uses."""
    row = conn.execute(
        text("SELECT datacl::text, datdba FROM pg_database WHERE datname = :db"),
        {"db": database},
    ).one()
    acl_text, owner_oid = row
    if acl_text is not None:
        return str(acl_text)
    return str(
        conn.execute(
            text("SELECT acldefault('d', :owner)::text"), {"owner": owner_oid}
        ).scalar_one()
    )


_GRANTS_QUERY: Final = text(
    "SELECT COALESCE(ge.rolname, '') AS grantee, a.privilege_type, "
    "a.is_grantable, gr.rolname AS grantor "
    "FROM pg_database d, "
    "aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a "
    "LEFT JOIN pg_roles ge ON ge.oid = a.grantee "
    "JOIN pg_roles gr ON gr.oid = a.grantor "
    "WHERE d.datname = :db"
)


def _current_grants(conn: Connection, database: str) -> _Grants:
    """The database's ACL, decomposed by the server itself via `aclexplode`.

    PUBLIC's grantee oid is 0, which `pg_roles` never matches, so
    `COALESCE(ge.rolname, '')` resolves it to `""` — the same sentinel used
    throughout this module. The grantor is always a real role (an ACL entry's
    grantor oid is never 0), so it is joined with a plain `JOIN`, never
    `COALESCE`-d — see the module docstring's "Grantor-exact restore"
    section for why the grantor is part of every comparison here."""
    rows = conn.execute(_GRANTS_QUERY, {"db": database})
    return frozenset(
        (str(row[0]), str(row[1]), bool(row[2]), str(row[3])) for row in rows
    )


def fence_writers(
    conn: Connection,
    *,
    database: str,
    fence_id: str,
    writer_roles: tuple[str, ...] = WRITER_ROLES,
    session_wait_seconds: float,
    prior: FenceProof | None = None,
    terminator: Terminator | None = None,
) -> FenceProof:
    """Revoke CONNECT from every existing writer role, verify it, then drain.

    `conn` is the database owner (production) or a superuser: the ACL work —
    REVOKE/GRANT CONNECT, `aclexplode`, `pg_auth_members`,
    `has_database_privilege`, `pg_stat_activity` reads — needs no more than
    that. Terminating another role's open backends is a separate privilege
    database ownership does not grant, so it goes through `terminator`
    instead of `conn`: `None` uses the default adapter (`pg_terminate_backend`
    over `conn` itself, today's behaviour, for a caller that does hold
    signalling rights), and a caller-supplied `terminator` is a no-argument
    callable requesting termination of every writer backend, invoked without
    ever being told which pids or roles to terminate — the production broker
    re-derives that set itself, server-side, over its own superuser channel.
    Without the right to signal (an absent or ineffective `terminator`), the
    drain times out and the fence is compensated, so it fails safe. The
    library never trusts a terminator's claim; its own poll of
    `pg_stat_activity` is the only proof it acts on.

    `fence_id` is a required, caller-supplied identifier of THIS run,
    recorded on the returned `FenceProof` and bound by `restore_writers`
    against its own `expected_fence_id` before any GRANT (see the module
    docstring's "Two required bindings" section) — refused `PROOF_INVALID`
    if empty or unsafe. A re-fence (`prior=`) records THIS call's `fence_id`
    on the new proof, never the prior proof's own.
    """
    _require_autocommit(conn)
    _reject_invalid_fence_id(fence_id)

    if not _database_exists(conn, database):
        raise FenceRefused(
            FenceRefusalCode.UNKNOWN_DATABASE,
            f"no database named {database!r} exists in this cluster",
        )
    _require_owner_member_or_superuser(conn, database)

    existing = _existing_roles(conn, writer_roles)
    absent = tuple(role for role in writer_roles if role not in existing)
    fenced = tuple(role for role in writer_roles if role in existing)
    # The EFFECTIVE set: every named writer, plus every role that is a
    # (transitive) member of one. A login role that is a member of a fenced
    # writer can `SET ROLE` to it and keep writing, or hold its own CONNECT
    # grant and reconnect — so every pre-check, the revoke, the verification
    # and the drain below all run over this set, not just `fenced`. See the
    # module docstring's "effective set" section.
    member_roles = _member_roles(conn, fenced)
    effective = tuple(dict.fromkeys((*fenced, *member_roles)))

    # Every check below runs before any ACL change, and over the EFFECTIVE
    # role set. None of these hazards can be repaired by revoking — a role
    # that inherits CONNECT through ownership or membership keeps it
    # regardless, and a role sharing identity with the migrator would fence
    # the migration along with it — so all are refused rather than revoked
    # and then "verified" against a privilege check that was never going to
    # move.
    before_acl = _current_acl_text(conn, database)
    before_grants = _current_grants(conn, database)

    if prior is not None:
        if not prior.fence_id:
            raise FenceRefused(
                FenceRefusalCode.PROOF_INVALID,
                "prior proof's fence_id is empty; a valid prior always "
                "carries the non-empty run identifier its own fence "
                "recorded",
            )
        if (
            prior.database != database
            or set(prior.fenced_roles) != set(fenced)
            or set(prior.member_roles) != set(member_roles)
        ):
            raise FenceRefused(
                FenceRefusalCode.PRIOR_MISMATCH,
                f"prior proof names database {prior.database!r}, fenced roles "
                f"{sorted(prior.fenced_roles)} and member roles "
                f"{sorted(prior.member_roles)}, but this call resolved "
                f"{database!r}, {sorted(fenced)} and {sorted(member_roles)} — "
                "a mismatched prior would restore the wrong ACL",
            )
        # `prior.prior_grants` is about to become this call's own idea of
        # "the ACL to restore to" — bound it against LIVE state before
        # trusting it. `before_grants` (what the database's ACL holds RIGHT
        # NOW, already fenced by an earlier call) must be a SUBSET of what
        # `prior` claims the original ACL was — anything currently granted
        # that `prior` does not also claim would be silently dropped on
        # restore. And every entry `prior` adds beyond that live subset is
        # bounded exactly as `restore_writers` bounds a restore's own GRANTs:
        # a CONNECT grant to `{"", *effective}` made by the CURRENT owner —
        # never a wider claim a caller could use to smuggle an arbitrary
        # grant back in under a later restore.
        if not before_grants <= prior.prior_grants:
            raise FenceRefused(
                FenceRefusalCode.PRIOR_MISMATCH,
                f"the live ACL for {database!r} holds grant(s) "
                f"{sorted(before_grants - prior.prior_grants)} that the "
                "given prior proof does not account for; a mismatched prior "
                "would restore the wrong ACL",
            )
        owner_for_prior = _database_owner(conn, database)
        allowed_for_prior = {"", *effective}
        bad_prior_entry = next(
            (
                entry
                for entry in (prior.prior_grants - before_grants)
                if entry[1] != "CONNECT"
                or entry[0] not in allowed_for_prior
                or entry[3] != owner_for_prior
                # PostgreSQL never allows a grant option to PUBLIC — an
                # entry claiming one cannot have come from a real
                # `aclexplode` read of any ACL this module could have
                # fenced.
                or (entry[0] == "" and entry[2])
            ),
            None,
        )
        if bad_prior_entry is not None:
            grantee, privilege, is_grantable, grantor = bad_prior_entry
            display_grantee = "PUBLIC" if grantee == "" else grantee
            if grantee == "" and is_grantable:
                raise FenceRefused(
                    FenceRefusalCode.PRIOR_MISMATCH,
                    f"the given prior proof for {database!r} claims a "
                    f"{privilege!r} grant WITH GRANT OPTION to PUBLIC beyond "
                    "the live ACL, which PostgreSQL never allows; refusing "
                    "before any change",
                )
            raise FenceRefused(
                FenceRefusalCode.PRIOR_MISMATCH,
                f"the given prior proof for {database!r} claims a "
                f"{privilege!r} grant to {display_grantee!r} (recorded "
                f"grantor {grantor!r}) beyond the live ACL, which is not a "
                "CONNECT grant to an effective role or PUBLIC made by the "
                f"database's current owner {owner_for_prior!r}; refusing "
                "before any change",
            )

    _reject_superuser_writers(conn, effective)
    _require_migration_connect_without_public(conn, database, before_grants)
    _reject_shared_writer_roles(conn, effective, writer_roles)
    _reject_inherited_connect(conn, effective, database, before_grants)
    _reject_grants_not_owner_granted(conn, database, effective, before_grants)

    prior_acl = prior.prior_acl if prior is not None else before_acl
    prior_grants = prior.prior_grants if prior is not None else before_grants

    try:
        return _apply_fence(
            conn,
            database=database,
            fence_id=fence_id,
            fenced=fenced,
            member_roles=member_roles,
            effective=effective,
            absent=absent,
            prior_acl=prior_acl,
            prior_grants=prior_grants,
            session_wait_seconds=session_wait_seconds,
            terminator=terminator,
        )
    except BaseException as exc:
        # Any exception at all after the first REVOKE — another refusal, a
        # driver error, a timeout, KeyboardInterrupt — puts the ACL back to
        # what THIS call started from, never leaves a half-fenced database
        # with no proof to restore from. On a re-fence that is the
        # still-holding fence, not the original prior ACL.
        compensating = FenceProof(
            database=database,
            fence_id=fence_id,
            prior_acl=before_acl,
            prior_grants=before_grants,
            member_roles=member_roles,
            fenced_roles=fenced,
            absent_roles=absent,
            terminated_count=0,
            # A local timestamp, never a query: on a dropped connection a
            # `SELECT now()` here would raise raw and lose `before_acl` on the
            # very path that guarantee exists for.
            fenced_at=datetime.now(UTC),
        )
        try:
            restore_writers(
                conn,
                compensating,
                database=database,
                expected_fence_id=fence_id,
                session_wait_seconds=session_wait_seconds,
                terminator=terminator,
            )
        except BaseException as restore_exc:
            failure = FenceRefused(
                FenceRefusalCode.COMPENSATION_FAILED,
                f"restoring the ACL for {database!r} after {exc!r} itself "
                f"failed: {restore_exc!r}; the database may still be fenced "
                "— restore to before_acl by hand",
                before_acl=before_acl,
            )
            raise failure from exc
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        if isinstance(exc, FenceRefused):
            exc.before_acl = before_acl
            raise
        raise FenceRefused(
            FenceRefusalCode.FENCE_INTERRUPTED,
            f"fencing {database!r} was interrupted after the first ACL "
            f"change: {exc!r}",
            before_acl=before_acl,
        ) from exc


def _writer_pids(
    conn: Connection, database: str, writers: tuple[str, ...]
) -> list[int]:
    return list(
        conn.execute(
            text(
                "SELECT pid FROM pg_stat_activity WHERE datname = :db "
                "AND usename = ANY(:writers) AND pid <> pg_backend_pid()"
            ),
            {"db": database, "writers": list(writers)},
        )
        .scalars()
        .all()
    )


def _default_terminate(conn: Connection, database: str, roles: tuple[str, ...]) -> None:
    """The default `Terminator` adapter: `pg_terminate_backend` issued over
    `conn` itself for every pid `_writer_pids` currently finds — today's
    behaviour, unchanged, for a caller that holds signalling rights on
    `conn`."""
    for pid in _writer_pids(conn, database, roles):
        conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})


def _request_termination(
    conn: Connection,
    database: str,
    roles: tuple[str, ...],
    terminator: Terminator | None,
    session_wait_seconds: float,
) -> None:
    """Route one termination request through `terminator`, or the default
    adapter when `terminator` is `None`. Never passes a pid or a role name to
    `terminator` — it takes no arguments and re-derives the writer set
    itself.

    Any exception `terminator()` raises — including a `FenceRefused` it
    raises itself — is caught here and re-raised as `_TerminatorFailed`,
    chained from the original: a terminator is untrusted code, and a
    `FenceRefused` it happens to raise must never be mistaken for a refusal
    this module produced (see `_TerminatorFailed`'s docstring).
    `KeyboardInterrupt`/`SystemExit` are not wrapped — they propagate as
    themselves, the same convention `fence_writers`/`restore_writers` use
    everywhere else.

    Python cannot interrupt a blocking callable: if `terminator()` itself
    takes longer than `session_wait_seconds` to return, THIS is the only
    place that can ever notice, since a single call can consume the entire
    deadline before the poll loop gets another chance to check it. Measured
    on return (success or a wrapped failure does not matter — a terminator
    that blocks past the deadline gets no benefit of the doubt either way),
    and raised as `WRITER_SESSIONS_SURVIVED` — a writer this call could not
    time-bound waiting for is exactly what that code means."""
    if terminator is not None:
        started = time.monotonic()
        try:
            terminator()
        except Exception as exc:
            raise _TerminatorFailed(f"terminator raised {exc!r}") from exc
        elapsed = time.monotonic() - started
        if elapsed > session_wait_seconds:
            raise FenceRefused(
                FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
                f"a terminator call for {database!r} took {elapsed:.3f}s, "
                f"exceeding the {session_wait_seconds}s deadline; "
                "PostgreSQL cannot interrupt a blocking callable, so this "
                "is the only place that can notice",
            )
    else:
        _default_terminate(conn, database, roles)


def _terminate_and_drain(
    conn: Connection,
    database: str,
    roles: tuple[str, ...],
    session_wait_seconds: float,
    terminator: Terminator | None = None,
) -> int:
    """Terminate every open backend for `roles` and block until TWO
    CONSECUTIVE polls, a full `_POLL_INTERVAL_SECONDS` apart, both find zero
    remaining — a termination request merely asks for termination, and a
    single zero reading can race a backend that is mid-termination and about
    to be replaced by a reconnect. Raises `WRITER_SESSIONS_SURVIVED` if the
    drain does not converge within `session_wait_seconds` — the poll loop's
    own deadline bounds the whole drain across repeated calls, AND (see
    `_request_termination`) a SINGLE `terminator()` call that itself blocks
    past `session_wait_seconds` is caught immediately when it returns,
    since Python cannot interrupt a blocking callable mid-call and the poll
    loop's deadline check would otherwise never get a chance to run.
    Returns the number of backends found on entry — read via `_writer_pids`,
    never taken on `terminator`'s word.

    `terminator`, when given, replaces the default `pg_terminate_backend`
    adapter (see `_request_termination`); the poll loop and its proof are
    identical either way."""
    if not roles:
        return 0
    backends = _writer_pids(conn, database, roles)
    terminated_count = len(backends)
    if backends:
        _request_termination(conn, database, roles, terminator, session_wait_seconds)

    deadline = time.monotonic() + session_wait_seconds
    while True:
        remaining = _writer_pids(conn, database, roles)
        if not remaining:
            time.sleep(_POLL_INTERVAL_SECONDS)
            confirm = _writer_pids(conn, database, roles)
            if not confirm:
                return terminated_count
            remaining = confirm
        if time.monotonic() >= deadline:
            raise FenceRefused(
                FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
                f"{len(remaining)} writer backend(s) on {database!r} "
                f"survived {session_wait_seconds}s of draining",
            )
        _request_termination(conn, database, roles, terminator, session_wait_seconds)
        time.sleep(_POLL_INTERVAL_SECONDS)


def _apply_fence(
    conn: Connection,
    *,
    database: str,
    fence_id: str,
    fenced: tuple[str, ...],
    member_roles: tuple[str, ...],
    effective: tuple[str, ...],
    absent: tuple[str, ...],
    prior_acl: str,
    prior_grants: _Grants,
    session_wait_seconds: float,
    terminator: Terminator | None = None,
) -> FenceProof:
    """The mutating half of `fence_writers`; its caller compensates a refusal.

    Every revoke, verification and drain below runs over the EFFECTIVE role
    set (`fenced` plus `member_roles`) — see the module docstring's
    "effective set" section.
    """
    quoted_db = _quote_ident(conn, database)
    conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM PUBLIC"))
    for role in effective:
        quoted_role = _quote_ident(conn, role)
        conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM {quoted_role}"))

    for role in effective:
        still_connect = conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": role, "db": database},
        ).scalar_one()
        if still_connect:
            raise FenceRefused(
                FenceRefusalCode.WRITER_STILL_HAS_CONNECT,
                f"role {role!r} still has CONNECT on {database!r} after revoke",
            )

    if not _existing_roles(conn, (MIGRATION_ROLE,)):
        raise FenceRefused(
            FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
            f"migration role {MIGRATION_ROLE!r} does not exist in this cluster",
        )
    migration_can_connect = conn.execute(
        text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
        {"role": MIGRATION_ROLE, "db": database},
    ).scalar_one()
    if not migration_can_connect:
        raise FenceRefused(
            FenceRefusalCode.MIGRATION_ROLE_LOST_CONNECT,
            f"migration role {MIGRATION_ROLE!r} lost CONNECT on {database!r}",
        )

    terminated_count = _terminate_and_drain(
        conn, database, effective, session_wait_seconds, terminator
    )

    # A local timestamp, never a query: every ACL mutation and the drain that
    # verifies it have already succeeded by this point, and a `SELECT now()`
    # here would be a non-essential query that could fail and flip a fence
    # that genuinely holds into a reported exception (see the module
    # docstring's "no query after the ACL is restored" section).
    fenced_at = datetime.now(UTC)
    return FenceProof(
        database=database,
        fence_id=fence_id,
        prior_acl=prior_acl,
        prior_grants=prior_grants,
        fenced_roles=fenced,
        member_roles=member_roles,
        absent_roles=absent,
        terminated_count=terminated_count,
        fenced_at=fenced_at,
    )


def _refence(conn: Connection, quoted_db: str, effective: tuple[str, ...]) -> None:
    """Re-revoke CONNECT from PUBLIC and every role in the EFFECTIVE set.

    By construction the effective set — `fenced_roles + member_roles` on the
    proof this restore was reversing — IS the fenced state; this never
    consults `restored` (the list of what a failed restore happened to grant
    before it failed), because a failure can leave that list short of the
    full effective set, or empty entirely if the failure was in the final
    comparison rather than partway through the GRANT loop. Re-revoking the
    ground-truth effective set is correct either way; a Python list built
    from a partial success is not."""
    conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM PUBLIC"))
    for role in effective:
        quoted_role = _quote_ident(conn, role)
        conn.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM {quoted_role}"))


def _refence_holds(conn: Connection, database: str, effective: tuple[str, ...]) -> bool:
    """True only when PUBLIC and every effective role has VERIFIABLY lost
    CONNECT — `has_database_privilege`, never assumed from the REVOKE having
    merely been issued (see `_apply_fence`'s identical discipline)."""
    public_can_connect = conn.execute(
        text("SELECT has_database_privilege('public', :db, 'CONNECT')"),
        {"db": database},
    ).scalar_one()
    if public_can_connect:
        return False
    for role in effective:
        still_connect = conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": role, "db": database},
        ).scalar_one()
        if still_connect:
            return False
    return True


def _refence_and_redrain(
    conn: Connection,
    quoted_db: str,
    database: str,
    effective: tuple[str, ...],
    session_wait_seconds: float,
    *,
    original: BaseException,
    detail: str,
    before_acl: str,
    terminator: Terminator | None = None,
) -> None:
    """Re-revoke the effective set as ground truth, VERIFY the re-fence
    actually holds, then re-drain it before the caller reports its own
    failure.

    A restore that briefly re-opened the ACL and then failed must not claim
    the database is fenced without re-proving it: a writer could have
    reconnected during the re-opened window, and the re-revoke itself could
    fail to take. Returning normally here means the re-fence was verified
    AND the re-drain converged, and only then may the caller's own message
    say "stays fenced" or "re-revoked" — the caller raises its own
    `ACL_NOT_RESTORED` in that case. Raising here (this function never
    returns on any other path) supersedes that with a sharper diagnosis:
    `COMPENSATION_FAILED` if the re-revoke could not be issued OR could not
    be verified, or `WRITER_SESSIONS_SURVIVED` if the drain never converged
    — both chained from `original`, the failure this restore was reacting
    to. A non-`FenceRefused` exception from the drain (a driver error, not a
    timeout) is wrapped as `COMPENSATION_FAILED` too, chained from
    `original`, rather than escaping raw."""
    try:
        _refence(conn, quoted_db, effective)
        holds = _refence_holds(conn, database, effective)
    except BaseException as refence_exc:
        raise FenceRefused(
            FenceRefusalCode.COMPENSATION_FAILED,
            f"re-fencing {database!r} after a failed restore itself failed: "
            f"{refence_exc!r}; the database may not be fenced — restore to "
            "prior_acl by hand",
            before_acl=before_acl,
        ) from original
    if not holds:
        raise FenceRefused(
            FenceRefusalCode.COMPENSATION_FAILED,
            f"re-fencing {database!r} after a failed restore could not be "
            "verified: an effective role or PUBLIC still holds CONNECT after "
            "the re-revoke; the database may not be fenced — restore to "
            "prior_acl by hand",
            before_acl=before_acl,
        ) from original
    try:
        _terminate_and_drain(
            conn, database, effective, session_wait_seconds, terminator
        )
    except FenceRefused as drain_exc:
        raise FenceRefused(
            FenceRefusalCode.WRITER_SESSIONS_SURVIVED,
            f"{detail}; re-fenced, but the drain did not converge: {drain_exc!r}",
        ) from original
    except BaseException as drain_exc:
        raise FenceRefused(
            FenceRefusalCode.COMPENSATION_FAILED,
            f"re-draining {database!r} after a failed restore raised "
            f"{drain_exc!r}; the ACL re-fence was verified but the drain "
            "state is unproven — restore to prior_acl by hand",
            before_acl=before_acl,
        ) from original


def restore_writers(
    conn: Connection,
    proof: FenceProof,
    *,
    database: str,
    expected_fence_id: str,
    session_wait_seconds: float,
    terminator: Terminator | None = None,
) -> UnfenceProof:
    """Put the ACL back to exactly `proof.prior_grants`. Idempotent.

    `database` and `expected_fence_id` are both REQUIRED bindings, checked
    first — before `_require_owner_member_or_superuser` and every other query
    that depends on `proof` — and refused with `PROOF_MISMATCH` unless
    `database == proof.database` and `expected_fence_id == proof.fence_id`
    (see the module docstring's "Two required bindings" section). Without
    them a caller could restore a proof meant for a different database, or
    replay a proof from a superseded fencing run against the same database.

    Only re-grants CONNECT to a grantee the prior ACL actually held it for —
    never PUBLIC, never a fenced role, unless `prior_grants` says so — and
    then verifies the restored ACL exactly matches the prior one (compared as
    decomposed grants, never as raw text; see the module docstring) before
    returning. Refuses, before granting anything, if the current ACL holds a
    grant the prior ACL never had — something changed the ACL while it was
    fenced — and, if the restored ACL still does not match afterwards,
    re-revokes everything it just granted (plus PUBLIC) so the database stays
    fenced rather than silently half-open.

    On either re-fence path (a partial GRANT failure, or a final mismatch)
    this also TERMINATES AND DRAINS the effective set again with
    `session_wait_seconds` before reporting the failure — reopening the ACL
    briefly is not itself a hazard a caller can act on, but a writer that
    reconnected during that window and is still open when this function
    returns would be, so this never claims the database is fenced without
    re-proving it holds no open writer sessions. `terminator`, passed through
    to that re-drain, has the same meaning as on `fence_writers`.

    Before touching anything, this also re-derives `_member_roles` from
    `proof.fenced_roles` against LIVE state and refuses
    (`PROOF_MISMATCH`) unless it equals `proof.member_roles` exactly — the
    same discipline `fence_is_holding` already applies to a proof it is only
    reading, applied here to one this function is about to ACT on. It then
    computes `to_add = proof.prior_grants - current` (the entries this
    restore would actually need to GRANT) and refuses (`PROOF_MISMATCH`)
    unless EVERY entry in `to_add` is a CONNECT grant to `{"", *effective}`
    made by the database's CURRENT owner — never checking every entry in the
    whole `prior_grants` set, only the ones this call would act on: a grant
    the fence never touched and this restore is not going to re-issue is not
    this function's business, and a restore must not refuse an ACL the fence
    itself already accepted at fence time (see the module docstring's
    "Grantor-exact restore" section for why `fence_writers` is the one place
    that checks the FULL ACL, once, before ever touching it). This is also
    what bounds a `prior_grants` grantee `FenceProof.from_document` could
    not (see that method's docstring): a legitimate owner-granted CONNECT
    entry always satisfies it, and a laundered one naming any other grantor,
    privilege, or grantee cannot.
    """
    _require_autocommit(conn)

    # Checked first, before any query that depends on `proof`: a caller's
    # `database` and `expected_fence_id` must both name what this proof
    # actually claims, or a stale/misdirected/replayed proof could restore
    # the wrong ACL under the wrong run's authority (see the module
    # docstring's "Two required bindings" section).
    if database != proof.database:
        raise FenceRefused(
            FenceRefusalCode.PROOF_MISMATCH,
            f"restore was called with database {database!r}, but the proof "
            f"names {proof.database!r}; refusing before any query that "
            "depends on the proof",
        )
    if expected_fence_id != proof.fence_id:
        raise FenceRefused(
            FenceRefusalCode.PROOF_MISMATCH,
            f"restore was called with expected_fence_id {expected_fence_id!r}, "
            f"but the proof names fence_id {proof.fence_id!r}; refusing "
            "before any GRANT",
        )

    _require_owner_member_or_superuser(conn, proof.database)

    live_member_roles = _member_roles(conn, proof.fenced_roles)
    if set(live_member_roles) != set(proof.member_roles):
        raise FenceRefused(
            FenceRefusalCode.PROOF_MISMATCH,
            f"re-deriving membership for {sorted(proof.fenced_roles)} right "
            f"now gives {sorted(live_member_roles)}, not the "
            f"{sorted(proof.member_roles)} this proof recorded; membership "
            "drifted since the fence closed, so this proof's effective set "
            "can no longer be trusted",
        )

    quoted_db = _quote_ident(conn, proof.database)
    current = _current_grants(conn, proof.database)

    unexpected = current - proof.prior_grants
    if unexpected:
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"the ACL for {proof.database!r} holds grant(s) {sorted(unexpected)} "
            "absent from the fence's recorded prior ACL; something changed "
            "the ACL while it was fenced, so nothing was granted",
        )

    # The EFFECTIVE set this proof fenced: named writers plus every role that
    # was a member of one at fence time (see the module docstring's
    # "effective set" section) — the only grantees `fence_writers` could ever
    # have revoked, and so the only ones `restore_writers` may re-grant.
    effective = tuple(dict.fromkeys((*proof.fenced_roles, *proof.member_roles)))
    allowed_grantees = {"", *effective}

    # Every entry this restore would actually need to GRANT, bounded before
    # the first GRANT — never against the WHOLE of `prior_grants` (a grant
    # the fence never revoked and this restore will never re-issue is not
    # this function's business, and refusing on it would be a restore that
    # rejects an ACL `fence_writers` itself already accepted: the HIGH
    # regression this replaced).
    owner = _database_owner(conn, proof.database)
    to_add = proof.prior_grants - current
    bad_entry = next(
        (
            entry
            for entry in to_add
            if entry[1] != "CONNECT"
            or entry[0] not in allowed_grantees
            or entry[3] != owner
            # PostgreSQL never allows a grant option to PUBLIC — an entry
            # claiming one cannot have come from a real `aclexplode` read of
            # any ACL this module could have fenced.
            or (entry[0] == "" and entry[2])
        ),
        None,
    )
    if bad_entry is not None:
        grantee, privilege, is_grantable, grantor = bad_entry
        display_grantee = "PUBLIC" if grantee == "" else grantee
        if grantee == "" and is_grantable:
            raise FenceRefused(
                FenceRefusalCode.PROOF_MISMATCH,
                f"restoring {proof.database!r} would need to grant "
                f"{privilege!r} WITH GRANT OPTION to PUBLIC, which "
                "PostgreSQL never allows; refusing before any change",
            )
        raise FenceRefused(
            FenceRefusalCode.PROOF_MISMATCH,
            f"restoring {proof.database!r} would need to grant {privilege!r} "
            f"to {display_grantee!r} (recorded grantor {grantor!r}), which is "
            "not a CONNECT grant to an effective role or PUBLIC made by the "
            f"database's current owner {owner!r}; refusing before any change",
        )
    # `missing` sorts PUBLIC first, so a partial failure below reopens the
    # least first.
    missing = sorted(to_add)

    restored: list[str] = []
    try:
        for grantee, _priv, is_grantable, _grantor in missing:
            # The GRANT below does not (and cannot, for an object privilege)
            # specify a grantor: it always records the EXECUTING identity as
            # grantor — the database owner itself, whether `conn` IS the
            # owner directly (D1: no superuser needed for the ACL work) or
            # is a superuser granting on the owner's behalf (see the module
            # docstring's "Grantor-exact restore" section). The pre-fence
            # check already refused any grant whose recorded grantor was not
            # the owner, so this reproduces it exactly; the post-loop
            # comparison against `proof.prior_grants` (grantor included) is
            # what actually proves it.
            option_sql = " WITH GRANT OPTION" if is_grantable else ""
            conn.execute(
                text(
                    f"GRANT CONNECT ON DATABASE {quoted_db} TO "
                    f"{_role_ref_sql(conn, grantee)}{option_sql}"
                )
            )
            restored.append("PUBLIC" if grantee == "" else grantee)
        final = _current_grants(conn, proof.database)
    except BaseException as exc:
        _refence_and_redrain(
            conn,
            quoted_db,
            proof.database,
            effective,
            session_wait_seconds,
            original=exc,
            detail=f"restoring the ACL for {proof.database!r} failed part-way "
            f"({exc!r}); re-revoked what was granted to stay fenced",
            before_acl=proof.prior_acl,
            terminator=terminator,
        )
        # Mirrors `fence_writers`: an interrupt is reported AS ITSELF, never
        # wrapped, once the re-fence and re-drain attempt has run.
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        raise FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"restoring the ACL for {proof.database!r} failed part-way "
            f"({exc!r}); re-revoked what was granted to stay fenced",
        ) from exc

    if final != proof.prior_grants:
        # Stay fenced: re-revoke PUBLIC and every role just granted, rather
        # than returning a proof claiming the restore worked.
        mismatch = FenceRefused(
            FenceRefusalCode.ACL_NOT_RESTORED,
            f"restored ACL for {proof.database!r} does not equal the prior "
            "ACL recorded in the fence proof; re-revoked to stay fenced",
        )
        _refence_and_redrain(
            conn,
            quoted_db,
            proof.database,
            effective,
            session_wait_seconds,
            original=mismatch,
            detail=str(mismatch),
            before_acl=proof.prior_acl,
            terminator=terminator,
        )
        raise mismatch

    # A local timestamp, never a query: the ACL is already restored and
    # verified equal to `proof.prior_grants` by this point, and a `SELECT
    # now()` here would be a non-essential query that could fail and flip a
    # restore that genuinely succeeded into a reported exception.
    restored_at = datetime.now(UTC)
    return UnfenceProof(
        database=proof.database,
        restored_at=restored_at,
        roles_restored=tuple(restored),
    )


def fence_is_holding(conn: Connection, proof: FenceProof) -> bool:
    """Read-only: is the fence this proof describes STILL in effect, right now?

    True only when ALL of:

    - every role in the EFFECTIVE set (`fenced_roles + member_roles`) still
      lacks CONNECT (`has_database_privilege`);
    - `MIGRATION_ROLE` still has CONNECT;
    - re-deriving `_member_roles` from `proof.fenced_roles` RIGHT NOW gives
      back exactly `proof.member_roles` — membership can drift after a fence
      closes (see the module docstring's "known limits" section), and a
      role granted membership in a writer after the fence would otherwise
      go unnoticed by every other check here;
    - zero backends remain open for the effective set.

    Never mutates anything — this is a read of the current state, not a
    re-fence."""
    effective = tuple(dict.fromkeys((*proof.fenced_roles, *proof.member_roles)))
    for role in effective:
        still_connect = conn.execute(
            text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
            {"role": role, "db": proof.database},
        ).scalar_one()
        if still_connect:
            return False

    migration_can_connect = conn.execute(
        text("SELECT has_database_privilege(:role, :db, 'CONNECT')"),
        {"role": MIGRATION_ROLE, "db": proof.database},
    ).scalar_one()
    if not migration_can_connect:
        return False

    current_members = _member_roles(conn, proof.fenced_roles)
    if set(current_members) != set(proof.member_roles):
        return False

    return _writer_pids(conn, proof.database, effective) == []
