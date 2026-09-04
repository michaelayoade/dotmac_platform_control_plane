"""Install a database principal's credential exactly once, and prove it works.

Platform implements this effect; Foundation plans it, invokes it and judges the
result. The ordering below is the design rather than a sequence of convenient
steps, and each one exists because the step before it can be undone by a race,
a crash or an optimistic reading.

1. Validate the declared principal is LOGIN, non-superuser and allowlisted.
2. Take a transaction-scoped advisory lock.
3. Re-read credential presence UNDER that lock.
4. Refuse if already present.
5. Perform exactly one injection-safe `ALTER ROLE`.
6. Commit, then PROVE authentication using the referenced material.
7. A crash after commit reconciles by AUTHENTICATING; never by altering again.

Step 3 is why step 2 exists: a presence check taken before the lock is a check of
a state that can change before the write. Step 6 is what makes this real rather
than optimistic — running an `ALTER ROLE` and observing no error says the
statement was accepted, not that the credential works. Step 7's constraint is
absolute: a second `ALTER ROLE` would rotate a credential other systems now
hold, so the crash path is `verify_credential`, which reads and never writes.

## There is no ledger, deliberately

`rolpassword` absent means install once; present means refuse. The database's own
state is the record, so there is no second idempotency mechanism to keep in step
with it (`dotmac_starter_mt` hard rule 21's owner is untouched). The existing
external `psql` path put its ledger and its password change in DIFFERENT
transactions, leaving a window where one was true and the other was not — that
is the thing being replaced, not extended.

## The privileged act is ONE NAMED OPERATION, not a role grant

`ALTER ROLE <other> PASSWORD` requires superuser or CREATEROLE, and reading
`pg_authid.rolpassword` requires superuser: `pg_roles` renders it as `********`
for everyone. This assembly's own roles have neither — `app_admin` is
explicitly `NOSUPERUSER NOCREATEROLE` — and widening that was refused, correctly.

So steps 1 to 5 live in `public.bootstrap_dispatcher_credential`, a
SECURITY DEFINER operation that alters exactly one role named as a constant in
its own body. The kernel's `0012_platform_outbox` is the precedent for the
shape; what does NOT carry over is its ownership, and the kernel says so itself:
those functions are `OWNER TO app_admin` because app_admin has the TABLE
privileges they need. It has no CREATEROLE, so an app_admin-owned function
cannot alter a role whatever its body says. This one is therefore owned by a
superuser and installed by one — `deploy/postgres/bootstrap-credential-function.sql`,
applied at cluster initialisation, deliberately not an Alembic revision because
migrations run as app_admin and a role cannot create an object owned by a
superuser.

Two things the caller gains beyond least privilege. It needs no standing
superuser at run time — EXECUTE on one operation that can touch one role is the
whole capability. And the material travels as a BIND PARAMETER rather than
inside DDL text, so it never reaches `log_statement`; the `ALTER ROLE` is built
inside plpgsql, which `log_statement` does not log.

This module still receives its session and constructs none, so deny case D1's
connection allowlist stays empty.

## The plan carries a reference; the material is resolved here

`PrincipalCredentialBootstrap` names a logical database, a principal, an OpenBao
path, a field and an expected version. No password, no DSN, no SQL and no
executable command. The pointer is resolved at execution time on the target, and
the material never enters the plan, the receipt, a log line or an argument
vector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

__all__ = [
    "ALLOWED_PRINCIPALS",
    "BootstrapOutcome",
    "BootstrapReceipt",
    "BootstrapRefused",
    "CredentialAuthenticator",
    "PrincipalCredentialBootstrap",
    "REFUSAL_CODES",
    "SecretResolver",
    "bootstrap_principal_credential",
    "verify_credential",
]

#: The principals this effect may install a credential for.
#:
#: A list rather than a rule, and short on purpose: the effect writes a
#: credential for a role it did not create, so the set of roles it may touch is
#: a decision rather than a consequence. Adding one is a deliberate edit here.
ALLOWED_PRINCIPALS: Final[frozenset[str]] = frozenset({"platform_outbox_dispatcher"})

#: A conservative role-name shape, checked BEFORE the allowlist so a malformed
#: name is refused as malformed rather than as unlisted.
_PRINCIPAL_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

#: Every refusal this effect can emit. Each names ONE reason: a caller scripting
#: against an aggregate cannot tell "not on the list" from "is a superuser", and
#: those need opposite responses.
REFUSAL_CODES: Final[frozenset[str]] = frozenset(
    {
        "principal.malformed",
        "principal.not_allowlisted",
        "principal.absent",
        "principal.not_login",
        "principal.is_superuser",
        "material.unresolvable",
        "material.version_mismatch",
        "credential.already_present",
        "credential.authentication_failed",
        "credential.authentication_not_enforced",
    }
)


#: The operation's SQLSTATE for each refusal it can raise, mapped back to the
#: name this module reports. Custom codes rather than PostgreSQL's own, because
#: three of these would otherwise share `invalid_parameter_value` and collapse
#: into one answer — and "cannot log in" and "is a superuser" need opposite
#: responses.
#:
#: Checked in BOTH directions against the SQL file, so a code raised there
#: without a mapping here, or a mapping for a code nothing raises, fails the
#: build.
SQLSTATE_REFUSALS: Final[dict[str, str]] = {
    "DM101": "principal.not_allowlisted",
    "DM102": "principal.absent",
    "DM103": "principal.not_login",
    "DM104": "principal.is_superuser",
    "DM105": "credential.already_present",
    "DM106": "material.unresolvable",
}


class BootstrapRefused(Exception):
    """One reason, named. Never an aggregate."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        if code not in REFUSAL_CODES:  # pragma: no cover - guarded by a test
            raise AssertionError(f"undeclared bootstrap refusal code {code!r}")
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class PrincipalCredentialBootstrap:
    """What the plan carries. A reference, never the material.

    `expected_version` binds the exact OpenBao record revision, so a record
    rewritten between planning and execution is refused rather than silently
    installed. The new record is created CAS-zero and therefore binds version 1.
    """

    database: str
    principal: str
    secret_path: str
    secret_field: str
    expected_version: int


class SecretResolver(Protocol):
    """Reads one versioned record. The narrowest port that can answer step 6.

    Deliberately not the full secret client: this effect must be able to read a
    record and must not be able to write one.
    """

    def read_versioned(self, path: str) -> object: ...


class CredentialAuthenticator(Protocol):
    """Proves a principal can actually authenticate with the given material.

    A Protocol so the effect can be driven without a server, and so the one real
    implementation lives at the edge where a connection is legitimate. Returns
    True or False; it never raises for a failed login, because a refused
    password is an ANSWER rather than an error.
    """

    def __call__(self, *, database: str, principal: str, material: str) -> bool: ...


class BootstrapOutcome(StrEnum):
    """What happened, as a member rather than a sentence."""

    #: The credential was absent, was installed, and authenticated afterwards.
    INSTALLED = "installed"
    #: Step 7. It was already present and authenticated with the referenced
    #: material, so a previous run committed and this one has nothing to do.
    ALREADY_INSTALLED = "already_installed"


@dataclass(frozen=True, slots=True)
class BootstrapReceipt:
    """What is recorded. Names and coordinates only — never the material.

    There is no `material`, no `password`, no `dsn` and no rendered statement
    field, and that is structural rather than a convention: a receipt is
    persisted, read back and travels, so the only safe receipt is one that
    cannot carry a value in the first place.
    """

    outcome: BootstrapOutcome
    database: str
    principal: str
    secret_path: str
    secret_field: str
    secret_version: int
    authenticated: bool


def _precheck_principal(principal: str) -> None:
    """The two checks this module can make WITHOUT the database.

    Shape and allowlist only. Everything about the role itself — that it exists,
    can log in, is not a superuser, and holds no credential yet — is checked by
    the operation, under its own lock, because that is where the answer is both
    authoritative and readable. `pg_authid` is not visible to this caller at all.
    """
    if _PRINCIPAL_NAME.fullmatch(principal) is None:
        raise BootstrapRefused(
            "principal.malformed", f"{principal!r} is not a role name"
        )
    if principal not in ALLOWED_PRINCIPALS:
        raise BootstrapRefused(
            "principal.not_allowlisted",
            f"{principal!r} is not a principal this effect may install a "
            "credential for",
        )


def _sqlstate(error: BaseException) -> str | None:
    """The SQLSTATE the operation raised, if this is one of its refusals."""
    for candidate in (error, getattr(error, "orig", None)):
        code = getattr(candidate, "sqlstate", None) or getattr(
            candidate, "pgcode", None
        )
        if isinstance(code, str):
            return code
    return None


def _install(db: Session, principal: str, material: str) -> None:
    """Steps 2 to 5, performed by the operation rather than by this session.

    The lock, the re-read under it, the refusal and the single `ALTER ROLE` all
    live inside `public.bootstrap_dispatcher_credential`. Moving them there did
    not lose the ordering — it moved the ordering to the only place that can
    both read `pg_authid` and alter a role.

    The material is a BIND PARAMETER. It is not interpolated into any statement
    this module composes, and the operation builds its `ALTER ROLE` inside
    plpgsql where `log_statement` does not reach.
    """
    try:
        db.execute(
            text(
                "SELECT public.bootstrap_dispatcher_credential("
                "CAST(:principal AS text), CAST(:material AS text))"
            ),
            {"principal": principal, "material": material},
        )
    except Exception as error:  # noqa: BLE001 - re-raised as a named refusal
        code = _sqlstate(error)
        refusal = SQLSTATE_REFUSALS.get(code or "")
        if refusal is None:
            raise
        db.rollback()
        raise BootstrapRefused(
            refusal,
            f"the credential bootstrap operation refused {principal!r} " f"({code})",
        ) from error


def _resolve_material(
    instruction: PrincipalCredentialBootstrap, secrets: SecretResolver
) -> tuple[str, int]:
    """Resolve the pointer on the target. Returns the material and its version.

    The material is returned rather than stored, and every caller below keeps it
    in a local. Nothing in this module logs it, formats it into a message, or
    puts it in the receipt.
    """
    try:
        record = secrets.read_versioned(instruction.secret_path)
    except Exception as error:  # noqa: BLE001 - reported without its detail
        raise BootstrapRefused(
            "material.unresolvable",
            f"the record at {instruction.secret_path} could not be read",
        ) from error
    version = getattr(record, "version", None)
    fields = getattr(record, "fields", None)
    if not isinstance(version, int) or not isinstance(fields, dict):
        raise BootstrapRefused(
            "material.unresolvable",
            f"{instruction.secret_path} did not answer with a versioned record",
        )
    if version != instruction.expected_version:
        raise BootstrapRefused(
            "material.version_mismatch",
            f"{instruction.secret_path} is at version {version}, and the plan "
            f"binds version {instruction.expected_version}. A record rewritten "
            "between planning and execution is refused, not installed",
        )
    material = fields.get(instruction.secret_field)
    if not isinstance(material, str) or not material:
        raise BootstrapRefused(
            "material.unresolvable",
            f"{instruction.secret_path} carries no {instruction.secret_field!r}",
        )
    return material, version


def _prove_authentication(
    instruction: PrincipalCredentialBootstrap,
    material: str,
    authenticate: CredentialAuthenticator,
    *,
    installed: bool,
) -> None:
    """Step 6, in BOTH directions — because one direction is not a proof.

    The referenced material must authenticate, and a deliberately wrong one must
    NOT. The second half is the one that makes the first mean anything: a host
    configured with `trust` accepts every password, so a positive-only check
    passes there while proving nothing at all about the credential.

    That is measured rather than imagined. The migration-tier cluster runs
    `POSTGRES_HOST_AUTH_METHOD: trust`, and this negative control is what caught
    it — a wrong password authenticated, and the positive half had been green
    the whole time.

    The wrong material is derived from the real one so it is guaranteed to
    differ, and it is used exactly once. It costs one failed-authentication line
    in the server log, which is the price of knowing the proof can fail.
    """
    if not authenticate(
        database=instruction.database,
        principal=instruction.principal,
        material=material,
    ):
        raise BootstrapRefused(
            "credential.authentication_failed",
            f"role {instruction.principal!r} does not authenticate with the "
            + (
                "referenced material. The credential is COMMITTED and must not "
                "be altered again; investigate the host's authentication "
                "configuration"
                if installed
                else "referenced material, so the effect did not complete. It "
                "is NOT reconcilable by this path: installing over an unknown "
                "credential is a rotation, and needs its own authorization"
            ),
        )
    if authenticate(
        database=instruction.database,
        principal=instruction.principal,
        material=material + "-deliberately-wrong",
    ):
        raise BootstrapRefused(
            "credential.authentication_not_enforced",
            f"the host accepted a deliberately wrong credential for "
            f"{instruction.principal!r}, so it is not enforcing password "
            "authentication and no credential can be proven on it. The "
            "positive check passed and means nothing",
        )


def bootstrap_principal_credential(
    admin_db: Session,
    instruction: PrincipalCredentialBootstrap,
    *,
    secrets: SecretResolver,
    authenticate: CredentialAuthenticator,
) -> BootstrapReceipt:
    """The seven steps, in order.

    `admin_db` is a PRIVILEGED session the executor supplies — see the module
    docstring for why it cannot be one of this assembly's own roles.

    This function COMMITS, which is a deliberate exception to the usual
    receives-a-session-never-commits rule. Step 6 cannot be performed before the
    commit: a password installed in an open transaction is invisible to a new
    connection, so an authentication proof taken inside it would prove nothing
    and would pass for the wrong reason.
    """
    _precheck_principal(instruction.principal)
    material, version = _resolve_material(instruction, secrets)

    # Steps 2 to 5, inside the operation. It takes the advisory lock, re-reads
    # presence under it, refuses if a credential is already there, and performs
    # exactly one `ALTER ROLE`.
    _install(admin_db, instruction.principal, material)
    admin_db.commit()  # Step 6a. The proof below is meaningless before this.

    _prove_authentication(instruction, material, authenticate, installed=True)
    return BootstrapReceipt(
        outcome=BootstrapOutcome.INSTALLED,
        database=instruction.database,
        principal=instruction.principal,
        secret_path=instruction.secret_path,
        secret_field=instruction.secret_field,
        secret_version=version,
        authenticated=True,
    )


def verify_credential(
    instruction: PrincipalCredentialBootstrap,
    *,
    secrets: SecretResolver,
    authenticate: CredentialAuthenticator,
) -> BootstrapReceipt:
    """Step 7. Reconcile a crash after commit by AUTHENTICATING, never altering.

    Takes no database session at all, and that is the enforcement rather than
    the description: a function with no session cannot run an `ALTER ROLE`
    however it is later edited. A process that died between the commit and its
    receipt reconciles by proving the credential works — a second install would
    rotate a credential the relay may already be using.
    """
    material, version = _resolve_material(instruction, secrets)
    _prove_authentication(instruction, material, authenticate, installed=False)
    return BootstrapReceipt(
        outcome=BootstrapOutcome.ALREADY_INSTALLED,
        database=instruction.database,
        principal=instruction.principal,
        secret_path=instruction.secret_path,
        secret_field=instruction.secret_field,
        secret_version=version,
        authenticated=True,
    )
