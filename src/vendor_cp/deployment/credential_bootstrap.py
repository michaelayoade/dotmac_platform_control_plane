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

## The session is RECEIVED, and it cannot be one of ours

`ALTER ROLE <other> PASSWORD` requires superuser or CREATEROLE, and reading
`pg_authid.rolpassword` requires superuser: `pg_roles` renders it as `********`
for everyone. This assembly's own roles have neither — `app_admin` is
explicitly `NOSUPERUSER NOCREATEROLE`, and that is not an oversight to route
around but the reason the application cannot rewrite its own principals.

So the executor supplies a privileged session, reached on the target the same
way `init-roles.sh` was. This module never constructs it, never holds a DSN for
it, and deny case D1's connection allowlist stays empty.

## The plan carries a reference; the material is resolved here

`PrincipalCredentialBootstrap` names a logical database, a principal, an OpenBao
path, a field and an expected version. No password, no DSN, no SQL and no
executable command. The pointer is resolved at execution time on the target, and
the material never enters the plan, the receipt, a log line or an argument
vector.
"""

from __future__ import annotations

import hashlib
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
    }
)


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


def _advisory_key(principal: str) -> int:
    """A stable 63-bit lock key derived from the principal name.

    Derived rather than allocated, so two executors bootstrapping the same
    principal contend on the same key without a registry to keep in step.
    """
    digest = hashlib.sha256(principal.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") >> 1


def _validate_principal(db: Session, principal: str) -> None:
    """Step 1. Four separate refusals, because they need four different fixes."""
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
    row = db.execute(
        text("SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname = :principal"),
        {"principal": principal},
    ).one_or_none()
    if row is None:
        raise BootstrapRefused(
            "principal.absent",
            f"role {principal!r} does not exist; this effect installs a "
            "credential for a role, it does not create one",
        )
    if not row[0]:
        raise BootstrapRefused(
            "principal.not_login",
            f"role {principal!r} cannot log in, so a password would give it "
            "nothing and hide that fact",
        )
    if row[1]:
        raise BootstrapRefused(
            "principal.is_superuser",
            f"role {principal!r} is a superuser; this effect does not install "
            "credentials for roles that can rewrite every other one",
        )


def _credential_present(db: Session, principal: str) -> bool:
    """Whether `rolpassword` is set. Requires superuser — `pg_roles` renders it
    as `********` for everyone, so a non-privileged reader cannot answer."""
    return bool(
        db.execute(
            text(
                "SELECT rolpassword IS NOT NULL FROM pg_authid WHERE "
                "rolname = :principal"
            ),
            {"principal": principal},
        ).scalar_one()
    )


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


def _install(db: Session, principal: str, material: str) -> None:
    """Step 5. Exactly one `ALTER ROLE`, quoted by PostgreSQL itself.

    Neither half of `ALTER ROLE <name> PASSWORD <literal>` can be a bind
    parameter — one is an identifier and the other is a DDL literal — so the
    statement is built by `format(%I, %L)` ON THE SERVER, from bound values.
    That is PostgreSQL's own quoting rather than this module's idea of it, which
    is the only injection-safe construction available here.

    `log_statement` is silenced for this transaction because the rendered
    statement necessarily contains the material, and a server configured to log
    DDL would write it to a file nobody is treating as a secret store. This
    requires superuser, which the caller already is.
    """
    db.execute(text("SET LOCAL log_statement = 'none'"))
    statement = db.execute(
        text("SELECT format('ALTER ROLE %I PASSWORD %L', :principal, :material)"),
        {"principal": principal, "material": material},
    ).scalar_one()
    db.execute(text(statement))


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
    _validate_principal(admin_db, instruction.principal)
    material, version = _resolve_material(instruction, secrets)

    # Step 2, then step 3. The lock is transaction-scoped, so it is released by
    # the commit below or by any rollback — there is no path that leaks it.
    admin_db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": _advisory_key(instruction.principal)},
    )
    if _credential_present(admin_db, instruction.principal):
        # Step 4. Refuse. The caller reconciles with `verify_credential` if it
        # believes a previous run of ITS OWN plan committed.
        admin_db.rollback()
        raise BootstrapRefused(
            "credential.already_present",
            f"role {instruction.principal!r} already holds a credential. This "
            "effect installs once; altering again would rotate a credential "
            "other systems now hold",
        )

    _install(admin_db, instruction.principal, material)
    admin_db.commit()  # Step 6a. The proof below is meaningless before this.

    authenticated = authenticate(
        database=instruction.database,
        principal=instruction.principal,
        material=material,
    )
    if not authenticated:
        raise BootstrapRefused(
            "credential.authentication_failed",
            f"role {instruction.principal!r} was installed and then could not "
            "authenticate with the referenced material. The credential is "
            "COMMITTED and must not be altered again; investigate the host's "
            "authentication configuration",
        )
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
    if not authenticate(
        database=instruction.database,
        principal=instruction.principal,
        material=material,
    ):
        raise BootstrapRefused(
            "credential.authentication_failed",
            f"role {instruction.principal!r} does not authenticate with the "
            "referenced material, so the effect did not complete. It is NOT "
            "reconcilable by this path: installing over an unknown credential "
            "is a rotation, and needs its own authorization",
        )
    return BootstrapReceipt(
        outcome=BootstrapOutcome.ALREADY_INSTALLED,
        database=instruction.database,
        principal=instruction.principal,
        secret_path=instruction.secret_path,
        secret_field=instruction.secret_field,
        secret_version=version,
        authenticated=True,
    )
