"""The bootstrap effect's refusals, its ordering, and what it will not carry.

SCOPE. This tier drives the decision logic with a fake session, so it proves
which refusal fires and in what ORDER. It proves nothing about PostgreSQL:
`pg_authid` visibility, `format(%I, %L)` quoting and the atomicity of a rolled
back `ALTER ROLE` are server behaviour, and
`tests/migration/test_credential_bootstrap_atomicity.py` measures them against a
real one. Documentation of what PostgreSQL does is not a measurement of it.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Any

import pytest

from vendor_cp.deployment.credential_bootstrap import (
    ALLOWED_PRINCIPALS,
    REFUSAL_CODES,
    SQLSTATE_REFUSALS,
    BootstrapOutcome,
    BootstrapRefused,
    PrincipalCredentialBootstrap,
    bootstrap_principal_credential,
    verify_credential,
)

PRINCIPAL = "platform_outbox_dispatcher"
MATERIAL = "not-a-real-credential"

INSTRUCTION = PrincipalCredentialBootstrap(
    database="vendor_control_plane",
    principal=PRINCIPAL,
    secret_path="secret/dotmac/vendor-control-plane/production/relay-dispatcher",
    secret_field="dispatcher_password",
    expected_version=1,
)


class _Record:
    def __init__(self, version: int, fields: dict[str, str]) -> None:
        self.version = version
        self.fields = fields


class _Secrets:
    """Reads one record. Cannot write one — the port has no write method."""

    def __init__(self, record: object | Exception) -> None:
        self._record = record

    def read_versioned(self, path: str) -> object:
        if isinstance(self._record, Exception):
            raise self._record
        return self._record


def _secrets(version: int = 1, field: str = "dispatcher_password") -> _Secrets:
    return _Secrets(_Record(version, {field: MATERIAL}))


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value

    def one_or_none(self) -> object:
        return self._value


class _OperationRefused(Exception):
    """What the driver raises when the operation's RAISE reaches it."""

    def __init__(self, sqlstate: str) -> None:
        super().__init__(f"operation refused ({sqlstate})")
        self.sqlstate = sqlstate


class _AdminSession:
    """A session that can call the operation. Faked at the statement level.

    Steps 2 to 5 live in `public.bootstrap_dispatcher_credential` now, so this
    tier sees ONE statement and cannot observe the lock, the presence re-read or
    the ordering between them. Those are measured against a real server in
    `tests/migration/test_credential_bootstrap_atomicity.py`, which is the only
    place they are observable at all — a faked session can be told to answer
    anything, including in the wrong order.
    """

    def __init__(self, *, refuses: str | None = None) -> None:
        self.statements: list[str] = []
        self.params: list[object] = []
        self.committed = False
        self.rolled_back = False
        self._refuses = refuses

    def execute(self, statement: object, params: object = None) -> _Result:
        self.statements.append(str(statement))
        self.params.append(params)
        if self._refuses is not None:
            raise _OperationRefused(self._refuses)
        return _Result("installed")

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


def _authenticator(result: bool = True, *, enforces: bool = True) -> Any:
    """A host that accepts `MATERIAL` and, when `enforces`, rejects anything else.

    `enforces=False` models a `trust`-configured server: it says yes to every
    password. That is not hypothetical — the migration-tier cluster is exactly
    that, and it is what the two-directional proof exists to catch.
    """
    calls: list[dict[str, str]] = []

    def _authenticate(*, database: str, principal: str, material: str) -> bool:
        calls.append(
            {"database": database, "principal": principal, "material": material}
        )
        if not enforces:
            return True
        return result if material == MATERIAL else False

    _authenticate.calls = calls  # type: ignore[attr-defined]
    return _authenticate


# ── what this tier can still decide: the two checks made without a database ─


@pytest.mark.parametrize(
    ("principal", "code"),
    [
        ("Robert'); DROP ROLE--", "principal.malformed"),
        ("app_user", "principal.not_allowlisted"),
    ],
)
def test_the_prechecks_refuse_before_any_statement(principal: str, code: str) -> None:
    """Shape and allowlist are decidable here, so they are decided here — and
    before the session is touched, so a malformed name never reaches a server."""
    session = _AdminSession()
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            dataclasses.replace(INSTRUCTION, principal=principal),
            secrets=_secrets(),
            authenticate=_authenticator(),
        )
    assert refused.value.code == code
    assert session.statements == []


# ── the operation's refusals arrive as SQLSTATEs and keep their names ───────


@pytest.mark.parametrize(
    ("sqlstate", "code"),
    sorted(SQLSTATE_REFUSALS.items()),
)
def test_each_operation_refusal_keeps_its_own_name(sqlstate: str, code: str) -> None:
    """One SQLSTATE per refusal, so moving steps 1 to 5 into SQL did not
    collapse them. Three of these would share `invalid_parameter_value` if the
    operation used PostgreSQL's own codes, and "cannot log in" and "is a
    superuser" need opposite responses."""
    session = _AdminSession(refuses=sqlstate)
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(),
        )
    assert refused.value.code == code
    assert session.committed is False
    assert session.rolled_back is True


def test_an_unrecognised_database_error_is_not_swallowed() -> None:
    """A failure that is not one of the operation's refusals must propagate. A
    mapping that quietly turned every error into a named refusal would report a
    connection fault as a policy decision."""
    session = _AdminSession(refuses="08006")
    with pytest.raises(_OperationRefused):
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(),
        )


def test_the_sqlstate_mapping_matches_the_operation_in_both_directions() -> None:
    """The SQL file and this mapping are one contract in two files.

    A code raised there without a mapping here would surface as an unhandled
    driver error; a mapping here for a code nothing raises is a refusal that can
    never happen. Both are read out of the checked-in SQL rather than trusted.
    """
    sql = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "postgres"
        / "bootstrap-credential-function.sql"
    ).read_text(encoding="utf-8")
    raised = set(re.findall(r"ERRCODE = '(DM\d{3})'", sql))
    assert raised == set(SQLSTATE_REFUSALS), sorted(raised ^ set(SQLSTATE_REFUSALS))
    assert len(set(SQLSTATE_REFUSALS.values())) == len(SQLSTATE_REFUSALS)


def test_the_operation_is_called_with_bound_parameters() -> None:
    """The material is a BIND PARAMETER, so it never enters a statement this
    module composes and never reaches `log_statement`."""
    session = _AdminSession()
    bootstrap_principal_credential(
        session,  # type: ignore[arg-type]
        INSTRUCTION,
        secrets=_secrets(),
        authenticate=_authenticator(),
    )
    assert len(session.statements) == 1
    assert "bootstrap_dispatcher_credential" in session.statements[0]
    assert MATERIAL not in session.statements[0]
    assert session.params[0] == {"principal": PRINCIPAL, "material": MATERIAL}


# ── step 5: the statement is quoted by PostgreSQL, not by us ────────────────


# ── step 6: the proof happens, and it happens AFTER the commit ──────────────


def test_authentication_is_proved_after_the_commit() -> None:
    """A password installed in an open transaction is invisible to a new
    connection, so a proof taken inside it would pass for the wrong reason."""
    session = _AdminSession()
    authenticate = _authenticator()
    receipt = bootstrap_principal_credential(
        session,  # type: ignore[arg-type]
        INSTRUCTION,
        secrets=_secrets(),
        authenticate=authenticate,
    )
    assert session.committed is True
    assert authenticate.calls[0] == {
        "database": "vendor_control_plane",
        "principal": PRINCIPAL,
        "material": MATERIAL,
    }
    assert receipt.outcome is BootstrapOutcome.INSTALLED
    assert receipt.authenticated is True
    # BOTH directions were driven: the referenced material, then a deliberately
    # wrong one. A positive-only proof passes on a host that accepts anything.
    assert len(authenticate.calls) == 2
    assert authenticate.calls[0]["material"] == MATERIAL
    assert authenticate.calls[1]["material"] != MATERIAL


def test_a_failed_proof_refuses_and_says_the_credential_is_committed() -> None:
    """The one case where a refusal must NOT read as "nothing happened". The
    ALTER is committed; an operator who retried a rotation here would rotate a
    credential another system may already hold."""
    session = _AdminSession()
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(result=False),
        )
    assert refused.value.code == "credential.authentication_failed"
    assert "COMMITTED" in refused.value.message
    assert session.committed is True


# ── step 7: reconcile by authenticating, and it CANNOT alter ────────────────


def test_the_crash_path_takes_no_session_at_all() -> None:
    """Enforcement rather than description: a function with no database session
    cannot run an `ALTER ROLE` however it is later edited."""
    import inspect

    parameters = inspect.signature(verify_credential).parameters
    assert "admin_db" not in parameters
    assert not any("Session" in str(p.annotation) for p in parameters.values())


def test_the_crash_path_reconciles_by_authenticating() -> None:
    receipt = verify_credential(
        INSTRUCTION, secrets=_secrets(), authenticate=_authenticator()
    )
    assert receipt.outcome is BootstrapOutcome.ALREADY_INSTALLED
    assert receipt.authenticated is True


def test_the_crash_path_refuses_rather_than_reinstalling() -> None:
    """A credential that does not authenticate is NOT reconcilable this way.
    Installing over an unknown credential is a rotation and needs its own
    authorization."""
    with pytest.raises(BootstrapRefused) as refused:
        verify_credential(
            INSTRUCTION, secrets=_secrets(), authenticate=_authenticator(result=False)
        )
    assert refused.value.code == "credential.authentication_failed"
    assert "rotation" in refused.value.message


# ── the reference binds an exact record revision ────────────────────────────


def test_a_record_at_another_version_is_refused() -> None:
    """A record rewritten between planning and execution is refused, not
    installed. The plan binds version 1 because the record is created CAS-zero."""
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            _AdminSession(),  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(version=2),
            authenticate=_authenticator(),
        )
    assert refused.value.code == "material.version_mismatch"


@pytest.mark.parametrize(
    "secrets",
    [
        _Secrets(RuntimeError("bao unreachable")),
        _Secrets(_Record(1, {})),
        _Secrets(None),
    ],
    ids=["unreachable", "field-absent", "not-a-record"],
)
def test_an_unresolvable_pointer_is_refused_without_its_detail(
    secrets: _Secrets,
) -> None:
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            _AdminSession(),  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=secrets,
            authenticate=_authenticator(),
        )
    assert refused.value.code == "material.unresolvable"


# ── what the receipt cannot carry ───────────────────────────────────────────


def test_the_receipt_has_no_field_that_could_hold_the_material() -> None:
    """Structural rather than a convention. A receipt is persisted, read back
    and travels, so the only safe one is a receipt that cannot carry a value.

    Checked on the FIELD NAMES rather than on a rendered instance, because an
    instance that happens not to contain the material today proves nothing about
    the next one.
    """
    from vendor_cp.deployment.credential_bootstrap import BootstrapReceipt

    names = {field.name for field in dataclasses.fields(BootstrapReceipt)}
    assert not names & {"material", "password", "secret", "dsn", "statement"}
    receipt = verify_credential(
        INSTRUCTION, secrets=_secrets(), authenticate=_authenticator()
    )
    assert MATERIAL not in repr(receipt)
    assert MATERIAL not in str(dataclasses.asdict(receipt))


def test_the_allowlist_is_narrow_and_can_refuse() -> None:
    assert ALLOWED_PRINCIPALS == {PRINCIPAL}
    assert "app_admin" not in ALLOWED_PRINCIPALS
    assert "postgres" not in ALLOWED_PRINCIPALS


def test_every_refusal_code_is_declared_and_distinct() -> None:
    assert len(REFUSAL_CODES) == 10
    assert all(code.count(".") == 1 for code in REFUSAL_CODES)


# ── step 6 needs a host that can say no ─────────────────────────────────────


def test_a_host_that_accepts_anything_is_refused() -> None:
    """A PROOF THAT CANNOT FAIL IS NOT A PROOF.

    A `trust`-configured server accepts every password, so the positive half of
    step 6 passes there while establishing nothing. This is not hypothetical:
    the migration-tier cluster runs `POSTGRES_HOST_AUTH_METHOD: trust`, and its
    negative control is what found it — a wrong password authenticated, and the
    positive check had been green the whole time.
    """
    session = _AdminSession()
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(enforces=False),
        )
    assert refused.value.code == "credential.authentication_not_enforced"
    assert "means nothing" in refused.value.message


def test_the_crash_path_also_requires_an_enforcing_host() -> None:
    """Step 7 reads rather than writes, and its proof is the same proof."""
    with pytest.raises(BootstrapRefused) as refused:
        verify_credential(
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(enforces=False),
        )
    assert refused.value.code == "credential.authentication_not_enforced"


def test_the_wrong_material_is_derived_from_the_real_one() -> None:
    """So it is guaranteed to differ. A hardcoded wrong password could collide
    with the real one and turn the negative control into a false alarm."""
    authenticate = _authenticator()
    verify_credential(INSTRUCTION, secrets=_secrets(), authenticate=authenticate)
    tried = [call["material"] for call in authenticate.calls]
    assert tried[0] == MATERIAL
    assert tried[1].startswith(MATERIAL)
    assert tried[1] != MATERIAL
