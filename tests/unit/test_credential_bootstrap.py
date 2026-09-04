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
from typing import Any

import pytest

from vendor_cp.deployment.credential_bootstrap import (
    ALLOWED_PRINCIPALS,
    REFUSAL_CODES,
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


class _AdminSession:
    """A privileged session, faked at the statement level.

    Records every statement in order, so the tests can assert the SEQUENCE —
    which is the part of this effect that is the design.
    """

    def __init__(
        self,
        *,
        role: tuple[bool, bool] | None = (True, False),
        present: bool = False,
    ) -> None:
        self.statements: list[str] = []
        self.committed = False
        self.rolled_back = False
        self._role = role
        self._present = present

    def execute(self, statement: object, params: object = None) -> _Result:
        rendered = str(statement)
        self.statements.append(rendered)
        if "pg_roles" in rendered:
            return _Result(self._role)
        if "pg_authid" in rendered:
            return _Result(self._present)
        if "format(" in rendered:
            return _Result(f"ALTER ROLE {PRINCIPAL} PASSWORD 'quoted-by-postgres'")
        return _Result(None)

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


# ── step 1: four separate refusals, because they need four different fixes ──


@pytest.mark.parametrize(
    ("instruction", "role", "code"),
    [
        (
            dataclasses.replace(INSTRUCTION, principal="Robert'); DROP ROLE--"),
            (True, False),
            "principal.malformed",
        ),
        (
            dataclasses.replace(INSTRUCTION, principal="app_user"),
            (True, False),
            "principal.not_allowlisted",
        ),
        (INSTRUCTION, None, "principal.absent"),
        (INSTRUCTION, (False, False), "principal.not_login"),
        (INSTRUCTION, (True, True), "principal.is_superuser"),
    ],
    ids=["malformed", "not-allowlisted", "absent", "not-login", "superuser"],
)
def test_each_principal_check_refuses_with_its_own_code(
    instruction: PrincipalCredentialBootstrap,
    role: tuple[bool, bool] | None,
    code: str,
) -> None:
    """Five plants, five codes. An aggregate refusal cannot tell "not on the
    list" from "is a superuser", and those need opposite responses."""
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            _AdminSession(role=role),  # type: ignore[arg-type]
            instruction,
            secrets=_secrets(),
            authenticate=_authenticator(),
        )
    assert refused.value.code == code


def test_a_malformed_principal_is_refused_before_the_allowlist() -> None:
    """ORDER. A name that cannot be a role should be reported as malformed
    rather than as unlisted — the second answer sends the reader to the wrong
    file."""
    session = _AdminSession()
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            dataclasses.replace(INSTRUCTION, principal="NOT A ROLE"),
            secrets=_secrets(),
            authenticate=_authenticator(),
        )
    assert refused.value.code == "principal.malformed"
    assert session.statements == [], "it must refuse before querying anything"


# ── steps 2 to 4: the lock comes BEFORE the presence read ───────────────────


def test_the_presence_check_is_taken_under_the_lock() -> None:
    """THE REASON STEP 2 EXISTS.

    A presence check taken before the lock is a check of a state that can change
    before the write, so two executors could both read "absent" and both
    install. Asserted on the statement ORDER, which is the only place this
    property is visible.
    """
    session = _AdminSession()
    bootstrap_principal_credential(
        session,  # type: ignore[arg-type]
        INSTRUCTION,
        secrets=_secrets(),
        authenticate=_authenticator(),
    )
    lock = next(i for i, s in enumerate(session.statements) if "advisory" in s)
    presence = next(i for i, s in enumerate(session.statements) if "pg_authid" in s)
    alter = next(i for i, s in enumerate(session.statements) if "format(" in s)
    assert lock < presence < alter


def test_an_existing_credential_is_refused_and_nothing_is_altered() -> None:
    """Step 4. Install once; present means refuse.

    The rollback matters as much as the refusal: it releases the
    transaction-scoped lock, so a refusing executor does not hold it against the
    next one.
    """
    session = _AdminSession(present=True)
    with pytest.raises(BootstrapRefused) as refused:
        bootstrap_principal_credential(
            session,  # type: ignore[arg-type]
            INSTRUCTION,
            secrets=_secrets(),
            authenticate=_authenticator(),
        )
    assert refused.value.code == "credential.already_present"
    assert not any("format(" in s for s in session.statements)
    assert session.committed is False
    assert session.rolled_back is True


# ── step 5: the statement is quoted by PostgreSQL, not by us ────────────────


def test_the_alter_is_built_by_the_server_and_logging_is_silenced() -> None:
    """Neither half of `ALTER ROLE <name> PASSWORD <literal>` can be a bind
    parameter, so the statement is rendered by `format(%I, %L)` ON THE SERVER
    from bound values. And `log_statement` is silenced first, because the
    rendered statement necessarily contains the material."""
    session = _AdminSession()
    bootstrap_principal_credential(
        session,  # type: ignore[arg-type]
        INSTRUCTION,
        secrets=_secrets(),
        authenticate=_authenticator(),
    )
    silenced = next(i for i, s in enumerate(session.statements) if "log_statement" in s)
    rendered = next(i for i, s in enumerate(session.statements) if "format(" in s)
    assert silenced < rendered
    assert any("%I" in s and "%L" in s for s in session.statements)
    # The material never appears in a statement this module composed. The one
    # statement that contains it is the one the SERVER rendered.
    composed = [s for s in session.statements if "format(" not in s]
    assert all(MATERIAL not in s for s in composed)


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
