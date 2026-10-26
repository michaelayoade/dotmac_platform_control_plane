"""Actual host password installer on disposable PG16; auth premise is explicit.

The ordinary migration service uses trust. Only the separately configured SCRAM
lane (CP_CANDIDATE_PASSWORD_AUTH_REQUIRED=1) proves password refusal. No test
changes pg_hba or reads/changes any permanent role's password.
"""

from __future__ import annotations

import os
import secrets
import uuid
from types import SimpleNamespace
from typing import cast

from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import OperationalError

from vendor_cp.deployment import candidate_roles
from vendor_cp.deployment import cp_transition_host as host_module
from vendor_cp.deployment import transition_fence as fence


def _login(url: URL, expected_role: str) -> bool:
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        try:
            with engine.connect() as connection:
                assert (
                    connection.execute(text("SELECT current_user")).scalar_one()
                    == expected_role
                )
            return True
        except OperationalError as refusal:
            # Inspect only the fixed authentication category; never print driver
            # diagnostics, DSNs, parameters or the synthetic credential.
            password_denial = "password authentication failed" in str(refusal.orig)
            assert password_denial, "unexpected candidate login refusal category"
            return False
    finally:
        engine.dispose()


def test_actual_host_installer_password_login_cleanup_and_auth_premise(
    postgres_url, scratch_db, target_only_connect, url_for, monkeypatch
):
    mode = os.getenv("CP_CANDIDATE_PASSWORD_AUTH_REQUIRED", "0")
    assert mode in {"0", "1"}
    database = make_url(scratch_db).database
    assert database is not None
    roles = candidate_roles.CandidateRoles.for_run(
        database=database, run_id=uuid.uuid4().hex
    )
    # Include SQL-format and quoting characters; server format(%L) must own
    # literal quoting while the GUC transfer remains parameterised.
    passwords = tuple(secrets.token_urlsafe(32) + "'\\%L" for _ in roles.bindings())
    env = {"VENDOR_DEPLOYMENT_PROFILE": "production-keyless-v1"}
    for (role, _parent), key, password in zip(
        roles.bindings(),
        ("DATABASE_URL", "PLATFORM_DATABASE_URL"),
        passwords,
        strict=True,
    ):
        env[key] = URL.create(
            "postgresql+psycopg", username=role, password=password, database=database
        ).render_as_string(hide_password=False)
    raw_env = "".join(f"{key}={value}\n" for key, value in env.items()).encode()
    monkeypatch.setattr(host_module, "_read_protected", lambda path: raw_env)
    host = object.__new__(host_module.ExistingCpTransitionHost)
    host.roles = roles
    host.launch = cast(
        host_module.CandidateComposeLaunch,
        SimpleNamespace(env_file="synthetic-held-env"),
    )
    engine = create_engine(
        url_for(postgres_url, database), isolation_level="AUTOCOMMIT"
    )
    try:
        with engine.connect() as owner:
            version = int(owner.execute(text("SHOW server_version_num")).scalar_one())
            assert 160000 <= version < 170000
            assert (
                owner.execute(text("SHOW password_encryption")).scalar_one()
                == "scram-sha-256"
            )
            proof = fence.fence_writers(
                owner,
                database=database,
                fence_id=uuid.uuid4().hex,
                session_wait_seconds=3,
            )
            args = {
                "expected_digest": proof.digest(),
                "expected_fence_id": proof.fence_id,
            }
            try:
                candidate_roles.create_roles(owner, roles, proof, **args)
                # This is the actual previously uncovered host implementation,
                # not test_candidate_roles' alternate password helper.
                host._install_candidate_passwords(cast(Connection, owner))
                assert (
                    owner.execute(
                        text(
                            "SELECT current_setting('dotmac.candidate_password', true)"
                        )
                    ).scalar_one()
                    == ""
                )
                assert (
                    owner.execute(
                        text(
                            "SELECT count(*) FROM pg_authid "
                            "WHERE rolname=ANY(CAST(:names AS text[])) "
                            "AND rolpassword IS NOT NULL"
                        ),
                        {"names": [name for name, _ in roles.bindings()]},
                    ).scalar_one()
                    == 2
                )
                candidate_roles.activate(owner, roles, proof, **args)
                assert candidate_roles.verify_staged_database(
                    owner, roles, proof, **args
                )
                for (role, _parent), password in zip(
                    roles.bindings(), passwords, strict=True
                ):
                    base = make_url(postgres_url).set(
                        username=role, database=database, password=password
                    )
                    assert _login(base, role) is True
                    wrong_accepted = _login(
                        base.set(password=password + "-wrong"), role
                    )
                    if mode == "1":
                        assert (
                            wrong_accepted is False
                        ), "SCRAM lane must refuse wrong passwords"
                    else:
                        assert (
                            wrong_accepted is True
                        ), "ordinary migration fixture must retain its trust premise"
            finally:
                present = owner.execute(
                    text(
                        "SELECT count(*) FROM pg_roles "
                        "WHERE rolname=ANY(CAST(:names AS text[]))"
                    ),
                    {"names": [name for name, _ in roles.bindings()]},
                ).scalar_one()
                if present == 2:
                    candidate_roles.deactivate(owner, roles, proof, **args)
                candidate_roles.cleanup_before_restore(owner, roles, proof, **args)
                assert fence.fence_is_holding(owner, proof)
                assert (
                    owner.execute(
                        text(
                            "SELECT count(*) FROM pg_roles "
                            "WHERE rolname=ANY(CAST(:names AS text[]))"
                        ),
                        {"names": [name for name, _ in roles.bindings()]},
                    ).scalar_one()
                    == 0
                )
                fence.restore_writers(
                    owner,
                    proof,
                    database=database,
                    expected_fence_id=proof.fence_id,
                    session_wait_seconds=3,
                )
    finally:
        engine.dispose()
