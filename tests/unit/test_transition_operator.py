"""Protected installation, owner delegation and redacted operator refusals."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition as cp
from vendor_cp.deployment import transition_operator as op
from vendor_cp.deployment import transition_request as producer

SHA = "sha256:" + "a" * 64
TARGET = "sha256:" + "b" * 64


def document() -> dict:
    return {
        "schema": "dotmac.cp_transition_installation/1",
        "identity": {
            "host": "cp-prod",
            "database": "platform",
            "cluster_system_identifier": "12345",
            "database_oid": 16384,
        },
        "trust": {
            "repository": producer.REPOSITORY,
            "repository_id": producer.REPOSITORY_ID,
            "repository_owner_id": producer.REPOSITORY_OWNER_ID,
            "workflow_path": producer.WORKFLOW_PATH,
            "workflow_revision": "f" * 40,
            "predicate_type": producer.PREDICATE_TYPE,
            "gh_binary": "/opt/cp/gh",
            "gh_binary_digest": SHA,
            "gh_config_directory": "/opt/cp/gh-config",
            "environment_protection_proof": "/opt/cp/protection.json",
            "environment_protection_digest": SHA,
        },
        "host": {
            "repository_root": "/opt/cp/source",
            "deploy_directory": "/opt/cp/deploy",
            "target_descriptor": "/opt/cp/target.toml",
            "source_image": "ghcr.io/michaelayoade/dotmac_vendor_control_plane@" + SHA,
            "target_image": "ghcr.io/michaelayoade/dotmac_vendor_control_plane@"
            + TARGET,
            "postgres_image": "postgres@" + SHA,
            "maintenance_helper": "/opt/cp/maintenance",
            "maintenance_helper_digest": SHA,
            "external_ready_url": "https://platform.dotmac.io/health/ready",
            "candidate_port": 18100,
            "host_id_file": "/etc/cp-host-id",
            "docker_binary": "/usr/bin/docker",
            "docker_binary_digest": SHA,
            "git_binary": "/usr/bin/git",
            "git_binary_digest": SHA,
            "backup_directory": "/opt/cp/backups",
            "compose_file": "/opt/cp/compose.yml",
            "compose_env_file": "/opt/cp/compose.env",
            "runtime_compose_overlay": None,
            "candidate_env_file": None,
            "candidate_runtime_environment": "/opt/cp/runtime.env",
            "licence_key_host_file": "/run/secrets/cp.key",
            "ready_host": "platform.dotmac.io",
            "app_port": 8100,
            "timeout_seconds": 180,
            "session_wait_seconds": 30,
        },
        "artifact_directory": "/opt/cp/artifacts",
        "historical_context_files": [],
    }


@pytest.fixture
def load(monkeypatch):
    monkeypatch.setattr(op.sys, "platform", "linux")
    monkeypatch.setattr(op.os, "geteuid", lambda: 0)
    monkeypatch.setattr(op, "_directory", lambda path: None)

    def read(value):
        monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(value))
        return op.load_installation(Path("/opt/cp/installation.json"))

    return read


def request() -> cp.CpTransitionRequestV1:
    value = {
        "schema": "dotmac.cp_transition_request/1",
        "product": "dotmac_vendor_control_plane",
        "environment": "production",
        **document()["identity"],
        "source": {
            "image_digest": SHA,
            "revision": "a" * 40,
            "raw_descriptor_digest": SHA,
            "heads": ["before"],
        },
        "target": {
            "image_digest": TARGET,
            "revision": "b" * 40,
            "raw_descriptor_digest": TARGET,
            "heads": ["after"],
        },
        "authorization_run_id": 123,
        "authorization_run_attempt": 1,
        "trusted_actor": "actor",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1))
        .isoformat()
        .replace("+00:00", "Z"),
        "previous_receipt_digest": None,
    }
    value["plan_digest"] = cp.transition_plan_digest(value)
    return value


def test_explicit_configuration_constructs_existing_owners(load) -> None:
    from vendor_cp.deployment.cp_transition_host import local_postgres_connection

    installed = load(document())
    assert installed.policy.repository_id == producer.REPOSITORY_ID
    assert installed.host.connection is local_postgres_connection
    assert installed.host.target_descriptor == Path("/opt/cp/target.toml")
    assert installed.host.candidate_env_file is None
    assert installed.host.candidate_runtime_environment == Path("/opt/cp/runtime.env")
    assert installed.store.root == Path("/opt/cp/artifacts")
    assert installed.historical_context_files == ()


def test_committed_installation_pins_operator_and_excludes_held_context(load):
    value = document()
    value["committed_migration_context"] = {"path": "/opt/cp/context", "digest": SHA}
    with pytest.raises(ContractError, match="operator_revision_required"):
        load(value)
    value["operator_revision"] = "c" * 40
    installed = load(value)
    assert installed.operator_revision == installed.host.operator_revision == "c" * 40
    value["held_fence_context"] = {
        "path": "/opt/cp/held",
        "digest": SHA,
        "proof_digest": SHA,
        "fence_id": "d" * 64,
    }
    with pytest.raises(ContractError, match="contexts_conflict"):
        load(value)


@pytest.fixture
def historical_execution(load, monkeypatch):
    installed = load(document())
    prior = request()
    start = int(datetime.now(UTC).timestamp())
    invocation = {
        "status": "ONE_ATTEMPT_STARTED",
        "run_id": prior["authorization_run_id"],
        "started_unix": start,
        "request_sha256": cp.request_digest(prior)[7:],
        "bundle_sha256": "b" * 64,
    }
    result = {
        "status": "OWNER_RETURNED",
        "exit": 3,
        "stdout_bytes": 201,
        "stderr_bytes": 8482,
        "work": "/opt/cp/original",
        "completed_unix": start + 60,
    }
    context = {
        "schema": "dotmac.cp_historical_authorization_context/1",
        "trust": document()["trust"],
        "request_name": "request.json",
        "invocation_file": "/opt/cp/original/invocation.json",
        "invocation_digest": cp.raw_digest(canonical_json(invocation)),
        "result_file": "/opt/cp/original/result.json",
        "result_digest": cp.raw_digest(canonical_json(result)),
    }
    reads = {}
    seen = {}

    def historical(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(verify=lambda value: seen.update(prior=value))

    monkeypatch.setattr(cp, "HistoricalAuthorization", historical)
    monkeypatch.setattr(cp, "_read_protected", lambda path: reads[path])

    def run():
        raw = canonical_json(context)
        key = cp.raw_digest(raw)
        blobs = {key: raw, SHA: b"retained-verification"}
        reads[Path("/opt/cp/original/invocation.json")] = canonical_json(invocation)
        reads[Path("/opt/cp/original/result.json")] = canonical_json(result)
        reads[Path("/opt/cp/protection.json")] = b"protected-policy-snapshot"
        return op._load_historical_authorization(
            installed,
            SimpleNamespace(read=lambda checksum: blobs[checksum]),
            {
                "request": prior,
                "authorization_context_digest": key,
                "authorization_verification_digest": SHA,
            },
        )

    return run, invocation, result, context, seen


def test_historical_execution_window_comes_from_both_protected_records(
    historical_execution,
):
    run, invocation, result, _context, seen = historical_execution
    run()
    assert seen["execution_window_start"] == datetime.fromtimestamp(
        invocation["started_unix"], UTC
    )
    assert seen["execution_window_end"] == datetime.fromtimestamp(
        result["completed_unix"], UTC
    )
    assert seen["verification_bytes"] == b"retained-verification"
    assert seen["prior"]["authorization_run_id"] == invocation["run_id"]


@pytest.mark.parametrize("field", ["run_id", "request_sha256", "started_unix", "extra"])
def test_changed_original_invocation_cannot_supply_historical_time(
    historical_execution, field
):
    run, invocation, _result, context, _seen = historical_execution
    invocation[field] = 0 if field in {"run_id", "started_unix"} else "changed"
    context["invocation_digest"] = cp.raw_digest(canonical_json(invocation))
    with pytest.raises(ContractError):
        run()


@pytest.mark.parametrize("field", ["work", "completed_unix", "exit", "extra"])
def test_changed_original_completion_cannot_supply_historical_time(
    historical_execution, field
):
    run, _invocation, result, context, _seen = historical_execution
    result[field] = 0 if field in {"completed_unix", "exit"} else "changed"
    context["result_digest"] = cp.raw_digest(canonical_json(result))
    with pytest.raises(ContractError):
        run()


def test_original_execution_record_raw_digest_is_required(historical_execution):
    run, invocation, _result, _context, _seen = historical_execution
    invocation["started_unix"] += 1
    with pytest.raises(ContractError, match="records_mismatch"):
        run()


def test_committed_context_raw_pin_is_independent_of_request(load, monkeypatch):
    installed = load(document())
    monkeypatch.setattr(cp, "_read_protected", lambda path: b"{}")
    with pytest.raises(ContractError, match="context_digest_mismatch"):
        op._load_committed_context(
            installed, {"path": "/opt/cp/context", "digest": SHA}
        )


@pytest.mark.parametrize("section", [None, "identity", "trust", "host"])
def test_unknown_or_secret_configuration_fields_refused(load, section) -> None:
    value = document()
    target = value if section is None else value[section]
    target["password"] = "NEVER_ECHO"
    with pytest.raises(ContractError):
        load(value)


@pytest.mark.parametrize(
    "key",
    [
        "repository",
        "repository_id",
        "repository_owner_id",
        "workflow_path",
        "predicate_type",
    ],
)
def test_installation_cannot_replace_repository_trust(load, key) -> None:
    value = document()
    value["trust"][key] = "another-authority"
    with pytest.raises(ContractError):
        load(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("candidate_port", True),
        ("app_port", 0),
        ("timeout_seconds", -1),
        ("repository_root", "relative/path"),
        ("docker_binary", "/opt/../unreviewed/docker"),
        ("target_image", "registry.invalid/cp:latest"),
        ("source_image", "registry.invalid/cp@" + SHA),
        ("postgres_image", "postgres:17"),
        ("external_ready_url", "https://user:password@example.invalid/"),
        ("candidate_env_file", "/opt/cp/ambiguous.env"),
        ("candidate_runtime_environment", None),
        ("connection", "serialized.callable"),
    ],
)
def test_unsafe_host_installation_refused(load, field, replacement) -> None:
    value = document()
    value["host"][field] = replacement
    with pytest.raises(ContractError):
        load(value)


def test_missing_explicit_installation_field_is_not_defaulted(load) -> None:
    value = document()
    del value["host"]["licence_key_host_file"]
    with pytest.raises(ContractError):
        load(value)


@pytest.mark.parametrize(("platform", "uid"), [("darwin", 0), ("linux", 1000)])
def test_nonroot_or_nonlinux_refused_before_read(monkeypatch, platform, uid) -> None:
    monkeypatch.setattr(op.sys, "platform", platform)
    monkeypatch.setattr(op.os, "geteuid", lambda: uid)
    monkeypatch.setattr(
        cp,
        "_read_protected",
        lambda path: pytest.fail("configuration must not be read"),
    )
    with pytest.raises(ContractError):
        op.load_installation(Path("/opt/cp/config.json"))


def test_unsafe_ancestor_refuses_before_configuration_read(monkeypatch) -> None:
    monkeypatch.setattr(op.sys, "platform", "linux")
    monkeypatch.setattr(op.os, "geteuid", lambda: 0)
    # /tmp is a world-writable ancestor; the protected-path owner refuses even
    # if a root caller selected the nonexistent leaf. No file is created/read.
    with pytest.raises((ContractError, OSError)):
        op.load_installation(Path("/tmp/cp-unsafe-ancestor/config.json"))  # noqa: S108 - planted unsafe ancestor


def historical() -> dict:
    return {
        "schema": "dotmac.cp_transition_recovery_context/1",
        "receipt_digest": SHA,
        "request": request(),
        "incumbent_roles": [{"role": "app", "image_digest": SHA}],
        "backup": {
            "dataset": "primary",
            "path": "/opt/cp/backups/retained",
            "size_bytes": 100,
            "checksum": "a" * 64,
            "checksum_algorithm": "sha256",
            "manifest_size_bytes": 20,
            "database_dump_sha256": SHA,
            "database_dump_size_bytes": 50,
            "globals_sha256": SHA,
            "globals_size_bytes": 20,
        },
    }


@pytest.mark.parametrize("section", [None, "backup", "request"])
def test_historical_context_is_closed_and_independently_installed(
    load, monkeypatch, section
) -> None:
    installed = load(document())
    installed = op.Installation(
        installed.policy,
        installed.host,
        installed.store,
        (Path("/opt/cp/history.json"),),
    )
    entry = historical()
    target = entry if section is None else entry[section]
    target["untrusted_claim"] = "injected"
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(entry))
    with pytest.raises(ContractError):
        op._load_recovery(installed)


def test_historical_context_wrong_database_refused(load, monkeypatch) -> None:
    installed = load(document())
    installed = op.Installation(
        installed.policy,
        installed.host,
        installed.store,
        (Path("/opt/cp/history.json"),),
    )
    entry = historical()
    entry["request"]["database_oid"] += 1
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(entry))
    with pytest.raises(ContractError):
        op._load_recovery(installed)


def test_composition_shares_mutable_recovery_and_returns_receipt_only(
    load, monkeypatch
) -> None:
    from vendor_cp.deployment import cp_transition_host

    installed = load(document())
    raw = canonical_json(request())
    monkeypatch.setattr(op, "load_installation", lambda path: installed)
    monkeypatch.setattr(cp, "_read_protected", lambda path: raw)
    seen = {}

    def host(config, *, store, recovery):
        seen["host_recovery"] = recovery
        return SimpleNamespace()

    def execute(raw_request, **kwargs):
        assert raw_request == raw
        assert kwargs["store"] is installed.store
        assert kwargs["recovery"] is seen["host_recovery"]
        assert isinstance(kwargs["recovery"], dict)
        assert kwargs["verifier"].policy is installed.policy
        return SHA

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", host)
    monkeypatch.setattr(cp, "execute_transition", execute)
    assert (
        op.run_transition(config_file=Path("/config"), request_file=Path("/request"))
        == SHA
    )


def test_previous_receipt_without_installed_context_refuses(load, monkeypatch) -> None:
    installed = load(document())
    candidate = request()
    candidate["previous_receipt_digest"] = SHA
    candidate["plan_digest"] = cp.transition_plan_digest(candidate)
    monkeypatch.setattr(op, "load_installation", lambda path: installed)
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(candidate))
    monkeypatch.setattr(
        installed.store,
        "read",
        lambda *args, **kwargs: canonical_json(
            {
                "schema": "dotmac.cp_migration_transition_receipt/1",
                "request": candidate,
                "request_digest": cp.request_digest(candidate),
                "host_nonce": "a" * 64,
                "phase": "complete",
                "genesis_digest": None,
                "previous_receipt_digest": SHA,
                "evidence": {},
            }
        ),
    )
    monkeypatch.setattr(
        cp, "execute_transition", lambda *args, **kwargs: pytest.fail("cannot execute")
    )
    with pytest.raises(op.TransitionOperatorRefused, match="^CP_TRANSITION_REFUSED$"):
        op.run_transition(config_file=Path("/config"), request_file=Path("/request"))


def test_cli_parser_owner_and_redacted_exit(monkeypatch, capsys) -> None:
    from vendor_cp.cli import build_parser, main
    from vendor_cp.cli.owners import by_command

    argv = [
        "admin",
        "cp-transition",
        "--config-file",
        "/config",
        "--request-file",
        "/request",
        "--bundle-file",
        "/bundle",
    ]
    args = build_parser().parse_args(argv)
    assert args.command == "admin cp-transition"
    owner = by_command()[args.command]
    assert (owner.module, owner.symbol, owner.mutates) == (
        op.__name__,
        "run_transition",
        True,
    )
    seen = {}

    def run(**kwargs):
        seen.update(kwargs)
        return SHA

    monkeypatch.setattr(op, "run_transition", run)
    assert main(["--format", "json", *argv]) == 0
    assert SHA in capsys.readouterr().out
    assert seen == {
        "config_file": Path("/config"),
        "request_file": Path("/request"),
        "bundle_file": Path("/bundle"),
    }

    def refuse(**kwargs):
        raise op.TransitionOperatorRefused("NEVER_ECHO")

    monkeypatch.setattr(op, "run_transition", refuse)
    assert main(["--format", "json", *argv]) == 3
    output = capsys.readouterr()
    assert "NEVER_ECHO" not in output.out + output.err
    result = json.loads(output.out)
    assert "CP_TRANSITION_REFUSED" in str(result)


def test_operator_failure_redacts_configuration_errors(monkeypatch) -> None:
    def fail(path):
        raise ValueError("NEVER_ECHO")

    monkeypatch.setattr(op, "load_installation", fail)
    with pytest.raises(
        op.TransitionOperatorRefused, match="^CP_TRANSITION_REFUSED$"
    ) as error:
        op.run_transition(config_file=Path("/config"), request_file=Path("/request"))
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("size_bytes", True), ("checksum", SHA), ("database_dump_sha256", "a" * 64)],
)
def test_bad_historical_backup_metadata_refused(load, monkeypatch, field, replacement):
    installed = load(document())
    installed = op.Installation(
        installed.policy,
        installed.host,
        installed.store,
        (Path("/opt/cp/history.json"),),
    )
    entry = historical()
    entry["backup"][field] = replacement
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(entry))
    with pytest.raises(ContractError):
        op._load_recovery(installed)


def test_overlay_requires_protected_file_metadata(load, monkeypatch):
    value = document()
    value["host"]["runtime_compose_overlay"] = "/opt/cp/runtime-overlay.yml"
    seen = []

    def reject(path):
        seen.append(path)
        raise ContractError("unsafe_artifact_path")

    monkeypatch.setattr(op, "_file", reject)
    with pytest.raises(ContractError):
        load(value)
    assert seen == [Path("/opt/cp/runtime-overlay.yml")]


def test_historical_reconstruction_uses_backup_and_receipt_owners(
    load, monkeypatch, tmp_path
):
    import os
    from dataclasses import replace

    installed = load(document())
    installed = op.Installation(
        installed.policy,
        replace(installed.host, backup_directory=tmp_path.parent),
        installed.store,
        (Path("/opt/cp/history.json"),),
    )
    entry = historical()
    entry["backup"]["path"] = str(tmp_path)
    for name in op.BUNDLE_COMPONENTS:
        (tmp_path / name).write_bytes(b"synthetic retained backup component")
    receipt = {
        "schema": "dotmac.cp_migration_transition_receipt/1",
        "request": entry["request"],
        "request_digest": cp.request_digest(entry["request"]),
        "host_nonce": "a" * 64,
        "phase": "complete",
        "genesis_digest": SHA,
        "previous_receipt_digest": None,
        "evidence": {},
    }
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(entry))
    monkeypatch.setattr(
        installed.store,
        "read",
        lambda checksum, **kwargs: (
            canonical_json(receipt)
            if kwargs.get("kind") == "receipt"
            else b"synthetic retained exact descriptor"
        ),
    )
    monkeypatch.setattr(
        cp,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    monkeypatch.setattr(cp, "_protected", lambda info, **kwargs: None)
    seen = {}

    def verify_backup(backup):
        seen["backup"] = backup
        return True

    owner = SimpleNamespace(verify=verify_backup)

    def construct(*args, **kwargs):
        seen["binding"] = kwargs
        return owner

    monkeypatch.setattr(
        op, "PlatformCpRecoveryBundle", SimpleNamespace(for_transition=construct)
    )

    def verify_receipt(raw, **kwargs):
        seen["receipt"] = kwargs

    monkeypatch.setattr(cp, "verify_receipt", verify_receipt)
    result = op._load_recovery(installed)
    key = cp.request_digest(entry["request"])
    assert result[key] == (owner, seen["backup"])
    assert (
        seen["binding"]["source_descriptor"] == b"synthetic retained exact descriptor"
    )
    assert seen["binding"]["target"] == installed.policy.identity.host
    assert seen["backup"].checksum == "a" * 64
    assert seen["receipt"]["recovery"] is result
    assert seen["receipt"]["request"] == entry["request"]


def committed_request():
    value = {
        **request(),
        "schema": "dotmac.cp_committed_migration_request/1",
        "authorization_run_id": 124,
        "operator_revision": "c" * 40,
        "basis": {
            "context_digest": SHA,
            "prior_request_digest": SHA,
            "prior_host_nonce": "d" * 64,
            "prior_reservation_digest": SHA,
            "prior_authorization_digest": SHA,
            "original_fence_digest": SHA,
            "current_fence_digest": SHA,
            "current_fence_id": "d" * 64,
            "frontier_measurement_digest": SHA,
        },
    }
    value["plan_digest"] = cp.transition_plan_digest(value)
    return value


def test_operator_dispatches_committed_request_without_v1_execution(load, monkeypatch):
    from vendor_cp.deployment import cp_transition_host

    value = document()
    value["operator_revision"] = "c" * 40
    value["committed_migration_context"] = {"path": "/opt/cp/context", "digest": SHA}
    installed = load(value)
    raw = canonical_json(committed_request())
    binding = object()
    context = SimpleNamespace(context_digest=SHA, recovery={"original-key": binding})
    seen = {}
    monkeypatch.setattr(op, "load_installation", lambda path: installed)
    monkeypatch.setattr(cp, "_read_protected", lambda path: raw)
    monkeypatch.setattr(op, "_load_committed_context", lambda installation: context)

    def host(config, **kwargs):
        seen.update(host=kwargs)
        return SimpleNamespace()

    def execute(raw_request, **kwargs):
        assert raw_request == raw
        assert kwargs["context"] is context
        assert kwargs["recovery"] == {"original-key": binding}
        assert kwargs["committed_contexts"] == {SHA: context}
        return TARGET

    monkeypatch.setattr(cp_transition_host, "ExistingCpTransitionHost", host)
    monkeypatch.setattr(cp, "execute_committed_continuation", execute)
    monkeypatch.setattr(
        cp, "execute_transition", lambda *a, **kw: pytest.fail("V1 used")
    )
    assert (
        op.run_transition(config_file=Path("/config"), request_file=Path("/request"))
        == TARGET
    )
    assert seen["host"]["committed_context"] is context
    assert seen["host"]["committed_contexts"] == {SHA: context}


def test_operator_refuses_different_operator_revision_before_context_loading(
    load, monkeypatch
):
    value = document()
    value["operator_revision"] = "e" * 40
    installed = load(value)
    raw = canonical_json(committed_request())
    monkeypatch.setattr(op, "load_installation", lambda path: installed)
    monkeypatch.setattr(cp, "_read_protected", lambda path: raw)
    monkeypatch.setattr(
        op, "_load_committed_context", lambda *a: pytest.fail("context loaded")
    )
    with pytest.raises(op.TransitionOperatorRefused, match="CP_TRANSITION_REFUSED"):
        op.run_transition(config_file=Path("/config"), request_file=Path("/request"))


def test_history_loads_explicit_committed_receipt_and_both_contexts(load, monkeypatch):
    value = document()
    value["historical_context_files"] = ["/opt/cp/history"]
    installed = load(value)
    entry = {
        "schema": "dotmac.cp_committed_recovery_context/1",
        "receipt_digest": TARGET,
        "committed_context": {"path": "/opt/cp/context", "digest": SHA},
    }
    current = committed_request()
    receipt = {
        "schema": "dotmac.cp_committed_migration_receipt/1",
        "request": current,
        "request_digest": cp.request_digest(current),
        "host_nonce": "e" * 64,
        "phase": "complete",
        "historical_context_digest": SHA,
        "frontier_reservation_digest": TARGET,
        "evidence": {},
    }
    binding = object()
    context = SimpleNamespace(context_digest=SHA, recovery={"original-key": binding})
    monkeypatch.setattr(cp, "_read_protected", lambda path: canonical_json(entry))
    monkeypatch.setattr(op, "_load_committed_context", lambda *a: context)
    monkeypatch.setattr(
        installed.store, "read", lambda *a, **kw: canonical_json(receipt)
    )
    seen = {}
    monkeypatch.setattr(
        cp, "verify_committed_receipt", lambda raw, **kw: seen.update(kw)
    )
    contexts = {}
    assert op._load_recovery(installed, committed_contexts=contexts) == {
        "original-key": binding
    }
    assert contexts == {SHA: context}
    assert seen["context"] is context and seen["routing_gate"] is True
    assert seen["committed_contexts"] is contexts
