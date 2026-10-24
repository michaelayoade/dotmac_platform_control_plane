"""Adversarial CP-only contract, replay and retained-evidence checks."""

from __future__ import annotations

import copy
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_catalogue
from vendor_cp.deployment import cp_transition as cp

NOW = datetime(2026, 10, 24, tzinfo=UTC)
SHA = "sha256:" + "a" * 64
GLOBALS = b"CREATE ROLE postgres;\nglobals\n"
IDENTITY = cp.CpTransitionIdentity("cp-prod", "platform", "12345", 16384)


def descriptor(image, revision):
    return (
        'product = "dotmac_vendor_control_plane"\nenvironment = "production"\n'
        f'[image]\nreference = "registry.invalid/cp@{image}"\n'
        f'source_revision = "{revision}"\n'
    ).encode()


def request() -> cp.CpTransitionRequestV1:
    value: cp.CpTransitionRequestV1 = {
        "schema": "dotmac.cp_transition_request/1",
        "product": "dotmac_vendor_control_plane",
        "environment": "production",
        "host": "cp-prod",
        "database": "platform",
        "cluster_system_identifier": "12345",
        "database_oid": 16384,
        "source": {
            "image_digest": SHA,
            "revision": "a" * 40,
            "raw_descriptor_digest": cp.raw_digest(descriptor(SHA, "a" * 40)),
            "heads": ["a", "b"],
        },
        "target": {
            "image_digest": "sha256:" + "b" * 64,
            "revision": "b" * 40,
            "raw_descriptor_digest": cp.raw_digest(
                descriptor("sha256:" + "b" * 64, "b" * 40)
            ),
            "heads": ["c", "d"],
        },
        "plan_digest": SHA,
        "authorization_run_id": 123,
        "authorization_run_attempt": 2,
        "trusted_actor": "example",
        "expires_at": "2026-10-25T00:00:00Z",
        "previous_receipt_digest": None,
    }

    value["plan_digest"] = cp.transition_plan_digest(value)
    return value


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("unknown", 1),
        ("database_oid", True),
        ("authorization_run_id", True),
        ("authorization_run_attempt", 0),
        ("host", "another-host"),
        ("cluster_system_identifier", "999"),
        ("database", "other"),
        ("expires_at", "2026-10-23T00:00:00Z"),
        ("plan_digest", SHA),
    ],
)
def test_request_refuses_wrong_bindings(key: str, value: object) -> None:
    candidate = dict(request())
    candidate[key] = value
    with pytest.raises(ContractError):
        cp.validate_request(candidate, identity=IDENTITY, now=NOW)


def test_duplicate_json_and_heads_refused() -> None:
    raw = canonical_json(request()).replace(
        b'"database_oid":16384', b'"database_oid":16384,"database_oid":1'
    )
    with pytest.raises(ContractError):
        cp.load_request(raw, identity=IDENTITY, now=NOW)
    candidate = copy.deepcopy(request())
    candidate["source"]["heads"] = ["a", "a"]
    with pytest.raises(ContractError):
        cp.validate_request(candidate, identity=IDENTITY, now=NOW)


def test_closed_request_roundtrip() -> None:
    value = cp.load_request(canonical_json(request()), identity=IDENTITY, now=NOW)
    assert value == request()
    assert cp.request_digest(value) == cp.request_digest(request())


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trust) -> cp.ArtifactStore:
    """Exercise actual exclusive I/O; emulate only root ownership for local tests."""
    protected = cp._protected

    def root_owned(info: os.stat_result, *, directory: bool) -> None:
        entries = list(info)
        entries[4] = 0
        protected(os.stat_result(entries), directory=directory)

    monkeypatch.setattr(cp, "_protected", root_owned)
    monkeypatch.setattr(
        cp,
        "_open_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    retained = cp.ArtifactStore(tmp_path)
    verifier, path, *_ = trust
    verified = verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)
    reserve = retained.reserve
    monkeypatch.setattr(
        retained,
        "reserve",
        lambda value, authorization=verified: reserve(value, authorization),
    )
    retained.recovery = {}
    return retained


def test_reservation_is_single_use_even_without_completion(
    store: cp.ArtifactStore,
) -> None:
    nonce = store.reserve(request())
    assert len(nonce) == 64
    with pytest.raises(FileExistsError):
        store.reserve(request())


def test_partial_write_keeps_reservation_consumed(
    store: cp.ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_write(_descriptor: int, _raw: object) -> int:
        raise OSError("disk full")

    with monkeypatch.context() as context:
        context.setattr(cp.os, "write", failed_write)
        with pytest.raises(OSError):
            store.reserve(request())
    with pytest.raises(FileExistsError):
        store.reserve(request())


def test_artifact_bytes_and_hardlinks_are_checked(store: cp.ArtifactStore) -> None:
    checksum = store.put(b"actual recovery evidence")
    location = store.root / store._name(checksum, "evidence")
    location.write_bytes(b"replaced")
    with pytest.raises(ContractError, match="artifact_digest_mismatch"):
        store.read(checksum)
    os.link(location, store.root / "hardlink")
    with pytest.raises(ContractError, match="unsafe_artifact_path"):
        store.read(checksum)


def test_symlink_is_never_followed(store: cp.ArtifactStore) -> None:
    name = store.root / store._name(SHA, "evidence")
    name.symlink_to(store.root / "missing")
    with pytest.raises(OSError):
        store.read(SHA)


def test_protected_directory_policy_rejects_writable_parents(tmp_path: Path) -> None:
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)
    retained = writable / "artifacts"
    retained.mkdir()
    with pytest.raises(ContractError, match="unsafe_artifact_path"):
        descriptor = cp._open_directory(retained)
        os.close(descriptor)


@pytest.fixture
def trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Synthetic values using the published sigstore-go verification JSON shape.

    Primary schema: github.com/sigstore/sigstore-go/blob/main/docs/verification.md
    No attestation is minted: only subprocess.run is replaced for unit tests.
    """
    import json
    import subprocess
    from types import SimpleNamespace

    proof = canonical_json(
        {
            "schema": "dotmac.cp_transition_environment_protection/2",
            "repository_id": "100",
            "repository_owner_id": "200",
            "workflow_revision": "c" * 40,
            "environment": "production",
            "protected_main": True,
            "approval_model": "single-user-manual",
            "prevent_self_review": False,
            "can_admins_bypass": False,
            "required_reviewer_ids": [200],
            "expires_at": "2026-10-25T00:00:00Z",
        }
    )
    policy = cp.CpTransitionTrustPolicy(
        IDENTITY,
        tmp_path / "gh",
        cp.raw_digest(b"published gh"),
        tmp_path,
        "example/cp",
        "100",
        "200",
        ".github/workflows/authorize.yml",
        "c" * 40,
        "https://example.test/cp-transition/1",
        tmp_path / "protection.json",
        cp.raw_digest(proof),
    )
    verifier = cp.GhAttestationVerifier(policy)
    request_path = tmp_path / "request.json"
    repository = "https://github.com/example/cp"
    signer = repository + "/.github/workflows/authorize.yml@refs/heads/main"
    cert = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": {"type": "URI", "value": signer},
        "buildSignerURI": signer,
        "buildSignerDigest": "c" * 40,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": repository,
        "sourceRepositoryDigest": "c" * 40,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryIdentifier": "100",
        "sourceRepositoryOwnerIdentifier": "200",
        "buildConfigURI": signer,
        "buildConfigDigest": "c" * 40,
        "runInvocationURI": repository + "/actions/runs/123/attempts/2",
    }
    result = {
        "signature": {"certificate": cert},
        "verifiedTimestamps": [
            {
                "type": "Tlog",
                "timestamp": "2026-10-24T00:00:00Z",
                "uri": "https://rekor.sigstore.dev",
            }
        ],
        "statement": {
            "predicateType": policy.predicate_type,
            "subject": [
                {
                    "name": "request.json",
                    "digest": {"sha256": cp.raw_digest(canonical_json(request()))[7:]},
                }
            ],
            "predicate": {
                "request_digest": cp.request_digest(request()),
                "trusted_actor": "example",
                "environment": "production",
            },
        },
    }
    files = {
        request_path: canonical_json(request()),
        policy.gh_binary: b"published gh",
        policy.environment_protection_proof: proof,
    }
    monkeypatch.setattr(cp, "_read_protected", files.__getitem__)
    monkeypatch.setattr(
        cp, "_protected_executable_digest", lambda path: cp.raw_digest(files[path])
    )
    monkeypatch.setattr(
        cp, "_open_directory", lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    )

    def run(argv, **kwargs):
        for flag in (
            "--repo",
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref",
            "--deny-self-hosted-runners",
            "--predicate-type",
            "--format",
        ):
            assert flag in argv
        assert set(kwargs["env"]) == {"GH_CONFIG_DIR", "PATH", "HOME"}
        return SimpleNamespace(
            returncode=0, stdout=json.dumps([{"verificationResult": result}]).encode()
        )

    monkeypatch.setattr(subprocess, "run", run)
    return verifier, request_path, result, cert, files


def test_real_verifier_boundary_checks_certificate(trust) -> None:
    verifier, path, _result, _cert, _files = trust
    verified = verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)
    assert verified.authorization_run_id == 123
    assert verified.authorization_run_attempt == 2


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("runnerEnvironment", "self-hosted"),
        ("sourceRepositoryIdentifier", "999"),
        ("sourceRepositoryOwnerIdentifier", "999"),
        ("sourceRepositoryRef", "refs/heads/evil"),
        ("buildSignerDigest", "d" * 40),
        ("sourceRepositoryDigest", "d" * 40),
        (
            "runInvocationURI",
            "https://github.com/example/cp/actions/runs/123/attempts/1",
        ),
        ("issuer", "https://attacker.test"),
    ],
)
def test_auth_refuses_forged_certificate_bindings(trust, field, bad) -> None:
    verifier, path, _result, cert, _files = trust
    cert[field] = bad
    with pytest.raises(ContractError):
        verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)


def test_auth_refuses_missing_timestamp_subject_actor_and_protection(trust) -> None:
    verifier, path, result, _cert, files = trust
    original = copy.deepcopy(result)
    for key, bad in (("verifiedTimestamps", []), ("statement", {})):
        result.clear()
        result.update(copy.deepcopy(original))
        result[key] = bad
        with pytest.raises(ContractError):
            verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)
    result.clear()
    result.update(original)
    files[verifier.policy.environment_protection_proof] = b"{}"
    with pytest.raises(ContractError):
        verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)


def recovery_owner(root, host="cp-prod"):
    source, target = request()["source"], request()["target"]
    return cp.PlatformCpRecoveryBundle.for_transition(
        root,
        source_descriptor=descriptor(source["image_digest"], source["revision"]),
        target_descriptor=descriptor(target["image_digest"], target["revision"]),
        source_image="registry.invalid/cp@" + source["image_digest"],
        source_revision=source["revision"],
        target_image="registry.invalid/cp@" + target["image_digest"],
        target_source_revision=target["revision"],
        expected_source_heads=tuple(source["heads"]),
        target=host,
        incumbent_roles=(("app", source["image_digest"]),),
        backup_dir=root / "backups",
    )


class Host:
    def __init__(self, fail: str | None = None, compensation_fails: bool = False):
        self.events: list[str] = []
        self.fail = fail
        self.nonce = ""
        self.compensation_fails = compensation_fails
        self.acl_may_be_restored = False
        self.migration = None
        self.pre_routing_digest = None

    def lock(self):
        from contextlib import nullcontext

        return nullcontext()

    def inspect(self, _request):
        self.events.append("inspect")
        return canonical_json(
            {"source": request()["source"], "target": request()["target"]}
        )

    def proof(self, kind):
        self.events.append(kind)
        if self.fail == kind:
            raise RuntimeError(kind)

        def retain(raw):
            checksum = cp.raw_digest(raw)
            try:
                self.store.put(raw)
            except FileExistsError:
                pass
            return checksum

        source, target = request()["source"], request()["target"]
        retain(descriptor(source["image_digest"], source["revision"]))
        genesis = {
            "side": source,
            "descriptor_declarations": cp.source_descriptor_declarations(
                descriptor(source["image_digest"], source["revision"])
            ),
            "database_owner": "app_admin",
            "roles": sorted(cp.REQUIRED_ROLES),
            "catalogue_digest": retain(
                canonical_json(
                    {
                        **{name: [] for name in cp_catalogue.CATALOGUE_QUERIES},
                        "bootstrap": [["postgres", 10, True]],
                    }
                )
            ),
        }
        # Explicitly synthetic parser boundary, like this fixture's recovery bytes.
        catalogue_proof = retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_catalogue_restore_comparison/1",
                    "request_digest": cp.request_digest(request()),
                    "host_nonce": self.nonce,
                    "source_cluster_system_identifier": request()[
                        "cluster_system_identifier"
                    ],
                    "source_database": request()["database"],
                    "source_catalogue_digest": genesis["catalogue_digest"],
                    "restored_catalogue_digest": genesis["catalogue_digest"],
                    "method": "postgres16-temp-view-parse/1",
                    "parser": {
                        "server_version_num": 160004,
                        "cluster_system_identifier": str(
                            int(request()["cluster_system_identifier"]) + 1
                        ),
                        "database": request()["database"],
                        "search_path": "pg_catalog",
                        "standard_conforming_strings": "on",
                    },
                    "checks": [],
                    "restored_catalogue_after_digest": genesis["catalogue_digest"],
                }
            )
        )
        manifest = canonical_json(
            {
                "schema": "PlatformCpRecoveryBundle.v2",
                "target": "cp-prod",
                "postgres_major": 16,
                "source_image": "registry.invalid/cp@" + source["image_digest"],
                "incumbent_roles": [
                    {"role": "app", "image_digest": source["image_digest"]}
                ],
                "first_deployment": False,
                "product": request()["product"],
                "environment": "production",
                "database_name": "platform",
                "cluster_system_identifier": "12345",
                "source_revision": source["revision"],
                "source_descriptor_raw_sha256": source["raw_descriptor_digest"],
                "target_descriptor_raw_sha256": target["raw_descriptor_digest"],
                "taken_for_image_digest": target["image_digest"],
                "taken_for_source_revision": target["revision"],
                "migration_heads": source["heads"],
                "files": {
                    "database.dump": cp.raw_digest(b"dump"),
                    "globals.sql": cp.raw_digest(GLOBALS),
                },
                "file_sizes": {"database.dump": 4, "globals.sql": len(GLOBALS)},
                "restore_order": ["globals.sql", "database.dump"],
            }
        )
        root = self.store.root / "backups" / "fixture"
        root.mkdir(parents=True, exist_ok=True)
        (root / "database.dump").write_bytes(b"dump")
        (root / "globals.sql").write_bytes(GLOBALS)
        (root / "manifest.json").write_bytes(manifest)
        (root / "SHA256SUMS").write_text(
            "".join(
                f"{cp.raw_digest(raw)[7:]}  {name}\n"
                for name, raw in (
                    ("database.dump", b"dump"),
                    ("globals.sql", GLOBALS),
                )
            )
        )
        owner = recovery_owner(self.store.root)
        backup = cp.PlatformBackupResult(
            "primary",
            str(root),
            sum(p.stat().st_size for p in root.iterdir()),
            cp.raw_digest(manifest)[7:],
            "sha256",
            len(manifest),
            cp.raw_digest(b"dump"),
            4,
            cp.raw_digest(GLOBALS),
            len(GLOBALS),
        )
        self.store.recovery[cp.request_digest(request())] = owner, backup
        replay_raw = GLOBALS.replace(cp.GLOBALS_BOOTSTRAP_STATEMENT.encode(), b"", 1)
        replay_proof = retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_globals_replay/1",
                    "request_digest": cp.request_digest(request()),
                    "host_nonce": self.nonce,
                    "original_digest": cp.raw_digest(GLOBALS),
                    "original_size": len(GLOBALS),
                    "replay_digest": cp.raw_digest(replay_raw),
                    "replay_size": len(replay_raw),
                    "omitted_statement": cp.GLOBALS_BOOTSTRAP_STATEMENT,
                    "source_bootstrap": {
                        "role": "postgres",
                        "oid": 10,
                        "superuser": True,
                    },
                    "fresh_bootstrap": {
                        "role": "postgres",
                        "oid": 10,
                        "superuser": True,
                    },
                }
            )
        )
        snapshot_digest = retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence_snapshot/1",
                    "request_digest": cp.request_digest(request()),
                    "host_nonce": self.nonce,
                    "measurement": {
                        "track_counts": True,
                        "stats_reset": None,
                        "server_start": "2026-10-24T00:00:00Z",
                        "relations": [["public", "alembic_version", 1, 1, 0, 0, 0]],
                        "sequences": [],
                        "catalogue_digest": genesis["catalogue_digest"],
                    },
                }
            )
        )
        quiescence_digest = retain(
            canonical_json(
                {
                    "schema": "dotmac.cp_candidate_quiescence/1",
                    "request_digest": cp.request_digest(request()),
                    "host_nonce": self.nonce,
                    "before_digest": snapshot_digest,
                    "after_digest": snapshot_digest,
                }
            )
        )
        results = {
            "maintenance": {
                "external_status": 503,
                "active_http": 0,
                "active_websockets": 0,
            },
            "strict-fence-reconnect": {
                "database": "platform",
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
            "writers-stopped": {"running_writers": [], "restart_enabled": []},
            "source-genesis": genesis,
            "recovery-restored": {
                "source": genesis,
                "restored_source": genesis,
                "restore_evidence_digest": retain(canonical_json(genesis)),
                "manifest_digest": retain(manifest),
                "manifest_size": len(manifest),
                "dump_digest": retain(b"dump"),
                "globals_digest": retain(GLOBALS),
                "dump_size": 4,
                "globals_size": len(GLOBALS),
                "restored_dump_digest": cp.raw_digest(b"dump"),
                "restored_globals_digest": cp.raw_digest(replay_raw),
                "globals_replay_digest": replay_proof,
                "catalogue_comparison_digest": catalogue_proof,
            },
            "fence-source-rechecked": {
                "source": source,
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
            "migrate": self.migration,
            "migrated-target-heads": target,
            "candidate-ready": {"side": target, "status": 200, "writer_sessions": 0},
            "candidate-removed-fenced": {
                "candidate_sessions": 0,
                "candidate_roles": [],
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
                "quiescence_digest": quiescence_digest,
            },
            "acl-restored": {"database": "platform", "acl_difference": []},
            "full-ready": {"side": target, "status": 200},
            "pre-routing-verified": {"receipt_digest": self.pre_routing_digest},
            "routing-restored": {"side": target, "external_status": 200},
            "failure": {
                "external_status": 503,
                "writer_sessions": 0,
                "reconnect_denial": "database_acl",
            },
        }
        return canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": cp.request_digest(request()),
                "host_nonce": self.nonce,
                "kind": kind,
                "result": results[kind],
            }
        )

    def __getattr__(self, method):
        kinds = {
            "maintenance": "maintenance",
            "fence_and_negative_reconnect": "strict-fence-reconnect",
            "stop_and_drain_writers": "writers-stopped",
            "source_genesis": "source-genesis",
            "capture_and_restore": "recovery-restored",
            "recheck_fence_source": "fence-source-rechecked",
            "target_heads": "migrated-target-heads",
            "candidate_ready": "candidate-ready",
            "close_candidate_and_refence": "candidate-removed-fenced",
            "restore_acl": "acl-restored",
            "full_ready": "full-ready",
            "restore_routing": "routing-restored",
        }
        if method not in kinds:
            raise AttributeError(method)

        def action(_request, nonce):
            self.nonce = nonce
            return self.proof(kinds[method])

        return action

    def migrate(self, _request, nonce, **kwargs):
        assert all(
            kwargs[key]
            for key in (
                "authorization",
                "reservation_digest",
                "genesis_digest",
                "restore_digest",
                "fence_digest",
            )
        )
        self.nonce = nonce
        self.migration = {
            "heads": request()["target"]["heads"],
            "restore_digest": kwargs["restore_digest"],
            "fence_digest": kwargs["fence_digest"],
        }
        return self.proof("migrate")

    def verify_pre_routing(self, raw):
        value = cp.read_json(raw)
        assert value["phase"] == "pre-routing"
        assert "routing-restored" not in value["evidence"]
        self.pre_routing_digest = cp.raw_digest(raw)
        return self.proof("pre-routing-verified")

    def fail_closed(self, _request, nonce, *, acl_may_be_restored):
        self.nonce = nonce
        self.acl_may_be_restored = acl_may_be_restored
        if self.compensation_fails:
            raise OSError("refence failed")
        return self.proof("failure")


def execute(store, trust, monkeypatch, host, clock=lambda: NOW):
    verifier, path, _result, _cert, _files = trust
    host.store = store
    return cp.execute_transition(
        canonical_json(request()),
        request_path=path,
        bundle_path=None,
        verifier=verifier,
        host=host,
        store=store,
        recovery=store.recovery,
        clock=clock,
    )


def test_execution_order_and_receipt_gate(store, trust, monkeypatch) -> None:
    host = Host()
    checksum = execute(store, trust, monkeypatch, host)
    final = cp.read_json(store.read(checksum, kind="receipt"))
    assert final["phase"] == "complete"
    forged = copy.deepcopy(final)
    forged["phase"] = "pre-routing"
    with pytest.raises(ContractError, match="receipt_phase_mismatch"):
        cp.verify_receipt(
            canonical_json(forged),
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce=final["host_nonce"],
            routing_gate=True,
        )

    assert host.events.index("strict-fence-reconnect") < host.events.index(
        "writers-stopped"
    )
    assert host.events.index("recovery-restored") < host.events.index("migrate")
    assert host.events.index("candidate-removed-fenced") < host.events.index(
        "acl-restored"
    )
    assert (
        host.events.index("full-ready")
        < host.events.index("pre-routing-verified")
        < host.events.index("routing-restored")
    )
    with pytest.raises(FileExistsError):
        execute(store, trust, monkeypatch, Host())


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "proof-nonce",
        "changed",
        "disabled",
        "catalogue",
        "boolean",
        "empty",
        "snapshot-nonce",
    ],
)
def test_candidate_quiescence_is_bound_and_required_before_acl(
    store, trust, monkeypatch, fault
):
    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    stage = cp.read_json(store.read(receipt["evidence"]["candidate-removed-fenced"]))
    proof = cp.read_json(store.read(stage["result"]["quiescence_digest"]))
    snapshot = cp.read_json(store.read(proof["before_digest"]))
    if fault == "missing":
        stage["result"].pop("quiescence_digest")
    else:
        if fault == "proof-nonce":
            proof["host_nonce"] = "other"
        else:
            if fault == "changed":
                snapshot["measurement"]["relations"][0][5] = 1
            elif fault == "disabled":
                snapshot["measurement"]["track_counts"] = False
            elif fault == "catalogue":
                snapshot["measurement"]["catalogue_digest"] = "sha256:" + "9" * 64
            elif fault == "boolean":
                snapshot["measurement"]["relations"][0][4] = False
            elif fault == "empty":
                snapshot["measurement"]["relations"] = []
            else:
                snapshot["host_nonce"] = "other"
            proof["after_digest"] = store.put(canonical_json(snapshot))
            if fault != "changed":
                proof["before_digest"] = proof["after_digest"]
        stage["result"]["quiescence_digest"] = store.put(canonical_json(proof))
    with pytest.raises((ContractError, FileNotFoundError)):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind="candidate-removed-fenced",
            store=store,
            evidence=receipt["evidence"],
            recovery=store.recovery,
        )


@pytest.mark.parametrize(
    "predecessor", ["absent", "incomplete", "wrong-source", "wrong-host"]
)
def test_bad_predecessor_refuses_before_any_host_mutation(
    tmp_path, monkeypatch, request: pytest.FixtureRequest, predecessor
):
    import sys

    module = sys.modules[__name__]
    current = module.request()
    if predecessor == "absent":
        checksum = "sha256:" + "9" * 64
    else:
        previous = {
            "schema": "dotmac.cp_migration_transition_receipt/1",
            "request": copy.deepcopy(current),
            "request_digest": cp.request_digest(current),
            "host_nonce": "f" * 64,
            "phase": "complete",
            "genesis_digest": SHA,
            "previous_receipt_digest": None,
            "evidence": {},
        }
        previous["request"]["target"] = copy.deepcopy(current["source"])
        if predecessor == "incomplete":
            previous["phase"] = "pre-routing"
        elif predecessor == "wrong-source":
            previous["request"]["target"]["heads"] = ["different"]
        else:
            previous["request"]["host"] = "other-host"
        raw = canonical_json(previous)
        checksum = cp.raw_digest(raw)
    current["previous_receipt_digest"] = checksum
    current["plan_digest"] = cp.transition_plan_digest(current)
    monkeypatch.setattr(module, "request", lambda: current)
    trust = request.getfixturevalue("trust")
    store = request.getfixturevalue("store")
    if predecessor != "absent":
        store.put(raw, kind="receipt")
    host = Host()
    with pytest.raises((FileNotFoundError, ContractError)):
        execute(store, trust, monkeypatch, host)
    assert "maintenance" not in host.events and "migrate" not in host.events
    assert not list(store.root.glob("*.reservation.json"))


@pytest.mark.parametrize(
    "phase",
    [
        "maintenance",
        "strict-fence-reconnect",
        "writers-stopped",
        "source-genesis",
        "recovery-restored",
        "fence-source-rechecked",
        "migrate",
        "migrated-target-heads",
        "candidate-ready",
        "candidate-removed-fenced",
        "acl-restored",
        "full-ready",
        "pre-routing-verified",
    ],
)
def test_every_failure_retains_authorization_and_prevents_routing(
    store, trust, monkeypatch, phase
) -> None:
    host = Host(fail=phase)
    with pytest.raises(RuntimeError, match=phase):
        execute(store, trust, monkeypatch, host)
    assert "routing-restored" not in host.events
    assert "failure" in host.events
    assert host.acl_may_be_restored == (
        phase in {"acl-restored", "full-ready", "pre-routing-verified"}
    )
    with pytest.raises(FileExistsError):
        store.reserve(request())


def test_compensation_failure_preserves_original(store, trust, monkeypatch) -> None:
    with pytest.raises(RuntimeError, match="full-ready") as caught:
        execute(
            store, trust, monkeypatch, Host(fail="full-ready", compensation_fails=True)
        )
    assert "OSError" in caught.value.__notes__[0]


def test_duplicate_heads_even_with_self_consistent_plan_refused() -> None:
    value = request()
    value["source"]["heads"] = ["a", "a"]
    value["plan_digest"] = cp.transition_plan_digest(value)
    with pytest.raises(ContractError):
        cp.validate_request(value, identity=IDENTITY, now=NOW)


def test_request_cannot_select_genesis_or_extend_authorization_lifetime() -> None:
    for key, value in (
        ("first_genesis_digest", SHA),
        ("expires_at", "2030-01-01T00:00:00Z"),
    ):
        candidate = dict(request())
        candidate[key] = value
        with pytest.raises(ContractError):
            cp.validate_request(candidate, identity=IDENTITY, now=NOW)


def test_boolean_only_host_evidence_is_refused(store, trust, monkeypatch) -> None:
    host = Host()
    monkeypatch.setattr(
        host,
        "maintenance",
        lambda _request, nonce: canonical_json(
            {
                "schema": "dotmac.cp_transition_evidence/2",
                "request_digest": cp.request_digest(request()),
                "host_nonce": nonce,
                "kind": "maintenance",
                "result": {"safe": True, "ready": True},
            }
        ),
    )
    with pytest.raises(ContractError, match="stage_result_mismatch"):
        execute(store, trust, monkeypatch, host)
    assert "writers-stopped" not in host.events


def test_verifier_process_failure_cannot_be_laundered_by_valid_json(
    trust, monkeypatch
) -> None:
    import subprocess
    from types import SimpleNamespace

    verifier, path, _result, _cert, _files = trust
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1, stdout=b'[{"verificationResult":{}}]'
        ),
    )
    with pytest.raises(ContractError, match="attestation_verification_failed"):
        verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)


def test_successful_json_without_subject_actor_or_signed_time_is_refused(trust) -> None:
    verifier, path, result, _cert, _files = trust
    original = copy.deepcopy(result)
    mutations = (
        lambda value: value["statement"].update(subject=[]),
        lambda value: value["statement"]["predicate"].update(trusted_actor="attacker"),
        lambda value: value["verifiedTimestamps"][0].update(
            timestamp="2020-01-01T00:00:00Z"
        ),
    )
    for mutate in mutations:
        result.clear()
        result.update(copy.deepcopy(original))
        mutate(result)
        with pytest.raises(ContractError):
            verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)


def test_receipt_requires_independently_retained_evidence_bytes(
    store, trust, monkeypatch
) -> None:
    checksum = execute(store, trust, monkeypatch, Host())
    raw = store.read(checksum, kind="receipt")
    value = cp.read_json(raw)
    evidence = value["evidence"]["full-ready"]
    (store.root / store._name(evidence, "evidence")).write_bytes(b"fabricated")
    with pytest.raises(ContractError, match="artifact_digest_mismatch"):
        cp.verify_receipt(
            raw,
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce=value["host_nonce"],
            routing_gate=True,
        )


@pytest.mark.parametrize(
    ("kind", "field", "bad"),
    [
        ("migrated-target-heads", "heads", ["wrong"]),
        ("candidate-ready", "status", 500),
        ("full-ready", "status", 500),
        ("maintenance", "external_status", 200),
        ("maintenance", "active_websockets", 1),
        ("strict-fence-reconnect", "reconnect_sqlstate", "00000"),
        ("candidate-removed-fenced", "candidate_sessions", 1),
        ("acl-restored", "acl_difference", [["writer", "CONNECT"]]),
        ("authorization", "verification_digest", SHA),
        ("recovery-restored", "restored_dump_digest", SHA),
        ("recovery-restored", "dump_size", 1),
        ("recovery-restored", "manifest_digest", SHA),
        ("recovery-restored", "restore_evidence_digest", SHA),
        ("recovery-restored", "restored_source", {}),
        ("source-genesis", "database_owner", "other"),
        ("source-genesis", "roles", ["app_admin"]),
    ],
)
def test_semantic_receipt_rejects_former_false_positives(
    store, trust, monkeypatch, kind, field, bad
):
    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    receipt["phase"] = "pre-routing"
    for routing in cp.ROUTING_EVIDENCE:
        del receipt["evidence"][routing]
    stage = cp.read_json(store.read(receipt["evidence"][kind]))
    if field in {"manifest_digest", "restore_evidence_digest"}:
        bad = store.put(canonical_json({"wrong": field}))
    stage["result"][field] = bad
    with pytest.raises(ContractError):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind=kind,
            store=store,
            recovery=store.recovery,
            evidence=receipt["evidence"],
        )
    receipt["evidence"][kind] = store.put(canonical_json(stage))
    with pytest.raises(ContractError):
        cp.verify_receipt(
            canonical_json(receipt),
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce=receipt["host_nonce"],
            routing_gate=True,
        )


def test_receipt_cannot_skip_reservation_or_change_nonce(store, trust, monkeypatch):
    checksum = execute(store, trust, monkeypatch, Host())
    raw = store.read(checksum, kind="receipt")
    receipt = cp.read_json(raw)
    with pytest.raises(ContractError, match="reservation_mismatch"):
        cp.verify_receipt(
            raw,
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce="f" * 64,
        )
    (store.root / store._name(cp.request_digest(request()), "reservation")).unlink()
    with pytest.raises(FileNotFoundError):
        cp.verify_receipt(
            raw,
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce=receipt["host_nonce"],
        )


def test_fabricated_verifier_json_cannot_reserve(store):
    forged = cp.VerifiedAuthorization(
        cp.request_digest(request()), 123, 2, "michael", b"fabricated"
    )
    with pytest.raises(ContractError, match="unverified_authorization"):
        cp.ArtifactStore.reserve(store, request(), forged)


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "authorization_run_id",
        "authorization_run_attempt",
        "trusted_actor",
        "verification_bytes",
    ],
)
def test_verified_capability_cannot_be_rebound(store, trust, field):
    from dataclasses import replace

    verifier, path, *_ = trust
    authorized = verifier.verify(
        request(), request_path=path, bundle_path=None, now=NOW
    )
    wrong = {
        "request_digest": SHA,
        "authorization_run_id": 456,
        "authorization_run_attempt": 3,
        "trusted_actor": "attacker",
        "verification_bytes": b"fabricated",
    }
    with pytest.raises(ContractError, match="unverified_authorization"):
        cp.ArtifactStore.reserve(
            store, request(), replace(authorized, **{field: wrong[field]})
        )


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("target", "wrong-host"),
        ("database_name", "wrong_database"),
        ("cluster_system_identifier", "999999"),
        ("source_image", "registry.invalid/cp@sha256:" + "f" * 64),
        ("incumbent_roles", [{"role": "app", "image_digest": "sha256:" + "f" * 64}]),
    ],
)
def test_receipt_uses_actual_recovery_owner_for_rehashed_manifest(
    store, trust, monkeypatch, field, bad
):
    from dataclasses import replace

    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    stage = cp.read_json(store.read(receipt["evidence"]["recovery-restored"]))
    owner, backup = store.recovery[cp.request_digest(request())]
    root = Path(backup.path)
    manifest = cp.read_json((root / "manifest.json").read_bytes())
    manifest[field] = bad
    raw = canonical_json(manifest)
    (root / "manifest.json").write_bytes(raw)
    backup = replace(
        backup,
        checksum=cp.raw_digest(raw)[7:],
        manifest_size_bytes=len(raw),
        size_bytes=sum(p.stat().st_size for p in root.iterdir()),
    )
    store.recovery[cp.request_digest(request())] = owner, backup
    stage["result"].update(manifest_digest=store.put(raw), manifest_size=len(raw))
    database_join = field in {"database_name", "cluster_system_identifier"}
    if database_join:
        assert owner.verify(backup)
    refusal = (
        "recovery_database_mismatch" if database_join else "recovery_owner_refused"
    )
    with pytest.raises(ContractError, match=refusal):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind="recovery-restored",
            store=store,
            evidence=receipt["evidence"],
            recovery=store.recovery,
        )


@pytest.mark.parametrize("delay", ["lock", "verification", "inspection"])
def test_expiration_is_rechecked_under_lock_and_at_consumption(
    store, trust, monkeypatch, delay
):
    from contextlib import contextmanager

    current = [NOW]
    expired = datetime(2026, 10, 25, tzinfo=UTC)
    host = Host()
    verifier = trust[0]
    if delay == "lock":

        @contextmanager
        def lock():
            current[0] = expired
            yield

        monkeypatch.setattr(host, "lock", lock)
    elif delay == "verification":
        verify = verifier.verify

        def verify_after_delay(*args, **kwargs):
            result = verify(*args, **kwargs)
            current[0] = expired
            return result

        monkeypatch.setattr(verifier, "verify", verify_after_delay)
    else:
        inspect = host.inspect

        def inspect_after_delay(value):
            result = inspect(value)
            current[0] = expired
            return result

        monkeypatch.setattr(host, "inspect", inspect_after_delay)
    with pytest.raises(ContractError, match="expired"):
        execute(store, trust, monkeypatch, host, clock=lambda: current[0])
    assert not list(store.root.glob("*.reservation.json"))
    assert "maintenance" not in host.events


def test_archival_receipt_does_not_repeat_authorization_expiry_check(
    store, trust, monkeypatch
):
    checksum = execute(store, trust, monkeypatch, Host())
    raw = store.read(checksum, kind="receipt")
    receipt = cp.read_json(raw)

    def admission_only(*args, **kwargs):
        raise AssertionError(
            "fresh authorization admission applied to archival receipt"
        )

    monkeypatch.setattr(cp, "validate_request", admission_only)
    assert (
        cp.verify_receipt(
            raw,
            store=store,
            recovery=store.recovery,
            request=request(),
            host_nonce=receipt["host_nonce"],
        )["phase"]
        == "complete"
    )


def test_valid_recovery_owner_and_backup_cannot_be_swapped_into_another_request(
    store, trust, monkeypatch
):
    from dataclasses import replace

    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    stage = cp.read_json(store.read(receipt["evidence"]["recovery-restored"]))
    _, backup = store.recovery[cp.request_digest(request())]
    root = Path(backup.path)
    manifest = cp.read_json((root / "manifest.json").read_bytes())
    manifest["target"] = "another-host"
    raw = canonical_json(manifest)
    (root / "manifest.json").write_bytes(raw)
    backup = replace(
        backup,
        checksum=cp.raw_digest(raw)[7:],
        manifest_size_bytes=len(raw),
        size_bytes=sum(p.stat().st_size for p in root.iterdir()),
    )
    owner = recovery_owner(store.root, "another-host")
    assert owner.verify(backup)
    store.recovery[cp.request_digest(request())] = owner, backup
    stage["result"].update(manifest_digest=store.put(raw), manifest_size=len(raw))
    with pytest.raises(ContractError, match="recovery_context_mismatch"):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind="recovery-restored",
            store=store,
            evidence=receipt["evidence"],
            recovery=store.recovery,
        )


@pytest.mark.parametrize("mode", [0o700, 0o600, 0o722])
def test_protected_executable_digest_checks_mode_and_streams(
    tmp_path, monkeypatch, mode
):
    binary = tmp_path / "tool"
    raw = b"public executable fixture" * (1024 * 1024)
    binary.write_bytes(raw)
    binary.chmod(mode)
    protected = cp._protected

    def owned(info, *, directory):
        values = list(info)
        values[4] = 0
        protected(os.stat_result(values), directory=directory)

    monkeypatch.setattr(cp, "_protected", owned)
    monkeypatch.setattr(
        cp, "_open_directory", lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    )
    if mode == 0o700:
        assert cp._protected_executable_digest(binary) == cp.raw_digest(raw)
        os.link(binary, tmp_path / "alias")
        with pytest.raises(ContractError, match="unsafe_artifact_path"):
            cp._protected_executable_digest(binary)
    else:
        with pytest.raises(ContractError):
            cp._protected_executable_digest(binary)


@pytest.mark.parametrize(
    "fault", ["missing", "nonce", "original", "replay", "size", "bootstrap", "boolean"]
)
def test_globals_replay_recipe_is_bound_and_required(store, trust, monkeypatch, fault):
    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    stage = cp.read_json(store.read(receipt["evidence"]["recovery-restored"]))
    proof = cp.read_json(store.read(stage["result"]["globals_replay_digest"]))
    if fault == "missing":
        stage["result"].pop("globals_replay_digest")
    else:
        if fault == "nonce":
            proof["host_nonce"] = "other"
        elif fault == "original":
            proof["original_digest"] = SHA
        elif fault == "replay":
            proof["replay_digest"] = SHA
            stage["result"]["restored_globals_digest"] = SHA
        elif fault == "size":
            proof["replay_size"] += 1
        elif fault == "bootstrap":
            proof["fresh_bootstrap"]["oid"] = 11
        else:
            proof["source_bootstrap"]["superuser"] = 1
        stage["result"]["globals_replay_digest"] = store.put(canonical_json(proof))
    with pytest.raises((ContractError, FileNotFoundError)):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind="recovery-restored",
            store=store,
            evidence=receipt["evidence"],
            recovery=store.recovery,
        )


@pytest.mark.parametrize("case", ["one", "none", "two", "long-line"])
def test_globals_recipe_streams_and_matches_complete_lines_only(store, case):
    statement = cp.GLOBALS_BOOTSTRAP_STATEMENT.encode()
    path = store.root / "original-globals.sql"
    expected = b"prefix\nsuffix\n"
    raw = b"prefix\n" + statement + b"suffix\n"
    if case == "none":
        raw = expected
    elif case == "two":
        raw += statement
    elif case == "long-line":
        expected = b"x" * (17 * 1024 * 1024) + statement + b"suffix\n"
        raw = b"x" * (17 * 1024 * 1024) + statement + statement + b"suffix\n"
    path.write_bytes(raw)
    if case in ("none", "two"):
        with pytest.raises(ContractError, match="globals_bootstrap_statement_count"):
            cp.globals_replay_fingerprint(path)
    else:
        assert cp.globals_replay_fingerprint(path) == (
            cp.raw_digest(expected),
            len(expected),
        )


@pytest.mark.parametrize(
    "fault", ["missing", "nonce", "catalogue", "same-cluster", "database", "extra"]
)
def test_catalogue_comparison_is_bound_and_recovery_requires_fresh_cluster(
    store, trust, monkeypatch, fault
):
    checksum = execute(store, trust, monkeypatch, Host())
    receipt = cp.read_json(store.read(checksum, kind="receipt"))
    stage = cp.read_json(store.read(receipt["evidence"]["recovery-restored"]))
    proof = cp.read_json(store.read(stage["result"]["catalogue_comparison_digest"]))
    if fault == "missing":
        stage["result"].pop("catalogue_comparison_digest")
    else:
        if fault == "nonce":
            proof["host_nonce"] = "f" * 64
        elif fault == "catalogue":
            proof["source_catalogue_digest"] = SHA
        elif fault == "same-cluster":
            # Generic comparison permits a separate DB in one disposable cluster.
            # Recovery independently requires a different cluster as well.
            proof["parser"]["cluster_system_identifier"] = request()[
                "cluster_system_identifier"
            ]
            proof["parser"]["database"] = "separate_scratch_database"
        elif fault == "database":
            proof["source_database"] = "another_database"
        elif fault == "extra":
            proof["verified"] = True
        stage["result"]["catalogue_comparison_digest"] = store.put(
            canonical_json(proof)
        )
    with pytest.raises(ContractError):
        cp._validate_evidence(
            stage,
            request=request(),
            nonce=receipt["host_nonce"],
            kind="recovery-restored",
            store=store,
            evidence=receipt["evidence"],
            recovery=store.recovery,
        )


@pytest.mark.parametrize(
    "case",
    [
        "old-v1",
        "missing-model",
        "unknown-model",
        "missing-prevent",
        "prevent-true",
        "missing-bypass",
        "bypass-true",
        "bypass-integer",
        "wrong-reviewer",
        "extra-reviewer",
        "duplicate-reviewer",
        "boolean-reviewer",
        "string-reviewer",
        "empty-reviewers",
        "missing-reviewers",
        "unknown-field",
        "unprotected-main",
    ],
)
def test_single_user_manual_v2_protection_is_closed_and_exact(trust, case):
    from dataclasses import replace

    verifier, path, _result, _cert, files = trust
    protection = verifier.policy.environment_protection_proof
    proof = cp.read_json(files[protection])
    if case == "old-v1":
        proof["schema"] = "dotmac.cp_transition_environment_protection/1"
        del proof["approval_model"]
        del proof["can_admins_bypass"]
        proof["prevent_self_review"] = True
    elif case == "missing-model":
        del proof["approval_model"]
    elif case == "unknown-model":
        proof["approval_model"] = "automatic"
    elif case == "missing-prevent":
        del proof["prevent_self_review"]
    elif case == "prevent-true":
        proof["prevent_self_review"] = True
    elif case == "missing-bypass":
        del proof["can_admins_bypass"]
    elif case == "bypass-true":
        proof["can_admins_bypass"] = True
    elif case == "bypass-integer":
        proof["can_admins_bypass"] = 0
    elif case == "wrong-reviewer":
        proof["required_reviewer_ids"] = [300]
    elif case == "extra-reviewer":
        proof["required_reviewer_ids"] = [200, 300]
    elif case == "duplicate-reviewer":
        proof["required_reviewer_ids"] = [200, 200]
    elif case == "boolean-reviewer":
        proof["required_reviewer_ids"] = [True]
    elif case == "string-reviewer":
        proof["required_reviewer_ids"] = ["200"]
    elif case == "empty-reviewers":
        proof["required_reviewer_ids"] = []
    elif case == "missing-reviewers":
        del proof["required_reviewer_ids"]
    elif case == "unknown-field":
        proof["auto_approve"] = False
    else:
        proof["protected_main"] = False
    files[protection] = canonical_json(proof)
    verifier.policy = replace(
        verifier.policy, environment_protection_digest=cp.raw_digest(files[protection])
    )
    with pytest.raises(ContractError):
        verifier.verify(request(), request_path=path, bundle_path=None, now=NOW)


def test_single_user_request_actor_must_be_exact_policy_owner(trust, monkeypatch):
    import subprocess

    verifier, path, _result, _cert, files = trust
    value = request()
    value["trusted_actor"] = "another-valid-actor"
    files[path] = canonical_json(value)

    def unexpected_verifier(*_args, **_kwargs):
        raise AssertionError("foreign actor must refuse before attestation subprocess")

    monkeypatch.setattr(subprocess, "run", unexpected_verifier)
    with pytest.raises(ContractError, match="environment_protection_mismatch"):
        verifier.verify(value, request_path=path, bundle_path=None, now=NOW)
