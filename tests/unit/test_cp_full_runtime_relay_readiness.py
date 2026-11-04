"""Full runtime uses the existing readiness owner, never relay Docker Health.

Process, HTTP and DB observations are test boundaries. Readiness/relay verdicts,
boolean configuration parsing, immutable inputs and loopback/ledger checks stay
real. These tests run only in the repository's hosted CI lane.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from vendor_cp.config import VendorSettings, parse_boolean_setting
from vendor_cp.config_errors import ProductionConfigurationError
from vendor_cp.deploy_agent.contracts import ContractError, canonical_json
from vendor_cp.deployment import cp_transition_host as module
from vendor_cp.deployment.cp_transition import ArtifactStore, TransitionRequest
from vendor_cp.readiness.service import check_readiness
from vendor_cp.relay import health as health_owner


class ReadinessSession:
    """DB observation boundary: an empty queue and the supplied heartbeat."""

    def __init__(self, heartbeat_at, *, unreadable=False):
        self.heartbeat_at = heartbeat_at
        self.unreadable = unreadable

    def execute(self, statement):
        if "relay_heartbeats" in str(statement) and self.unreadable:
            raise RuntimeError("unreadable heartbeat")
        return SimpleNamespace(
            one=lambda: (self.heartbeat_at, None), scalar_one=lambda: 0
        )

    def scalar(self, statement):
        return None


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module,
        "_protected_executable_digest",
        lambda path: (
            "sha256:" + ("5" * 64 if path == Path("/usr/bin/docker") else "6" * 64)
        ),
    )
    config = module.CpTransitionHostConfig(
        repository_root=tmp_path,
        deploy_directory=tmp_path,
        target_descriptor=tmp_path / "target.toml",
        source_image=f"{module.IMAGE_REPOSITORY}@sha256:{'1' * 64}",
        target_image=f"{module.IMAGE_REPOSITORY}@sha256:{'2' * 64}",
        postgres_image=f"postgres@sha256:{'3' * 64}",
        maintenance_helper=tmp_path / "maintenance",
        maintenance_helper_digest="sha256:" + "4" * 64,
        external_ready_url=module.EXTERNAL_READY_URL,
        candidate_port=18100,
        docker_binary_digest="sha256:" + "5" * 64,
        git_binary=Path("/usr/bin/git"),
        git_binary_digest="sha256:" + "6" * 64,
    )
    host = module.ExistingCpTransitionHost(
        config, store=ArtifactStore(tmp_path), recovery={}
    )
    host._acl_restored = True
    request = cast(TransitionRequest, {"database": "cp", "target": {"heads": []}})
    host._request = request
    host._nonce = "a" * 64
    monkeypatch.setattr(host, "_run", lambda *args, **kwargs: "")
    image_id = "sha256:" + "c" * 64
    environment = {
        "VENDOR_RELAY_EXPECTED": "true",
        "VENDOR_DEPLOYMENT_PROFILE": "production-keyless-v1",
        "VENDOR_DEPLOY_AGENT_ENABLED": "true",
    }
    mount = {
        "type": "volume",
        "source": "manifests",
        "target": "/run/dotmac/product-manifests",
        "read_only": True,
    }
    specification = {
        "services": {
            name: {
                "image": config.target_image,
                "environment": dict(environment) if name == "app" else {},
                "volumes": [deepcopy(mount)],
            }
            for name in ("app", "relay")
        }
    }
    specification["services"]["app"]["ports"] = [
        {
            "host_ip": "127.0.0.1",
            "target": 8000,
            "published": str(config.app_port),
            "protocol": "tcp",
        }
    ]
    writers = []
    for service in ("app", "relay"):
        writers.append(
            {
                "Image": image_id,
                "Config": {
                    "Image": config.target_image,
                    "Labels": {"com.docker.compose.service": service},
                    "Env": [
                        f"{key}={value}"
                        for key, value in specification["services"][service][
                            "environment"
                        ].items()
                    ],
                },
                "State": {"Running": True, "Restarting": False},
                "Mounts": [
                    {
                        "Type": "volume",
                        "Name": "manifests",
                        "Destination": mount["target"],
                        "RW": False,
                    }
                ],
            }
        )
    app, relay = writers
    app["Config"]["Healthcheck"] = {"Test": ["CMD", "ready-probe"]}
    app["State"]["Health"] = {"Status": "healthy"}
    bindings = {
        "8000/tcp": [
            {
                "HostIp": "127.0.0.1",
                "HostPort": str(config.app_port),
            }
        ]
    }
    app["HostConfig"] = {"PortBindings": deepcopy(bindings)}
    app["NetworkSettings"] = {"Ports": deepcopy(bindings)}
    monkeypatch.setattr(host, "_runtime_specification", lambda: specification)
    monkeypatch.setattr(host, "_docker", lambda *args: json.dumps([{"Id": image_id}]))
    monkeypatch.setattr(host, "_writers", lambda: writers)

    @contextmanager
    def connect(database):
        yield object()

    monkeypatch.setattr(host, "_connect", connect)
    monkeypatch.setattr(host, "_identity", lambda *args: None)
    monkeypatch.setattr(module, "read_current_migration_heads", lambda connection: [])
    state = SimpleNamespace(
        host=host,
        request=request,
        writers=writers,
        app=app,
        relay=relay,
        specification=specification,
        now=datetime.now(UTC),
        settings=VendorSettings(provider_mode="fake"),
        calls=[],
        ledger_bad=False,
        heartbeat_at=None,
        heartbeat_unreadable=False,
    )
    state.heartbeat_at = state.now

    class Response:
        def __init__(self, url, status, body):
            self.url, self.status, self.body = url, status, body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return canonical_json(self.body)

    def open_probe(request, timeout):
        url = request.full_url
        state.calls.append(url)
        if url == host._ledger_probe_url():
            detail = "Not Found" if state.ledger_bad else "desired_state_absent"
            return Response(url, 404, {"detail": detail})
        assert url == f"http://127.0.0.1:{config.app_port}/health/ready"
        env = dict(value.split("=", 1) for value in state.app["Config"]["Env"])
        settings = state.settings
        report = check_readiness(
            ReadinessSession(state.heartbeat_at, unreadable=state.heartbeat_unreadable),
            now=state.now,
            overdue_after=timedelta(seconds=settings.relay_overdue_seconds),
            stale_lease_after=timedelta(seconds=settings.relay_stale_lease_seconds),
            heartbeat_stale_after=timedelta(
                seconds=settings.relay_heartbeat_stale_seconds
            ),
            settled_within=timedelta(seconds=settings.relay_settled_within_seconds),
            relay_expected=parse_boolean_setting(
                env.get("VENDOR_RELAY_EXPECTED", ""),
                name="VENDOR_RELAY_EXPECTED",
                default=True,
            ),
        )
        return Response(
            url,
            200 if report.ready else 503,
            {"ready": report.ready, "detail": report.detail.value},
        )

    monkeypatch.setattr(
        module.urllib.request,
        "build_opener",
        lambda *args: SimpleNamespace(open=open_probe),
    )
    return state


def test_healthy_relay_without_docker_health_uses_positive_readiness_owner(runtime):
    assert "Health" not in runtime.relay["State"]
    assert "Healthcheck" not in runtime.relay["Config"]
    runtime.host._full_runtime(runtime.request)
    assert runtime.calls == [
        f"http://127.0.0.1:{runtime.host.config.app_port}/health/ready",
        runtime.host._ledger_probe_url(),
    ]


@pytest.mark.parametrize("heartbeat", ["missing", "stale", "unreadable"])
def test_running_relay_still_requires_readable_fresh_heartbeat(runtime, heartbeat):
    if heartbeat == "missing":
        runtime.heartbeat_at = None
    elif heartbeat == "stale":
        runtime.heartbeat_at = runtime.now - timedelta(
            seconds=runtime.settings.relay_heartbeat_stale_seconds + 1
        )
    else:
        runtime.heartbeat_unreadable = True
    with pytest.raises(ContractError, match="readiness_failed"):
        runtime.host._full_runtime(runtime.request)
    assert len(runtime.calls) == 1


@pytest.mark.parametrize("failure", ["queue_dead", "withdrawal_delivery"])
def test_relay_queue_and_delivery_owner_refusals_block_runtime(
    runtime, monkeypatch, failure
):
    def count(db, *, status, event_type=None, **kwargs):
        if failure == "queue_dead":
            return int(status is health_owner.OutboxStatus.DEAD and event_type is None)
        return int(
            event_type == health_owner.APPROVAL_WITHDRAWN_EVENT_TYPE
            and kwargs.get("attempts_greater_than") == 0
            and status is health_owner.OutboxStatus.PENDING
        )

    monkeypatch.setattr(health_owner, "_count", count)
    with pytest.raises(ContractError, match="readiness_failed"):
        runtime.host._full_runtime(runtime.request)
    assert len(runtime.calls) == 1


@pytest.mark.parametrize("value", [None, "", "  ", "true", "1", "yes", "on", " TRUE "])
def test_effective_true_flag_uses_configuration_owner_semantics(runtime, value):
    runtime.app["Config"]["Env"] = [
        item
        for item in runtime.app["Config"]["Env"]
        if not item.startswith("VENDOR_RELAY_EXPECTED=")
    ]
    runtime.specification["services"]["app"]["environment"].pop("VENDOR_RELAY_EXPECTED")
    if value is not None:
        runtime.app["Config"]["Env"].append("VENDOR_RELAY_EXPECTED=" + value)
        runtime.specification["services"]["app"]["environment"][
            "VENDOR_RELAY_EXPECTED"
        ] = value
    runtime.host._full_runtime(runtime.request)


@pytest.mark.parametrize("value", ["false", "0", "no", "off"])
def test_candidate_relay_not_expected_cannot_pass_full_runtime(runtime, value):
    runtime.specification["services"]["app"]["environment"]["VENDOR_RELAY_EXPECTED"] = (
        value
    )
    runtime.app["Config"]["Env"][0] = "VENDOR_RELAY_EXPECTED=" + value
    with pytest.raises(ContractError, match="full_runtime_relay_not_expected"):
        runtime.host._full_runtime(runtime.request)
    assert runtime.calls == []


def test_invalid_relay_expectation_refuses_through_configuration_owner(runtime):
    runtime.specification["services"]["app"]["environment"]["VENDOR_RELAY_EXPECTED"] = (
        "maybe"
    )
    runtime.app["Config"]["Env"][0] = "VENDOR_RELAY_EXPECTED=maybe"
    with pytest.raises(ProductionConfigurationError):
        runtime.host._full_runtime(runtime.request)
    assert runtime.calls == []


def test_duplicate_relay_expectation_is_ambiguous(runtime):
    runtime.app["Config"]["Env"].append("VENDOR_RELAY_EXPECTED=true")
    with pytest.raises(ContractError, match="full_runtime_relay_expectation_ambiguous"):
        runtime.host._full_runtime(runtime.request)


@pytest.mark.parametrize(
    "change,code",
    [
        ("relay_restarting", "full_runtime_restarting"),
        ("relay_exited", "full_runtime_image_mismatch"),
        ("relay_missing", "full_runtime_roles_missing"),
        ("relay_duplicate", "full_runtime_roles_ambiguous"),
        ("app_restarting", "full_runtime_restarting"),
        ("app_unhealthy", "full_runtime_unhealthy"),
        ("app_health_disabled", "full_runtime_app_healthcheck_disabled"),
        ("wrong_image", "full_runtime_image_mismatch"),
        ("wrong_reference", "full_runtime_image_mismatch"),
        ("wrong_mount", "runtime_mount_mismatch"),
        ("wrong_environment", "runtime_environment_mismatch"),
        ("ops_running", "ops_running"),
    ],
)
def test_invalid_runtime_never_reaches_positive_http_owner(runtime, change, code):
    if change == "relay_restarting":
        runtime.relay["State"]["Restarting"] = True
    elif change == "relay_exited":
        runtime.relay["State"]["Running"] = False
    elif change == "relay_missing":
        runtime.writers.remove(runtime.relay)
    elif change == "relay_duplicate":
        runtime.writers.append(deepcopy(runtime.relay))
    elif change == "app_restarting":
        runtime.app["State"]["Restarting"] = True
    elif change == "app_unhealthy":
        runtime.app["State"]["Health"]["Status"] = "unhealthy"
    elif change == "app_health_disabled":
        runtime.app["Config"]["Healthcheck"]["Test"] = ["NONE"]
    elif change == "wrong_image":
        runtime.relay["Image"] = "sha256:" + "d" * 64
    elif change == "wrong_reference":
        runtime.relay["Config"]["Image"] = "mutable:tag"
    elif change == "wrong_mount":
        runtime.relay["Mounts"][0]["Name"] = "other"
    elif change == "wrong_environment":
        runtime.app["Config"]["Env"] = []
    else:
        runtime.writers.append(
            {
                "Config": {"Labels": {"com.docker.compose.service": "ops"}},
                "State": {"Running": True, "Restarting": False},
            }
        )
    with pytest.raises(ContractError, match=code):
        runtime.host._full_runtime(runtime.request)
    assert runtime.calls == []


def test_positive_relay_readiness_still_requires_actual_keyless_ledger(runtime):
    runtime.ledger_bad = True
    with pytest.raises(ContractError, match="ledger_runtime_not_ready"):
        runtime.host._full_runtime(runtime.request)
    assert len(runtime.calls) == 2


def test_full_ready_clears_runtime_phase_only_after_positive_evidence(runtime):
    evidence = runtime.host.full_ready(runtime.request, "a" * 64)
    assert json.loads(evidence)["kind"] == "full-ready"
    assert runtime.host.runtime_phase is None


@pytest.mark.parametrize(
    "stage,expected",
    [
        ("compose", module.RuntimeReadinessPhase.COMPOSE_LAUNCH),
        ("containers", module.RuntimeReadinessPhase.CONTAINERS_VERIFY),
        ("loopback", module.RuntimeReadinessPhase.LOOPBACK_READY),
        ("ledger", module.RuntimeReadinessPhase.LEDGER_VERIFY),
    ],
)
def test_runtime_refusal_keeps_only_closed_phase(runtime, monkeypatch, stage, expected):
    def refuse(*args, **kwargs):
        raise ContractError("schema_violation")

    if stage == "compose":
        monkeypatch.setattr(runtime.host, "_run", refuse)
    elif stage == "containers":
        runtime.app["State"]["Health"]["Status"] = "unhealthy"
    elif stage == "loopback":
        runtime.heartbeat_at = None
    else:
        runtime.ledger_bad = True
    with pytest.raises(ContractError):
        runtime.host.full_ready(runtime.request, "a" * 64)
    assert runtime.host.runtime_phase is expected
