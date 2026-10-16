"""Source-preparation fixtures. No live GitHub/token/host access.

These tests are provided for separately authorized execution; source checks alone
are not evidence that the tests passed or native transport is qualified.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import struct
import time
import zipfile
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from vendor_cp.deployment import gate0_e_github as gh

_TRANSPORT_GET = gh.InstalledGate0GitHubReads._get


@pytest.fixture
def producer(monkeypatch):
    raw = b"name: reviewed\njobs: {}\n"
    source_hash = gh._digest(raw)
    blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
    ).hexdigest()
    repository = gh.RepositoryPin("dotmac", "selected", 10, 11)
    steps = (
        gh.StepPin(1, "Collect", gh.ProducerStage.COLLECTION_SNAPSHOT),
        gh.StepPin(2, "Upload", gh.ProducerStage.PRODUCER_JOB_COMPLETE),
    )
    workflow = gh.WorkflowPin(
        12,
        ".github/workflows/e.yml",
        "a" * 40,
        blob,
        source_hash,
        "e",
        "E job",
        13,
        "protected",
        14,
        15,
        16,
        "dedicated",
        steps,
        ("actions/checkout@" + "b" * 40,),
        ("/etc/dotmac-gate0-e/source.json", "c" * 64),
    )
    run = gh.RunPin(
        repository, workflow, 17, 1, "a" * 40, "main", "workflow_dispatch", 14, 14
    )
    owner = object.__new__(gh.InstalledGate0GitHubReads)
    owner._repository, owner._producer, owner._publication = repository, run, None
    owner._installation = {"phase": "producer"}
    owner._transfer = None
    owner._release = None
    owner._origins = ("download.example.com",)
    owner._used, owner._failed, owner._issued = set(), False, []
    owner._observations, owner._deadline, owner._metadata, owner._exchanges = (
        [],
        0.0,
        0,
        0,
    )
    policy = {
        "job_name": "E job",
        "mandatory_jobs": ["E job"],
        "environment_rules": [],
        "branch_policies": [],
        "sole_artifact_step": 2,
        "ciphertext_sha256": None,
        "projection_sha256": None,
        "policy_digest": "sha256:" + "1" * 64,
        "campaign_digest": "sha256:" + "2" * 64,
        "source_bundle_digest": "sha256:" + "3" * 64,
    }
    owner._policies = {17: policy}
    action = {
        "run_id": 17,
        "head_sha": "a" * 40,
        "runner_id": 16,
        "runner_group_id": 15,
        "job_name": "E job",
        "environment_id": 13,
        "qualified_at": "2026-10-15T10:00:00Z",
        "protection_rules_sha256": gh._digest(b"[]"),
        "branch_policies_sha256": gh._digest(b"[]"),
        "source_policy_digest": "c" * 64,
        "native_record_digest": "d" * 64,
    }
    owner._qualification = {
        "action_time": {"17": action},
        "transfer_profile": "flat-two-stored-or-deflate-no-extra.v1",
    }
    anchor = {
        "id": 17,
        "run_attempt": 1,
        "workflow_id": 12,
        "head_sha": "a" * 40,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": workflow.path,
        "status": "completed",
        "conclusion": "success",
        "display_title": "E read",
        "repository": {"id": 10, "owner": {"id": 11}},
        "head_repository": {"id": 10},
        "actor": {"id": 14},
        "triggering_actor": {"id": 14},
    }
    job = {
        "id": 18,
        "run_id": 17,
        "head_sha": "a" * 40,
        "name": "E job",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-10-15T10:01:00Z",
        "completed_at": "2026-10-15T10:05:00Z",
        "runner_id": 16,
        "runner_name": "dedicated",
        "runner_group_id": 15,
        "steps": [
            {
                "number": n,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-15T10:02:00Z",
                "completed_at": "2026-10-15T10:04:00Z",
            }
            for n, name in ((1, "Collect"), (2, "Upload"))
        ],
    }
    responses = {
        gh.EndpointCode.REPOSITORY: {
            "id": 10,
            "owner": {"id": 11},
            "full_name": "dotmac/selected",
            "unrelated_optional": "allowed",
        },
        gh.EndpointCode.RUN: anchor,
        gh.EndpointCode.ATTEMPT: copy.deepcopy(anchor),
        gh.EndpointCode.WORKFLOW: {"id": 12, "path": workflow.path},
        gh.EndpointCode.SOURCE: {
            "type": "file",
            "path": workflow.path,
            "sha": blob,
            "encoding": "base64",
            "size": len(raw),
            "content": base64.b64encode(raw).decode(),
        },
        gh.EndpointCode.JOBS: {"total_count": 1, "jobs": [job]},
        gh.EndpointCode.REVIEWS: [
            {
                "state": "approved",
                "user": {"id": 14},
                "environments": [{"id": 13, "name": "protected"}],
            }
        ],
        gh.EndpointCode.PENDING: [],
        gh.EndpointCode.ENVIRONMENT: {
            "id": 13,
            "name": "protected",
            "protection_rules": [],
        },
        gh.EndpointCode.BRANCHES: {"total_count": 0, "branch_policies": []},
    }

    def get(self, code, run=None, identifier=None, page=0, maximum=gh._JSON_CAP):
        value = copy.deepcopy(responses[code])
        body = gh._canonical(value)
        self._observations.append(
            gh.GitHubObservation(
                code,
                page,
                200,
                gh._digest(body),
                body,
                "2026-10-15T10:06:00Z",
                time.monotonic(),
            )
        )
        return value, 0, 0

    monkeypatch.setattr(gh.InstalledGate0GitHubReads, "_get", get)
    return owner, responses


def test_success_is_live_owner_fact_and_single_attempt(producer):
    owner, _ = producer
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert facts.attempt == 1 and facts.review.reviewer_id == 14
    assert owner.owns_facts(facts)
    assert not owner.owns_facts(replace(facts))
    assert "body=" not in repr(facts.observations[0])
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert not owner.owns_facts(facts)


@pytest.mark.parametrize(
    ("endpoint", "key", "value"),
    [
        (gh.EndpointCode.RUN, "run_attempt", 2),
        (gh.EndpointCode.RUN, "workflow_id", True),
        (gh.EndpointCode.RUN, "head_sha", "f" * 40),
        (gh.EndpointCode.RUN, "event", "pull_request"),
        (gh.EndpointCode.RUN, "head_repository", {"id": 999}),
        (gh.EndpointCode.RUN, "triggering_actor", {"id": 999}),
        (gh.EndpointCode.REPOSITORY, "owner", {"id": 999}),
        (gh.EndpointCode.SOURCE, "type", "symlink"),
        (gh.EndpointCode.SOURCE, "sha", "f" * 40),
        (gh.EndpointCode.ENVIRONMENT, "id", 999),
    ],
)
def test_selected_identity_and_source_refusal(producer, endpoint, key, value):
    owner, responses = producer
    responses[endpoint][key] = value
    with pytest.raises(gh.GitHubReadRefused, match="^GITHUB_READ_REFUSED$"):
        owner.producer_snapshot(gh.ProducerStage.COLLECTION_SNAPSHOT)
    assert owner._failed


@pytest.mark.parametrize(
    "mutation",
    [
        "skipped",
        "duplicate",
        "runner",
        "reviewer",
        "contradiction",
        "pending",
        "action_time",
    ],
)
def test_steps_reviews_and_historical_qualification(producer, mutation):
    owner, responses = producer
    job = responses[gh.EndpointCode.JOBS]["jobs"][0]
    if mutation == "skipped":
        job["steps"][0]["conclusion"] = "skipped"
    elif mutation == "duplicate":
        job["steps"].append(copy.deepcopy(job["steps"][0]))
    elif mutation == "runner":
        job["runner_id"] = 999
    elif mutation == "reviewer":
        responses[gh.EndpointCode.REVIEWS][0]["user"]["id"] = 999
    elif mutation == "contradiction":
        responses[gh.EndpointCode.REVIEWS].append(
            copy.deepcopy(responses[gh.EndpointCode.REVIEWS][0])
        )
    elif mutation == "pending":
        responses[gh.EndpointCode.PENDING] = [
            {"environment": {"id": 13, "name": "protected"}}
        ]
    else:
        owner._qualification["action_time"] = {}
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.COLLECTION_SNAPSHOT)


def test_collection_stage_does_not_invent_future_success(producer):
    owner, responses = producer
    for endpoint in (gh.EndpointCode.RUN, gh.EndpointCode.ATTEMPT):
        responses[endpoint].update(status="in_progress", conclusion=None)
    job = responses[gh.EndpointCode.JOBS]["jobs"][0]
    job.update(status="in_progress", conclusion=None, completed_at=None)
    job["steps"][1].update(
        status="queued", conclusion=None, started_at=None, completed_at=None
    )
    facts = owner.producer_snapshot(gh.ProducerStage.COLLECTION_SNAPSHOT)
    assert facts.status == "in_progress" and facts.jobs[0].steps[1].conclusion is None


def test_future_stage_requires_upload_success(producer):
    owner, responses = producer
    responses[gh.EndpointCode.JOBS]["jobs"][0]["steps"][1]["conclusion"] = "neutral"
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.PRODUCER_JOB_COMPLETE)


def _running_courier(producer):
    owner, responses = producer
    owner._installation["phase"] = "protected_job"
    for endpoint in (gh.EndpointCode.RUN, gh.EndpointCode.ATTEMPT):
        responses[endpoint].update(status="in_progress", conclusion=None)
    job = responses[gh.EndpointCode.JOBS]["jobs"][0]
    job.update(status="in_progress", conclusion=None, completed_at=None)
    first, second = copy.deepcopy(job["steps"])
    first.update(number=1, name="Prepare")
    second.update(
        number=2,
        name="Courier",
        status="in_progress",
        conclusion=None,
        completed_at=None,
    )
    future = [
        dict(second, number=n, name=name, status="queued", started_at=None)
        for n, name in ((3, "Collect"), (4, "Upload"))
    ]
    job["steps"] = [first, second, *future]
    steps = (
        gh.StepPin(1, "Prepare", gh.ProducerStage.COLLECTION_SNAPSHOT),
        gh.StepPin(2, "Courier", gh.ProducerStage.PROTECTED_JOB_STARTED),
        gh.StepPin(3, "Collect", gh.ProducerStage.COLLECTION_SNAPSHOT),
        gh.StepPin(4, "Upload", gh.ProducerStage.PRODUCER_JOB_COMPLETE),
    )
    owner._producer = replace(
        owner._producer,
        workflow=replace(owner._producer.workflow, required_steps=steps),
    )
    owner._policies[17]["sole_artifact_step"] = 4
    return owner, responses


def test_protected_job_snapshot_precedes_collection_and_keeps_original_bound(producer):
    owner, _ = _running_courier(producer)
    original_end = time.monotonic() + 5
    facts = owner.protected_job_snapshot(deadline=original_end)
    assert facts.stage == gh.ProducerStage.PROTECTED_JOB_STARTED
    assert owner.owns_facts(facts)
    assert owner._deadline == original_end
    assert facts.jobs[0].steps[1].status == "in_progress"
    assert all(step.status == "queued" for step in facts.jobs[0].steps[2:])
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=original_end + 100)


@pytest.mark.parametrize("step", [0, 1])
def test_protected_job_requires_successful_predecessor_and_current_courier(
    producer, step
):
    owner, responses = _running_courier(producer)
    responses[gh.EndpointCode.JOBS]["jobs"][0]["steps"][step].update(
        status="queued", conclusion=None, started_at=None, completed_at=None
    )
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=time.monotonic() + 5)


@pytest.mark.parametrize(
    "deadline", [None, "future", True, float("inf"), float("nan"), 10**400, 0]
)
def test_protected_job_snapshot_refuses_invalid_original_bound(producer, deadline):
    owner, _ = producer
    owner._installation["phase"] = "protected_job"
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=deadline)
    assert owner._failed and not owner._issued
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=time.monotonic() + 5)


def test_invalid_second_protected_job_call_invalidates_owned_facts(producer):
    owner, _ = _running_courier(producer)
    facts = owner.protected_job_snapshot(deadline=time.monotonic() + 5)
    assert owner.owns_facts(facts)
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=None)
    assert not owner.owns_facts(facts)


def test_protected_job_snapshot_rejects_already_completed_job(producer):
    owner, _ = producer
    owner._installation["phase"] = "protected_job"
    with pytest.raises(gh.GitHubReadRefused):
        owner.protected_job_snapshot(deadline=time.monotonic() + 5)


def test_producer_stage_cannot_bypass_provisioning_deadline(producer):
    owner, _ = producer
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.PROTECTED_JOB_STARTED)
    assert owner._failed


@pytest.mark.parametrize(
    "body", [b'{"a":1,"a":2}', b'{"x":NaN}', b"[" * 33 + b"0" + b"]" * 33, b"{}" + b"x"]
)
def test_json_rejects_duplicates_nonfinite_depth_and_trailing(body):
    with pytest.raises(gh.GitHubReadRefused):
        gh._json(body)


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/x",
        "https://download.example.com@evil.example/x",
        "https://download.example.com:444/x",
        "https://download.example.com/x#fragment",
        "https://download.example.com\\@evil.example/x",
        "http://download.example.com/x",
        "https://download.example.com//ambiguous",
    ],
)
def test_redirect_authority_is_closed(location):
    with pytest.raises(gh.GitHubReadRefused):
        gh._redirect(location, ("download.example.com",))


def test_child_redirect_never_forwards_api_token(monkeypatch):
    calls = []

    def https(host, path, token, binary, maximum, deadline):
        calls.append((host, token))
        if len(calls) == 1:
            return (
                302,
                {"location": "https://download.example.com/signed?secret=value"},
                b"",
            )
        return 200, {}, b"cipher"

    channel = SimpleNamespace(
        settimeout=lambda _: None,
        sendall=lambda _: None,
        shutdown=lambda _: None,
        close=lambda: None,
    )
    monkeypatch.setattr(gh, "_https", https)
    gh._http_child(
        channel,
        "/repos/o/r/releases/assets/1",
        b"private-token",
        True,
        100,
        ("download.example.com",),
        time.monotonic() + 1,
        0,
    )
    assert calls == [
        ("api.github.com", b"private-token"),
        ("download.example.com", None),
    ]


def test_metadata_redirect_never_reaches_second_host(monkeypatch):
    calls = []

    def https(*args):
        calls.append(args)
        return 302, {"location": "https://download.example.com/x"}, b""

    channel = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(gh, "_https", https)
    gh._http_child(
        channel,
        "/repos/o/r",
        b"private-token",
        False,
        100,
        ("download.example.com",),
        time.monotonic() + 1,
        0,
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
        b"Content-Type: application/json\r\n\r\n{}trailing",
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n"
        b"Content-Type: application/json\r\n\r\n{}",
    ],
)
def test_http_framing_refuses_ambiguity_and_partial(monkeypatch, wire):
    class FakeSocket:
        def __init__(self):
            self.body = io.BytesIO(wire)

        def settimeout(self, _):
            pass

        def connect(self, address):
            assert address == ("1.1.1.1", 443)

        def sendall(self, _):
            pass

        def recv(self, count):
            return self.body.read(count)

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeContext:
        def __init__(self, _):
            pass

        def load_verify_locations(self, **kwargs):
            assert kwargs == {"cafile": gh._CA}

        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "api.github.com"
            return raw

    monkeypatch.setattr(
        gh.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                gh.socket.AF_INET,
                gh.socket.SOCK_STREAM,
                gh.socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", 443),
            )
        ],
    )
    monkeypatch.setattr(gh.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(gh.ssl, "SSLContext", FakeContext)
    with pytest.raises(gh.GitHubReadRefused):
        gh._https(
            "api.github.com", "/repos/o/r", b"secret", False, 100, time.monotonic() + 1
        )


def zip_bytes(
    names=("gate0-evidence.pgp", "gate0-evidence-public.json"),
    compression=zipfile.ZIP_STORED,
):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name in names:
            archive.writestr(name, b"{}" if name.endswith(".json") else b"cipher")
    return stream.getvalue()


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_strict_zip_has_two_flat_members(compression):
    assert gh._unzip(zip_bytes(compression=compression)) == (b"cipher", b"{}")


@pytest.mark.parametrize(
    "names",
    [
        ("../gate0-evidence.pgp", "gate0-evidence-public.json"),
        ("gate0-evidence.pgp", "gate0-evidence.pgp"),
        ("gate0-evidence.pgp", "gate0-evidence-public.json", "extra"),
    ],
)
def test_zip_traversal_duplicate_extra_refused(names):
    with pytest.raises(gh.GitHubReadRefused):
        gh._unzip(zip_bytes(names))


def test_zip_trailing_and_crc_refused():
    raw = zip_bytes()
    with pytest.raises(gh.GitHubReadRefused):
        gh._unzip(raw + b"trailing")
    corrupt = bytearray(raw)
    corrupt[49] ^= 1
    with pytest.raises(gh.GitHubReadRefused):
        gh._unzip(bytes(corrupt))


@pytest.mark.parametrize("mode", ["partial", "nonzero", "timeout", "cleanup"])
def test_ipc_partial_exit_watchdog_and_cleanup_refuse(monkeypatch, mode):
    processes = []

    class Process:
        pid = 123
        exitcode = 1 if mode == "nonzero" else 0

        def __init__(self, **kwargs):
            self.channel = kwargs["args"][0]
            self.alive = mode in ("timeout", "cleanup")
            self.killed = False
            processes.append(self)

        def start(self):
            data = (
                struct.pack("!IIII", 200, 0, 0, 10 if mode == "partial" else 2) + b"{}"
            )
            self.channel.sendall(data)
            self.channel.shutdown(gh.socket.SHUT_WR)

        def join(self, timeout):
            assert timeout >= 0

        def is_alive(self):
            return self.alive

        def kill(self):
            self.killed = True
            if mode != "cleanup":
                self.alive = False

        def close(self):
            pass

    monkeypatch.setattr(
        gh.multiprocessing, "get_context", lambda _: SimpleNamespace(Process=Process)
    )
    if mode == "timeout":
        monkeypatch.setattr(gh.select, "select", lambda *args: ([], [], []))
    with pytest.raises(gh.GitHubReadRefused):
        gh._spawn_get("/repos/o/r", b"secret", False, 100, (), time.monotonic() + 2, 0)
    if mode in ("timeout", "cleanup"):
        assert processes[0].killed


def test_no_cli_attestation_success_from_json_or_dto():
    with pytest.raises(
        gh.AttestationTransportUnqualified, match="^ATTESTATION_TRANSPORT_UNQUALIFIED$"
    ):
        gh.InstalledGhReleaseVerifier.from_installed()


def test_constructor_sealed():
    with pytest.raises(gh.GitHubReadRefused):
        gh.InstalledGate0GitHubReads(object(), {}, {})


def test_pagination_changes_and_truncation_refuse(producer, monkeypatch):
    owner, _ = producer
    owner._deadline = time.monotonic() + 10
    monkeypatch.setattr(
        gh.InstalledGate0GitHubReads,
        "_get",
        lambda *args: ({"total_count": 2, "jobs": [{"id": 1}]}, 0, 0),
    )
    with pytest.raises(gh.GitHubReadRefused):
        owner._pages(gh.EndpointCode.JOBS, "jobs", 128, owner._producer)
    with pytest.raises(gh.GitHubReadRefused):
        gh._pagination(
            '<https://evil.example/jobs?per_page=100&page=2>; rel="next"',
            "/repos/o/r/actions/runs/1/attempts/1/jobs?per_page=100&page=1",
            1,
        )


@pytest.mark.parametrize(
    "address",  # noqa: S104 -- refusal fixture, never a bind address
    ["127.0.0.1", "10.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1"],  # noqa: S104
)
def test_dns_nonpublic_address_never_connects(monkeypatch, address):
    monkeypatch.setattr(
        gh.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                gh.socket.AF_INET,
                gh.socket.SOCK_STREAM,
                gh.socket.IPPROTO_TCP,
                "",
                (address, 443),
            )
        ],
    )

    def forbidden(*args):
        raise AssertionError("connect must not be constructed")

    monkeypatch.setattr(gh.socket, "socket", forbidden)
    with pytest.raises(gh.GitHubReadRefused):
        gh._https(
            "api.github.com", "/repos/o/r", b"secret", False, 100, time.monotonic() + 1
        )


@pytest.mark.parametrize("mutation", ["id", "expired", "source", "time", "digest"])
def test_artifact_metadata_cannot_substitute_source_or_time(producer, mutation):
    owner, responses = producer
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_JOB_COMPLETE)
    item = {
        "id": 21,
        "name": "transfer",
        "expired": False,
        "size_in_bytes": 100,
        "digest": "sha256:" + "a" * 64,
        "workflow_run": {
            "id": 17,
            "repository_id": 10,
            "head_repository_id": 10,
            "head_sha": "a" * 40,
            "head_branch": "main",
        },
        "created_at": "2026-10-15T10:02:01Z",
        "updated_at": "2026-10-15T10:03:59Z",
        "expires_at": "2030-10-15T10:00:00Z",
    }
    if mutation == "id":
        item["id"] = 999
    elif mutation == "expired":
        item["expired"] = True
    elif mutation == "source":
        item["workflow_run"]["head_repository_id"] = 999
    elif mutation == "time":
        item["created_at"] = "2026-10-15T09:59:00Z"
    else:
        item["digest"] = None
    responses[gh.EndpointCode.ARTIFACT] = item
    with pytest.raises(gh.GitHubReadRefused):
        owner._artifact(
            owner._producer, gh.TransferPin(21, "transfer", ("transfer",)), facts
        )


@pytest.mark.parametrize(
    "mutation",
    ["repository_id", "attempt", "ciphertext_digest", "campaign_digest", "extra"],
)
def test_projection_is_closed_and_bound_to_actual_producer(producer, mutation):
    owner, _ = producer
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_JOB_COMPLETE)
    policy = owner._policies[17]
    value = {
        "schema": "Gate0EncryptedEvidenceProjection.v1",
        "result": "encrypted_evidence",
        "policy_digest": policy["policy_digest"],
        "campaign_digest": policy["campaign_digest"],
        "source_bundle_digest": policy["source_bundle_digest"],
        "collection_digest": "sha256:" + "4" * 64,
        "plaintext_archive_digest": "sha256:" + "5" * 64,
        "inner_manifest_digest": "sha256:" + "6" * 64,
        "ciphertext_digest": "sha256:" + gh._digest(b"cipher"),
        "ciphertext_bytes": 6,
        "producer": {
            "repository_id": 10,
            "owner_id": 11,
            "workflow_id": 12,
            "run_id": 17,
            "attempt": 1,
            "job_id": 18,
            "source_revision": "a" * 40,
        },
    }
    assert gh._projection(gh._canonical(value), b"cipher", facts, policy) == value
    if mutation in ("repository_id", "attempt"):
        value["producer"][mutation] = True
    elif mutation == "extra":
        value["approval"] = True
    else:
        value[mutation] = "sha256:" + "f" * 64
    with pytest.raises(gh.GitHubReadRefused):
        gh._projection(gh._canonical(value), b"cipher", facts, policy)


@pytest.mark.parametrize(
    ("key", "value"),
    [("id", 999), ("draft", True), ("immutable", False), ("tag_name", "wrong")],
)
def test_published_anchor_requires_exact_release_and_immutability(producer, key, value):
    owner, _ = producer
    pin = gh.ReleasePin(22, "gate0-selected", "a" * 40, ())
    anchor = {
        "id": 22,
        "tag_name": "gate0-selected",
        "draft": False,
        "immutable": True,
        "created_at": "2026-10-15T10:00:00Z",
        "published_at": "2026-10-15T10:01:00Z",
    }
    anchor[key] = value
    with pytest.raises(gh.GitHubReadRefused):
        owner._release_anchor(anchor, pin, True)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", 999),
        ("state", "new"),
        ("size", True),
        ("digest", None),
        ("name", "wrong"),
    ],
)
def test_release_asset_metadata_requires_pinned_bytes(producer, key, value):
    owner, _ = producer
    pin = gh.ReleaseAssetPin(23, "gate0-evidence.pgp", 6, "a" * 64)
    metadata = {
        "id": 23,
        "name": pin.name,
        "state": "uploaded",
        "size": 6,
        "digest": "sha256:" + "a" * 64,
        "content_type": "application/octet-stream",
        "uploader": {"id": 14},
        "created_at": "2026-10-15T10:00:00Z",
        "updated_at": "2026-10-15T10:01:00Z",
    }
    metadata[key] = value
    with pytest.raises(gh.GitHubReadRefused):
        owner._asset_metadata(metadata, pin)


def test_tag_cycle_and_wrong_commit_refuse(producer):
    owner, responses = producer
    pin = gh.ReleasePin(22, "gate0-selected", "a" * 40, ())
    responses[gh.EndpointCode.TAG_REF] = {
        "ref": "refs/tags/gate0-selected",
        "object": {"type": "commit", "sha": "b" * 40},
    }
    with pytest.raises(gh.GitHubReadRefused):
        owner._tag_commit(pin)
    responses[gh.EndpointCode.TAG_REF]["object"] = {"type": "tag", "sha": "b" * 40}
    responses[gh.EndpointCode.TAG] = {
        "sha": "b" * 40,
        "object": {"type": "tag", "sha": "b" * 40},
    }
    with pytest.raises(gh.GitHubReadRefused):
        owner._tag_commit(pin)


def test_tag_binding_preserves_raw_annotated_identity(producer):
    owner, responses = producer
    pin = gh.ReleasePin(22, "gate0-selected", "a" * 40, ())
    responses[gh.EndpointCode.TAG_REF] = {
        "ref": "refs/tags/gate0-selected",
        "object": {"type": "tag", "sha": "b" * 40},
    }
    responses[gh.EndpointCode.TAG] = {
        "sha": "b" * 40,
        "object": {"type": "commit", "sha": "a" * 40},
    }
    assert owner._tag_binding(pin) == ("b" * 40, "a" * 40)
    responses[gh.EndpointCode.TAG_REF]["object"] = {"type": "commit", "sha": "a" * 40}
    assert owner._tag_binding(pin) == ("a" * 40, "a" * 40)


def test_tag_binding_detects_new_tag_object_at_same_commit(producer):
    owner, responses = producer
    pin = gh.ReleasePin(22, "gate0-selected", "a" * 40, ())
    responses[gh.EndpointCode.TAG_REF] = {
        "ref": "refs/tags/gate0-selected",
        "object": {"type": "tag", "sha": "b" * 40},
    }
    responses[gh.EndpointCode.TAG] = {
        "sha": "b" * 40,
        "object": {"type": "commit", "sha": "a" * 40},
    }
    before = owner._tag_binding(pin)
    responses[gh.EndpointCode.TAG_REF]["object"]["sha"] = "c" * 40
    responses[gh.EndpointCode.TAG]["sha"] = "c" * 40
    after = owner._tag_binding(pin)
    assert before[1] == after[1]
    assert before != after


def test_documented_attempt_jobs_shape_needs_no_job_attempt(producer):
    owner, responses = producer
    assert "run_attempt" not in responses[gh.EndpointCode.JOBS]["jobs"][0]
    assert "/attempts/1/jobs?per_page=100&page=1" in owner._path(
        gh.EndpointCode.JOBS, owner._producer, None, 1
    )
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert facts.attempt == 1 and facts.jobs[0].run_id == 17


def test_attempt_anchor_still_refuses_rerun_without_job_attempt(producer):
    owner, responses = producer
    responses[gh.EndpointCode.ATTEMPT]["run_attempt"] = 2
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.COLLECTION_SNAPSHOT)


@pytest.mark.parametrize("value", [2, True, "1", None])
def test_optional_job_attempt_cannot_contradict_selected_attempt(producer, value):
    owner, responses = producer
    responses[gh.EndpointCode.JOBS]["jobs"][0]["run_attempt"] = value
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.COLLECTION_SNAPSHOT)


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [
        ("2019-08-08T18:59:58.000-07:00", "2019-08-09T01:59:58+00:00"),
        ("2026-10-15T10:02:00.123456Z", "2026-10-15T10:02:00.123456+00:00"),
        ("2026-10-15T11:02:00.5+01:00", "2026-10-15T10:02:00.500000+00:00"),
        ("2026-10-15T02:02:00.123456-08:00", "2026-10-15T10:02:00.123456+00:00"),
        ("2026-01-01T00:00:00.000001+01:00", "2025-12-31T23:00:00.000001+00:00"),
        ("2026-12-31T23:59:59.999999-01:00", "2027-01-01T00:59:59.999999+00:00"),
        ("2026-10-15T10:02:00+00:00", "2026-10-15T10:02:00+00:00"),
    ],
)
def test_documented_fractional_offset_instants_preserve_precision(spelling, expected):
    value = gh._instant(spelling)
    assert value == datetime.fromisoformat(expected)
    assert value.tzinfo is UTC


@pytest.mark.parametrize(
    "spelling",
    [
        "2026-10-15T10:02:00",
        "2026-10-15 10:02:00Z",
        "2026-10-15T10:02:00z",
        "2026-10-15T10:02:00.1234567Z",
        "2026-10-15T10:02:00.Z",
        "2026-10-15T10:02:00-00:00",
        "2026-10-15T10:02:00+24:00",
        "2026-10-15T10:02:00+00:60",
        "2026-10-15T10:02:00+0100",
        "2026-10-15T10:02:00+01:00:00",
        "2026-10-15T10:02:60Z",
        "2026-02-30T10:02:00Z",
        "0000-01-01T00:00:00Z",
        "0001-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59-01:00",
        "2026-10-15T10:02:00Z\n",
        "2026-10-15T10:02:00\x00Z",
        "2026-10-15T10:02:00." + "1" * 100 + "Z",
        "NaN",
    ],
)
def test_upstream_timestamp_refuses_ambiguous_or_unrepresentable_instants(spelling):
    with pytest.raises(gh.GitHubReadRefused):
        gh._instant(spelling)


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_artifact_upload_interval_keeps_subsecond_boundary(producer, delta):
    owner, responses = producer
    step = responses[gh.EndpointCode.JOBS]["jobs"][0]["steps"][1]
    step["started_at"] = "2026-10-15T02:02:00.123456-08:00"
    step["completed_at"] = "2026-10-15T11:04:00.654321+01:00"
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_JOB_COMPLETE)
    assert facts.jobs[0].steps[1].started_at == step["started_at"]
    assert step["started_at"].encode() in next(
        obs.body for obs in facts.observations if obs.endpoint == gh.EndpointCode.JOBS
    )
    fraction = 123456 + delta
    item = {
        "id": 21,
        "name": "transfer",
        "expired": False,
        "size_in_bytes": 100,
        "digest": "sha256:" + "a" * 64,
        "workflow_run": {
            "id": 17,
            "repository_id": 10,
            "head_repository_id": 10,
            "head_sha": "a" * 40,
            "head_branch": "main",
        },
        "created_at": f"2026-10-15T10:02:00.{fraction:06d}Z",
        "updated_at": "2026-10-15T10:04:00.654321Z",
        "expires_at": "2030-10-15T10:00:00Z",
    }
    responses[gh.EndpointCode.ARTIFACT] = item
    pin = gh.TransferPin(21, "transfer", ("transfer",))
    if delta < 0:
        with pytest.raises(gh.GitHubReadRefused):
            owner._artifact(owner._producer, pin, facts)
    else:
        assert (
            owner._artifact(owner._producer, pin, facts)["created_at"]
            == item["created_at"]
        )


@pytest.fixture
def release_snapshot(producer, monkeypatch):
    """Real reader composition with only its HTTP response seam replaced."""
    owner, responses = producer
    original_get = gh.InstalledGate0GitHubReads._get
    calls = []
    counts = {}
    changes = {}
    assets = {}
    asset_bytes = {}

    def configure(published=False):
        owner._installation["phase"] = "published" if published else "draft"
        ciphertext = b"selected ciphertext"
        projection = gh._canonical(
            {
                "schema": "Gate0EncryptedEvidenceProjection.v1",
                "result": "encrypted_evidence",
                "policy_digest": "sha256:" + "1" * 64,
                "campaign_digest": "sha256:" + "2" * 64,
                "source_bundle_digest": "sha256:" + "3" * 64,
                "collection_digest": "sha256:" + "4" * 64,
                "plaintext_archive_digest": "sha256:" + "5" * 64,
                "inner_manifest_digest": "sha256:" + "6" * 64,
                "ciphertext_digest": "sha256:" + gh._digest(ciphertext),
                "ciphertext_bytes": len(ciphertext),
                "producer": {
                    "repository_id": 10,
                    "owner_id": 11,
                    "workflow_id": 12,
                    "run_id": 17,
                    "attempt": 1,
                    "job_id": 18,
                    "source_revision": "a" * 40,
                },
            }
        )
        selected = [
            ("gate0-evidence.pgp", ciphertext),
            ("gate0-evidence-public.json", projection),
        ]
        if published:
            selected.append(("gate0-readiness-receipt.json", b"{}"))
        for identifier, (name, raw) in enumerate(selected, 30):
            asset_bytes[identifier] = raw
            assets[identifier] = {
                "id": identifier,
                "name": name,
                "state": "uploaded",
                "size": len(raw),
                "digest": "sha256:" + gh._digest(raw),
                "content_type": "application/octet-stream",
                "uploader": {"id": 14},
                "created_at": "2026-10-15T10:06:00Z",
                "updated_at": "2026-10-15T10:06:00Z",
            }
        owner._release = {
            "release_id": 22,
            "tag": "gate0-selected",
            "commit": "a" * 40,
            "assets": [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "size": item["size"],
                    "sha256": item["digest"][7:],
                }
                for item in assets.values()
            ],
        }
        responses[gh.EndpointCode.RELEASE] = {
            "id": 22,
            "tag_name": "gate0-selected",
            "draft": not published,
            "immutable": published,
            "target_commitish": "a" * 40,
            "created_at": "2026-10-15T10:06:00Z",
            "published_at": "2026-10-15T10:07:00Z" if published else None,
        }
        responses[gh.EndpointCode.ASSETS] = list(assets.values())
        if published:
            owner._qualification["immutable_setting"] = {
                "repository_id": 10,
                "state": "enabled",
                "response_sha256": "7" * 64,
                "native_record_digest": "8" * 64,
                "observed_at": "2026-10-15T10:00:00Z",
            }
            responses[gh.EndpointCode.TAG_REF] = {
                "ref": "refs/tags/gate0-selected",
                "object": {"type": "tag", "sha": "b" * 40},
            }
            responses[gh.EndpointCode.TAG] = {
                "sha": "b" * 40,
                "object": {"type": "commit", "sha": "a" * 40},
            }
        return owner

    def get(self, code, run=None, identifier=None, page=0, maximum=gh._JSON_CAP):
        calls.append((code, identifier))
        counts[code] = counts.get(code, 0) + 1
        change = changes.get((code, counts[code]))
        if change is not None:
            change()
        if code not in (gh.EndpointCode.ASSET, gh.EndpointCode.ASSET_BYTES):
            return original_get(self, code, run, identifier, page, maximum)
        value = (
            copy.deepcopy(assets[identifier])
            if code is gh.EndpointCode.ASSET
            else asset_bytes[identifier]
        )
        body = value if isinstance(value, bytes) else gh._canonical(value)
        self._observations.append(
            gh.GitHubObservation(
                code,
                page,
                200,
                gh._digest(body),
                body,
                "2026-10-15T10:08:00Z",
                time.monotonic(),
            )
        )
        return value, 0, 0

    monkeypatch.setattr(gh.InstalledGate0GitHubReads, "_get", get)
    return configure, responses, assets, asset_bytes, calls, changes


def test_first_create_draft_binds_target_without_any_tag_request(release_snapshot):
    configure, responses, _, _, calls, _ = release_snapshot
    owner = configure()
    assert (
        gh.EndpointCode.TAG_REF not in responses
        and gh.EndpointCode.TAG not in responses
    )
    facts = owner.draft_snapshot()
    assert type(facts) is gh.DraftReleaseFacts and owner.owns_facts(facts)
    assert facts.draft and facts.target_commitish == owner._producer.head_sha
    assert not hasattr(facts, "raw_tag_sha") and not hasattr(facts, "peeled_commit")
    assert all(
        code not in (gh.EndpointCode.TAG_REF, gh.EndpointCode.TAG) for code, _ in calls
    )
    assert (
        len(facts.assets) == 2 and facts.assets[0].raw_bytes == b"selected ciphertext"
    )
    with pytest.raises(gh.GitHubReadRefused):
        owner.draft_snapshot()
    assert not owner.owns_facts(facts)


@pytest.mark.parametrize("target", ["main", "b" * 40, "A" * 40, None, True])
def test_draft_refuses_nonexact_selected_target(release_snapshot, target):
    configure, responses, _, _, _, _ = release_snapshot
    owner = configure()
    responses[gh.EndpointCode.RELEASE]["target_commitish"] = target
    with pytest.raises(gh.GitHubReadRefused):
        owner.draft_snapshot()
    assert not owner._issued


def test_draft_detects_target_mutation_during_asset_reads(release_snapshot):
    configure, responses, _, _, _, changes = release_snapshot
    owner = configure()
    changes[(gh.EndpointCode.RELEASE, 2)] = lambda: responses[
        gh.EndpointCode.RELEASE
    ].update(target_commitish="b" * 40)
    with pytest.raises(gh.GitHubReadRefused):
        owner.draft_snapshot()
    assert not owner._issued and owner._observations == []


@pytest.mark.parametrize("mutation", ["inventory", "bytes", "deadline"])
def test_draft_keeps_inventory_byte_and_phase_bounds(release_snapshot, mutation):
    configure, responses, _, asset_bytes, _, changes = release_snapshot
    owner = configure()
    if mutation == "inventory":
        changes[(gh.EndpointCode.ASSETS, 2)] = lambda: responses[
            gh.EndpointCode.ASSETS
        ].pop()
    elif mutation == "bytes":
        asset_bytes[30] = b"substituted bytes"
    else:

        def expire():
            owner._deadline = time.monotonic() - 1

        changes[(gh.EndpointCode.RELEASE, 2)] = expire
    with pytest.raises(gh.GitHubReadRefused):
        owner.draft_snapshot()
    assert not owner._issued


def test_published_snapshot_still_requires_real_annotated_tag_binding(release_snapshot):
    configure, responses, _, _, calls, _ = release_snapshot
    owner = configure(published=True)
    # GitHub's branch-like target statement cannot replace actual tag authority.
    responses[gh.EndpointCode.RELEASE]["target_commitish"] = "main"
    facts = owner.published_snapshot()
    assert type(facts) is gh.DownloadedReleaseFacts and owner.owns_facts(facts)
    assert facts.raw_tag_sha == "b" * 40 and facts.peeled_commit == "a" * 40
    assert not facts.draft and facts.immutable and len(facts.assets) == 3
    assert sum(code is gh.EndpointCode.TAG_REF for code, _ in calls) == 2
    assert sum(code is gh.EndpointCode.TAG for code, _ in calls) == 2


@pytest.mark.parametrize(
    "mutation",
    ["missing_tag", "wrong_commit", "retag_same_commit", "mutable", "missing_receipt"],
)
def test_published_tag_and_immutable_guards_remain_strict(release_snapshot, mutation):
    configure, responses, _, _, _, changes = release_snapshot
    owner = configure(published=True)
    if mutation == "missing_tag":
        responses.pop(gh.EndpointCode.TAG_REF)
    elif mutation == "wrong_commit":
        responses[gh.EndpointCode.TAG]["object"]["sha"] = "c" * 40
    elif mutation == "retag_same_commit":

        def retag():
            responses[gh.EndpointCode.TAG_REF]["object"]["sha"] = "c" * 40
            responses[gh.EndpointCode.TAG]["sha"] = "c" * 40

        changes[(gh.EndpointCode.TAG_REF, 2)] = retag
    elif mutation == "mutable":
        responses[gh.EndpointCode.RELEASE]["immutable"] = False
    else:
        responses[gh.EndpointCode.ASSETS].pop()
    with pytest.raises(gh.GitHubReadRefused):
        owner.published_snapshot()
    assert not owner._issued


@pytest.fixture
def metadata_wire(producer, monkeypatch):
    """Exercise the production _get owner through its shared transport seam."""
    owner, responses = producer
    owner._qualification["credential_uid"] = 0
    owner._deadline = time.monotonic() + 180
    wire = {}
    original_lengths = []

    def bind(code, payload, *, identifier=None, page=0, run=None):
        path = owner._path(code, run, identifier, page)
        wire[path] = payload
        return path

    for code, payload in responses.items():
        page = 1 if code in (gh.EndpointCode.JOBS, gh.EndpointCode.BRANCHES) else 0
        bind(code, payload, page=page, run=owner._producer)

    def get(path, token, binary, maximum, origins, deadline, page):
        assert token == b"test-only-credential"
        raw = wire[path] if binary else gh._canonical(wire[path])
        original_lengths.append(len(raw))
        return 200, 0, 0, raw

    monkeypatch.setattr(gh.InstalledGate0GitHubReads, "_get", _TRANSPORT_GET)
    monkeypatch.setattr(
        gh, "_protected", lambda *args, **kwargs: b"test-only-credential"
    )
    monkeypatch.setattr(gh, "_spawn_get", get)
    return owner, wire, bind, original_lengths


def _inject_private_metadata(item):
    if isinstance(item, dict):
        for child in list(item.values()):
            _inject_private_metadata(child)
        item["download_url"] = "https://private.invalid/blob?token=private-query-marker"
        item["url"] = "https://private.invalid/metadata?token=private-query-marker"
        item["unknown_secret"] = {"deep": [{"credential": "unknown-secret-marker"}]}
    elif isinstance(item, list):
        for child in item:
            _inject_private_metadata(child)


def test_live_producer_projects_private_metadata_and_original_byte_budget(
    metadata_wire,
):
    owner, wire, _, lengths = metadata_wire
    for item in wire.values():
        _inject_private_metadata(item)
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert owner.owns_facts(facts) and facts.workflow_source.raw_bytes.startswith(
        b"name:"
    )
    assert owner._metadata == sum(lengths)
    for observation in facts.observations:
        assert b"private-query-marker" not in observation.body
        assert b"unknown-secret-marker" not in observation.body
        assert b"download_url" not in observation.body
        assert observation.response_sha256 == gh._digest(observation.body)
        # Canonical observation serialization contains only the closed projection.
        serialized = gh._canonical(
            {
                "sha256": observation.response_sha256,
                "body": base64.b64encode(observation.body).decode(),
            }
        )
        assert b"private-query-marker" not in base64.b64decode(
            gh._json(serialized)["body"]
        )
    assert facts.review.observation_sha256 == next(
        obs.response_sha256
        for obs in facts.observations
        if obs.endpoint is gh.EndpointCode.REVIEWS
    )


def test_private_projection_failure_has_no_context_or_partial_facts(metadata_wire):
    owner, wire, _, _ = metadata_wire
    for item in wire.values():
        _inject_private_metadata(item)
    source = next(value for path, value in wire.items() if "/contents/" in path)
    source["sha"] = "f" * 40
    with pytest.raises(gh.GitHubReadRefused) as error:
        owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert str(error.value) == "GITHUB_READ_REFUSED" and error.value.__context__ is None
    assert not owner._issued and not owner._observations


@pytest.mark.parametrize("code", list(gh.EndpointCode))
def test_every_endpoint_retains_only_join_projection_or_exact_binary(
    metadata_wire, code
):
    owner, _, bind, _ = metadata_wire
    run = owner._producer
    assets = {
        "id": 30,
        "name": "gate0-evidence.pgp",
        "state": "uploaded",
        "size": 5,
        "digest": "sha256:" + "e" * 64,
        "content_type": "application/octet-stream",
        "uploader": {"id": 14},
        "created_at": "2026-10-15T10:00:00Z",
        "updated_at": "2026-10-15T10:01:00Z",
    }
    extras = {
        gh.EndpointCode.PENDING: [{"environment": {"id": 99, "name": "other"}}],
        gh.EndpointCode.BRANCHES: {
            "total_count": 1,
            "branch_policies": [{"id": 31, "name": "main", "type": "branch"}],
        },
        gh.EndpointCode.ARTIFACTS: {
            "total_count": 1,
            "artifacts": [{"id": 30, "name": "bundle"}],
        },
        gh.EndpointCode.ARTIFACT: {
            "id": 30,
            "name": "bundle",
            "size_in_bytes": 5,
            "expired": False,
            "digest": "sha256:" + "e" * 64,
            "created_at": "2026-10-15T10:00:00Z",
            "updated_at": "2026-10-15T10:01:00Z",
            "expires_at": "2027-10-15T10:01:00Z",
            "workflow_run": {
                "id": 17,
                "repository_id": 10,
                "head_repository_id": 10,
                "head_sha": "a" * 40,
                "head_branch": "main",
            },
        },
        gh.EndpointCode.RELEASE: {
            "id": 22,
            "tag_name": "selected",
            "draft": False,
            "immutable": True,
            "created_at": "2026-10-15T10:00:00Z",
            "published_at": "2026-10-15T10:01:00Z",
            "target_commitish": "main",
        },
        gh.EndpointCode.ASSETS: [copy.deepcopy(assets)],
        gh.EndpointCode.ASSET: assets,
        gh.EndpointCode.TAG_REF: {
            "ref": "refs/tags/selected",
            "object": {"sha": "a" * 40, "type": "commit"},
        },
        gh.EndpointCode.TAG: {
            "sha": "b" * 40,
            "object": {"sha": "a" * 40, "type": "commit"},
        },
        gh.EndpointCode.ZIP: b"exact selected binary",
        gh.EndpointCode.ASSET_BYTES: b"exact selected binary",
    }
    identifier = (
        "selected"
        if code is gh.EndpointCode.TAG_REF
        else "b" * 40
        if code is gh.EndpointCode.TAG
        else 30
    )
    if code in extras:
        payload = extras[code]
    else:
        path = owner._path(
            code,
            run,
            None,
            1 if code in (gh.EndpointCode.JOBS, gh.EndpointCode.BRANCHES) else 0,
        )
        payload = metadata_wire[1][path]
    page = (
        1
        if code
        in (
            gh.EndpointCode.JOBS,
            gh.EndpointCode.BRANCHES,
            gh.EndpointCode.ARTIFACTS,
            gh.EndpointCode.ASSETS,
        )
        else 0
    )
    path = bind(code, copy.deepcopy(payload), run=run, identifier=identifier, page=page)
    clean, _, _ = owner._get(code, run, identifier, page)
    clean_observation = owner._observations[-1]
    _inject_private_metadata(metadata_wire[1][path])
    actual, _, _ = owner._get(code, run, identifier, page)
    observed = owner._observations[-1]
    assert actual == clean and observed.body == clean_observation.body
    assert observed.response_sha256 == clean_observation.response_sha256
    assert (
        b"private-query-marker" not in observed.body
        and b"unknown-secret-marker" not in observed.body
    )
    if isinstance(payload, bytes):
        assert observed.body == payload
    else:
        assert observed.response_sha256 != gh._digest(
            gh._canonical(metadata_wire[1][path])
        )


@pytest.mark.parametrize(
    "mutation", [None, "wait", "reviewer", "prevent", "unknown_type"]
)
def test_environment_semantics_project_without_hiding_control_changes(
    metadata_wire, mutation
):
    owner, wire, _, _ = metadata_wire
    rules = [
        {"id": 1, "type": "wait_timer", "wait_timer": 0},
        {
            "id": 2,
            "type": "required_reviewers",
            "prevent_self_review": True,
            "reviewers": [{"type": "User", "reviewer": {"id": 14}}],
        },
        {"id": 3, "type": "branch_policy"},
    ]
    owner._policies[17]["environment_rules"] = copy.deepcopy(rules)
    owner._qualification["action_time"]["17"]["protection_rules_sha256"] = gh._digest(
        gh._canonical(rules)
    )
    environment = next(
        value
        for path, value in wire.items()
        if "/environments/" in path and "deployment-branch-policies" not in path
    )
    environment["protection_rules"] = copy.deepcopy(rules)
    for item in wire.values():
        _inject_private_metadata(item)
    if mutation == "wait":
        environment["protection_rules"][0]["wait_timer"] = 1
    elif mutation == "reviewer":
        environment["protection_rules"][1]["reviewers"][0]["reviewer"]["id"] = 99
    elif mutation == "prevent":
        environment["protection_rules"][1]["prevent_self_review"] = False
    elif mutation == "unknown_type":
        environment["protection_rules"].append({"id": 4, "type": "unknown_authority"})
    if mutation is not None:
        with pytest.raises(gh.GitHubReadRefused):
            owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    else:
        facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
        observation = next(
            obs
            for obs in facts.observations
            if obs.endpoint is gh.EndpointCode.ENVIRONMENT
        )
        assert gh._json(observation.body)["protection_rules"] == rules


@pytest.mark.parametrize(
    "rules",
    [
        [{"id": True, "type": "wait_timer", "wait_timer": 0}],
        [{"id": 1, "type": "wait_timer", "wait_timer": True}],
        [
            {
                "id": 1,
                "type": "required_reviewers",
                "prevent_self_review": 1,
                "reviewers": [],
            }
        ],
        [
            {
                "id": 1,
                "type": "required_reviewers",
                "reviewers": [{"type": "User", "reviewer": {"id": True}}],
            }
        ],
        [{"id": 1, "type": "unknown_authority"}],
        [
            {
                "id": 1,
                "type": "branch_policy",
                "url": "https://private.invalid/?token=installed-marker",
            }
        ],
    ],
)
def test_qualified_environment_policy_requires_closed_typed_semantics(rules):
    with pytest.raises(gh.GitHubReadRefused):
        gh._environment_rules(rules, installed=True)


def test_irrelevant_review_metadata_is_not_a_new_required_field(metadata_wire):
    owner, wire, _, _ = metadata_wire
    reviews = next(value for path, value in wire.items() if path.endswith("/approvals"))
    reviews.append(
        {
            "environments": [{"id": 99, "name": "other"}],
            "state": {"malformed_unassigned": "unknown-secret-marker"},
            "user": {"malformed_unassigned": "unknown-secret-marker"},
        }
    )
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert facts.review.reviewer_id == 14
    assert all(b"unknown-secret-marker" not in obs.body for obs in facts.observations)


def test_draft_target_is_projected_only_for_draft_phase(metadata_wire):
    owner, _, bind, _ = metadata_wire
    payload = {
        "id": 22,
        "tag_name": "selected",
        "draft": True,
        "immutable": False,
        "created_at": "2026-10-15T10:00:00Z",
        "published_at": None,
        "target_commitish": "a" * 40,
    }
    _inject_private_metadata(payload)
    bind(gh.EndpointCode.RELEASE, payload, identifier=22)
    owner._installation["phase"] = "draft"
    draft, _, _ = owner._get(gh.EndpointCode.RELEASE, identifier=22)
    assert draft["target_commitish"] == "a" * 40
    owner._installation["phase"] = "published"
    payload["target_commitish"] = {"malformed_unassigned": "unknown-secret-marker"}
    published, _, _ = owner._get(gh.EndpointCode.RELEASE, identifier=22)
    assert "target_commitish" not in published
    assert b"unknown-secret-marker" not in owner._observations[-1].body


def test_wire_error_drops_private_exception_context(metadata_wire, monkeypatch):
    owner, _, _, _ = metadata_wire

    def fail(*args):
        raise ValueError("https://private.invalid/?token=private-query-marker")

    monkeypatch.setattr(gh, "_spawn_get", fail)
    with pytest.raises(gh.GitHubReadRefused) as error:
        owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert str(error.value) == "GITHUB_READ_REFUSED" and error.value.__context__ is None
    assert not owner._issued and not owner._observations


def test_publication_completion_uses_successful_whole_run_and_review(producer):
    owner, responses = producer
    owner._publication, owner._producer = owner._producer, None
    owner._installation["phase"] = "publication_complete"
    owner._policies[17].update(
        publication_title="E read", selected_summary_digest="e" * 64
    )
    facts = owner.publication_complete_snapshot()
    assert owner.owns_facts(facts)
    assert facts.run.stage is gh.ProducerStage.PRODUCER_RUN_COMPLETE
    assert facts.run.conclusion == "success"
    assert facts.selected_summary_digest == "e" * 64
    assert facts.review_response_digest == facts.run.review.observation_sha256
    assert responses[gh.EndpointCode.RUN]["status"] == "completed"


@pytest.mark.parametrize("fault", ["run", "step", "title", "review", "phase"])
def test_publication_completion_refuses_incomplete_or_foreign_evidence(producer, fault):
    owner, responses = producer
    owner._publication, owner._producer = owner._producer, None
    owner._installation["phase"] = "publication_complete"
    owner._policies[17].update(
        publication_title="E read", selected_summary_digest="e" * 64
    )
    if fault == "run":
        for code in (gh.EndpointCode.RUN, gh.EndpointCode.ATTEMPT):
            responses[code].update(status="in_progress", conclusion=None)
    elif fault == "step":
        responses[gh.EndpointCode.JOBS]["jobs"][0]["steps"][-1].update(
            status="completed", conclusion="skipped"
        )
    elif fault == "title":
        owner._policies[17]["publication_title"] = "another digest"
    elif fault == "review":
        responses[gh.EndpointCode.REVIEWS][0]["user"]["id"] = 999
    else:
        owner._installation["phase"] = "publication"
    with pytest.raises(gh.GitHubReadRefused):
        owner.publication_complete_snapshot()
    assert not owner._issued


def test_prepublication_draft_requires_exact_three_assets_without_tag(release_snapshot):
    configure, responses, _, _, calls, _ = release_snapshot
    owner = configure(published=True)
    owner._installation["phase"] = "draft_with_receipt"
    responses[gh.EndpointCode.RELEASE].update(
        draft=True, immutable=False, published_at=None
    )
    facts = owner.draft_with_receipt_snapshot()
    assert type(facts) is gh.DraftReleaseFacts and owner.owns_facts(facts)
    assert facts.draft and len(facts.assets) == 3
    assert facts.assets[-1].name == "gate0-readiness-receipt.json"
    assert all(
        code not in (gh.EndpointCode.TAG_REF, gh.EndpointCode.TAG) for code, _ in calls
    )


@pytest.mark.parametrize("fault", ["missing_receipt", "wrong_phase", "published"])
def test_prepublication_draft_does_not_relax_other_inventories(release_snapshot, fault):
    configure, responses, _, _, _, _ = release_snapshot
    owner = configure(published=fault != "missing_receipt")
    owner._installation["phase"] = "draft_with_receipt"
    if fault != "published":
        responses[gh.EndpointCode.RELEASE].update(
            draft=True, immutable=False, published_at=None
        )
    if fault == "wrong_phase":
        owner._installation["phase"] = "draft"
    with pytest.raises(gh.GitHubReadRefused):
        owner.draft_with_receipt_snapshot()
    assert not owner._issued


def test_selected_job_exposes_only_installed_named_job_with_live_identity(producer):
    owner, responses = producer
    other = copy.deepcopy(responses[gh.EndpointCode.JOBS]["jobs"][0])
    other.update(id=19, name="Other successful job")
    responses[gh.EndpointCode.JOBS]["jobs"].append(other)
    responses[gh.EndpointCode.JOBS]["total_count"] = 2
    owner._policies[17]["mandatory_jobs"].append(other["name"])
    facts = owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    assert len(facts.jobs) == 2
    assert owner.selected_job(facts).id == 18
    assert owner.installed_selection_digest == gh._digest(
        gh._canonical(owner._installation)
    )
    with pytest.raises(gh.GitHubReadRefused):
        owner.selected_job(replace(facts))
    with pytest.raises(gh.GitHubReadRefused):
        owner.producer_snapshot(gh.ProducerStage.PRODUCER_RUN_COMPLETE)
    with pytest.raises(gh.GitHubReadRefused):
        owner.selected_job(facts)
    with pytest.raises(gh.GitHubReadRefused):
        _ = owner.installed_selection_digest


def test_selected_publication_job_is_bound_to_owned_outer_publication_fact(producer):
    owner, _ = producer
    owner._publication, owner._producer = owner._producer, None
    owner._installation["phase"] = "publication_complete"
    owner._policies[17].update(
        publication_title="E read", selected_summary_digest="e" * 64
    )
    facts = owner.publication_complete_snapshot()
    assert owner.selected_job(facts).id == 18
    with pytest.raises(gh.GitHubReadRefused):
        owner.selected_job(facts.run)
    with pytest.raises(gh.GitHubReadRefused):
        owner.selected_job(replace(facts))


def test_private_publication_endpoint_set_has_no_url_or_retry_surface(monkeypatch):
    calls = []

    def core(path, token, binary, maximum, origins, deadline, page, finite=None):
        calls.append((path, token, binary, origins, page, finite))
        return finite[3][0], 0, 0, b"{}"

    monkeypatch.setattr(gh, "_spawn_core", core)
    deadline = time.monotonic() + 10
    create = gh._canonical(
        dict(
            tag_name="gate0-selected",
            target_commitish="a" * 40,
            name="Exact",
            body="Exact body",
            draft=True,
            prerelease=False,
        )
    )
    for operation, identifier, payload in (
        ("create", None, create),
        ("upload_ciphertext", 23, b"cipher"),
        ("upload_projection", 23, b"{}"),
        ("upload_receipt", 23, b"{}"),
        ("publish", 23, b'{"draft":false}'),
        ("tag_absence", "gate0-selected", b""),
        ("release_absence", "gate0-selected", b""),
        ("repository", None, b""),
    ):
        gh._publication_exchange(
            operation, identifier, b"private-token", payload, 1024, (), deadline
        )
    assert [call[5][0] for call in calls[:5]] == [
        "api.github.com",
        "uploads.github.com",
        "uploads.github.com",
        "uploads.github.com",
        "api.github.com",
    ]
    assert [call[5][1] for call in calls[:5]] == [
        "POST",
        "POST",
        "POST",
        "POST",
        "PATCH",
    ]
    assert calls[5][5][3] == calls[6][5][3] == (200, 404)
    assert calls[7][5][3] == (200,)
    assert all(
        call[0].startswith("/repos/dotmac-tech/gate0-issuer-execution")
        for call in calls
    )
    for operation, identifier, payload, page in (
        ("delete", 23, b"", 0),
        ("publish", 23, b'{"draft":false,"name":"other"}', 0),
        ("upload_url", "https://evil.invalid", b"cipher", 0),
        ("upload_ciphertext", True, b"cipher", 0),
        ("tag_absence", "../other", b"", 0),
        ("releases", None, b"", 5),
    ):
        with pytest.raises(gh.GitHubReadRefused):
            gh._publication_exchange(
                operation,
                identifier,
                b"private-token",
                payload,
                1024,
                (),
                deadline,
                page,
            )
    assert len(calls) == 8


def _finite_ipc_child(
    channel, path, token, binary, maximum, origins, deadline, page, finite
):
    """Actual spawned process seam for EOF/wait/reap; no network operation."""
    import os

    try:
        if token == b"timeout":
            time.sleep(10)
        channel.sendall(struct.pack("!IIII", 200, 0, 0, 2) + b"{}")
        if token == b"extra":
            channel.sendall(b"extra")
        channel.shutdown(gh.socket.SHUT_WR)
        if token == b"nonzero":
            os._exit(3)
    finally:
        channel.close()


@pytest.mark.parametrize("mode", [b"valid", b"extra", b"nonzero", b"timeout"])
def test_finite_shared_process_requires_eof_zero_exit_and_original_reap_deadline(
    monkeypatch, mode
):
    monkeypatch.setattr(gh, "_http_child", _finite_ipc_child)
    deadline = time.monotonic() + (2 if mode == b"timeout" else 10)
    if mode == b"valid":
        assert gh._publication_exchange(
            "repository", None, mode, b"", 100, (), deadline
        ) == (200, 0, 0, b"{}")
    else:
        with pytest.raises(gh.GitHubReadRefused):
            gh._publication_exchange("repository", None, mode, b"", 100, (), deadline)
    assert time.monotonic() <= deadline + 0.5


@pytest.mark.parametrize(
    "status,host,method,payload",
    [
        (201, "uploads.github.com", "POST", b"cipher"),
        (200, "api.github.com", "PATCH", b'{"draft":false}'),
        (404, "api.github.com", "GET", b""),
    ],
)
def test_finite_tls_sni_checked_address_and_exact_request_bytes(
    monkeypatch, status, host, method, payload
):
    calls = []
    wire = (
        f"HTTP/1.1 {status} result\r\nContent-Length: 2\r\n"
        "Content-Type: application/json\r\n\r\n{}"
    ).encode()

    class NativeSocket:
        def __init__(self):
            self.wire = io.BytesIO(wire)

        def connect(self, address):
            assert address == ("1.1.1.1", 443)

        def settimeout(self, remaining):
            assert remaining > 0

        def sendall(self, raw):
            calls.append(raw)

        def recv(self, count):
            return self.wire.read(count)

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class NativeTLS:
        def __init__(self, protocol):
            assert protocol == gh.ssl.PROTOCOL_TLS_CLIENT

        def load_verify_locations(self, **kwargs):
            assert kwargs == {"cafile": gh._CA}

        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == host
            assert self.minimum_version == gh.ssl.TLSVersion.TLSv1_2
            return raw

    monkeypatch.setattr(
        gh.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (
                gh.socket.AF_INET,
                gh.socket.SOCK_STREAM,
                gh.socket.IPPROTO_TCP,
                "",
                ("1.1.1.1", 443),
            )
        ],
    )
    monkeypatch.setattr(gh.socket, "socket", lambda *args: NativeSocket())
    monkeypatch.setattr(gh.ssl, "SSLContext", NativeTLS)
    path = (
        "/repos/dotmac-tech/gate0-issuer-execution/releases/23/assets"
        "?name=gate0-evidence.pgp"
    )
    result = gh._https_core(
        host,
        path,
        b"synthetic-token",
        False,
        100,
        time.monotonic() + 10,
        method=method,
        request_body=payload,
        statuses=(status,),
    )
    assert result[0] == status and result[2] == b"{}"
    assert calls[0].startswith((method + " " + path + " HTTP/1.1\r\n").encode())
    assert b"Host: " + host.encode() in calls[0]
    assert b"Authorization: Bearer synthetic-token\r\n" in calls[0]
    assert calls[0].endswith(b"\r\n\r\n" + payload)
    if method != "GET":
        assert b"Content-Length: " + str(len(payload)).encode() + b"\r\n" in calls[0]


def test_finite_mutation_redirect_never_reaches_another_host(monkeypatch):
    calls = []

    def https(*args, **kwargs):
        calls.append((args, kwargs))
        return 302, {"location": "https://evil.invalid/private-token"}, b""

    monkeypatch.setattr(gh, "_https_core", https)
    channel = SimpleNamespace(close=lambda: None)
    gh._http_child(
        channel,
        "/repos/dotmac-tech/gate0-issuer-execution/releases",
        b"synthetic-token",
        False,
        100,
        (),
        time.monotonic() + 10,
        0,
        ("api.github.com", "POST", b"{}", (201,)),
    )
    assert len(calls) == 1
