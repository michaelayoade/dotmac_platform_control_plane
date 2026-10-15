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
