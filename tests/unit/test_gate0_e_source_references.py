"""Historical reader contract plants; fixtures never qualify an installation."""

from __future__ import annotations

import base64
import copy
import hashlib
import time

import pytest

from vendor_cp.deployment import gate0_e_source_references as reader


@pytest.fixture
def installed(monkeypatch):
    body = b"historical owner source\n"
    sha = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()  # noqa: S324 -- Git identity
    retained = {}
    files = {}

    def pin(name, raw):
        path = reader._RETAINED + name
        retained[path] = raw
        return {"path": path, "sha256": reader._digest(raw)}

    source = {
        "revision": "a" * 40,
        "path": "src/contract.py",
        "blob_sha": sha,
        "sha256": reader._digest(body),
        "retained_pin": pin("source", body),
    }
    repos = {
        key: {
            "owner": "michaelayoade",
            "name": name,
            "repository_id": index,
            "owner_id": 8,
        }
        for index, (key, name) in enumerate(reader._REPOSITORIES.items(), 10)
    }
    decisions = {}
    for key, pr in (("a7", 197), ("a6", 199)):
        decisions[key] = dict(source, repository="cp", pr=pr, path=reader._ADR)
    for key, (slug, version) in reader._DECISIONS.items():
        decisions[key] = {
            "system": "dotmac_knowledge",
            "slug": slug,
            "version": version,
            "retained_pin": pin(
                key,
                reader._canonical(
                    {"slug": slug, "version": version, "body": "owner record"}
                ),
            ),
        }
    packets = []
    for index, (key, repository, pr) in enumerate(
        (
            ("b", "cp", 200),
            ("c1_foundation", "starter", 753),
            ("c1_cp", "cp", 201),
            ("c1_dependencies", "cp", 204),
        ),
        20,
    ):
        packets.append(
            {
                "id": key,
                "repository": repository,
                "pr": pr,
                "merge_sha": "a" * 40,
                "pr_head_sha": "b" * 40,
                "sources": [copy.deepcopy(source)],
                "runs": [
                    {
                        "run_id": index,
                        "attempt": 2,
                        "workflow_id": 5,
                        "workflow_path": ".github/workflows/ci.yml",
                        "event": "pull_request",
                        "tested_sha": "b" * 40,
                        "required_jobs": [{"id": index * 10, "name": "source checks"}],
                    }
                ],
            }
        )
    selection = {
        "schema": "Gate0EHistoricalSourceSelection.v1",
        "policy_digest": "d" * 64,
        "repositories": repos,
        "decisions": decisions,
        "packets": packets,
        "credential": reader._CREDENTIAL,
    }
    receipt = pin(
        "native",
        reader._canonical(
            {
                "schema": "Gate0ENativeReviewReceipt.v1",
                "qualification_measurements_digest": "1" * 64,
                "runtime_identity_digest": "2" * 64,
                "reviewer_record_digest": "3" * 64,
            }
        ),
    )
    qual = {
        "schema": "Gate0EHistoricalSourceQualification.v1",
        "selection_sha256": reader._digest(reader._canonical(selection)),
        "policy_digest": selection["policy_digest"],
        "runtime_uid": 123,
        "credential_uid": 0,
        "api_version": reader._API_VERSION,
        "repositories": copy.deepcopy(repos),
        "permissions": {
            "metadata": "read",
            "actions": "read",
            "contents": "read",
            "pull_requests": "read",
        },
        "native_receipt_pin": receipt,
        "decision_provenance_pin": pin("dossier", b"qualified owner dossier"),
    }
    qual_raw = reader._canonical(qual)
    selection["qualification"] = {
        "path": reader._QUALIFICATION,
        "sha256": reader._digest(qual_raw),
    }
    raw = reader._canonical(selection)
    binding = {
        "schema": "Gate0EHistoricalSourceBinding.v1",
        "installation_sha256": reader._digest(raw),
        "qualification_sha256": reader._digest(qual_raw),
        "reader_source_sha256": reader._digest(b"reader source"),
        "github_mechanics_sha256": reader._digest(b"mechanics source"),
        "native_receipt_pin": receipt,
        "runtime_uid": 123,
    }
    files.update(retained)
    files.update(
        {
            reader._INSTALLATION: raw,
            reader._QUALIFICATION: qual_raw,
            reader._BINDING: reader._canonical(binding),
            reader._CREDENTIAL: b"test-only-token",
            reader.__file__: b"reader source",
            reader._mechanics.__file__: b"mechanics source",
        }
    )
    monkeypatch.setattr(reader.os, "getuid", lambda: 123)
    monkeypatch.setattr(reader.os, "geteuid", lambda: 123)
    monkeypatch.setattr(
        reader, "_protected", lambda path, maximum, *args, **kwargs: files[path]
    )

    def identity(repo):
        return {
            "id": repo["repository_id"],
            "owner": {"id": repo["owner_id"]},
            "full_name": repo["owner"] + "/" + repo["name"],
        }

    responses = {}
    for key, repo in repos.items():
        root = "/repos/" + repo["owner"] + "/" + repo["name"]
        responses[root] = identity(repo)
        for entry in ([decisions["a7"], decisions["a6"]] if key == "cp" else []) + [
            p for p in packets if p["repository"] == key
        ]:
            responses[root + "/pulls/" + str(entry["pr"])] = {
                "number": entry["pr"],
                "merged": True,
                "merged_at": "2026-09-25T10:00:00Z",
                "merge_commit_sha": "a" * 40,
                "base": {"repo": identity(repo)},
                "head": {"sha": "b" * 40, "repo": identity(repo)},
            }
            for src in entry.get("sources", [entry]):
                responses[
                    root + "/contents/" + src["path"] + "?ref=" + src["revision"]
                ] = {
                    "type": "file",
                    "path": src["path"],
                    "sha": sha,
                    "encoding": "base64",
                    "content": base64.b64encode(body).decode(),
                    "size": len(body),
                }
            for run in entry.get("runs", []):
                path = root + "/actions/runs/" + str(run["run_id"]) + "/attempts/2"
                responses[path] = {
                    "id": run["run_id"],
                    "run_attempt": 2,
                    "workflow_id": 5,
                    "event": run["event"],
                    "path": run["workflow_path"],
                    "head_sha": "b" * 40,
                    "repository": identity(repo),
                    "head_repository": identity(repo),
                    "status": "completed",
                    "conclusion": "success",
                }
                responses[path + "/jobs?per_page=100&page=1"] = {
                    "total_count": 1,
                    "jobs": [
                        {
                            "id": run["run_id"] * 10,
                            "name": "source checks",
                            "run_id": run["run_id"],
                            "status": "completed",
                            "conclusion": "success",
                        }
                    ],
                }
    calls = []
    pagination = {}

    def get(path, token, binary, maximum, origins, deadline, page):
        assert token == b"test-only-token" and binary is False and origins == ()
        assert maximum == reader._CAP and deadline <= time.monotonic() + 180
        calls.append(path)
        following, last = pagination.get(path, (0, 0))
        return 200, following, last, reader._canonical(responses[path])

    monkeypatch.setattr(reader, "_spawn_get", get)
    return selection, files, responses, calls, pagination


def verify():
    result = reader.InstalledHistoricalSourceReads.from_installed()
    return result, result.verify(deadline=time.monotonic() + 300)


def test_valid_head_merge_and_optional_job_attempt(installed):
    owner, facts = verify()
    assert owner.owns_facts(facts)
    assert facts.result == "historical_source_references_verified"
    assert facts.reference_sha256 == reader._digest(facts.reference_bytes)
    assert not hasattr(facts, "accepted") and not hasattr(facts, "readiness")
    assert len(installed[3]) == len(set(installed[3]))
    assert b"test-only-token" not in facts.reference_bytes
    other = reader.InstalledHistoricalSourceReads.from_installed()
    assert not other.owns_facts(facts)
    with pytest.raises(
        reader.HistoricalReferencesRefused, match="^HISTORICAL_REFERENCES_REFUSED$"
    ):
        owner.verify(deadline=time.monotonic() + 20)
    assert not owner.owns_facts(facts)


@pytest.mark.parametrize(
    "kind",
    [
        "repository",
        "pr",
        "head",
        "merge",
        "blob",
        "bytes",
        "attempt",
        "workflow",
        "tested",
        "skipped",
        "missing",
        "duplicate",
        "job_attempt",
    ],
)
def test_authenticated_join_refusals(installed, kind):
    responses = installed[2]
    root = "/repos/michaelayoade/dotmac_platform_control_plane"
    run = responses[root + "/actions/runs/20/attempts/2"]
    jobs = responses[root + "/actions/runs/20/attempts/2/jobs?per_page=100&page=1"]
    pr = responses[root + "/pulls/200"]
    source = responses[root + "/contents/src/contract.py?ref=" + "a" * 40]
    if kind == "repository":
        responses[root]["id"] = 999
    elif kind == "pr":
        pr["number"] = 999
    elif kind == "head":
        pr["head"]["sha"] = "c" * 40
    elif kind == "merge":
        pr["merge_commit_sha"] = "c" * 40
    elif kind == "blob":
        source["sha"] = "c" * 40
    elif kind == "bytes":
        source["content"] = base64.b64encode(b"wrong").decode()
    elif kind in ("attempt", "workflow", "tested"):
        run[
            {"attempt": "run_attempt", "workflow": "workflow_id", "tested": "head_sha"}[
                kind
            ]
        ] = "c" * 40 if kind == "tested" else 999
    elif kind == "skipped":
        jobs["jobs"][0]["conclusion"] = "skipped"
    elif kind == "missing":
        jobs.update(total_count=0, jobs=[])
    elif kind == "duplicate":
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0]))
        jobs["total_count"] = 2
    else:
        jobs["jobs"][0]["run_attempt"] = 1
    with pytest.raises(reader.HistoricalReferencesRefused):
        verify()


def test_complete_pagination_and_unrelated_skipped_job(installed):
    path = (
        "/repos/michaelayoade/dotmac_platform_control_plane/"
        "actions/runs/20/attempts/2/jobs?per_page=100&page="
    )
    responses, pagination = installed[2], installed[4]
    responses[path + "1"]["total_count"] = 2
    responses[path + "2"] = {
        "total_count": 2,
        "jobs": [
            {
                "id": 999,
                "run_id": 20,
                "name": "unrelated",
                "status": "completed",
                "conclusion": "skipped",
            }
        ],
    }
    pagination[path + "1"] = (2, 2)
    pagination[path + "2"] = (0, 2)
    verify()
    responses[path + "2"]["total_count"] = 3
    with pytest.raises(reader.HistoricalReferencesRefused):
        verify()


@pytest.mark.parametrize(
    "kind",
    [
        "version",
        "digest",
        "permissions",
        "source",
        "qualification_path",
        "retained_path",
    ],
)
def test_missing_or_changed_qualification_refuses_before_transport(installed, kind):
    selection, files, _, calls, _ = installed

    def rebind():
        qual = reader._json(files[reader._QUALIFICATION])
        qual["selection_sha256"] = reader._digest(
            reader._canonical(
                {k: v for k, v in selection.items() if k != "qualification"}
            )
        )
        files[reader._QUALIFICATION] = reader._canonical(qual)
        selection["qualification"]["sha256"] = reader._digest(
            files[reader._QUALIFICATION]
        )
        files[reader._INSTALLATION] = reader._canonical(selection)
        binding = reader._json(files[reader._BINDING])
        binding["installation_sha256"] = reader._digest(files[reader._INSTALLATION])
        binding["qualification_sha256"] = reader._digest(files[reader._QUALIFICATION])
        files[reader._BINDING] = reader._canonical(binding)

    if kind == "version":
        pin = selection["decisions"]["rulings"]["retained_pin"]
        files[pin["path"]] = reader._canonical(
            {"slug": reader._DECISIONS["rulings"][0], "version": 121}
        )
        pin["sha256"] = reader._digest(files[pin["path"]])
        rebind()
    elif kind == "digest":
        files[reader._INSTALLATION] += b" "
    elif kind == "source":
        files[reader.__file__] = b"changed source"
    elif kind == "permissions":
        qual = reader._json(files[reader._QUALIFICATION])
        qual["permissions"].pop("pull_requests")
        files[reader._QUALIFICATION] = reader._canonical(qual)
        rebind()
    else:
        if kind == "qualification_path":
            selection["qualification"]["path"] = "/unqualified/qualification"
        else:
            selection["decisions"]["a7"]["retained_pin"]["path"] = (
                reader._RETAINED + "../escape"
            )
        rebind()
    with pytest.raises(reader.HistoricalReferencesRefused):
        verify()
    assert not calls


@pytest.mark.parametrize(
    "path",
    [
        "../src/a",
        "src/../a",
        "src//a",
        "https://evil/a",
        "src/a?ref=b",
        "src/%2e",
        "src/a\\b",
        "/src/a",
        "deploy/a",
    ],
)
def test_fixed_path_profile(path):
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader._path(path)


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), -1, True])
def test_deadline_refuses_and_invalidates(installed, deadline):
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    with pytest.raises(reader.HistoricalReferencesRefused):
        owner.verify(deadline=deadline)
    assert not installed[3] and not owner.owns_facts(object())


def test_constructor_seals(installed):
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.InstalledHistoricalSourceReads(object(), {}, {}, b"", b"", {})
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.HistoricalSourceFacts(object(), b"", "", "", "", (), ())


def test_response_cap_and_failure_clears_observations(installed, monkeypatch):
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    monkeypatch.setattr(
        reader, "_spawn_get", lambda *args: (200, 0, 0, b"x" * (reader._CAP + 1))
    )
    with pytest.raises(reader.HistoricalReferencesRefused):
        owner.verify(deadline=time.monotonic() + 30)
    assert owner._responses == [] and owner._issued == []


def test_valid_present_attempt_and_unassigned_fields_discarded(installed):
    for path, value in installed[2].items():
        value["owner_api_extra_field"] = {"nested": "discard unknown"}
        if "/jobs?" in path:
            for job in value["jobs"]:
                job["run_attempt"] = 2
    _, facts = verify()
    assert all(b"owner_api_extra_field" not in raw for raw in facts.observations)
    reference = reader._json(facts.reference_bytes)
    assert all(
        "next_page" in row and "last_page" in row for row in reference["observations"]
    )


def test_http_aggregate_overflow_refuses_without_facts(installed, monkeypatch):
    original = reader._spawn_get

    def padded_response(*args):
        status, following, last, raw = original(*args)
        # HTTP accounting bounds the original bytes even though whitespace and
        # unassigned API fields are discarded from retained projections.
        return status, following, last, raw + b" " * (reader._CAP - len(raw))

    monkeypatch.setattr(reader, "_spawn_get", padded_response)
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    with pytest.raises(reader.HistoricalReferencesRefused):
        owner.verify(deadline=time.monotonic() + 180)
    assert not owner._issued and not owner._responses


def test_timeout_has_no_retry_or_partial_facts(installed, monkeypatch):
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    calls = []

    def timeout(*args):
        calls.append(args[0])
        raise TimeoutError("private transport details")

    monkeypatch.setattr(reader, "_spawn_get", timeout)
    with pytest.raises(
        reader.HistoricalReferencesRefused, match="^HISTORICAL_REFERENCES_REFUSED$"
    ):
        owner.verify(deadline=time.monotonic() + 30)
    assert len(calls) == 1 and not owner._issued and not owner._responses


@pytest.mark.parametrize("tamper", [False, True])
def test_private_api_urls_and_nested_unknown_fields_never_escape(installed, tamper):
    _, baseline = verify()
    private = "https://private.invalid/source?token=confidential-api-marker"
    marker = "unknown-secret-marker"

    def inject(item):
        if isinstance(item, dict):
            for child in list(item.values()):
                inject(child)
            item["download_url"] = private
            item["url"] = private
            item["unknown_secret_field"] = {"nested": [{"credential": marker}]}
        elif isinstance(item, list):
            for child in item:
                inject(child)

    for value in installed[2].values():
        inject(value)
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    if tamper:
        root = "/repos/michaelayoade/dotmac_platform_control_plane"
        installed[2][root + "/contents/src/contract.py?ref=" + "a" * 40]["sha"] = (
            "c" * 40
        )
        with pytest.raises(reader.HistoricalReferencesRefused) as error:
            owner.verify(deadline=time.monotonic() + 30)
        assert str(error.value) == "HISTORICAL_REFERENCES_REFUSED"
        assert error.value.__context__ is None
        assert marker not in repr(error.value) and private not in repr(error.value)
        assert owner._cache == {} and owner._responses == [] and owner._issued == []
    else:
        facts = owner.verify(deadline=time.monotonic() + 30)
        # Unassigned fields do not even affect a retained digest: the safe
        # projection and complete reference serialization remain byte-identical.
        assert facts.reference_bytes == baseline.reference_bytes
        assert facts.observations == baseline.observations
        for raw in facts.observations:
            assert marker.encode() not in raw and private.encode() not in raw
            assert b"download_url" not in raw and b"unknown_secret_field" not in raw
        assert marker not in repr(owner._cache) and private not in repr(owner._cache)
        reference = reader._json(facts.reference_bytes)
        for observation in reference["observations"]:
            raw = base64.b64decode(observation["projection_bytes_base64"])
            assert reader._digest(raw) == observation["projection_sha256"]
            assert marker.encode() not in raw and private.encode() not in raw
        assert b"historical owner source" in next(
            raw for _, raw, _ in facts.decision_records if raw.startswith(b"historical")
        )
