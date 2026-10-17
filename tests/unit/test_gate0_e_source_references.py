"""Historical reader contract plants; fixtures never qualify an installation."""

from __future__ import annotations

import base64
import copy
import hashlib
import time

import pytest

from vendor_cp.deployment import gate0_e_source_references as reader

_PRIVATE_MARKER = b"HISTORICAL-PRIVATE-ENVELOPE-DOSSIER-MARKER"
_NATIVE_PRIVATE_RETAINED = reader._private_retained


def install_public_metadata(selection, files):
    """Trusted fixture derivation from the full private-qualified selection."""
    coordinates = {
        "schema": "Gate0EHistoricalSourceCoordinates.v1",
        **{
            key: copy.deepcopy(selection[key])
            for key in ("policy_digest", "repositories", "decisions", "packets")
        },
    }
    for decision in coordinates["decisions"].values():
        decision["retained_sha256"] = decision.pop("retained_pin")["sha256"]
    for packet in coordinates["packets"]:
        for source in packet["sources"]:
            source["retained_sha256"] = source.pop("retained_pin")["sha256"]
    private_qual = reader._json(files[reader._QUALIFICATION])
    private_binding = reader._json(files[reader._BINDING])
    native_raw = files[private_binding["native_receipt_pin"]["path"]]
    files[reader._PUBLIC_NATIVE] = native_raw
    native = {"path": reader._PUBLIC_NATIVE, "sha256": reader._digest(native_raw)}
    selected = dict(
        schema="Gate0EPublicHistoricalSourceSelection.v1",
        coordinates=coordinates,
        credential=reader._CREDENTIAL,
    )
    qual = {
        key: copy.deepcopy(private_qual[key])
        for key in (
            "policy_digest",
            "runtime_uid",
            "credential_uid",
            "api_version",
            "repositories",
            "permissions",
        )
    }
    qual.update(
        schema="Gate0EPublicHistoricalSourceQualification.v1",
        selection_sha256=reader._digest(reader._canonical(selected)),
        native_receipt_pin=native,
        decision_provenance_digest=reader._digest(
            files[private_qual["decision_provenance_pin"]["path"]]
        ),
        method_scope=reader._PUBLIC_SCOPE,
    )
    qual_raw = reader._canonical(qual)
    selected["qualification"] = {
        "path": reader._PUBLIC_QUALIFICATION,
        "sha256": reader._digest(qual_raw),
    }
    raw = reader._canonical(selected)
    binding = {
        key: private_binding[key]
        for key in ("reader_source_sha256", "github_mechanics_sha256", "runtime_uid")
    }
    binding.update(
        schema="Gate0EPublicHistoricalSourceBinding.v1",
        installation_sha256=reader._digest(raw),
        qualification_sha256=reader._digest(qual_raw),
        native_receipt_pin=native,
    )
    files.update(
        {
            reader._PUBLIC_INSTALLATION: raw,
            reader._PUBLIC_QUALIFICATION: qual_raw,
            reader._PUBLIC_BINDING: reader._canonical(binding),
        }
    )
    return coordinates


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
                    {
                        "slug": slug,
                        "version": version,
                        "body": "owner record " + _PRIVATE_MARKER.decode(),
                    }
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
        "decision_provenance_pin": pin(
            "dossier", b"qualified owner dossier " + _PRIVATE_MARKER
        ),
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
    monkeypatch.setattr(reader, "_private_retained", lambda path, uid: files[path])

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


@pytest.fixture
def public_installed(installed, monkeypatch):
    selection, files, responses, calls, pagination = installed
    coordinates = install_public_metadata(selection, files)
    protected = reader._protected
    allowed = {
        reader._PUBLIC_INSTALLATION,
        reader._PUBLIC_QUALIFICATION,
        reader._PUBLIC_BINDING,
        reader._PUBLIC_NATIVE,
        reader._CREDENTIAL,
        reader.__file__,
        reader._mechanics.__file__,
    }
    opened = []

    def public_only(path, maximum, *args, **kwargs):
        assert path in allowed, "attempted private historical file read"
        if path == reader._CREDENTIAL:
            assert kwargs.get("private", True) is True and args == (0,)
        else:
            assert kwargs.get("private", True) is False
        opened.append(path)
        return protected(path, maximum, *args, **kwargs)

    monkeypatch.setattr(reader, "_protected", public_only)

    def no_private_leaf(*args, **kwargs):
        pytest.fail("public mode attempted a private retained leaf")

    monkeypatch.setattr(reader, "_private_retained", no_private_leaf)
    return coordinates, files, responses, calls, pagination, opened


def test_public_real_loader_fresh_checks_owned_facts_no_private_reads(public_installed):
    coordinates, _, responses, calls, _, opened = public_installed
    for value in responses.values():
        value["unknown_private_body"] = _PRIVATE_MARKER.decode()
    owner = reader.InstalledHistoricalSourceReads.from_installed_public()
    facts = owner.verify_public(deadline=time.monotonic() + 180)
    assert type(facts) is reader.PublicHistoricalSourceFacts and owner.owns_facts(facts)
    assert facts.coordinates_bytes == reader._canonical(coordinates)
    assert facts.coordinates_sha256 == reader._digest(facts.coordinates_bytes)
    assert not hasattr(facts, "decision_records") and not hasattr(
        facts, "reference_bytes"
    )
    assert not hasattr(facts, "observations") and not owner._retained
    assert _PRIVATE_MARKER not in facts.coordinates_bytes
    for path, value in owner._cache.items():
        if "/contents/" in path:
            assert "content" not in value[0] and "computed_sha256" in value[0]
        assert _PRIVATE_MARKER not in reader._canonical(value)
    assert all(_PRIVATE_MARKER not in raw for _, raw in owner._responses)
    assert calls and opened and len(calls) == len(set(calls))
    other = reader.InstalledHistoricalSourceReads.from_installed_public()
    assert not other.owns_facts(facts) and not owner.owns_facts(copy.copy(facts))
    with pytest.raises(reader.HistoricalReferencesRefused):
        owner.verify_public(deadline=time.monotonic() + 10)
    assert not owner.owns_facts(facts)


def test_public_coordinates_match_private_normalization_and_preserve_private_mode(
    installed,
):
    from vendor_cp.deployment import gate0_e_writer as writer

    owner, private = verify()
    assert owner.owns_facts(private) and private.decision_records
    assert any(
        _PRIVATE_MARKER in base64.b64decode(item["bytes_base64"])
        for item in reader._json(private.reference_bytes)["retained"]
    )
    coordinates = install_public_metadata(installed[0], installed[1])
    assert reader._canonical(
        {key: value for key, value in coordinates.items() if key != "schema"}
    ) == writer._source_coordinates(private.reference_bytes)
    public = reader.InstalledHistoricalSourceReads.from_installed_public()
    public_facts = public.verify_public(deadline=time.monotonic() + 180)
    assert private.reference_sha256 != public_facts.coordinates_sha256
    assert _PRIVATE_MARKER not in public_facts.coordinates_bytes
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.InstalledHistoricalSourceReads.from_installed().verify_public(
            deadline=time.monotonic() + 30
        )
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.InstalledHistoricalSourceReads.from_installed_public().verify(
            deadline=time.monotonic() + 30
        )


@pytest.mark.parametrize(
    "change",
    [
        "private_selection",
        "full_wrapper",
        "body",
        "retained_pin",
        "observations",
        "private_qualification",
        "private_native",
        "native_scope",
        "binding",
        "source",
        "decision_digest",
    ],
)
def test_public_historical_closed_mode_refuses_private_and_unqualified_inputs(
    public_installed, change
):
    _, files, _, calls, _, opened = public_installed
    selected = reader._json(files[reader._PUBLIC_INSTALLATION])
    if change == "private_selection":
        selected = reader._json(files[reader._INSTALLATION])
    elif change == "full_wrapper":
        selected["coordinates"] = {
            "schema": "Gate0EHistoricalSourceReferences.v1",
            "selection": {},
            "qualification": {},
            "retained": [],
            "observations": [],
        }
    elif change in ("body", "retained_pin", "observations"):
        selected["coordinates"]["decisions"]["rulings"][change] = (
            _PRIVATE_MARKER.decode()
        )
    elif change == "private_qualification":
        selected["qualification"]["path"] = reader._QUALIFICATION
    elif change == "private_native":
        binding = reader._json(files[reader._PUBLIC_BINDING])
        binding["native_receipt_pin"]["path"] = reader._RETAINED + "dossier"
        files[reader._PUBLIC_BINDING] = reader._canonical(binding)
    elif change == "native_scope":
        qual = reader._json(files[reader._PUBLIC_QUALIFICATION])
        qual["method_scope"] = "full-private-historical"
        files[reader._PUBLIC_QUALIFICATION] = reader._canonical(qual)
    elif change == "binding":
        files[reader._PUBLIC_BINDING] += b" "
    elif change == "source":
        files[reader.__file__] += b"changed owner"
    else:
        selected["coordinates"]["decisions"]["rulings"]["retained_sha256"] = "e" * 64
    files[reader._PUBLIC_INSTALLATION] = reader._canonical(selected)
    with pytest.raises(reader.HistoricalReferencesRefused) as error:
        reader.InstalledHistoricalSourceReads.from_installed_public()
    assert not calls and opened
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert _PRIVATE_MARKER not in repr(error.value).encode()


@pytest.mark.parametrize(
    "change",
    [
        "body",
        "blob",
        "size",
        "truncated",
        "repository",
        "head",
        "merge",
        "attempt",
        "workflow",
        "event",
        "missing_job",
        "failed_job",
        "pagination_gap",
    ],
)
def test_public_historical_uses_actual_source_pr_run_job_and_pagination_checks(
    public_installed, change
):
    _, _, responses, _, pagination, _ = public_installed
    root = "/repos/michaelayoade/dotmac_platform_control_plane"
    source = responses[root + "/contents/src/contract.py?ref=" + "a" * 40]
    pr = responses[root + "/pulls/200"]
    run_path = root + "/actions/runs/20/attempts/2"
    run = responses[run_path]
    jobs = responses[run_path + "/jobs?per_page=100&page=1"]
    if change == "body":
        source["content"] = base64.b64encode(_PRIVATE_MARKER).decode()
    elif change == "blob":
        source["sha"] = "c" * 40
    elif change == "size":
        source["size"] += 1
    elif change == "truncated":
        source["truncated"] = True
    elif change == "repository":
        responses[root]["id"] = 999
    elif change == "head":
        pr["head"]["sha"] = "c" * 40
    elif change == "merge":
        pr["merge_commit_sha"] = "c" * 40
    elif change in ("attempt", "workflow", "event"):
        run[
            {"attempt": "run_attempt", "workflow": "workflow_id", "event": "event"}[
                change
            ]
        ] = "foreign" if change == "event" else 999
    elif change == "missing_job":
        jobs["jobs"] = []
        jobs["total_count"] = 0
    elif change == "failed_job":
        jobs["jobs"][0]["conclusion"] = "failure"
    else:
        pagination[run_path + "/jobs?per_page=100&page=1"] = (3, 3)
    owner = reader.InstalledHistoricalSourceReads.from_installed_public()
    with pytest.raises(reader.HistoricalReferencesRefused) as error:
        owner.verify_public(deadline=time.monotonic() + 180)
    assert (
        owner._failed
        and not owner._cache
        and not owner._responses
        and not owner._issued
    )
    assert error.value.__cause__ is None and error.value.__context__ is None
    for trace in (error.value.__traceback__,):
        while trace is not None:
            if trace.tb_frame.f_code.co_filename == reader.__file__:
                assert _PRIVATE_MARKER not in repr(trace.tb_frame.f_locals).encode()
            trace = trace.tb_next


def _repin_private_metadata(selection, files):
    qual = reader._json(files[reader._QUALIFICATION])
    qual["selection_sha256"] = reader._digest(
        reader._canonical({k: v for k, v in selection.items() if k != "qualification"})
    )
    qual_raw = reader._canonical(qual)
    selection["qualification"]["sha256"] = reader._digest(qual_raw)
    raw = reader._canonical(selection)
    binding = reader._json(files[reader._BINDING])
    binding["installation_sha256"] = reader._digest(raw)
    binding["qualification_sha256"] = reader._digest(qual_raw)
    files.update(
        {
            reader._INSTALLATION: raw,
            reader._QUALIFICATION: qual_raw,
            reader._BINDING: reader._canonical(binding),
        }
    )


def _private_filesystem(monkeypatch, files, uid, *, fault=None):
    """Real private walker through synthetic native calls; never OS UID proof."""
    import os
    import stat
    from types import SimpleNamespace

    descriptors, offsets, calls = {}, {}, []
    target = reader._RETAINED + "dossier"

    def opened(name, flags, *, dir_fd=None):
        path = name if dir_fd is None else descriptors[dir_fd].rstrip("/") + "/" + name
        if path != "/":
            assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        if path == target and fault == "symlink":
            raise OSError("synthetic no-follow refusal")
        if path in files:
            assert not flags & os.O_DIRECTORY
            calls.append(path)
        else:
            assert flags & os.O_DIRECTORY
        descriptor = len(offsets) + 100
        descriptors[descriptor], offsets[descriptor] = path, 0
        return descriptor

    def data(path):
        raw = files[path]
        return raw + b"changed" if path == target and fault == "digest" else raw

    def inspected(descriptor):
        path = descriptors[descriptor]
        leaf = path in files
        mode = stat.S_IFREG | 0o600 if leaf else stat.S_IFDIR | 0o755
        owner = uid if leaf else 0
        size = len(data(path)) if leaf else 0
        if path == target:
            if fault == "owner":
                owner = uid + 1
            elif fault in ("world_read", "read_only", "executable"):
                mode = (
                    stat.S_IFREG
                    | {
                        "world_read": 0o644,
                        "read_only": 0o400,
                        "executable": 0o700,
                    }[fault]
                )
            elif fault == "type":
                mode = stat.S_IFIFO | 0o600
            elif fault == "empty":
                size = 0
            elif fault == "oversize":
                size = reader._CAP + 1
        if path == "/etc":
            if fault == "ancestor_owner":
                owner = uid + 1
            elif fault == "ancestor_write":
                mode = stat.S_IFDIR | 0o777
        return SimpleNamespace(st_uid=owner, st_mode=mode, st_size=size)

    def read(descriptor, maximum):
        path, start = descriptors[descriptor], offsets[descriptor]
        offsets[descriptor] += maximum
        return data(path)[start : start + maximum]

    monkeypatch.setattr(reader.os, "open", opened)
    monkeypatch.setattr(reader.os, "fstat", inspected)
    monkeypatch.setattr(reader.os, "read", read)
    monkeypatch.setattr(reader.os, "close", lambda fd: descriptors.pop(fd))
    private_calls = []

    def private(path, runtime_uid):
        private_calls.append((path, runtime_uid))
        return _NATIVE_PRIVATE_RETAINED(path, runtime_uid)

    monkeypatch.setattr(reader, "_private_retained", private)
    return calls, private_calls, descriptors


@pytest.mark.parametrize("runtime_uid", [0, 123])
def test_full_private_loader_derives_exact_leaf_owner_from_qualified_runtime(
    installed, monkeypatch, runtime_uid
):
    selection, files, _, _, _ = installed
    qual = reader._json(files[reader._QUALIFICATION])
    qual["runtime_uid"] = runtime_uid
    assert qual["credential_uid"] == 0  # Separate purpose, even for nonroot actor.
    files[reader._QUALIFICATION] = reader._canonical(qual)
    binding = reader._json(files[reader._BINDING])
    binding["runtime_uid"] = runtime_uid
    files[reader._BINDING] = reader._canonical(binding)
    _repin_private_metadata(selection, files)
    monkeypatch.setattr(reader.os, "getuid", lambda: runtime_uid)
    monkeypatch.setattr(reader.os, "geteuid", lambda: runtime_uid)
    metadata = reader._protected
    metadata_calls = []

    def public_metadata(path, maximum, *args, **kwargs):
        metadata_calls.append(path)
        if path == reader._CREDENTIAL:
            assert args == (0,) and kwargs.get("private", True) is True
        else:
            assert kwargs.get("private", True) is False
        return metadata(path, maximum, *args, **kwargs)

    monkeypatch.setattr(reader, "_protected", public_metadata)
    opened, private_calls, descriptors = _private_filesystem(
        monkeypatch, files, runtime_uid
    )
    owner = reader.InstalledHistoricalSourceReads.from_installed()
    facts = owner.verify(deadline=time.monotonic() + 180)
    assert owner.owns_facts(facts) and facts.decision_records
    assert _PRIVATE_MARKER in owner._retained[reader._RETAINED + "dossier"]
    assert private_calls and {uid for _, uid in private_calls} == {runtime_uid}
    assert set(opened) == {path for path, _ in private_calls}
    assert not descriptors
    assert {
        reader._INSTALLATION,
        reader._BINDING,
        reader._QUALIFICATION,
        reader._RETAINED + "native",
    } <= set(metadata_calls)
    assert reader._RETAINED + "dossier" not in metadata_calls


@pytest.mark.parametrize(
    "fault",
    [
        "owner",
        "world_read",
        "read_only",
        "executable",
        "type",
        "empty",
        "oversize",
        "ancestor_owner",
        "ancestor_write",
        "symlink",
        "digest",
    ],
)
def test_full_private_loader_rejects_wrong_leaf_or_ancestry(
    installed, monkeypatch, fault
):
    _, files, _, calls, _ = installed
    _, private_calls, descriptors = _private_filesystem(
        monkeypatch, files, 123, fault=fault
    )
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.InstalledHistoricalSourceReads.from_installed()
    assert private_calls and not descriptors and not calls


@pytest.mark.parametrize(
    "change", ["qualified_uid", "actual_uid", "opaque_field", "native_alias"]
)
def test_private_owner_authority_refuses_before_opaque_read(
    installed, monkeypatch, change
):
    selection, files, _, calls, _ = installed
    qual = reader._json(files[reader._QUALIFICATION])
    if change == "qualified_uid":
        qual["runtime_uid"] = 124
    elif change == "actual_uid":
        monkeypatch.setattr(reader.os, "geteuid", lambda: 124)
    elif change == "opaque_field":
        qual["body"] = _PRIVATE_MARKER.decode()
    else:
        qual["decision_provenance_pin"] = copy.deepcopy(qual["native_receipt_pin"])
    files[reader._QUALIFICATION] = reader._canonical(qual)
    _repin_private_metadata(selection, files)
    private_calls = []
    monkeypatch.setattr(
        reader, "_private_retained", lambda *args: private_calls.append(args)
    )
    with pytest.raises(reader.HistoricalReferencesRefused):
        reader.InstalledHistoricalSourceReads.from_installed()
    assert not private_calls and not calls
