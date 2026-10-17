"""Hosted-only installed/HTTP-boundary tests; no live qualification or adoption.

Fixtures use the real protected installation loaders and actual read phases.
Only protected-file and finite HTTP native boundaries provide synthetic bytes.
No owns_facts replacement, owner seal, private field mutation or acceptance flag.
"""

from __future__ import annotations

import base64
import copy
import io
import os
import stat
import sys
import time
import zipfile
from asyncio import CancelledError
from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import FrameType, SimpleNamespace

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_e_github import producer as github_producer  # noqa: F401
from test_gate0_e_preparation import inputs  # noqa: F401
from test_gate0_e_source_references import (
    installed as historical_installed,  # noqa: F401
)
from test_gate0_e_writer import (
    a9_export,  # noqa: F401
    receipt_composition,  # noqa: F401
)
from test_gate0_e_writer import (
    installed_composition as writer_composition,  # noqa: F401
)
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_github as gh
from vendor_cp.deployment import gate0_e_publication as publication
from vendor_cp.deployment import gate0_e_writer as writer


@pytest.fixture
def installed_composition(writer_composition):  # noqa: F811
    """Requalify fixture *files* for the fixed repo before creating new readers."""
    c = writer_composition
    native_reader = c.reader

    def reader(phase, **kwargs):
        native_reader(phase, **kwargs)
        doc = gh._json(c.gh_files[gh._INSTALLATION])
        doc["repository"].update(owner="dotmac-tech", name="gate0-issuer-execution")
        for name in ("producer", "publication"):
            if doc[name] is not None:
                doc[name]["repository"] = doc["repository"]
        raw = gh._canonical(doc)
        c.gh_files[gh._INSTALLATION] = raw
        binding = gh._json(c.gh_files[gh._ROOT_BINDING])
        binding["installation_sha256"] = gh._digest(raw)
        c.gh_files[gh._ROOT_BINDING] = gh._canonical(binding)
        source = "/repos/dotmac/selected"
        target = "/repos/" + publication._REPOSITORY
        for (path, binary), value in list(c.wire.items()):
            if path != source and not path.startswith(source + "/"):
                continue
            del c.wire[(path, binary)]
            value = copy.deepcopy(value)
            if isinstance(value, dict) and value.get("full_name") == "dotmac/selected":
                value["full_name"] = publication._REPOSITORY
            c.wire[(target + path[len(source) :], binary)] = value
        result = gh.InstalledGate0GitHubReads.from_installed()
        c.reader_digests[phase] = result.installed_selection_digest
        if phase == "producer":
            c.gh_files[gh._PRODUCER_COMPLETION_INSTALLATION] = c.gh_files[
                gh._INSTALLATION
            ]
            c.gh_files[gh._PRODUCER_COMPLETION_ROOT_BINDING] = c.gh_files[
                gh._ROOT_BINDING
            ]
        return result

    c.reader = reader
    return c


def test_fixture_repository_rebinding_keeps_fresh_producer_phase(installed_composition):
    c = installed_composition
    collection_reads = c.reader("producer", snapshot_stage="collection")
    collection = collection_reads.producer_snapshot(
        gh.ProducerStage.COLLECTION_SNAPSHOT
    )
    assert collection_reads.owns_facts(collection)
    assert collection.status == "in_progress"

    completed_reads = c.reader("producer")
    completed = completed_reads.producer_snapshot(
        gh.ProducerStage.PRODUCER_JOB_COMPLETE
    )
    assert completed_reads.owns_facts(completed)
    assert completed.status == "completed"
    assert completed_reads.selected_job(completed).status == "completed"
    assert collection.status == "in_progress"


class NativeReleaseBoundary:
    """Exact finite native HTTP response seam, preserving server-side effects."""

    def __init__(self, c):
        self.c = c
        self.calls = []
        self.release = None
        self.assets = {}
        self.bytes = {}
        self.uncertain = None
        self.partial = False
        self.conflict = False
        self.foreign_tag = False
        self.wrong_repo = False
        self.wrong_bytes = False
        self.reply_kind = "lost"
        self.next_id = 100

    def exchange(
        self, operation, identifier, token, payload, maximum, origins, deadline, page=0
    ):
        assert token == b"SOURCE-UNIT-WRITE-TOKEN"
        assert time.monotonic() < deadline and maximum <= gh._CIPHER_CAP
        self.calls.append((operation, identifier, payload, deadline))
        value = None
        status = 200
        if operation == "repository":
            value = dict(
                id=self.c.producer.repository_id + int(self.wrong_repo),
                owner={"id": self.c.producer.owner_id},
                full_name=publication._REPOSITORY,
            )
        elif operation in ("tag_absence", "release_absence"):
            status = 200 if self.foreign_tag else 404
            value = {"message": "URL/TOKEN-FIELD-MUST-NOT-BE-RETAINED"}
        elif operation == "releases":
            value = [] if self.release is None else [self.release]
            if self.conflict and self.release is not None:
                value = [self.release, {**self.release, "id": self.release["id"] + 1}]
        elif operation == "create":
            assert self.release is None
            request = gh._json(payload)
            self.release = dict(
                id=22,
                tag_name=request["tag_name"],
                target_commitish=request["target_commitish"],
                name=request["name"],
                body=request["body"],
                draft=True,
                immutable=False,
                author={"id": 14},
                created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                published_at=None,
                upload_url="https://evil.invalid/?token=PRIVATE-MARKER",
            )
            value, status = self.release, 201
        elif operation == "release":
            assert identifier == self.release["id"]
            value = self.release
        elif operation == "assets":
            value = list(self.assets.values())
        elif operation.startswith("upload_"):
            name = {
                "upload_ciphertext": publication._NAMES[0],
                "upload_projection": publication._NAMES[1],
                "upload_receipt": publication._RECEIPT,
            }[operation]
            assert name not in self.assets
            self.next_id += 1
            self.assets[name] = self.asset(self.next_id, name, payload)
            self.bytes[self.next_id] = payload
            value, status = self.assets[name], 201
            if self.partial:
                del self.assets[name]
        elif operation == "asset":
            value = next(
                item for item in self.assets.values() if item["id"] == identifier
            )
        elif operation == "asset_bytes":
            value = self.bytes[identifier]
            if self.wrong_bytes:
                value += b"changed"
        elif operation == "publish":
            assert payload == b'{"draft":false}' and self.release["draft"]
            self.release.update(
                draft=False,
                immutable=True,
                published_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            value = self.release
        elif operation == "tag":
            value = dict(
                ref="refs/tags/gate0-unit", object=dict(type="tag", sha="b" * 40)
            )
        elif operation == "tag_object":
            value = dict(
                sha="b" * 40,
                object=dict(type="commit", sha=self.c.producer.source_revision),
            )
        else:
            raise AssertionError(operation)
        if operation == self.uncertain:
            if self.reply_kind == "lost":
                raise OSError("PRIVATE-MARKER reply uncertainty")
            if self.reply_kind == "invalid_json":
                return status, 0, 0, b'{"duplicate":1,"duplicate":2}'
            value = {"partial": True}
        raw = value if isinstance(value, bytes) else gh._canonical(value)
        assert len(raw) <= maximum
        return status, 0, 0, raw

    @staticmethod
    def asset(identifier, name, raw):
        return dict(
            id=identifier,
            name=name,
            state="uploaded",
            size=len(raw),
            digest="sha256:" + gh._digest(raw),
            uploader={"id": 14},
            content_type="application/octet-stream"
            if name.endswith(".pgp")
            else "application/json",
            browser_download_url="https://evil.invalid/PRIVATE-MARKER",
        )


def _publisher(c, monkeypatch, *, operation, draft=None, pub_reads=None, summary=b"{}"):
    native = NativeReleaseBoundary(c)
    original_protected = gh._protected
    files = {}
    for module in (publication, gh, writer):
        files[str(Path(module.__file__).absolute())] = Path(
            module.__file__
        ).read_bytes()
    owners = {
        name: gh._digest(files[str(Path(module.__file__).absolute())])
        for name, module in (
            ("publication", publication),
            ("github", gh),
            ("writer", writer),
        )
    }

    def pin(name, value):
        raw = gh._canonical(value)
        path = "/etc/dotmac-gate0-e/publication-" + name + ".json"
        files[path] = raw
        return {"path": path, "sha256": gh._digest(raw)}

    default_raw = c.gh_files.get(gh._INSTALLATION)
    default_binding = c.gh_files.get(gh._ROOT_BINDING)
    producer_reader = c.reader("producer")
    producer_doc = gh._json(c.gh_files[gh._INSTALLATION])["producer"]
    producer = dict(
        run_id=c.producer.run_id,
        attempt=1,
        workflow_id=c.producer.workflow_id,
        job_id=c.producer.job_id,
        head_sha=c.producer.source_revision,
        workflow_digest=producer_doc["workflow"]["sha256"],
        source_policy_digest=producer_doc["workflow"]["source_policy_pin"]["digest"],
    )
    if default_raw is not None and gh._json(default_raw)["phase"] == "transfer":
        c.gh_files[gh._INSTALLATION] = default_raw
        c.gh_files[gh._ROOT_BINDING] = default_binding
    doc = dict(
        schema="Gate0EPublicationInstallation.v2",
        operation=operation,
        policy_digest=c.selection.policy_digest[7:],
        repository=dict(
            owner="dotmac-tech",
            name="gate0-issuer-execution",
            repository_id=c.producer.repository_id,
            owner_id=c.producer.owner_id,
        ),
        release=dict(
            id=None if draft is None else draft.release_id,
            tag="gate0-unit",
            target_commit=c.producer.source_revision,
            title="Gate0 source unit",
            body="Fixed reviewed body",
            author_id=14,
        ),
        producer=producer,
        transfer_selection_digest=producer_reader.installed_selection_digest,
        draft_selection_digest=c.draft_reads.installed_selection_digest
        if operation == "publish"
        else None,
        publication_selection_digest=pub_reads.installed_selection_digest
        if operation == "publish"
        else None,
        summary_digest=gh._digest(summary) if operation == "publish" else None,
        credential=publication._CREDENTIAL,
        download_origins=["download.example.com"],
    )
    # draft is a fact, supplied separately below; no synthetic runtime DTO is issued.
    now = datetime.now(UTC)
    selection_digest = gh._digest(gh._canonical(doc))
    native_pin = pin(
        "native",
        dict(
            schema="Gate0EPublicationNativeReview.v1",
            method_scope=publication._METHOD_SCOPE,
            owner_digests=owners,
            qualification_measurements_digest="a" * 64,
            runtime_identity_digest="b" * 64,
            reviewer_record_digest="c" * 64,
        ),
    )
    qual = dict(
        schema="Gate0EPublicationNativeQualification.v1",
        selection_digest=selection_digest,
        policy_digest=doc["policy_digest"],
        runtime_uid=123,
        credential_uid=0,
        permissions=dict(
            contents="write", metadata="read", repository_id=c.producer.repository_id
        ),
        method_scope=publication._METHOD_SCOPE,
        owners=owners,
        native_receipt=native_pin,
        immutable_setting=dict(
            repository_id=c.producer.repository_id,
            state="enabled",
            response_sha256="a" * 64,
            native_record_digest="b" * 64,
            observed_at=(now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        action_time=dict(
            selection_digest=selection_digest,
            native_record_digest="d" * 64,
            qualified_at=(now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            valid_until=(now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            repository_id=c.producer.repository_id,
            operation=operation,
            target_commit=c.producer.source_revision,
            method_scope=publication._METHOD_SCOPE,
            source_policy_digest=producer["source_policy_digest"],
            credential_identity_digest="e" * 64,
            exclusive_writer_record_digest="f" * 64,
        ),
    )

    def load(draft_reads=None, transfer_reads=None, change=None, after_binding=None):
        if draft_reads:
            doc["draft_selection_digest"] = draft_reads.installed_selection_digest
        if transfer_reads:
            doc["transfer_selection_digest"] = transfer_reads.installed_selection_digest
        if change:
            change(doc, qual)
        digest = gh._digest(
            gh._canonical(
                {key: value for key, value in doc.items() if key != "qualification"}
            )
        )
        qual["selection_digest"] = qual["action_time"]["selection_digest"] = digest
        doc["qualification"] = pin("qualification", qual)
        raw = gh._canonical(doc)
        files[publication._INSTALLATION] = raw
        files[publication._BINDING] = gh._canonical(
            dict(
                schema="Gate0EPublicationBinding.v1",
                installation_sha256=gh._digest(raw),
                qualification_sha256=doc["qualification"]["sha256"],
                runtime_uid=123,
                owners=owners,
                native_receipt=native_pin,
            )
        )
        if after_binding is not None:
            after_binding(files, doc, qual)
        return publication.InstalledEPublication.from_installed()

    def protected(path, maximum, *args, **kwargs):
        if path == publication._CREDENTIAL:
            return b"SOURCE-UNIT-WRITE-TOKEN"
        if path in files:
            assert len(files[path]) <= maximum
            return files[path]
        return original_protected(path, maximum, *args, **kwargs)

    monkeypatch.setattr(gh, "_protected", protected)
    monkeypatch.setattr(gh, "_publication_exchange", native.exchange)
    return SimpleNamespace(
        load=load, native=native, document=doc, qualification=qual, files=files
    )


@pytest.fixture
def transfer_composition(installed_composition):  # noqa: F811
    c = installed_composition
    c.reader("producer", snapshot_stage="collection")
    c.load().prepare(deadline=time.monotonic() + 180)
    c.reader("producer")
    doc = gh._json(c.gh_files[gh._INSTALLATION])
    doc["phase"] = "transfer"
    doc["transfer"] = dict(
        artifact_id=40,
        name="gate0-encrypted-e",
        expected_artifact_names=["gate0-encrypted-e"],
        ciphertext_name=publication._NAMES[0],
        projection_name=publication._NAMES[1],
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in c.staged[0].items():
            archive.writestr(name, raw)
    archive_bytes = output.getvalue()
    artifact = dict(
        id=40,
        name="gate0-encrypted-e",
        expired=False,
        size_in_bytes=len(archive_bytes),
        digest="sha256:" + gh._digest(archive_bytes),
        workflow_run=dict(
            id=c.producer.run_id,
            repository_id=c.producer.repository_id,
            head_repository_id=c.producer.repository_id,
            head_sha=c.producer.source_revision,
            head_branch="main",
        ),
        created_at="2026-10-15T10:02:00Z",
        updated_at="2026-10-15T10:03:00Z",
        expires_at="2099-01-01T00:00:00Z",
    )
    prefix = "/repos/" + publication._REPOSITORY
    c.wire[(prefix + "/actions/artifacts/40", False)] = artifact
    c.wire[
        (
            prefix + f"/actions/runs/{c.producer.run_id}/artifacts?per_page=100&page=1",
            False,
        )
    ] = dict(total_count=1, artifacts=[artifact])
    c.wire[(prefix + "/actions/artifacts/40/zip", True)] = archive_bytes
    qual = gh._json(c.gh_files[doc["qualification"]["path"]])
    native_path = "/etc/dotmac-gate0-e/github-read-transfer-native.json"
    c.gh_files[native_path] = c.gh_files[qual["native_receipt_pin"]["path"]]
    native_pin = {"path": native_path, "digest": gh._digest(c.gh_files[native_path])}
    qual["native_receipt_pin"] = native_pin
    qual_path = "/etc/dotmac-gate0-e/github-read-transfer-qualification.json"
    c.gh_files[qual_path] = gh._canonical(qual)
    doc["qualification"] = {
        "path": qual_path,
        "digest": gh._digest(c.gh_files[qual_path]),
    }
    raw = gh._canonical(doc)
    c.gh_files[gh._INSTALLATION] = raw
    binding = gh._json(c.gh_files[gh._ROOT_BINDING])
    binding["installation_sha256"] = gh._digest(raw)
    binding["qualification_sha256"] = doc["qualification"]["digest"]
    binding["native_receipt_pin"] = native_pin
    c.gh_files[gh._ROOT_BINDING] = gh._canonical(binding)
    reads = gh.InstalledGate0GitHubReads.from_installed()
    facts = reads.encrypted_transfer()
    assert reads.owns_facts(facts)
    return c, reads, facts


def test_transfer_job_selection_requires_the_owned_outer_transfer(transfer_composition):
    c, reads, transfer = transfer_composition
    assert reads.selected_job(transfer).id == c.producer.job_id
    assert not reads.owns_facts(transfer.producer)
    for unowned in (transfer.producer, replace(transfer)):
        with pytest.raises(gh.GitHubReadRefused):
            reads.selected_job(unowned)
    foreign_reads = c.reader("producer")
    with pytest.raises(gh.GitHubReadRefused):
        foreign_reads.selected_job(transfer)
    with pytest.raises(gh.GitHubReadRefused):
        reads.encrypted_transfer()
    with pytest.raises(gh.GitHubReadRefused):
        reads.selected_job(transfer)


@pytest.mark.parametrize(
    "field",
    ["draft_selection_digest", "publication_selection_digest", "summary_digest"],
)
@pytest.mark.parametrize("value", ["a" * 64, "", True, "missing"])
def test_prepare_draft_refuses_non_null_or_missing_future_inputs(
    transfer_composition, monkeypatch, field, value
):
    c, reads, _ = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")

    def change(doc, qual):
        if value == "missing":
            del doc[field]
        else:
            doc[field] = value

    with pytest.raises(publication.EPublicationRefused) as raised:
        p.load(transfer_reads=reads, change=change)
    _assert_publication_graph_clean(raised.value)
    assert not p.native.calls


def test_first_create_and_exact_two_byte_readback(transfer_composition, monkeypatch):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    assert all(
        p.document[field] is None
        for field in (
            "draft_selection_digest",
            "publication_selection_digest",
            "summary_digest",
        )
    )
    installed = p.load(transfer_reads=reads)
    result = installed.prepare_draft_once(reads, transfer)
    assert result.result == "DRAFT_PREPARED" and result.release_id == 22
    assert {a.name: a.raw_bytes for a in result.assets} == c.staged[0]
    mutations = [
        op
        for op, _, _, _ in p.native.calls
        if op in ("create", "upload_ciphertext", "upload_projection")
    ]
    assert mutations == ["create", "upload_ciphertext", "upload_projection"]
    assert len({deadline for _, _, _, deadline in p.native.calls}) == 1
    assert "PRIVATE-MARKER" not in repr(installed._document)
    with pytest.raises(publication.EPublicationIncomplete):
        installed.prepare_draft_once(reads, transfer)
    assert mutations == [op for op, _, _, _ in p.native.calls if op in mutations]


@pytest.mark.parametrize(
    "operation", ["create", "upload_ciphertext", "upload_projection"]
)
@pytest.mark.parametrize("reply_kind", ["lost", "invalid_json", "partial_json"])
def test_uncertain_first_create_or_upload_readonly_reconciles_once(
    transfer_composition, monkeypatch, operation, reply_kind
):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    p.native.uncertain, p.native.reply_kind = operation, reply_kind
    result = p.load(transfer_reads=reads).prepare_draft_once(reads, transfer)
    assert result.result == "DRAFT_PREPARED"
    assert sum(op == operation for op, _, _, _ in p.native.calls) == 1
    assert all(
        op not in ("delete", "replace", "retag") for op, _, _, _ in p.native.calls
    )


@pytest.mark.parametrize(
    "failure",
    [
        "wrong_tag",
        "wrong_repo",
        "spoofed_transfer",
        "source",
        "partial_upload",
        "race",
        "changed_bytes",
    ],
)
def test_prepare_conflict_or_partial_bytes_preserve_attempt(
    transfer_composition, monkeypatch, failure
):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    installed = p.load(transfer_reads=reads)
    if failure == "wrong_tag":
        p.native.foreign_tag = True
    elif failure == "wrong_repo":
        p.native.wrong_repo = True
    elif failure == "spoofed_transfer":
        transfer = replace(transfer)
    elif failure == "source":
        p.document["producer"]["head_sha"] = "d" * 40
        p.document["release"]["target_commit"] = "d" * 40
        p.qualification["action_time"]["target_commit"] = "d" * 40
        installed = p.load(transfer_reads=reads)
    elif failure == "partial_upload":
        p.native.partial = True
    elif failure == "race":
        p.native.conflict = True
    else:
        p.native.wrong_bytes = True
    expected = (
        publication.EPublicationIncomplete
        if failure in ("partial_upload", "race", "changed_bytes")
        else publication.EPublicationRefused
    )
    with pytest.raises(expected):
        installed.prepare_draft_once(reads, transfer)
    assert sum(op == "create" for op, _, _, _ in p.native.calls) <= 1
    assert not any(op in ("delete", "publish") for op, _, _, _ in p.native.calls)


def _ready_publish(c, monkeypatch):
    p = _publisher(
        c,
        monkeypatch,
        operation="publish",
        draft=c.draft,
        pub_reads=c.pub_reads,
        summary=c.summary,
    )
    p.native.release = dict(
        id=c.draft.release_id,
        tag_name=c.draft.tag,
        target_commitish=c.draft.target_commitish,
        name=p.document["release"]["title"],
        body=p.document["release"]["body"],
        draft=True,
        immutable=False,
        author={"id": 14},
        created_at="2026-10-15T10:06:00Z",
        published_at=None,
    )
    for asset in c.draft.assets:
        p.native.assets[asset.name] = p.native.asset(
            asset.id, asset.name, asset.raw_bytes
        )
        p.native.bytes[asset.id] = asset.raw_bytes
    return p


@pytest.mark.parametrize(
    "field",
    ["draft_selection_digest", "publication_selection_digest", "summary_digest"],
)
@pytest.mark.parametrize("value", [None, "", "g" * 64, "a" * 63, True, "missing"])
def test_publish_refuses_null_malformed_or_missing_phase_inputs(
    receipt_composition,  # noqa: F811
    monkeypatch,
    field,
    value,
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)

    def change(doc, qual):
        if value == "missing":
            del doc[field]
        else:
            doc[field] = value

    with pytest.raises(publication.EPublicationRefused) as raised:
        p.load(draft_reads=c.draft_reads, change=change)
    _assert_publication_graph_clean(raised.value)
    assert not p.native.calls


@pytest.mark.parametrize("operation", ["prepare_draft", "publish"])
def test_legacy_publication_installation_schema_refused(
    request, monkeypatch, operation
):
    if operation == "prepare_draft":
        c, reads, _ = request.getfixturevalue("transfer_composition")
        p = _publisher(c, monkeypatch, operation=operation)
        load_inputs = {"transfer_reads": reads}
    else:
        c = request.getfixturevalue("receipt_composition")
        p = _ready_publish(c, monkeypatch)
        load_inputs = {"draft_reads": c.draft_reads}

    def change(doc, qual):
        doc["schema"] = "Gate0EPublicationInstallation.v1"
        if operation == "prepare_draft":
            # A complete old-style record must refuse, even with hex-shaped
            # future inputs; v1 is never reinterpreted as v2.
            for field in (
                "draft_selection_digest",
                "publication_selection_digest",
                "summary_digest",
            ):
                doc[field] = "a" * 64

    with pytest.raises(publication.EPublicationRefused) as raised:
        p.load(**load_inputs, change=change)
    _assert_publication_graph_clean(raised.value)
    assert not p.native.calls


@pytest.mark.parametrize(
    "field",
    ["draft_selection_digest", "publication_selection_digest", "summary_digest"],
)
def test_publish_refuses_valid_hex_phase_digest_mismatch(
    receipt_composition,  # noqa: F811
    monkeypatch,
    field,
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)

    def change(doc, qual):
        assert doc[field] != "a" * 64
        doc[field] = "a" * 64

    owner = p.load(draft_reads=c.draft_reads, change=change)
    with pytest.raises(publication.EPublicationRefused):
        owner.publish_once(
            c.load("publish", c.pins),
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            c.summary,
        )
    assert not any(
        op in ("upload_receipt", "publish") for op, _, _, _ in p.native.calls
    )


@pytest.mark.parametrize("uncertain", [None, "upload_receipt", "publish"])
@pytest.mark.parametrize("reply_kind", ["lost", "invalid_json", "partial_json"])
def test_actual_installed_writer_receipt_then_single_publish_bytes(
    receipt_composition,  # noqa: F811
    monkeypatch,
    uncertain,
    reply_kind,  # noqa: F811
):  # noqa: F811
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    p.native.uncertain, p.native.reply_kind = uncertain, reply_kind
    owner = p.load(draft_reads=c.draft_reads)
    result = owner.publish_once(
        c.load("publish", c.pins),
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        c.summary,
    )
    assert (
        result.result == "PUBLICATION_OBSERVED"
        and result.peeled_commit == c.producer.source_revision
    )
    assert len(result.assets) == 3
    receipt = next(a.raw_bytes for a in result.assets if a.name == publication._RECEIPT)
    assert gh._json(receipt)["b_summary_digest"] == writer._sha(c.summary)
    assert [
        op for op, _, _, _ in p.native.calls if op in ("upload_receipt", "publish")
    ] == ["upload_receipt", "publish"]
    assert not hasattr(result, "readiness_accepted")


@pytest.mark.parametrize(
    "failure",
    ["adoption", "summary", "review", "source", "spoofed_draft", "changed_bytes"],
)
def test_genuine_writer_gate_and_exact_recheck_before_publication_mutation(
    receipt_composition,  # noqa: F811
    monkeypatch,
    failure,  # noqa: F811
):  # noqa: F811
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    owner = p.load(draft_reads=c.draft_reads)
    pins = copy.deepcopy(c.pins)
    summary, draft, facts = c.summary, c.draft, c.pub_facts
    if failure == "adoption":
        pins["decision"] = c.pin("missing-adoption", b"foreign actual decision")
    elif failure == "summary":
        summary += b" "
    elif failure == "review":
        facts = replace(facts, review_response_digest="0" * 64)
    elif failure == "source":
        pins["run"]["source_revision"] = "d" * 40
    elif failure == "spoofed_draft":
        draft = replace(draft)
    else:
        p.native.wrong_bytes = True
    with pytest.raises(publication.EPublicationRefused):
        owner.publish_once(
            c.load("publish", pins), c.draft_reads, draft, c.pub_reads, facts, summary
        )
    assert not any(
        op in ("upload_receipt", "publish") for op, _, _, _ in p.native.calls
    )


@pytest.mark.parametrize(
    "failure",
    ["method_scope", "immutable", "credential", "expired", "root_binding", "unknown"],
)
def test_new_scope_native_and_root_binding_are_required(
    transfer_composition, monkeypatch, failure
):
    c, reads, _ = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")

    def change(doc, qual):
        if failure == "method_scope":
            qual["method_scope"] = "old-get-only-profile"
        elif failure == "immutable":
            qual["immutable_setting"]["state"] = "disabled"
        elif failure == "credential":
            doc["credential"] = "/arbitrary/token"
        elif failure == "expired":
            qual["action_time"]["valid_until"] = "2026-10-15T00:00:00Z"
        elif failure == "unknown":
            doc["unknown"] = True

    def after_binding(files, doc, qual):
        if failure == "root_binding":
            binding = gh._json(files[publication._BINDING])
            binding["installation_sha256"] = "0" * 64
            files[publication._BINDING] = gh._canonical(binding)

    with pytest.raises(publication.EPublicationRefused):
        p.load(transfer_reads=reads, change=change, after_binding=after_binding)
    assert not p.native.calls


@pytest.mark.parametrize(
    "slot,phase",
    [
        ("producer_completion", "producer"),
        ("publication_completion", "publication_complete"),
        ("published_release", "published"),
        ("draft_release", "draft"),
        ("publication_start", "publication"),
    ],
)
def test_independent_fixed_slot_loaders_keep_native_root_and_phase_checks(
    receipt_composition,  # noqa: F811
    slot,
    phase,  # noqa: F811
):  # noqa: F811
    c = receipt_composition
    kwargs = {}
    if phase in ("draft", "published"):
        release_files = dict(c.staged[0])
        if phase == "published":
            release_files[publication._RECEIPT] = b"{}"
        kwargs["release_files"] = release_files
    if phase in ("publication", "publication_complete"):
        kwargs.update(title="Gate0 source unit", summary_digest=gh._digest(c.summary))
    expected = c.reader(phase, **kwargs)
    installation_path = getattr(gh, "_" + slot.upper() + "_INSTALLATION")
    binding_path = getattr(gh, "_" + slot.upper() + "_ROOT_BINDING")
    c.gh_files[installation_path] = c.gh_files[gh._INSTALLATION]
    c.gh_files[binding_path] = c.gh_files[gh._ROOT_BINDING]
    loader = getattr(gh.InstalledGate0GitHubReads, "from_installed_" + slot)
    installed = loader()
    assert installed.installed_selection_digest == expected.installed_selection_digest
    # Default slot can now be absent: no runtime protected-file swapping needed.
    del c.gh_files[gh._INSTALLATION]
    del c.gh_files[gh._ROOT_BINDING]
    assert loader().installed_selection_digest == installed.installed_selection_digest
    raw = c.gh_files[installation_path]
    doc = gh._json(raw)
    doc["phase"] = "transfer"
    c.gh_files[installation_path] = gh._canonical(doc)
    binding = gh._json(c.gh_files[binding_path])
    binding["installation_sha256"] = gh._digest(c.gh_files[installation_path])
    c.gh_files[binding_path] = gh._canonical(binding)
    with pytest.raises(gh.GitHubReadRefused):
        loader()


@pytest.mark.parametrize("failure", ["root_binding", "source", "native_receipt"])
def test_fixed_slot_independent_provenance_tamper_refuses(receipt_composition, failure):  # noqa: F811
    c = receipt_composition
    c.reader("producer")
    installation_path = gh._PRODUCER_COMPLETION_INSTALLATION
    binding_path = gh._PRODUCER_COMPLETION_ROOT_BINDING
    c.gh_files[installation_path] = c.gh_files[gh._INSTALLATION]
    binding = gh._json(c.gh_files[gh._ROOT_BINDING])
    if failure == "root_binding":
        binding["installation_sha256"] = "0" * 64
    elif failure == "source":
        binding["source_sha256"] = "0" * 64
    else:
        binding["native_receipt_pin"]["digest"] = "0" * 64
    c.gh_files[binding_path] = gh._canonical(binding)
    with pytest.raises(gh.GitHubReadRefused):
        gh.InstalledGate0GitHubReads.from_installed_producer_completion()


def test_argument_free_prepare_entry_executes_actual_installed_transfer(
    transfer_composition, monkeypatch, capsys
):
    c, reads, _ = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    p.load(transfer_reads=reads)
    assert publication.run_installed_prepare_e_draft() == 0
    assert capsys.readouterr().out == "DRAFT_PREPARED\n"
    assert [op for op, _, _, _ in p.native.calls if op == "create"] == ["create"]


def test_argument_free_publish_entry_uses_independent_fixed_slots_and_actual_writer(
    receipt_composition,  # noqa: F811
    monkeypatch,
    capsys,  # noqa: F811
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    # Assemble all immutable fixture files before invoking the actual entry.
    for phase, kwargs, installation_path, binding_path in (
        (
            "draft",
            {"release_files": c.staged[0]},
            gh._DRAFT_RELEASE_INSTALLATION,
            gh._DRAFT_RELEASE_ROOT_BINDING,
        ),
        (
            "publication",
            {"title": c.pins["display_title"], "summary_digest": gh._digest(c.summary)},
            gh._PUBLICATION_START_INSTALLATION,
            gh._PUBLICATION_START_ROOT_BINDING,
        ),
    ):
        c.reader(phase, **kwargs)
        c.gh_files[installation_path] = c.gh_files[gh._INSTALLATION]
        c.gh_files[binding_path] = c.gh_files[gh._ROOT_BINDING]
    c.load("publish", c.pins)
    p.files["/run/dotmac-gate0-e/b-archive-verification.json"] = c.summary
    p.load(draft_reads=c.draft_reads)
    assert publication.run_installed_publish_e() == 0
    assert capsys.readouterr().out == "PUBLICATION_OBSERVED\n"
    assert [op for op, _, _, _ in p.native.calls if op == "publish"] == ["publish"]


_PUBLICATION_PRIVATE = b"WRITER-PRIVATE-PAYLOAD-RETENTION-MARKER"
_PUBLICATION_API_PRIVATE = b"POST-PATCH-UNKNOWN-PRIVATE-METADATA"
_PUBLICATION_TOKEN = b"SOURCE-UNIT-WRITE-TOKEN"
_OWNED_FILES = frozenset((publication.__file__, gh.__file__, writer.__file__))


def _assert_publication_graph_clean(
    error, *, publisher=None, consumed_writer=None, extra=(), captured_frames=()
):
    """Inspect emitted chains, groups, frame locals and reachable owner objects."""
    markers = (
        _PUBLICATION_PRIVATE,
        base64.b64encode(_PUBLICATION_PRIVATE),
        _PUBLICATION_API_PRIVATE,
        _PUBLICATION_TOKEN,
        *extra,
    )
    seen = set()

    def inspect(value):
        if id(value) in seen:
            return
        seen.add(id(value))
        if isinstance(value, bytes):
            assert not any(marker in value for marker in markers)
        elif isinstance(value, str):
            assert not any(marker.decode("ascii") in value for marker in markers)
        elif isinstance(value, BaseException):
            assert value.__cause__ is None and value.__context__ is None
            inspect(value.args)
            if isinstance(value, BaseExceptionGroup):
                for item in value.exceptions:
                    inspect(item)
            trace = value.__traceback__
            while trace is not None:
                inspect(trace.tb_frame)
                trace = trace.tb_next
        elif isinstance(value, FrameType):
            if value.f_code.co_filename in _OWNED_FILES:
                local = dict(value.f_locals)
                assert not any(
                    key in local
                    for key in (
                        "self",
                        "writer",
                        "draft_reads",
                        "draft",
                        "publication_reads",
                        "publication",
                        "transfer_reads",
                        "transfer",
                        "summary",
                        "receipt",
                        "receipt_doc",
                        "expected",
                        "response",
                        "token",
                        "raw",
                    )
                )
                inspect(local)
        elif isinstance(value, Mapping):
            for key, item in value.items():
                inspect(key)
                inspect(item)
        elif isinstance(value, tuple | list | set | frozenset):
            for item in value:
                inspect(item)
        elif isinstance(value, type):
            return
        elif is_dataclass(value):
            for item in fields(value):
                inspect(getattr(value, item.name))
        elif getattr(value, "__self__", None) is not None:
            inspect(value.__self__)
        elif not callable(value) and hasattr(value, "__dict__"):
            inspect(vars(value))
        elif type(value) is publication.InstalledEPublication:
            for name in value.__slots__:
                inspect(getattr(value, name))

    inspect(error)
    for frame in captured_frames:
        inspect(frame)
    if publisher is not None:
        assert publisher._used is True
        assert publisher._document == {} and publisher._qualification == {}
        inspect(publisher)
    if consumed_writer is not None:
        assert consumed_writer.__dict__ == {"_used": True}
        inspect(consumed_writer)


def _capture_owned_frames(output):
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_filename in _OWNED_FILES:
            output.append(frame)
        frame = frame.f_back


def test_post_patch_unknown_response_and_consumed_writer_are_detached(
    receipt_composition,  # noqa: F811
    monkeypatch,  # noqa: F811
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    publisher = p.load(draft_reads=c.draft_reads)
    consumed = c.load("publish", c.pins)
    native = p.native.exchange
    captured = []

    def exchange(operation, *args, **kwargs):
        if operation == "assets" and p.native.release["draft"] is False:
            _capture_owned_frames(captured)
            raise RuntimeError(_PUBLICATION_API_PRIVATE)
        result = native(operation, *args, **kwargs)
        if operation == "publish":
            value = gh._json(result[3])
            value["unknown_private_url"] = (
                "https://private.invalid/" + _PUBLICATION_API_PRIVATE.decode()
            )
            return *result[:3], gh._canonical(value)
        return result

    monkeypatch.setattr(gh, "_publication_exchange", exchange)
    with pytest.raises(publication.EPublicationIncomplete) as raised:
        publisher.publish_once(
            consumed, c.draft_reads, c.draft, c.pub_reads, c.pub_facts, c.summary
        )
    _assert_publication_graph_clean(
        raised.value,
        publisher=publisher,
        consumed_writer=consumed,
        captured_frames=captured,
    )
    assert p.native.release["draft"] is False  # issued evidence is preserved
    assert sum(op == "publish" for op, _, _, _ in p.native.calls) == 1


@pytest.mark.parametrize("early", [False, True])
def test_preparation_failure_drops_actual_transfer_and_caller_dto_refs(
    transfer_composition, monkeypatch, early
):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    publisher = p.load(transfer_reads=reads)
    if early:
        transfer = replace(transfer, ciphertext=_PUBLICATION_PRIVATE)
    else:
        p.native.wrong_bytes = True
    expected = (
        publication.EPublicationRefused if early else publication.EPublicationIncomplete
    )
    with pytest.raises(expected) as raised:
        publisher.prepare_draft_once(reads, transfer)
    _assert_publication_graph_clean(raised.value, publisher=publisher)
    if early:
        assert transfer.ciphertext == _PUBLICATION_PRIVATE  # no caller zeroization
        assert not p.native.calls


@pytest.mark.parametrize("stage", ["credential", "receipt_upload", "post_patch"])
@pytest.mark.parametrize(
    "category", ["interrupt", "exit", "cancelled", "generator", "group"]
)
def test_control_categories_detach_transport_receipt_and_owned_completed_frames(
    receipt_composition,  # noqa: F811
    monkeypatch,
    stage,
    category,  # noqa: F811
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    publisher = p.load(draft_reads=c.draft_reads)
    consumed = c.load("publish", c.pins)
    native = p.native.exchange
    captured, receipts = [], []

    def stop(payload):
        # Deliberately retain synthetic credential/receipt material in nested
        # causes/groups. The new emitted exception must not point back here.
        if category == "interrupt":
            error = KeyboardInterrupt(payload)
        elif category == "exit":
            error = SystemExit(payload)
        elif category == "cancelled":
            error = CancelledError(payload)
        elif category == "generator":
            error = GeneratorExit(payload)
        else:
            error = BaseExceptionGroup(
                "private group", [RuntimeError(payload), CancelledError(payload)]
            )
        error.__cause__ = RuntimeError(_PUBLICATION_API_PRIVATE)
        raise error

    def exchange(operation, identifier, token, payload, *args, **kwargs):
        if stage == "credential" and operation == "repository":
            _capture_owned_frames(captured)
            stop(token)
        if stage == "receipt_upload" and operation == "upload_receipt":
            receipts.append(payload)
            _capture_owned_frames(captured)
            stop((token, payload))
        if (
            stage == "post_patch"
            and operation == "assets"
            and p.native.release["draft"] is False
        ):
            _capture_owned_frames(captured)
            stop(token)
        return native(operation, identifier, token, payload, *args, **kwargs)

    monkeypatch.setattr(gh, "_publication_exchange", exchange)
    expected = {
        "interrupt": KeyboardInterrupt,
        "exit": SystemExit,
        "cancelled": CancelledError,
        "generator": GeneratorExit,
        "group": CancelledError,
    }[category]
    with pytest.raises(expected) as raised:
        publisher.publish_once(
            consumed, c.draft_reads, c.draft, c.pub_reads, c.pub_facts, c.summary
        )
    if category == "exit":
        assert raised.value.code == 1  # private/noninteger exit payload is discarded
    _assert_publication_graph_clean(
        raised.value,
        publisher=publisher,
        consumed_writer=consumed,
        extra=tuple(receipts),
        captured_frames=captured,
    )
    assert sum(op == "publish" for op, _, _, _ in p.native.calls) <= 1


@pytest.mark.parametrize(
    "field",
    [
        "installation_sha256",
        "qualification_sha256",
        "owner_source",
        "native_binding",
        "owner_set",
        "native_scope",
        "reviewer",
    ],
)
def test_actual_publication_binding_and_native_provenance_tamper_before_http(
    transfer_composition, monkeypatch, field
):
    c, reads, _ = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")

    def corrupt(files, doc, qual):
        binding = gh._json(files[publication._BINDING])
        if field in ("installation_sha256", "qualification_sha256"):
            binding[field] = "0" * 64
        elif field == "owner_source":
            binding["owners"]["publication"] = "0" * 64
        elif field == "native_binding":
            binding["native_receipt"]["sha256"] = "0" * 64
        elif field == "owner_set":
            del binding["owners"]["writer"]
        else:
            native_path = binding["native_receipt"]["path"]
            native = gh._json(files[native_path])
            if field == "native_scope":
                native["method_scope"] = "old-get-only"
            else:
                native["reviewer_record_digest"] = "not-a-reviewed-record-digest"
            files[native_path] = gh._canonical(native)
            digest = gh._digest(files[native_path])
            # Coherently re-pin bytes at the fixture boundary to reach the native
            # record predicate, not just the enclosing hash mismatch guard.
            binding["native_receipt"]["sha256"] = digest
            qual["native_receipt"] = copy.deepcopy(binding["native_receipt"])
            files[doc["qualification"]["path"]] = gh._canonical(qual)
            doc["qualification"]["sha256"] = gh._digest(
                files[doc["qualification"]["path"]]
            )
            files[publication._INSTALLATION] = gh._canonical(doc)
            binding["installation_sha256"] = gh._digest(
                files[publication._INSTALLATION]
            )
            binding["qualification_sha256"] = doc["qualification"]["sha256"]
        files[publication._BINDING] = gh._canonical(binding)

    with pytest.raises(publication.EPublicationRefused) as raised:
        p.load(transfer_reads=reads, after_binding=corrupt)
    _assert_publication_graph_clean(raised.value)
    assert not p.native.calls


_NATIVE_PROTECTED = gh._protected


@pytest.mark.parametrize(
    "failure",
    [
        "installation_owner",
        "binding_mode",
        "source_owner",
        "writable_ancestor",
        "symlink",
    ],
)
def test_publication_loader_uses_actual_protected_metadata_checks(
    transfer_composition, monkeypatch, failure
):
    c, reads, _ = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    p.load(transfer_reads=reads)
    descriptors, offsets = {}, {}
    next_fd = 800
    source_path = str(Path(publication.__file__).absolute())

    def native_open(path, flags, *, dir_fd=None):
        nonlocal next_fd
        parent = descriptors[dir_fd] if dir_fd is not None else ""
        full = os.path.join(parent, path)
        if full != "/":
            assert flags & os.O_NOFOLLOW
        if failure == "symlink" and full == publication._INSTALLATION:
            raise OSError("synthetic no-follow refusal")
        next_fd += 1
        descriptors[next_fd] = full
        offsets[next_fd] = 0
        return next_fd

    def native_stat(descriptor):
        path = descriptors[descriptor]
        leaf = path in p.files
        mode = (stat.S_IFREG | 0o600) if leaf else (stat.S_IFDIR | 0o755)
        uid = 0
        if failure == "installation_owner" and path == publication._INSTALLATION:
            uid = 999
        elif failure == "binding_mode" and path == publication._BINDING:
            mode = stat.S_IFREG | 0o646
        elif failure == "source_owner" and path == source_path:
            uid = 999
        elif failure == "writable_ancestor" and path == "/run":
            mode = stat.S_IFDIR | 0o777
        return SimpleNamespace(
            st_uid=uid, st_mode=mode, st_size=len(p.files[path]) if leaf else 0
        )

    def native_read(descriptor, maximum):
        raw = p.files[descriptors[descriptor]]
        start = offsets[descriptor]
        offsets[descriptor] += maximum
        return raw[start : start + maximum]

    monkeypatch.setattr(gh, "_protected", _NATIVE_PROTECTED)
    monkeypatch.setattr(gh.os, "open", native_open)
    monkeypatch.setattr(gh.os, "fstat", native_stat)
    monkeypatch.setattr(gh.os, "read", native_read)
    monkeypatch.setattr(gh.os, "close", lambda fd: descriptors.pop(fd))
    with pytest.raises(publication.EPublicationRefused) as raised:
        publication.InstalledEPublication.from_installed()
    _assert_publication_graph_clean(raised.value)
    assert not p.native.calls and not descriptors


def test_publication_credential_file_refusal_precedes_mutation_and_scrubs_error(
    transfer_composition, monkeypatch
):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    publisher = p.load(transfer_reads=reads)
    native = gh._protected

    def protected(path, *args, **kwargs):
        if path == publication._CREDENTIAL:
            raise PermissionError(_PUBLICATION_TOKEN)
        return native(path, *args, **kwargs)

    monkeypatch.setattr(gh, "_protected", protected)
    with pytest.raises(publication.EPublicationRefused) as raised:
        publisher.prepare_draft_once(reads, transfer)
    _assert_publication_graph_clean(raised.value, publisher=publisher)
    assert not p.native.calls


def test_publication_exact_public_metadata_and_private_credential_options(
    transfer_composition, monkeypatch
):
    c, reads, transfer = transfer_composition
    p = _publisher(c, monkeypatch, operation="prepare_draft")
    p.load(transfer_reads=reads)
    native = gh._protected
    calls = []
    allowed = {
        publication._INSTALLATION,
        publication._BINDING,
        "/etc/dotmac-gate0-e/publication-qualification.json",
        "/etc/dotmac-gate0-e/publication-native.json",
    }

    def classified(path, *args, **kwargs):
        if path in allowed:
            assert kwargs.get("private", True) is False
        if path == publication._CREDENTIAL:
            assert kwargs.get("private", True) is True and args[-1] == 0
        calls.append(path)
        return native(path, *args, **kwargs)

    monkeypatch.setattr(gh, "_protected", classified)
    publisher = publication.InstalledEPublication.from_installed()
    publisher.prepare_draft_once(reads, transfer)
    assert allowed <= set(calls) and publication._CREDENTIAL in calls


def test_publication_public_pin_refuses_private_history_before_open(monkeypatch):
    opened = []
    monkeypatch.setattr(gh, "_protected", lambda *args, **kwargs: opened.append(args))
    with pytest.raises(publication.EPublicationRefused):
        publication._pin(
            {
                "path": "/etc/dotmac-gate0-e/source-references/dossier",
                "sha256": "a" * 64,
            },
            "/etc/dotmac-gate0-e/publication-native.json",
        )
    assert not opened


@pytest.mark.parametrize("producer_delay", [30, 181])
def test_publisher_original_deadline_covers_slow_producer_and_historical_reads(
    receipt_composition,  # noqa: F811
    monkeypatch,
    producer_delay,
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    owner = p.load(draft_reads=c.draft_reads)
    installed_writer = c.load("publish", c.pins)
    clock = [100.0]
    producer_deadlines, historical_deadlines = [], []
    producer_get = gh._spawn_get
    historical_get = writer.historical_owner._spawn_get

    def slow_producer(path, token, binary, maximum, origins, deadline, page):
        producer_deadlines.append(deadline)
        result = producer_get(path, token, binary, maximum, origins, deadline, page)
        if len(producer_deadlines) == 1:
            clock[0] += producer_delay
        return result

    def historical(path, token, binary, maximum, origins, deadline, page):
        historical_deadlines.append((deadline, deadline - clock[0]))
        return historical_get(path, token, binary, maximum, origins, deadline, page)

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(gh, "_spawn_get", slow_producer)
    monkeypatch.setattr(writer.historical_owner, "_spawn_get", historical)
    args = (
        installed_writer,
        c.draft_reads,
        c.draft,
        c.pub_reads,
        c.pub_facts,
        c.summary,
    )
    if producer_delay > 180:
        with pytest.raises(publication.EPublicationRefused):
            owner.publish_once(*args)
        assert not historical_deadlines
        assert not any(
            op in ("upload_receipt", "publish") for op, _, _, _ in p.native.calls
        )
    else:
        result = owner.publish_once(*args)
        assert result.result == "PUBLICATION_OBSERVED"
        assert historical_deadlines
        assert all(
            end == 280.0 and remaining == 150.0
            for end, remaining in historical_deadlines
        )
        assert all(call[3] == 280.0 for call in p.native.calls)
    # The unchanged publisher end is propagated, while the existing producer
    # phase retains its stricter 90-second cap from phase start at100.
    assert producer_deadlines and set(producer_deadlines) == {min(280.0, 100.0 + 90)}


def test_historical_read_overruns_original_publication_end_without_success_or_mutation(
    receipt_composition,  # noqa: F811
    monkeypatch,
):
    c = receipt_composition
    p = _ready_publish(c, monkeypatch)
    owner = p.load(draft_reads=c.draft_reads)
    installed_writer = c.load("publish", c.pins)
    clock = [100.0]
    deadlines = []
    native = writer.historical_owner._spawn_get

    def slow_historical(path, token, binary, maximum, origins, deadline, page):
        deadlines.append(deadline)
        result = native(path, token, binary, maximum, origins, deadline, page)
        clock[0] = 281.0
        return result

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(writer.historical_owner, "_spawn_get", slow_historical)
    with pytest.raises(publication.EPublicationRefused):
        owner.publish_once(
            installed_writer,
            c.draft_reads,
            c.draft,
            c.pub_reads,
            c.pub_facts,
            c.summary,
        )
    assert deadlines == [280.0]
    assert not any(
        op in ("upload_receipt", "publish") for op, _, _, _ in p.native.calls
    )
