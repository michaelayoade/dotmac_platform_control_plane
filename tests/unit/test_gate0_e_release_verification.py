"""Candidate source tests; mocked output is never native qualification."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace

import pytest

from vendor_cp.deployment import gate0_e_github as reads_owner
from vendor_cp.deployment import gate0_e_release_verification as verifier


@pytest.fixture
def facts():
    assets = tuple(
        reads_owner.ReleaseAssetFact(
            index,
            name,
            "uploaded",
            "application/octet-stream",
            len(raw),
            verifier._sha(raw),
            15,
            raw,
        )
        for index, (name, raw) in enumerate(
            (
                ("gate0-evidence.pgp", b"ciphertext"),
                ("gate0-evidence-public.json", b"{}"),
                ("gate0-readiness-receipt.json", b"{}"),
            ),
            start=10,
        )
    )
    return reads_owner.DownloadedReleaseFacts(
        905988044,
        222158671,
        "v6",
        "a" * 40,
        False,
        True,
        assets,
        (),
        "c5e17a62e06a1d201570249c61fae531e9244e1b",
        398027,
    )


def statement(facts):
    # Actual official fixture shapes at cli/cli fc4b137c: URI release subject,
    # named assets, decimal-string predicate IDs and pkg:github PURL.
    purl = "pkg:github/bdehamer/delme@v6"
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://in-toto.io/attestation/release/v0.1",
        "subject": [{"uri": purl, "digest": {"sha1": facts.raw_tag_sha}}]
        + [{"name": a.name, "digest": {"sha256": a.sha256}} for a in facts.assets],
        "predicate": {
            "ownerId": str(facts.owner_id),
            "purl": purl,
            "releaseId": str(facts.release_id),
            "repository": "bdehamer/delme",
            "repositoryId": str(facts.repository_id),
            "tag": facts.tag,
        },
    }


def output(facts):
    stmt = statement(facts)
    return {
        "attestation": {
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {"certificate": {"rawBytes": "AA=="}},
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
                    "signatures": [{"sig": "AA=="}],
                },
            },
            "bundle_url": "",
            "initiator": "",
        },
        "verificationResult": {
            "mediaType": (
                "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
            ),
            "statement": stmt,
            "signature": {"certificate": {}},
            "verifiedTimestamps": [
                {
                    "type": "TimestampAuthority",
                    "uri": "https://timestamp.github.com",
                    "timestamp": "2025-05-30T20:13:39Z",
                }
            ],
        },
    }


def encoded(facts):
    return json.dumps(output(facts)).encode()


def test_real_schema_semantic_join_and_annotated_tag(facts):
    parsed = verifier._statement(encoded(facts))
    verifier._join(
        parsed,
        facts,
        "bdehamer/delme",
        "pkg:github/bdehamer/delme@v6",
        "pkg:github/bdehamer/delme@v6",
    )
    assert facts.raw_tag_sha != facts.peeled_commit
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._join(
            parsed,
            replace(facts, raw_tag_sha=facts.peeled_commit),
            "bdehamer/delme",
            "pkg:github/bdehamer/delme@v6",
            "pkg:github/bdehamer/delme@v6",
        )


@pytest.mark.parametrize(
    "field", ["ownerId", "releaseId", "repositoryId", "tag", "repository", "purl"]
)
def test_one_predicate_field_rebind_refused(facts, field):
    parsed = statement(facts)
    parsed["predicate"][field] = "different"
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._join(
            parsed,
            facts,
            "bdehamer/delme",
            "pkg:github/bdehamer/delme@v6",
            "pkg:github/bdehamer/delme@v6",
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "null",
        "mismatch",
        "duplicate_subject",
        "wrong_name",
        "wrong_digest",
        "array",
        "missing_timestamp",
    ],
)
def test_output_and_roster_tamper(facts, mutation):
    document = output(facts)
    if mutation == "null":
        document["verificationResult"] = None
    elif mutation == "mismatch":
        document["verificationResult"]["statement"] = copy.deepcopy(statement(facts))
        document["verificationResult"]["statement"]["predicate"]["tag"] = "v7"
    elif mutation == "array":
        document = [document]
    elif mutation == "missing_timestamp":
        document["verificationResult"]["verifiedTimestamps"] = None
    else:
        stmt = statement(facts)
        if mutation == "duplicate_subject":
            stmt["subject"].append(copy.deepcopy(stmt["subject"][1]))
        elif mutation == "wrong_name":
            stmt["subject"][1]["name"] = "other.pgp"
        else:
            stmt["subject"][1]["digest"]["sha256"] = "0" * 64
        document["verificationResult"]["statement"] = stmt
        document["attestation"]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(stmt).encode()
        ).decode()
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        parsed = verifier._statement(json.dumps(document).encode())
        verifier._join(
            parsed,
            facts,
            "bdehamer/delme",
            "pkg:github/bdehamer/delme@v6",
            "pkg:github/bdehamer/delme@v6",
        )


@pytest.mark.parametrize(
    "raw",
    [b'{"attestation":{},"attestation":{}}', b"{", b"[]", b"x" * (1024 * 1024 + 1)],
)
def test_strict_bounded_json(raw):
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._statement(raw)


def test_missing_installed_qualification_refuses(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(verifier, "_protected", missing)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier.InstalledGhReleaseVerifier.from_installed()


def test_caller_facts_cannot_mint_verification(facts):
    owner = object.__new__(reads_owner.InstalledGate0GitHubReads)
    owner._failed, owner._issued = False, []
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL, {}, {}, "/fixed/gh", "1" * 64, "2" * 64
    )
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        adapter.verify_published(owner, facts)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        adapter.verify_published(owner, facts)


def test_mocked_full_four_command_flow(facts, monkeypatch, tmp_path):
    owner = object.__new__(reads_owner.InstalledGate0GitHubReads)
    owner._failed, owner._issued = False, [facts]
    installation = {
        "repository": {
            "owner": "bdehamer",
            "name": "delme",
            "repository_id": facts.repository_id,
            "owner_id": facts.owner_id,
        },
        "release": {
            "release_id": facts.release_id,
            "tag": facts.tag,
            "raw_tag_sha": facts.raw_tag_sha,
            "peeled_commit": facts.peeled_commit,
            "assets": [
                {"id": a.id, "name": a.name, "size": a.size, "sha256": a.sha256}
                for a in facts.assets
            ],
        },
    }
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL,
        installation,
        {"credential_uid": 0},
        "/fixed/gh",
        "1" * 64,
        "2" * 64,
    )
    monkeypatch.setattr(verifier, "_WORK", str(tmp_path))
    monkeypatch.setattr(
        adapter.__class__, "_work_profile", staticmethod(lambda q: None)
    )
    monkeypatch.setattr(adapter.__class__, "_reader_profile", lambda self, owner: None)
    monkeypatch.setattr(adapter.__class__, "_runtime_profile", lambda self: None)
    monkeypatch.setattr(
        verifier, "_protected", lambda *args, **kwargs: b"private-fixture-token"
    )
    calls = []

    def command(argv, env, cwd, deadline):
        calls.append((list(argv), dict(env), cwd, deadline))
        return encoded(facts)

    monkeypatch.setattr(verifier, "_command", command)
    result = adapter.verify_published(owner, facts)
    assert len(result.commands) == len(calls) == 4
    assert calls[0][0] == [
        "/fixed/gh",
        "release",
        "verify",
        "v6",
        "--repo",
        "bdehamer/delme",
        "--format",
        "json",
    ]
    assert {call[3] for call in calls} == {calls[0][3]}
    assert all(call[1]["GH_HOST"] == "github.com" for call in calls)
    assert all("PATH" not in call[1] and "HTTP_PROXY" not in call[1] for call in calls)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("status", [0, 1])
def test_owned_child_requires_zero_eof_and_wait(monkeypatch, tmp_path, status):
    import os
    import subprocess
    import time

    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"bounded-output")
    os.close(write_fd)

    class Child:
        pid = 123
        stdin = stderr = None
        returncode = None
        stdout = os.fdopen(read_fd, "rb")
        waited = False

        def wait(self, timeout):
            assert timeout > 0
            self.waited = True
            self.returncode = status
            return status

    child = Child()
    captured = []

    def launch(argv, **kwargs):
        captured.append((argv, kwargs))
        return child

    monkeypatch.setattr(os, "listdir", lambda path: ["123"])
    monkeypatch.setattr(subprocess, "Popen", launch)
    if status:
        with pytest.raises(reads_owner.AttestationTransportUnqualified):
            verifier._command(["/fixed/gh"], {}, str(tmp_path), time.monotonic() + 5)
    else:
        assert (
            verifier._command(["/fixed/gh"], {}, str(tmp_path), time.monotonic() + 5)
            == b"bounded-output"
        )
    assert child.waited and child.stdout.closed
    assert captured[0][1]["close_fds"] is True
    assert captured[0][1]["preexec_fn"] is verifier._limits
    assert captured[0][1]["stdin"] == subprocess.DEVNULL


def test_cleanup_attempts_reap_after_signal_and_stream_failures(monkeypatch, tmp_path):
    import os
    import subprocess
    import time

    attempts = []

    class BrokenStream:
        def fileno(self):
            raise OSError("fixture")

        def close(self):
            attempts.append("close")
            raise OSError("fixture")

    class Child:
        pid = 123
        stdin = stderr = None
        stdout = BrokenStream()
        returncode = None

        def kill(self):
            attempts.append("kill")
            raise OSError("fixture")

        def wait(self, timeout):
            attempts.append("wait")
            assert timeout > 0
            self.returncode = -9
            return -9

    def kill_group(*args):
        attempts.append("group")
        raise PermissionError

    monkeypatch.setattr(os, "listdir", lambda path: ["123"])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Child())
    monkeypatch.setattr(os, "killpg", kill_group)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._command(["/fixed/gh"], {}, str(tmp_path), time.monotonic() + 5)
    assert attempts == ["group", "kill", "close", "wait"]


def test_expired_shared_budget_never_launches(monkeypatch, tmp_path):
    import subprocess
    import time

    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._command(["/fixed/gh"], {}, str(tmp_path), time.monotonic() + 1)
    assert calls == []


def test_asset_command_rebind_invalidates_whole_result(facts, monkeypatch, tmp_path):
    owner = object.__new__(reads_owner.InstalledGate0GitHubReads)
    owner._failed, owner._issued = False, [facts]
    installation = {
        "repository": {
            "owner": "bdehamer",
            "name": "delme",
            "repository_id": facts.repository_id,
            "owner_id": facts.owner_id,
        },
        "release": {
            "release_id": facts.release_id,
            "tag": facts.tag,
            "raw_tag_sha": facts.raw_tag_sha,
            "peeled_commit": facts.peeled_commit,
            "assets": [
                {"id": a.id, "name": a.name, "size": a.size, "sha256": a.sha256}
                for a in facts.assets
            ],
        },
    }
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL,
        installation,
        {"credential_uid": 0},
        "/fixed/gh",
        "1" * 64,
        "2" * 64,
    )
    monkeypatch.setattr(verifier, "_WORK", str(tmp_path))
    monkeypatch.setattr(
        adapter.__class__, "_work_profile", staticmethod(lambda q: None)
    )
    monkeypatch.setattr(adapter.__class__, "_reader_profile", lambda self, owner: None)
    monkeypatch.setattr(adapter.__class__, "_runtime_profile", lambda self: None)
    monkeypatch.setattr(
        verifier, "_protected", lambda *args, **kwargs: b"private-fixture-token"
    )
    calls = []

    def command(argv, env, cwd, deadline):
        calls.append(argv)
        if len(calls) == 1:
            return encoded(facts)
        return encoded(replace(facts, release_id=facts.release_id + 1))

    monkeypatch.setattr(verifier, "_command", command)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        adapter.verify_published(owner, facts)
    assert len(calls) == 2
    assert not list(tmp_path.iterdir())


def test_reader_binding_is_original_owner_selection(monkeypatch):
    owner = object.__new__(reads_owner.InstalledGate0GitHubReads)
    owner._installation = {"selected": 1}
    owner._qualification = {"native": 2}
    binding = {
        "installation_sha256": verifier._sha(verifier._canonical(owner._installation)),
        "qualification_sha256": verifier._sha(
            verifier._canonical(owner._qualification)
        ),
    }
    raw = verifier._canonical(binding)
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL,
        {},
        {"reader_binding_sha256": verifier._sha(raw)},
        "/fixed/gh",
        "1" * 64,
        "2" * 64,
    )
    monkeypatch.setattr(verifier, "_protected", lambda *args, **kwargs: raw)
    adapter._reader_profile(owner)
    owner._qualification = {"native": 3}
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        adapter._reader_profile(owner)


def test_staged_inode_substitution_is_refused(tmp_path):
    import os
    import time

    path = tmp_path / "gate0-evidence.pgp"
    path.write_bytes(b"ciphertext")
    path.chmod(0o600)
    info = path.stat()
    identity = (info.st_dev, info.st_ino)
    assert verifier._staged(str(path), identity, b"ciphertext", time.monotonic() + 5)
    path.rename(tmp_path / "original")
    path.write_bytes(b"ciphertext")
    path.chmod(0o600)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._staged(str(path), identity, b"ciphertext", time.monotonic() + 5)
    assert os.path.exists(tmp_path / "original")


@pytest.fixture
def installed_documents(monkeypatch, facts):
    import os
    import platform
    import sys

    files = {}

    def pin(path, raw):
        files[path] = raw
        return {"path": path, "sha256": verifier._sha(raw)}

    native = pin(
        verifier._NATIVE,
        verifier._canonical(
            {
                "schema": "Gate0ENativeReviewReceipt.v1",
                "qualification_measurements_digest": "1" * 64,
                "runtime_identity_digest": "2" * 64,
                "reviewer_record_digest": "3" * 64,
            }
        ),
    )
    gh_pin = pin("/opt/pinned/gh", b"pinned-binary")
    interpreter = pin(os.path.realpath(sys.executable), b"pinned-interpreter")
    installation = {
        "schema": "Gate0EGhReleaseInstallation.v1",
        "repository": {
            "owner": "bdehamer",
            "name": "delme",
            "repository_id": facts.repository_id,
            "owner_id": facts.owner_id,
        },
        "release": {
            "release_id": facts.release_id,
            "tag": facts.tag,
            "raw_tag_sha": facts.raw_tag_sha,
            "peeled_commit": facts.peeled_commit,
            "assets": [
                {"id": a.id, "name": a.name, "size": a.size, "sha256": a.sha256}
                for a in facts.assets
            ],
        },
        "gh": gh_pin,
        "interpreter": interpreter,
    }
    source = pin(os.path.abspath(verifier.__file__), b"pinned-wrapper")
    reader = pin(
        "/etc/dotmac-gate0-e/github-read-published-release-binding.json",
        b"reader-binding",
    )
    ca = pin(verifier._CA, b"ca-bundle")
    qualification = {
        "schema": "Gate0EGhReleaseNativeQualification.v1",
        "gh_source": verifier._GH_SOURCE,
        "gh_version": "2.102.0",
        "installation_policy_sha256": verifier._sha(verifier._canonical(installation)),
        "resource_policy": dict(verifier._POLICY),
        "runtime_uid": 501,
        "credential_uid": 501,
        "kernel": "qualified-kernel",
        "boot_id": "qualified-boot",
        "work_mountinfo_sha256": "4" * 64,
        "ca_sha256": ca["sha256"],
        "source_sha256": source["sha256"],
        "reader_binding_sha256": reader["sha256"],
        "runtime_image_digest": "5" * 64,
        "output_profile": "gh-2.102-release-single-result-v1",
        "process_profile": "dedicated-uid-contained-gh-group-v1",
        "network_profile": "github-release-tuf-ca-isolated-cache-v1",
        "native_receipt": native,
    }
    qual_pin = pin(verifier._QUALIFICATION, verifier._canonical(qualification))
    installation["qualification"] = qual_pin
    files[verifier._INSTALLATION] = verifier._canonical(installation)
    binding = {
        "schema": "Gate0EGhReleaseRootBinding.v1",
        "installation_sha256": verifier._sha(files[verifier._INSTALLATION]),
        "qualification_sha256": qual_pin["sha256"],
        "native_receipt": native,
        "source_sha256": source["sha256"],
        "runtime_uid": 501,
        "credential_uid": 501,
        "reader_binding_sha256": reader["sha256"],
        "runtime_image_digest": "5" * 64,
    }
    files[verifier._BINDING] = verifier._canonical(binding)
    monkeypatch.setattr(
        verifier, "_protected", lambda path, *args, **kwargs: files[path]
    )
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "release", lambda: "qualified-kernel")
    monkeypatch.setattr(verifier, "_boot_id", lambda: "qualified-boot")
    monkeypatch.setattr(os, "getuid", lambda: 501)
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(os, "access", lambda *args: True)
    monkeypatch.setattr(
        verifier.InstalledGhReleaseVerifier,
        "_work_profile",
        staticmethod(lambda q: None),
    )
    return files, qualification


def test_closed_installed_loader_and_pins(installed_documents):
    adapter = verifier.InstalledGhReleaseVerifier.from_installed()
    assert adapter._binary == "/opt/pinned/gh"
    assert adapter._binary_digest == verifier._sha(b"pinned-binary")


@pytest.mark.parametrize(
    "mutation", ["binary", "extra_field", "missing_native", "qualification_bytes"]
)
def test_changed_installed_inputs_refuse(installed_documents, mutation):
    files, _ = installed_documents
    if mutation == "binary":
        files["/opt/pinned/gh"] = b"different"
    elif mutation == "missing_native":
        del files[verifier._NATIVE]
    elif mutation == "qualification_bytes":
        files[verifier._QUALIFICATION] += b" "
    else:
        parsed = json.loads(files[verifier._INSTALLATION])
        parsed["accepted"] = True
        files[verifier._INSTALLATION] = verifier._canonical(parsed)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier.InstalledGhReleaseVerifier.from_installed()


def _bounded_fifo_fault(operation, fifo_path):
    """Exercise an actual FIFO; unblock a regressed blocking open before failing."""
    import os
    import threading

    errors = []

    def invoke():
        try:
            operation()
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    worker.join(timeout=0.5)
    blocked = worker.is_alive()
    if blocked:
        # A blocking O_RDONLY open has registered a reader. Release that reader
        # so a regression fails promptly without abandoning a blocked thread.
        writer = os.open(fifo_path(), os.O_WRONLY | os.O_NONBLOCK)
        os.close(writer)
        worker.join(timeout=0.5)
    assert not worker.is_alive()
    assert not blocked, "staged FIFO open blocked before regular-file validation"
    assert len(errors) == 1
    assert isinstance(errors[0], reads_owner.AttestationTransportUnqualified)


def test_actual_fifo_substitution_before_use_is_nonblocking(tmp_path):
    import os
    import stat
    import time

    path = tmp_path / "gate0-evidence.pgp"
    original = tmp_path / "retained-original"
    path.write_bytes(b"ciphertext")
    path.chmod(0o600)
    info = path.stat()
    path.rename(original)
    os.mkfifo(path, 0o600)
    fifo_identity = path.stat()
    deadline = time.monotonic() + 3
    _bounded_fifo_fault(
        lambda: verifier._staged(
            str(path), (info.st_dev, info.st_ino), b"ciphertext", deadline
        ),
        lambda: str(path),
    )
    assert stat.S_ISFIFO(path.stat().st_mode)
    assert (path.stat().st_dev, path.stat().st_ino) == (
        fifo_identity.st_dev,
        fifo_identity.st_ino,
    )
    assert original.read_bytes() == b"ciphertext"
    assert time.monotonic() < deadline


def test_staged_expired_original_deadline_never_opens(monkeypatch, tmp_path):
    import os
    import time

    path = tmp_path / "fifo"
    os.mkfifo(path, 0o600)
    opened = []
    original_open = os.open

    def record_open(*args, **kwargs):
        opened.append(args)
        return original_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", record_open)
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        verifier._staged(str(path), (0, 0), b"ciphertext", time.monotonic() - 1)
    assert opened == []
    assert path.exists()


def test_actual_fifo_cleanup_keeps_original_deadline_and_evidence(
    facts, monkeypatch, tmp_path
):
    import os
    import stat
    from pathlib import Path

    owner = object.__new__(reads_owner.InstalledGate0GitHubReads)
    owner._failed, owner._issued = False, [facts]
    installation = {
        "repository": {
            "owner": "bdehamer",
            "name": "delme",
            "repository_id": facts.repository_id,
            "owner_id": facts.owner_id,
        },
        "release": {
            "release_id": facts.release_id,
            "tag": facts.tag,
            "raw_tag_sha": facts.raw_tag_sha,
            "peeled_commit": facts.peeled_commit,
            "assets": [
                {"id": a.id, "name": a.name, "size": a.size, "sha256": a.sha256}
                for a in facts.assets
            ],
        },
    }
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL,
        installation,
        {"credential_uid": 0},
        "/fixed/gh",
        "1" * 64,
        "2" * 64,
    )
    monkeypatch.setattr(verifier, "_WORK", str(tmp_path))
    monkeypatch.setattr(
        adapter.__class__, "_work_profile", staticmethod(lambda q: None)
    )
    monkeypatch.setattr(adapter.__class__, "_reader_profile", lambda self, reader: None)
    monkeypatch.setattr(adapter.__class__, "_runtime_profile", lambda self: None)
    monkeypatch.setattr(
        verifier, "_protected", lambda *args, **kwargs: b"private-fixture-token"
    )
    commands = []
    substituted = []
    staged_deadlines = []
    original_staged = verifier._staged

    def staged(path, identity, expected, deadline):
        staged_deadlines.append(deadline)
        return original_staged(path, identity, expected, deadline)

    def command(argv, env, cwd, deadline):
        commands.append((argv, deadline))
        if len(commands) == 1:
            return encoded(facts)
        path = Path(argv[4])
        path.rename(path.with_suffix(".retained"))
        os.mkfifo(path, 0o600)
        substituted.append(path)
        raise OSError("fixture failure after child-side pathname substitution")

    monkeypatch.setattr(verifier, "_staged", staged)
    monkeypatch.setattr(verifier, "_command", command)
    _bounded_fifo_fault(
        lambda: adapter.verify_published(owner, facts),
        lambda: str(substituted[0]),
    )
    original_end = commands[0][1]
    assert commands[1][1] == original_end
    assert staged_deadlines == [
        original_end - verifier._POLICY["cleanup_seconds"],
        original_end,
    ]
    assert stat.S_ISFIFO(substituted[0].stat().st_mode)
    assert (
        substituted[0].with_suffix(".retained").read_bytes()
        == facts.assets[0].raw_bytes
    )
    assert len(list(tmp_path.iterdir())) == 1  # refusal retains the owned private work
    with pytest.raises(reads_owner.AttestationTransportUnqualified):
        adapter.verify_published(owner, facts)


def test_official_initial_and_runtime_metadata_use_public_published_slot(
    installed_documents, monkeypatch
):
    files, _ = installed_documents
    native = verifier._protected
    calls = []

    def protected(path, *args, **kwargs):
        calls.append((path, kwargs.get("private", True)))
        assert path != "/etc/dotmac-gate0-e/github-read-binding.json"
        assert kwargs.get("private", True) is False
        return native(path, *args, **kwargs)

    monkeypatch.setattr(verifier, "_protected", protected)
    adapter = verifier.InstalledGhReleaseVerifier.from_installed()
    adapter._runtime_profile()
    published = "/etc/dotmac-gate0-e/github-read-published-release-binding.json"
    assert (published, False) in calls
    assert calls.count((verifier._INSTALLATION, False)) == 2
    assert calls.count((verifier._BINDING, False)) == 2
    assert "/etc/dotmac-gate0-e/github-read-binding.json" not in files


def test_official_reader_recheck_never_uses_default_binding(monkeypatch):
    calls = []

    def missing_published(path, *args, **kwargs):
        calls.append((path, kwargs.get("private", True)))
        if path == "/etc/dotmac-gate0-e/github-read-binding.json":
            pytest.fail("default binding used as an alias")
        raise FileNotFoundError

    monkeypatch.setattr(verifier, "_protected", missing_published)
    adapter = verifier.InstalledGhReleaseVerifier(
        verifier._SEAL, {}, {}, "/fixed/gh", "1" * 64, "2" * 64
    )
    with pytest.raises(FileNotFoundError):
        adapter._reader_profile(None)
    assert calls == [
        ("/etc/dotmac-gate0-e/github-read-published-release-binding.json", False)
    ]
