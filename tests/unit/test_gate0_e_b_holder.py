"""Positive installed composition with native metadata/decrypt seams only.

Real fixed loaders/readers, HTTP projections, proof/private verifier and private
record writer run unchanged. Fixtures establish no real Mac/GPG custody.
"""

from __future__ import annotations

import base64
import copy
import os
import stat
import time
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_e_github import producer as github_producer  # noqa: F401
from test_gate0_e_preparation import inputs  # noqa: F401
from test_gate0_e_source_references import (
    installed as historical_installed,  # noqa: F401
)
from test_gate0_e_writer import a9_export, installed_composition  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_b_holder as holder
from vendor_cp.deployment.gate0_framing import canonical, strict_object


@pytest.fixture
def b_composition(installed_composition, historical_installed, monkeypatch, tmp_path):  # noqa: F811
    comp = installed_composition
    operational = comp.document["evidence"]["operational"]
    comp.files[operational["path"]] = b"B-PRIVATE-PAYLOAD-MARKER"
    operational["digest"] = holder._sha(comp.files[operational["path"]])
    comp.reader("producer")
    comp.load().prepare(deadline=time.monotonic() + 180)
    transfer, package = comp.staged[-1], comp.packages[-1]
    plaintext = package[4]
    reads = comp.reader("draft", release_files=transfer)
    facts = reads.draft_snapshot()
    assert type(reads) is holder.github.InstalledGate0GitHubReads
    assert reads.owns_facts(facts)
    home, uid = "/Users/fixture-b", 123
    private_root = home + "/.config/dotmac-gate0-e-b/records"
    mac_files, native_nodes = {}, {}
    verified = tmp_path / "verified"
    verified.mkdir(mode=0o700)
    real_fstat, real_open = os.fstat, os.open
    directory_info = verified.stat()

    def pin(name, raw, *, root=False):
        path = (holder._RECORD_ROOT if root else private_root + "/") + name
        mac_files[path] = raw
        return dict(path=path, digest=holder._sha(raw))

    def remap(value):
        if isinstance(value, dict) and set(value) == {"path", "digest"}:
            return pin(Path(value["path"]).name, comp.files[value["path"]])
        if isinstance(value, dict):
            return {key: remap(item) for key, item in value.items()}
        if isinstance(value, list):
            return [remap(item) for item in value]
        return value

    native = pin(
        "native.json",
        canonical(
            dict(
                schema="Gate0ENativeReviewReceipt.v1",
                qualification_measurements_digest="1" * 64,
                runtime_identity_digest="2" * 64,
                reviewer_record_digest="3" * 64,
            )
        ),
        root=True,
    )
    public_profile = copy.deepcopy(comp.document["gpg"])
    public_profile["public_key"] = remap(public_profile["public_key"])
    custody = dict(
        schema="Gate0EBExistingCustodyProfile.v1",
        platform="darwin",
        runtime_uid=uid,
        runtime_home=home,
        homedir=home + "/.gnupg",
        agent_boundary=home,
        agent_root=home + "/.gnupg",
        agent_socket=home + "/.gnupg/S.gpg-agent",
        keyring=home + "/.gnupg/pubring.kbx",
        private_key_directory=home + "/.gnupg/private-keys-v1.d",
        public_profile=public_profile,
        gpgconf=dict(
            executable="/Library/Dotmac/gpgconf",
            executable_sha256="4" * 64,
            version_line="gpgconf (GnuPG) 2.4.7",
        ),
        qualified_at="2020-01-01T00:00:00+00:00",
        not_after="2100-01-01T00:00:00+00:00",
        native_receipt_digest=native["digest"],
        nodes={},
    )
    for index, key in enumerate(
        ("homedir", "agent_root", "agent_socket", "keyring", "private_key_directory"),
        10,
    ):
        identity = native_nodes.setdefault(
            custody[key], (1, index, uid, 0o600 if key == "keyring" else 0o700)
        )
        custody["nodes"][key] = dict(
            zip(("device", "inode", "uid", "mode"), identity, strict=True)
        )
    native_nodes[home] = (1, 1, uid, 0o700)
    native_nodes[private_root] = (1, 2, uid, 0o700)
    native_nodes[home + "/.config/dotmac-gate0-e-b/verified"] = (
        directory_info.st_dev,
        directory_info.st_ino,
        uid,
        0o700,
    )
    source_modules = dict(
        holder=holder,
        archive=holder.archive,
        writer=holder.writer,
        github=holder.github,
        historical=holder.historical,
        preparation=holder.preparation,
        proof=holder.proof,
        handoff=holder.handoff,
        framing=holder.framing,
    )
    source_digests = {}
    for name, module in source_modules.items():
        path = str(Path(module.__file__).absolute())
        mac_files[path] = Path(path).read_bytes()
        source_digests[name] = holder._sha(mac_files[path])
    document = dict(
        schema="Gate0EBHolderInstallation.v1",
        policy_digest=comp.selection.policy_digest,
        campaign_digest=comp.selection.campaign_digest,
        source_bundle_digest=comp.document["source_bundle_digest"],
        source=asdict(comp.selection.source),
        cases=remap(comp.document["cases"]),
        withdrawal_reference=comp.selection.withdrawal_reference,
        environment=comp.selection.environment,
        producer=comp.producer.document(),
        prerequisite=pin("prerequisite.json", package[1]["prerequisites.json"]),
        historical_reference=pin("historical.json", comp.historical_reference),
        github_installation=dict(
            path=holder.github._INSTALLATION,
            digest=holder._sha(comp.gh_files[holder.github._INSTALLATION]),
        ),
        historical_installation=dict(
            path=holder.historical._INSTALLATION,
            digest=holder._sha(
                historical_installed[1][holder.historical._INSTALLATION]
            ),
        ),
        custody=pin("custody.json", canonical(custody), root=True),
    )

    def qualify():
        qualification = dict(
            schema="Gate0EBHolderNativeQualification.v1",
            platform="darwin",
            selection_digest=holder._sha(
                canonical(
                    {
                        key: value
                        for key, value in document.items()
                        if key != "qualification"
                    }
                )
            ),
            runtime_uid=uid,
            runtime_home=home,
            source_digests=source_digests,
            native_receipt=native,
            custody_profile_digest=document["custody"]["digest"],
            github_installation_digest=document["github_installation"]["digest"],
            historical_installation_digest=document["historical_installation"][
                "digest"
            ],
        )
        document["qualification"] = pin(
            "qualification.json", canonical(qualification), root=True
        )
        mac_files[holder._INSTALLATION] = canonical(document)
        mac_files[holder._BINDING] = canonical(
            dict(
                schema="Gate0EBHolderBinding.v1",
                installation_digest=holder._sha(mac_files[holder._INSTALLATION]),
                qualification_digest=document["qualification"]["digest"],
                runtime_uid=uid,
                runtime_home=home,
                source_digests=source_digests,
                native_receipt=native,
            )
        )

    def root_read(path):
        if path in mac_files:
            return mac_files[path]
        if path in comp.gh_files:
            return comp.gh_files[path]
        return historical_installed[1][path]

    def walk(
        path,
        runtime_uid,
        boundary,
        *,
        kind="file",
        private=False,
        read=False,
        maximum=holder._CAP,
    ):
        assert runtime_uid == uid and boundary == home
        if read:
            raw = mac_files[path]
            assert 0 < len(raw) <= maximum and path.startswith(private_root + "/")
            return (1, 100, uid, 0o600), raw
        return native_nodes[path], b""

    def native_fstat(fd):
        info = real_fstat(fd)
        values = list(info)
        values[4] = uid
        return os.stat_result(values)

    decrypted_calls = []

    def decrypt(ciphertext, profile, *, deadline):
        assert (
            ciphertext == transfer["gate0-evidence.pgp"] and time.monotonic() < deadline
        )
        assert type(profile) is holder.archive.GpgHolderProfile
        decrypted_calls.append(profile)
        return holder.archive.DecryptedArchive(
            plaintext, holder._sha(plaintext)[7:], "5" * 64
        )

    monkeypatch.setattr(holder.sys, "platform", "darwin")
    monkeypatch.setattr(
        holder.pwd, "getpwuid", lambda value: SimpleNamespace(pw_dir=home)
    )
    monkeypatch.setattr(holder, "_root_read", root_read)
    monkeypatch.setattr(holder, "_walk", walk)
    monkeypatch.setattr(
        holder,
        "_open_directory",
        lambda path: real_open(verified, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(holder.os, "fstat", native_fstat)
    monkeypatch.setattr(holder.archive, "decrypt_private_collection", decrypt)
    qualify()
    return SimpleNamespace(
        comp=comp,
        document=document,
        qualify=qualify,
        files=mac_files,
        source_modules=source_modules,
        reads=reads,
        facts=facts,
        native_nodes=native_nodes,
        custody=custody,
        verified=verified,
        decrypted_calls=decrypted_calls,
        plaintext=plaintext,
        load=holder.InstalledBArchiveVerifier.from_installed,
    )


def test_positive_fixed_mac_loader_and_complete_live_owned_draft(b_composition):
    fixture = b_composition
    installed = fixture.load()
    assert installed._selection == fixture.comp.selection
    result = installed.verify_draft(
        fixture.reads, fixture.facts, deadline=time.monotonic() + 180
    )
    summary = strict_object(result.summary)
    assert summary["result"] == "private_archive_and_proofs_verified"
    assert summary["producer"] == fixture.comp.producer.document()
    assert result.summary_digest == holder._sha(result.summary)
    records = list(fixture.verified.glob("*.json"))
    assert (
        len(records) == 1
        and holder._sha(records[0].read_bytes()) == result.private_record_digest
    )
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600
    assert fixture.decrypted_calls and not installed._selected
    assert installed._selection is None and installed._profile is None
    assert b"B-PRIVATE-PAYLOAD-MARKER" not in result.summary


@pytest.mark.parametrize("owner", ["proof", "handoff", "framing"])
def test_positive_loader_owner_byte_change_refuses(b_composition, owner):
    fixture = b_composition
    path = str(Path(fixture.source_modules[owner].__file__).absolute())
    fixture.files[path] += b"changed-owner"
    with pytest.raises(holder.BHolderRefused) as caught:
        fixture.load()
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert not fixture.decrypted_calls


def test_coherent_independent_workflow_mismatch_refuses_before_decrypt(b_composition):
    fixture = b_composition
    fixture.document["source"]["workflow_digest"] = "sha256:" + "f" * 64
    fixture.qualify()
    installed = fixture.load()
    with pytest.raises(holder.BHolderRefused):
        installed.verify_draft(
            fixture.reads, fixture.facts, deadline=time.monotonic() + 180
        )
    assert not fixture.decrypted_calls


@pytest.mark.parametrize(
    "change", ["copied_facts", "foreign_reader", "wrong_job", "custody_inode"]
)
def test_one_binding_change_from_complete_valid_path_refuses(b_composition, change):
    fixture = b_composition
    reads, facts = fixture.reads, fixture.facts
    if change == "wrong_job":
        fixture.document["producer"]["job_id"] += 1
        fixture.qualify()
    installed = fixture.load()
    if change == "copied_facts":
        facts = replace(facts)
    elif change == "foreign_reader":
        reads = holder.github.InstalledGate0GitHubReads.from_installed()
    elif change == "custody_inode":
        path = fixture.custody["agent_socket"]
        dev, inode, uid, mode = fixture.native_nodes[path]
        fixture.native_nodes[path] = (dev, inode + 1, uid, mode)
    with pytest.raises(holder.BHolderRefused):
        installed.verify_draft(reads, facts, deadline=time.monotonic() + 180)
    assert not fixture.decrypted_calls


def _private_trace_values(error):
    assert error.__context__ is None and error.__cause__ is None
    retained = []
    tb = error.__traceback__
    while tb:
        if tb.tb_frame.f_code.co_filename in (holder.__file__, holder.archive.__file__):
            retained.extend(repr(value) for value in tb.tb_frame.f_locals.values())
        tb = tb.tb_next
    return "\n".join(retained)


@pytest.mark.parametrize(
    "stage", ["after_decrypt", "proof", "after_record", "interrupt", "system_exit"]
)
def test_late_private_failures_drop_context_and_payload_frames(
    b_composition, monkeypatch, stage
):
    fixture = b_composition
    installed = fixture.load()
    marker = "B-PRIVATE-FAILURE-MARKER"
    if stage == "after_decrypt":

        def fail(plaintext):
            raise ValueError(marker + str(len(plaintext)))

        monkeypatch.setattr(holder.archive, "unpack_private_archive", fail)
    elif stage == "proof":

        def fail(private_archive, selection, private_inputs):
            plaintext = private_inputs.plaintext
            raise ValueError(marker + str(len(plaintext)))

        monkeypatch.setattr(holder.writer, "verify_private_e", fail)
    else:
        original = installed._retain

        def fail(record, digest):
            original(record, digest)
            private_record = record + marker.encode()
            if stage == "interrupt":
                raise KeyboardInterrupt(private_record)
            if stage == "system_exit":
                raise SystemExit(7)
            raise ValueError(private_record)

        monkeypatch.setattr(installed, "_retain", fail)
    expected = (
        KeyboardInterrupt
        if stage == "interrupt"
        else SystemExit
        if stage == "system_exit"
        else holder.BHolderRefused
    )
    with pytest.raises(expected) as caught:
        installed.verify_draft(
            fixture.reads, fixture.facts, deadline=time.monotonic() + 180
        )
    retained = _private_trace_values(caught.value)
    assert marker not in retained
    assert base64.b64encode(b"B-PRIVATE-PAYLOAD-MARKER").decode() not in retained
    assert (
        not installed._selected
        and installed._selection is None
        and installed._profile is None
    )
    assert fixture.decrypted_calls
    assert len(list(fixture.verified.glob("*.json"))) == (
        0 if stage in ("proof", "after_decrypt") else 1
    )
    if stage == "interrupt":
        assert caught.value.args == ()
    if stage == "system_exit":
        assert caught.value.code == 7


def test_walk_identity_race_closes_new_and_parent_descriptors(monkeypatch):
    closed, opened = [], iter((100, 101))
    before = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    after = SimpleNamespace(st_dev=1, st_ino=3, st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    with monkeypatch.context() as patch:
        patch.setattr(holder.os, "open", lambda *args, **kwargs: next(opened))
        patch.setattr(holder.os, "stat", lambda *args, **kwargs: before)
        patch.setattr(holder.os, "fstat", lambda fd: after)
        patch.setattr(holder.os, "close", lambda fd: closed.append(fd))
        with pytest.raises(holder.BHolderRefused):
            holder._walk("/parent/child", 123, "/Users/fixture-b", read=True)
    assert sorted(closed) == [100, 101]


def test_linux_cannot_claim_mac_native_qualification(monkeypatch):
    monkeypatch.setattr(holder.sys, "platform", "linux")
    monkeypatch.setattr(
        holder, "_root_read", lambda path: pytest.fail("no native read")
    )
    with pytest.raises(holder.BHolderRefused):
        holder.InstalledBArchiveVerifier.from_installed()


@pytest.mark.parametrize("change", ["ciphertext_bytes", "projection_size"])
def test_valid_installed_pipeline_refuses_one_http_asset_change(b_composition, change):
    fixture = b_composition
    transfer = fixture.comp.staged[-1]
    reader = fixture.comp.reader("draft", release_files=transfer)
    identifier = 30 if change == "ciphertext_bytes" else 31
    path = reader._path(holder.github.EndpointCode.ASSET, None, identifier, 0)
    if change == "ciphertext_bytes":
        fixture.comp.wire[(path, True)] += b"tamper"
    else:
        fixture.comp.wire[(path, False)]["size"] += 1
    with pytest.raises(holder.github.GitHubReadRefused):
        reader.draft_snapshot()
    assert not fixture.decrypted_calls
