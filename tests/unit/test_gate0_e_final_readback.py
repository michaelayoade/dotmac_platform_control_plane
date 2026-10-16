"""Hosted-only concrete three-slot composition; no live/native acceptance claim."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_gate0_e_finalization import complete_retained_collection  # noqa: F401
from test_gate0_e_github import producer as github_producer  # noqa: F401
from test_gate0_e_preparation import inputs  # noqa: F401
from test_gate0_e_source_references import (
    installed as historical_installed,  # noqa: F401
)
from test_gate0_e_writer import (  # noqa: F401
    a9_export,
    installed_composition,
    receipt_composition,
)
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_e_final_readback as readback
from vendor_cp.deployment import gate0_e_github as gh
from vendor_cp.deployment import gate0_e_writer as writer


@pytest.fixture
def final_slots(receipt_composition, monkeypatch):  # noqa: F811
    """Populate all three protected slots before invoking the argument-free owner.

    Namespaced source-policy/qualification files avoid replacement or phase swaps
    while readers are live. Installation, native qualification and HTTP checks
    run in their existing owners. Only native/protected-file seams are synthetic.
    """
    c = receipt_composition
    receipt = c.load("publish", c.pins).construct_receipt(
        c.draft_reads, c.draft, c.pub_reads, c.pub_facts
    )
    slots = {}

    def retain(phase, installation_path, binding_path, **kwargs):
        c.reader(phase, **kwargs)
        doc = gh._json(c.gh_files[gh._INSTALLATION])
        binding = gh._json(c.gh_files[gh._ROOT_BINDING])
        for role in ("producer", "publication"):
            if doc[role] is not None:
                pin = doc[role]["workflow"]["source_policy_pin"]
                path = "/etc/dotmac-gate0-e/unit-" + phase + "-source.json"
                c.gh_files[path] = c.gh_files[pin["path"]]
                pin["path"] = path
        pin = doc["qualification"]
        path = "/etc/dotmac-gate0-e/unit-" + phase + "-qualification.json"
        c.gh_files[path] = c.gh_files[pin["path"]]
        pin["path"] = path
        raw = gh._canonical(doc)
        binding["installation_sha256"] = gh._digest(raw)
        c.gh_files[installation_path] = raw
        c.gh_files[binding_path] = gh._canonical(binding)
        c.reader_digests[phase] = gh._digest(raw)
        slots[phase] = (installation_path, binding_path)
        return raw

    pub_raw = retain(
        "publication_complete",
        gh._PUBLICATION_COMPLETION_INSTALLATION,
        gh._PUBLICATION_COMPLETION_ROOT_BINDING,
        title=c.pins["display_title"],
        summary_digest=writer._sha(c.summary)[7:],
    )
    retain(
        "producer",
        gh._PRODUCER_COMPLETION_INSTALLATION,
        gh._PRODUCER_COMPLETION_ROOT_BINDING,
    )
    retain(
        "published",
        gh._PUBLISHED_RELEASE_INSTALLATION,
        gh._PUBLISHED_RELEASE_ROOT_BINDING,
        release_files={**c.staged[0], "gate0-readiness-receipt.json": receipt},
    )
    pins = copy.deepcopy(c.pins)
    pins["reader_selection_digest"] = writer._sha(pub_raw)
    c.load("verify_published", pins)
    # The fallback selection is deliberately unavailable during the actual owner.
    del c.gh_files[gh._INSTALLATION], c.gh_files[gh._ROOT_BINDING]
    checked = []
    official_calls = []
    original_verify = writer.InstalledEWriter.verify_published

    def verify(
        self,
        release_reads,
        release,
        publication_reads,
        publication,
        producer_reads,
        producer,
    ):
        pairs = (
            (release_reads, release),
            (publication_reads, publication),
            (producer_reads, producer),
        )
        assert len({id(owner) for owner, _ in pairs}) == 3
        assert all(owner.owns_facts(facts) for owner, facts in pairs)
        checked.append(pairs)
        return original_verify(
            self,
            release_reads,
            release,
            publication_reads,
            publication,
            producer_reads,
            producer,
        )

    monkeypatch.setattr(writer.InstalledEWriter, "verify_published", verify)
    official = writer.release_owner

    class OfficialNativeUnitBoundary:
        def verify_published(self, reads, facts):
            assert reads is checked[-1][0][0] and facts is checked[-1][0][1]
            assert reads.owns_facts(facts)
            official_calls.append((reads, facts))
            if getattr(c, "fail_official", False):
                raise gh.AttestationTransportUnqualified()
            return official.VerifiedReleaseAssertion(
                facts.repository_id,
                facts.owner_id,
                facts.release_id,
                facts.tag,
                facts.raw_tag_sha,
                facts.peeled_commit,
                tuple((a.id, a.name, a.size, a.sha256) for a in facts.assets),
                "7" * 64,
                "8" * 64,
                (
                    official.ReleaseCommandEvidence(
                        "unit-native-process-boundary", None, "9" * 64, b"UNIT-ONLY"
                    ),
                ),
            )

    monkeypatch.setattr(
        writer.InstalledGhReleaseVerifier,
        "from_installed",
        classmethod(lambda cls: OfficialNativeUnitBoundary()),
    )
    return SimpleNamespace(
        c=c,
        slots=slots,
        checked=checked,
        official_calls=official_calls,
        original_verify=original_verify,
    )


def test_installed_final_readback_uses_three_original_slots_and_official_verifier(
    final_slots, capsys
):
    f = final_slots
    assert readback.run_installed_verify_e_published() == 0
    assert len(f.checked) == len(f.official_calls) == 1
    release, publication, producer = (pair[1] for pair in f.checked[0])
    assert release.immutable is True and release.draft is False
    assert (
        publication.run.stage
        == producer.stage
        == gh.ProducerStage.PRODUCER_RUN_COMPLETE
    )
    assert publication.run.conclusion == producer.conclusion == "success"
    streams = capsys.readouterr()
    assert streams.out == "E_PUBLISHED_VERIFIED\n" and streams.err == ""


@pytest.mark.parametrize(
    "failure",
    [
        "wrong_slot",
        "wrong_phase",
        "source_mismatch",
        "publication_incomplete",
        "producer_incomplete",
        "tag",
        "assets",
        "official",
        "copied_release",
        "copied_publication",
        "copied_producer",
        "wrong_stage",
    ],
)
def test_final_readback_refuses_before_success(
    final_slots, monkeypatch, capsys, failure
):
    f, c = final_slots, final_slots.c
    if failure in ("wrong_slot", "wrong_phase"):
        path, binding_path = f.slots["publication_complete"]
        if failure == "wrong_slot":
            other, other_binding = f.slots["producer"]
            c.gh_files[path] = c.gh_files[other]
            c.gh_files[binding_path] = c.gh_files[other_binding]
        else:
            doc = gh._json(c.gh_files[path])
            doc["phase"] = "publication"
            c.gh_files[path] = gh._canonical(doc)
            binding = gh._json(c.gh_files[binding_path])
            binding["installation_sha256"] = gh._digest(c.gh_files[path])
            c.gh_files[binding_path] = gh._canonical(binding)
    elif failure == "source_mismatch":
        c.gh_files[str(Path(gh.__file__).absolute())] += b"\n# changed source\n"
    elif failure in ("publication_incomplete", "producer_incomplete"):
        run_id = c.producer.run_id + (100 if failure == "publication_incomplete" else 0)
        for (_, binary), value in c.wire.items():
            if not binary and isinstance(value, dict) and value.get("id") == run_id:
                value.update(status="in_progress", conclusion=None)
    elif failure == "tag":
        for (path, binary), value in c.wire.items():
            if not binary and "/git/tags/" in path:
                previous = value["object"]["sha"]
                value["object"]["sha"] = "f" * 40 if previous != "f" * 40 else "e" * 40
                assert value["object"]["sha"] != previous
    elif failure == "assets":
        for (path, binary), value in c.wire.items():
            if not binary and "/releases/22/assets" in path:
                value.pop()
    elif failure == "official":
        c.fail_official = True
    elif failure == "wrong_stage":
        original_snapshot = gh.InstalledGate0GitHubReads.producer_snapshot

        def earlier_owned_stage(self, stage):
            assert stage == gh.ProducerStage.PRODUCER_RUN_COMPLETE
            facts = original_snapshot(self, gh.ProducerStage.PRODUCER_JOB_COMPLETE)
            assert self.owns_facts(facts)
            assert facts.stage != gh.ProducerStage.PRODUCER_RUN_COMPLETE
            return facts

        monkeypatch.setattr(
            gh.InstalledGate0GitHubReads, "producer_snapshot", earlier_owned_stage
        )
    else:

        def substituted(self, rr, release, pr, publication, sr, producer):
            if failure == "copied_release":
                release = replace(release)
            elif failure == "copied_publication":
                publication = replace(publication)
            elif failure == "copied_producer":
                producer = replace(producer)
            else:
                raise AssertionError("unhandled copy refusal case")
            return f.original_verify(self, rr, release, pr, publication, sr, producer)

        monkeypatch.setattr(writer.InstalledEWriter, "verify_published", substituted)
    assert readback.run_installed_verify_e_published() == 3
    streams = capsys.readouterr()
    assert streams.out == "" and streams.err == "GATE0_E_UNAVAILABLE\n"
    assert len(f.official_calls) == (1 if failure == "official" else 0)
