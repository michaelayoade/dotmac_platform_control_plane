"""Build → embed → admission-check → read back, held as a wiring contract.

Four verbs, and until this lane none of them happened. The verifier merged in
#165/#166 is the READING half and had never run against an image: every one of
its tests wrote a document into `tmp_path` and then read it back, which is a
claim about a fixture.

This module holds the wiring that makes the other three real, and the ONE
assertion that records the transition:

:data:`EXPECTED_CANDIDATE_VERDICT` is what the acceptance battery asserts the
candidate's readback returns, and the two must agree. It was
``DOCUMENT_ABSENT`` in the commit that added the probe — the honest state of an
artifact carrying no document, observed against real bytes for the first time —
and the embed moved it to ``CONCERNS_INCOMPLETE``. A verdict that moved with no
diff here, or a diff here with no movement there, fails.

That is the whole reason the probe asserts a NAMED verdict rather than "the
readback ran". A step that accepted any answer would have gone on passing
straight through the embed and proved nothing about it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from vendor_cp.deployment.profile_readback import (
    DEFAULT_PROFILE_PATH,
    ProfileVerdict,
)

ROOT = Path(__file__).resolve().parents[2]
ACCEPTANCE = ROOT / ".github" / "candidate" / "acceptance.sh"
CI = ROOT / ".github" / "workflows" / "ci.yml"
PUBLICATION = ROOT / ".github" / "workflows" / "production-image.yml"
DOCKERFILE = ROOT / "Dockerfile"
READBACK = ROOT / "src" / "vendor_cp" / "deployment" / "profile_readback.py"
BUILDER = ROOT / "src" / "vendor_cp" / "deployment" / "profile.py"

#: The verdict the candidate's own readback must currently return. It was
#: `DOCUMENT_ABSENT` in the commit that added the probe and CI observed exactly
#: that against a real image; the embed moved it here, and the two sides moved
#: together — see this module's docstring.
EXPECTED_CANDIDATE_VERDICT = ProfileVerdict.CONCERNS_INCOMPLETE

#: The caller-supplied expectation. Named here so the two workflows and the
#: script cannot disagree about the variable that carries it.
REVISION_VARIABLE = "CANDIDATE_SOURCE_REVISION"


def _acceptance() -> str:
    return ACCEPTANCE.read_text(encoding="utf-8")


def _imported_names(path: Path) -> set[str]:
    """Every name a module actually imports. Prose about a name is not an
    import, and the difference is what keeps this guard able to pass."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def test_the_verifier_still_imports_nothing_from_the_builder() -> None:
    """One-directional, and it is the direction that matters.

    A verifier that re-derived its expectation from the code that produced the
    document would confirm that one module agrees with itself. The builder may
    import the verifier's VOCABULARY — the contract string and the thirteen slot
    names, where two spellings is a bug with no upside — but never the reverse.
    """
    readback = READBACK.read_text(encoding="utf-8")
    assert "vendor_cp.deployment.profile " not in readback
    assert "from vendor_cp.deployment.profile import" not in readback
    assert "import vendor_cp.deployment.profile" not in readback

    imported = _imported_names(BUILDER)
    assert "FOUNDATION_CONCERNS" in imported
    assert "PROFILE_CONTRACT" in imported
    # And it does NOT import the digest. Asked of the IMPORT STATEMENTS, not of
    # the file's text: the builder's docstring names
    # `canonical_profile_digest` in order to explain why it implements the
    # specification again, and a source-text check would forbid a token its own
    # explanation contains — the shape that has already produced a test in this
    # repository that could never pass.
    assert "canonical_profile_digest" not in imported


def test_the_acceptance_battery_reads_the_profile_back_inside_the_candidate() -> None:
    """Inside the image, against the paths the artifact actually uses.

    A readback run against the checkout would prove what the source says, and
    the defect class this pipeline exists for is an artifact that disagrees with
    its source.
    """
    text = _acceptance()
    assert "verify_embedded_profile" in text
    assert "profile_readback" in text
    # `in_image` is the helper that runs a SCRIPT inside the candidate.
    step = text.split('step "18 ', 1)[1]
    assert 'profile_readback="$(in_image)"' in step


def test_the_probe_asserts_one_named_verdict_and_it_is_the_declared_one() -> None:
    """The transition, held from both sides.

    Exactly one verdict literal is compared in the step, it is a real member of
    `ProfileVerdict`, and it is the one this module declares. The embed commit
    moves both together or fails.
    """
    step = _acceptance().split('step "18 ', 1)[1]
    compared = re.findall(r'verdict != "([a-z_]+)"', step)
    assert compared == [str(EXPECTED_CANDIDATE_VERDICT)], compared
    assert compared[0] in {str(verdict) for verdict in ProfileVerdict}


def test_the_expectation_comes_from_the_caller_and_the_script_refuses_without_it() -> (
    None
):
    """Reading the expected revision back off the image would make the
    expectation a copy of the claim. The script refuses rather than defaulting,
    because a default here is an expectation nobody chose."""
    text = _acceptance()
    assert f': "${{{REVISION_VARIABLE}:?' in text


def test_both_callers_supply_the_revision_the_battery_refuses_without() -> None:
    """The rehearsal and the publication path. A variable the script demands and
    a workflow never sets is a step that fails for a reason about the harness."""
    for workflow in (CI, PUBLICATION):
        text = workflow.read_text(encoding="utf-8")
        assert "acceptance.sh" in text, workflow
        assert REVISION_VARIABLE in text, workflow


def test_the_builder_is_runnable_as_a_module_entry_point() -> None:
    """`python -m vendor_cp.deployment.profile`, from the INSTALLED wheel.

    Not a Dockerfile heredoc: a document constructed by a literal in a build
    file is exactly the fixture-shaped binding this lane exists to replace, and
    nothing would lint, type-check or be testable.
    """
    builder = BUILDER.read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in builder
    assert "def main(" in builder


# ── the embed: the document is part of the image ────────────────────────────


def test_the_image_builds_the_document_from_the_installed_wheel() -> None:
    """`python -m vendor_cp.deployment.profile`, not an inline build script.

    The Dockerfile takes per-file DIGESTS with a heredoc, and that is fine: a
    measurement of files is something a build script can honestly make. A
    profile is a set of CLAIMS about which providers this artifact carries, and
    a claim written into a build file is a literal. Running the installed module
    is what makes every concern in the document there because a provider
    RESOLVED in this environment.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "python -m vendor_cp.deployment.profile" in dockerfile
    assert '--source-revision "$SOURCE_REVISION"' in dockerfile
    assert "--lock /app/poetry.lock" in dockerfile


def test_the_runtime_stage_carries_the_document_where_the_verifier_reads_it() -> None:
    """The path is DERIVED from the verifier's own constant, not written twice.

    An embed that landed the document one directory over would produce an image
    the verifier reports `DOCUMENT_ABSENT` for while the build log says it was
    written — a disagreement no test comparing two literals could see.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert str(DEFAULT_PROFILE_PATH.parent) == "/app"
    assert "WORKDIR /app" in dockerfile
    assert f"/app/{DEFAULT_PROFILE_PATH.name}" in dockerfile
    assert f"./{DEFAULT_PROFILE_PATH.name}" in dockerfile


def test_the_probe_names_the_concerns_it_expects_to_be_unsatisfied() -> None:
    """By NAME, so it fails the day either one lands.

    A probe asserting only "two are missing" would keep passing when
    `request_evidence_context` bound and something else silently broke. Naming
    them is what makes the next state a decision rather than a drift.
    """
    step = _acceptance().split('step "18 ', 1)[1]
    assert "request_evidence_context" in step
    assert "integration" in step
    assert re.search(r"len\(bound\) != 11", step), step[:0] or "no bound-count check"
