"""The mint dossier is normative prose, so it is bound to the code by test.

A dossier is pasted by a person. If it names a pointer the shipped validator
would refuse, the ceremony creates material that nothing can use — and the
mistake is only discovered at the far end of a signature, after the key exists,
after enrolment, and after `CREDENTIALS.md` records it. Prose outranks code in
practice because the operator reads the sentence, not the module.

So: every pointer this document names is DERIVED from the document and checked
against the real descriptors, and every check here is proved to bite.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from vendor_cp.deployment.signers import (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    FORBIDDEN_SIGNING_POINTERS,
    POINTER_PREFIX,
    AuthorizationSignerPointer,
    ObservationSignerPointer,
    SignerPointerRefused,
    SignerRefusal,
)

DOSSIER = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "design"
    / "signing-identity-mint-dossier.md"
)

#: `platform_release_evidence` has no descriptor on `main` yet — it lands with
#: the atomic cutover, whose `bindings.py` already consumes it through
#: `Ed25519EvidenceVerifier`. Pinned as a literal so the dossier and that work
#: cannot disagree; replace this with the imported constant in the same change
#: that lands it, and this comment with it.
RELEASE_EVIDENCE_PURPOSE = "platform_release_evidence"

#: `deployment_dispatch`, read from Control a11's `dispatch_envelope.py:45`
#: (`DISPATCH_PURPOSE`). Pinned as a literal for the same reason as the one
#: above: no descriptor for it exists in this repository yet, and Control is a
#: separate distribution. Replace both with imported constants in the change
#: that lands their descriptors.
DISPATCH_PURPOSE = "deployment_dispatch"

EXPECTED_PURPOSES = frozenset(
    {
        AUTHORIZATION_PURPOSE,
        EXECUTION_OBSERVATION_PURPOSE,
        DISPATCH_PURPOSE,
        RELEASE_EVIDENCE_PURPOSE,
    }
)

#: A purpose is a lowercase identifier. The reader matches SHAPE rather than an
#: allowlist, and that is the whole difference between this guard biting and
#: passing: filtering rows through `EXPECTED_PURPOSES` meant a row naming an
#: UNDECLARED purpose was silently skipped, so the count assertion below still
#: saw the old number and agreed with itself. A guard that only reads what it
#: already expects cannot report a surprise.
_PURPOSE_SHAPED = re.compile(r"^[a-z][a-z0-9_]*$")

_BACKTICKED = re.compile(r"`([^`]+)`")


def declared_pointers(text: str) -> dict[str, str]:
    """Pair each purpose with the pointer named beside it.

    Reads the document rather than restating it: a line naming both a purpose
    and a pointer under this product's prefix declares that pairing.
    """
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        # Per CELL, not per line. Scanning the whole line counted
        # `verify_dispatch_envelope` -- prose in the "verified by" column -- as a
        # second purpose, so the row had two candidates and was skipped, and the
        # count assertion then reported the fourth purpose as simply absent. A
        # purpose is a cell that is EXACTLY one backticked identifier; a cell of
        # prose that happens to contain one is not a declaration.
        cells = [cell.strip() for cell in line.split("|")]
        purposes = [
            _BACKTICKED.fullmatch(cell).group(1)  # type: ignore[union-attr]
            for cell in cells
            if _BACKTICKED.fullmatch(cell)
            and _PURPOSE_SHAPED.fullmatch(_BACKTICKED.fullmatch(cell).group(1))  # type: ignore[union-attr]
        ]
        pointers = [
            _BACKTICKED.fullmatch(cell).group(1)  # type: ignore[union-attr]
            for cell in cells
            if _BACKTICKED.fullmatch(cell)
            and _BACKTICKED.fullmatch(cell).group(1).startswith(POINTER_PREFIX)  # type: ignore[union-attr]
        ]
        if len(purposes) == 1 and len(pointers) == 1:
            pairs[purposes[0]] = pointers[0]
    return pairs


def mentioned_pointers(text: str) -> set[str]:
    """Every pointer under this product's prefix the document names anywhere.

    Includes the `bao kv put` and verification commands, not just the table —
    a command naming a pointer the table does not declare is the drift this
    catches. KV v2 POLICY paths (`secret/data/...`) deliberately do not match.
    """
    return set(re.findall(rf"{re.escape(POINTER_PREFIX)}[A-Za-z0-9/_.-]+", text))


def test_the_dossier_is_present_and_not_empty() -> None:
    """POSITIVE CONTROL. Every check below reads this file; over a missing or
    empty one they would all pass by finding nothing to object to."""
    assert DOSSIER.is_file()
    assert len(DOSSIER.read_text(encoding="utf-8")) > 2000


def test_the_dossier_declares_exactly_the_expected_purposes() -> None:
    """One ceremony, four identities. A fifth would need a policy, a token, an
    enrolment line and a verification pass this document does not carry.

    The reader takes any purpose-shaped row, so an undeclared purpose arrives
    here as a surprise rather than being filtered out on the way in.
    """
    declared = declared_pointers(DOSSIER.read_text(encoding="utf-8"))
    assert set(declared) == EXPECTED_PURPOSES, (
        "the dossier's purpose/pointer table does not declare exactly the "
        f"expected purposes; found {sorted(declared)}"
    )


def test_every_declared_pointer_is_admitted_by_the_shipped_descriptor() -> None:
    """The check that makes this file worth having.

    A pointer that reads fine in a table and is refused at construction time
    produces key material nothing can use.
    """
    declared = declared_pointers(DOSSIER.read_text(encoding="utf-8"))

    authorization = declared[AUTHORIZATION_PURPOSE]
    assert AuthorizationSignerPointer(authorization).pointer == authorization

    observation = declared[EXECUTION_OBSERVATION_PURPOSE]
    assert ObservationSignerPointer(observation).pointer == observation

    # No descriptor on `main` yet for these two; hold them to the two rules
    # that already exist, and to the same prefix every signer answers to.
    for purpose in (DISPATCH_PURPOSE, RELEASE_EVIDENCE_PURPOSE):
        pointer = declared[purpose]
        assert pointer.startswith(POINTER_PREFIX), purpose
        assert pointer not in FORBIDDEN_SIGNING_POINTERS, purpose


def test_the_dossier_names_no_undeclared_pointer() -> None:
    """A `bao kv put` against a pointer the table never declared would mint an
    identity with no policy, no enrolment line and no verification step."""
    text = DOSSIER.read_text(encoding="utf-8")
    declared = set(declared_pointers(text).values())
    assert mentioned_pointers(text) <= declared, (
        "the dossier names a pointer its purpose table does not declare: "
        f"{sorted(mentioned_pointers(text) - declared)}"
    )


def test_the_dossier_carries_the_namespace_constant_it_depends_on() -> None:
    """Decision 2 is overridable by changing `POINTER_PREFIX`. If the constant
    moves and this document does not, the override silently half-lands."""
    assert POINTER_PREFIX in DOSSIER.read_text(encoding="utf-8")


def test_the_dossier_proves_the_licensing_key_is_refused() -> None:
    """The dossier tells the operator to confirm the licensing path is denied.
    That instruction is only meaningful while the code refuses it too."""
    text = DOSSIER.read_text(encoding="utf-8")
    for licensing in FORBIDDEN_SIGNING_POINTERS:
        assert licensing in text, (
            f"the dossier never mentions {licensing}, so its verification step "
            "cannot ask the operator to prove it is unreachable"
        )
        with pytest.raises(SignerPointerRefused) as refused:
            AuthorizationSignerPointer(licensing)
        assert refused.value.refusal is SignerRefusal.FORBIDDEN_POINTER


# --- sensitivity: each check above is shown to bite -------------------------

_DOCTORED_HEADER = "| # | purpose | pointer |\n|---|---|---|\n"


def test_the_pairing_reader_bites_on_a_foreign_pointer() -> None:
    """SENSITIVITY for `declared_pointers` + the admission check. A dossier
    naming a legacy-namespace pointer must be refused, not read past."""
    doctored = (
        _DOCTORED_HEADER + f"| 1 | `{AUTHORIZATION_PURPOSE}` | "
        "`secret/dotmac/vendor-control-plane/production/database` |\n"
    )
    # The foreign pointer is not under the prefix, so it is not even READ as a
    # declaration — which is itself the refusal: the purpose ends up undeclared.
    assert declared_pointers(doctored) == {}
    with pytest.raises(SignerPointerRefused) as refused:
        AuthorizationSignerPointer(
            "secret/dotmac/vendor-control-plane/production/database"
        )
    assert refused.value.refusal is SignerRefusal.FOREIGN_NAMESPACE


def test_the_undeclared_pointer_check_bites() -> None:
    """SENSITIVITY. A command naming a fourth pointer must be caught."""
    doctored = (
        _DOCTORED_HEADER
        + f"| 1 | `{AUTHORIZATION_PURPOSE}` | `{POINTER_PREFIX}a/primary` |\n"
        f"\n```sh\nbao kv put {POINTER_PREFIX}smuggled/primary key=@x\n```\n"
    )
    declared = set(declared_pointers(doctored).values())
    assert mentioned_pointers(doctored) - declared == {
        f"{POINTER_PREFIX}smuggled/primary"
    }


def test_the_pairing_reader_finds_a_well_formed_row() -> None:
    """SENSITIVITY, the other direction. A reader that found nothing would make
    every check above pass over an empty set."""
    doctored = (
        _DOCTORED_HEADER
        + f"| 1 | `{AUTHORIZATION_PURPOSE}` | `{POINTER_PREFIX}a/primary` |\n"
    )
    assert declared_pointers(doctored) == {
        AUTHORIZATION_PURPOSE: f"{POINTER_PREFIX}a/primary"
    }


def test_an_undeclared_purpose_row_is_read_rather_than_skipped() -> None:
    """SENSITIVITY for the reader, and the reason it no longer filters.

    The earlier reader kept only rows whose purpose was already in
    `EXPECTED_PURPOSES`. A row naming a purpose nobody had declared was
    therefore dropped on the way in, and the count assertion compared the three
    it expected against the three it had been allowed to see -- agreeing with
    itself while the document declared something else. Control a11 adding a
    fourth purpose is exactly the event that shape cannot report.

    Now the row is read, so it shows up as a surprise the count refuses.
    """
    doctored = (
        _DOCTORED_HEADER
        + f"| 1 | `{AUTHORIZATION_PURPOSE}` | `{POINTER_PREFIX}a/primary` |\n"
        f"| 2 | `an_undeclared_purpose` | `{POINTER_PREFIX}b/primary` |\n"
    )
    declared = declared_pointers(doctored)
    assert "an_undeclared_purpose" in declared, (
        "the reader skipped a purpose it did not already expect, so the count "
        "assertion can never see a new one"
    )
    assert set(declared) != EXPECTED_PURPOSES
