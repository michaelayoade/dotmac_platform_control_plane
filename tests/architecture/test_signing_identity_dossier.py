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

EXPECTED_PURPOSES = frozenset(
    {AUTHORIZATION_PURPOSE, EXECUTION_OBSERVATION_PURPOSE, RELEASE_EVIDENCE_PURPOSE}
)

_BACKTICKED = re.compile(r"`([^`]+)`")


def declared_pointers(text: str) -> dict[str, str]:
    """Pair each purpose with the pointer named beside it.

    Reads the document rather than restating it: a line naming both a purpose
    and a pointer under this product's prefix declares that pairing.
    """
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        tokens = _BACKTICKED.findall(line)
        purposes = [t for t in tokens if t in EXPECTED_PURPOSES]
        pointers = [t for t in tokens if t.startswith(POINTER_PREFIX)]
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


def test_the_dossier_declares_exactly_the_three_purposes() -> None:
    """One ceremony, three identities. A fourth would need a policy, a token, an
    enrolment line and a verification pass that this document does not carry."""
    declared = declared_pointers(DOSSIER.read_text(encoding="utf-8"))
    assert set(declared) == EXPECTED_PURPOSES, (
        "the dossier's purpose/pointer table does not declare exactly the three "
        f"purposes; found {sorted(declared)}"
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

    # No descriptor on `main` yet; hold it to the two rules that already exist.
    release_evidence = declared[RELEASE_EVIDENCE_PURPOSE]
    assert release_evidence.startswith(POINTER_PREFIX)
    assert release_evidence not in FORBIDDEN_SIGNING_POINTERS


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
