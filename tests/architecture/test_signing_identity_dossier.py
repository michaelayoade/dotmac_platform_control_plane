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
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

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

#: `deployment_recovery`, read from Control's `RECOVERY_PURPOSE` at
#: `src/dotmac_deployment_control/recovery_grant.py:77`, merged commit
#: `312e9a8227cda941f15d0e44a93c41a76332d86e`. Pinned as a literal for the same
#: reason as the two above: no descriptor for it exists in this repository yet.
#: Replace all three with imported constants in the change that lands their
#: descriptors.
RECOVERY_PURPOSE = "deployment_recovery"

#: NOT a signer purpose, and named here so the difference is checkable rather
#: than remembered: `RECOVERY_GRANT_SCHEMA` discriminates the DOCUMENT, and
#: refuses a deployment authorization before any field is compared. A purpose
#: constant and a schema constant are different discriminators and neither
#: substitutes for the other.
RECOVERY_GRANT_SCHEMA = "dotmac.deployment_control.recovery_grant"

EXPECTED_PURPOSES = frozenset(
    {
        AUTHORIZATION_PURPOSE,
        EXECUTION_OBSERVATION_PURPOSE,
        DISPATCH_PURPOSE,
        RELEASE_EVIDENCE_PURPOSE,
        RECOVERY_PURPOSE,
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
    """One ceremony, five identities. A sixth would need a policy, a token, an
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
    for purpose in (DISPATCH_PURPOSE, RELEASE_EVIDENCE_PURPOSE, RECOVERY_PURPOSE):
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


# --- the purpose-misuse matrix, derived rather than counted by hand ----------
#
# Step 7b's matrix is the document's statement that every DIRECTED pair of
# identities has been considered: identity A's key, offered for identity B's
# purpose, must refuse. With N identities that is N*(N-1) cells, and the count
# has now moved twice — three identities to four, four to five — while the
# sentence naming it moved separately, by hand, in a different paragraph.
#
# So nothing below states a number. The axes are compared with the identity
# table's own declared short labels, the cell count is DERIVED from how many
# identities that table declares, and the prose count is checked against the
# derivation rather than trusted. A fifth identity therefore turns this red
# until the matrix carries all twenty directed pairs and each one is attributed
# to a mechanism that refuses it.
#
# `each demonstrably able to refuse` is the last rule and the one that stops the
# matrix being decoration: a numbered cell nobody attributed to a named refusing
# mechanism is a pair that was drawn, not checked.

_NUMBER_WORDS: Final[dict[str, int]] = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
    "thirty": 30,
}

_SHORT_LABEL_HEADER = "short label"
_MATRIX_CORNER = re.compile(r"holder\s*\\?\s*used as", re.IGNORECASE)
_CELL_NUMBER = re.compile(r"^\((\d+)\)$")
_MECHANISM_BULLET = re.compile(r"^- \*\*\(")
_STATED_PAIRS = re.compile(r"\*?\*?([a-z]+|\d+)\*?\*? ordered pairs", re.IGNORECASE)
#: "four identities", "three purpose-bound Ed25519 identities". The count token
#: is restricted to the known words so `the authorization and observation
#: identities` — a phrase with no count in it — is not read as one.
_STATED_IDENTITIES = re.compile(
    r"\b(one|two|three|four|five|six|seven|eight|nine|ten|\d+)\b"
    r"(?: [\w-]+){0,3}? identities",
    re.IGNORECASE,
)
_MUST_SUCCEED = "must succeed"


class MatrixRefusal(StrEnum):
    """Why the purpose-misuse matrix does not cover the identities declared."""

    #: The matrix axes are not the identity table's declared short labels.
    AXES_DISAGREE_WITH_IDENTITIES = "AXES_DISAGREE_WITH_IDENTITIES"
    #: A diagonal cell — an identity used for its OWN purpose — does not say it
    #: must succeed. A matrix of refusals with no successes proves nothing about
    #: whether the identities work at all.
    DIAGONAL_NOT_REQUIRED_TO_SUCCEED = "DIAGONAL_NOT_REQUIRED_TO_SUCCEED"
    #: Fewer numbered cells than there are directed pairs.
    ORDERED_PAIR_MISSING = "ORDERED_PAIR_MISSING"
    #: One number used for two cells, which hides a missing one behind a count.
    ORDERED_PAIR_NUMBERED_TWICE = "ORDERED_PAIR_NUMBERED_TWICE"
    #: A numbered cell no mechanism bullet claims. Drawn, not checked.
    PAIR_HAS_NO_REFUSING_MECHANISM = "PAIR_HAS_NO_REFUSING_MECHANISM"
    #: The prose pair count disagrees with the derived one.
    STATED_COUNT_DISAGREES = "STATED_COUNT_DISAGREES"
    #: The document says it covers a different number of identities than it
    #: declares. The merged title said THREE while the table declared four.
    STATED_IDENTITY_COUNT_DISAGREES = "STATED_IDENTITY_COUNT_DISAGREES"
    #: A cell or table the reader cannot parse. Never a pass.
    MATRIX_UNREADABLE = "MATRIX_UNREADABLE"


@dataclass(frozen=True, slots=True)
class MatrixFinding:
    refusal: MatrixRefusal
    detail: str


def _norm(cell: str) -> str:
    return " ".join(cell.replace("**", "").replace("`", "").split()).lower()


def _row_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def identity_labels(text: str) -> tuple[str, ...]:
    """The identity table's declared short labels, in declaration order.

    Located by HEADER rather than by position, so adding a column to the
    identity table cannot silently shift which one this reads.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        header = [_norm(cell) for cell in _row_cells(line)]
        if _SHORT_LABEL_HEADER not in header:
            continue
        column = header.index(_SHORT_LABEL_HEADER)
        labels: list[str] = []
        for row in lines[index + 2 :]:
            if not row.lstrip().startswith("|"):
                break
            cells = _row_cells(row)
            if len(cells) <= column:
                break
            labels.append(_norm(cells[column]))
        return tuple(labels)
    return ()


def misuse_matrix(text: str) -> tuple[tuple[str, ...], list[tuple[str, list[str]]]]:
    """(column labels, [(row label, cells)]) for step 7b's matrix."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        cells = _row_cells(line)
        if not cells or not _MATRIX_CORNER.search(cells[0]):
            continue
        columns = tuple(_norm(cell) for cell in cells[1:])
        rows: list[tuple[str, list[str]]] = []
        for row in lines[index + 2 :]:
            if not row.lstrip().startswith("|"):
                break
            row_cells = _row_cells(row)
            rows.append((_norm(row_cells[0]), [_norm(c) for c in row_cells[1:]]))
        return columns, rows
    return (), []


def attributed_pairs(text: str) -> set[int]:
    """Every cell number a mechanism bullet claims to refuse."""
    claimed: set[int] = set()
    for line in text.splitlines():
        if not _MECHANISM_BULLET.match(line.strip()):
            continue
        head = line.split("—")[0]
        claimed.update(int(n) for n in re.findall(r"\((\d+)\)", head))
    return claimed


def stated_pair_counts(text: str) -> list[tuple[str, int | None]]:
    """Every "<n> ordered pairs" the prose states, with its parsed value."""
    found: list[tuple[str, int | None]] = []
    for match in _STATED_PAIRS.finditer(text):
        token = match.group(1).lower()
        if token.isdigit():
            found.append((match.group(0), int(token)))
        else:
            found.append((match.group(0), _NUMBER_WORDS.get(token)))
    return found


def stated_identity_counts(text: str) -> list[tuple[str, int | None]]:
    """Every "<n> identities" the prose states, with its parsed value."""
    found: list[tuple[str, int | None]] = []
    for match in _STATED_IDENTITIES.finditer(text):
        token = match.group(1).lower()
        found.append(
            (
                match.group(0),
                int(token) if token.isdigit() else _NUMBER_WORDS.get(token),
            )
        )
    return found


def scan_matrix(text: str) -> list[MatrixFinding]:
    """Every way the matrix fails to cover the identities that were declared."""
    labels = identity_labels(text)
    columns, rows = misuse_matrix(text)
    findings: list[MatrixFinding] = []

    def flag(refusal: MatrixRefusal, detail: str) -> None:
        findings.append(MatrixFinding(refusal, detail))

    if not labels:
        flag(MatrixRefusal.MATRIX_UNREADABLE, "no identity short labels parsed")
        return findings
    for phrase, value in stated_identity_counts(text):
        if value != len(labels):
            flag(
                MatrixRefusal.STATED_IDENTITY_COUNT_DISAGREES,
                f"prose says {phrase!r}; the identity table declares " f"{len(labels)}",
            )

    if not columns or not rows:
        flag(MatrixRefusal.MATRIX_UNREADABLE, "no purpose-misuse matrix parsed")
        return findings

    row_labels = tuple(label for label, _ in rows)
    # The two axes must be the same sequence as each other — a matrix whose rows
    # and columns are ordered differently makes every cell mean something other
    # than it appears to. Against the IDENTITY TABLE the comparison is by SET,
    # deliberately: the cells are self-describing through their own row and
    # column labels, so a different ordering costs a reader nothing, while a
    # missing or extra identity is the defect this exists to catch. The merged
    # document already ordered the two tables differently — observation and
    # dispatch are swapped — and requiring agreement there would have failed on
    # a difference that misleads nobody.
    if row_labels != columns:
        flag(
            MatrixRefusal.AXES_DISAGREE_WITH_IDENTITIES,
            f"rows {list(row_labels)} are not the same sequence as columns "
            f"{list(columns)}; every cell would mean something other than it "
            "appears to",
        )
    if len(set(row_labels)) != len(row_labels):
        flag(
            MatrixRefusal.AXES_DISAGREE_WITH_IDENTITIES,
            f"the matrix repeats an axis label: {list(row_labels)}",
        )
    if set(columns) != set(labels):
        flag(
            MatrixRefusal.AXES_DISAGREE_WITH_IDENTITIES,
            f"matrix axes {sorted(columns)} do not cover the declared "
            f"identities {sorted(labels)}",
        )
    if findings:
        return findings

    size = len(labels)
    numbered: dict[int, list[str]] = {}
    for row_index, (row_label, cells) in enumerate(rows):
        if len(cells) != size:
            flag(
                MatrixRefusal.MATRIX_UNREADABLE,
                f"row {row_label!r} has {len(cells)} cells, expected {size}",
            )
            continue
        for column_index, cell in enumerate(cells):
            where = f"{row_label} used as {columns[column_index]}"
            if row_index == column_index:
                if cell != _MUST_SUCCEED:
                    flag(
                        MatrixRefusal.DIAGONAL_NOT_REQUIRED_TO_SUCCEED,
                        f"{where}: {cell!r}",
                    )
                continue
            match = _CELL_NUMBER.match(cell)
            if not match:
                flag(MatrixRefusal.MATRIX_UNREADABLE, f"{where}: {cell!r}")
                continue
            numbered.setdefault(int(match.group(1)), []).append(where)

    expected = size * (size - 1)
    for number, places in sorted(numbered.items()):
        if len(places) > 1:
            flag(
                MatrixRefusal.ORDERED_PAIR_NUMBERED_TWICE,
                f"({number}) used by {places}",
            )
    missing = sorted(set(range(1, expected + 1)) - set(numbered))
    if missing:
        flag(
            MatrixRefusal.ORDERED_PAIR_MISSING,
            f"{size} identities are {expected} directed pairs; the matrix is "
            f"missing {missing}",
        )

    claimed = attributed_pairs(text)
    unattributed = sorted(set(numbered) - claimed)
    if unattributed:
        flag(
            MatrixRefusal.PAIR_HAS_NO_REFUSING_MECHANISM,
            f"cells {unattributed} are numbered but no mechanism bullet says "
            "what refuses them",
        )

    for phrase, value in stated_pair_counts(text):
        if value != expected:
            flag(
                MatrixRefusal.STATED_COUNT_DISAGREES,
                f"prose says {phrase!r}; {size} identities are {expected}",
            )
    return findings


def test_the_matrix_covers_every_directed_pair_of_declared_identities() -> None:
    """The document as it stands. Everything below plants a defect into THIS."""
    assert scan_matrix(DOSSIER.read_text(encoding="utf-8")) == []


def test_the_matrix_reader_is_not_reading_an_empty_document() -> None:
    """POSITIVE CONTROL. Every rule in `scan_matrix` passes by finding nothing,
    so a reader that parsed no labels and no cells would report a clean matrix
    over a document that has neither."""
    text = DOSSIER.read_text(encoding="utf-8")
    labels = identity_labels(text)
    columns, rows = misuse_matrix(text)

    assert len(labels) >= 4, labels
    assert set(labels) == {label for label, _ in rows} == set(columns)
    assert len(rows) == len(labels)
    # The derived count is what every rule is measured against, so it is
    # asserted directly rather than left implicit in a green scan.
    assert sum(
        1
        for row_index, (_, cells) in enumerate(rows)
        for column_index, _ in enumerate(cells)
        if row_index != column_index
    ) == len(labels) * (len(labels) - 1)
    assert attributed_pairs(text) == set(range(1, len(labels) * (len(labels) - 1) + 1))
    assert stated_pair_counts(text), "the prose states no pair count to check"


# --- sensitivity: every matrix rule is shown to bite ------------------------


def _dossier_with(old: str, new: str) -> str:
    text = DOSSIER.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"anchor is not unique: {old[:60]!r}"
    return text.replace(old, new)


def _matrix_only(text: str, refusal: MatrixRefusal) -> MatrixFinding:
    findings = scan_matrix(text)
    matching = [f for f in findings if f.refusal is refusal]
    assert len(matching) == 1, f"expected exactly one {refusal}, got {findings}"
    return matching[0]


def test_an_identity_the_matrix_does_not_cover_is_refused() -> None:
    """THE PLANT THIS GUARD EXISTS FOR.

    A fifth identity added to the table while the matrix keeps its four axes is
    precisely the drift Michael's five-identity ruling names: the count of
    ordered pairs moves from twelve to twenty, and nothing in a hand-written
    matrix notices. The document must go red until the matrix covers it.
    """
    doctored = _dossier_with(
        "| 4 | `platform_release_evidence` | release evidence |",
        "| 6 | `key_escrow_probe` | escrow | "
        "`secret/dotmac/platform-cp/escrow-signing/primary` | a holder | "
        "a verifier |\n| 4 | `platform_release_evidence` | release evidence |",
    )
    findings = scan_matrix(doctored)
    axes = [
        f for f in findings if f.refusal is MatrixRefusal.AXES_DISAGREE_WITH_IDENTITIES
    ]
    assert len(axes) == 1, findings
    assert "escrow" in axes[0].detail
    # The stated counts go stale in the same edit, and reporting BOTH is right:
    # an editor who adds an identity has two registers to move, and being told
    # about one of them would send them round the loop twice.
    assert MatrixRefusal.STATED_IDENTITY_COUNT_DISAGREES in {
        f.refusal for f in findings
    }


def test_a_directed_pair_the_matrix_omits_is_refused() -> None:
    """A cell reusing another's number hides the missing one behind a count."""
    doctored = _dossier_with(
        "| (17) | (18) | (19) | (20) | must succeed |",
        "| (17) | (18) | (19) | (19) | must succeed |",
    )
    findings = scan_matrix(doctored)
    assert {f.refusal for f in findings} == {
        MatrixRefusal.ORDERED_PAIR_NUMBERED_TWICE,
        MatrixRefusal.ORDERED_PAIR_MISSING,
    }, findings


def test_a_pair_no_mechanism_claims_is_refused() -> None:
    """`each demonstrably able to refuse`: a numbered cell nobody attributed to
    a refusing mechanism was drawn, not checked."""
    doctored = _dossier_with(
        "- **(4), (8), (12), (16) — used as RECOVERY.**",
        "- **(4), (8), (12) — used as RECOVERY.**",
    )
    finding = _matrix_only(doctored, MatrixRefusal.PAIR_HAS_NO_REFUSING_MECHANISM)
    assert "[16]" in finding.detail


def test_a_diagonal_that_is_not_required_to_succeed_is_refused() -> None:
    """A matrix of refusals with no successes never proves the identities work.

    This is the same failure as a readiness probe that only ever returns 503:
    every refusal cell would pass against identities that refuse everything,
    including their own purpose.
    """
    doctored = _dossier_with(
        # A number OUTSIDE the derived range, so the plant tests the diagonal
        # rule alone. `(13)` is a real cell in a five-identity matrix and would
        # have fired the duplicate rule as well, making the assertion below pass
        # for a reason it does not name.
        "| **authorization** | must succeed |",
        "| **authorization** | (21) |",
    )
    finding = _matrix_only(doctored, MatrixRefusal.DIAGONAL_NOT_REQUIRED_TO_SUCCEED)
    assert "authorization used as authorization" in finding.detail


def test_a_prose_count_that_disagrees_with_the_matrix_is_refused() -> None:
    """The sentence and the table are two registers, and the sentence is the one
    a reader believes. It moved by hand twice; now it cannot move alone."""
    doctored = _dossier_with(
        "### 7b — purpose: the twenty ordered pairs",
        "### 7b — purpose: the thirty ordered pairs",
    )
    finding = _matrix_only(doctored, MatrixRefusal.STATED_COUNT_DISAGREES)
    assert "thirty" in finding.detail


def test_a_stated_identity_count_that_disagrees_is_refused() -> None:
    """The title said THREE while the table declared four, and had since the
    fourth identity landed. Nothing could see it: the count lived in prose and
    the identities lived in a table, and no check read both.

    This is the rule that found it, so it is planted rather than assumed.
    """
    doctored = _dossier_with(
        "# Signing identity mint dossier — five purpose-bound Ed25519 identities",
        "# Signing identity mint dossier — four purpose-bound Ed25519 identities",
    )
    finding = _matrix_only(doctored, MatrixRefusal.STATED_IDENTITY_COUNT_DISAGREES)
    assert "four purpose-bound" in finding.detail


def test_the_identity_count_reader_ignores_a_phrase_with_no_count() -> None:
    """SENSITIVITY, the other direction. `the authorization and observation
    identities` states no number, and a reader that treated the preceding word
    as one would refuse a correct sentence — noise that gets a guard disabled."""
    assert stated_identity_counts("the authorization and observation identities") == []
    assert stated_identity_counts("four identities") == [("four identities", 4)]


def test_an_unreadable_cell_refuses_rather_than_passing_as_clean() -> None:
    """ABSENT must be distinguishable from UNPARSED.

    Every rule above passes by finding nothing, so a cell the reader cannot
    parse would otherwise read exactly like a cell with nothing wrong with it.
    """
    doctored = _dossier_with("| (5) | must succeed |", "| see below | must succeed |")
    findings = scan_matrix(doctored)
    # TWO distinct findings, and reporting them separately is the point: the
    # cell cannot be read AND the directed pair it should have carried is now
    # uncovered. An aggregate would send an editor round the loop twice.
    assert {f.refusal for f in findings} == {
        MatrixRefusal.MATRIX_UNREADABLE,
        MatrixRefusal.ORDERED_PAIR_MISSING,
    }, findings
    unreadable = _matrix_only(doctored, MatrixRefusal.MATRIX_UNREADABLE)
    assert "see below" in unreadable.detail


def test_a_document_with_no_matrix_at_all_is_refused() -> None:
    """The strongest form of the same point: deleting the matrix must not read
    as a matrix with no problems in it."""
    text = DOSSIER.read_text(encoding="utf-8")
    without = text.replace("| holder \\ used as |", "| holder and use |")
    assert without != text
    finding = _matrix_only(without, MatrixRefusal.MATRIX_UNREADABLE)
    assert "no purpose-misuse matrix parsed" in finding.detail
