"""The commercial-backfill dossier, held to the properties it claims.

Three families of check live here.

**The no-emission property.** A backfill report may carry counts, categories and
blocker reasons and nothing else. That is claimed structurally in
`vendor_cp.commercial_backfill.report`, and claiming it structurally is worth
nothing unless something proves the structure. So: the report types' annotations
are scanned for any value-carrying type, the `Count(` constructor is ratcheted to
one module, and the renderer is fed an identifier, an amount, a label and a
timestamp — one test each, because a single combined case passes as soon as the
first of the four is caught.

**Totality.** Every enumerated source row lands in exactly one bucket. Asserted
twice from opposite ends: `classify`'s control flow is walked for the shapes that
lose a row (a bare `return`, a `return None`, a `continue`), and the planner's
own totality invariant is exercised.

**The gates.** Both non-vacuous, and no condition needing an external oracle is
recorded as discharged — `AGENTS.md` rule 17. The declaration that produced
that rule, `AWAITING_RELEASE_TAG`, had exactly the shape this family exists to
refuse: an assertion implying a check it could not perform.

Every "no offenders" assertion here is paired with a sensitivity test that plants
an offender, because a scan that matched nothing satisfies it just as well.
"""

from __future__ import annotations

import ast
import re
import tomllib
from datetime import date
from pathlib import Path

import pytest

from vendor_cp.commercial_backfill import (
    cohort,
    comparator,
    gates,
    planner,
    report,
    transforms,
    vocabulary,
)
from vendor_cp.commercial_backfill import shadow as shadow_module
from vendor_cp.commercial_backfill.vocabulary import (
    BLOCKING_OUTCOMES,
    DIMENSION_ORDER,
    DIMENSION_SUBJECT,
    DIMENSIONS_BY_SOURCE_KIND,
    REPORT_ENUMS,
    TALLY_DOMAIN,
    Bucket,
    CadenceOutcome,
    Dimension,
    ParityVerdict,
    SourceKind,
    TallySubject,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "vendor_cp" / "commercial_backfill"
COMMAND = ROOT / "scripts" / "reconcile_backfill_shadow.py"
DOSSIER = ROOT / "docs" / "commercial-backfill-dossier.md"
READINESS = ROOT / "docs" / "cutover-readiness.md"

_A2_ORACLE_MARKERS = (
    "COMMERCIAL_AGREEMENTS_A2_RELEASE_RUN_REQUIRED_BEFORE_MERGE",
    "COMMERCIAL_AGREEMENTS_A2_PEELED_TAG_REQUIRED_BEFORE_MERGE",
)

#: The report surface. These are the modules a value could escape through, and
#: they are named rather than globbed so adding a module to the package is a
#: decision about whether it is one of them.
REPORT_SURFACE = (
    PACKAGE / "report.py",
    PACKAGE / "planner.py",
    PACKAGE / "comparator.py",
)

#: Types a report field may be annotated with. Everything else — `str`, `int`,
#: `Decimal`, `datetime`, `date`, `UUID`, `Any`, `object` — is a channel for the
#: four things a report may never emit.
SAFE_ANNOTATIONS = frozenset(
    {
        "Count",
        "Tally",
        "ParityLine",
        "ParitySubject",
        "ParityVerdict",
        "ReportEnum",
        "TallySubject",
        "Report",
    }
)


def _module(path: Path) -> ast.Module:
    return ast.parse(path.read_text())


def _dataclasses(tree: ast.Module) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            "dataclass" in ast.unparse(decorator) for decorator in node.decorator_list
        )
    ]


def _annotation_names(annotation: ast.expr) -> set[str]:
    """Every bare name in an annotation, with `tuple[...]`/`|` unwrapped."""
    return {node.id for node in ast.walk(annotation) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(annotation) if isinstance(node, ast.Attribute)
    }


# ── The no-emission property ───────────────────────────────────────────────


def test_no_report_field_is_annotated_with_a_value_carrying_type() -> None:
    """The structural half. A report holds counts and closed-enum members; a
    field typed `str` would be the one slot every identifier, amount, label and
    timestamp could travel through, and it would be added for a good reason."""
    offenders: list[str] = []
    tree = _module(PACKAGE / "report.py")
    for node in _dataclasses(tree):
        # `Count` is the one type that IS an integer — it is the boundary where a
        # cardinality becomes a report value, and it validates rather than
        # annotates its way to safety (non-negative, and never a bool).
        if node.name == "Count":
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign):
                continue
            names = _annotation_names(statement.annotation)
            unsafe = sorted(
                name
                for name in names
                if name not in SAFE_ANNOTATIONS and name not in {"tuple", "None"}
            )
            if unsafe:
                offenders.append(
                    f"{node.name}.{ast.unparse(statement.target)}: {unsafe}"
                )
    assert offenders == [], offenders


def test_the_annotation_scan_can_see_a_planted_field(tmp_path: Path) -> None:
    """SENSITIVITY. "No unsafe annotations" and "the scan found no dataclass"
    are the same assertion until this separates them."""
    planted = tmp_path / "report.py"
    planted.write_text(
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class Leaky:\n"
        "    subject: TallySubject\n"
        "    note: str\n"
    )
    found = [
        sorted(
            name
            for name in _annotation_names(statement.annotation)
            if name not in SAFE_ANNOTATIONS and name not in {"tuple", "None"}
        )
        for node in _dataclasses(_module(planted))
        for statement in node.body
        if isinstance(statement, ast.AnnAssign)
    ]
    assert ["str"] in found


def test_only_the_report_module_constructs_a_count() -> None:
    """A ratchet, and honestly a ratchet rather than a language guarantee.

    Counts are cardinalities obtained by counting members. The planner and the
    comparator never build one, so the numbers in a report come from `len()`
    over classified rows rather than from anything read off a source row.
    """
    constructing = sorted(
        path.relative_to(ROOT).as_posix()
        for path in PACKAGE.rglob("*.py")
        if re.search(r"\bCount\(", path.read_text())
    )
    assert constructing == ["src/vendor_cp/commercial_backfill/report.py"]


@pytest.mark.parametrize(
    ("planted", "kind"),
    [
        pytest.param(
            "BUCKET MAPPED 3\nSOURCE_KIND 0f9c2e1a-1111-4b3c-8a11-000000000000 1",
            "identifier",
            id="identifier",
        ),
        pytest.param("CURRENCY EXACT 1499.00", "amount", id="amount"),
        pytest.param(
            "BUCKET MAPPED 3\nEXCLUSION Acme Corporation 1", "label", id="label"
        ),
        pytest.param(
            "BUCKET MAPPED 3 2026-08-25T12:44:24Z", "timestamp", id="timestamp"
        ),
    ],
)
def test_the_render_check_refuses_each_forbidden_value(planted: str, kind: str) -> None:
    """SENSITIVITY, one case per forbidden value kind.

    Separate cases on purpose: a single combined string passes the moment the
    FIRST of the four is caught, and the timestamp is the one a token-wise check
    misses — a date is just a run of integers.
    """
    with pytest.raises(report.UnsafeReportValue):
        report.refuse_unless_in_vocabulary(planted)


def test_the_render_check_accepts_a_real_report() -> None:
    """NON-VACUITY for the four refusals above: a check that refused everything
    would pass all of them and be useless."""
    rendered = report.render(
        report.Report(
            parity=(),
            tallies=(
                report.tally(TallySubject.BUCKET, [Bucket.MAPPED, Bucket.MAPPED]),
            ),
        )
    )
    assert rendered == "BUCKET MAPPED 2"


def test_a_report_has_no_free_text_field() -> None:
    """The field that would be added for the best of reasons.

    A `note`, a `title`, a `summary`: one slot, and every value this type exists
    to exclude travels through it. Checked by name as well as by annotation,
    because a `note: TallySubject` would pass the annotation scan and still be
    the beginning of one.
    """
    named = {
        ast.unparse(statement.target)
        for node in _dataclasses(_module(PACKAGE / "report.py"))
        for statement in node.body
        if isinstance(statement, ast.AnnAssign)
    }
    assert not named & {"note", "title", "summary", "detail", "message", "label"}


def test_the_tally_refuses_a_member_of_another_domain() -> None:
    """A tally is a histogram over ONE closed domain. Mixing domains would let a
    caller assemble an arbitrary alphabet out of declared parts."""
    with pytest.raises(report.UnsafeReportValue):
        report.tally(TallySubject.BUCKET, [CadenceOutcome.MONTHLY])


def test_the_planner_and_the_comparator_take_no_writable_seam() -> None:
    """Dry-run and read-only, as signatures rather than as flags.

    A `Session`, a connection or an output path in either signature is the edit
    that turns a planner into a backfill, and it should be a review rather than
    a default argument.
    """
    forbidden = {"Session", "Connection", "Engine", "connection", "db"}
    offenders: list[str] = []
    for path in (PACKAGE / "planner.py", PACKAGE / "comparator.py"):
        for node in ast.walk(_module(path)):
            if not isinstance(node, ast.FunctionDef):
                continue
            names = {argument.arg for argument in node.args.args + node.args.kwonlyargs}
            annotations = {
                name
                for argument in node.args.args + node.args.kwonlyargs
                if argument.annotation is not None
                for name in _annotation_names(argument.annotation)
            }
            hit = sorted((names | annotations) & forbidden)
            if hit:
                offenders.append(f"{path.name}:{node.name}: {hit}")
    assert offenders == [], offenders


# ── Totality: every row in exactly one bucket ──────────────────────────────


def _classify_function() -> ast.FunctionDef:
    for node in ast.walk(_module(PACKAGE / "cohort.py")):
        if isinstance(node, ast.FunctionDef) and node.name == "classify":
            return node
    raise AssertionError("classify is gone — the totality claim has no subject")


def test_the_classifier_loses_no_row() -> None:
    """Walked as CONTROL FLOW, not as an assertion at the end.

    A `continue`, a bare `return` or a `return None` is how a row leaves without
    a verdict, and the resulting report still adds up — to the wrong total.
    """
    function = _classify_function()
    for node in ast.walk(function):
        assert not isinstance(node, ast.Continue), "a continue drops a row"
        if isinstance(node, ast.Return):
            assert node.value is not None, "a bare return drops a row"
            assert ast.unparse(node.value) != "None", "a None return drops a row"


def test_every_classifier_return_is_a_verdict() -> None:
    """The other half: returning something that is not a `RowVerdict` would put
    a row in no bucket at all while satisfying the check above."""
    returns = [
        ast.unparse(node.value)
        for node in ast.walk(_classify_function())
        if isinstance(node, ast.Return) and node.value is not None
    ]
    assert returns
    assert all(rendered.startswith("RowVerdict(") for rendered in returns), returns


def test_a_tally_refuses_a_value_that_is_not_a_declared_member() -> None:
    """The string spelling of a member is not the member.

    `"MAPPED"` reads identically in a rendered report and is arbitrary text.
    Refusing it is what stops the closed alphabet being reopened by a caller who
    found the enum inconvenient.
    """
    with pytest.raises(report.UnsafeReportValue):
        report.tally(TallySubject.BUCKET, [Bucket.MAPPED, "MAPPED"])


def test_a_verdict_cannot_hold_two_buckets_worth_of_evidence() -> None:
    """The three buckets are exclusive because the type refuses the overlap, not
    because the classifier happens to fill one field at a time."""
    with pytest.raises(cohort.SourceRowError):
        cohort.RowVerdict(
            bucket=Bucket.MAPPED,
            exclusion=vocabulary.ExclusionReason.ZERO_QUANTITY_LINE,
        )
    with pytest.raises(cohort.SourceRowError):
        cohort.RowVerdict(bucket=Bucket.BLOCKED)


# ── Vocabulary coherence ───────────────────────────────────────────────────


def test_every_tally_subject_has_a_declared_domain() -> None:
    assert set(TALLY_DOMAIN) == set(TallySubject)
    for domain in TALLY_DOMAIN.values():
        assert domain in REPORT_ENUMS, domain


def test_every_dimension_has_a_subject_and_appears_in_the_order() -> None:
    assert set(DIMENSION_SUBJECT) == set(Dimension)
    assert set(DIMENSION_ORDER) == set(Dimension)
    assert len(DIMENSION_ORDER) == len(Dimension), "the order repeats a dimension"
    for kind in SourceKind:
        assert set(DIMENSIONS_BY_SOURCE_KIND[kind]) <= set(Dimension)


def test_every_blocking_outcome_belongs_to_a_dimension_domain() -> None:
    """A blocking member of an enum no dimension tallies would block rows that
    no report could then explain."""
    domains = {TALLY_DOMAIN[DIMENSION_SUBJECT[d]] for d in Dimension}
    stranded = sorted(
        f"{type(member).__name__}.{member.name}"
        for member in BLOCKING_OUTCOMES
        if type(member) not in domains
    )
    assert stranded == [], stranded


def test_no_report_enum_member_carries_a_string_value() -> None:
    """`auto()` everywhere, deliberately: a member value is a second, unreviewed
    place for text to enter a report."""
    textual = sorted(
        f"{enum_type.__name__}.{member.name}"
        for enum_type in REPORT_ENUMS
        for member in enum_type
        if isinstance(member.value, str)
    )
    assert textual == [], textual


def test_the_digest_vocabulary_is_imported_and_not_restated() -> None:
    """One opinion about what a content digest is. The frozen-content dimension
    maps the approvals module's rejection reasons one for one, so a reason added
    there fails HERE rather than being silently unmapped."""
    from vendor_cp.approvals_authority import DIGEST_REJECTION_REASONS

    assert set(transforms.DIGEST_REJECTION_OUTCOMES) == set(DIGEST_REJECTION_REASONS)


def test_the_agreement_status_sets_partition_the_vocabulary() -> None:
    """The four sets must not overlap, or a status's fate depends on which
    branch is written first."""
    from dotmac_commercial_agreements import AgreementStatus

    sets = (
        cohort.PRE_COMMERCIAL_STATUSES,
        cohort.ENDED_STATUSES,
        cohort.LIVE_STATUSES,
        cohort.SUPERSEDED_STATUSES,
    )
    for index, left in enumerate(sets):
        for right in sets[index + 1 :]:
            assert not left & right
    assert cohort.KNOWN_AGREEMENT_STATUSES == frozenset(
        status.name for status in AgreementStatus
    )


# ── The source projection names attributes that exist ──────────────────────

#: Each source-row field, and the attribute in this assembly it is projected
#: from. Held against the real declaration rather than against the prose: the
#: dossier can say anything, and this is what makes it be true.
SOURCE_PROJECTION = {
    "src/vendor_cp/offers/models.py": (
        "product_code",
        "offer_code",
        "version",
        "amount",
        "currency_code",
    ),
    "src/vendor_cp/contracts/adapter.py": (
        "unit_amount",
        "unit_currency_code",
        "quantity",
        "content_hash",
        "status",
        "offer_ref",
        "line_no",
        "superseded_by_id",
        "term_start",
        "term_end_exclusive",
    ),
}


def test_the_source_projection_reads_attributes_that_exist() -> None:
    """A mapping dossier that named a field nobody has is a dossier describing a
    system that does not exist, and it reads exactly as confidently."""
    missing: list[str] = []
    for relative, attributes in SOURCE_PROJECTION.items():
        text = (ROOT / relative).read_text()
        missing += [
            f"{relative}: {attribute}"
            for attribute in attributes
            if not re.search(rf"\b{re.escape(attribute)}\b", text)
        ]
    assert missing == [], missing


def test_agreement_enumeration_is_the_exact_pinned_owner_reader() -> None:
    """The local fact behind `COHORT_FULLY_ENUMERABLE`.

    Vendor exposes one bounded page adapter over the a2 top-level public API.
    It neither queries the module schema nor invents a second estate reader.
    """
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependency = project["tool"]["poetry"]["dependencies"][
        "dotmac-commercial-agreements"
    ]
    assert dependency["version"] == "0.1.0a2"

    adapter_path = ROOT / "src" / "vendor_cp" / "contracts" / "adapter.py"
    tree = _module(adapter_path)
    public_aliases = {
        (alias.name, alias.asname)
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.module == "dotmac_commercial_agreements"
        for alias in node.names
    }
    assert ("list_agreements", "module_list_agreements") in public_aliases

    listing = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "list_agreements"
    )
    calls = {
        node.func.id
        for node in ast.walk(listing)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "module_list_agreements" in calls
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"execute", "query", "scalars"}
        for node in ast.walk(listing)
    )

    walker_path = PACKAGE / "enumeration.py"
    walker = _module(walker_path)
    walk = next(
        node
        for node in walker.body
        if isinstance(node, ast.FunctionDef) and node.name == "walk_agreement_lines"
    )
    calls = {
        ast.unparse(node.func) for node in ast.walk(walk) if isinstance(node, ast.Call)
    }
    assert "list_agreements" in calls
    execute_calls = [
        node
        for node in ast.walk(walk)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    ]
    assert len(execute_calls) == 1
    assert ast.unparse(execute_calls[0]) == "db.execute(text(_READ_ONLY_SNAPSHOT))"
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"query", "scalars"}
        for node in ast.walk(walk)
    )


def test_agreements_a2_pin_has_immutable_release_oracles() -> None:
    """A source pin does not prove a release or a pinnable tag.

    This intentionally blocks the adoption until the release captain replaces
    the preparation markers with both exact external coordinates.
    """
    text = READINESS.read_text()
    assert not any(marker in text for marker in _A2_ORACLE_MARKERS)
    assert "Commercial Agreements a2 is deliberately absent" not in text
    assert "release oracle pending" not in text
    assert "| `dotmac-commercial-agreements` | `0.1.0a2` | a2 | current |" in text
    assert re.search(
        r"dotmac-commercial-agreements` `0\.1\.0a2` is published and "
        r"installable \| `release_run` \| `dotmac_starter_mt` release run "
        r"`[0-9]+`",
        text,
    )
    assert re.search(
        r"dotmac-commercial-agreements-v0\.1\.0a2`, peeled commit " r"`[0-9a-f]{40}`",
        text,
    )


def test_full_enumeration_local_fact_is_discharged() -> None:
    condition = next(
        condition
        for condition in gates.INCUMBENT_WRITER_RETIREMENT_GATE.conditions
        if condition.code == "COHORT_FULLY_ENUMERABLE"
    )
    assert condition.evidence is gates.EvidenceKind.LOCAL_FACT
    assert condition.discharged is True


def test_enumeration_gate_keeps_the_upstream_reader_release_explicit() -> None:
    condition = next(
        condition
        for condition in gates.INCUMBENT_WRITER_RETIREMENT_GATE.conditions
        if condition.code == "TYPED_PAGINATED_AGREEMENT_READER_RELEASED"
    )
    assert condition.evidence is gates.EvidenceKind.RELEASE_RUN
    assert "dotmac-commercial-agreements" in condition.owner
    assert "typed paginated agreement reader" in condition.statement
    assert condition.discharged is False


def test_term_end_is_normalized_once_at_the_typed_adapter_boundary() -> None:
    adapter = (ROOT / "src" / "vendor_cp" / "contracts" / "adapter.py").read_text()
    cohort_source = (PACKAGE / "cohort.py").read_text()
    command_source = COMMAND.read_text()

    assert adapter.count("end_exclusive_from_inclusive(value.expiry_date)") == 1
    assert "term_end_exclusive" in adapter
    assert "term_end_exclusive" in cohort_source
    assert "term_end_exclusive" in command_source
    for source in (cohort_source, command_source):
        assert "term_end_convention" not in source


# ── The rehearsal shadow ───────────────────────────────────────────────────


#: A SQL `GRANT` STATEMENT, not the word. Prose in these files discusses granting
#: at length — "it does not grant", "emits no `GRANT` at all" — and a bare
#: substring scan would fail on the very sentences that state the property. The
#: privilege list is what makes it a statement rather than a noun.
GRANT_STATEMENT = re.compile(
    r"\bGRANT\s+(ALL|SELECT|INSERT|UPDATE|DELETE|USAGE|CREATE|CONNECT|EXECUTE)\b",
    re.IGNORECASE,
)


def test_the_shadow_repair_emits_no_grant() -> None:
    """The final-DML-grant gate's one discharged condition, as a check.

    Vendor's runtime role gains nothing from this work. The repair revokes; it
    never grants, and neither does the command that prints it.
    """
    emitted = "\n".join(
        (
            *shadow_module.CREATE_SQL,
            shadow_module.REVOKE_SQL,
            *shadow_module.repair_statements(()),
        )
    )
    assert GRANT_STATEMENT.search(emitted) is None
    assert GRANT_STATEMENT.search(COMMAND.read_text()) is None
    assert "REVOKE ALL" in shadow_module.REVOKE_SQL


def test_the_grant_scan_can_see_a_planted_grant() -> None:
    """SENSITIVITY, in both directions.

    It must catch a real statement, and it must NOT catch the prose that states
    the property — which is the failure a substring scan produces, on the exact
    files that document the rule.
    """
    assert GRANT_STATEMENT.search("GRANT INSERT ON bf_rehearsal.shadow_verdicts")
    assert GRANT_STATEMENT.search("GRANT ALL ON SCHEMA bf_rehearsal TO platform_api")
    assert GRANT_STATEMENT.search("It does not grant.") is None
    assert GRANT_STATEMENT.search("emits no `GRANT` at all") is None


def test_the_shadow_declares_no_table_and_holds_no_timestamp() -> None:
    """Two properties in one place because they defend each other.

    No `__tablename__` anywhere in the package, so the declared vendor-owned
    table set in `vendor_cp.cutover_readiness` does not move and nothing here
    reaches a production database. And no timestamp column, which is what makes
    a replay byte-identical rather than a diff somebody has to explain.
    """
    declaring = re.compile(r"""__tablename__\s*=\s*["']""")
    for path in PACKAGE.rglob("*.py"):
        # The ASSIGNMENT, matching `test_cutover_readiness.py`'s own scan. The
        # module docstrings name the token while explaining that nothing here
        # declares one, and a bare substring check would fail on the sentence
        # that states the property.
        assert not declaring.search(path.read_text()), path
    created = "\n".join(shadow_module.CREATE_SQL).lower()
    for banned in ("timestamptz", "timestamp", "now()", "default current", "serial"):
        assert banned not in created, banned


def test_the_shadow_literal_refuses_anything_outside_the_closed_sets() -> None:
    """SENSITIVITY for the `S608` per-file ignore in `pyproject.toml`.

    That ignore rests on a claim — nothing that could need escaping can reach a
    statement — and this is the check the claim rests on rather than the comment.
    """
    for planted in ("acme'; DROP TABLE x; --", "Acme Corp", "1499.00", "MAPPED "):
        with pytest.raises(shadow_module.UnsafeShadowValue):
            shadow_module._literal(planted)
    assert shadow_module._literal("MAPPED") == "'MAPPED'"
    assert shadow_module._literal("a" * 64) == f"'{'a' * 64}'"


def test_the_shadow_repair_is_deterministic() -> None:
    """Two runs over the same verdicts emit identical text, or a reviewer
    diffing two rehearsals reads an ordering as a change."""
    rows = _sample_rows()
    outcome = planner.plan(rows, _rules(), enumerated=frozenset(SourceKind))
    first = shadow_module.repair_statements(outcome.verdicts)
    second = shadow_module.repair_statements(tuple(reversed(outcome.verdicts)))
    assert first == second


def test_the_shadow_columns_cover_every_dimension() -> None:
    assert set(shadow_module.DIMENSION_COLUMNS) == set(Dimension)
    for column in shadow_module.DIMENSION_COLUMNS.values():
        assert column in shadow_module.COLUMNS


# ── The two gates ──────────────────────────────────────────────────────────


def test_gate_state_is_derived_and_every_gate_is_non_vacuous() -> None:
    """A gate cannot open merely because its condition list was empty."""
    for gate in gates.GATES:
        assert gate.conditions, gate.name
        assert gate.state() in set(gates.GateState), gate.name


def test_no_condition_needing_an_oracle_is_recorded_as_discharged() -> None:
    """`AGENTS.md` rule 17, as a check rather than as a habit.

    `AWAITING_RELEASE_TAG` is the known-bad case: a declaration whose shape
    implied a check it could not perform, which stayed green through the very
    event it claimed to gate. A condition whose evidence is a release run, a
    peeled tag, a deploy run or an adoption citation cannot be settled from
    inside this repository, and the type refuses to record it as settled.
    """
    for gate in gates.GATES:
        for condition in gate.conditions:
            if condition.evidence is not gates.EvidenceKind.LOCAL_FACT:
                assert not condition.discharged, condition.code


def test_a_non_local_condition_cannot_be_constructed_as_discharged() -> None:
    """SENSITIVITY: the refusal is structural, so plant one."""
    with pytest.raises(ValueError):
        gates.GateCondition(
            code="PLANTED",
            evidence=gates.EvidenceKind.RELEASE_RUN,
            owner="nobody",
            statement="a claim about a registry that this repository cannot see",
            discharged=True,
        )


def test_every_gate_condition_is_reviewable() -> None:
    """A gate over an empty or unowned condition list passes for the wrong
    reason forever."""
    assert gates.GATES
    codes: list[str] = []
    for gate in gates.GATES:
        assert gate.conditions, gate.name
        for condition in gate.conditions:
            assert condition.owner.strip(), condition.code
            assert len(condition.statement) > 40, condition.code
            codes.append(f"{gate.name}.{condition.code}")
    assert len(codes) == len(set(codes)), "a condition code repeats"


def test_the_discharged_conditions_are_exactly_the_local_facts_earned() -> None:
    """Two local conditions are settled: the owner reader makes the cohort
    enumerable, and this work still grants Vendor's runtime role nothing.

    Ratcheted so a later change cannot mark another one settled without moving
    this line.
    """
    discharged = sorted(
        condition.code
        for gate in gates.GATES
        for condition in gate.conditions
        if condition.discharged
    )
    assert discharged == [
        "COHORT_FULLY_ENUMERABLE",
        "NO_VENDOR_RUNTIME_DML_ADDED",
    ], discharged


# ── The dossier says what the declarations say ─────────────────────────────


def test_the_dossier_names_every_category_a_report_can_emit() -> None:
    """Prose and declaration drift apart the moment only one is edited, and the
    dossier is where a reader starts."""
    text = DOSSIER.read_text()
    missing = sorted(
        f"{enum_type.__name__}.{member.name}"
        for enum_type in REPORT_ENUMS
        for member in enum_type
        if member.name not in text
    )
    assert missing == [], missing


def test_the_dossier_names_both_gates_and_every_condition() -> None:
    text = DOSSIER.read_text()
    for gate in gates.GATES:
        assert gate.name in text, gate.name
        for condition in gate.conditions:
            assert condition.code in text, condition.code


def test_the_dossier_takes_no_authority_decision() -> None:
    """This task contracts a backfill; it does not choose who owns billing.

    A dossier that quietly named an owner would be an authority decision wearing
    a mapping document's clothes, and hard rule 12 wants that in an ADR with a
    checked premise instead.
    """
    flattened = " ".join(DOSSIER.read_text().split())
    assert "does not choose" in flattened
    assert "TARGET_AUTHORITY_ACCEPTED" in flattened


# ── Shared fixtures for the checks above ───────────────────────────────────


def _rules() -> cohort.CohortRules:
    return cohort.CohortRules(declared_product_codes=frozenset({"acme"}))


def _sample_rows() -> tuple[cohort.SourceRow, ...]:
    return (
        cohort.SourceRow(
            kind=SourceKind.AGREEMENT_LINE,
            fingerprint="a" * 64,
            amount="10.00",
            currency_code="NGN",
            product_code="acme",
            agreement_status="ACTIVE",
            content_hash="c" * 64,
            term_start=date(2026, 1, 1),
            term_end_exclusive=date(2027, 1, 1),
        ),
        cohort.SourceRow(
            kind=SourceKind.OFFER_VERSION,
            fingerprint="b" * 64,
            amount="10.00",
            currency_code="NGN",
            product_code="acme",
        ),
    )


def test_the_comparator_keeps_the_two_parity_claims_apart() -> None:
    """The failure worth catching: every row present, every meaning wrong.

    Row-count parity matches and semantic parity does not, in the same report,
    and there is no combined verdict anywhere for a reader to mistake for one.
    """
    outcome = planner.plan(_sample_rows(), _rules(), enumerated=frozenset(SourceKind))
    observation = comparator.observe(
        row_count=2,
        dimension_counts={Dimension.CADENCE: {CadenceOutcome.MONTHLY: 1}},
    )
    result = comparator.compare(outcome, observation)
    verdicts = {line.subject: line.verdict for line in result.parity}
    assert verdicts[vocabulary.ParitySubject.ROW_COUNT] is ParityVerdict.MATCHED
    assert verdicts[vocabulary.ParitySubject.TARGET_SEMANTIC] is ParityVerdict.DIVERGED
    assert len(result.parity) == 2, "a third, combined verdict appeared"
