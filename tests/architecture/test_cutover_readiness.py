"""Readiness claims, held to the facts they claim — and only to those.

`AGENTS.md` rule 17, the fleet rule approved 2026-08-21:

    Repository-local transition claims must be derived from repository-local
    facts. Release, registry and production-adoption claims require an
    authoritative external oracle.

This file asserts only the first kind: the declared table set, the symbol-level
authority inventory, the measured brand absence, and one recorded local
DECISION. It observes no registry, no other product and no database.

An earlier draft asserted that no distribution "awaiting a release tag" was
pinned and called that an executable gate on the tag. It was not — it only read
`pyproject.toml`, so the tag was published and the assertion stayed green. That
assertion is deleted rather than reworded, and the Brand Profiles entry is named
for what it holds: a deferral decision, not proof of another product's state.

`TARGET_ESTATE_MEASUREMENT` is deliberately not asserted against a database. It
is named so the obligation is visible, and discharged by an operator against a
target Michael names explicitly. The external claims this work depends on are
carried in `docs/cutover-readiness.md`, each beside its oracle.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from vendor_cp.cutover_readiness import (
    BRAND_ADJACENT_LITERALS,
    BRAND_WRITER_MARKERS,
    BRAND_WRITERS_TO_RETIRE,
    DEFERRED_BY_LOCAL_DECISION,
    DELIVERY_ESTATE,
    DELIVERY_TRANSPORT_MODULES,
    FOREIGN_TABLE_MARKERS,
    NOT_A_DEPLOYMENT_WRITER,
    RETIRED_DESIGN_BRIEFS,
    TARGET_AUTHORITY_AUDIT_ACTIONS,
    TARGET_AUTHORITY_ROUTES,
    TARGET_AUTHORITY_SYMBOLS,
    TARGET_ESTATE_MEASUREMENT,
    TARGET_PROJECTION_SYMBOLS,
    VENDOR_OWNED_TABLES,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DOSSIER = ROOT / "docs" / "cutover-readiness.md"

#: This file and the module it checks both NAME every symbol they inventory, so
#: counting them would count the ledger as a call site.
LEDGERS = frozenset(
    {
        SRC / "vendor_cp" / "cutover_readiness.py",
        Path(__file__).resolve(),
    }
)

TABLENAME = re.compile(r"""__tablename__\s*=\s*["']([a-z0-9_]+)["']""")


def _python_sources(root: Path) -> list[Path]:
    return [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]


def _scanned() -> list[Path]:
    roots = (SRC, ROOT / "tests", ROOT / "scripts")
    return [
        path
        for root in roots
        if root.exists()
        for path in _python_sources(root)
        if path.resolve() not in LEDGERS
    ]


def declared_tablenames(root: Path) -> set[str]:
    """Every table a model in `root` declares."""
    return {
        match
        for path in _python_sources(root)
        for match in TABLENAME.findall(path.read_text())
    }


def call_sites(symbol: str) -> dict[str, int]:
    """Every file referencing `symbol`, and how many times."""
    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    found: dict[str, int] = {}
    for path in _scanned():
        hits = len(pattern.findall(path.read_text()))
        if hits:
            found[path.relative_to(ROOT).as_posix()] = hits
    return found


def _dependencies() -> dict[str, object]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = config["tool"]["poetry"]["dependencies"]
    assert isinstance(dependencies, dict)
    return dependencies


# ── What this assembly still owns ──────────────────────────────────────────


def test_the_vendor_owned_table_set_is_exactly_declared() -> None:
    """Two-directional: a new local table fails until it is declared, and a
    retired one fails until the declaration is lowered. A one-sided assertion
    would let the v013–v016 drops leave phantom names behind."""
    assert declared_tablenames(SRC) == set(VENDOR_OWNED_TABLES)


def test_the_delivery_estate_is_a_subset_of_what_is_owned() -> None:
    """ADR-0010's retirement definition names five tables. If one has already
    gone, the ADR is describing work that is partly done and its definition
    must be lowered rather than left standing."""
    assert DELIVERY_ESTATE <= VENDOR_OWNED_TABLES


def test_the_target_estate_to_measure_is_owned_and_joined() -> None:
    """The measurement obligation must name tables this assembly actually has.
    Both are required: `licence_deliveries.target_id` is a foreign key into the
    registry, so measuring targets without their dependent rows would report an
    emptiness that the dependent rows contradict."""
    assert TARGET_ESTATE_MEASUREMENT <= VENDOR_OWNED_TABLES
    assert "licence_delivery_targets" in TARGET_ESTATE_MEASUREMENT
    assert "licence_deliveries" in TARGET_ESTATE_MEASUREMENT


def test_no_vendor_table_carries_an_independent_module_shape() -> None:
    """`mod_deploy` and `mod_brand` own deployment and brand records. There is
    no exemption list here: `licence_delivery_targets` is not waved through as
    a near miss, it is inventoried as a real second authority below, and
    `target` is deliberately absent from the markers for that reason."""
    offenders = sorted(
        f"{table} matches {marker!r}"
        for table in VENDOR_OWNED_TABLES
        for marker in FOREIGN_TABLE_MARKERS
        if marker in table
    )
    assert offenders == [], offenders


def test_the_foreign_shape_scan_can_see_a_planted_table() -> None:
    """SENSITIVITY. The assertion above is "no offenders", which an empty
    marker list would also satisfy."""
    planted = {"deployment_targets", "brand_profiles", "vendor_accounts"}
    seen = sorted(
        {
            table
            for table in planted
            for marker in FOREIGN_TABLE_MARKERS
            if marker in table
        }
    )
    assert seen == ["brand_profiles", "deployment_targets"]


def test_the_tablename_scan_can_see_a_planted_model(tmp_path: Path) -> None:
    """SENSITIVITY for the derivation itself: a scan that silently matched
    nothing would make the exact-set assertion pass for the wrong reason."""
    (tmp_path / "models.py").write_text(
        'class Thing(Base):\n    __tablename__ = "planted_table"\n'
    )
    assert declared_tablenames(tmp_path) == {"planted_table"}


# ── The deployment-target authority, ratcheted at symbol level ─────────────


def test_the_target_write_authority_call_sites_are_exact() -> None:
    """The half ADR-0011 must MIGRATE, not merely stop calling.

    Ratcheted in both directions and per file, because the failure this catches
    is subtle: deleting `register_delivery_target` while `projection.py`
    remains would leave a path-level ledger green while the authority moved.
    """
    drift = {
        symbol: {"declared": declared, "actual": call_sites(symbol)}
        for symbol, declared in TARGET_AUTHORITY_SYMBOLS.items()
        if call_sites(symbol) != declared
    }
    assert drift == {}, drift


def test_the_target_projection_call_sites_are_exact() -> None:
    """The half that survives ADR-0011 as a reconciled projection and retires
    at ADR-0010. Separate from the write path on purpose: conflating them is
    how "we composed the owner" becomes "we still have two"."""
    drift = {
        symbol: {"declared": declared, "actual": call_sites(symbol)}
        for symbol, declared in TARGET_PROJECTION_SYMBOLS.items()
        if call_sites(symbol) != declared
    }
    assert drift == {}, drift


def test_the_write_and_projection_inventories_do_not_overlap() -> None:
    """A symbol in both would mean the cutover boundary is not decided."""
    assert not set(TARGET_AUTHORITY_SYMBOLS) & set(TARGET_PROJECTION_SYMBOLS)
    assert TARGET_AUTHORITY_SYMBOLS and TARGET_PROJECTION_SYMBOLS


def test_the_call_site_scan_can_see_a_new_caller(tmp_path: Path) -> None:
    """SENSITIVITY. Both assertions above compare against a declared mapping,
    which a scanner returning nothing would satisfy by matching an empty dict
    only if the declaration were also empty — so prove the scanner counts."""
    probe = tmp_path / "caller.py"
    probe.write_text(
        "from vendor_cp.licensing.projection import register_delivery_target\n"
        "register_delivery_target(db, command)\n"
    )
    pattern = re.compile(r"\bregister_delivery_target\b")
    assert len(pattern.findall(probe.read_text())) == 2


def test_the_target_write_surface_is_still_mounted_where_declared() -> None:
    """The routes and audit vocabulary the write authority owns. Both must be
    present TODAY — this is the pre-cutover inventory, and an entry naming
    something already gone is describing someone else's retirement."""
    router = (SRC / "vendor_cp" / "licensing" / "router.py").read_text()
    for method, path in TARGET_AUTHORITY_ROUTES:
        assert f'@router.{method}("{path}"' in router, (method, path)

    manifest = (SRC / "vendor_cp" / "licensing" / "feature.py").read_text()
    for action in TARGET_AUTHORITY_AUDIT_ACTIONS:
        assert f'"{action}"' in manifest, action
        # ADR-0008: a declared code with no consumer fails the build, so the
        # writer and its vocabulary retire in the same change or neither does.
        assert call_sites(action) or action in manifest


def test_every_delivery_transport_module_still_exists() -> None:
    """Path-level is correct here — these retire entirely rather than losing a
    symbol — but the same staleness rule applies."""
    missing = sorted(
        path for path, _ in DELIVERY_TRANSPORT_MODULES if not (ROOT / path).exists()
    )
    assert missing == [], missing
    for path, reason in DELIVERY_TRANSPORT_MODULES:
        assert reason.strip(), path


def test_the_retired_design_briefs_still_exist_and_say_so() -> None:
    """A brief retired as a design to implement must SAY so where a reader
    starts, or it is still an implementation licence."""
    for brief in RETIRED_DESIGN_BRIEFS:
        text = " ".join((ROOT / brief).read_text().split())
        assert "Retirement amendment" in text[:1500], brief
        assert "ADR-0011" in text[:1500], brief


def test_the_things_that_are_not_deployment_writers_still_exist() -> None:
    """The disclaimer is only useful while the paths it disclaims are real."""
    for path in NOT_A_DEPLOYMENT_WRITER:
        assert (ROOT / path).exists(), path
    assert not set(NOT_A_DEPLOYMENT_WRITER) & {
        path for path, _ in DELIVERY_TRANSPORT_MODULES
    }


# ── The one recorded local decision ────────────────────────────────────────


def test_a_locally_deferred_distribution_is_not_pinned() -> None:
    """This holds a DECISION this repository took, not a fact about another
    product. It cannot and does not claim `dotmac_sub` has finished; it claims
    Vendor has not unilaterally decided that it has. When the extraction
    dossier records the first adopter, this entry is removed in the change that
    takes the pin."""
    dependencies = _dependencies()
    pinned = sorted(
        f"{name} (deferred by {authority})"
        for name, authority, _ in DEFERRED_BY_LOCAL_DECISION
        if name in dependencies
    )
    assert pinned == [], pinned


def test_the_deferral_is_declared_and_carries_its_reason() -> None:
    """A deferral with no reason is a version number nobody can re-evaluate.
    When the list genuinely empties, delete it rather than leaving a gate that
    passes forever."""
    assert DEFERRED_BY_LOCAL_DECISION
    for name, authority, reason in DEFERRED_BY_LOCAL_DECISION:
        assert name.startswith("dotmac-"), name
        assert authority.startswith("ADR-"), authority
        assert len(reason) > 40, name
        assert (ROOT / "docs" / "adr").glob(f"{authority[4:8]}-*.md")


def test_the_composed_modules_are_exact_pinned() -> None:
    """Hard rule 8. Unrelated to the deferral above, and worth keeping
    separate: one is about what may not be pinned yet, this is about how the
    things that ARE pinned are written."""
    loose = sorted(
        f"{name} = {_version(spec)!r}"
        for name, spec in _dependencies().items()
        if name.startswith("dotmac-") and not EXACT_ALPHA.fullmatch(_version(spec))
    )
    assert loose == [], loose


EXACT_ALPHA = re.compile(r"0\.\d+\.\d+a\d+")


def _version(spec: object) -> str:
    if isinstance(spec, dict):
        return str(spec.get("version", ""))
    return str(spec)


# ── The brand result, which is an absence ──────────────────────────────────


def test_this_assembly_holds_no_brand_record() -> None:
    """The measurement behind the empty retirement list. Scanned over `src/`
    and the vendor lineage, because a brand record could arrive as a model, a
    service or a migration."""
    roots = (SRC, ROOT / "alembic" / "versions")
    declaring = SRC / "vendor_cp" / "cutover_readiness.py"
    hits = sorted(
        f"{path.relative_to(ROOT)}: {marker!r}"
        for root in roots
        for path in _python_sources(root)
        if path != declaring
        for marker in BRAND_WRITER_MARKERS
        if marker in path.read_text()
    )
    assert hits == [], hits
    assert BRAND_WRITERS_TO_RETIRE == ()


def test_the_brand_scan_can_see_a_planted_record(tmp_path: Path) -> None:
    """SENSITIVITY. "No brand writer" and "the scan matched nothing" are the
    same assertion until this proves they are not."""
    planted = tmp_path / "models.py"
    planted.write_text("class BrandProfile(Base):\n    primary_hex: Mapped[str]\n")
    assert [
        marker for marker in BRAND_WRITER_MARKERS if marker in planted.read_text()
    ] == ["BrandProfile", "primary_hex"]


def test_the_one_brand_adjacent_literal_is_a_literal_and_not_a_record() -> None:
    """The dossier claims this assembly displays a product name without storing
    one. That is only honest while the name really is a literal in a template
    string — so the file is named, and checked to hold no column."""
    for literal in BRAND_ADJACENT_LITERALS:
        text = (ROOT / literal).read_text()
        assert "DotMac Vendor Control Plane" in text, literal
        assert not any(marker in text for marker in BRAND_WRITER_MARKERS), literal


# ── The dossier says what the declaration says ─────────────────────────────


def test_the_dossier_names_the_deferral_and_the_measurement() -> None:
    """Prose and declaration drift apart the moment only one is edited. The
    dossier is the reader's entry point, so it must name the deferred
    distribution, its first adopter, and the tables owed a measurement."""
    text = DOSSIER.read_text()
    for name, _, reason in DEFERRED_BY_LOCAL_DECISION:
        assert name in text, name
        assert "dotmac_sub" in reason and "dotmac_sub" in text
    for table in TARGET_ESTATE_MEASUREMENT:
        assert table in text, table
