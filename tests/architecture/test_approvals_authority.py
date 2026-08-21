"""The module is the approval authority, and the legacy writer is gone for good.

The cutover contract's retirement gate was "the legacy `evaluate` has no
remaining caller". That gate is now satisfied in the strongest available way —
the module does not exist — and the ratchet is kept at zero rather than deleted,
because a guard that stops mattering the moment it passes stops mattering exactly
when a regression would become invisible.

What is checked here:

* the retired writer has ZERO call sites, and the detector can still see one;
* only the ADAPTER speaks to `dotmac_approvals`; composition may name it, nothing
  else may;
* the declared eligibility mapping and digest translation — written during the
  contract phase, before any code used them — are the ones the adapter uses;
* the pin is exact;
* lifecycle: composed and authoritative in code is NOT adopted.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from uuid import UUID

import pytest
from import_scanner import (
    reaches_module,
    scan_imports,
    source_files,
    submodule_reach_ins,
)

from vendor_cp.approvals_authority import (
    ACTOR_MAPPING,
    ADAPTER_MODULE,
    AUTHORITY,
    COARSE_ELIGIBILITY_RULE,
    DIGEST_REJECTION_REASONS,
    MODULE_DIGEST_PREFIX,
    PLATFORM_ADMIN_ROLE_ID,
    RETIRED_LOCAL_WRITER,
    RETIRED_WRITER_CALL_SITES,
    VENDOR_DIGEST_LENGTH,
    digest_rejection_reason,
    translate_digest,
)

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PACKAGE = SRC / "vendor_cp"

#: Modules permitted to name the module at all: the adapter, which is the seam,
#: plus composition, which must name the manifest and the migration locator.
PERMITTED_NAMERS = {
    "vendor_cp/approvals/adapter.py",
    "vendor_cp/assembly.py",
    "vendor_cp/migrations.py",
}


def _refs(path: Path):
    return scan_imports(path, source_root=SRC)


# ── The retired writer, ratcheted at zero ───────────────────────────────────


def test_the_legacy_writer_no_longer_exists() -> None:
    """The strongest form of "no remaining caller": nothing to call."""
    assert not (PACKAGE / "approvals" / "service.py").exists()
    assert not (PACKAGE / "approvals" / "models.py").exists()


def test_no_source_file_calls_the_retired_writer() -> None:
    """Zero, and it stays zero."""
    callers = sorted(
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), RETIRED_LOCAL_WRITER)
    )
    assert callers == [], callers
    assert RETIRED_WRITER_CALL_SITES == frozenset()


def test_the_call_site_ratchet_can_still_see_a_caller(tmp_path: Path) -> None:
    """SENSITIVITY. An empty result is what this guard asserts, which is exactly
    what a broken detector also produces — so prove it still detects one."""
    package = tmp_path / "src" / "vendor_cp" / "somewhere"
    package.mkdir(parents=True)
    probe = package / "probe.py"
    probe.write_text(f"from {RETIRED_LOCAL_WRITER} import evaluate\n")
    assert reaches_module(
        scan_imports(probe, source_root=tmp_path / "src"), RETIRED_LOCAL_WRITER
    )


# ── The adapter is the only seam ────────────────────────────────────────────


def test_only_the_adapter_and_composition_name_the_module() -> None:
    """A second caller is a second mapping, and two mappings drift."""
    namers = {
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if reaches_module(_refs(path), AUTHORITY)
        or submodule_reach_ins(_refs(path), AUTHORITY)
    }
    assert namers == PERMITTED_NAMERS, sorted(namers ^ PERMITTED_NAMERS)


def test_only_the_adapter_reaches_the_modules_service_surface() -> None:
    """Composition names the manifest and the migration locator; the SERVICE
    surface is the adapter's alone."""
    reachers = sorted(
        path.relative_to(SRC).as_posix()
        for path in source_files(PACKAGE)
        if f"{AUTHORITY}.service" in submodule_reach_ins(_refs(path), AUTHORITY)
    )
    assert reachers == [ADAPTER_MODULE.replace(".", "/") + ".py"], reachers


def test_the_adapter_is_typed_at_the_seam() -> None:
    """No `Any` where Vendor meets the module: a wrong shape must be a type
    error at the call site, not a row in the wrong shape."""
    source = (PACKAGE / "approvals" / "adapter.py").read_text()
    assert ": Any" not in source
    assert "-> Any" not in source
    assert "Any]" not in source


# ── The declared mapping is the one in use ──────────────────────────────────


def test_the_eligibility_mapping_is_declared_and_stable() -> None:
    assert COARSE_ELIGIBILITY_RULE == "any_authenticated_platform_admin"
    assert str(UUID(PLATFORM_ADMIN_ROLE_ID)) == PLATFORM_ADMIN_ROLE_ID
    assert ACTOR_MAPPING


def test_the_adapter_uses_the_declared_mapping() -> None:
    """INDEPENDENT EXPECTED TRUTH: the adapter must take these from the
    declaration, not restate them. A second copy of a role id is a second thing
    to get wrong."""
    source = (PACKAGE / "approvals" / "adapter.py").read_text()
    assert "from vendor_cp.approvals_authority import" in source
    assert "PLATFORM_ADMIN_ROLE_ID" in source
    assert "translate_digest" in source
    assert (
        PLATFORM_ADMIN_ROLE_ID not in source
    ), "the role id is restated in the adapter instead of imported"


def test_the_router_enforces_the_rule_the_mapping_describes() -> None:
    """The mapping claims Vendor's eligibility rule is `require_platform_admin`
    and that the approver is the acting admin. This reads the router."""
    router = (PACKAGE / "approvals" / "router.py").read_text()
    assert "require_platform_admin" in router
    assert "approver_id=admin.id" in router


# ── Digest translation ──────────────────────────────────────────────────────


def test_a_valid_digest_translates() -> None:
    vendor = "a" * VENDOR_DIGEST_LENGTH
    assert digest_rejection_reason(vendor) is None
    assert translate_digest(vendor) == f"{MODULE_DIGEST_PREFIX}{vendor}"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param("", "empty", id="empty"),
        pytest.param(f"sha256:{'a' * 64}", "already_prefixed", id="already-prefixed"),
        pytest.param("a" * 63, "wrong_length", id="too-short"),
        pytest.param("A" * 64, "uppercase", id="uppercase"),
        pytest.param("g" * 64, "non_hex", id="non-hex"),
    ],
)
def test_every_untranslatable_digest_is_refused(value: str, reason: str) -> None:
    """Nothing is normalised into validity: a digest that needed repairing is a
    digest whose provenance is unknown."""
    assert digest_rejection_reason(value) == reason
    with pytest.raises(ValueError, match="not translatable"):
        translate_digest(value)


def test_every_declared_rejection_reason_is_reachable() -> None:
    produced = {
        digest_rejection_reason(value)
        for value in ("", f"sha256:{'a' * 64}", "a" * 63, "A" * 64, "g" * 64)
    }
    assert produced == set(DIGEST_REJECTION_REASONS)


# ── Pin and lifecycle ───────────────────────────────────────────────────────


def test_the_module_is_pinned_exactly() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["tool"]["poetry"]["dependencies"]["dotmac-approvals"] == {
        "version": "0.1.0a5",
        "source": "forgejo",
    }


def test_authoritative_in_code_is_not_marked_adopted() -> None:
    """Lifecycle stays below adopted until the new owner actually runs in
    production. Composed and authoritative in code is not the same claim, and
    conflating them is how a status board starts lying."""
    # Whitespace collapsed. This repo has been bitten twice by a prose assertion
    # failing on an 80-column line wrap rather than on meaning, and the tempting
    # fix each time is to loosen the assertion until it checks nothing.
    authority = " ".join((PACKAGE / "approvals_authority.py").read_text().split())
    assert "not** adopted" in authority
    assert "has not run in production" in authority
