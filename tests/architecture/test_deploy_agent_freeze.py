"""The CP `deploy_agent` is FROZEN (build-once generic deploy, ruling M1).

Multi-product desired state is Deployment Control's, and the generic launch is
the Starter `dotmac-deploy-agent`. The CP deploy agent stays single-product and
staging-only until it is retired, so nothing may grow it quietly.

A freeze here is a RATCHET in both directions: the recorded content digest of
every file in the package (plus its migration), and the exact set of modules
outside the package that name it, must equal `deploy_agent_freeze.json`. A
change is therefore never silent: unfreezing, extending, retiring, or coupling
another module to it all edit the manifest in the same diff, where a reviewer
sees it. Nothing is derived from the tree it checks, so a planted change cannot
move the reference with it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("deploy_agent_freeze.json")
PACKAGE = "src/vendor_cp/deploy_agent"
MIGRATION = "alembic/versions/v022_deploy_agent.py"
NEEDLES = ("vendor_cp.deploy_agent", "from vendor_cp import deploy_agent")


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _digests(root: Path) -> dict[str, str]:
    paths = sorted((root / PACKAGE).rglob("*.py")) + [root / MIGRATION]
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def _importers(root: Path) -> list[str]:
    found = []
    for path in sorted((root / "src").rglob("*.py")):
        relative = str(path.relative_to(root))
        if relative.startswith(PACKAGE + "/"):
            continue
        text = path.read_text(encoding="utf-8")
        if any(needle in text for needle in NEEDLES):
            found.append(relative)
    return found


def _drift(recorded: dict[str, str], actual: dict[str, str]) -> list[str]:
    problems = [f"added {name}" for name in sorted(set(actual) - set(recorded))]
    problems += [f"removed {name}" for name in sorted(set(recorded) - set(actual))]
    problems += [
        f"changed {name}"
        for name in sorted(set(recorded) & set(actual))
        if recorded[name] != actual[name]
    ]
    return problems


def test_manifest_is_well_formed_and_names_the_ruling() -> None:
    manifest = _manifest()
    assert manifest["schema"] == "vendor_cp.deploy_agent_freeze/1"
    assert "M1" in str(manifest["ruling"]) and "FROZEN" in str(manifest["ruling"])
    files = manifest["files"]
    assert isinstance(files, dict) and files
    assert MIGRATION in files
    assert f"{PACKAGE}/service.py" in files


def test_deploy_agent_package_and_migration_are_byte_frozen() -> None:
    recorded = _manifest()["files"]
    assert isinstance(recorded, dict)
    assert _drift(recorded, _digests(ROOT)) == [], (
        "the CP deploy_agent is frozen (M1). Editing, adding or removing a file "
        "is an unfreeze: change tests/architecture/deploy_agent_freeze.json in "
        "the same diff and say why"
    )


def test_no_new_module_couples_to_the_frozen_agent() -> None:
    recorded = _manifest()["importers_outside_package"]
    assert _importers(ROOT) == recorded, (
        "the set of modules outside the package that name vendor_cp.deploy_agent "
        "changed; the freeze ratchet allows it to shrink or grow only through "
        "the manifest"
    )


def test_the_agent_stays_disabled_by_default() -> None:
    runtime = (ROOT / PACKAGE / "runtime.py").read_text(encoding="utf-8")
    assert 'os.environ.get("VENDOR_DEPLOY_AGENT_ENABLED", "false")' in runtime


def test_the_ratchet_can_fail(tmp_path: Path) -> None:
    """SENSITIVITY: a planted edit, addition and removal are each seen."""
    for name in (f"{PACKAGE}/service.py", f"{PACKAGE}/router.py", MIGRATION):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    recorded = _digests(tmp_path)
    assert _drift(recorded, _digests(tmp_path)) == []
    (tmp_path / PACKAGE / "service.py").write_bytes(b"# edited\n")
    (tmp_path / PACKAGE / "extra.py").write_bytes(b"")
    (tmp_path / PACKAGE / "router.py").unlink()
    assert _drift(recorded, _digests(tmp_path)) == [
        f"added {PACKAGE}/extra.py",
        f"removed {PACKAGE}/router.py",
        f"changed {PACKAGE}/service.py",
    ]
