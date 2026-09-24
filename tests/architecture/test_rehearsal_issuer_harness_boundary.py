"""The disposable issuer harness cannot become application composition."""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock
from zipfile import ZipFile

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "rehearsal_issuer_harness"

# The harness is intentionally outside the installed application package and
# the default test collection. Hosted CI does not put the repository root on
# sys.path, so load this excluded source explicitly and then restore sys.path.
sys.path.insert(0, str(ROOT))
try:
    from rehearsal_issuer_harness.artifacts import (  # noqa: E402
        read_public_lock,
        verify_public_wheelhouse,
        verify_wheels,
    )
    from rehearsal_issuer_harness.conftest import (  # noqa: E402
        _verify_role_contracts,
    )
finally:
    sys.path.remove(str(ROOT))


_STDLIB_ROOTS = {
    "__future__",
    "base64",
    "binascii",
    "collections",
    "concurrent",
    "dataclasses",
    "datetime",
    "email",
    "hashlib",
    "importlib",
    "json",
    "os",
    "pathlib",
    "re",
    "typing",
    "uuid",
    "zipfile",
}
_INSTALLED_ROOTS = {
    "alembic",
    "cryptography",
    "dotmac_deployment_control",
    "dotmac_kernel",
    "packaging",
    "psycopg",
    "pytest",
    "sqlalchemy",
}
_SEAM = "vendor_cp.deployment.rehearsal_issuer_seam"


def _imports(source: str) -> set[str]:
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                found.add("<relative import>")
            else:
                found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _offenders(imports: set[str]) -> set[str]:
    internal = {path.stem for path in HARNESS.glob("*.py")} | {"alembic"}
    allowed = _STDLIB_ROOTS | _INSTALLED_ROOTS
    return {
        name
        for name in imports
        if not (
            name == _SEAM
            or name.startswith(_SEAM + ".")
            or name.split(".", 1)[0] in allowed
            or name == "rehearsal_issuer_harness"
            or (
                name.startswith("rehearsal_issuer_harness.")
                and name.split(".")[1] in internal
            )
        )
    }


def test_harness_isolated_from_application_and_product_imports() -> None:
    assert HARNESS.is_dir()
    assert not HARNESS.is_relative_to(ROOT / "src")
    for path in HARNESS.rglob("*.py"):
        assert _offenders(_imports(path.read_text())) == set(), path
    assert _offenders(
        _imports("from vendor_cp import main\nimport dotmac_erp.service")
    ) == {
        "vendor_cp.main",
        "dotmac_erp.service",
    }
    assert _offenders(_imports("from vendor_cp.deployment import assembly")) == {
        "vendor_cp.deployment.assembly"
    }
    assert (
        _offenders(_imports("import vendor_cp.deployment.rehearsal_issuer_seam"))
        == set()
    )
    assert _offenders(_imports("from vendor_cp import deployment")) == {
        "vendor_cp.deployment"
    }
    assert any(
        name.startswith(_SEAM + ".")
        for name in _imports((HARNESS / "test_issuer.py").read_text())
    )
    runtime = (HARNESS / "runtime.py").read_text()
    assert "vendor_cp.deployment.rehearsal_issuer_seam" in runtime
    assert "issue_rehearsal_issuer_authorization_for_plan" in runtime
    assert "dict(invocation.to_control_request())" in runtime
    source = "\n".join(path.read_text() for path in HARNESS.rglob("*.py"))
    assert "request_rollout(" not in source
    assert "dispatch_attempt(" not in source


def test_lock_and_verifier_are_wired_to_exact_artifacts() -> None:
    lock = json.loads((HARNESS / "artifacts.json").read_text())
    assert set(lock["artifacts"]) == {"dotmac-deployment-control", "dotmac-kernel"}
    for item in lock["artifacts"].values():
        assert item["filename"].endswith(".whl")
        assert len(item["sha256"]) == 64
        assert len(item["source_commit"]) == 40
        assert "/" not in item["filename"]
        assert "branch" not in item and "path" not in item
    verifier = (HARNESS / "artifacts.py").read_text()
    assert "hashlib.sha256(path.read_bytes()).hexdigest()" in verifier
    assert 'info["Name"]' in verifier and 'info["Version"]' in verifier
    assert "dotmac-kernel (>=0.1.0a100)" in verifier
    public = read_public_lock()
    assert len(public) == 31
    assert public["email-validator"].version == "2.3.0"
    assert public["dnspython"].version == "2.8.0"
    assert public["psycopg-binary"].version == "3.3.4"
    assert public["greenlet"].version == "3.5.4"
    assert "read_public_lock()" in verifier
    assert "verify_public_wheelhouse(public_wheelhouse)" in verifier
    assert (
        "verify_wheels(control_wheel, kernel_wheel)"
        in (HARNESS / "conftest.py").read_text()
    )
    assert (
        'parser.addoption("--public-wheelhouse", type=Path)'
        in (HARNESS / "conftest.py").read_text()
    )


def test_planted_mutable_locator_and_wrong_bytes_fail_lock(tmp_path: Path) -> None:
    source = tmp_path / "main"
    source.write_text("mutable checkout")
    with pytest.raises(ValueError, match="existing wheel path"):
        verify_wheels(source, source)
    lock = json.loads((HARNESS / "artifacts.json").read_text())
    filename = lock["artifacts"]["dotmac-deployment-control"]["filename"]
    bad_wheel = tmp_path / filename
    bad_wheel.write_bytes(b"not the locked wheel")
    with pytest.raises(ValueError, match="wheel bytes differ"):
        verify_wheels(bad_wheel, source)


def test_planted_unhashed_public_dependency_fails(tmp_path: Path) -> None:
    original = (HARNESS / "public-requirements.lock").read_text()
    planted = tmp_path / "public-requirements.lock"
    planted.write_text(original.replace("--hash=sha256:", "--unchecked=sha256:", 1))
    with pytest.raises(ValueError, match="unrecognized line"):
        read_public_lock(planted)


def test_planted_missing_greenlet_fails_even_with_same_count(tmp_path: Path) -> None:
    original = (HARNESS / "public-requirements.lock").read_text()
    start = original.index("greenlet==3.5.4 \\\n")
    end = original.index("idna==3.18 \\\n", start)
    planted = tmp_path / "public-requirements.lock"
    planted.write_text(
        original[:start]
        + "replacement==1.0 \\\n    --hash=sha256:"
        + "0" * 64
        + "\n"
        + original[end:]
    )
    with pytest.raises(ValueError, match="SQLAlchemy's Linux greenlet dependency"):
        read_public_lock(planted)


def _fake_wheel(path: Path, name: str, version: str) -> None:
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with ZipFile(path, "w") as wheel:
        wheel.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )


def test_public_wheelhouse_refuses_missing_unknown_duplicate_and_modified(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="public wheelhouse lacks"):
        verify_public_wheelhouse(tmp_path)

    unknown = tmp_path / "unknown_pkg-1.0.0-py3-none-any.whl"
    _fake_wheel(unknown, "unknown-pkg", "1.0.0")
    with pytest.raises(ValueError, match="unknown public wheel unknown-pkg"):
        verify_public_wheelhouse(tmp_path)
    unknown.unlink()

    first = tmp_path / "cryptography-50.0.0-py3-none-any.whl"
    second = tmp_path / "cryptography-50.0.0-1-py3-none-any.whl"
    _fake_wheel(first, "cryptography", "50.0.0")
    _fake_wheel(second, "cryptography", "50.0.0")
    with pytest.raises(ValueError, match="duplicate public wheel cryptography"):
        verify_public_wheelhouse(tmp_path)
    second.unlink()

    with pytest.raises(ValueError, match="cryptography wheel bytes differ"):
        verify_public_wheelhouse(tmp_path)


def test_alembic_os_separator_discovers_both_lineage_heads(tmp_path: Path) -> None:
    first = tmp_path / "kernel_versions"
    second = tmp_path / "control_versions"
    first.mkdir()
    second.mkdir()
    (first / "kernel_probe.py").write_text(
        "revision = 'kernel_probe'\n"
        "down_revision = None\n"
        "branch_labels = ('kernel_lineage',)\n"
        "depends_on = None\n"
    )
    (second / "control_probe.py").write_text(
        "revision = 'control_probe'\n"
        "down_revision = None\n"
        "branch_labels = ('control_lineage',)\n"
        "depends_on = None\n"
    )
    cfg = Config(str(HARNESS / "alembic.ini"))
    cfg.set_main_option("version_locations", f"{first} {second}")
    bad_locations = cfg.get_version_locations_list()
    assert bad_locations is not None and len(bad_locations) == 1
    assert ScriptDirectory.from_config(cfg).get_heads() == []
    cfg.set_main_option("version_locations", os.pathsep.join((str(first), str(second))))
    good_locations = cfg.get_version_locations_list()
    assert good_locations is not None
    assert tuple(map(Path, good_locations)) == (first, second)
    assert set(ScriptDirectory.from_config(cfg).get_heads()) == {
        "kernel_probe",
        "control_probe",
    }
    fixture = (HARNESS / "conftest.py").read_text()
    assert "os.pathsep.join" in fixture
    assert "ScriptDirectory.from_config(cfg).get_heads()" in fixture


def test_role_contract_preflight_refuses_missing_or_mismatched_roles() -> None:
    """`app_admin` must be `NOCREATEROLE` -- the opposite of the old harness's
    wrong requirement -- matching production's real contract exactly."""
    conn = MagicMock()
    conn.execute.return_value.all.return_value = [
        ("app_admin", "false|false|true|true"),
        ("app_user", "false|false|false|true"),
    ]
    with pytest.raises(RuntimeError, match="lacks roles.*platform_api"):
        _verify_role_contracts(conn)
    query = str(conn.execute.call_args.args[0])
    assert "rolcreaterole" in query and "FROM pg_roles" in query

    conn.execute.return_value.all.return_value = [
        # Planted defect: app_admin wrongly holds CREATEROLE.
        ("app_admin", "false|true|true|true"),
        ("app_user", "false|false|false|true"),
        ("platform_api", "false|false|false|true"),
        ("outbox_dispatcher", "false|false|false|true"),
        ("platform_outbox_dispatcher", "false|false|false|true"),
    ]
    with pytest.raises(RuntimeError, match="role contract differs from production"):
        _verify_role_contracts(conn)

    conn.execute.return_value.all.return_value[0] = (
        "app_admin",
        "false|false|true|true",
    )
    _verify_role_contracts(conn)
    fixture = (HARNESS / "conftest.py").read_text()
    assert fixture.index("_verify_role_contracts(conn)") < fixture.index(
        "conn.execute(text(f'CREATE DATABASE \"{scratch_name}\" OWNER app_admin'))"
    )
    assert (
        "requires CREATEROLE" not in fixture
    ), "the harness must never require CREATEROLE for app_admin again"


def test_no_private_key_or_checkout_dependency() -> None:
    for path in HARNESS.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".json", ".ini"}:
            continue
        contents = path.read_text()
        assert "BEGIN PRIVATE KEY" not in contents
        assert "PRIVATE KEY-----" not in contents
        assert "control-rehearsal-issuer-factory" not in contents
        assert "cp193-lock-bundle" not in contents
        assert "Base.metadata.create_all" not in contents
        assert "sqlite" not in contents.lower()
    guard = (HARNESS / "conftest.py").read_text()
    assert 'os.environ.get("REHEARSAL_ISSUER_DATABASE_URL")' in guard
    assert "pytest.UsageError" in guard
    assert "versions_dir" in guard and 'command.upgrade(cfg, "heads")' in guard
    assert "dc_0014_rehearsal_issuer_ledger" in guard
