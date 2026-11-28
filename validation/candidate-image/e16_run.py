#!/usr/bin/env python3
"""Supplemental thirteen-scenario conformance on an unchanged candidate venv."""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import importlib.metadata as metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import site
import stat
import sys
from xml.etree import ElementTree
from zipfile import ZipFile

REVISION = "310bec2a69fa6eba1165da7cc007ed60101274b4"
CONTROL_SOURCE = "3bd99c2ce19b287f22f9ff8ad92907b4e45324c8"
CONTROL_SHA = "17fdb59adc23b8eda5108c32caf6f3850e627e83a4ec7a94e7942f462c39f421"
PUBLIC_LOCK_SHA = "fbdd86c0141b5840ef46b116530aa36c52fc6927f79ace82f673eb8262f74d51"
CHECKS, EXTRAS, TESTS, VENV, OUT = map(Path, (
    "/checks", "/opt/e16-test-deps", "/checks/test-root", "/opt/venv", "/out"))
SCENARIOS = {"positive", "withdrawn", "replay", "finalize_failure", "expired", "revoked",
             "changed_target", "changed_observation", "changed_host", "ambiguous_commit",
             "swapped_request", "session_reuse", "finalization_withdrawal"}
FUNCTION = "test_real_approved_cp_v3_lifecycle"
EXPECTED_CASES = {FUNCTION + "[" + scenario + "]" for scenario in SCENARIOS}
IDENTITIES = {"/app/application_foundation_profile.json", "/app/migration_heads.json",
              "/app/distributions.json"}
PINNED_TEST_FILES = {
    "conformance/conftest.py": "3f4f397dc0d89c365af11a0e1a7d4a215506c81cbe0f023fc3895e3b9ff13f71",
    "conformance/test_host_admission_conformance.py": "098b5a11bfe7bc70db2dfdf7ea6b3dbf4775ce5f1f9ff84252732ad44aa8a44b",
    "rehearsal_issuer_harness/artifacts.py": "5b415faf8f332c15d930310dd82f77c18d0707afcecc8a4e1570e68bb8244692",
    "rehearsal_issuer_harness/public-requirements.lock": PUBLIC_LOCK_SHA,
}


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")


def relative(name):
    path = Path(name)
    require(isinstance(name, str) and name and not path.is_absolute()
            and path.as_posix() == name and ".." not in path.parts, "unsafe relative path")
    return path


def readonly_file(path):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
            and not path.stat().st_mode & 0o222, "input is not a readonly regular file")


def verify_tree(root, expected, *, symlinks=False, ignored=()):
    require(root.is_dir() and not root.is_symlink(), "invalid input root")
    require(os.statvfs(root).f_flag & os.ST_RDONLY, "input filesystem must be mounted readonly")
    actual = {}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if name in ignored or any(name.startswith(item + "/") for item in ignored):
            continue
        if path.is_symlink():
            require(symlinks, "symlink in supplemental inputs")
            actual[name] = {"symlink": os.readlink(path)}
        elif path.is_dir():
            require(any(item.startswith(name + "/") for item in expected), "extra input directory")
        else:
            require(stat.S_ISREG(path.stat().st_mode), "nonregular input")
            if not symlinks:
                readonly_file(path)
            actual[name] = {"sha256": sha(path.read_bytes())} if symlinks else sha(path.read_bytes())
    for name in expected:
        relative(name)
    require(actual == expected, "complete file inventory/hash mismatch")


def read_json(path):
    readonly_file(path)
    return json.loads(path.read_text())


def load_config():
    readonly_file(Path(__file__))
    config = read_json(CHECKS / "config.json")
    require(set(config) == {"candidate_revision", "candidate_image_id", "runner_sha256",
        "identity_files", "venv_snapshot_sha256", "original_distributions_sha256",
        "checks_files", "extras_files", "test_root_files", "foundation_wheel_sha256",
        "expected_migration_heads"}, "config fields differ")
    require(config["candidate_revision"] == REVISION
            and re.fullmatch(r"sha256:[0-9a-f]{64}", config["candidate_image_id"]), "candidate binding differs")
    for key in ("runner_sha256", "venv_snapshot_sha256", "original_distributions_sha256", "foundation_wheel_sha256"):
        digest(config[key])
    require(sha(Path(__file__).read_bytes()) == config["runner_sha256"], "runner hash differs")
    require(set(config["identity_files"]) == IDENTITIES, "runtime identity closure differs")
    for inventory in (config["identity_files"], config["checks_files"], config["extras_files"], config["test_root_files"]):
        require(isinstance(inventory, dict) and inventory, "missing inventory")
        for value in inventory.values():
            digest(value)
    require(config["checks_files"].get("venv-snapshot.json") == config["venv_snapshot_sha256"]
            and config["checks_files"].get("original-distributions.json") == config["original_distributions_sha256"], "snapshot bindings differ")
    for name in config["checks_files"]:
        path = relative(name)
        require(name in {"venv-snapshot.json", "original-distributions.json", "original-artifacts.json"}
                or (len(path.parts) == 3 and path.parts[0] == "wheels"
                    and path.parts[1] in {"private", "public", "foundation"}
                    and path.suffix == ".whl"), "unexpected checks input")
    require(config["checks_files"].get("original-artifacts.json") ==
            "4aa8bbcf876b92ae48e3f6260cde3423c36d9eeae83e4602fd43ff982a2d3c45", "baseline artifact data differs")
    for name in config["test_root_files"]:
        require(relative(name).parts[0] in {"conformance", "rehearsal_issuer_harness"}, "test-root may contain only test packages")
    for name, expected in PINNED_TEST_FILES.items():
        require(config["test_root_files"].get(name) == expected, "frozen test source differs")
    require(config["expected_migration_heads"] and len(set(config["expected_migration_heads"]))
            == len(config["expected_migration_heads"]), "missing/duplicate expected migration heads")
    return config


def original_snapshot(config):
    require(sys.executable == "/opt/venv/bin/python" and sys.flags.isolated
            and sys.dont_write_bytecode, "isolated original interpreter required")
    require(sys.prefix == str(VENV), "original venv required")
    verify_tree(VENV, read_json(CHECKS / "venv-snapshot.json"), symlinks=True)
    for name, expected in config["identity_files"].items():
        path = Path(name)
        require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == expected, "runtime identity changed")
    profile = json.loads(Path("/app/application_foundation_profile.json").read_text())
    require(profile["source_revision"] == REVISION, "installed profile revision differs")
    roots = [Path(p).resolve() for p in site.getsitepackages()]
    require(roots and all(root.is_relative_to(VENV) for root in roots), "external site-packages")
    return roots


def distributions(roots):
    found = {}
    for dist in metadata.distributions(path=list(map(str, roots))):
        name = re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
        require(name not in found, "duplicate distribution")
        found[name] = dist.version
    return found


def modules(root):
    result = set()
    for path in root.iterdir():
        name = path.name
        require(not name.endswith((".pth", ".egg-link")), "import path hook refused")
        if name.endswith((".dist-info", ".data")) or name.startswith(".") or name == "__pycache__":
            continue
        if path.is_dir() or name.endswith((".py", ".so")):
            result.add(name.split(".")[0])
    require(not result & {"sitecustomize", "usercustomize"}, "import customization refused")
    return result


def verify_origins(roots, baseline):
    require(distributions(roots) == baseline, "original distribution inventory changed")
    expected = {
        "dotmac-deployment-control": ("0.1.0a18", "dotmac_deployment_control", VENV),
        "dotmac-kernel": ("0.1.0a100", "dotmac_kernel", VENV),
        "dotmac-approvals": ("0.1.0a8", "dotmac_approvals", VENV),
        "dotmac-vendor-control-plane": ("0.1.0", "vendor_cp", VENV),
        "dotmac-deployment-foundation": ("0.4.0a1", "dotmac_deployment_foundation", EXTRAS),
    }
    visible = distributions(roots + [EXTRAS])
    for name, (version, module, root) in expected.items():
        require(visible.get(name) == version, "installed version differs")
        spec = importlib.util.find_spec(module)
        require(spec and spec.origin and Path(spec.origin).resolve().is_relative_to(root), "module origin differs")
        loaded = sys.modules.get(module)
        if loaded is not None:
            require(Path(loaded.__file__).resolve() == Path(spec.origin).resolve(), "loaded module origin differs")
        for imported_name, imported in tuple(sys.modules.items()):
            if imported_name == module or imported_name.startswith(module + "."):
                origin = getattr(imported, "__file__", None)
                require(origin and Path(origin).resolve().is_relative_to(root), "loaded submodule origin differs")


def verify_artifact_data():
    baseline = read_json(CHECKS / "original-artifacts.json")
    expected = copy.deepcopy(baseline)
    control = expected["artifacts"]["dotmac-deployment-control"]
    control.update(filename="dotmac_deployment_control-0.1.0a18-py3-none-any.whl",
                   version="0.1.0a18", sha256=CONTROL_SHA, source_commit=CONTROL_SOURCE)
    control.pop("tag_object")
    require(read_json(TESTS / "rehearsal_issuer_harness/artifacts.json") == expected,
            "artifact data adaptation changed outside exact a18 coordinates")
    from rehearsal_issuer_harness import artifacts
    pins = artifacts.read_lock()["artifacts"]
    wheels = {name: CHECKS / "wheels/private" / pin["filename"] for name, pin in pins.items()}
    artifacts.verify_wheels(wheels["dotmac-deployment-control"], wheels["dotmac-kernel"],
                            approvals_wheel=wheels["dotmac-approvals"])
    artifacts.verify_installed(wheels["dotmac-deployment-control"], wheels["dotmac-kernel"],
        CHECKS / "wheels/public", approvals_wheel=wheels["dotmac-approvals"])


def verify_foundation(config):
    wheels = list((CHECKS / "wheels/foundation").glob("*.whl"))
    require(len(wheels) == 1 and sha(wheels[0].read_bytes()) == config["foundation_wheel_sha256"], "Foundation wheel binding differs")
    dist = metadata.distribution("dotmac-deployment-foundation")
    require(Path(dist.locate_file("")).resolve() == EXTRAS, "Foundation must be supplemental")
    with ZipFile(wheels[0]) as wheel:
        for name in wheel.namelist():
            if name.endswith("/") or name.endswith(".dist-info/RECORD"):
                continue
            relative(name)
            require(".data/" not in name, "unexpected Foundation wheel relocation")
            path = EXTRAS / name
            require(path.is_file() and path.read_bytes() == wheel.read(name), "Foundation installed bytes differ")


def static_control_heads(directory):
    revisions, parents = set(), set()
    for path in sorted(Path(directory).glob("*.py")):
        values = {}
        for node in ast.parse(path.read_bytes(), filename=str(path)).body:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                    require(target.id not in values, "duplicate migration identity")
                    values[target.id] = ast.literal_eval(node.value)
        if not values:
            continue
        require(set(values) == {"revision", "down_revision"} and isinstance(values["revision"], str)
                and values["revision"] not in revisions, "static Control migration derivation needs review")
        revisions.add(values["revision"])
        down = values["down_revision"]
        require(down is None or isinstance(down, (str, tuple, list)), "nonliteral migration parent")
        parents.update([down] if isinstance(down, str) else down or [])
    require(revisions and parents <= revisions, "Control migration lineage needs static source review")
    return revisions - parents


def migrate(config):
    from alembic import command
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from dotmac_deployment_control import versions_dir as control_versions
    from dotmac_approvals.migrations import versions_dir as approval_versions
    from dotmac_kernel.migrations import versions_dir as kernel_versions
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    runtime_url = make_url(os.environ["CONFORMANCE_DATABASE_URL"])
    migration_url = make_url(os.environ["REHEARSAL_ISSUER_MIGRATION_DATABASE_URL"])
    endpoint = lambda url: (url.drivername, url.host, url.port, url.database, url.query)
    require(runtime_url.username == "platform_api" and migration_url.username == "app_admin"
            and endpoint(runtime_url) == endpoint(migration_url),
            "database roles/endpoint differ from disposable recipe")
    control_heads = static_control_heads(control_versions())
    cfg = Config(str(TESTS / "rehearsal_issuer_harness/alembic.ini"))
    cfg.set_main_option("version_locations", os.pathsep.join(map(str, (kernel_versions(), control_versions(), approval_versions()))))
    scripts = ScriptDirectory.from_config(cfg)
    heads = set(scripts.get_heads())
    require(control_heads <= heads and heads == set(config["expected_migration_heads"]), "actual migration heads differ; no guessed historical head allowed")
    # Read-only precondition before the canonical owner performs migrations.
    engine = create_engine(os.environ["REHEARSAL_ISSUER_MIGRATION_DATABASE_URL"], future=True)
    try:
        with engine.connect() as connection:
            count = connection.execute(text("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')")).scalar_one()
            require(count == 0, "disposable database is not fresh")
    finally:
        engine.dispose()
    command.upgrade(cfg, "heads")
    try:
        with engine.connect() as connection:
            require(set(MigrationContext.configure(connection).get_current_heads()) == heads,
                    "database migration heads differ after upgrade")
    finally:
        engine.dispose()
    return sorted(heads)


class InventoryPlugin:
    def pytest_collection_modifyitems(self, session, config, items):
        require(len(items) == 13 and {item.name for item in items} == EXPECTED_CASES,
                "collected scenario inventory differs")


def main():
    config = load_config()
    config_bytes = (CHECKS / "config.json").read_bytes()
    roots = original_snapshot(config)
    baseline = read_json(CHECKS / "original-distributions.json")
    require(distributions(roots) == baseline and "dotmac-deployment-foundation" not in baseline, "original installed snapshot differs")
    verify_tree(CHECKS, config["checks_files"], ignored=("config.json", "run_e16.py", "test-root"))
    verify_tree(EXTRAS, config["extras_files"])
    verify_tree(TESTS, config["test_root_files"])
    base_modules = set().union(*(modules(root) for root in roots))
    require(not base_modules & modules(EXTRAS) and not (base_modules | modules(EXTRAS)) & modules(TESTS), "supplemental import collision")
    require(not set(distributions([EXTRAS])) & set(baseline), "supplemental distribution collision")
    dsns = {key: os.environ.get(key) for key in ("CONFORMANCE_DATABASE_URL", "REHEARSAL_ISSUER_MIGRATION_DATABASE_URL")}
    require(all(dsns.values()), "disposable database DSNs required")
    require(OUT.is_dir() and not any(OUT.iterdir()), "fresh writable /out required")
    for name in ("home", "tmp", "pytest-temp"):
        (OUT / name).mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(dsns)
    os.environ.update(HOME=str(OUT / "home"), TMPDIR=str(OUT / "tmp"),
        PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", LANG="C.UTF-8",
        PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        DATABASE_URL=dsns["CONFORMANCE_DATABASE_URL"], PLATFORM_DATABASE_URL=dsns["CONFORMANCE_DATABASE_URL"],
        CONFORMANCE_PRIVATE_WHEELHOUSE=str(CHECKS / "wheels/private"),
        CONFORMANCE_PUBLIC_WHEELHOUSE=str(CHECKS / "wheels/public"))
    sys.path.extend([str(EXTRAS), str(TESTS)])
    pinned_path = list(sys.path)
    os.chdir(OUT)
    result = None
    try:
        verify_origins(roots, baseline)
        verify_artifact_data()
        verify_foundation(config)
        heads = migrate(config)
        import pytest
        junit = OUT / "e16.xml"
        result = pytest.main(["-q", "-rs", "-c", "/dev/null", "--rootdir=" + str(TESTS),
            "--confcutdir=" + str(TESTS), "--import-mode=importlib", "-p", "no:cacheprovider",
            "--basetemp=" + str(OUT / "pytest-temp"), "--junitxml=" + str(junit),
            str(TESTS / "conformance/test_host_admission_conformance.py") + "::" + FUNCTION],
            plugins=[InventoryPlugin()])
        require(result == 0, "supplemental pytest failed")
        cases = ElementTree.parse(junit).getroot().findall(".//testcase")
        require(len(cases) == 13 and {case.attrib["name"] for case in cases} == EXPECTED_CASES
                and all(not any(case.find(outcome) is not None for outcome in ("skipped", "failure", "error")) for case in cases), "JUnit scenario inventory/outcomes differ")
    finally:
        require(sys.path == pinned_path, "import path changed during supplemental run")
        require((CHECKS / "config.json").read_bytes() == config_bytes, "config changed during run")
        original_snapshot(config)
        verify_origins(roots, baseline)
        verify_artifact_data()
        verify_foundation(config)
        verify_tree(EXTRAS, config["extras_files"])
        verify_tree(TESTS, config["test_root_files"])
        verify_tree(CHECKS, config["checks_files"], ignored=("config.json", "run_e16.py", "test-root"))
    receipt = {"status": "SUPPLEMENTAL_APPROVED_CP_V3_SCENARIOS_PASS", "source_revision": REVISION,
        "candidate_image_id_supplied_by_coordinator": config["candidate_image_id"],
        "cases": 13, "failures": 0, "errors": 0, "skips": 0, "migration_heads": heads,
        "original_venv_unchanged": True, "supplemental_test_tools": True,
        "foundation_test_only": True, "deterministic_signer": True, "local_approvals": True,
        "original_runtime_adoption": False, "production_custody": False,
        "workload_execution": False, "full_governed_deployment": False, "published": False}
    (OUT / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        detail = str(error) if isinstance(error, Refused) else type(error).__name__
        print("supplemental runner refused (" + detail + ")", file=sys.stderr)
        sys.exit(1)
