"""Closed source contracts for private qualification-only role retention."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/gate0-sshd-conformance.yml"
RETAIN = ROOT / ".github/candidate/retain_gate0_publisher.py"
INSPECT = ROOT / ".github/candidate/inspect_gate0_publisher.py"


def test_private_role_selection_is_manual_and_upload_is_only_completed_pair():
    text = WORKFLOW.read_text()
    assert text.count("inputs.retention_packet_sha256 != ''") == 3
    assert "github.event_name == 'workflow_dispatch'" in text
    for name in (
        "GATE0_ROLE_RETENTION_PACKET_JSON",
        "GATE0_ROLE_RETENTION_CERTIFICATE_BASE64",
        "GATE0_ROLE_RETENTION_GPG_QUALIFICATION_JSON",
    ):
        assert text.count("vars." + name) == 1
    private_upload = text.split(
        "name: Retain the selected encrypted role qualification input", 1
    )[1].split("- name:", 1)[0]
    assert "name: gate0-role-qualification-runtime" in private_upload
    assert "retention-days: 30" in private_upload
    assert "overwrite: false" in private_upload
    assert "/encrypted-runtime-bundle.pgp" in private_upload
    assert "/producer-receipt.json" in private_upload
    assert ".tar" not in private_upload
    for forbidden in (
        "packages: write",
        "id-token: write",
        "docker login",
        "docker push",
        "environment: production",
    ):
        assert forbidden not in text
    assert "actions: read" in text


def test_same_immutable_role_image_flows_through_existing_owners_and_export_once():
    text = WORKFLOW.read_text()
    assert text.count("docker build --target gate0-role") == 1
    assert '--iidfile "$GATE0_ROLE_PRIVATE_DIR/role-image-id"' in text
    assert '--entrypoint /opt/venv/bin/python "$image_id"' in text
    assert 'accept_gate0_network.sh "$image_id"' in text
    assert 'retain_gate0_publisher.py role-export-create "$private"' in text
    assert text.count("docker export --output") == 1
    assert (
        'docker image save --output "$private/role-image-save.tar" "$image_id"' in text
    )
    assert (
        text.index("role-preflight")
        < text.index("docker export --output")
        < text.index("role-inspect")
    )
    assert (
        text.index("Clean the owned role export before staging")
        < text.index("Stage only the completed encrypted role pair")
        < text.index("Retain the selected encrypted role qualification input")
    )
    assert text.count('retain_gate0_publisher.py role-export-cleanup "$private"') == 2
    assert "docker container rm" not in text
    assert "Remove all owned private role packaging and upload files" in text


def test_role_entrypoints_and_terminal_false_markers_are_fixed():
    retention = RETAIN.read_text()
    inspector = INSPECT.read_text()
    for fixed in (
        "role-preflight",
        'sys.argv[1] == "role"',
        "DotmacRoleRuntimeQualificationRetentionExecution.v1",
        "DotmacRoleRuntimeGpgQualification.v1",
        "role-runtime-public-key-encryption.v1",
        "Gate0RoleQualificationPrivateBuild.v1",
        "Gate0RoleQualificationProducerReceipt.v1",
        "private-native-qualification-input-only",
    ):
        assert fixed in retention
    assert 'sys.argv[1] == "role-inspect"' in inspector
    for key in (
        "live_readiness",
        "installed_native_qualified",
        "operationally_accepted",
        "gate0_accepted",
    ):
        assert f'"{key}": False' in inspector
    tree = ast.parse(retention)
    role_measurement = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "role_export_measurement"
    )
    assert any(
        isinstance(node, ast.Attribute) and node.attr == "role_inventory"
        for node in ast.walk(role_measurement)
    )
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "inventory"
        for node in ast.walk(role_measurement)
    )
    assert 'clock["monotonic"] + 1180' in retention
    assert 'packet["limits"]' in retention


def test_role_only_cache_correction_keeps_other_docker_stages_identical():
    text = (ROOT / "Dockerfile").read_text()
    before, remainder = text.split("FROM ubuntu:24.04", 1)
    role, after = remainder.split("# Nondefault candidate publisher bytes only.", 1)
    assert 'pip" install --no-cache-dir' in role
    assert "rm -rf /root/.cache/pip /root/.cache/pypoetry" in role
    assert "rmdir /root/.cache" in role
    # Immutable hashes captured from the task's exact e9f833e baseline.
    assert (
        hashlib.sha256(before.encode()).hexdigest()
        == "003716f3ff438b27ca6612284b85959ce34ab1bb626cf8eacef7cb2a6e7e5750"
    )
    assert (
        hashlib.sha256(after.encode()).hexdigest()
        == "2c0ac3060b4b4c9a9344f4796ea195ae3817fe8bd3c9cfbc0755fffb1918ca3b"
    )


def test_ordinary_export_check_reuses_pure_joins_and_excludes_selected_retention():
    workflow = WORKFLOW.read_text()
    checker = (ROOT / "conformance/check_gate0_role_export.py").read_text()
    step = workflow.split(
        "name: Inspect the already-smoked role export as hosted source conformance", 1
    )[1].split("- name:", 1)[0]
    assert (
        "github.event_name != 'workflow_dispatch' || "
        "inputs.retention_packet_sha256 == ''" in step
    )
    assert "timeout-minutes: 6" in step
    assert "305s" in step
    assert 'check_gate0_role_export.py "$GATE0_ROLE_PRIVATE_DIR" "$private"' in step
    assert "GATE0_ROLE_EXPORT_CHECK_PRIVATE_DIR=$private" in step
    assert workflow.index(
        "Prove native capability and socket boundaries"
    ) < workflow.index("Inspect the already-smoked role export")
    assert workflow.index(
        "Reconcile owned source-conformance cleanup"
    ) < workflow.index("Package the selected private role")
    assert "role_export_image_subject" in checker
    assert "role_export_measurement" in checker
    for forbidden in (
        "role_context(",
        "role_main(",
        "role_inspection(",
        "load_role_packet(",
        "authenticate_role_context(",
        "checked_encrypt(",
        "producer-receipt",
        "RETENTION_PACKET",
        "GITHUB_TOKEN",
        "upload-artifact",
    ):
        assert forbidden not in checker
    assert '"runtime_retained": False' in checker
    assert '"live_readiness": False' in checker
    assert "started + 280" in checker
    assert 'intent["work_deadline"] + 20' in RETAIN.read_text()
    assert '"pull", retention.ROLE_BASE_IMAGE' in checker
    assert "retention.role_export_create(private, image_id, deadline)" in checker
    assert '"export",' in checker and '"save",' in checker
    assert "retention.role_export_cleanup(private)" in checker
    assert "shutil.rmtree(private)" in checker
    public_upload = workflow.split(
        "name: Retain candidate identity and smoke evidence", 1
    )[1]
    assert "check_gate0_role_export" not in public_upload
    assert "gate0-role-export" not in public_upload
    assert "manifest.json" not in public_upload


def test_retention_wrappers_forward_to_same_pure_export_joins():
    tree = ast.parse(RETAIN.read_text())
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    for wrapper, pure in (
        ("role_image_subject", "role_export_image_subject"),
        ("role_measurement", "role_export_measurement"),
    ):
        body = functions[wrapper].body
        assert len(body) == 1 and isinstance(body[0], ast.Return)
        call = body[0].value
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        assert call.func.id == pure


def test_both_cleanup_paths_use_role_pinned_owner_and_preserve_unknown_identity():
    workflow = WORKFLOW.read_text()
    retention = RETAIN.read_text()
    checker = (ROOT / "conformance/check_gate0_role_export.py").read_text()
    assert "docker container rm" not in workflow
    assert 'sys.argv[1] == "role-export-create"' in retention
    assert 'sys.argv[1] == "role-export-cleanup"' in retention
    assert 'document[0]["Id"] != container_id' in retention
    assert 'document[0]["Name"] != "/" + name' in retention
    assert 'document[0]["Image"] != image_id' in retention
    assert "export-created-owner.json" in retention
    assert "cid_device" in retention and "cid_inode" in retention
    assert "export-cleanup-confirmed.json" in workflow
    selected_final = workflow.split(
        "name: Remove all owned private role packaging and upload files", 1
    )[1].split("- name:", 1)[0]
    assert selected_final.index("export-cleanup-confirmed.json") < selected_final.index(
        'rm -rf -- "$GATE0_ROLE_PRIVATE_DIR"'
    )
    ordinary_final = checker.split("    finally:", 1)[1]
    assert ordinary_final.index(
        "retention.role_export_cleanup(private)"
    ) < ordinary_final.index("shutil.rmtree(private)")


def _diagnostic_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "role_export_diagnostic_canary", ROOT / "conformance/check_gate0_role_export.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failure_diagnostic_redacts_arbitrary_messages_and_bounds_cycles():
    import json

    checker = _diagnostic_checker()
    private = ValueError("SYNTHETIC_PRIVATE_VALUE/private/member")
    other = RuntimeError("SYNTHETIC_PRIVATE_VALUE/private/cleanup")
    private.__context__ = other
    other.__context__ = private
    chain = checker._failure_chain(private)
    assert len(chain) == 2
    encoded = json.dumps(chain)
    assert "SYNTHETIC_PRIVATE_VALUE" not in encoded
    assert "/private/" not in encoded
    assert chain[0]["predicate"] == "unclassified"
    assert (
        checker._failure_metadata(ValueError("protected native link"))["predicate"]
        == "protected_native_link"
    )
    assert (
        checker._failure_metadata(type("PrivateExceptionName", (Exception,), {})())[
            "exception_kind"
        ]
        == "other"
    )
    current = ValueError("synthetic")
    for _ in range(8):
        next_error = ValueError("synthetic")
        next_error.__cause__ = current
        current = next_error
    assert len(checker._failure_chain(current)) == 4


def test_failure_chain_preserves_work_and_masking_cleanup_without_private_values(
    monkeypatch,
):
    import json

    checker = _diagnostic_checker()
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    try:
        checker.check("SYNTHETIC_PRIVATE_VALUE", "SYNTHETIC_PRIVATE_VALUE")
    except ValueError as primary:
        checker._DIAGNOSTIC["work_failure"] = {
            "phase": "rootfs_subject_join",
            **checker._failure_metadata(primary),
        }
        checker._DIAGNOSTIC["phase"] = "owned_container_cleanup"
        checker._DIAGNOSTIC["cleanup_outcome"] = "unconfirmed"
        try:
            raise RuntimeError("SYNTHETIC_PRIVATE_VALUE/cleanup") from primary
        except RuntimeError as cleanup:
            report = checker._failure_report(cleanup)
    else:
        raise AssertionError("synthetic hosted refusal did not occur")
    assert report["cleanup_outcome"] == "unconfirmed"
    assert report["work_failure"]["phase"] == "rootfs_subject_join"
    assert len(report["exception_chain"]) == 2
    locations = report["exception_chain"][1]["source_locations"]
    assert locations and all(location["owner"] == "checker" for location in locations)
    assert all(
        type(location["line"]) is int and location["line"] > 0 for location in locations
    )
    encoded = json.dumps(report)
    assert "SYNTHETIC_PRIVATE_VALUE" not in encoded
    assert "check_gate0_role_export.py" not in encoded
    assert str(ROOT) not in encoded


def test_failure_diagnostics_do_no_io_and_keep_failure_cleanup_deadlines():
    checker = (ROOT / "conformance/check_gate0_role_export.py").read_text()
    tree = ast.parse(checker)
    names = {"_failure_metadata", "_failure_chain", "_failure_report"}
    for function in tree.body:
        if isinstance(function, ast.FunctionDef) and function.name in names:
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        assert node.func.id not in {"open", "str", "repr"}
                    if isinstance(node.func, ast.Attribute):
                        assert node.func.attr not in {
                            "open",
                            "read",
                            "read_bytes",
                            "read_text",
                            "resolve",
                            "extractfile",
                        }
    assert "range(64)" in checker and "range(4)" in checker
    assert '"work_failure"' in checker and '"exception_chain"' in checker
    assert '"cleanup_outcome"] = "unconfirmed"' in checker
    assert '"cleanup_outcome"] = "confirmed"' in checker
    assert "started + 280" in checker
    assert "role_export_cleanup(private)" in checker
    assert (
        'raise SystemExit("role export source conformance refused") from None'
        in checker
    )


def test_retained_inspection_data_functions_have_no_operational_calls():
    tree = ast.parse(INSPECT.read_text())
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    selected = (
        "retained_outer",
        "retained_gzip",
        "retained_join",
        "retained_measure",
        "retained_equal",
        "retained_stat",
        "retained_directory",
        "role_retained_inspect",
    )
    forbidden = {
        "exec",
        "eval",
        "compile",
        "extract",
        "extractall",
        "run_bounded",
        "api_json",
        "checked_encrypt",
        "role_context",
        "role_inspection",
        "role_main",
        "system",
        "popen",
        "run",
        "check_output",
        "connect",
    }
    for name in selected:
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call):
                called = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else None
                )
                assert called not in forbidden
    mode = functions["role_retained_inspect"]
    literals = {
        node.value
        for node in ast.walk(mode)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "retained-inspection.json" in literals
    assert "DotmacRoleRetainedInspection.v1" in literals
    for flag in (
        "live_readiness",
        "installed_native_qualified",
        "operationally_accepted",
        "gate0_accepted",
    ):
        assert flag in literals


def test_retained_current_helper_loader_is_captured_and_hash_checked():
    tree = ast.parse(INSPECT.read_text())
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    loader_owner = functions["retained_owner"]
    classes = [node for node in loader_owner.body if isinstance(node, ast.ClassDef)]
    assert len(classes) == 1
    loader = classes[0]
    assert [ast.unparse(base) for base in loader.bases] == [
        "importlib.machinery.SourceFileLoader"
    ]
    methods = [node for node in loader.body if isinstance(node, ast.FunctionDef)]
    assert [method.name for method in methods] == ["get_code"]
    returned = next(
        node for node in ast.walk(methods[0]) if isinstance(node, ast.Return)
    )
    assert ast.unparse(returned.value) == "self.source_to_code(raw, path)"
    calls = [node for node in ast.walk(loader_owner) if isinstance(node, ast.Call)]
    names = [ast.unparse(call.func) for call in calls]
    assert "stream.read" in names and "digest" in names
    assert "loader.exec_module" in names
    assert not {
        "open",
        "os.open",
        "exec",
        "eval",
        "compile",
        "importlib.util.spec_from_file_location",
    }.intersection(names)
    refusal = next(
        index
        for index, node in enumerate(loader_owner.body)
        if isinstance(node, ast.If)
    )
    load = next(
        index
        for index, node in enumerate(loader_owner.body)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "loader.exec_module"
    )
    assert "digest(raw) != expected" in ast.unparse(loader_owner.body[refusal].test)
    assert refusal < load
    mode_calls = [
        node
        for node in ast.walk(functions["role_retained_inspect"])
        if isinstance(node, ast.Call)
    ]
    assert [
        ast.unparse(node)
        for node in mode_calls
        if ast.unparse(node.func) == "retained_owner"
    ] == ["retained_owner(streams[-1], expected[-1])"]
    measure_calls = [
        node
        for node in ast.walk(functions["retained_measure"])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"role_subjects", "role_synthetic_qualification"}
    ]
    assert len(measure_calls) == 2
    assert all(
        any(
            keyword.arg == "validation_owner" and ast.unparse(keyword.value) == "owner"
            for keyword in call.keywords
        )
        for call in measure_calls
    )
