"""CI-only continuation core contract checks against an installed candidate.

The runner prepares only five fixed test files and public, lock-hashed pure
pytest wheels. The offline candidate receives no application source overlay.
This is synthetic core coverage, not protected issuance or native host proof.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

COLLECT = (
    "test_cp_committed_continuation.py",
    "test_cp_committed_host.py",
    "test_transition_operator.py",
)
TESTS = (*COLLECT, "test_cp_transition.py", "test_cp_transition_host.py")
OWNERS = (
    "vendor_cp.deployment.cp_transition",
    "vendor_cp.deployment.cp_transition_host",
    "vendor_cp.deployment.transition_operator",
)
REPORT_SCHEMA = "dotmac.cp_committed_continuation_artifact_acceptance/1"
REPORT_SCOPE = (
    "installed core/host/operator with synthetic boundaries; not native host acceptance"
)
TOOL_ROOTS = {
    "pytest": {"pytest", "_pytest", "py.py"},
    "iniconfig": {"iniconfig"},
    "packaging": {"packaging"},
    "pluggy": {"pluggy"},
    "pygments": {"pygments"},
}


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def select_wheels(lock: dict) -> dict:
    selected = {}
    for name in TOOL_ROOTS:
        packages = [p for p in lock["package"] if p["name"] == name]
        if len(packages) != 1 or "source" in packages[0]:
            raise ValueError(f"ambiguous or non-public tool: {name}")
        package = packages[0]
        filename = f"{name}-{package['version']}-py3-none-any.whl"
        files = [f for f in package["files"] if f["file"] == filename]
        if len(files) != 1:
            raise ValueError(f"no unique pure wheel: {name}")
        checksum = files[0]["hash"]
        if len(checksum) != 71 or not checksum.startswith("sha256:"):
            raise ValueError("invalid wheel hash")
        bytes.fromhex(checksum[7:])
        selected[name] = {
            "version": package["version"],
            "filename": filename,
            "sha256": checksum,
        }
    return selected


def validate_wheel(path: Path, name: str, pin: dict) -> None:
    if path.name != pin["filename"] or sha256(path.read_bytes()) != pin["sha256"]:
        raise ValueError("tool wheel identity differs from lock")
    dist_info = pin["filename"].removesuffix("-py3-none-any.whl") + ".dist-info"
    roots = TOOL_ROOTS[name] | {dist_info}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not names or len(names) != len(set(names)):
            raise ValueError("empty or duplicate wheel paths")
        for filename in names:
            parts = PurePosixPath(filename).parts
            if (
                not parts
                or parts[0] not in roots
                or ".." in parts
                or "\\" in filename
                or filename.startswith("/")
            ):
                raise ValueError("tool wheel contains an unapproved import path")


def candidate_coordinate(native: dict, coordinates: dict, identity: dict) -> dict:
    candidate = coordinates["target"]
    if (
        native["schema"] != "dotmac.candidate_native_acceptance/1"
        or native["candidate"] != candidate
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", candidate["config_digest"])
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", coordinates["docker_image_ids"]["target"]
        )
        or any(
            identity[key] != candidate[key]
            for key in ("config_digest", "source_revision", "platform", "layers")
        )
    ):
        raise ValueError(
            "continuation contract candidate differs from native candidate"
        )
    return candidate


def prepare(
    root: Path, destination: Path, native: Path, coordinates: Path, identity: Path
) -> str:
    observed = json.loads(coordinates.read_text())
    candidate = candidate_coordinate(
        json.loads(native.read_text()), observed, json.loads(identity.read_text())
    )
    docker_image_id = observed["docker_image_ids"]["target"]
    wheels = select_wheels(tomllib.loads((root / "poetry.lock").read_text()))
    destination.mkdir(mode=0o755)
    sources = {}
    for name in TESTS:
        raw = (root / "tests/unit" / name).read_bytes()
        (destination / name).write_bytes(raw)
        sources[name] = sha256(raw)
    shutil.copyfile(__file__, destination / Path(__file__).name)
    requirements = destination / "pytest-requirements.txt"
    requirements.write_text(
        "".join(
            f"{name}=={pin['version']} --hash={pin['sha256']}\n"
            for name, pin in wheels.items()
        )
    )
    subprocess.run(  # noqa: S603 - fixed interpreter/pip argv and locked hashes
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--index-url",
            "https://pypi.org/simple",
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            "--dest",
            str(destination),
            "--requirement",
            str(requirements),
        ],
        check=True,
        stdout=sys.stderr,
    )
    if {p.name for p in destination.glob("*.whl")} != {
        pin["filename"] for pin in wheels.values()
    }:
        raise ValueError("download did not produce the exact five locked pure wheels")
    for name, pin in wheels.items():
        path = destination / pin["filename"]
        validate_wheel(path, name, pin)
    (destination / "inputs.json").write_text(
        json.dumps(
            {
                "tests": sources,
                "tools": wheels,
                "candidate": candidate,
                "docker_image_id": docker_image_id,
            },
            sort_keys=True,
        )
        + "\n"
    )
    # The candidate runs as the image's service UID, not runner/root.
    for path in destination.iterdir():
        path.chmod(0o644)
    return docker_image_id


def verify_vectors(native: dict) -> None:
    vectors = native["installed_contract_vectors"]
    raw = vectors["report_raw_utf8"].encode("utf-8")
    report = vectors["report"]
    if (
        sha256(raw) != vectors["report_raw_sha256"]
        or json.loads(raw) != report
        or vectors["scope"] != REPORT_SCOPE
        or report["schema"] != REPORT_SCHEMA
        or report["scope"] != REPORT_SCOPE
        or vectors["candidate"] != native["candidate"]
        or report["inputs"]["candidate"] != native["candidate"]
        or vectors["docker_image_id"] != report["inputs"]["docker_image_id"]
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", vectors["docker_image_id"])
        or type(report["collected"]) is not int
        or report["collected"] != len(report["cases"])
        or report["passed"] != report["collected"]
        or report["rejected"] != 0
        or report["modules"]
        != {
            name: sum(n.startswith(name + "::") for n in report["cases"])
            for name in COLLECT
        }
    ):
        raise ValueError(
            "continuation report digest, results or candidate binding differs"
        )
    results = Results()
    results.collected = report["cases"]
    results.passed = report["cases"]
    results.accept(0)


def bind_report(native_path: Path, report_path: Path, coordinates_path: Path) -> None:
    native = json.loads(native_path.read_text())
    if (
        native["schema"] != "dotmac.candidate_native_acceptance/1"
        or "installed_contract_vectors" in native
    ):
        raise ValueError(
            "native report is invalid or continuation report is already bound"
        )
    raw = report_path.read_bytes()
    report = json.loads(raw)
    coordinates = json.loads(coordinates_path.read_text())
    if (
        native["candidate"] != coordinates["target"]
        or report["inputs"]["docker_image_id"]
        != coordinates["docker_image_ids"]["target"]
    ):
        raise ValueError(
            "report Docker image ID differs from the saved native candidate"
        )
    native["installed_contract_vectors"] = {
        "scope": REPORT_SCOPE,
        "candidate": native["candidate"],
        "docker_image_id": report["inputs"]["docker_image_id"],
        "report": report,
        "report_raw_utf8": raw.decode("utf-8"),
        "report_raw_sha256": sha256(raw),
    }
    verify_vectors(native)
    # Retain inside the existing uploaded native report. This joins candidate
    # identity; it adds no cryptographic field to the release-receipt contract.
    temporary = native_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(native, sort_keys=True) + "\n")
    temporary.replace(native_path)


def installed_origins() -> dict[str, str]:
    purelib = Path(sysconfig.get_path("purelib")).resolve()
    dist = importlib.metadata.distribution("dotmac-vendor-control-plane")
    records = {Path(dist.locate_file(p)).resolve(): p for p in dist.files or ()}
    result = {}
    for name, module in sorted(sys.modules.items()):
        if name != "vendor_cp" and not name.startswith("vendor_cp."):
            continue
        origin = Path(module.__file__).resolve()
        record = records.get(origin)
        if not origin.is_relative_to(purelib) or record is None or record.hash is None:
            raise ValueError(f"module is outside installed wheel RECORD: {name}")
        expected = record.hash
        actual = base64.urlsafe_b64encode(hashlib.sha256(origin.read_bytes()).digest())
        if expected.mode != "sha256" or actual.decode().rstrip("=") != expected.value:
            raise ValueError(f"installed module differs from wheel RECORD: {name}")
        result[name] = str(origin)
    if not {"vendor_cp", *OWNERS} <= result.keys():
        raise ValueError("installed continuation owner was not imported")
    return result


class Results:
    def __init__(self):
        self.collected = []
        self.passed = []
        self.rejected = []

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_deselected(self, items):
        self.rejected.extend(item.nodeid for item in items)

    def pytest_collectreport(self, report):
        if report.failed or report.skipped:
            self.rejected.append(report.nodeid)

    def pytest_runtest_logreport(self, report):
        if report.failed or report.skipped or hasattr(report, "wasxfail"):
            self.rejected.append(report.nodeid)
        elif report.when == "call" and report.passed:
            self.passed.append(report.nodeid)

    def accept(self, exit_code: int) -> None:
        if (
            exit_code != 0
            or not self.collected
            or self.rejected
            or sorted(self.passed) != sorted(self.collected)
            or len(self.collected) != len(set(self.collected))
            or any(
                not any(n.startswith(t + "::") for t in COLLECT) for n in self.collected
            )
            or any(
                not any(n.startswith(t + "::") for n in self.collected) for t in COLLECT
            )
        ):
            raise ValueError(
                "continuation cases must all execute and pass without skips"
            )


def run(root: Path) -> None:
    if sys.platform != "linux" or sys.version_info[:2] != (3, 12):
        raise ValueError("requires the candidate Linux Python 3.12 interpreter")
    manifest = json.loads((root / "inputs.json").read_text())
    if set(manifest["tests"]) != set(TESTS) or set(manifest["tools"]) != set(
        TOOL_ROOTS
    ):
        raise ValueError("unexpected continuation test inputs")
    for name, checksum in manifest["tests"].items():
        if sha256((root / name).read_bytes()) != checksum:
            raise ValueError("selected test file changed after preparation")
    paths = []
    for name, pin in manifest["tools"].items():
        path = root / pin["filename"]
        validate_wheel(path, name, pin)
        paths.append(str(path))
    # -I omits cwd, script directory and PYTHONPATH. Add only fixed test-helper
    # and allowlisted, rehashed tool paths; vendor_cp stays in installed purelib.
    sys.path[:0] = [str(root), *paths]
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    for name in OWNERS:
        importlib.import_module(name)
    before = installed_origins()
    import pytest

    results = Results()
    with contextlib.redirect_stdout(sys.stderr):
        code = pytest.main(
            [
                "-q",
                "-c",
                "/dev/null",
                "--rootdir",
                str(root),
                "--confcutdir",
                str(root),
                "-p",
                "no:cacheprovider",
                "--basetemp",
                "/tmp/continuation-tests",  # noqa: S108 - private container tmpfs
                *(str(root / name) for name in COLLECT),
            ],
            plugins=[results],
        )
    after = installed_origins()
    if any(after.get(name) != path for name, path in before.items()):
        raise ValueError("installed origins changed during continuation cases")
    results.accept(int(code))
    print(
        json.dumps(
            {
                "schema": REPORT_SCHEMA,
                "scope": REPORT_SCOPE,
                "collected": len(results.collected),
                "passed": len(results.passed),
                "rejected": 0,
                "cases": results.collected,
                "modules": {
                    name: sum(n.startswith(name + "::") for n in results.collected)
                    for name in COLLECT
                },
                "installed_origins": after,
                "inputs": manifest,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "prepare":
        print(prepare(*(Path(p).resolve() for p in sys.argv[2:])))
    elif len(sys.argv) == 5 and sys.argv[1] == "bind":
        bind_report(*(Path(p) for p in sys.argv[2:]))
    elif len(sys.argv) == 2 and sys.argv[1] == "run":
        run(Path(__file__).resolve().parent)
    else:
        raise SystemExit(
            "usage: harness prepare <checkout> <new-directory> <native-report> "
            "<coordinates> <identity> | bind <native-report> <contract-report> "
            "<coordinates> | run"
        )
