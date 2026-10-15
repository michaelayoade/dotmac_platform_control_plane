"""Exercise the real native-container owner with a synthetic Docker adapter."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/candidate/accept_gate0_network.sh"
OWNED = "a" * 64
OTHER = "b" * 64


@pytest.mark.parametrize(
    "mode,expected,removed",
    [
        ("success", 0, True),
        ("failed-owned", 17, True),
        ("preexisting", 1, False),
        ("creation-collision", 1, False),
        ("cleanup-unknown", 1, True),
        ("bad-proof", 1, True),
    ],
)
def test_wrapper_removes_only_its_created_id_and_requires_cleanup(
    tmp_path: Path, mode: str, expected: int, removed: bool
) -> None:
    adapter = tmp_path / "bin"
    adapter.mkdir()
    docker = adapter / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "args=sys.argv[1:]; mode=os.environ['CASE_MODE']\n"
        "state=pathlib.Path(os.environ['CASE_STATE'])\n"
        "with open(os.environ['CASE_TRACE'],'a') as f:\n"
        "    f.write(json.dumps(args)+'\\n')\n"
        "if args[:2]==['container','ls']:\n"
        "    query=args[-1]\n"
        "    if query.startswith('id=') and mode=='cleanup-unknown': sys.exit(2)\n"
        "    if query.startswith('name=') and "
        "(mode=='preexisting' or state.exists()):\n"
        "        print('b'*64)\n"
        "elif args[0]=='run':\n"
        "    if mode=='creation-collision': state.write_text('other'); sys.exit(17)\n"
        "    pathlib.Path(args[args.index('--cidfile')+1]).write_text('a'*64)\n"
        "    if mode=='failed-owned': sys.exit(17)\n"
        "    print(json.dumps({'schema':'Gate0NativeNetworkPrivilegeProof.v1',"
        "'passed':True,'wrong_principal_refused_under_k':mode!='bad-proof',"
        "'refused_authentication_boundary_empty':True,"
        "'full_wireguard_installation_qualified':False,'live_readiness':False}))\n"
        "elif args[:2]==['container','rm']:\n"
        "    assert args==['container','rm','-f','a'*64]\n"
        "else: sys.exit(3)\n"
    )
    docker.chmod(0o700)
    trace = tmp_path / "trace.jsonl"
    output = tmp_path / "report.json"
    result = subprocess.run(  # noqa: S603 -- fixed reviewed script and fixture arguments
        ["/bin/bash", str(SCRIPT), "synthetic-candidate", str(output)],
        env={
            **os.environ,
            "PATH": str(adapter) + os.pathsep + os.environ["PATH"],
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
            "RUNNER_TEMP": str(tmp_path),
            "CASE_MODE": mode,
            "CASE_STATE": str(tmp_path / "other-container"),
            "CASE_TRACE": str(trace),
        },
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == expected, result.stderr
    calls = [json.loads(line) for line in trace.read_text().splitlines()]
    removals = [call for call in calls if call[:2] == ["container", "rm"]]
    assert removals == ([["container", "rm", "-f", OWNED]] if removed else [])
    assert not any(OTHER in call for call in removals)
    if expected == 0:
        assert json.loads(output.read_text())["passed"] is True
    if mode in {"creation-collision", "cleanup-unknown"}:
        assert b"unconfirmed" in result.stderr


def test_native_wrapper_bounds_the_exact_candidate_and_private_namespace() -> None:
    text = SCRIPT.read_text()
    for required in (
        "--network none --read-only --cap-drop ALL",
        "--cap-add NET_ADMIN",
        "--security-opt no-new-privileges:true",
        "--pids-limit 96 --memory 512m --cpus 1",
        "--tmpfs /run:rw,nosuid,nodev,noexec,size=16m,mode=0755",
        "timeout --signal=TERM --kill-after=5s 60s",
        '--entrypoint /opt/venv/bin/python "$image"',
        'docker container rm -f "$owned_id"',
        'docker container ls -aq --filter "id=$owned_id"',
        "full_wireguard_installation_qualified == false",
    ):
        assert required in text
    for forbidden in (
        "--privileged",
        "--network host",
        "--pid host",
        "--cap-add SYS_ADMIN",
        "--cap-add NET_RAW",
    ):
        assert forbidden not in text
