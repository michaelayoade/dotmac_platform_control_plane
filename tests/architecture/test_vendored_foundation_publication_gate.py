"""Publication refuses a provisional vendored pin; PR-head builds do not (M1, N1)."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / ".github" / "candidate" / "require_certified_vendored_pins.py"
PINS_PATH = ROOT / "src" / "vendor_cp" / "vendored_foundation" / "PINS.json"
SHIPPED = ROOT / ".github" / "vendored-foundation"
SSH_KEYGEN = "/usr/bin/ssh-keygen"

spec = importlib.util.spec_from_file_location("require_certified", GATE_PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _run(pins_path: Path, base: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(GATE_PATH), str(pins_path), str(base)],
        capture_output=True,
        text=True,
    )


def _sign(base: Path, key: Path, record: Path, namespace: str) -> None:
    """`ssh-keygen -Y sign` writes `<record>.sig` beside the record (inside `base`)."""
    (base / gate.SIGNATURE.name).unlink(missing_ok=True)
    subprocess.run(  # noqa: S603
        [SSH_KEYGEN, "-Y", "sign", "-q", "-f", str(key), "-n", namespace, str(record)],
        check=True,
    )


class World:
    """A synthetic certified world: a throwaway key, record, signature and signers."""

    def __init__(self, tmp: Path) -> None:
        self.base = tmp / "vf"
        self.base.mkdir()
        self.key = tmp / "key"
        subprocess.run(  # noqa: S603
            [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        self.pins: dict[str, Any] = json.loads(PINS_PATH.read_text("utf-8"))
        self.pins["status"] = "CERTIFIED"
        self.write_record(self.record_document())
        self.write_signers(gate.PRINCIPAL, gate.NAMESPACE)

    def record_document(self) -> dict[str, Any]:
        return {
            "schema": gate.SCHEMA,
            "certifies": {
                "source_commit": self.pins["source_commit"],
                "foundation_src_tree": self.pins["foundation_src_tree"],
                "files": {n: f["sha256"] for n, f in self.pins["files"].items()},
                "wheel_only_checks": {
                    n: f["sha256"] for n, f in self.pins["wheel_only_checks"].items()
                },
            },
        }

    def write_record_bytes(self, raw: bytes) -> None:
        """A record whose exact bytes the test controls; digest and signature follow."""
        record = self.base / gate.RECORD.name
        record.write_bytes(raw)
        self.pins["e5_record_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        _sign(self.base, self.key, record, gate.NAMESPACE)

    def write_record(
        self, document: dict[str, Any], namespace: str | None = None
    ) -> None:
        record = self.base / gate.RECORD.name
        record.write_bytes(json.dumps(document, sort_keys=True).encode())
        self.pins["e5_record_digest"] = (
            "sha256:" + hashlib.sha256(record.read_bytes()).hexdigest()
        )
        _sign(self.base, self.key, record, namespace or gate.NAMESPACE)

    def write_signers(self, principal: str, namespace: str) -> None:
        public = (self.key.parent / "key.pub").read_text("utf-8").split()
        line = f'{principal} namespaces="{namespace}" {public[0]} {public[1]}\n'
        (self.base / gate.ALLOWED_SIGNERS.name).write_text(line, encoding="utf-8")

    def run(self) -> subprocess.CompletedProcess[str]:
        pins = self.base.parent / "pins.json"
        pins.write_text(json.dumps(self.pins), encoding="utf-8")
        return _run(pins, self.base)


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path)


def test_the_committed_pin_is_provisional_so_publication_refuses_today() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GATE_PATH), str(PINS_PATH), str(SHIPPED)],
        capture_output=True,
        text=True,
    )
    assert (
        json.loads(PINS_PATH.read_text("utf-8"))["status"] == "PROVISIONAL-PENDING-E5"
    )
    assert result.returncode == 1
    assert "not 'CERTIFIED'" in result.stderr


def test_the_shipped_signer_file_pins_no_signer_and_no_record_exists_yet() -> None:
    raw = (SHIPPED / "allowed_signers").read_bytes()
    assert not gate._signers_present(raw)
    assert not (SHIPPED / "e5-certification.json").exists()
    assert not (SHIPPED / "e5-certification.json.sig").exists()


def test_a_certified_pin_whose_record_and_signature_verify_is_admitted(
    world: World,
) -> None:
    result = world.run()
    assert result.returncode == 0, result.stderr


def test_a_forged_digest_is_refused(world: World) -> None:
    world.pins["e5_record_digest"] = "sha256:" + "a" * 64
    result = world.run()
    assert result.returncode == 1
    assert "not the sha256 of the E5 certification record" in result.stderr


def test_a_record_certifying_different_source_is_refused(world: World) -> None:
    for field, value in (
        ("source_commit", "0" * 40),
        ("foundation_src_tree", "1" * 40),
    ):
        document = world.record_document()
        document["certifies"][field] = value
        world.write_record(document)
        assert world.run().returncode == 1, field
    document = world.record_document()
    first = next(iter(document["certifies"]["files"]))
    document["certifies"]["files"][first] = "2" * 64
    world.write_record(document)
    result = world.run()
    assert result.returncode == 1
    assert "does not certify exactly the pinned source" in result.stderr


def test_the_record_must_bind_the_wheel_init_hash_too(world: World) -> None:
    document = world.record_document()
    document["certifies"]["wheel_only_checks"]["__init__.py"] = "4" * 64
    world.write_record(document)
    assert "does not certify exactly" in world.run().stderr
    document = world.record_document()
    del document["certifies"]["wheel_only_checks"]
    world.write_record(document)
    assert "does not certify exactly" in world.run().stderr


def test_the_record_schema_and_shape_are_fixed(world: World) -> None:
    for mutate in (
        lambda d: d.update(schema="other.v1"),
        lambda d: d.pop("schema"),
        lambda d: d.update(extra="x"),
        lambda d: d["certifies"].update(extra="x"),
        lambda d: d.pop("certifies"),
    ):
        document = world.record_document()
        mutate(document)
        world.write_record(document)
        assert world.run().returncode == 1


def test_a_record_with_a_duplicate_json_key_is_refused(world: World) -> None:
    good = json.dumps(world.record_document())
    # a second, different `schema` first, the real one last: last-wins parsers admit it
    world.write_record_bytes(('{"schema": "x", ' + good[1:]).encode())
    result = world.run()
    assert result.returncode == 1
    assert "malformed" in result.stderr
    world.write_record_bytes(b'{"schema": "a", "schema": "b"}')
    assert "malformed" in world.run().stderr
    world.write_record_bytes(b"[1, 2")
    assert "malformed" in world.run().stderr


def test_a_signature_by_another_key_or_namespace_is_refused(
    world: World, tmp_path: Path
) -> None:
    other = tmp_path / "other"
    subprocess.run(  # noqa: S603
        [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True
    )
    record = world.base / gate.RECORD.name
    _sign(world.base, other, record, gate.NAMESPACE)  # not the allowed signer
    assert "does not verify" in world.run().stderr
    world.write_record(world.record_document(), namespace="some-other-namespace@x")
    assert "does not verify" in world.run().stderr  # right key, wrong namespace


def test_a_tampered_record_after_signing_is_refused(world: World) -> None:
    record = world.base / gate.RECORD.name
    record.write_bytes(record.read_bytes() + b" ")
    world.pins["e5_record_digest"] = (
        "sha256:" + hashlib.sha256(record.read_bytes()).hexdigest()
    )
    assert "does not verify" in world.run().stderr


def test_a_missing_record_or_signature_is_refused(world: World) -> None:
    (world.base / gate.SIGNATURE.name).unlink()
    assert "unreadable" in world.run().stderr
    world.write_record(world.record_document())
    (world.base / gate.RECORD.name).unlink()
    assert "unreadable" in world.run().stderr


def test_an_empty_or_comment_only_allowed_signers_refuses_everything(
    world: World,
) -> None:
    (world.base / gate.ALLOWED_SIGNERS.name).write_text("", encoding="utf-8")
    assert "pins no signer" in world.run().stderr
    (world.base / gate.ALLOWED_SIGNERS.name).write_text(
        "# only a comment\n", encoding="utf-8"
    )
    assert "pins no signer" in world.run().stderr


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(status="PROVISIONAL-PENDING-E5"),
        lambda p: p.pop("e5_record_digest"),
        lambda p: p.update(e5_record_digest="sha256:" + "A" * 64),
        lambda p: p.update(e5_record_digest=7),
        lambda p: p.update(status="certified"),
    ],
)
def test_anything_short_of_certified_with_a_digest_is_refused(
    world: World, mutate: Any
) -> None:
    mutate(world.pins)
    assert world.run().returncode == 1


def test_a_non_object_pin_file_and_an_unreadable_one_are_refused(
    tmp_path: Path,
) -> None:
    assert gate.problems([]) != []
    result = _run(tmp_path / "absent.json", tmp_path)
    assert result.returncode == 2


def _signer_line(world: World, **parts: str) -> str:
    public = (world.key.parent / "key.pub").read_text("utf-8").split()
    fields = {
        "principal": gate.PRINCIPAL,
        "options": f'namespaces="{gate.NAMESPACE}"',
        "type": public[0],
        "key": public[1],
    }
    fields.update(parts)
    return " ".join(fields.values()) + "\n"


@pytest.mark.parametrize(
    "case",
    [
        "two-lines",
        "wrong-principal",
        "wildcard-principal",
        "no-options",
        "cert-authority",
        "extra-option",
        "wildcard-namespace",
        "other-namespace",
        "two-namespaces",
        "disallowed-key-type",
        "rsa-key-type",
        "malformed-key",
        "too-short",
    ],
)
def test_every_allowed_signers_violation_is_refused(world: World, case: str) -> None:
    ns = f'namespaces="{gate.NAMESPACE}"'
    line = {
        "two-lines": _signer_line(world) + _signer_line(world),
        "wrong-principal": _signer_line(world, principal="someone@dotmac.io"),
        "wildcard-principal": _signer_line(world, principal="*@dotmac.io"),
        "no-options": f"{gate.PRINCIPAL} " + _signer_line(world).split(" ", 2)[2],
        "cert-authority": _signer_line(world, options=f"cert-authority,{ns}"),
        "extra-option": _signer_line(world, options=f'{ns},valid-before="20991231"'),
        "wildcard-namespace": _signer_line(world, options='namespaces="*"'),
        "other-namespace": _signer_line(world, options='namespaces="other@x"'),
        "two-namespaces": _signer_line(
            world, options=f'namespaces="a@x,{gate.NAMESPACE}"'
        ),
        "disallowed-key-type": _signer_line(world, type="ssh-dss"),
        "rsa-key-type": _signer_line(world, type="ssh-rsa"),
        "malformed-key": _signer_line(world, key="not base64 !!"),
        "too-short": f"{gate.PRINCIPAL} {ns}\n",
    }[case]
    (world.base / gate.ALLOWED_SIGNERS.name).write_text(line, encoding="utf-8")
    result = world.run()
    assert result.returncode == 1, result.stderr
    assert "allowed_signers" in result.stderr


def test_one_conformant_signer_line_with_a_comment_and_blank_lines_is_admitted(
    world: World,
) -> None:
    line = _signer_line(world).rstrip("\n") + " ceremony key\n"
    text = "# header\n\n" + line + "\n# trailer\n"
    (world.base / gate.ALLOWED_SIGNERS.name).write_text(text, encoding="utf-8")
    assert world.run().returncode == 0


def test_the_allowed_key_types_are_exactly_the_four_named() -> None:
    assert gate.KEY_TYPES == {
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }


def test_the_gate_runs_on_the_publication_path_and_not_in_ordinary_ci() -> None:
    publication = (ROOT / ".github/workflows/production-image.yml").read_text("utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text("utf-8")
    assert "require_certified_vendored_pins.py" in publication
    # before the image is built, so a refused pin publishes nothing
    assert publication.index("require_certified_vendored_pins.py") < publication.index(
        "docker buildx build"
    )
    # the PR-head image build (dry run 2) and the ordinary CI image job stay open
    assert "require_certified_vendored_pins.py" not in ci


def test_the_world_fixture_is_not_vacuous(world: World) -> None:
    """SENSITIVITY: an admitted world is refused once one input moves."""
    assert world.run().returncode == 0
    broken = copy.deepcopy(world.pins)
    broken["files"]["errors.py"]["sha256"] = "3" * 64
    world.pins = broken
    assert world.run().returncode == 1
