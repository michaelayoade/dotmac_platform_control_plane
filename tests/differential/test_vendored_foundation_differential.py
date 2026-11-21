"""The vendored step-8 verifier against a Foundation wheel built from the pin (H1).

PROVISIONAL-PENDING-E5. The hosted `vendored-verifier-differential` job builds a
wheel from Starter commit e4f9a072, installs it into a SEPARATE venv (so CP's own
environment never gains Foundation) and exports `FOUNDATION_WHEEL_PYTHON`. This
test runs the same corpus through that wheel and through the vendored copy and
requires the same accept/refuse result, the same error class and stable code, the
same message, the same `signed_bytes` and the same envelope digest. It then checks
the Ed25519 signature the way step 8 does, over BOTH `signed_bytes`, so forged and
tampered fixtures agree end to end. Keys are synthetic and derived from labels.

Without the environment variable the tests skip, unless
`VENDORED_FOUNDATION_REQUIRED=1`, in which case a missing wheel FAILS: a skipped
security test is not a passing one.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vendor_cp.vendored_foundation import trusted_host_source as vendored

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "foundation_runner.py"
PINS = json.loads(
    (
        HERE.parents[1] / "src" / "vendor_cp" / "vendored_foundation" / "PINS.json"
    ).read_text(encoding="utf-8")
)


def _wheel_python() -> str:
    value = os.environ.get("FOUNDATION_WHEEL_PYTHON")
    if not value:
        if os.environ.get("VENDORED_FOUNDATION_REQUIRED") == "1":
            pytest.fail("FOUNDATION_WHEEL_PYTHON is required in this job")
        pytest.skip("the hosted differential job supplies the Foundation wheel venv")
    return value


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _fingerprint(key: Ed25519PrivateKey) -> str:
    return "sha256:" + hashlib.sha256(_public(key)).hexdigest()


def _base(key: Ed25519PrivateKey) -> dict[str, Any]:
    return {
        "schema": "TrustedHostAttestation.v2",
        "purpose": "dotmac.foundation.installed-host.v2",
        "issuer": "urn:dotmac:foundation:installed-host-ceremony:test",
        "key_id": "synthetic-1",
        "algorithm": "ed25519",
        "public_key_fingerprint": _fingerprint(key),
        "custody_domain": "host_attester",
        "trust_root_version": "11111111-1111-4111-8111-111111111111",
        "issued_at": "2026-11-19T10:00:00Z",
        "expires_at": "2031-01-01T00:00:00Z",
        "audience": "host-synthetic",
        "observation_id": "22222222-2222-4222-8222-222222222222",
        "subject": {"host_identity": "host-synthetic", "n": 1},
        "signature": "AAAA",
    }


def _signed(key: Ed25519PrivateKey, **override: Any) -> dict[str, Any]:
    fields = _base(key)
    fields.update(override)
    envelope = vendored.AttestationEnvelopeV2.from_mapping(fields)
    fields["signature"] = base64.b64encode(key.sign(envelope.signed_bytes())).decode()
    return fields


def corpus() -> dict[str, Any]:
    good, other = _key("differential-good"), _key("differential-other")
    valid = _signed(good)
    forged = _signed(other)  # signed by another key, claims the good fingerprint
    forged["public_key_fingerprint"] = _fingerprint(good)
    tampered = copy.deepcopy(valid)
    tampered["subject"]["n"] = 2  # edited after signing
    stale = _signed(
        good, issued_at="2020-01-01T00:00:00Z", expires_at="2020-01-02T00:00:00Z"
    )
    cases: dict[str, Any] = {
        "valid": valid,
        "valid-fractional-seconds": _signed(
            good, issued_at="2026-11-19T10:00:00.123456Z"
        ),
        "valid-nested-subject": _signed(
            good, subject={"a": {"b": [1, 2, {"c": None}]}}
        ),
        "forged-other-key": forged,
        "forged-tampered-subject": tampered,
        "forged-truncated-signature": {**valid, "signature": valid["signature"][:8]},
        "forged-not-base64": {**valid, "signature": "!!not base64!!"},
        "stale-expired-long-ago": stale,
        "stale-expires-equals-issued": {**valid, "expires_at": valid["issued_at"]},
        "stale-expires-before-issued": {**valid, "expires_at": "2026-11-19T09:00:00Z"},
        "wrong-schema": {**valid, "schema": "TrustedHostAttestation.v1"},
        "bad-fingerprint-case": {
            **valid,
            "public_key_fingerprint": "sha256:" + "A" * 64,
        },
        "bad-fingerprint-length": {**valid, "public_key_fingerprint": "sha256:00"},
        "missing-member": {k: v for k, v in valid.items() if k != "audience"},
        "unknown-member": {**valid, "extra": "x"},
        "empty-field": {**valid, "issuer": ""},
        "padded-field": {**valid, "audience": " host-synthetic"},
        "non-string-field": {**valid, "key_id": 7},
        "subject-not-object": {**valid, "subject": "text"},
        "instant-not-utc": {**valid, "issued_at": "2026-11-19 10:00:00"},
        "instant-offset": {**valid, "expires_at": "2031-01-01T00:00:00+01:00"},
        "not-a-mapping-list": [valid],
        "not-a-mapping-null": None,
        "not-a-mapping-string": "envelope",
    }
    return cases


def _run_foundation(python: str, cases: dict[str, Any]) -> dict[str, dict[str, Any]]:
    done = subprocess.run(  # noqa: S603 - the CI-built wheel venv's interpreter
        [python, "-I", str(RUNNER), "dotmac_deployment_foundation"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
        cwd=str(HERE.parent),  # not the checkout root, so nothing shadows the wheel
    )
    return json.loads(done.stdout)  # type: ignore[no-any-return]


def _run_vendored(cases: dict[str, Any]) -> dict[str, dict[str, Any]]:
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(RUNNER), "vendor_cp.vendored_foundation"],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(HERE.parents[1] / "src")},
    )
    return json.loads(done.stdout)  # type: ignore[no-any-return]


def differences(
    left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]
) -> list[str]:
    """Case names whose recorded result differs (the harness's own check)."""
    return sorted(n for n in set(left) | set(right) if left.get(n) != right.get(n))


def test_the_wheel_is_the_pinned_foundation_and_not_the_checkout() -> None:
    python = _wheel_python()
    probe = subprocess.run(  # noqa: S603
        [
            python,
            "-I",
            "-c",
            "import dotmac_deployment_foundation.trusted_host_source as t, "
            "dotmac_deployment_foundation.errors as e, "
            "dotmac_deployment_foundation.digest as d, json;"
            "import dotmac_deployment_foundation as f;"
            "print(json.dumps([t.__file__, e.__file__, d.__file__, f.__file__]))",
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(HERE.parent),
    )
    paths = [Path(p) for p in json.loads(probe.stdout)]
    init = paths.pop()
    assert "site-packages" in init.parts
    assert (
        hashlib.sha256(init.read_bytes()).hexdigest()
        == PINS["wheel_only_checks"]["__init__.py"]["sha256"]
    ), "the wheel's package __init__ is not the E5 packet's"
    for name, path in zip(
        ("trusted_host_source.py", "errors.py", "digest.py"), paths, strict=True
    ):
        assert path.name == name
        assert (
            "site-packages" in path.parts
        ), "the wheel must be installed, not on a path"
        assert (
            hashlib.sha256(path.read_bytes()).hexdigest()
            == PINS["files"][name]["sha256"]
        ), f"the wheel's {name} is not the pinned source"


def test_same_accept_refuse_codes_and_digests_over_the_corpus() -> None:
    python = _wheel_python()
    cases = corpus()
    foundation = _run_foundation(python, cases)
    ours = _run_vendored(cases)
    assert set(foundation) == set(cases) == set(ours)
    assert differences(foundation, ours) == []
    accepted = {n for n, r in foundation.items() if r["outcome"] == "accepted"}
    refused = {n for n, r in foundation.items() if r["outcome"] == "refused"}
    # NON-VACUITY: both outcomes occur, and a refusal carries a stable code.
    assert len(accepted) >= 8 and len(refused) >= 12
    assert {foundation[n]["code"] for n in refused if foundation[n]["code"]} >= {
        "trusted-host-source-attestation-malformed"
    }


def test_forged_and_stale_fixtures_agree_end_to_end_with_the_signature_check() -> None:
    """Step 8's own verification, run over `signed_bytes` from each package."""
    python = _wheel_python()
    good = _key("differential-good")
    cases = corpus()
    foundation = _run_foundation(python, cases)
    ours = _run_vendored(cases)

    def verdict(result: dict[str, Any], case: Any) -> str:
        if result["outcome"] != "accepted":
            return f"refused:{result['code']}"
        envelope = vendored.AttestationEnvelopeV2.from_mapping(case)
        # same bytes (compared above by hash), so verifying with the local copy
        # of `signed_bytes` is verifying with either package's
        assert (
            hashlib.sha256(envelope.signed_bytes()).hexdigest()
            == result["signed_bytes_sha256"]
        )
        try:
            signature = base64.b64decode(case["signature"], validate=True)
            if len(signature) != 64:
                raise ValueError("length")
            Ed25519PublicKey.from_public_bytes(_public(good)).verify(
                signature, envelope.signed_bytes()
            )
        except (InvalidSignature, ValueError):
            return "signature-refused"
        return "signature-valid"

    verdicts = {
        n: (verdict(foundation[n], cases[n]), verdict(ours[n], cases[n])) for n in cases
    }
    assert all(a == b for a, b in verdicts.values()), verdicts
    assert verdicts["valid"][0] == "signature-valid"
    assert verdicts["valid-fractional-seconds"][0] == "signature-valid"
    assert verdicts["forged-other-key"][0] == "signature-refused"
    assert verdicts["forged-tampered-subject"][0] == "signature-refused"
    assert verdicts["forged-truncated-signature"][0] == "signature-refused"
    assert verdicts["forged-not-base64"][0] == "signature-refused"
    # stale at parse: expiry not after issue is refused by both with one code
    assert verdicts["stale-expires-equals-issued"][0].startswith("refused:")
    assert verdicts["stale-expires-before-issued"][0].startswith("refused:")
    # signed and well-formed but long expired: both accept at parse (expiry versus
    # database time is CP's own check in step 8, outside both packages)
    assert verdicts["stale-expired-long-ago"][0] == "signature-valid"


def test_the_differential_can_still_fail() -> None:
    """SENSITIVITY: a planted divergence is named; equal results are not."""
    cases = {"valid": corpus()["valid"]}
    ours = _run_vendored(cases)
    planted = copy.deepcopy(ours)
    planted["valid"]["envelope_digest"] = "sha256:" + "0" * 64
    assert differences(ours, planted) == ["valid"]
    refused = copy.deepcopy(ours)
    refused["valid"] = {"outcome": "refused", "error": "SpecError", "code": "x"}
    assert differences(ours, refused) == ["valid"]
    assert differences(ours, copy.deepcopy(ours)) == []
