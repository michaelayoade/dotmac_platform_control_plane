"""The E10 command's pure rules (CP-3): digest, PoP, transit key read-back, refusals.

The database-backed behaviour (Control's registry, the receipt rows, the store's
verification) is exercised against real PostgreSQL in
`tests/migration/test_lane3_e10_database.py`. Everything here runs with no
database: every refusal below fires BEFORE the database is touched, which the
`db=None` argument proves by raising if it is.
"""

from __future__ import annotations

import base64
import hashlib
import io
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vendor_cp.deployment import lane3_e10 as e10

SEED = bytes(range(64, 96))
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
RAW = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
NONCE = bytes(range(32))
HOST = "host-a"


def _sign(message: bytes, key: Ed25519PrivateKey = KEY) -> str:
    return "vault:v1:" + base64.b64encode(key.sign(message)).decode("ascii")


def _transit(raw: bytes = RAW, **override: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "type": "ed25519",
        "exportable": False,
        "allow_plaintext_backup": False,
        "derived": False,
        "deletion_allowed": False,
        "keys": {"1": {"public_key": base64.b64encode(raw).decode("ascii")}},
    }
    document.update(override)
    return {"data": document}


def _request(**override: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "host_id": HOST,
        "vm_alias": "vm-alpha",
        "vm_slot": None,
        "machine_id": "0123456789abcdef0123456789abcdef",
        "ssh_host_key_fingerprint": "SHA256:" + "B" * 43,
        "mount": "transit-a2-hi-vm-alpha-1",
        "transit_key": _transit(),
        "pop_signature": _sign(e10.incarnation_pop_message(HOST, NONCE)),
        "nonce": base64.urlsafe_b64encode(NONCE).decode().rstrip("="),
        "issuer": "urn:dotmac:foundation:installed-host-ceremony:a2",
        "attestation_key_id": "incarnation-1",
        "not_after": "2026-12-31T00:00:00Z",
        "recorded_by": "operator",
    }
    request.update(override)
    return request


class _NoDatabase:
    def execute(self, *_: Any, **__: Any) -> Any:
        raise AssertionError("the database was touched before a refusal")


class _NoRegistry:
    def enrol(self, *_: Any, **__: Any) -> Any:
        raise AssertionError("Control was asked before a refusal")

    def revoke(self, *_: Any, **__: Any) -> None:
        raise AssertionError("Control was asked before a refusal")


def _code(**override: Any) -> str:
    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_incarnation(_NoDatabase(), _NoRegistry(), _request(**override))
    return refused.value.code


# ── the pop messages ────────────────────────────────────────────────────────


def test_the_pop_messages_are_the_designs_exact_bytes() -> None:
    assert (
        e10.incarnation_pop_message("host-a", NONCE)
        == b"dotmac.lane3.incarnation-pop.v1\x00host-a\x00" + NONCE
    )
    assert (
        e10.candidate_pop_message("subject", NONCE)
        == b"dotmac.lane3.candidate-pop.v1\x00subject\x00" + NONCE
    )


@pytest.mark.parametrize(
    "prefix", [e10.INCARNATION_POP_PREFIX, e10.CANDIDATE_POP_PREFIX]
)
def test_a_pop_message_can_never_parse_as_a_json_envelope(prefix: bytes) -> None:
    """Domain separation: no transit signature over a PoP can be presented as one
    over an attestation envelope, because the signed bytes are not JSON."""
    import json

    with pytest.raises(ValueError):
        json.loads(prefix + b"host-a\x00" + NONCE)


def test_the_two_pop_prefixes_differ() -> None:
    assert e10.INCARNATION_POP_PREFIX != e10.CANDIDATE_POP_PREFIX


# ── the transit key read-back ───────────────────────────────────────────────


def test_a_key_with_every_flag_off_and_one_version_is_accepted() -> None:
    assert e10.parse_transit_key(_transit()) == RAW
    assert e10.parse_transit_key(_transit()["data"]) == RAW  # no `data` envelope


@pytest.mark.parametrize(
    "flag", ["exportable", "allow_plaintext_backup", "derived", "deletion_allowed"]
)
def test_any_flag_that_could_let_the_key_leave_transit_refuses(flag: str) -> None:
    with pytest.raises(e10.E10Refused) as refused:
        e10.parse_transit_key(_transit(**{flag: True}))
    assert refused.value.code == "transit-key-flag"


def test_an_absent_flag_is_a_refusal_not_a_default() -> None:
    document = _transit()
    del document["data"]["exportable"]
    with pytest.raises(e10.E10Refused) as refused:
        e10.parse_transit_key(document)
    assert refused.value.code == "transit-key-flag"


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"type": "rsa-4096"}, "transit-key-type"),
        ({"keys": {"1": {"public_key": "AAAA"}}}, "public-key-invalid"),
        (
            {"keys": {"1": {"public_key": "x"}, "2": {"public_key": "y"}}},
            "transit-key-versions",
        ),
        ({"keys": {}}, "transit-key-versions"),
        ({"keys": {"2": {"public_key": "AAAA"}}}, "transit-key-versions"),
        ({"keys": "no"}, "transit-key-versions"),
    ],
)
def test_a_key_that_is_not_one_32_byte_ed25519_version_refuses(
    override: dict[str, Any], code: str
) -> None:
    with pytest.raises(e10.E10Refused) as refused:
        e10.parse_transit_key(_transit(**override))
    assert refused.value.code == code


def test_a_key_of_the_wrong_length_refuses() -> None:
    with pytest.raises(e10.E10Refused) as refused:
        e10.parse_transit_key(_transit(RAW + b"\x00"))
    assert refused.value.code == "public-key-invalid"


# ── proof of possession ─────────────────────────────────────────────────────


def test_a_pop_over_the_exact_message_verifies() -> None:
    message = e10.incarnation_pop_message(HOST, NONCE)
    e10.verify_pop(RAW, _sign(message), message)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m + b"x",
        lambda m: e10.incarnation_pop_message("host-b", NONCE),
        lambda m: e10.incarnation_pop_message(HOST, bytes(32)),
        lambda m: e10.candidate_pop_message(HOST, NONCE),
    ],
)
def test_a_pop_over_any_other_message_refuses(mutate: Any) -> None:
    message = e10.incarnation_pop_message(HOST, NONCE)
    with pytest.raises(e10.E10Refused) as refused:
        e10.verify_pop(RAW, _sign(message), mutate(message))
    assert refused.value.code == "pop-invalid"


def test_a_pop_by_another_key_refuses() -> None:
    message = e10.incarnation_pop_message(HOST, NONCE)
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    with pytest.raises(e10.E10Refused) as refused:
        e10.verify_pop(RAW, _sign(message, other), message)
    assert refused.value.code == "pop-invalid"


@pytest.mark.parametrize(
    "signature", ["", "AAAA", "vault:v2:AAAA", "vault:v1:", "vault:v1:@@@", None, 7]
)
def test_a_malformed_pop_refuses(signature: object) -> None:
    with pytest.raises(e10.E10Refused) as refused:
        e10.verify_pop(RAW, signature, b"message")
    assert refused.value.code in {"pop-malformed", "pop-invalid"}


# ── enrol-incarnation: every refusal precedes the database ─────────────────


def test_a_request_with_a_missing_or_extra_member_refuses() -> None:
    request = _request()
    del request["nonce"]
    with pytest.raises(e10.E10Refused) as refused:
        e10.enrol_incarnation(_NoDatabase(), _NoRegistry(), request)
    assert refused.value.code == "request-malformed"
    with pytest.raises(e10.E10Refused):
        e10.enrol_incarnation(_NoDatabase(), _NoRegistry(), _request(extra="x"))


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"host_id": "Host_A"}, "host-id-invalid"),
        ({"host_id": "-host"}, "host-id-invalid"),
        ({"vm_alias": "VM"}, "vm-alias-invalid"),
        ({"vm_slot": "proxmox"}, "vm-slot-invalid"),
        ({"machine_id": "abc"}, "machine-id-invalid"),
        ({"ssh_host_key_fingerprint": "sha256:" + "a" * 64}, "ssh-fingerprint-invalid"),
        ({"mount": "transit-a2-hi-other-1"}, "mount-invalid"),
        ({"mount": "transit-a2-cp"}, "mount-invalid"),
        ({"not_after": "2026-12-31"}, "not-after-invalid"),
        ({"nonce": "short"}, "nonce-invalid"),
        ({"recorded_by": "has space"}, "recorded-by-invalid"),
    ],
)
def test_a_malformed_fact_refuses_before_any_database_access(
    override: dict[str, Any], code: str
) -> None:
    assert _code(**override) == code


def test_a_pop_for_another_host_refuses() -> None:
    other = e10.incarnation_pop_message("host-b", NONCE)
    assert _code(pop_signature=_sign(other)) == "pop-invalid"


def test_a_pop_with_another_nonce_refuses() -> None:
    other = e10.incarnation_pop_message(HOST, bytes(32))
    assert _code(pop_signature=_sign(other)) == "pop-invalid"


def test_a_key_that_can_be_exported_never_reaches_the_registry() -> None:
    assert _code(transit_key=_transit(exportable=True)) == "transit-key-flag"


def test_the_mount_must_belong_to_this_vm_alias() -> None:
    assert _code(mount="transit-a2-hi-vm-beta-1") == "mount-invalid"


# ── the digest: one rule ────────────────────────────────────────────────────

ROW: dict[str, Any] = {
    "receipt_ref": "e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11",
    "vm_alias": "vm-alpha",
    "host_id": HOST,
    "machine_id": "0123456789abcdef0123456789abcdef",
    "ssh_host_key_fingerprint": "SHA256:" + "B" * 43,
    "vm_slot": None,
    "incarnation_public_key_b64url": base64.urlsafe_b64encode(RAW).decode().rstrip("="),
    "incarnation_fingerprint": "sha256:" + hashlib.sha256(RAW).hexdigest(),
    "enrolment_uuid": "6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b12",
    "key_custody_pointer": "bao://transit-a2-hi-vm-alpha-1/keys/incarnation",
    "recorded_by": "operator",
    "recorded_at": "2026-11-19T10:00:00.250000Z",
    "seq": 7,
}


def test_the_digest_is_sha256_over_the_canonical_row_with_a_trailing_newline() -> None:
    expected = (
        "sha256:"
        + hashlib.sha256(
            (
                '{"enrolment_uuid":"6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b12",'
                f'"host_id":"{HOST}","incarnation_fingerprint":"'
                + str(ROW["incarnation_fingerprint"])
                + '","incarnation_public_key_b64url":"'
                + str(ROW["incarnation_public_key_b64url"])
                + '","key_custody_pointer":'
                '"bao://transit-a2-hi-vm-alpha-1/keys/incarnation",'
                '"machine_id":"0123456789abcdef0123456789abcdef",'
                '"receipt_ref":"e10-6f1c2f4e-52a8-4d0e-9a1b-2f0c7e6d9b11",'
                '"recorded_at":"2026-11-19T10:00:00.250000Z",'
                '"recorded_by":"operator","seq":7,'
                '"ssh_host_key_fingerprint":"SHA256:' + "B" * 43 + '",'
                '"vm_alias":"vm-alpha","vm_slot":null}\n'
            ).encode("ascii")
        ).hexdigest()
    )
    assert e10.receipt_digest(ROW) == expected


def test_the_digest_changes_with_any_member() -> None:
    base = e10.receipt_digest(ROW)
    for name in e10.RECEIPT_EXPORT_KEYS:
        changed = dict(ROW)
        changed[name] = 99 if name == "seq" else "x"
        if name == "vm_slot":
            changed[name] = "node/1"
        assert e10.receipt_digest(changed) != base, name


@pytest.mark.parametrize("mutation", ["drop", "add"])
def test_the_digest_refuses_a_row_that_is_not_the_closed_thirteen(
    mutation: str,
) -> None:
    row = dict(ROW)
    if mutation == "drop":
        del row["seq"]
    else:
        row["extra"] = 1
    with pytest.raises(e10.E10Refused):
        e10.receipt_digest(row)


def test_the_step3_receipt_is_the_nine_member_shape() -> None:
    assert set(e10.step3_receipt(ROW)) == {
        "vm_alias",
        "host_id",
        "machine_id",
        "ssh_host_key_fingerprint",
        "incarnation_public_key_b64url",
        "incarnation_fingerprint",
        "enrolment_uuid",
        "receipt_ref",
        "vm_slot",
    }


def test_time_is_always_utc_with_microseconds() -> None:
    from datetime import UTC, datetime, timedelta, timezone

    zone = timezone(timedelta(hours=1))
    assert (
        e10.format_time(datetime(2026, 11, 19, 11, 0, 0, tzinfo=zone))
        == "2026-11-19T10:00:00.000000Z"
    )
    assert (
        e10.format_time(datetime(2026, 11, 19, 10, 0, 0, 5, tzinfo=UTC))
        == "2026-11-19T10:00:00.000005Z"
    )
    with pytest.raises(e10.E10Refused):
        e10.format_time(datetime(2026, 11, 19, 10, 0, 0))


# ── the CLI ─────────────────────────────────────────────────────────────────


def test_challenge_prints_a_fresh_32_byte_nonce(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert e10.main(["challenge", "--kind", "incarnation"], environ={}) == 0
    first = capsys.readouterr().out
    assert e10.main(["challenge", "--kind", "candidate"], environ={}) == 0
    second = capsys.readouterr().out
    nonces = [
        line.split("=", 1)[1]
        for text in (first, second)
        for line in text.splitlines()
        if line.startswith("nonce=")
    ]
    assert len(nonces) == 2 and nonces[0] != nonces[1]
    for nonce in nonces:
        assert len(base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))) == 32


def test_a_missing_owner_dsn_is_a_typed_refusal_naming_the_variable_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = e10.main(["show", "--receipt-ref", "e10-x"], environ={})
    assert code == 2
    assert "dsn-missing" in capsys.readouterr().err


def test_libpq_environment_variables_refuse_by_name_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = e10.main(
        ["show", "--receipt-ref", "e10-x"],
        environ={e10.DSN_ENV: "postgresql://u:s3cret@h/d", "PGPASSWORD": "s3cret"},
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "libpq-environment" in err and "s3cret" not in err


def test_an_oversized_or_malformed_stdin_refuses() -> None:
    with pytest.raises(e10.E10Refused):
        e10._stdin_json(io.StringIO(""))
    with pytest.raises(e10.E10Refused):
        e10._stdin_json(io.StringIO("[1]"))
    with pytest.raises(e10.E10Refused):
        e10._stdin_json(io.StringIO("{" + " " * (1024 * 1024 + 1)))
