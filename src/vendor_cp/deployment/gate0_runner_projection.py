"""Closed A9 CP reads. Construction validates shape, never installation provenance.

TLS authenticates the installed server; that server alone verifies the Bearer
signature. The JWT payload here supplies a *restrictive* expiry cap only.
No DB, custody transport, mutation, retry, or installed entrypoint is composed.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from multiprocessing.connection import Connection
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from vendor_cp.deployment.gate0_composition import AdmissionExpectation, WindowFreshness
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_launch import parse_run_document
from vendor_cp.deployment.gate0_role_custody import (
    ProviderRefused,
    _BoundedHTTPReader,
    _BoundedHTTPSocket,
    _spawn_request,
)
from vendor_cp.deployment.gate0_runtime import AdmittedOperation
from vendor_cp.deployment.gate0_window import ApprovedWindowBinding, FrozenIssuerWindow

_MAXIMUM = 65536
_PREFIX = "/platform/vendor/gate0/collection/windows/"
_REFERENCE = "X-Dotmac-Gate0-Withdrawal-Reference"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z"
)


def _fields(value: object, names: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ProviderRefused()
    return cast(dict[str, Any], value)


def _text(value: object, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= maximum
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ProviderRefused()
    return value


def _uuid(value: object) -> str:
    value = _text(value)
    if str(UUID(value)) != value:
        raise ProviderRefused()
    return value


def _digest(value: object) -> str:
    value = _text(value)
    if _DIGEST.fullmatch(value) is None:
        raise ProviderRefused()
    return value


def _instant(value: object) -> datetime:
    result = datetime.fromisoformat(_text(value, 64).replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ProviderRefused()
    return result


@dataclass(frozen=True, slots=True)
class RunnerProjectionCase:
    """Inert protected inputs and one original clock mapping; no authenticity claim."""

    shared_packet: bytes = field(repr=False)
    frozen_window: bytes = field(repr=False)
    wall_origin: datetime
    monotonic_origin: float

    def __post_init__(self) -> None:
        packet, window = parse_run_document(self.shared_packet), self.window
        doc, capture = window.document, packet["capture"]
        if (
            type(self.wall_origin) is not datetime
            or self.wall_origin.tzinfo is None
            or self.wall_origin.utcoffset() != timedelta(0)
            or self.wall_origin > datetime.now(UTC)
            or type(self.monotonic_origin) not in (int, float)
            or not math.isfinite(self.monotonic_origin)
            or not 0 <= self.monotonic_origin <= time.monotonic()
            or capture["window_digest"] != window.digest
            or capture["target_id"] != doc["target"]["id"]
            or packet["controller_ca_fingerprint"]
            != doc["controller"]["ca_fingerprint"]
            or packet["case_kind"] != doc["case_kind"]
            or packet["not_before"] != doc["not_before"]
            or packet["expires_at"] != doc["expires_at"]
            or packet["run_id"] != doc["github"]["run_id"]
            or packet["run_attempt"] != doc["github"]["run_attempt"]
        ):
            raise ProviderRefused()

    @property
    def window(self) -> FrozenIssuerWindow:
        return FrozenIssuerWindow.parse(self.frozen_window)

    @property
    def start(self) -> float:
        return (
            self.monotonic_origin
            + (
                _instant(self.window.document["not_before"]) - self.wall_origin
            ).total_seconds()
        )

    @property
    def deadline(self) -> float:
        return (
            self.monotonic_origin
            + (
                _instant(self.window.document["expires_at"]) - self.wall_origin
            ).total_seconds()
        )

    @property
    def binding(self) -> dict[str, str]:
        packet, window = parse_run_document(self.shared_packet), self.window
        capture = packet["capture"]
        return {
            "window_digest": capture["window_digest"],
            "plan_id": capture["plan_id"],
            "plan_digest": capture["plan_digest"],
            "target_id": capture["target_id"],
            "approval_request_id": capture["approval_request_id"],
            "launch_packet_digest": "sha256:"
            + hashlib.sha256(self.shared_packet).hexdigest(),
            "case_kind": packet["case_kind"],
            "window_id": window.document["window_id"],
            "run_id": packet["run_id"],
            "run_attempt": packet["run_attempt"],
        }

    def require_open(self) -> None:
        now = datetime.now(UTC)
        if not (
            _instant(self.window.document["not_before"])
            <= now
            < _instant(self.window.document["expires_at"])
            and self.start <= time.monotonic() < self.deadline
        ):
            raise ProviderRefused()


def _jwt_deadline(token: str, case: RunnerProjectionCase) -> float:
    """Unverified exp cannot extend the original protected case interval."""
    if (
        type(token) is not str
        or not 0 < len(token) <= 32768
        or re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)
        is None
    ):
        raise ProviderRefused()
    payload = token.split(".")[1]
    if len(payload) > 24576:
        raise ProviderRefused()
    raw = base64.b64decode(
        payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True
    )
    claims = strict_object(raw, 24576)
    if (
        base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != payload
        or type(claims.get("exp")) is not int
    ):
        raise ProviderRefused()
    expiry = cast(int, claims["exp"])
    return min(
        case.deadline,
        case.monotonic_origin + expiry - case.wall_origin.timestamp(),
        time.monotonic() + 5.0,
    )


class _ProjectionHTTPResponse(http.client.HTTPResponse):
    """Apply CP's cumulative 16KiB line bound before HTTP parsing/allocation.

    Retain the bounded input stream after framed completion to require actual
    EOF (including buffered bytes) before success. Only close() releases it.
    """

    def __init__(
        self,
        sock: socket.socket,
        debuglevel: int = 0,
        method: str | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(
            cast(socket.socket, _BoundedHTTPSocket(sock)),
            debuglevel=debuglevel,
            method=method,
            url=url,
        )
        self._bounded_stream = cast(_BoundedHTTPReader, self.fp)

    def _close_conn(self) -> None:
        # HTTPResponse uses None for framed completion; typeshed narrows fp.
        self.fp = None  # type: ignore[assignment]

    def require_eof(self) -> None:
        if not self.isclosed() or self._bounded_stream.read(1):
            raise ProviderRefused()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._bounded_stream.close()


def _decode_response(response: _ProjectionHTTPResponse) -> bytes:
    lengths = response.headers.get_all("Content-Length") or []
    transfers = response.headers.get_all("Transfer-Encoding") or []
    if (
        response.status != 200
        or len(response.getheaders()) > 64
        or (response.headers.get_all("Content-Type") or []) != ["application/json"]
        or (response.headers.get_all("Content-Encoding") or [])
        not in ([], ["identity"])
        or (response.headers.get_all("Location") or [])
        or len(lengths) > 1
        or len(transfers) > 1
        or bool(lengths) == bool(transfers)
        or transfers
        and transfers != ["chunked"]
        or lengths
        and (
            re.fullmatch(r"[0-9]{1,6}", lengths[0]) is None
            or not 0 < int(lengths[0]) <= _MAXIMUM
        )
    ):
        raise ProviderRefused()
    raw = response.read(_MAXIMUM + 1)
    if not 0 < len(raw) <= _MAXIMUM or lengths and len(raw) != int(lengths[0]):
        raise ProviderRefused()
    response.require_eof()
    return raw


def _read_child(
    pipe: Connection,
    host: str,
    path: str,
    token: str,
    reference: str | None,
    timeout: float,
) -> None:
    """No redirect handling, proxy lookup, environment trust, or exception output."""
    connection = None
    response = None
    raw = None
    failed = False
    try:
        # Use compiled system trust paths, ignoring SSL_CERT_FILE/SSL_CERT_DIR.
        paths = ssl.get_default_verify_paths()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(
            cafile=paths.openssl_cafile, capath=paths.openssl_capath
        )
        connection = http.client.HTTPSConnection(
            host, 443, timeout=timeout, context=context
        )
        connection.response_class = _ProjectionHTTPResponse
        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Connection": "close",
        }
        if reference is not None:
            headers[_REFERENCE] = reference
        connection.request("GET", path, body=None, headers=headers)
        response = connection.getresponse()
        if type(response) is not _ProjectionHTTPResponse:
            raise ProviderRefused()
        raw = _decode_response(response)
    except BaseException:
        failed = True
    finally:
        try:
            if response is not None:
                response.close()
        except BaseException:
            failed = True
        try:
            if connection is not None:
                connection.close()
        except BaseException:
            failed = True
    # Failed transport cleanup suppresses the result before it enters IPC.
    try:
        if not failed and raw is not None:
            pipe.send_bytes(raw)
    except BaseException:  # noqa: S110 -- EOF only, no source diagnostics.
        pass
    finally:
        try:
            pipe.close()
        except BaseException:  # noqa: S110 -- teardown never emits source details.
            pass


def _request(
    host: str, path: str, token: str, reference: str | None, deadline: float
) -> bytes:
    """Reuse CP's existing cancellation owner without changing custody HTTP."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderRefused()
    raw = _spawn_request(
        _read_child, (host, path, token, reference, remaining), deadline
    )
    if not 0 < len(raw) <= _MAXIMUM:
        raise ProviderRefused()
    return raw


@dataclass(frozen=True, slots=True)
class ApprovalProjection:
    raw: bytes = field(repr=False)
    approved_at: datetime
    binding: ApprovedWindowBinding


@dataclass(frozen=True, slots=True)
class WithdrawalProjection:
    raw: bytes = field(repr=False)
    state: str
    withdrawal_id: str | None


def _document(
    raw: bytes, case: RunnerProjectionCase, schema: str, fields: str
) -> dict[str, Any]:
    case.require_open()
    doc = _fields(strict_object(raw, _MAXIMUM), fields)
    if (
        canonical(doc) != raw
        or doc["schema"] != schema
        or doc["binding"] != case.binding
    ):
        raise ProviderRefused()
    observed = _instant(doc["observed_at"])
    window = case.window.document
    if (
        not _instant(window["not_before"])
        <= observed
        <= datetime.now(UTC)
        < _instant(window["expires_at"])
    ):
        raise ProviderRefused()
    return doc


def decode_approval(raw: bytes, case: RunnerProjectionCase) -> ApprovalProjection:
    """Pure approved-at-read adapter; use only after authenticated CP transport."""
    doc = _document(
        raw,
        case,
        "Gate0CollectionApproval.v1",
        "schema binding frozen_window_b64 descriptor_digest "
        "authorized_image_digests approval observed_at",
    )
    encoded = _text(doc["frozen_window_b64"], 45000)
    if base64.b64encode(case.frozen_window).decode("ascii") != encoded:
        raise ProviderRefused()
    window = case.window
    w, b = window.document, case.binding
    approval = _fields(
        doc["approval"],
        "request_id subject_type subject_id content_digest policy_code "
        "policy_version state decided_at decisions",
    )
    subject = approval["subject_id"]
    expected_subject = [
        "v1",
        b["plan_id"],
        w["purpose"],
        w["target"]["operation"],
        w["plan_inputs"]["execution_plan_digest"],
    ]
    if (
        approval["request_id"] != b["approval_request_id"]
        or approval["subject_type"] != "rehearsal_issuer_plan.v1"
        or type(subject) is not str
        or subject.split("|") != expected_subject
        or approval["content_digest"] != b["plan_digest"]
        or approval["policy_code"] != w["approval_policy"]["code"]
        or type(approval["policy_version"]) is not int
        or approval["policy_version"] != w["approval_policy"]["version"]
        or approval["state"] != "approved"
        or doc["descriptor_digest"] != w["plan_inputs"]["descriptor_digest"]
    ):
        raise ProviderRefused()
    decided = _instant(approval["decided_at"])
    if decided > _instant(doc["observed_at"]):
        raise ProviderRefused()
    decisions = approval["decisions"]
    if type(decisions) is not list or not 0 < len(decisions) <= 64:
        raise ProviderRefused()
    ids, approved = set(), False
    for decision in decisions:
        d = _fields(decision, "id actor_id action decided_at")
        identity = _uuid(d["id"])
        _uuid(d["actor_id"])
        if identity in ids or d["action"] not in ("approve", "reject"):
            raise ProviderRefused()
        ids.add(identity)
        at = _instant(d["decided_at"])
        if at > _instant(doc["observed_at"]):
            raise ProviderRefused()
        approved |= d["action"] == "approve" and at <= decided
    images = doc["authorized_image_digests"]
    if not approved or type(images) is not list or not 0 < len(images) <= 64:
        raise ProviderRefused()
    image_terms = tuple(_digest(image) for image in images)
    g, c, t = w["github"], w["controller"], w["target"]
    operation = AdmittedOperation(
        g["repository_id"],
        g["run_id"],
        g["run_attempt"],
        w["window_id"],
        "issue",
        None,
        None,
        c["lease_id"],
        c["fingerprint"],
        t["ref"],
        b["plan_id"],
        b["plan_digest"],
        w["purpose"],
        t["operation"],
        w["plan_inputs"]["execution_plan_digest"],
        c["certificate_digest"],
        c["ca_fingerprint"],
    )
    expectation = AdmissionExpectation(
        operation,
        UUID(t["id"]),
        t["environment"],
        UUID(b["approval_request_id"]),
        approval["policy_code"],
        approval["policy_version"],
        case.frozen_window,
        window.digest,
        WindowFreshness(case.start, case.deadline),
    )
    result = ApprovalProjection(
        raw,
        decided,
        ApprovedWindowBinding(
            expectation, window, doc["descriptor_digest"], image_terms
        ),
    )
    case.require_open()
    return result


def decode_withdrawal(
    raw: bytes,
    case: RunnerProjectionCase,
    *,
    reference: str,
    approval: ApprovalProjection,
    authorization_ref: str,
) -> WithdrawalProjection:
    """Match owner event/relay to the actual B issued authorization reference."""
    if case.window.document["case_kind"] != "withdrawal_later_use":
        raise ProviderRefused()
    _text(reference, 200)
    _text(authorization_ref)
    doc = _document(
        raw,
        case,
        "Gate0CollectionWithdrawal.v1",
        "schema binding state withdrawal relay observed_at",
    )
    # Approval may be retained across withdrawal, but must be this exact case.
    original = decode_approval(approval.raw, case)
    if original != approval:
        raise ProviderRefused()
    state = doc["state"]
    if state == "pending_withdrawal":
        if doc["withdrawal"] is not None or doc["relay"] is not None:
            raise ProviderRefused()
        return WithdrawalProjection(raw, state, None)
    if state not in ("pending_relay", "applied"):
        raise ProviderRefused()
    w = _fields(
        doc["withdrawal"],
        "request_id withdrawal_id actor_id authority_ref "
        "approved_at effective_at external_ref",
    )
    event = _uuid(w["withdrawal_id"])
    _uuid(w["actor_id"])
    _text(w["authority_ref"])
    if (
        w["request_id"] != case.binding["approval_request_id"]
        or w["external_ref"] != reference
        or _instant(w["approved_at"]) != approval.approved_at
        or not approval.approved_at
        <= _instant(w["effective_at"])
        <= _instant(doc["observed_at"])
    ):
        raise ProviderRefused()
    if state == "pending_relay":
        if doc["relay"] is not None:
            raise ProviderRefused()
    else:
        relay = _fields(
            doc["relay"],
            "event_id payload_digest event_type request_id subject_type subject_id "
            "plan_id withdrawal_ref disposition authorizations_revoked",
        )
        a = _fields(
            strict_object(approval.raw, _MAXIMUM)["approval"],
            "request_id subject_type subject_id content_digest policy_code "
            "policy_version state decided_at decisions",
        )
        _digest(relay["payload_digest"])
        expected = dict(
            event_id=event,
            event_type="approval.withdrawn",
            request_id=w["request_id"],
            subject_type=a["subject_type"],
            subject_id=a["subject_id"],
            plan_id=case.binding["plan_id"],
            withdrawal_ref=event,
            disposition="applied",
            authorizations_revoked=[authorization_ref],
        )
        if any(relay[k] != v for k, v in expected.items()):
            raise ProviderRefused()
    case.require_open()
    return WithdrawalProjection(raw, state, event)


class RunnerProjectionClient:
    """Exactly one A/B campaign budget; failures consume slots, no retry loops.

    The root installer must authenticate origin/cases before construction.
    This object cannot manufacture that provenance, or authenticate a parsed DTO.
    """

    def __init__(
        self, origin: str, cases: tuple[RunnerProjectionCase, RunnerProjectionCase]
    ) -> None:
        parsed = urlsplit(origin)
        if (
            type(origin) is not str
            or parsed.scheme != "https"
            or not parsed.hostname
            or _HOST.fullmatch(parsed.hostname) is None
            or len(parsed.hostname) > 253
            or origin
            not in ("https://" + parsed.hostname, "https://" + parsed.hostname + ":443")
            or parsed.port not in (None, 443)
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or type(cases) is not tuple
            or len(cases) != 2
            or any(type(c) is not RunnerProjectionCase for c in cases)
            or tuple(c.window.document["case_kind"] for c in cases)
            != ("consume_replay", "withdrawal_later_use")
            or len({c.window.document["window_id"] for c in cases}) != 2
            or len({c.binding["plan_id"] for c in cases}) != 2
            or len({c.binding["approval_request_id"] for c in cases}) != 2
            or len({(c.wall_origin, c.monotonic_origin) for c in cases}) != 1
            or cases[0].window.document["controller"]["lease_id"]
            == cases[1].window.document["controller"]["lease_id"]
            or cases[0].window.document["controller"]["fingerprint"]
            == cases[1].window.document["controller"]["fingerprint"]
            or cases[0].window.document["controller"]["certificate_digest"]
            == cases[1].window.document["controller"]["certificate_digest"]
            or cases[0].window.document["github"] != cases[1].window.document["github"]
        ):
            raise ProviderRefused()
        self._host, self._cases = parsed.hostname, cases
        self._approvals: set[str] = set()
        self._withdrawals = 0

    def _read(
        self,
        case: RunnerProjectionCase,
        token: str,
        kind: str,
        reference: str | None = None,
    ) -> tuple[bytes, float]:
        if not any(case is c for c in self._cases):
            raise ProviderRefused()
        case.require_open()
        deadline = _jwt_deadline(token, case)
        if time.monotonic() >= deadline:
            raise ProviderRefused()
        raw = _request(
            self._host,
            _PREFIX + case.window.document["window_id"] + "/" + kind,
            token,
            reference,
            deadline,
        )
        case.require_open()
        if time.monotonic() >= deadline:
            raise ProviderRefused()
        return raw, deadline

    def approval(self, case: RunnerProjectionCase, token: str) -> ApprovalProjection:
        if not any(case is c for c in self._cases):
            raise ProviderRefused()
        window_id = case.window.document["window_id"]
        if window_id in self._approvals:
            raise ProviderRefused()
        self._approvals.add(window_id)
        try:
            raw, deadline = self._read(case, token, "approval")
            result = decode_approval(raw, case)
            if time.monotonic() >= deadline:
                raise ProviderRefused()
            return result
        except Exception:
            raise ProviderRefused() from None

    def withdrawal(
        self,
        token: str,
        *,
        reference: str,
        approval: ApprovalProjection,
        authorization_ref: str,
    ) -> WithdrawalProjection:
        try:
            _text(reference, 200)
            reference.encode("latin-1")
            if self._withdrawals >= 16:
                raise ProviderRefused()
            self._withdrawals += 1
            case = self._cases[1]
            raw, deadline = self._read(case, token, "withdrawal", reference)
            result = decode_withdrawal(
                raw,
                case,
                reference=reference,
                approval=approval,
                authorization_ref=authorization_ref,
            )
            if time.monotonic() >= deadline:
                raise ProviderRefused()
            return result
        except Exception:
            raise ProviderRefused() from None
