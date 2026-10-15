"""Fixed GitHub JWT verification over the adopted frozen Control window.

IDP3 uses public Control views and the existing exact Approvals hold. NS3 has
only an independently delivered approved-at-start snapshot. Actual installation
bindings remain UNCONFIGURED; constructors never create approval authority.
"""

from __future__ import annotations

import base64
import re
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, TypedDict, cast
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    WindowFreshness,
    authorization_binding,
)
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
    json_record,
    json_string,
    strict_json,
)

if TYPE_CHECKING:
    from dotmac_deployment_control import (
        RehearsalIssuerAuthorizationSignerIdentity,
        RehearsalIssuerAuthorizationVerifier,
    )

    from vendor_cp.deployment.gate0_window import (
        ApprovedWindowBinding,
        OwnerWindowReader,
        WindowClockOrigin,
    )


class VerifiedClaims(TypedDict):
    iat: int
    nbf: int
    exp: int
    jti: str
    run_id: str
    run_attempt: str


GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_JWKS_PATH = "/.well-known/jwks"
_FIXED_CLAIMS = {
    "iss": GITHUB_ISSUER,
    "aud": "urn:dotmac:gate0:rehearsal-issuer",
    "repository": "dotmac-tech/gate0-issuer-execution",
    "repository_id": "1397614140",
    "repository_owner_id": "335992433",
    "environment": "rehearsal-issuer-protected",
    "ref": "refs/heads/main",
    "workflow_ref": (
        "dotmac-tech/gate0-issuer-execution/"
        ".github/workflows/gate0-issuer.yml@refs/heads/main"
    ),
    "event_name": "workflow_dispatch",
}


def _decode(value: str, maximum: int) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise ProviderRefused()
    raw = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ProviderRefused()
    return raw


@dataclass(frozen=True, slots=True)
class ProposedApprovedWindow:
    """Legacy preauthenticated snapshot for explicitly synthetic mechanism tests.

    Source MUST independently authenticate these bytes before construction.
    Neither GitHub approval nor any Lane-3 broker grant is this authority.
    All operation, approval policy, target, certificate, lease and phase facts
    come from this snapshot; tokens/requests cannot provide replacements.
    """

    expectation: AdmissionExpectation
    subject: str
    workflow_sha: str
    approved_from: datetime
    approved_until: datetime
    authority_record_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.expectation) is not AdmissionExpectation
            or not isinstance(self.subject, str)
            or not 0 < len(self.subject) <= 1024
            or re.fullmatch(r"[0-9a-f]{40}", self.workflow_sha) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.authority_record_digest)
            is None
            or self.approved_from.tzinfo is None
            or self.approved_until.tzinfo is None
            or not 0 < (self.approved_until - self.approved_from).total_seconds() <= 300
        ):
            raise ProviderRefused()
        if self.expectation.operation.repository_id != _FIXED_CLAIMS["repository_id"]:
            raise ProviderRefused()


class WorkloadAdmission:
    """Finite one-start window set. No JWT/JWKS/admission success cache.

    Every admit retrieves fixed-origin JWKS through bounded TLS transport and
    repeats signature, exact claims, original wall/monotonic expiry and window
    checks. Unknown keys refuse; no refresh loop, token-controlled URL or retry.
    The immutable local snapshot performs no external I/O and runs no callback.
    """

    def __init__(
        self,
        *,
        windows: tuple[ProposedApprovedWindow, ...] | None = None,
        transport: BoundedJSONTransport | None = None,
        expires_at: datetime | None = None,
        clock_origin: WindowClockOrigin | None = None,
    ) -> None:
        from vendor_cp.deployment.gate0_window import WindowClockOrigin

        if clock_origin is not None:
            if type(clock_origin) is not WindowClockOrigin:
                raise ProviderRefused()
            clock_origin.__post_init__()
        self._attempts = 0
        self._windows: tuple[ProposedApprovedWindow, ...] = ()
        self._transport: BoundedJSONTransport | None = None
        self._deadline = 0.0
        self._expires = expires_at
        self._started_at = datetime.now(UTC)
        self._origin = time.monotonic()
        if clock_origin is not None:
            self._started_at = clock_origin.started_at
            self._origin = clock_origin.monotonic_origin
        self._window_deadlines: dict[tuple[str, str], float] = {}
        if (
            windows is None
            and transport is None
            and expires_at is None
            and clock_origin is None
        ):
            return
        if (
            type(windows) is not tuple
            or not 0 < len(windows) <= 4
            or any(type(window) is not ProposedApprovedWindow for window in windows)
            or type(transport) is not BoundedJSONTransport
            or transport.origin.rstrip("/") != GITHUB_ISSUER
            or expires_at is None
            or expires_at.tzinfo is None
            or not 0 < (expires_at - datetime.now(UTC)).total_seconds() <= 300
        ):
            raise ProviderRefused()
        coordinates = [
            (w.expectation.operation.phase, w.expectation.operation.plan_id)
            for w in windows
        ]
        if len(set(coordinates)) != len(coordinates):
            raise ProviderRefused()
        self._windows, self._transport = windows, transport
        self._deadline = self._origin + (expires_at - self._started_at).total_seconds()
        if clock_origin is not None:
            if not 0 < (expires_at - self._started_at).total_seconds() <= 300:
                raise ProviderRefused()
            self._deadline = min(self._deadline, clock_origin.deadline)
        self._window_deadlines = {
            (
                w.expectation.operation.phase,
                w.expectation.operation.plan_id,
            ): self._origin + (w.approved_until - self._started_at).total_seconds()
            for w in windows
        }

    def _open(self) -> None:
        if (
            self._transport is None
            or self._expires is None
            or not self._origin <= time.monotonic() < self._deadline
            or not self._started_at <= datetime.now(UTC) < self._expires
        ):
            raise ProviderRefused()

    def _window(
        self, phase: Literal["issue", "consume"], plan_id: UUID
    ) -> ProposedApprovedWindow:
        self._open()
        if phase not in ("issue", "consume") or type(plan_id) is not UUID:
            raise ProviderRefused()
        found = [
            window
            for window in self._windows
            if window.expectation.operation.phase == phase
            and window.expectation.operation.plan_id == str(plan_id)
        ]
        if (
            len(found) != 1
            or not found[0].approved_from <= datetime.now(UTC) < found[0].approved_until
        ):
            raise ProviderRefused()
        if time.monotonic() >= self._window_deadlines[(phase, str(plan_id))]:
            raise ProviderRefused()
        return found[0]

    def _claims(self, token: str) -> VerifiedClaims:
        self._open()
        if type(token) is not str or not 0 < len(token) <= 32768:
            raise ProviderRefused()
        parts = token.split(".")
        if len(parts) != 3:
            raise ProviderRefused()
        header = strict_json(_decode(parts[0], 4096), 4096)
        if (
            not {"alg", "kid", "typ"} <= set(header)
            or set(header) - {"alg", "kid", "typ", "x5t"}
            or header["alg"] != "RS256"
            or header["typ"] != "JWT"
            or not 0 < len(json_string(header["kid"])) <= 512
        ):
            raise ProviderRefused()
        claims = cast(VerifiedClaims, strict_json(_decode(parts[1], 24576), 24576))
        if any(claims.get(key) != value for key, value in _FIXED_CLAIMS.items()):
            raise ProviderRefused()
        if "job_workflow_ref" in claims or "job_workflow_sha" in claims:
            raise ProviderRefused()
        now = datetime.now(UTC).timestamp()
        if (
            any(type(claims.get(key)) is not int for key in ("iat", "nbf", "exp"))
            or not claims["iat"] <= now < claims["exp"]
            or not claims["nbf"] <= now
            or not claims["iat"] <= claims["nbf"] < claims["exp"]
            or not 0 < claims["exp"] - claims["iat"] <= 300
            or type(claims.get("jti")) is not str
            or not 0 < len(claims["jti"]) <= 512
            or any(
                type(claims.get(key)) is not str
                or re.fullmatch(r"[1-9][0-9]{0,19}", json_string(claims.get(key)))
                is None
                for key in ("run_id", "run_attempt")
            )
        ):
            raise ProviderRefused()
        jwt_deadline = min(self._deadline, time.monotonic() + claims["exp"] - now)
        transport = self._transport
        if transport is None:
            raise ProviderRefused()
        jwks = transport.request(
            GITHUB_JWKS_PATH,
            method="GET",
            token=None,
            document=None,
            deadline=jwt_deadline,
        )
        raw_keys = jwks.get("keys")
        if (
            type(raw_keys) is not list
            or not 0 < len(raw_keys) <= 16
            or any(type(k) is not dict for k in raw_keys)
        ):
            raise ProviderRefused()
        keys = [json_record(k) for k in cast(list[object], raw_keys)]
        ids = [json_string(k.get("kid")) for k in keys]
        if any(type(kid) is not str for kid in ids) or len(ids) != len(set(ids)):
            raise ProviderRefused()
        selected = [k for k in keys if k["kid"] == header["kid"]]
        if len(selected) != 1:
            raise ProviderRefused()
        key = selected[0]
        if (
            key.get("kty") != "RSA"
            or key.get("alg") != "RS256"
            or key.get("use") != "sig"
            or any(name in key for name in ("d", "p", "q", "dp", "dq", "qi", "oth"))
            or ("key_ops" in key and key["key_ops"] != ["verify"])
        ):
            raise ProviderRefused()
        n = int.from_bytes(_decode(json_string(key["n"]), 1400), "big")
        e = int.from_bytes(_decode(json_string(key["e"]), 16), "big")
        if not 2048 <= n.bit_length() <= 8192 or e != 65537:
            raise ProviderRefused()
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            _decode(parts[2], 1400),
            (parts[0] + "." + parts[1]).encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        self._open()
        if (
            datetime.now(UTC).timestamp() >= claims["exp"]
            or time.monotonic() >= jwt_deadline
        ):
            raise ProviderRefused()
        return claims

    def admit(
        self,
        token: str,
        phase: Literal["issue", "consume"],
        plan_id: UUID,
        authorization_document: bytes | None = None,
    ) -> AdmissionExpectation:
        failed = False
        result: AdmissionExpectation | None = None
        try:
            self._attempts += 1
            if self._attempts > 16:
                raise ProviderRefused()
            window = self._window(phase, plan_id)
            claims = self._claims(token)
            operation = window.expectation.operation
            if (
                claims["run_id"] != operation.run_id
                or claims["run_attempt"] != operation.run_attempt
                or claims.get("sub") != window.subject
                or claims.get("workflow_sha") != window.workflow_sha
                or claims["iat"] < window.approved_from.timestamp()
                or claims["exp"] > window.approved_until.timestamp()
            ):
                raise ProviderRefused()
            if phase == "issue":
                if authorization_document is not None:
                    raise ProviderRefused()
            else:
                if authorization_document is None:
                    raise ProviderRefused()
                binding = authorization_binding(authorization_document)
                if (
                    binding.digest != operation.authorization_digest
                    or binding.issued_at != operation.authorization_issued_at
                ):
                    raise ProviderRefused()
            self._window(phase, plan_id)
            result = window.expectation
        except Exception:
            failed = True
        if failed or result is None:
            self._transport = None
            raise ProviderRefused()
        return result

    def window_record_digest(self, expected: AdmissionExpectation) -> str:
        if type(expected) is not AdmissionExpectation:
            raise ProviderRefused()
        window = self._window(
            cast(Literal["issue", "consume"], expected.operation.phase),
            UUID(expected.operation.plan_id),
        )
        if asdict(window.expectation) != asdict(expected):
            raise ProviderRefused()
        return window.authority_record_digest


class OwnerWorkloadAdmission(WorkloadAdmission):
    """IDP3 only: fresh frozen Control records and real Approvals hold per call.

    NS3's approved-at-start snapshot can never be substituted for this provider.
    The returned snapshot is checked again in the mutation session; the existing
    CP wrappers reacquire the actual approval hold before owner writes.
    """

    def __init__(
        self,
        *,
        reader: OwnerWindowReader,
        transport: BoundedJSONTransport | None = None,
    ) -> None:
        from vendor_cp.deployment.gate0_window import OwnerWindowReader

        if (
            type(reader) is not OwnerWindowReader
            or type(transport) is not BoundedJSONTransport
            or transport.origin.rstrip("/") != GITHUB_ISSUER
        ):
            raise ProviderRefused()
        super().__init__()
        reader._open()
        self._reader, self._transport = reader, transport
        self._expires, self._deadline = reader._expires, reader._deadline
        self._started_at, self._origin = reader._started, reader._origin

    def admit(
        self,
        token: str,
        phase: Literal["issue", "consume"],
        plan_id: UUID,
        authorization_document: bytes | None = None,
    ) -> AdmissionExpectation:
        from vendor_cp.deployment.gate0_window import (
            AuthenticatedApprovalWithdrawal,
            OwnerWindowWithdrawal,
        )

        failed = False
        denial: OwnerWindowWithdrawal | None = None
        result: AdmissionExpectation | None = None
        try:
            self._open()
            self._attempts += 1
            if self._attempts > 16:
                raise ProviderRefused()
            # Verify signature and fixed claims before interpreting owner denial.
            claims = self._claims(token)
            try:
                captured = self._reader.read(phase, plan_id, authorization_document)
            except OwnerWindowWithdrawal as caught:
                if caught.plan_id != plan_id or caught.phase != phase:
                    raise ProviderRefused() from None
                denial = caught
                expected = None
                window = caught.window
            else:
                expected, window = captured.expectation, captured.window
            document = window.document
            if (
                any(
                    claims.get(key) != value
                    for key, value in document["github"].items()
                )
                or claims["iat"]
                < datetime.fromisoformat(
                    document["not_before"].replace("Z", "+00:00")
                ).timestamp()
                or claims["exp"]
                > datetime.fromisoformat(
                    document["expires_at"].replace("Z", "+00:00")
                ).timestamp()
            ):
                raise ProviderRefused()
            self._open()
            if datetime.now(UTC) >= datetime.fromisoformat(
                document["expires_at"].replace("Z", "+00:00")
            ):
                raise ProviderRefused()
            if denial is not None:
                denial.freshness.require_open()
            else:
                if expected is None or expected.window_freshness is None:
                    raise ProviderRefused()
                expected.window_freshness.require_open()
                result = expected
        except Exception:
            failed = True
        if failed:
            self._transport = None
            raise ProviderRefused()
        if denial is not None:
            self._transport = None
            raise AuthenticatedApprovalWithdrawal(denial)
        if result is None:
            self._transport = None
            raise ProviderRefused()
        return result

    def window_record_digest(self, expected: AdmissionExpectation) -> str:
        from vendor_cp.deployment.gate0_window import FrozenIssuerWindow

        self._open()
        if (
            type(expected) is not AdmissionExpectation
            or expected.frozen_window_bytes is None
        ):
            raise ProviderRefused()
        if expected.window_freshness is None:
            raise ProviderRefused()
        expected.window_freshness.require_open()
        window = FrozenIssuerWindow.parse(expected.frozen_window_bytes)
        if window.digest != expected.window_digest:
            raise ProviderRefused()
        document = window.document
        if (
            not datetime.fromisoformat(document["not_before"].replace("Z", "+00:00"))
            <= datetime.now(UTC)
            < datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        ):
            raise ProviderRefused()
        retained = self._reader._freshness.get(
            (UUID(expected.operation.plan_id), window.digest)
        )
        if expected.window_freshness is not retained:
            raise ProviderRefused()
        # A content binding for the proof, never an assertion of current approval.
        return window.digest


class ApprovedAtStartAdmission(WorkloadAdmission):
    """NS3 only: a trusted CP-delivered approval snapshot, no current-standing claim."""

    def __init__(
        self,
        *,
        binding: ApprovedWindowBinding,
        issuer_identity: RehearsalIssuerAuthorizationSignerIdentity,
        authorization_verifier: RehearsalIssuerAuthorizationVerifier,
        transport: BoundedJSONTransport | None = None,
        expires_at: datetime | None = None,
        clock_origin: WindowClockOrigin | None = None,
    ) -> None:
        from vendor_cp.deployment.gate0_window import (
            ApprovedWindowBinding,
            FrozenIssuerWindow,
        )

        if (
            type(binding) is not ApprovedWindowBinding
            or binding.expectation.operation.phase != "issue"
            or issuer_identity is None
            or authorization_verifier is None
            or type(transport) is not BoundedJSONTransport
            or expires_at is None
        ):
            raise ProviderRefused()
        if binding.expectation.frozen_window_bytes is None:
            raise ProviderRefused()
        window = FrozenIssuerWindow.parse(binding.expectation.frozen_window_bytes)
        document = window.document
        until = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        if (
            window != binding.window
            or window.digest != binding.expectation.window_digest
            or expires_at > until
        ):
            raise ProviderRefused()
        snapshot = ProposedApprovedWindow(
            binding.expectation,
            document["github"]["sub"],
            document["github"]["workflow_sha"],
            datetime.fromisoformat(document["not_before"].replace("Z", "+00:00")),
            until,
            window.digest,
        )
        super().__init__(
            windows=(snapshot,),
            transport=transport,
            expires_at=expires_at,
            clock_origin=clock_origin,
        )
        # The sender's monotonic coordinates are never portable. Map the
        # authenticated absolute end once at this process's own startup.
        freshness = WindowFreshness(
            self._origin,
            min(
                self._deadline,
                self._window_deadlines[
                    ("issue", binding.expectation.operation.plan_id)
                ],
            ),
        )
        local_expected = replace(binding.expectation, window_freshness=freshness)
        self._windows = (replace(snapshot, expectation=local_expected),)
        self._binding, self._identity, self._verifier = (
            replace(binding, expectation=local_expected),
            issuer_identity,
            authorization_verifier,
        )

    def admit(
        self,
        token: str,
        phase: Literal["issue", "consume"],
        plan_id: UUID,
        authorization_document: bytes | None = None,
    ) -> AdmissionExpectation:
        from vendor_cp.deployment.gate0_window import derive_consume_expectation

        failed = False
        result: AdmissionExpectation | None = None
        try:
            self._open()
            self._attempts += 1
            if (
                self._attempts > 16
                or type(plan_id) is not UUID
                or str(plan_id) != self._binding.expectation.operation.plan_id
            ):
                raise ProviderRefused()
            if phase == "issue" and authorization_document is None:
                expected = self._binding.expectation
            elif phase == "consume" and authorization_document is not None:
                expected = derive_consume_expectation(
                    self._binding,
                    authorization_document,
                    self._identity,
                    self._verifier,
                )
            else:
                raise ProviderRefused()
            document = self._binding.window.document
            claims = self._claims(token)
            if (
                any(
                    claims.get(key) != value
                    for key, value in document["github"].items()
                )
                or claims["iat"] < self._windows[0].approved_from.timestamp()
                or claims["exp"] > self._windows[0].approved_until.timestamp()
            ):
                raise ProviderRefused()
            self._window(
                "issue", plan_id
            )  # Original absolute and monotonic snapshot deadline.
            if expected.window_freshness is None:
                raise ProviderRefused()
            expected.window_freshness.require_open()
            result = expected
        except Exception:
            failed = True
        if failed or result is None:
            self._transport = None
            raise ProviderRefused()
        return result

    def window_record_digest(self, expected: AdmissionExpectation) -> str:
        self._window("issue", UUID(self._binding.expectation.operation.plan_id))
        if (
            type(expected) is not AdmissionExpectation
            or expected.frozen_window_bytes != self._binding.window.canonical_bytes
            or expected.window_digest != self._binding.window.digest
            or expected.window_freshness != self._binding.expectation.window_freshness
        ):
            raise ProviderRefused()
        return self._binding.window.digest
