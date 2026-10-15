"""Fixed GitHub JWT verification over the adopted frozen Control window.

IDP3 uses public Control views and the existing exact Approvals hold. NS3 has
only an independently delivered approved-at-start snapshot. Actual installation
bindings remain UNCONFIGURED; constructors never create approval authority.
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, cast
from uuid import UUID

from vendor_cp.deployment.gate0_composition import (
    AdmissionExpectation,
    RequestAuthenticationFreshness,
    WindowFreshness,
    authorization_binding,
)
from vendor_cp.deployment.gate0_github_jwt import (
    _FIXED_CLAIMS,
    GITHUB_ISSUER,
    VerifiedClaims,
    verify_github_claims,
)
from vendor_cp.deployment.gate0_role_custody import (
    BoundedJSONTransport,
    ProviderRefused,
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
        if self._transport is None:
            raise ProviderRefused()
        claims = verify_github_claims(
            token, transport=self._transport, deadline=self._deadline
        )
        self._open()
        return claims

    def _authentication_freshness(
        self,
        claims: VerifiedClaims,
        window_end: datetime,
        original_deadline: float,
    ) -> RequestAuthenticationFreshness:
        effective_end = min(window_end.timestamp(), claims["exp"])
        freshness = RequestAuthenticationFreshness(
            self._origin,
            min(
                self._deadline,
                original_deadline,
                self._origin + effective_end - self._started_at.timestamp(),
            ),
            datetime.fromtimestamp(effective_end, UTC),
        )
        self._open()
        freshness.require_open()
        return freshness

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
            authentication = self._authentication_freshness(
                claims,
                window.approved_until,
                self._window_deadlines[(phase, str(plan_id))],
            )
            result = replace(
                window.expectation, authentication_freshness=authentication
            )
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
        if asdict(window.expectation) != asdict(
            replace(expected, authentication_freshness=None)
        ):
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
            ):
                raise ProviderRefused()
            self._open()
            if datetime.now(UTC) >= datetime.fromisoformat(
                document["expires_at"].replace("Z", "+00:00")
            ):
                raise ProviderRefused()
            original_freshness = (
                denial.freshness
                if denial is not None
                else (None if expected is None else expected.window_freshness)
            )
            if original_freshness is None:
                raise ProviderRefused()
            authentication = self._authentication_freshness(
                claims,
                datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00")),
                original_freshness.deadline,
            )
            if denial is not None:
                denial.freshness.require_open()
            else:
                if expected is None or expected.window_freshness is None:
                    raise ProviderRefused()
                expected.window_freshness.require_open()
                result = replace(expected, authentication_freshness=authentication)
        except Exception:
            failed = True
        if failed:
            self._transport = None
            raise ProviderRefused()
        if denial is not None:
            self._transport = None
            authentication.require_open()
            raise AuthenticatedApprovalWithdrawal(
                denial, authentication_freshness=authentication
            )
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
            ):
                raise ProviderRefused()
            self._window(
                "issue", plan_id
            )  # Original absolute and monotonic snapshot deadline.
            if expected.window_freshness is None:
                raise ProviderRefused()
            expected.window_freshness.require_open()
            authentication = self._authentication_freshness(
                claims,
                self._windows[0].approved_until,
                expected.window_freshness.deadline,
            )
            result = replace(expected, authentication_freshness=authentication)
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
