"""Finite installed A9 collection; successful collection never grants readiness."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

from dotmac_deployment_control import RehearsalIssuerAuthorizationSignerIdentity

from vendor_cp.deployment.gate0_collection import FixedEvidenceCollector
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_observation import encode
from vendor_cp.deployment.gate0_role_custody import (
    ProviderRefused,
    PublicIssuerVerifier,
)
from vendor_cp.deployment.gate0_runner_collector_handoff import OwnedCollectorHandoff
from vendor_cp.deployment.gate0_runner_installation import (
    InstalledRunnerCase,
    InstalledRunnerCollection,
)
from vendor_cp.deployment.gate0_runner_projection import (
    RunnerProjectionCase,
    RunnerProjectionClient,
)
from vendor_cp.deployment.gate0_runner_ssh import (
    OwnedAttesterSession,
    OwnedIssuerSession,
    close_owned_sessions,
)
from vendor_cp.deployment.gate0_runner_tokens import InstalledJobTokens
from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier

# Existing token and projection request owners each cap a request at5 seconds.
_FINAL_RESERVE_SECONDS = 15
_POLL_REQUEST_SECONDS = 2 * 5
_LATEST_POLL_START_MARGIN = _FINAL_RESERVE_SECONDS + _POLL_REQUEST_SECONDS


def _wait_original(case: RunnerProjectionCase) -> None:
    """Wait on both original clocks, never reanchor a later case."""
    not_before = datetime.fromisoformat(
        case.window.document["not_before"].replace("Z", "+00:00")
    )
    expiry = datetime.fromisoformat(
        case.window.document["expires_at"].replace("Z", "+00:00")
    )
    while True:
        elapsed, wall = time.monotonic(), datetime.now(UTC)
        if elapsed >= case.deadline or wall >= expiry:
            raise ProviderRefused()
        remaining = max(case.start - elapsed, (not_before - wall).total_seconds())
        if remaining <= 0:
            case.require_open()
            return
        time.sleep(min(0.25, remaining, case.deadline - elapsed))


def _wait_pending_withdrawal(case: RunnerProjectionCase, reads: int) -> None:
    """Pace fixed polls while reserving both requests and15 completion seconds."""
    case.require_open()
    if type(reads) is not int or not 1 <= reads < 16:
        raise ProviderRefused()
    remaining = case.deadline - _LATEST_POLL_START_MARGIN - time.monotonic()
    if remaining <= 0:
        raise ProviderRefused()
    time.sleep(min(5.0, remaining / (16 - reads)))
    case.require_open()


def _private_parent(path: str, uid: int) -> int:
    """No-follow ancestry and a collector-owned, exclusively private last directory."""
    selected = Path(path)
    if not selected.is_absolute() or any(p in (".", "..") for p in selected.parts):
        raise ProviderRefused()
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(selected.parts[1:]):
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            last = index == len(selected.parts) - 2
            if (
                info.st_uid != (uid if last else 0)
                or stat.S_IMODE(info.st_mode) != 0o700
                and last
                or not last
                and info.st_mode & 0o022
            ):
                raise ProviderRefused()
        return directory
    except BaseException:
        os.close(directory)
        raise


def _exclusive(directory: int, name: str, raw: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        os.fchmod(fd, 0o600)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                raise ProviderRefused()
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


class InstalledCollectionController:
    """No caller tokens, callbacks, channels, ACKs or fabricated completed joins."""

    def __init__(self, installation: InstalledRunnerCollection) -> None:
        if type(installation) is not InstalledRunnerCollection:
            raise ProviderRefused()
        self.installation = installation
        self._used = False
        self._sessions: list[OwnedIssuerSession | OwnedAttesterSession] = []

    def _verifiers(
        self, case: InstalledRunnerCase
    ) -> tuple[
        BoundedHarnessVerifier,
        RehearsalIssuerAuthorizationSignerIdentity,
        PublicIssuerVerifier,
    ]:
        case.projection.require_open()
        expiry = datetime.fromisoformat(
            case.projection.window.document["expires_at"].replace("Z", "+00:00")
        )
        attester, issuer = case.attester_trust, case.issuer_trust
        proof = BoundedHarnessVerifier(
            key_id=attester.key_id,
            public_key=attester.public_key,
            trust_state=attester.start(),
            expires_at=expiry,
            deadline=case.projection.deadline,
        )
        identity = RehearsalIssuerAuthorizationSignerIdentity(
            issuer.key_id,
            "ed25519",
            "sha256:" + hashlib.sha256(issuer.public_key).hexdigest(),
        )
        authorization = PublicIssuerVerifier(
            issuer.key_id,
            issuer.public_key,
            issuer.start(),
            case.projection.deadline,
            expiry,
            case.projection.wall_origin,
            case.projection.monotonic_origin,
        )
        return proof, identity, authorization

    def run(self) -> None:
        if self._used:
            raise ProviderRefused()
        self._used = True
        installed = self.installation
        installed.require_actual_job()
        parent = _private_parent(
            str(Path(installed.marker).parent), installed.collector_uid
        )
        root = None
        tokens = None
        try:
            if Path(installed.output_directory).parent != Path(installed.marker).parent:
                raise ProviderRefused()
            _exclusive(parent, Path(installed.marker).name, b"claimed\n")
            os.fsync(parent)
            a, b = installed.cases
            cases = (a.projection, b.projection)
            core = FixedEvidenceCollector.for_installed(
                cases=cases,
                command_a=a.command_id,
                command_b=b.command_id,
                withdrawal_ref=installed.withdrawal_reference,
            )
            client = RunnerProjectionClient(installed.origin, cases)
            root = OwnedCollectorHandoff(installed)
            _wait_original(a.projection)
            tokens = InstalledJobTokens.from_installed(installed)
            approval_a = client.approval(a.projection, tokens.next(a.projection))
            verifier_a, identity_a, authorization_a = self._verifiers(a)
            root.await_issuer_start(a)
            issuer_a = OwnedIssuerSession(a.ssh)
            self._sessions.append(issuer_a)
            core.bind_case_a(
                approval_a, issuer_a, verifier_a, identity_a, authorization_a
            )
            root.await_attester_start(a)
            issue_a = OwnedAttesterSession(a.ssh)
            self._sessions.append(issue_a)
            issue_bundle_a = issue_a.collect(
                approval_a.binding.expectation.operation,
                workload_token=tokens.next(a.projection),
            )
            signed_a, consume_expected_a = core.issue_a(
                issue_bundle=issue_bundle_a,
                tokens=(tokens.next(a.projection), tokens.next(a.projection)),
            )
            consume_a = OwnedAttesterSession(a.ssh)
            self._sessions.append(consume_a)
            consume_bundle_a = consume_a.collect(
                consume_expected_a.operation,
                workload_token=tokens.next(a.projection),
                authorization=signed_a,
            )
            core.collect_a(
                consume_bundle=consume_bundle_a,
                tokens=(
                    tokens.next(a.projection),
                    tokens.next(a.projection),
                    tokens.next(a.projection),
                ),
            )
            issuer_a.finish()
            core.complete_case_a(root, issue_a, consume_a)
            # Only the concrete join and successful ACK unlock every B action.
            if not root.case_a_complete:
                raise ProviderRefused()
            _wait_original(b.projection)
            approval_b = client.approval(b.projection, tokens.next(b.projection))
            verifier_b, identity_b, authorization_b = self._verifiers(b)
            root.await_issuer_start(b)
            issuer_b = OwnedIssuerSession(b.ssh)
            self._sessions.append(issuer_b)
            core.bind_case_b(
                approval_b, issuer_b, verifier_b, identity_b, authorization_b
            )
            root.await_attester_start(b)
            issue_b = OwnedAttesterSession(b.ssh)
            self._sessions.append(issue_b)
            issue_bundle_b = issue_b.collect(
                approval_b.binding.expectation.operation,
                workload_token=tokens.next(b.projection),
            )
            signed_b, consume_expected_b = core.issue_b(
                issue_bundle=issue_bundle_b,
                tokens=(tokens.next(b.projection), tokens.next(b.projection)),
            )
            consume_b = OwnedAttesterSession(b.ssh)
            self._sessions.append(consume_b)
            consume_bundle_b = consume_b.collect(
                consume_expected_b.operation,
                workload_token=tokens.next(b.projection),
                authorization=signed_b,
            )
            core.prepare_b(
                consume_bundle=consume_bundle_b, token=tokens.next(b.projection)
            )
            authorization_id = strict_object(
                issuer_b.collector.outcomes[0].result_bytes
            )["authorization_id"]
            withdrawal_raw = []
            for read_index in range(16):
                b.projection.require_open()
                if (
                    time.monotonic()
                    >= b.projection.deadline - _LATEST_POLL_START_MARGIN
                ):
                    raise ProviderRefused()
                projection = client.withdrawal(
                    tokens.next(b.projection),
                    reference=installed.withdrawal_reference,
                    approval=approval_b,
                    authorization_ref=authorization_id,
                )
                withdrawal_raw.append(projection.raw)
                if core.observe_b_projection(projection):
                    b.projection.require_open()
                    if (
                        b.projection.deadline - time.monotonic()
                        <= _FINAL_RESERVE_SECONDS
                    ):
                        raise ProviderRefused()
                    break
                _wait_pending_withdrawal(b.projection, read_index + 1)
            else:
                raise ProviderRefused()
            evidence = core.collect_b_later_use(token=tokens.next(b.projection))
            issuer_b.finish()
            root.complete_case_b(
                issuer_b,
                issue_b,
                consume_b,
                issue_expected=approval_b.binding.expectation,
                consume_expected=consume_expected_b,
            )
            root.close()
            raw = canonical(
                {
                    "collection_complete": True,
                    "readiness_accepted": False,
                    "evidence": evidence.document(),
                    "root_records": [encode(value) for value in root.records],
                    "joins": [encode(value) for value in root.joins],
                    "approval_projection_raw": [
                        encode(approval_a.raw),
                        encode(approval_b.raw),
                    ],
                    "withdrawal_projection_raw": [
                        encode(value) for value in withdrawal_raw
                    ],
                    "original_selections": [
                        {
                            "shared_packet": encode(case.projection.shared_packet),
                            "frozen_window": encode(case.projection.frozen_window),
                        }
                        for case in installed.cases
                    ],
                    "public_trust": [
                        {
                            "key_id": trust.key_id,
                            "public_key": encode(trust.public_key),
                            "record": encode(trust.record),
                            "minimum_version": trust.minimum_version,
                            "source_ref": trust.source_ref,
                            "qualification_digest": trust.qualification_digest,
                        }
                        for case in installed.cases
                        for trust in (case.issuer_trust, case.attester_trust)
                    ],
                }
            )
            if len(raw) > 8 * 1024 * 1024 or len(root.joins) != 2:
                raise ProviderRefused()
            name = Path(installed.output_directory).name
            os.mkdir(name, 0o700, dir_fd=parent)
            output = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            try:
                os.fchmod(output, 0o700)
                _exclusive(output, "collection.json", raw)
                os.fsync(output)
            finally:
                os.close(output)
            os.fsync(parent)
        finally:
            # All actual SSH/signing children share one bounded teardown owner.
            try:
                close_owned_sessions(*self._sessions)
            finally:
                try:
                    if root is not None:
                        root.close()
                finally:
                    if tokens is not None:
                        tokens._credential = ""
                        tokens._failed = True
                    os.close(parent)
