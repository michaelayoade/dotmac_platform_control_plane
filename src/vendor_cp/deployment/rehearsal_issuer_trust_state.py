"""Public trust standing for a future rehearsal-issuer verifier composition.

The caller supplies a public-data reader and a durable minimum version. This
module does not choose a source, load a signing key, verify a signature, or
decide whether Control permits an authorization to be consumed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock, RLock
from types import MappingProxyType


class TrustStateInstallError(ValueError):
    """The public trust record could not be installed; details are withheld."""


class TrustEligibility(StrEnum):
    ELIGIBLE = "eligible"
    UNAVAILABLE = "unavailable"
    REVOKED = "revoked"
    UNKNOWN_KEY = "unknown_key"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"


@dataclass(frozen=True, slots=True)
class TrustStateSnapshot:
    """A detached, immutable copy of one validated public trust record."""

    version: int
    trusted_key_ids: Mapping[str, str]
    revoked_key_ids: frozenset[str]


def _nonblank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _parse_record(record: object) -> TrustStateSnapshot:
    if not isinstance(record, Mapping) or set(record) != {
        "version",
        "trusted_key_ids",
        "revoked_key_ids",
    }:
        raise TrustStateInstallError("invalid public trust-state record")
    version = record["version"]
    trusted = record["trusted_key_ids"]
    revoked = record["revoked_key_ids"]
    if type(version) is not int or version < 1:
        raise TrustStateInstallError("invalid public trust-state record")
    if not isinstance(trusted, Mapping) or any(
        not _nonblank(key) or not _nonblank(fingerprint)
        for key, fingerprint in trusted.items()
    ):
        raise TrustStateInstallError("invalid public trust-state record")
    if not isinstance(revoked, list | tuple | set | frozenset) or any(
        not _nonblank(key) for key in revoked
    ):
        raise TrustStateInstallError("invalid public trust-state record")
    if len(revoked) != len(set(revoked)):
        raise TrustStateInstallError("invalid public trust-state record")
    return TrustStateSnapshot(
        version=version,
        trusted_key_ids=MappingProxyType(dict(trusted)),
        revoked_key_ids=frozenset(revoked),
    )


class RehearsalIssuerTrustState:
    """Explicit, serialized installs and atomic eligibility snapshots.

    ``read_record`` is invoked exactly once by ``start`` or ``refresh``. It
    must return only the three public fields; source access belongs to the
    caller. No timer, background thread, or network access is created here.
    Refresh attempts serialize separately from the short state lock. The
    gate closes before a reader is called, so eligibility and snapshot reads
    remain prompt even if that reader stalls. A failed refresh keeps the prior
    version for diagnosis, but eligibility stays unavailable until success.
    """

    def __init__(self, *, minimum_version: int) -> None:
        if type(minimum_version) is not int or minimum_version < 1:
            raise ValueError("minimum trust-state version must be a positive integer")
        self._minimum_version = minimum_version
        self._snapshot: TrustStateSnapshot | None = None
        self._available = False
        self._state_lock = RLock()
        self._refresh_lock = Lock()

    @classmethod
    def start(
        cls, *, minimum_version: int, read_record: Callable[[], object]
    ) -> RehearsalIssuerTrustState:
        """Fail startup unless a valid record meets the injected durable floor."""
        state = cls(minimum_version=minimum_version)
        state.refresh(read_record=read_record)
        return state

    @property
    def snapshot(self) -> TrustStateSnapshot | None:
        with self._state_lock:
            return self._snapshot

    @property
    def available(self) -> bool:
        with self._state_lock:
            return self._available

    def refresh(self, *, read_record: Callable[[], object]) -> None:
        """Install one explicit read; every unsuccessful attempt closes the gate."""
        with self._refresh_lock:
            # Close eligibility before any potentially blocking source read.
            with self._state_lock:
                self._available = False
            try:
                candidate = _parse_record(read_record())
                if candidate.version < self._minimum_version:
                    raise TrustStateInstallError(
                        "trust-state version below durable floor"
                    )
                with self._state_lock:
                    previous = self._snapshot
                    if previous is not None:
                        if candidate.version < previous.version:
                            raise TrustStateInstallError(
                                "trust-state version rollback refused"
                            )
                        if (
                            candidate.version == previous.version
                            and candidate != previous
                        ):
                            raise TrustStateInstallError(
                                "trust-state version content changed"
                            )
                    self._snapshot = candidate
                    self._available = True
            except Exception:
                refused = True
            else:
                refused = False
        # Raise outside the handler so the reader's exception (which may
        # include sensitive source data) is not retained in __context__.
        if refused:
            raise TrustStateInstallError("public trust-state install refused")

    def eligibility(
        self, *, key_id: str, public_key_fingerprint: str
    ) -> TrustEligibility:
        """Check public standing only; the caller still verifies the signature."""
        with self._state_lock:
            snapshot = self._snapshot
            if not self._available or snapshot is None:
                return TrustEligibility.UNAVAILABLE
            if key_id in snapshot.revoked_key_ids:
                return TrustEligibility.REVOKED
            expected = snapshot.trusted_key_ids.get(key_id)
            if expected is None:
                return TrustEligibility.UNKNOWN_KEY
            if expected != public_key_fingerprint:
                return TrustEligibility.FINGERPRINT_MISMATCH
            return TrustEligibility.ELIGIBLE
