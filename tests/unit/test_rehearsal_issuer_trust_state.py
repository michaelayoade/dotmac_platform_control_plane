"""Standalone public-data tests; no private wheel or repository conftest needed."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from threading import Event, Thread

from vendor_cp.deployment.rehearsal_issuer_trust_state import (
    RehearsalIssuerTrustState,
    TrustEligibility,
    TrustStateInstallError,
)


def record(
    version: int = 7,
    *,
    trusted: dict[str, str] | None = None,
    revoked: list[str] | None = None,
) -> dict[str, object]:
    return {
        "version": version,
        "trusted_key_ids": {"issuer-1": "sha256:public-one"}
        if trusted is None
        else trusted,
        "revoked_key_ids": [] if revoked is None else revoked,
    }


def start(value: object = None, *, floor: int = 7) -> RehearsalIssuerTrustState:
    if value is None:
        value = record()
    return RehearsalIssuerTrustState.start(
        minimum_version=floor, read_record=lambda: value
    )


def standing(
    state: RehearsalIssuerTrustState, key: str = "issuer-1"
) -> TrustEligibility:
    return state.eligibility(key_id=key, public_key_fingerprint="sha256:public-one")


class RehearsalIssuerTrustStateTests(unittest.TestCase):
    def test_startup_accepts_public_record_at_durable_floor(self) -> None:
        state = start()
        self.assertEqual(state.snapshot.version, 7)
        self.assertTrue(state.available)
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_startup_refuses_missing_malformed_and_below_floor(self) -> None:
        for value in (
            None,
            {},
            {"version": True, "trusted_key_ids": {}, "revoked_key_ids": []},
            record(6),
            {**record(), "private_key": "never-echo-this"},
        ):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TrustStateInstallError) as caught:
                    RehearsalIssuerTrustState.start(
                        minimum_version=7, read_record=lambda value=value: value
                    )
                self.assertNotIn("never-echo-this", str(caught.exception))

        def unreadable() -> object:
            raise RuntimeError("never-echo-this")

        with self.assertRaises(TrustStateInstallError) as caught:
            RehearsalIssuerTrustState.start(minimum_version=7, read_record=unreadable)
        self.assertNotIn("never-echo-this", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_durable_floor_is_required_and_validated(self) -> None:
        for floor in (0, -1, True, "7"):
            with self.subTest(floor=floor):
                with self.assertRaises(ValueError):
                    RehearsalIssuerTrustState.start(
                        minimum_version=floor, read_record=record
                    )

    def test_revoked_wins_even_when_key_is_trusted(self) -> None:
        state = start(record(revoked=["issuer-1"]))
        self.assertIs(standing(state), TrustEligibility.REVOKED)
        # Sensitivity: deleting the revocation in an otherwise identical
        # startup record must flip the answer to eligible.
        self.assertIs(standing(start(record())), TrustEligibility.ELIGIBLE)

    def test_unknown_key_and_fingerprint_mismatch_are_distinct(self) -> None:
        state = start()
        self.assertIs(standing(state, "issuer-2"), TrustEligibility.UNKNOWN_KEY)
        self.assertIs(
            state.eligibility(key_id="issuer-1", public_key_fingerprint="sha256:other"),
            TrustEligibility.FINGERPRINT_MISMATCH,
        )
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_refresh_refuses_rollback_and_keeps_higher_snapshot(self) -> None:
        state = start(record(8), floor=7)
        with self.assertRaises(TrustStateInstallError):
            state.refresh(read_record=lambda: record(7, revoked=["issuer-1"]))
        self.assertEqual(state.snapshot.version, 8)
        self.assertFalse(state.available)
        self.assertIs(standing(state), TrustEligibility.UNAVAILABLE)
        # Sensitivity: a strictly higher valid version installs and recovers.
        state.refresh(read_record=lambda: record(9, revoked=["issuer-1"]))
        self.assertEqual(state.snapshot.version, 9)
        self.assertIs(standing(state), TrustEligibility.REVOKED)

    def test_same_version_changed_content_refused_without_aba(self) -> None:
        state = start()
        with self.assertRaises(TrustStateInstallError):
            state.refresh(read_record=lambda: record(7, revoked=["issuer-1"]))
        self.assertEqual(state.snapshot.version, 7)
        self.assertIs(standing(state), TrustEligibility.UNAVAILABLE)
        state.refresh(read_record=lambda: record(7))
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_failed_read_and_malformed_refresh_close_then_recover(self) -> None:
        state = start()

        def unreadable() -> object:
            raise OSError("never-echo-this")

        with self.assertRaises(TrustStateInstallError) as caught:
            state.refresh(read_record=unreadable)
        self.assertNotIn("never-echo-this", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertIs(standing(state), TrustEligibility.UNAVAILABLE)
        with self.assertRaises(TrustStateInstallError):
            state.refresh(read_record=lambda: {"version": 8})
        self.assertIs(standing(state), TrustEligibility.UNAVAILABLE)
        state.refresh(read_record=lambda: record(8))
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_snapshot_copies_inputs_and_cannot_be_mutated(self) -> None:
        trusted = {"issuer-1": "sha256:public-one"}
        revoked: list[str] = []
        state = start(record(trusted=trusted, revoked=revoked))
        trusted["issuer-1"] = "sha256:tampered"
        revoked.append("issuer-1")
        snapshot = state.snapshot
        self.assertEqual(snapshot.trusted_key_ids["issuer-1"], "sha256:public-one")
        self.assertEqual(snapshot.revoked_key_ids, frozenset())
        with self.assertRaises(TypeError):
            snapshot.trusted_key_ids["issuer-1"] = "sha256:tampered"
        with self.assertRaises(FrozenInstanceError):
            snapshot.version = 99
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_blocked_refresh_closes_gate_without_blocking_state_reads(self) -> None:
        state = start()
        loader_started = Event()
        release_loader = Event()
        refresh_done = Event()
        observer_done = Event()
        errors: list[Exception] = []
        observed: list[tuple[int | None, TrustEligibility, bool]] = []

        def blocked_reader() -> object:
            loader_started.set()
            if not release_loader.wait(5):
                raise TimeoutError("test loader was not released")
            return record(8)

        def refresh() -> None:
            try:
                state.refresh(read_record=blocked_reader)
            except Exception as exc:
                errors.append(exc)
            finally:
                refresh_done.set()

        def observe() -> None:
            try:
                snapshot = state.snapshot
                observed.append(
                    (
                        None if snapshot is None else snapshot.version,
                        standing(state),
                        state.available,
                    )
                )
            finally:
                observer_done.set()

        refreshing = Thread(target=refresh, daemon=True)
        observing = Thread(target=observe, daemon=True)
        refreshing.start()
        try:
            self.assertTrue(loader_started.wait(2), "loader never entered")
            observing.start()
            self.assertTrue(
                observer_done.wait(2),
                "eligibility or snapshot blocked behind the reader",
            )
            self.assertEqual(observed, [(7, TrustEligibility.UNAVAILABLE, False)])
        finally:
            release_loader.set()
            refreshing.join(2)
            if observing.ident is not None:
                observing.join(2)

        self.assertTrue(refresh_done.is_set())
        self.assertFalse(errors)
        self.assertEqual(state.snapshot.version, 8)
        self.assertIs(standing(state), TrustEligibility.ELIGIBLE)

    def test_validation_refuses_duplicate_revocations_and_non_public_fields(
        self,
    ) -> None:
        for value in (
            record(revoked=["issuer-1", "issuer-1"]),
            record(trusted={"": "sha256:public-one"}),
            record(trusted={"issuer-1": ""}),
            {**record(), "public_key": "material-not-part-of-record"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(TrustStateInstallError):
                    RehearsalIssuerTrustState.start(
                        minimum_version=7, read_record=lambda value=value: value
                    )


if __name__ == "__main__":
    unittest.main()
