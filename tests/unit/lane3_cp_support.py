"""Harness: run Starter's store-agnostic lease conformance suite against `CpLeaseStore`.

Not a test module (no `test_` prefix); `tests/migration/test_lane3_lease_store.py`
and the local runner both import it by path, because `tests` is not a package.

## What is real and what is injected

Real: the `v023_lane3_store` migration as the migration role, the SECURITY DEFINER
functions, a real per-run LEASE ROLE created from `lease_role_spec`'s statements
(one role per handle: each is `CONNECTION LIMIT 2`, and the concurrency case needs
eight simultaneous handles), a real `run_bindings` row per role, the real
`CpLeaseStore`, real Foundation `HostLease` / `HostLeaseReleaseV1` values, and the
real `lane3_e10` command core writing receipts and destructions.

Injected: the attestation registry (`lane3_e10.Registry`). CI passes Control a17's
`ControlRegistry`; the local runner passes a SQL stand-in for the same tables.

The clock is the one thing this harness replaces, and only in the per-case
database: `cp_lane3.store_now()` is redefined over a one-row clock table that
`advance` moves, so `covers(...) == database_time()` and
`released_at == database_time()` are assertions no live clock could satisfy. The
production body is proven separately (`test_lane3_store_clock`): `pg_get_functiondef`
digest of the MIGRATION's `store_now`.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import threading
import types
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from vendor_cp.deployment import lane3_e10, lease_role_spec
from vendor_cp.deployment.lease_store import CpLeaseStore

VENDORED = Path(__file__).resolve().parents[1] / "vendored" / "starter_lane3"
FIXED_PASSWORD = "x" * 24  # noqa: S105 - the test cluster trusts local logins

_loaded: types.SimpleNamespace | None = None


def verify_pins() -> dict[str, Any]:
    """The vendored blobs must equal their recorded sha256, byte for byte."""
    pins = json.loads((VENDORED / "PINS.json").read_text(encoding="utf-8"))
    for name, entry in pins["files"].items():
        actual = hashlib.sha256((VENDORED / name).read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise AssertionError(f"vendored {name} drifted from its pinned digest")
    return pins  # type: ignore[no-any-return]


def load_vendored() -> types.SimpleNamespace:
    """Import the pinned Starter suite under the names it imports itself by.

    `tests` is not a package here, so the suite's `from tests.unit.lane3_e10_support
    import ...` is satisfied by a temporary `sys.modules` alias that is removed
    again; the `lane3_*` script names stay registered.
    """
    global _loaded
    if _loaded is not None:
        return _loaded
    verify_pins()
    saved = {k: sys.modules.get(k) for k in ("tests", "tests.unit")}
    saved_path = list(sys.path)

    def load(name: str, filename: str) -> types.ModuleType:
        spec = importlib.util.spec_from_file_location(name, VENDORED / filename)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    try:
        receipt = load("lane3_e10_receipt", "lane3_e10_receipt.py")
        store = load("lane3_lease_store", "lane3_lease_store.py")
        e10_support = load("tests.unit.lane3_e10_support", "lane3_e10_support.py")
        sys.modules["tests"] = types.ModuleType("tests")
        sys.modules["tests.unit"] = types.ModuleType("tests.unit")
        sys.modules["tests.unit.lane3_e10_support"] = e10_support
        support = load("lane3_store_support_vendored", "lane3_store_support.py")
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
        sys.modules.pop("tests.unit.lane3_e10_support", None)
        sys.path[:] = saved_path
    _loaded = types.SimpleNamespace(
        e10_receipt=receipt, lease_store=store, e10_support=e10_support, support=support
    )
    return _loaded


class SqlRegistry:
    """The registry stand-in for a database without Control (local runs only).

    Implements the same contract on the same table names and columns.
    """

    def enrol(self, db: Any, **kw: Any) -> lane3_e10.RegistryEnrolment:
        raw = lane3_e10._raw_b64url(kw["public_key_b64url"])
        fingerprint = lane3_e10.fingerprint_of(raw)
        domain, subject = kw["custody_domain"], kw["subject"]
        current = db.execute(
            text(
                "SELECT current_fingerprint FROM mod_deploy.attestation_current_roots "
                "WHERE custody_domain=:d AND subject=:s"
            ),
            {"d": domain, "s": subject},
        ).scalar_one_or_none()
        enrolment = str(uuid.uuid4())
        db.execute(
            text(
                "INSERT INTO mod_deploy.attestation_enrolments (id, custody_domain, "
                "subject, public_key_b64, public_key_fingerprint, algorithm, "
                "key_custody_pointer, supersedes_fingerprint, enrolled_at, "
                "enrolment_authority) VALUES (CAST(:id AS uuid), :d, :s, :k, :fp, "
                "'ed25519', :p, :sup, :at, 'test')"
            ),
            {
                "id": enrolment,
                "d": domain,
                "s": subject,
                "k": kw["public_key_b64url"],
                "fp": fingerprint,
                "p": kw["pointer"],
                "sup": current,
                "at": kw["enrolled_at"],
            },
        )
        if current is None:
            db.execute(
                text(
                    "INSERT INTO mod_deploy.attestation_current_roots VALUES (:d,:s,:f)"
                ),
                {"d": domain, "s": subject, "f": fingerprint},
            )
        else:
            db.execute(
                text(
                    "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                    "VALUES (:f, 'superseded')"
                ),
                {"f": current},
            )
            db.execute(
                text(
                    "UPDATE mod_deploy.attestation_current_roots SET "
                    "current_fingerprint=:f WHERE custody_domain=:d AND subject=:s"
                ),
                {"d": domain, "s": subject, "f": fingerprint},
            )
        return lane3_e10.RegistryEnrolment(enrolment, fingerprint, kw["enrolled_at"])

    def revoke(
        self, db: Any, *, fingerprint: str, reason: str, revoked_at: Any
    ) -> None:
        db.execute(
            text(
                "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                "VALUES (:f, 'revoked')"
            ),
            {"f": fingerprint},
        )
        db.execute(
            text(
                "DELETE FROM mod_deploy.attestation_current_roots "
                "WHERE current_fingerprint = :f"
            ),
            {"f": fingerprint},
        )


class TransitKey:
    """A stand-in for one OpenBao transit key: an Ed25519 key the TEST holds."""

    def __init__(self, seed: bytes) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._key = Ed25519PrivateKey.from_private_bytes(seed)

    @property
    def raw_public(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def read_back(self, **flags: bool) -> dict[str, Any]:
        document: dict[str, Any] = {
            "type": "ed25519",
            "exportable": False,
            "allow_plaintext_backup": False,
            "derived": False,
            "deletion_allowed": False,
            "latest_version": 1,
            "keys": {
                "1": {"public_key": base64.b64encode(self.raw_public).decode("ascii")}
            },
        }
        document.update(flags)
        return {"data": document}

    def sign(self, message: bytes) -> str:
        return "vault:v1:" + base64.b64encode(self._key.sign(message)).decode("ascii")


class CaseDatabase:
    """One migrated database for one case, a frozen clock, and its lease handles."""

    HOSTS = ("host-a", "host-b", "host-other")
    RUNS = tuple(
        dict.fromkeys(("run-1", "run-2", "run-3", *[f"run-{i}" for i in range(8)]))
    )

    def __init__(
        self,
        *,
        admin: Engine,
        url_for_role: Callable[[str], str],
        registry: Any,
        clock_start: datetime,
    ) -> None:
        self.admin = admin
        self._url_for_role = url_for_role
        self.registry = registry
        self.start = clock_start.replace(microsecond=0)
        self._engines: list[Engine] = []
        self.stores: list[CpLeaseStore] = []
        self.roles: list[str] = []
        self._receipts: dict[tuple[Any, ...], Any] = {}
        self._keys: dict[tuple[str, int], TransitKey] = {}
        self._lock = threading.RLock()
        self._install_clock()

    @property
    def vendored(self) -> types.SimpleNamespace:
        """The pinned Starter suite, loaded on first use (it needs Foundation)."""
        return load_vendored()

    # ── the frozen clock ────────────────────────────────────────────────────

    def _install_clock(self) -> None:
        with self.admin.begin() as conn:
            conn.execute(text("CREATE SCHEMA cp_lane3_test"))
            conn.execute(text("CREATE TABLE cp_lane3_test.clock (t timestamptz)"))
            # The replacement `store_now` runs as the function OWNER (the
            # migration role), which must be able to read the clock table.
            conn.execute(text("GRANT USAGE ON SCHEMA cp_lane3_test TO app_admin"))
            conn.execute(text("GRANT SELECT ON cp_lane3_test.clock TO app_admin"))
            conn.execute(
                text("INSERT INTO cp_lane3_test.clock VALUES (:t)"), {"t": self.start}
            )
            conn.execute(
                text(
                    "CREATE OR REPLACE FUNCTION cp_lane3.store_now() "
                    "RETURNS timestamptz "
                    "LANGUAGE sql SECURITY DEFINER "
                    "SET search_path = pg_catalog, pg_temp "
                    "AS $$ SELECT t FROM cp_lane3_test.clock $$"
                )
            )

    def advance(self, _store: Any, seconds: float) -> None:
        with self.admin.begin() as conn:
            conn.execute(
                text("UPDATE cp_lane3_test.clock SET t = t + :s * interval '1 second'"),
                {"s": seconds},
            )

    def now(self) -> datetime:
        with self.admin.begin() as conn:
            return conn.execute(text("SELECT t FROM cp_lane3_test.clock")).scalar_one()  # type: ignore[no-any-return]

    # ── lease roles and stores ──────────────────────────────────────────────

    def _create_role(self) -> str:
        role = "l3_" + uuid.uuid4().hex[:16]
        verifier = lease_role_spec.scram_verifier(FIXED_PASSWORD, iterations=4096)
        real_now = datetime.now(UTC)
        until_dt = real_now + timedelta(hours=3)
        statements = lease_role_spec.executable_creation_sql(
            role,
            host_id=self.HOSTS[0],
            authorization_run=self.RUNS[0],
            scram_verifier_value=verifier,
            valid_until=until_dt,
            now=real_now,
        )
        until = until_dt.strftime("%Y-%m-%d %H:%M:%S+00")
        with self.admin.connect().execution_options(
            isolation_level="AUTOCOMMIT"
        ) as conn:
            # The rendered transaction, statement by statement (autocommit).
            for statement in statements:
                if statement not in ("BEGIN", "COMMIT"):
                    conn.exec_driver_sql(statement)
            for host in self.HOSTS:
                for run in self.RUNS:
                    if (host, run) != (self.HOSTS[0], self.RUNS[0]):
                        conn.exec_driver_sql(
                            "INSERT INTO cp_lane3.run_bindings (role_name, host_id, "
                            "authorization_run, valid_until, recorded_by) VALUES "
                            f"('{role}', '{host}', '{run}', '{until}', "
                            "'lane3-ceremony')"
                        )
        self.roles.append(role)
        return role

    def make_store(self, handle: CpLeaseStore | None = None) -> CpLeaseStore:
        """A NEW handle (its own role, its own connection) onto this database."""
        role = self._create_role()
        engine = create_engine(self._url_for_role(role), pool_size=1, max_overflow=0)
        self._engines.append(engine)
        v = self.vendored
        store = CpLeaseStore(
            lambda: engine.connect(),
            workload_principal=v.support.PRINCIPAL,
            refused=v.lease_store.StoreRefused,
            held_lease=v.lease_store.HeldLease,
            standing_enum=v.lease_store.LeaseStanding,
        )
        self.stores.append(store)
        return store

    # ── receipts (real command core) ────────────────────────────────────────

    def _key(self, host: str, n: int) -> TransitKey:
        key = self._keys.get((host, n))
        if key is None:
            seed = hashlib.sha256(f"lane3-test:{host}:{n}".encode()).digest()
            key = self._keys[(host, n)] = TransitKey(seed)
        return key

    def _enrol(self, host: str, n: int, *, key_of: int | None) -> str:
        """One receipt, as the real command writes it. Returns its ref."""
        key = self._key(host, key_of or n)
        nonce = bytes(range(32))
        request = {
            "host_id": host,
            "vm_alias": f"vm-{host}",
            "vm_slot": None,
            "machine_id": hashlib.sha256(host.encode()).hexdigest()[:32],
            "ssh_host_key_fingerprint": "SHA256:" + "B" * 43,
            "mount": f"transit-a2-hi-vm-{host}-{n}",
            "transit_key": key.read_back(),
            "pop_signature": key.sign(lane3_e10.incarnation_pop_message(host, nonce)),
            "nonce": base64.urlsafe_b64encode(nonce).decode().rstrip("="),
            "issuer": "urn:dotmac:foundation:installed-host-ceremony:a2",
            "attestation_key_id": f"incarnation-{host}-{n}",
            "not_after": (self.start + timedelta(days=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "recorded_by": "harness",
        }
        with Session(self.admin) as db:
            if key_of is not None and key_of != n:
                # The SAME incarnation key under a second receipt: Control would
                # (rightly) refuse to enrol a fingerprint twice, so this row has
                # an enrolment Control never saw. The store refuses it for being
                # the same incarnation BEFORE it asks Control.
                ref = self._insert_receipt_directly(db, request, key)
            else:
                ref = lane3_e10.enrol_incarnation(
                    db, self.registry, request
                ).receipt_ref
            db.commit()
        return ref

    def _insert_receipt_directly(
        self, conn: Any, request: dict[str, Any], key: TransitKey
    ) -> str:
        receipt_ref = f"e10-{uuid.uuid4()}"
        public = lane3_e10._b64url(key.raw_public)
        conn.execute(
            text(
                "INSERT INTO cp_lane3.e10_receipts (receipt_ref, vm_alias, host_id, "
                "machine_id, ssh_host_key_fingerprint, vm_slot, "
                "incarnation_public_key_b64url, incarnation_fingerprint, "
                "enrolment_uuid, key_custody_pointer, recorded_by) VALUES (:ref, "
                ":alias, :host, :machine, :ssh, NULL, :key, :fp, "
                "CAST(:enrolment AS uuid), :pointer, 'harness')"
            ),
            {
                "ref": receipt_ref,
                "alias": request["vm_alias"],
                "host": request["host_id"],
                "machine": request["machine_id"],
                "ssh": request["ssh_host_key_fingerprint"],
                "key": public,
                "fp": lane3_e10.fingerprint_of(key.raw_public),
                "enrolment": str(uuid.uuid4()),
                "pointer": f"bao://{request['mount']}/keys/incarnation",
            },
        )
        return receipt_ref

    def receipt(
        self,
        host_id: str,
        generation: int,
        *,
        ordered_as: int | None = None,
        incarnation_of: int | None = None,
        **_unused: Any,
    ) -> Any:
        """The generation-th receipt for the host, in the store's own order.

        Earlier generations are created first so each is LATER in `seq` than the
        one before. `ordered_as=n` gives the receipt generation n's `seq` (a tie:
        the table deliberately carries no UNIQUE on `seq`); `incarnation_of=n`
        gives it generation n's KEY while its ref, enrolment and order stay its own.
        """
        with self._lock:
            memo = (host_id, generation, ordered_as, incarnation_of)
            if memo in self._receipts:
                return self._receipts[memo]
            for earlier in range(1, generation):
                if (host_id, earlier, None, None) not in self._receipts:
                    self._receipts[(host_id, earlier, None, None)] = self._make(
                        host_id, earlier, None, None
                    )
            made = self._make(host_id, generation, ordered_as, incarnation_of)
            self._receipts[memo] = made
            return made

    def _make(
        self, host: str, n: int, ordered_as: int | None, incarnation_of: int | None
    ) -> Any:
        tied_seq: int | None = None
        if ordered_as is not None:
            tied_seq = self._seq_of(host, ordered_as)
        ref = self._enrol(host, n, key_of=incarnation_of)
        if tied_seq is not None:
            # Owner-only test setup, in its own transaction: give this receipt
            # another generation's position. Production never does this, and the
            # guard trigger refuses it; `replica` mode steps over the trigger for
            # this one statement only (and over the clock-stamp trigger too,
            # which is why the destruction below is a separate transaction).
            with self.admin.begin() as conn:
                conn.execute(text("SET LOCAL session_replication_role = replica"))
                conn.execute(
                    text(
                        "UPDATE cp_lane3.e10_receipts SET seq=:s WHERE receipt_ref=:r"
                    ),
                    {"s": tied_seq, "r": ref},
                )
        with self.admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO cp_lane3.e10_destructions (receipt_ref, route, "
                    "evidence_digest, recorded_by) VALUES (:r, "
                    "'transit_mount_disabled', :d, 'harness')"
                ),
                {"r": ref, "d": "sha256:" + hashlib.sha256(ref.encode()).hexdigest()},
            )
            row = (
                conn.execute(
                    text(
                        "SELECT r.*, r.enrolment_uuid::text AS enrolment_text, "
                        "d.destroyed_at FROM cp_lane3.e10_receipts r JOIN "
                        "cp_lane3.e10_destructions d USING (receipt_ref) "
                        "WHERE r.receipt_ref = :r"
                    ),
                    {"r": ref},
                )
                .mappings()
                .one()
            )
        return self.vendored.e10_receipt.E10ReceiptRef(
            vm_alias=row["vm_alias"],
            host_id=row["host_id"],
            machine_id=row["machine_id"],
            ssh_host_key_fingerprint=row["ssh_host_key_fingerprint"],
            incarnation_public_key_b64url=row["incarnation_public_key_b64url"],
            incarnation_fingerprint=row["incarnation_fingerprint"],
            enrolment_uuid=row["enrolment_text"],
            incarnation_key_destroyed_at=row["destroyed_at"],
            receipt_ref=row["receipt_ref"],
            vm_slot=row["vm_slot"],
        )

    def unsealed_receipt(self, host: str, generation: int) -> Any:
        """A receipt whose destruction was NEVER stamped (claimed as destroyed now).

        The store reads the destruction from its own table, so the claim is refused
        (`-not-destroyed`) however the receipt is spelled.
        """
        ref = self._enrol(host, generation, key_of=None)
        with self.admin.begin() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT *, enrolment_uuid::text AS enrolment_text "
                        "FROM cp_lane3.e10_receipts WHERE receipt_ref = :r"
                    ),
                    {"r": ref},
                )
                .mappings()
                .one()
            )
        return self.vendored.e10_receipt.E10ReceiptRef(
            vm_alias=row["vm_alias"],
            host_id=row["host_id"],
            machine_id=row["machine_id"],
            ssh_host_key_fingerprint=row["ssh_host_key_fingerprint"],
            incarnation_public_key_b64url=row["incarnation_public_key_b64url"],
            incarnation_fingerprint=row["incarnation_fingerprint"],
            enrolment_uuid=row["enrolment_text"],
            incarnation_key_destroyed_at=self.now(),
            receipt_ref=row["receipt_ref"],
            vm_slot=row["vm_slot"],
        )

    def _seq_of(self, host: str, generation: int) -> int:
        receipt = self.receipt(host, generation)
        with self.admin.begin() as conn:
            return int(
                conn.execute(
                    text("SELECT seq FROM cp_lane3.e10_receipts WHERE receipt_ref=:r"),
                    {"r": receipt.receipt_ref},
                ).scalar_one()
            )

    # ── the fixtures the suite asks a real store for ────────────────────────

    def fixtures(self) -> Any:
        v = self.vendored
        from dotmac_deployment_foundation.controller_identity import (
            ControllerSshFingerprintV1,
        )
        from dotmac_deployment_foundation.lease_release import (
            CleanupDisposition,
            HostClosure,
            HostLeaseReleaseV1,
            ReleasingPrincipal,
            TerminalOutcome,
            lease_digest,
        )

        def make_release(
            store: Any,
            held: Any,
            *,
            digest: str | None = None,
            principal: str | None = None,
            controller: Any = None,
            released_at: str | None = None,
        ) -> Any:
            run = "33860000001"
            return HostLeaseReleaseV1(
                lease_digest=digest or lease_digest(held.lease),
                vm_slot="dotmacproxmox/102",
                vm_installation_id="",
                candidate_version="0.4.0a2",
                candidate_source_revision="0" * 40,
                runner_revision="1" * 40,
                authorization_run_id=held.lease.authorization_run_id,
                rehearsal_run_id=run,
                outcome=TerminalOutcome(receipt_digest="sha256:" + "b" * 64),
                released_at=released_at or store.database_time().isoformat(),
                released_by=ReleasingPrincipal(
                    kind="github_actions_workload",
                    subject=principal or held.lease.workload_principal,
                    run_binding=run,
                ),
                controller_identity_fingerprint=(
                    controller or held.lease.controller_identity_fingerprint
                ),
                closure=HostClosure.REUSABLE,
                cleanup=CleanupDisposition.PURGED,
            )

        def pid_of(store: CpLeaseStore) -> int:
            conn = store._connection()
            pid = conn.exec_driver_sql("SELECT pg_backend_pid()").scalar_one()
            conn.rollback()
            return int(pid)

        def terminate(pid: int) -> None:
            with self.admin.begin() as conn:
                conn.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})

        def sever(store: CpLeaseStore, when: str) -> None:
            if when == "before_write":
                terminate(pid_of(store))
                return
            if when != "after_commit":
                raise ValueError(when)
            conn = store._connection()
            pid = pid_of(store)
            real_commit = conn.commit

            def commit_then_die() -> None:
                real_commit()  # the COMMIT lands...
                terminate(pid)  # ...and the connection dies before the answer
                raise OperationalError(
                    "COMMIT", None, ConnectionError("server closed the connection")
                )

            conn.commit = commit_then_die  # type: ignore[method-assign]

        return v.support.Fixtures(
            controller_identity=ControllerSshFingerprintV1(digest=bytes(range(32))),
            other_controller_identity=ControllerSshFingerprintV1(
                digest=bytes(range(1, 33))
            ),
            principal=v.support.PRINCIPAL,
            lease_digest=lambda held: lease_digest(held.lease),
            make_release=make_release,
            receipt=self.receipt,
            sever=sever,
            write_attempts=lambda _store: sum(s.writes_reached for s in self.stores),
        )

    def close(self) -> None:
        for store in self.stores:
            store.close()
        for engine in self._engines:
            engine.dispose()
