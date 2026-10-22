"""Signer/receipt owner. Git commits precede all successful responses."""

import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from . import contracts as c
from .candidates import CandidateEvidenceReader
from .keys import ConfiguredDesiredSigner
from .ledger import GitLedger
from .models import (
    ActivateKey,
    Drift,
    IngestOutcome,
    IssueCommand,
    KeyRecord,
    KeyState,
    PlanPreview,
    PreviewCommand,
    Receipt,
    RegisterKey,
    RevokeKey,
)
from .projection import rebuild, receipt

GENERATED_FIELDS = set(
    "schema nonce issued_at expires_at signer_key_id plan_digest".split()
)


class DeployAgentService:
    def __init__(
        self,
        ledger: GitLedger,
        signer: ConfiguredDesiredSigner,
        *,
        deployment_ref: str = "dotmac_sub/staging/dotmac-sub-staging",
        clock: Callable[[], datetime] | None = None,
        candidate_reader: CandidateEvidenceReader | None = None,
        gate_scope: bytes | None = None,
    ) -> None:
        self.ledger, self.signer = ledger, signer
        self.deployment_ref = deployment_ref
        self.clock = clock or (lambda: datetime.now(UTC))
        self.candidate_reader = candidate_reader
        from .gate_admission import scope_bytes

        self.gate_scope = (
            scope_bytes(c.read_json(gate_scope)) if gate_scope is not None else None
        )

    def _events(self, kind: str) -> list[tuple[str, c.Json]]:
        return [
            (path, value)
            for path, value in self.ledger.events()
            if path.startswith(kind + "/")
        ]

    def _keys(self) -> dict[str, KeyRecord]:
        records = [cast(KeyRecord, value) for _, value in self._events("keys")]
        return {value["key_id"]: value for value in records}

    def _desired(
        self, ref: str | None = None
    ) -> list[tuple[str, c.Envelope, c.DesiredState]]:
        result = []
        for path, envelope in self._events("desired"):
            doc = c.validate_desired(
                c.verify(
                    c.DESIRED, cast(c.Envelope, envelope), self.signer.public_key_b64
                )
            )
            if ref is None or doc["deployment_ref"] == ref:
                result.append((path, cast(c.Envelope, envelope), doc))
        return result

    def _record(self, db: Session, records: dict[str, object]) -> None:
        self.ledger.append_many(records)
        # Repair a commit->DB crash before returning: git remains authoritative.
        self.validate_history()
        rebuild(db, self.ledger)

    def validate_history(self) -> None:
        keys: dict[str, KeyRecord] = {}
        desired: dict[str, c.DesiredState] = {}
        consumed: set[str] = set()
        for path, event in self.ledger.events():
            if path.startswith("keys/"):
                c._shape(event, KeyRecord)
                key = cast(KeyRecord, event)
                previous = keys.get(key["key_id"])
                c.require(
                    key["deployment_ref"] == self.deployment_ref, "ledger_identity"
                )
                if previous:
                    c.require(
                        previous["public_key_b64"] == key["public_key_b64"]
                        and previous["deployment_ref"] == key["deployment_ref"],
                        "ledger_identity",
                    )
                    c.require(
                        previous["state"] == "pending" or key["state"] == "revoked",
                        "ledger_identity",
                    )
                else:
                    c.require(
                        key["state"] == "pending"
                        and all(
                            other["public_key_b64"] != key["public_key_b64"]
                            for other in keys.values()
                        ),
                        "ledger_identity",
                    )
                if key["state"] == "active" and (
                    not previous or previous["state"] != "active"
                ):
                    c.require(
                        previous is not None and previous["state"] == "pending",
                        "ledger_identity",
                    )
                    proof = c.validate_possession(
                        c.verify(
                            c.POSSESSION, key["possession"], key["public_key_b64"]
                        ),
                        now=c.timestamp(key["received_at"]),
                    )
                    c.require(
                        proof["key_id"] == key["key_id"]
                        and proof["deployment_ref"] == key["deployment_ref"],
                        "ledger_identity",
                    )
                    challenge = cast(
                        c.Challenge, cast(KeyRecord, previous)["challenge"]
                    )
                    c.require(
                        all(
                            cast(c.Json, proof)[field] == value
                            for field, value in challenge.items()
                            if field != "schema"
                        ),
                        "ledger_identity",
                    )
                    c.require(
                        key["baseline_digest"] == proof["observed_image_digest"],
                        "ledger_identity",
                    )
                keys[key["key_id"]] = key
            elif path.startswith("desired/"):
                doc = c.validate_desired(
                    c.verify(
                        c.DESIRED, cast(c.Envelope, event), self.signer.public_key_b64
                    )
                )
                c.require(doc["nonce"] not in desired, "ledger_conflict")
                desired[doc["nonce"]] = doc
            elif path.startswith("quarantine/"):
                c.exact(event, {"code", "envelope"})
                envelope = cast(c.Envelope, event["envelope"])
                c._shape(envelope, c.Envelope)
                quarantine_key = keys.get(envelope["key_id"])
                if quarantine_key is None or quarantine_key["state"] != "active":
                    raise c.ContractError("host_key_inactive")
                c.validate_applied(
                    c.verify(c.APPLIED, envelope, quarantine_key["public_key_b64"])
                )
                c.require(
                    path == f"quarantine/{c.digest(envelope)[7:]}.json"
                    and event["code"]
                    in {
                        "deployment_mismatch",
                        "report_reused",
                        "desired_unknown",
                        "observed_mismatch",
                        "desired_mismatch",
                        "nonce_replay",
                    },
                    "ledger_identity",
                )
            elif path.startswith("applied/"):
                envelope = cast(c.Envelope, event)
                key = keys[envelope["key_id"]]
                c.require(key["state"] == "active", "host_key_inactive")
                report = c.validate_applied(
                    c.verify(c.APPLIED, envelope, key["public_key_b64"])
                )
                nonce = report["desired"]["nonce"]
                c.require(
                    report["deployment_ref"] == key["deployment_ref"]
                    and nonce in desired
                    and nonce not in consumed,
                    "ledger_identity",
                )
                c.require(
                    all(
                        cast(c.Json, desired[nonce])[field] == value
                        for field, value in report["desired"].items()
                    ),
                    "ledger_identity",
                )
                if report["disposition"] in {"applied", "already_applied"}:
                    c.require(
                        self._valid_success(report, desired[nonce]), "observed_mismatch"
                    )
                consumed.add(nonce)

        from .gate_admission import history

        history(self)

    def _latest_report(
        self, ref: str, *, successful: bool = False
    ) -> c.AppliedState | None:
        order = {
            doc["nonce"]: index for index, (_, _, doc) in enumerate(self._desired(ref))
        }
        reports = [
            c.validate_applied(c.read_json(c.unb64(cast(str, event["payload_b64"]))))
            for _, event in self._events("applied")
        ]
        eligible = [
            report
            for report in reports
            if report["deployment_ref"] == ref
            and report["desired"]["nonce"] in order
            and (
                not successful
                or report["disposition"] in {"applied", "already_applied"}
            )
        ]
        return (
            max(eligible, key=lambda report: order[report["desired"]["nonce"]])
            if eligible
            else None
        )

    def _baseline(self, ref: str) -> str:
        report = self._latest_report(ref, successful=True)
        if report:
            running = report["observed"]["running_image"]
            c.require(
                running is not None and "@sha256:" in running, "observed_mismatch"
            )
            return cast(str, running).rsplit("@", 1)[1]
        baseline = next(
            (
                key.get("baseline_digest")
                for key in self._keys().values()
                if key["deployment_ref"] == ref and key["state"] == "active"
            ),
            None,
        )
        c.require(baseline is not None, "baseline_missing")
        return cast(str, baseline)

    def issue(
        self,
        db: Session,
        request: IssueCommand | PreviewCommand,
        *,
        actor_admin_id: UUID,
    ) -> c.Envelope | PlanPreview:
        if request.get("mode") == "preview":
            c.exact(request, {"mode", "desired"})
            with self.ledger.transaction():
                doc = cast(c.Json, dict(request["desired"]))
                generated = GENERATED_FIELDS | {"from_image_digest"}
                c.exact(doc, c.DESIRED_FIELDS - generated)
                c.require(
                    doc["deployment_ref"] == self.deployment_ref, "deployment_mismatch"
                )
                doc["from_image_digest"] = self._baseline(self.deployment_ref)
                return {
                    "plan": c.plan_document(cast(c.Plan, doc)),
                    "plan_digest": c.plan_digest(cast(c.Plan, doc)),
                }
        request = cast(IssueCommand, request)
        c.exact(request, {"command_id", "desired", "approved_plan_digest"})
        c.identifier(request["command_id"])
        fingerprint = c.digest(
            {"request": request, "actor_admin_id": str(actor_admin_id)}
        )
        command_path = "commands/" + request["command_id"] + ".json"
        with self.ledger.transaction():
            previous = self.ledger.read(command_path)
            if previous:
                command = c.read_json(previous)
                c.require(command["fingerprint"] == fingerprint, "command_reused")
                rebuild(db, self.ledger)
                return cast(
                    c.Envelope,
                    c.read_json(
                        self.ledger.read(cast(str, command["desired_path"])) or b""
                    ),
                )
            doc = cast(c.Json, dict(request["desired"]))
            generated = GENERATED_FIELDS
            c.exact(doc, c.DESIRED_FIELDS - generated)
            c.require(
                doc["deployment_ref"] == self.deployment_ref, "deployment_mismatch"
            )
            c.require(
                doc["from_image_digest"]
                == self._baseline(cast(str, doc["deployment_ref"])),
                "baseline_moved",
            )
            now = self.clock()
            doc.update(
                schema=c.DESIRED,
                nonce=c.b64(secrets.token_bytes(24)),
                issued_at=now.isoformat().replace("+00:00", "Z"),
                expires_at=(now + timedelta(hours=4))
                .isoformat()
                .replace("+00:00", "Z"),
                signer_key_id=self.signer.key_id,
                plan_digest=request["approved_plan_digest"],
            )
            c.validate_desired(
                doc, now=now, approved_plan_digest=request["approved_plan_digest"]
            )
            c.require(self.candidate_reader is not None, "candidate_reader_unavailable")
            verified = c.validate_desired(doc)
            cast(CandidateEvidenceReader, self.candidate_reader).verify(verified)
            envelope = c.seal(c.DESIRED, verified, self.signer)
            path = f"desired/{self.deployment_ref}/{doc['nonce']}.json"
            self._record(
                db,
                {
                    path: envelope,
                    command_path: {
                        "fingerprint": fingerprint,
                        "desired_path": path,
                        "actor_admin_id": str(actor_admin_id),
                    },
                },
            )
            return envelope

    def latest(self, product: str, environment: str, host: str) -> c.Envelope | None:
        ref = "/".join((product, environment, host))
        c.require(ref == self.deployment_ref, "host_mismatch")
        with self.ledger.transaction():
            docs = self._desired(ref)
            return docs[-1][1] if docs else None

    def register(
        self, db: Session, request: RegisterKey | RevokeKey, *, actor_admin_id: UUID
    ) -> KeyRecord | KeyState:
        if request.get("operation") == "revoke":
            c.exact(request, {"operation", "key_id"})
            with self.ledger.transaction():
                key = self._keys().get(request["key_id"])
                if key is None:
                    raise c.ContractError("host_key_unknown")
                event = {
                    **key,
                    "state": "revoked",
                    "actor_admin_id": str(actor_admin_id),
                }
                self._record(db, {f"keys/{key['key_id']}/{uuid4()}.json": event})
                return {"state": "revoked"}
        request = cast(RegisterKey, request)
        c.exact(request, {"key_id", "deployment_ref", "public_key_b64"})
        c.identifier(request["key_id"])
        c.require(
            request["deployment_ref"] == self.deployment_ref, "deployment_mismatch"
        )
        c.require(len(c.unb64(request["public_key_b64"])) == 32)
        with self.ledger.transaction():
            keys = self._keys()
            if request["key_id"] in keys:
                existing = keys[request["key_id"]]
                c.require(
                    all(
                        cast(c.Json, existing)[k] == cast(c.Json, request)[k]
                        for k in request
                    ),
                    "key_reused",
                )
                return existing
            c.require(
                all(
                    key["public_key_b64"] != request["public_key_b64"]
                    for key in keys.values()
                ),
                "key_reused",
            )
            registration = cast(
                KeyRecord,
                {
                    **request,
                    "state": "pending",
                    "challenge": None,
                    "actor_admin_id": str(actor_admin_id),
                },
            )
            self._record(db, {f"keys/{request['key_id']}/{uuid4()}.json": registration})
            return registration

    def challenge(
        self, db: Session, key_id: str, *, actor_admin_id: UUID
    ) -> c.Challenge:
        with self.ledger.transaction():
            key = self._keys().get(key_id)
            c.require(
                key is not None and key["state"] == "pending", "host_key_inactive"
            )
            key = cast(KeyRecord, key)
            challenge: c.Challenge = {
                "schema": "dotmac.deploy_host_challenge/1",
                "key_id": key_id,
                "deployment_ref": key["deployment_ref"],
                "nonce": c.b64(secrets.token_bytes(24)),
                "expires_at": (self.clock() + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
            }
            event = {
                **key,
                "challenge": challenge,
                "actor_admin_id": str(actor_admin_id),
            }
            self._record(db, {f"keys/{key_id}/{uuid4()}.json": event})
            return challenge

    def activate(
        self, db: Session, request: ActivateKey, *, actor_admin_id: UUID
    ) -> KeyState:
        c.exact(request, {"envelope", "approved_public_key_fingerprint"})
        with self.ledger.transaction():
            key_id = request["envelope"].get("key_id")
            key = self._keys().get(key_id)
            c.require(
                key is not None and key["state"] == "pending", "host_key_inactive"
            )
            key = cast(KeyRecord, key)
            import hashlib

            expected = (
                "sha256:" + hashlib.sha256(c.unb64(key["public_key_b64"])).hexdigest()
            )
            c.require(
                request["approved_public_key_fingerprint"] == expected,
                "fingerprint_mismatch",
            )
            doc = c.validate_possession(
                c.verify(c.POSSESSION, request["envelope"], key["public_key_b64"])
            )
            c.validate_possession(doc, now=self.clock())
            c.require(
                all(
                    cast(c.Json, doc)[field] == value
                    for field, value in cast(c.Challenge, key["challenge"]).items()
                    if field != "schema"
                ),
                "challenge_mismatch",
            )
            event = {
                **key,
                "state": "active",
                "possession": request["envelope"],
                "baseline_digest": doc["observed_image_digest"],
                "received_at": self.clock().isoformat().replace("+00:00", "Z"),
                "actor_admin_id": str(actor_admin_id),
            }
            self._record(db, {f"keys/{key_id}/{uuid4()}.json": event})
            return {"state": "active"}

    @staticmethod
    def _valid_success(doc: c.AppliedState, desired: c.DesiredState) -> bool:
        observed, health = doc["observed"], doc["health"]
        matches = (
            observed["running_image"]
            == desired["image_reference"] + "@" + desired["image_digest"]
            and observed["running_revision_label"] == desired["source_revision"]
            and observed["pinned_image"] == observed["running_image"]
            and observed["pinned_git_sha"] == desired["source_revision"]
            and observed["config_files"] == desired["config_files"]
        )
        healthy = (
            health["live"]["status"] == health["ready"]["status"] == 200
            and health["ready"]["body_status"] == "ready"
            and health["background"]["celery_inspect_ok"]
            and health["background"]["restart_counts_zero"]
            and bool(health["background"]["containers"])
            and all(
                value == "running"
                for value in health["background"]["containers"].values()
            )
        )
        return matches and healthy

    def ingest(self, db: Session, envelope: c.Envelope) -> IngestOutcome:
        with self.ledger.transaction():
            c.exact(envelope, {"schema", "key_id", "payload_b64", "signature_b64"})
            key = self._keys().get(envelope["key_id"])
            c.require(key is not None and key["state"] == "active", "host_key_inactive")
            key = cast(KeyRecord, key)
            doc = c.validate_applied(
                c.verify(c.APPLIED, envelope, key["public_key_b64"])
            )

            def quarantine(code: str) -> IngestOutcome:
                path = f"quarantine/{c.digest(envelope)[7:]}.json"
                self._record(db, {path: {"code": code, "envelope": envelope}})
                return {"verdict": "quarantined:" + code}

            if key["deployment_ref"] != doc["deployment_ref"]:
                return quarantine("deployment_mismatch")
            path = f"applied/{key['deployment_ref']}/{doc['report_id']}.json"
            prior = self.ledger.read(path)
            if prior:
                if prior != c.canonical_json(envelope):
                    return quarantine("report_reused")
                rebuild(db, self.ledger)
                return {"verdict": "idempotent_replay"}
            desired = next(
                (
                    item[2]
                    for item in self._desired(key["deployment_ref"])
                    if item[2]["nonce"] == doc["desired"]["nonce"]
                ),
                None,
            )
            if desired is None:
                return quarantine("desired_unknown")
            if doc["disposition"] in {
                "applied",
                "already_applied",
            } and not self._valid_success(doc, desired):
                return quarantine("observed_mismatch")
            if any(
                cast(c.Json, desired)[field] != value
                for field, value in doc["desired"].items()
            ):
                return quarantine("desired_mismatch")
            for _, previous in self._events("applied"):
                previous_doc = c.validate_applied(
                    c.read_json(c.unb64(cast(str, previous["payload_b64"])))
                )
                if previous_doc["desired"]["nonce"] == doc["desired"]["nonce"]:
                    return quarantine("nonce_replay")
            self._record(db, {path: envelope})
            return {"verdict": "accepted"}

    def receipt(self, db: Session, report_id: UUID) -> Receipt | None:
        return receipt(db, self.deployment_ref, report_id)

    def drift(self) -> Drift:
        with self.ledger.transaction():
            desired = self._desired(self.deployment_ref)
            latest = self._latest_report(self.deployment_ref)
            target = desired[-1][2] if desired else None
            return {
                "deployment_ref": self.deployment_ref,
                "desired": target,
                "applied": latest,
                "drift": bool(
                    target
                    and (
                        not latest
                        or latest["desired"]["nonce"] != target["nonce"]
                        or latest["disposition"] not in {"applied", "already_applied"}
                    )
                ),
            }
