"""Finite installed historical source evidence for the future single CP E writer.

No source fact authorizes publication or confers an owner decision. Private helper
imports intentionally reuse the same assembly's qualified transport mechanics.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from vendor_cp.deployment import gate0_e_github as _mechanics
from vendor_cp.deployment.gate0_e_github import (
    _API_VERSION,
    _canonical,
    _closed,
    _digest,
    _hex,
    _id,
    _instant,
    _json,
    _obj,
    _protected,
    _spawn_get,
    _text,
)

_INSTALLATION = "/run/dotmac-gate0-e/source-references.json"
_QUALIFICATION = "/run/dotmac-gate0-e/source-references-qualification.json"
_BINDING = "/etc/dotmac-gate0-e/source-references-binding.json"
_CREDENTIAL = "/run/dotmac-gate0-e/source-references-token"
_RETAINED = "/etc/dotmac-gate0-e/source-references/"
_CAP = 1024 * 1024
_SEAL = object()
_REPOSITORIES = {"cp": "dotmac_platform_control_plane", "starter": "dotmac_starter_mt"}
_CP_PRS = {200, 201, 204, 205, 206, 207, 208, 209, 210, 212, 214, 215, 216}
_ADR = "docs/adr/0013-operator-authorization-issuer-and-its-bootstrap.md"
_DECISIONS = {
    "rulings": ("dotmac-build-once-programme-queue-2026-08-30", 120),
    "source_completion": (
        "dotmac-debt-d1-gate-0-protected-rehearsal-issuer-readiness",
        1,
    ),
}


class HistoricalReferencesRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("HISTORICAL_REFERENCES_REFUSED")


def _require(condition: bool) -> None:
    if not condition:
        raise HistoricalReferencesRefused()


def _path(value: object) -> str:
    path = _text(value, 256)
    _require(
        not any(c in path for c in "?#%\\")
        and all(part not in ("", ".", "..") for part in path.split("/"))
        and (
            path.startswith(
                ("src/", "packages/", "tests/", "docs/adr/", ".github/workflows/")
            )
            or path in ("pyproject.toml", "poetry.lock")
        )
    )
    return path


def _list(value: object, minimum: int, maximum: int) -> list[Any]:
    _require(type(value) is list and minimum <= len(value) <= maximum)
    return value


def _repo(value: object, key: str) -> dict[str, Any]:
    repo = _closed(value, "owner name repository_id owner_id")
    _require(repo["owner"] == "michaelayoade" and repo["name"] == _REPOSITORIES[key])
    _id(repo["repository_id"])
    _id(repo["owner_id"])
    return repo


@dataclass(frozen=True, slots=True, init=False)
class HistoricalSourceFacts:
    reference_bytes: bytes = field(repr=False)
    reference_sha256: str
    installation_sha256: str
    qualification_sha256: str
    source_policy_digest: str
    observations: tuple[bytes, ...] = field(repr=False)
    decision_records: tuple[tuple[str, bytes, str], ...] = field(repr=False)
    result: str = "historical_source_references_verified"

    def __init__(
        self,
        seal: object,
        reference_bytes: bytes,
        installation_sha256: str,
        qualification_sha256: str,
        source_policy_digest: str,
        observations: tuple[bytes, ...],
        decision_records: tuple[tuple[str, bytes, str], ...],
    ) -> None:
        _require(seal is _SEAL)
        for key, value in (
            ("reference_bytes", reference_bytes),
            ("reference_sha256", _digest(reference_bytes)),
            ("installation_sha256", installation_sha256),
            ("qualification_sha256", qualification_sha256),
            ("source_policy_digest", source_policy_digest),
            ("observations", observations),
            ("decision_records", decision_records),
            ("result", "historical_source_references_verified"),
        ):
            object.__setattr__(self, key, value)


class InstalledHistoricalSourceReads:
    """No caller-selected installation, credential, endpoint or transport."""

    def __init__(
        self,
        seal: object,
        installation: dict[str, Any],
        qualification: dict[str, Any],
        installation_raw: bytes,
        qualification_raw: bytes,
        retained: dict[str, bytes],
    ) -> None:
        _require(seal is _SEAL)
        self._installation = installation
        self._qualification = qualification
        self._installation_raw = installation_raw
        self._qualification_raw = qualification_raw
        self._retained = retained
        self._used = False
        self._failed = False
        self._issued: list[object] = []
        self._cache: dict[str, tuple[dict[str, Any], int, int]] = {}
        self._responses: list[tuple[str, bytes]] = []
        self._bytes = 0
        self._deadline = 0.0

    @classmethod
    def from_installed(cls) -> InstalledHistoricalSourceReads:
        try:
            raw = _protected(_INSTALLATION, 256 * 1024)
            selection = _closed(
                _json(raw),
                "schema policy_digest repositories decisions packets credential "
                "qualification",
            )
            _require(_canonical(selection) == raw)
            _require(selection["schema"] == "Gate0EHistoricalSourceSelection.v1")
            _hex(selection["policy_digest"])
            _require(selection["credential"] == _CREDENTIAL)
            binding_raw = _protected(_BINDING, 64 * 1024)
            binding = _closed(
                _json(binding_raw),
                "schema installation_sha256 qualification_sha256 reader_source_sha256 "
                "github_mechanics_sha256 native_receipt_pin runtime_uid",
            )
            _require(_canonical(binding) == binding_raw)
            _require(binding["schema"] == "Gate0EHistoricalSourceBinding.v1")
            _require(_hex(binding["installation_sha256"]) == _digest(raw))
            uid = binding["runtime_uid"]
            _require(
                type(uid) is int and uid >= 0 and os.getuid() == os.geteuid() == uid
            )
            for path, key in (
                (os.path.abspath(__file__), "reader_source_sha256"),
                (os.path.abspath(_mechanics.__file__), "github_mechanics_sha256"),
            ):
                _require(
                    _digest(_protected(path, _CAP, private=False)) == _hex(binding[key])
                )
            retained: dict[str, bytes] = {}

            def pin(value: object) -> bytes:
                record = _closed(value, "path sha256")
                path = _text(record["path"], 1024)
                _require(path.startswith(_RETAINED))
                _require(all(p not in ("", ".", "..") for p in path[1:].split("/")))
                if path not in retained:
                    retained[path] = _protected(path, _CAP)
                result = retained[path]
                _require(_digest(result) == _hex(record["sha256"]))
                _require(sum(map(len, retained.values())) <= 4 * _CAP)
                return result

            qualification_pin = _closed(selection["qualification"], "path sha256")
            _require(qualification_pin["path"] == _QUALIFICATION)
            qual_raw = _protected(_QUALIFICATION, 64 * 1024)
            _require(_digest(qual_raw) == _hex(qualification_pin["sha256"]))
            qual = _closed(
                _json(qual_raw),
                "schema selection_sha256 policy_digest runtime_uid credential_uid "
                "api_version repositories permissions native_receipt_pin "
                "decision_provenance_pin",
            )
            _require(_canonical(qual) == qual_raw)
            _require(qual["schema"] == "Gate0EHistoricalSourceQualification.v1")
            _require(_digest(qual_raw) == _hex(binding["qualification_sha256"]))
            _require(
                _hex(qual["selection_sha256"])
                == _digest(
                    _canonical(
                        {k: v for k, v in selection.items() if k != "qualification"}
                    )
                )
            )
            _require(_hex(qual["policy_digest"]) == selection["policy_digest"])
            _require(qual["runtime_uid"] == uid and type(qual["runtime_uid"]) is int)
            _require(
                type(qual["credential_uid"]) is int
                and qual["credential_uid"] in (0, uid)
            )
            _require(qual["api_version"] == _API_VERSION)
            repositories = _closed(selection["repositories"], "cp starter")
            for key in _REPOSITORIES:
                _repo(repositories[key], key)
            _require(qual["repositories"] == repositories)
            _require(
                qual["permissions"]
                == {
                    "metadata": "read",
                    "actions": "read",
                    "contents": "read",
                    "pull_requests": "read",
                }
            )
            _require(qual["native_receipt_pin"] == binding["native_receipt_pin"])
            receipt = _closed(
                _json(pin(binding["native_receipt_pin"])),
                "schema qualification_measurements_digest runtime_identity_digest "
                "reviewer_record_digest",
            )
            _require(receipt["schema"] == "Gate0ENativeReviewReceipt.v1")
            for key in (
                "qualification_measurements_digest",
                "runtime_identity_digest",
                "reviewer_record_digest",
            ):
                _hex(receipt[key])
            pin(qual["decision_provenance_pin"])
            decisions = _closed(
                selection["decisions"], "a7 a6 rulings source_completion"
            )
            for key, pr in (("a7", 197), ("a6", 199)):
                decision = _closed(
                    decisions[key],
                    "repository pr revision path blob_sha sha256 retained_pin",
                )
                _require(decision["repository"] == "cp" and decision["pr"] == pr)
                _require(decision["path"] == _ADR)
                cls._source_selection(decision, pin)
            for key, (slug, version) in _DECISIONS.items():
                decision = _closed(decisions[key], "system slug version retained_pin")
                _require(decision["system"] == "dotmac_knowledge")
                _require(
                    decision["slug"] == slug
                    and type(decision["version"]) is int
                    and decision["version"] == version
                )
                envelope = _obj(_json(pin(decision["retained_pin"])))
                _require(
                    envelope.get("slug") == slug
                    and type(envelope.get("version")) is int
                    and envelope["version"] == version
                )
            packets = _list(selection["packets"], 4, 16)
            seen: set[str] = set()
            for value in packets:
                packet = _closed(
                    value, "id repository pr merge_sha pr_head_sha sources runs"
                )
                key = packet["id"]
                _require(type(key) is str and key not in seen)
                seen.add(key)
                fixed = {
                    "b": ("cp", 200),
                    "c1_foundation": ("starter", 753),
                    "c1_cp": ("cp", 201),
                    "c1_dependencies": ("cp", 204),
                }
                _require(
                    (packet["repository"], packet["pr"]) == fixed.get(key)
                    or (
                        re.fullmatch(r"c2_[0-9]+", key) is not None
                        and packet["repository"] == "cp"
                        and key == "c2_" + str(packet["pr"])
                        and packet["pr"] in _CP_PRS
                    )
                )
                _id(packet["pr"])
                _hex(packet["merge_sha"], 40)
                _hex(packet["pr_head_sha"], 40)
                for source in _list(packet["sources"], 1, 16):
                    _closed(source, "revision path blob_sha sha256 retained_pin")
                    _require(
                        source["revision"]
                        in (packet["merge_sha"], packet["pr_head_sha"])
                    )
                    cls._source_selection(source, pin)
                run_ids: set[int] = set()
                for run in _list(packet["runs"], 1, 4):
                    _closed(
                        run,
                        "run_id attempt workflow_id workflow_path event tested_sha "
                        "required_jobs",
                    )
                    for name in ("run_id", "attempt", "workflow_id"):
                        _id(run[name])
                    _require(run["run_id"] not in run_ids)
                    run_ids.add(run["run_id"])
                    _require(
                        _path(run["workflow_path"]).startswith(".github/workflows/")
                    )
                    _text(run["event"], 100)
                    _require(run["tested_sha"] == packet["pr_head_sha"])
                    ids: set[int] = set()
                    for job in _list(run["required_jobs"], 1, 32):
                        _closed(job, "id name")
                        _id(job["id"])
                        _text(job["name"], 512)
                        _require(job["id"] not in ids)
                        ids.add(job["id"])
            _require({"b", "c1_foundation", "c1_cp", "c1_dependencies"} <= seen)
            return cls(_SEAL, selection, qual, raw, qual_raw, retained)
        except Exception:
            raise HistoricalReferencesRefused() from None

    @staticmethod
    def _source_selection(source: dict[str, Any], pin: Any) -> None:
        _hex(source["revision"], 40)
        _hex(source["blob_sha"], 40)
        _path(source["path"])
        raw = pin(source["retained_pin"])
        _require(_digest(raw) == _hex(source["sha256"]))
        _require(
            hashlib.sha1(  # noqa: S324 -- Git object identity
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest()
            == source["blob_sha"]
        )  # noqa: S324 -- Git object identity

    def owns_facts(self, facts: object) -> bool:
        return not self._failed and any(facts is item for item in self._issued)

    def _project(self, path: str, value: object) -> dict[str, Any]:
        """Discard raw API data; recursively retain only required join fields.

        These validated metadata projections are authenticated transport evidence,
        not byte-for-byte API transcripts. In particular no API URL is retained.
        """
        value = _obj(value)

        def identity(item: object) -> dict[str, Any]:
            item = _obj(item)
            return {
                "id": _id(item.get("id")),
                "owner": {"id": _id(_obj(item.get("owner")).get("id"))},
                "full_name": _text(item.get("full_name")),
            }

        if "/contents/" in path:
            content = value.get("content")
            _require(type(content) is str and len(content) <= 750000)
            decoded = base64.b64decode(content.replace("\n", ""), validate=True)
            _require(len(decoded) <= _CAP)
            size = value.get("size")
            _require(type(size) is int and size >= 0)
            truncated = value.get("truncated", False)
            _require(type(truncated) is bool)
            return {
                "type": _text(value.get("type")),
                "path": _path(value.get("path")),
                "sha": _hex(value.get("sha"), 40),
                "encoding": _text(value.get("encoding")),
                "content": base64.b64encode(decoded).decode("ascii"),
                "size": size,
                "truncated": truncated,
            }
        if "/pulls/" in path:
            merged = value.get("merged")
            _require(type(merged) is bool)
            _instant(value.get("merged_at"))
            head = _obj(value.get("head"))
            return {
                "number": _id(value.get("number")),
                "merged": merged,
                "merged_at": value["merged_at"],
                "merge_commit_sha": _hex(value.get("merge_commit_sha"), 40),
                "base": {"repo": identity(_obj(value.get("base")).get("repo"))},
                "head": {
                    "sha": _hex(head.get("sha"), 40),
                    "repo": identity(head.get("repo")),
                },
            }
        if "/actions/runs/" in path:
            if "/jobs?" not in path:
                return {
                    "id": _id(value.get("id")),
                    "workflow_id": _id(value.get("workflow_id")),
                    "run_attempt": _id(value.get("run_attempt")),
                    "event": _text(value.get("event"), 100),
                    "path": _path(value.get("path")),
                    "head_sha": _hex(value.get("head_sha"), 40),
                    "status": _text(value.get("status")),
                    "conclusion": _text(value.get("conclusion")),
                    "repository": identity(value.get("repository")),
                    "head_repository": identity(value.get("head_repository")),
                }
            count = value.get("total_count")
            _require(type(count) is int and 0 <= count <= 400)
            required_ids = {
                job["id"]
                for packet in self._installation["packets"]
                for run in packet["runs"]
                if path.startswith(
                    "/repos/"
                    + self._installation["repositories"][packet["repository"]]["owner"]
                    + "/"
                    + self._installation["repositories"][packet["repository"]]["name"]
                    + "/actions/runs/"
                    + str(run["run_id"])
                    + "/attempts/"
                    + str(run["attempt"])
                    + "/jobs?"
                )
                for job in run["required_jobs"]
            }
            jobs = []
            for item in _list(value.get("jobs"), 0, 100):
                item = _obj(item)
                identifier = _id(item.get("id"))
                job = {"id": identifier, "run_id": _id(item.get("run_id"))}
                if "run_attempt" in item:
                    job["run_attempt"] = _id(item["run_attempt"])
                if identifier in required_ids:
                    job.update(
                        {
                            "name": _text(item.get("name")),
                            "status": _text(item.get("status")),
                            "conclusion": _text(item.get("conclusion")),
                        }
                    )
                jobs.append(job)
            return {"total_count": count, "jobs": jobs}
        return identity(value)

    def _get(self, path: str, page: int = 0) -> tuple[dict[str, Any], int, int]:
        _require(time.monotonic() < self._deadline)
        if path in self._cache:
            return self._cache[path]
        _require(len(self._responses) < 256)
        token = _protected(_CREDENTIAL, 16384, self._qualification["credential_uid"])
        try:
            _require(all(32 < byte < 127 for byte in token))
            status, following, last, raw = _spawn_get(
                path, token, False, _CAP, (), self._deadline, page
            )
        finally:
            token = b""
        _require(
            status == 200 and len(raw) <= _CAP and time.monotonic() < self._deadline
        )
        # The shared transport applies _pagination to raw Link headers in its child.
        _require(0 <= following <= 4 and 0 <= last <= 4)
        if page:
            _require(following in (0, page + 1) and (last == 0 or last >= page))
        else:
            _require(following == last == 0)
        self._bytes += len(raw)
        _require(self._bytes <= 16 * _CAP)
        projection_failed = False
        value: dict[str, Any] = {}
        try:
            value = self._project(path, _json(raw))
        except Exception:
            projection_failed = True
        finally:
            raw = b""
        # Raise after leaving the handler, so the original parser/projection
        # traceback (and its unassigned API data) is not exception context.
        if projection_failed:
            raise HistoricalReferencesRefused()
        self._responses.append((path, _canonical(value)))
        result = value, following, last
        self._cache[path] = result
        return result

    def _identity(self, value: object, repo: dict[str, Any]) -> None:
        returned = _obj(value)
        owner = _obj(returned.get("owner"))
        _require(
            type(returned.get("id")) is int and returned["id"] == repo["repository_id"]
        )
        _require(type(owner.get("id")) is int and owner["id"] == repo["owner_id"])
        _require(returned.get("full_name") == repo["owner"] + "/" + repo["name"])

    def _pr(
        self, root: str, repo: dict[str, Any], pr: int, merge: str, head: str | None
    ) -> None:
        value, _, _ = self._get(root + "/pulls/" + str(pr))
        _require(type(value.get("number")) is int and value["number"] == pr)
        _require(
            value.get("merged") is True
            and type(value.get("merged_at")) is str
            and bool(value["merged_at"])
        )
        _require(value.get("merge_commit_sha") == merge)
        self._identity(_obj(value.get("base")).get("repo"), repo)
        source_head = _obj(value.get("head"))
        self._identity(source_head.get("repo"), repo)
        _hex(source_head.get("sha"), 40)
        _require(head is None or source_head["sha"] == head)

    def _source(self, root: str, source: dict[str, Any]) -> None:
        value, _, _ = self._get(
            root
            + "/contents/"
            + quote(source["path"], safe="/")
            + "?ref="
            + source["revision"]
        )
        _require(
            value.get("type") == "file"
            and value.get("path") == source["path"]
            and value.get("encoding") == "base64"
        )
        _require(
            value.get("sha") == source["blob_sha"]
            and value.get("truncated", False) is False
        )
        content = value.get("content")
        _require(type(content) is str and len(content) <= 750000)
        decoded = base64.b64decode(content.replace("\n", ""), validate=True)
        retained = self._retained[source["retained_pin"]["path"]]
        _require(
            type(value.get("size")) is int and value["size"] == len(decoded) <= _CAP
        )
        _require(decoded == retained and _digest(decoded) == source["sha256"])
        _require(
            hashlib.sha1(  # noqa: S324 -- Git object identity
                b"blob " + str(len(decoded)).encode() + b"\0" + decoded
            ).hexdigest()
            == source["blob_sha"]
        )  # noqa: S324 -- Git object identity

    def _run(self, root: str, repo: dict[str, Any], run: dict[str, Any]) -> None:
        path = (
            root
            + "/actions/runs/"
            + str(run["run_id"])
            + "/attempts/"
            + str(run["attempt"])
        )
        value, _, _ = self._get(path)
        for actual, selected in (
            ("id", "run_id"),
            ("workflow_id", "workflow_id"),
            ("run_attempt", "attempt"),
        ):
            _require(type(value.get(actual)) is int and value[actual] == run[selected])
        for actual, selected in (
            ("event", "event"),
            ("path", "workflow_path"),
            ("head_sha", "tested_sha"),
        ):
            _require(value.get(actual) == run[selected])
        _require(
            value.get("status") == "completed" and value.get("conclusion") == "success"
        )
        self._identity(value.get("repository"), repo)
        self._identity(value.get("head_repository"), repo)
        jobs: dict[int, dict[str, Any]] = {}
        total: int | None = None
        final_page: int | None = None
        for page in range(1, 5):
            result, following, last = self._get(
                path + "/jobs?per_page=100&page=" + str(page), page
            )
            count = result.get("total_count")
            _require(type(count) is int and 0 <= count <= 400)
            _require(total is None or count == total)
            total = count
            _require(last == 0 or final_page is None or last == final_page)
            if last:
                final_page = last
            for job in _list(result.get("jobs"), 0, 100):
                job = _obj(job)
                identifier = _id(job.get("id"))
                _require(identifier not in jobs)
                _require(
                    type(job.get("run_id")) is int and job["run_id"] == run["run_id"]
                )
                # GitHub's job schema may omit run_attempt; the exact attempt URL
                # and mandatory run.run_attempt establish the attempt binding.
                if "run_attempt" in job:
                    _require(
                        type(job["run_attempt"]) is int
                        and job["run_attempt"] == run["attempt"]
                    )
                jobs[identifier] = job
            if not following:
                _require(last in (0, page) and final_page in (None, page))
                break
            _require(page < 4)
        _require(len(jobs) == total)
        for required in run["required_jobs"]:
            job = jobs.get(required["id"])
            _require(
                job is not None
                and job.get("name") == required["name"]
                and job.get("status") == "completed"
                and job.get("conclusion") == "success"
            )

    def verify(self, *, deadline: float) -> HistoricalSourceFacts:
        try:
            now = time.monotonic()
            _require(not self._used and not self._failed)
            self._used = True
            _require(
                type(deadline) in (int, float)
                and math.isfinite(deadline)
                and deadline > now
            )
            self._deadline = min(deadline, now + 180)
            repos = self._installation["repositories"]
            roots = {
                k: "/repos/" + v["owner"] + "/" + v["name"] for k, v in repos.items()
            }
            for key, repo in repos.items():
                value, _, _ = self._get(roots[key])
                self._identity(value, repo)
            decisions = self._installation["decisions"]
            for key in ("a7", "a6"):
                decision = decisions[key]
                self._pr(
                    roots["cp"], repos["cp"], decision["pr"], decision["revision"], None
                )
                self._source(roots["cp"], decision)
            for packet in self._installation["packets"]:
                key = packet["repository"]
                root, repo = roots[key], repos[key]
                self._pr(
                    root, repo, packet["pr"], packet["merge_sha"], packet["pr_head_sha"]
                )
                for source in packet["sources"]:
                    self._source(root, source)
                for run in packet["runs"]:
                    self._run(root, repo, run)
            records = tuple(
                (
                    key,
                    self._retained[value["retained_pin"]["path"]],
                    value["retained_pin"]["sha256"],
                )
                for key, value in decisions.items()
            )
            reference = _canonical(
                {
                    "schema": "Gate0EHistoricalSourceReferences.v1",
                    "selection": self._installation,
                    "qualification": self._qualification,
                    "retained": [
                        {
                            "path": path,
                            "sha256": _digest(raw),
                            "bytes_base64": base64.b64encode(raw).decode(),
                        }
                        for path, raw in sorted(self._retained.items())
                    ],
                    "observations": [
                        {
                            "path": path,
                            "projection_sha256": _digest(raw),
                            "projection_bytes_base64": base64.b64encode(raw).decode(),
                            "next_page": self._cache[path][1],
                            "last_page": self._cache[path][2],
                        }
                        for path, raw in self._responses
                    ],
                }
            )
            _require(len(reference) <= 16 * _CAP and time.monotonic() < self._deadline)
            facts = HistoricalSourceFacts(
                _SEAL,
                reference,
                _digest(self._installation_raw),
                _digest(self._qualification_raw),
                self._installation["policy_digest"],
                tuple(raw for _, raw in self._responses),
                records,
            )
            self._issued.append(facts)
            return facts
        except Exception:
            self._failed = True
            self._issued.clear()
            self._cache.clear()
            self._responses.clear()
        # No private transport/parser exception survives as chained context.
        raise HistoricalReferencesRefused()
