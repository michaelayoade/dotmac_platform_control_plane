"""Finite first-create publication owner; results are never E acceptance.

Native qualification, genuine B-review adoption and actual workflow review are
external evidence. No installation values or action-time observations are made
up here. A failed attempt is consumed and can only reconcile by bounded reads.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NoReturn, cast

from vendor_cp.deployment import gate0_e_github as github
from vendor_cp.deployment import gate0_e_writer as writer_owner

_INSTALLATION = "/run/dotmac-gate0-e/publication.json"
_BINDING = "/etc/dotmac-gate0-e/publication-binding.json"
_CREDENTIAL = "/run/dotmac-gate0-e/github-publication-token"
_REPOSITORY = "dotmac-tech/gate0-issuer-execution"
_NAMES = ("gate0-evidence.pgp", "gate0-evidence-public.json")
_RECEIPT = "gate0-readiness-receipt.json"
_METHOD_SCOPE = "gate0-e-first-create-upload-publish-reconcile.v1"
_SEAL = object()


class EPublicationRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("E_PUBLICATION_REFUSED")


class EPublicationIncomplete(ValueError):
    def __init__(self) -> None:
        super().__init__("PUBLICATION_INCOMPLETE")


@dataclass(frozen=True, slots=True)
class _PublicationFailure:
    control: writer_owner._PrivateFailure
    incomplete: bool = False


def _failure(error: BaseException, incomplete: bool = False) -> _PublicationFailure:
    # Reuse the existing owner of recursive frame/chain/group detachment and
    # bounded control categories; no transport/proof object enters this outcome.
    return _PublicationFailure(writer_owner._private_failure(error), incomplete)


def _raise_failure(failure: _PublicationFailure) -> NoReturn:
    if failure.control.category != "refused":
        writer_owner._raise_private_failure(failure.control)
    if failure.incomplete:
        raise EPublicationIncomplete()
    raise EPublicationRefused()


def _response_failure(error: BaseException) -> None:
    # Ordinary ambiguous replies reconcile. Control exceptions stop the attempt.
    outcome = _failure(error)
    if outcome.control.category != "refused":
        _raise_failure(outcome)


def _require(value: bool) -> None:
    if not value:
        raise EPublicationRefused()


def _document(raw: bytes, fields: str) -> dict[str, Any]:
    value = github._closed(github._json(raw), fields)
    _require(github._canonical(value) == raw)
    return value


def _pin(value: object, expected_path: str) -> tuple[dict[str, Any], bytes]:
    pin = github._closed(value, "path sha256")
    path = pin["path"]
    _require(type(path) is str and path == expected_path)
    raw = github._protected(path, github._JSON_CAP, private=False)
    _require(github._digest(raw) == github._hex(pin["sha256"]))
    value = github._obj(github._json(raw))
    _require(github._canonical(value) == raw)
    return value, raw


@dataclass(frozen=True, slots=True)
class PreparedEDraft:
    repository_id: int
    release_id: int
    tag: str
    target_commit: str
    assets: tuple[github.ReleaseAssetFact, ...] = field(repr=False)
    result: str = "DRAFT_PREPARED"


@dataclass(frozen=True, slots=True)
class PublishedEAttempt:
    """Observed mutation completion; independent writer readback is still owed."""

    repository_id: int
    release_id: int
    tag: str
    raw_tag_sha: str
    peeled_commit: str
    assets: tuple[github.ReleaseAssetFact, ...] = field(repr=False)
    result: str = "PUBLICATION_OBSERVED"


class InstalledEPublication:
    """Concrete installed owner. No URL/client/factory/callback injection."""

    __slots__ = (
        "_document",
        "_qualification",
        "_used",
        "_deadline",
        "_exchanges",
        "_bytes",
        "_mutation_started",
        "_started_at",
    )

    def __init__(
        self, seal: object, document: dict[str, Any], qualification: dict[str, Any]
    ) -> None:
        _require(seal is _SEAL)
        self._document, self._qualification = document, qualification
        self._used = False
        self._deadline = 0.0
        self._exchanges = self._bytes = 0
        self._mutation_started = False
        self._started_at = datetime.now(UTC)

    @classmethod
    def from_installed(cls) -> InstalledEPublication:
        result = cls._load_checked()
        del cls
        if isinstance(result, _PublicationFailure):
            _raise_failure(result)
        return result

    @classmethod
    def _load_checked(cls) -> InstalledEPublication | _PublicationFailure:
        try:
            return cls._load()
        except BaseException as error:
            return _failure(error)
        finally:
            del cls

    @classmethod
    def _load(cls) -> InstalledEPublication:
        raw = github._protected(_INSTALLATION, github._JSON_CAP, private=False)
        doc = _document(
            raw,
            "schema operation policy_digest repository release producer "
            "transfer_selection_digest draft_selection_digest "
            "publication_selection_digest "
            "summary_digest credential qualification download_origins",
        )
        _require(doc["schema"] == "Gate0EPublicationInstallation.v1")
        _require(doc["operation"] in ("prepare_draft", "publish"))
        for name in (
            "policy_digest",
            "transfer_selection_digest",
            "draft_selection_digest",
            "publication_selection_digest",
            "summary_digest",
        ):
            github._hex(doc[name])
        repository = github._repository(doc["repository"])
        _require(repository.owner + "/" + repository.name == _REPOSITORY)
        release = github._closed(
            doc["release"], "id tag target_commit title body author_id"
        )
        _require((release["id"] is None) == (doc["operation"] == "prepare_draft"))
        if release["id"] is not None:
            github._id(release["id"])
        _require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release["tag"])
            is not None
        )
        github._hex(release["target_commit"], 40)
        github._text(release["title"], 256)
        github._text(release["body"], 8192)
        github._id(release["author_id"])
        producer = github._closed(
            doc["producer"],
            "run_id attempt workflow_id job_id head_sha workflow_digest "
            "source_policy_digest",
        )
        for name in ("run_id", "workflow_id", "job_id"):
            github._id(producer[name])
        _require(type(producer["attempt"]) is int and producer["attempt"] == 1)
        _require(github._hex(producer["head_sha"], 40) == release["target_commit"])
        github._hex(producer["workflow_digest"])
        github._hex(producer["source_policy_digest"])
        binding = _document(
            github._protected(_BINDING, 65536, private=False),
            "schema installation_sha256 qualification_sha256 runtime_uid owners "
            "native_receipt",
        )
        _require(binding["schema"] == "Gate0EPublicationBinding.v1")
        _require(github._hex(binding["installation_sha256"]) == github._digest(raw))
        _require(
            type(binding["runtime_uid"]) is int
            and os.getuid() == os.geteuid() == binding["runtime_uid"]
        )
        owners = {
            "publication": __file__,
            "github": github.__file__,
            "writer": writer_owner.__file__,
        }
        _require(
            type(binding["owners"]) is dict and set(binding["owners"]) == set(owners)
        )
        for name, path in owners.items():
            _require(
                binding["owners"][name]
                == github._digest(
                    github._protected(
                        os.path.abspath(path), github._JSON_CAP, private=False
                    )
                )
            )
        qual, qual_raw = _pin(
            doc["qualification"], "/etc/dotmac-gate0-e/publication-qualification.json"
        )
        qual = github._closed(
            qual,
            "schema selection_digest policy_digest runtime_uid credential_uid "
            "permissions method_scope owners native_receipt immutable_setting "
            "action_time",
        )
        _require(qual["schema"] == "Gate0EPublicationNativeQualification.v1")
        _require(
            github._digest(qual_raw) == github._hex(binding["qualification_sha256"])
        )
        selection = {key: value for key, value in doc.items() if key != "qualification"}
        _require(
            qual["selection_digest"] == github._digest(github._canonical(selection))
        )
        _require(
            qual["policy_digest"] == doc["policy_digest"]
            and type(qual["runtime_uid"]) is int
            and qual["runtime_uid"] == binding["runtime_uid"]
        )
        _require(
            qual["method_scope"] == _METHOD_SCOPE
            and qual["owners"] == binding["owners"]
        )
        _require(qual["native_receipt"] == binding["native_receipt"])
        native, _ = _pin(
            binding["native_receipt"], "/etc/dotmac-gate0-e/publication-native.json"
        )
        native = github._closed(
            native,
            "schema method_scope owner_digests qualification_measurements_digest "
            "runtime_identity_digest reviewer_record_digest",
        )
        _require(
            native["schema"] == "Gate0EPublicationNativeReview.v1"
            and native["method_scope"] == _METHOD_SCOPE
        )
        _require(native["owner_digests"] == binding["owners"])
        for key in (
            "qualification_measurements_digest",
            "runtime_identity_digest",
            "reviewer_record_digest",
        ):
            github._hex(native[key])
        _require(
            github._canonical(qual["permissions"])
            == github._canonical(
                {
                    "contents": "write",
                    "metadata": "read",
                    "repository_id": repository.repository_id,
                }
            )
        )
        _require(
            type(qual["credential_uid"]) is int
            and qual["credential_uid"] in (0, binding["runtime_uid"])
        )
        _require(doc["credential"] == _CREDENTIAL)
        setting = github._closed(
            qual["immutable_setting"],
            "repository_id state response_sha256 native_record_digest observed_at",
        )
        _require(
            github._id(setting["repository_id"]) == repository.repository_id
            and setting["state"] == "enabled"
        )
        github._hex(setting["response_sha256"])
        github._hex(setting["native_record_digest"])
        github._instant(setting["observed_at"])
        action = github._closed(
            qual["action_time"],
            "selection_digest native_record_digest qualified_at valid_until "
            "repository_id operation target_commit method_scope source_policy_digest "
            "credential_identity_digest exclusive_writer_record_digest",
        )
        _require(action["selection_digest"] == qual["selection_digest"])
        _require(
            github._id(action["repository_id"]) == repository.repository_id
            and action["operation"] == doc["operation"]
            and action["target_commit"] == release["target_commit"]
            and action["method_scope"] == _METHOD_SCOPE
            and action["source_policy_digest"] == producer["source_policy_digest"]
        )
        github._hex(action["credential_identity_digest"])
        github._hex(action["exclusive_writer_record_digest"])
        github._hex(action["native_record_digest"])
        _require(
            github._instant(action["qualified_at"])
            <= github._instant(action["valid_until"])
        )
        origins = github._array(doc["download_origins"], 16)
        _require(bool(origins) and len(set(origins)) == len(origins))
        for host in origins:
            # Same qualified CDN host grammar as the read owner; never an upload URL.
            _require(
                type(host) is str
                and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host)
                is not None
            )
            _require(
                "." in host
                and ".." not in host
                and host not in ("api.github.com", "uploads.github.com")
            )
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            raise EPublicationRefused()
        return cls(_SEAL, doc, qual)

    def _discard_private_state(self) -> None:
        """Detach this owner's inputs without modifying caller-owned copies."""
        self._document = {}
        self._qualification = {}
        self._used = True

    def _begin(self, operation: str) -> None:
        _require(not self._used)
        self._used = True
        _require(self._document["operation"] == operation)
        self._started_at = datetime.now(UTC)
        self._deadline = time.monotonic() + 180
        action = self._qualification["action_time"]
        _require(
            github._instant(action["qualified_at"])
            <= self._started_at
            < github._instant(action["valid_until"])
        )
        _require(
            (github._instant(action["valid_until"]) - self._started_at).total_seconds()
            >= 180
        )
        _require(
            github._instant(self._qualification["immutable_setting"]["observed_at"])
            <= self._started_at
        )

    def _exchange(
        self,
        operation: str,
        identifier: int | str | None = None,
        payload: bytes = b"",
        *,
        page: int = 0,
        maximum: int = github._JSON_CAP,
    ) -> tuple[int, int, int, bytes]:
        token = b""
        raw = b""
        result = None
        failure = None
        try:
            _require(time.monotonic() < self._deadline and self._exchanges < 64)
            self._exchanges += 2 if operation == "asset_bytes" else 1
            _require(self._exchanges <= 64)
            # Reserve original response capacity even if a child/reply fails.
            self._bytes += len(payload) + maximum
            _require(self._bytes <= 128 * 1024 * 1024)
            token = github._protected(
                _CREDENTIAL, 16384, self._qualification["credential_uid"]
            )
            _require(all(32 < byte < 127 for byte in token))
            status, next_page, last_page, raw = github._publication_exchange(
                operation,
                identifier,
                token,
                payload,
                maximum,
                tuple(self._document["download_origins"]),
                self._deadline,
                page,
            )
            self._bytes -= maximum - len(raw)
            _require(self._bytes <= 128 * 1024 * 1024)
            result = status, next_page, last_page, raw
        except BaseException as error:
            failure = _failure(error)
        finally:
            token = raw = b""
        if failure is not None:
            _raise_failure(failure)
        if result is None:
            raise EPublicationRefused()
        return result

    def _read(self, operation: str, identifier: int | str | None = None) -> object:
        status, next_page, last_page, raw = self._exchange(operation, identifier)
        _require(status == 200 and next_page == last_page == 0)
        return github._json(raw)

    def _release(
        self, value: object, *, published: bool, release_id: int | None = None
    ) -> dict[str, Any]:
        item, pin = github._obj(value), self._document["release"]
        result = {
            key: item[key]
            for key in (
                "id",
                "tag_name",
                "target_commitish",
                "name",
                "body",
                "draft",
                "immutable",
                "created_at",
                "published_at",
            )
        }
        result["author_id"] = github._id(github._obj(item["author"])["id"])
        github._id(result["id"])
        _require(release_id is None or result["id"] == release_id)
        _require(
            result["tag_name"] == pin["tag"]
            and result["target_commitish"] == pin["target_commit"]
        )
        _require(
            result["name"] == pin["title"]
            and result["body"] == pin["body"]
            and result["author_id"] == pin["author_id"]
        )
        _require(type(result["draft"]) is bool and result["draft"] is (not published))
        _require(type(result["immutable"]) is bool)
        _require(github._instant(result["created_at"]) <= datetime.now(UTC))
        if published:
            _require(result["immutable"] is True and result["published_at"] is not None)
            _require(
                github._instant(result["created_at"])
                <= github._instant(result["published_at"])
                <= datetime.now(UTC)
            )
        else:
            _require(result["immutable"] is False and result["published_at"] is None)
        return result

    def _pages(
        self, operation: str, identifier: int | None = None
    ) -> list[dict[str, Any]]:
        output = []
        for page in range(1, 5):
            status, following, last, raw = self._exchange(
                operation, identifier, page=page
            )
            _require(status == 200)
            items = github._array(github._json(raw), 100)
            # Closed projections discard all URL-bearing/unknown response fields.
            for item in items:
                item = github._obj(item)
                if operation == "releases":
                    output.append(
                        {
                            key: item[key]
                            for key in (
                                "id",
                                "tag_name",
                                "target_commitish",
                                "name",
                                "body",
                                "draft",
                                "immutable",
                                "created_at",
                                "published_at",
                            )
                        }
                        | {
                            "author": {
                                "id": github._id(github._obj(item["author"])["id"])
                            }
                        }
                    )
                else:
                    output.append(self._asset(item))
            _require(len({github._id(item["id"]) for item in output}) == len(output))
            if not following:
                _require(last in (0, page) and len(items) < 100)
                return output
            _require(following == page + 1 and last >= following and len(items) == 100)
        raise EPublicationRefused()

    def _identity(self) -> None:
        item, pin = github._obj(self._read("repository")), self._document["repository"]
        _require(
            github._id(item["id"]) == pin["repository_id"]
            and item["full_name"] == _REPOSITORY
        )
        _require(github._id(github._obj(item["owner"])["id"]) == pin["owner_id"])

    def _producer(self, value: github.ProducerFacts) -> None:
        pin, repository = self._document["producer"], self._document["repository"]
        _require(
            value.repository_id == repository["repository_id"]
            and value.owner_id == repository["owner_id"]
        )
        _require(
            value.run_id == pin["run_id"]
            and value.attempt == pin["attempt"]
            and value.workflow_id == pin["workflow_id"]
        )
        _require(
            value.head_sha == pin["head_sha"]
            and value.workflow_source.bytes_sha256 == pin["workflow_digest"]
        )
        _require(pin["source_policy_digest"] in value.policy_observation_digests)

    def _asset(self, value: object) -> dict[str, Any]:
        item = github._obj(value)
        result = {
            key: item[key]
            for key in ("id", "name", "state", "size", "digest", "content_type")
        }
        result["uploader_id"] = github._id(github._obj(item["uploader"])["id"])
        github._id(result["id"])
        _require(
            result["name"] in (*_NAMES, _RECEIPT) and result["state"] == "uploaded"
        )
        _require(
            type(result["size"]) is int
            and 0 < result["size"] <= github._asset_cap(result["name"])
        )
        _require(result["digest"] == "sha256:" + github._hex(result["digest"][7:]))
        _require(
            result["content_type"]
            == (
                "application/octet-stream"
                if result["name"] == _NAMES[0]
                else "application/json"
            )
        )
        _require(result["uploader_id"] == self._document["release"]["author_id"])
        return result

    def _inventory(
        self,
        release_id: int,
        expected: dict[str, bytes],
        ids: dict[str, int],
        *,
        published: bool = False,
    ) -> tuple[github.ReleaseAssetFact, ...]:
        before = self._release(
            self._read("release", release_id),
            published=published,
            release_id=release_id,
        )
        inventory = self._pages("assets", release_id)
        _require(
            len(inventory) == len(expected)
            and {item["name"] for item in inventory} == set(expected)
        )
        facts = []
        for item in inventory:
            name, raw = item["name"], expected[item["name"]]
            _require(name not in ids or ids[name] == item["id"])
            _require(item == self._asset(self._read("asset", item["id"])))
            _require(
                item["size"] == len(raw)
                and item["digest"] == "sha256:" + github._digest(raw)
            )
            status, following, last, downloaded = self._exchange(
                "asset_bytes", item["id"], maximum=github._asset_cap(name)
            )
            _require(status == 200 and following == last == 0 and downloaded == raw)
            _require(item == self._asset(self._read("asset", item["id"])))
            ids[name] = item["id"]
            facts.append(
                github.ReleaseAssetFact(
                    item["id"],
                    name,
                    "uploaded",
                    item["content_type"],
                    len(raw),
                    github._digest(raw),
                    item["uploader_id"],
                    raw,
                )
            )
        _require(
            self._release(
                self._read("release", release_id),
                published=published,
                release_id=release_id,
            )
            == before
        )
        after = self._pages("assets", release_id)
        _require(
            sorted(after, key=lambda a: a["id"])
            == sorted(inventory, key=lambda a: a["id"])
        )
        return tuple(sorted(facts, key=lambda a: a.name))

    def _mutate(
        self, operation: str, identifier: int | None, payload: bytes
    ) -> object | None:
        # Only this point performs one mutation. An uncertain response never retries.
        self._mutation_started = True
        value = None
        try:
            _, following, last, raw = self._exchange(operation, identifier, payload)
            _require(following == last == 0)
            value = github._json(raw)
        except BaseException as error:
            _response_failure(error)
        return value

    def _tag_absent(self) -> None:
        status, following, last, _ = self._exchange(
            "tag_absence", self._document["release"]["tag"]
        )
        _require(status == 404 and following == last == 0)

    def _create(self) -> int:
        pin = self._document["release"]
        for operation in ("tag_absence", "release_absence"):
            status, following, last, _ = self._exchange(operation, pin["tag"])
            _require(status == 404 and following == last == 0)
        _require(
            not any(item["tag_name"] == pin["tag"] for item in self._pages("releases"))
        )
        payload = github._canonical(
            dict(
                tag_name=pin["tag"],
                target_commitish=pin["target_commit"],
                name=pin["title"],
                body=pin["body"],
                draft=True,
                prerelease=False,
            )
        )
        response = self._mutate("create", None, payload)
        # Even a successful reply is checked against actual selected-tag inventory.
        matches = [
            item for item in self._pages("releases") if item["tag_name"] == pin["tag"]
        ]
        _require(len(matches) == 1)
        observed = self._release(matches[0], published=False)
        _require(
            github._instant(observed["created_at"])
            >= self._started_at.replace(microsecond=0)
        )
        if response is not None:
            checked = None
            try:
                checked = self._release(response, published=False)
            except BaseException as error:
                _response_failure(error)
            _require(checked is None or checked == observed)
        _require(not self._pages("assets", observed["id"]))
        self._tag_absent()
        return cast(int, observed["id"])

    def _upload(
        self,
        release_id: int,
        name: str,
        raw: bytes,
        expected: dict[str, bytes],
        ids: dict[str, int],
    ) -> tuple[github.ReleaseAssetFact, ...]:
        operation = dict(
            zip(
                (*_NAMES, _RECEIPT),
                ("upload_ciphertext", "upload_projection", "upload_receipt"),
                strict=True,
            )
        )[name]
        response = self._mutate(operation, release_id, raw)
        if response is not None:
            item = None
            try:
                item = self._asset(response)
            except BaseException as error:
                _response_failure(error)
            if item is not None:
                _require(item["name"] == name)
                ids[name] = item["id"]
        # Lost/error/invalid replies reconcile the exact inventory and bytes once.
        return self._inventory(release_id, expected, ids)

    def prepare_draft_once(
        self,
        transfer_reads: github.InstalledGate0GitHubReads,
        transfer: github.VerifiedProducerTransfer,
    ) -> PreparedEDraft:
        result = self._prepare_checked(transfer_reads, transfer)
        del self, transfer_reads, transfer
        if isinstance(result, _PublicationFailure):
            _raise_failure(result)
        return result

    def _prepare_checked(
        self,
        transfer_reads: github.InstalledGate0GitHubReads,
        transfer: github.VerifiedProducerTransfer,
    ) -> PreparedEDraft | _PublicationFailure:
        try:
            return self._prepare_work(transfer_reads, transfer)
        except BaseException as error:
            incomplete = self._mutation_started
            self._discard_private_state()
            return _failure(error, incomplete)
        finally:
            del self, transfer_reads, transfer

    def _prepare_work(
        self,
        transfer_reads: github.InstalledGate0GitHubReads,
        transfer: github.VerifiedProducerTransfer,
    ) -> PreparedEDraft:
        self._begin("prepare_draft")
        _require(
            type(transfer_reads) is github.InstalledGate0GitHubReads
            and type(transfer) is github.VerifiedProducerTransfer
        )
        _require(
            transfer_reads.owns_facts(transfer)
            and transfer_reads.installed_selection_digest
            == self._document["transfer_selection_digest"]
        )
        self._producer(transfer.producer)
        _require(
            transfer_reads.selected_job(transfer.producer).id
            == self._document["producer"]["job_id"]
        )
        _require(transfer.producer.stage == github.ProducerStage.PRODUCER_JOB_COMPLETE)
        _require(
            github._digest(transfer.ciphertext) == transfer.ciphertext_sha256
            and github._digest(transfer.projection) == transfer.projection_sha256
        )
        _require(
            github._obj(github._json(transfer.projection))["policy_digest"]
            == "sha256:" + self._document["policy_digest"]
        )
        self._identity()
        release_id = self._create()
        ids: dict[str, int] = {}
        expected: dict[str, bytes] = {}
        assets: tuple[github.ReleaseAssetFact, ...] = ()
        for name, raw in zip(
            _NAMES, (transfer.ciphertext, transfer.projection), strict=True
        ):
            expected[name] = raw
            assets = self._upload(release_id, name, raw, expected, ids)
        _require(time.monotonic() < self._deadline)
        self._tag_absent()
        result = PreparedEDraft(
            self._document["repository"]["repository_id"],
            release_id,
            self._document["release"]["tag"],
            transfer.producer.head_sha,
            assets,
        )
        return result

    def publish_once(
        self,
        writer: writer_owner.InstalledEWriter,
        draft_reads: github.InstalledGate0GitHubReads,
        draft: github.DraftReleaseFacts,
        publication_reads: github.InstalledGate0GitHubReads,
        publication: github.PublicationFacts,
        summary: bytes,
    ) -> PublishedEAttempt:
        result = self._publish_checked(
            writer, draft_reads, draft, publication_reads, publication, summary
        )
        del self, writer, draft_reads, draft, publication_reads, publication, summary
        if isinstance(result, _PublicationFailure):
            _raise_failure(result)
        return result

    def _publish_checked(
        self,
        writer: writer_owner.InstalledEWriter,
        draft_reads: github.InstalledGate0GitHubReads,
        draft: github.DraftReleaseFacts,
        publication_reads: github.InstalledGate0GitHubReads,
        publication: github.PublicationFacts,
        summary: bytes,
    ) -> PublishedEAttempt | _PublicationFailure:
        try:
            return self._publish_work(
                writer, draft_reads, draft, publication_reads, publication, summary
            )
        except BaseException as error:
            incomplete = self._mutation_started
            self._discard_private_state()
            return _failure(error, incomplete)
        finally:
            del (
                self,
                writer,
                draft_reads,
                draft,
                publication_reads,
                publication,
                summary,
            )

    def _publish_work(
        self,
        writer: writer_owner.InstalledEWriter,
        draft_reads: github.InstalledGate0GitHubReads,
        draft: github.DraftReleaseFacts,
        publication_reads: github.InstalledGate0GitHubReads,
        publication: github.PublicationFacts,
        summary: bytes,
    ) -> PublishedEAttempt:
        self._begin("publish")
        _require(type(writer) is writer_owner.InstalledEWriter)
        _require(
            type(draft_reads) is github.InstalledGate0GitHubReads
            and type(draft) is github.DraftReleaseFacts
            and draft_reads.owns_facts(draft)
        )
        _require(
            type(publication_reads) is github.InstalledGate0GitHubReads
            and type(publication) is github.PublicationFacts
            and publication_reads.owns_facts(publication)
        )
        _require(
            draft_reads.installed_selection_digest
            == self._document["draft_selection_digest"]
        )
        _require(
            publication_reads.installed_selection_digest
            == self._document["publication_selection_digest"]
        )
        _require(type(summary) is bytes and len(summary) <= github._JSON_CAP)
        _require(
            github._digest(summary)
            == self._document["summary_digest"]
            == publication.selected_summary_digest
        )
        self._producer_from_draft(draft)
        # Sole writer authenticates genuine adoption, qualified proofs and review
        # BEFORE any publication mutation. Caller JSON is never a receipt.
        workflow_digest = writer.selection.source.workflow_digest
        receipt = writer.construct_receipt(
            draft_reads, draft, publication_reads, publication
        )
        receipt_doc = github._obj(github._json(receipt))
        _require(
            receipt_doc["policy_digest"] == "sha256:" + self._document["policy_digest"]
        )
        _require(receipt_doc["b_summary_digest"] == "sha256:" + github._digest(summary))
        for name, source in (
            ("run_id", "run_id"),
            ("attempt", "attempt"),
            ("workflow_id", "workflow_id"),
            ("source_revision", "head_sha"),
        ):
            _require(
                receipt_doc["producer"][name] == self._document["producer"][source]
            )
        _require(
            receipt_doc["producer"]
            == dict(
                repository_id=self._document["repository"]["repository_id"],
                owner_id=self._document["repository"]["owner_id"],
                run_id=self._document["producer"]["run_id"],
                attempt=1,
                workflow_id=self._document["producer"]["workflow_id"],
                job_id=self._document["producer"]["job_id"],
                source_revision=self._document["producer"]["head_sha"],
            )
        )
        _require(
            workflow_digest == "sha256:" + self._document["producer"]["workflow_digest"]
        )
        self._identity()
        self._tag_absent()
        expected = {asset.name: asset.raw_bytes for asset in draft.assets}
        ids = {asset.name: asset.id for asset in draft.assets}
        _require(set(expected) == set(_NAMES) and len(draft.assets) == 2)
        self._inventory(draft.release_id, expected, ids)
        expected[_RECEIPT] = receipt
        self._upload(draft.release_id, _RECEIPT, receipt, expected, ids)
        self._tag_absent()
        response = self._mutate("publish", draft.release_id, b'{"draft":false}')
        if response is not None:
            try:
                self._release(response, published=True, release_id=draft.release_id)
            except BaseException as error:
                _response_failure(error)
        assets = self._inventory(draft.release_id, expected, ids, published=True)
        raw_tag, peeled = self._tag()
        _require(time.monotonic() < self._deadline)
        result = PublishedEAttempt(
            draft.repository_id,
            draft.release_id,
            draft.tag,
            raw_tag,
            peeled,
            assets,
        )
        return result

    def _producer_from_draft(self, draft: github.DraftReleaseFacts) -> None:
        pin, repository = self._document["release"], self._document["repository"]
        _require(
            draft.repository_id == repository["repository_id"]
            and draft.owner_id == repository["owner_id"]
        )
        _require(
            draft.release_id == pin["id"]
            and draft.tag == pin["tag"]
            and draft.target_commitish == pin["target_commit"]
        )
        _require(draft.draft is True and draft.immutable is False)

    def _tag(self) -> tuple[str, str]:
        ref = github._obj(self._read("tag", self._document["release"]["tag"]))
        _require(ref["ref"] == "refs/tags/" + self._document["release"]["tag"])
        obj = github._obj(ref["object"])
        raw = github._hex(obj["sha"], 40)
        _require(obj["type"] in ("commit", "tag"))
        peeled = raw
        if obj["type"] == "tag":
            tag = github._obj(self._read("tag_object", raw))
            _require(github._hex(tag["sha"], 40) == raw)
            target = github._obj(tag["object"])
            _require(target["type"] == "commit")
            peeled = github._hex(target["sha"], 40)
        _require(peeled == self._document["release"]["target_commit"])
        return raw, peeled


def _run_prepare_work() -> None:
    publisher = None
    completed = False
    try:
        publisher = InstalledEPublication.from_installed()
        reads = github.InstalledGate0GitHubReads.from_installed()
        transfer = reads.encrypted_transfer()
        publisher.prepare_draft_once(reads, transfer)
        completed = True
    finally:
        if publisher is not None and not completed:
            publisher._discard_private_state()


def _run_publish_work() -> None:
    publisher = writer = None
    completed = False
    try:
        publisher = InstalledEPublication.from_installed()
        writer = writer_owner.InstalledEWriter.from_installed()
        draft_reads = github.InstalledGate0GitHubReads.from_installed_draft_release()
        draft = draft_reads.draft_snapshot()
        publication_reads = (
            github.InstalledGate0GitHubReads.from_installed_publication_start()
        )
        publication = publication_reads.publication_snapshot()
        summary = github._protected(
            "/run/dotmac-gate0-e/b-archive-verification.json", 65536, private=False
        )
        publisher.publish_once(
            writer, draft_reads, draft, publication_reads, publication, summary
        )
        completed = True
    finally:
        # These owners were loaded by this entry, never supplied by a caller.
        if writer is not None:
            writer._discard_private_state()
        if publisher is not None and not completed:
            publisher._discard_private_state()


def _run_prepare_checked() -> _PublicationFailure | None:
    try:
        _run_prepare_work()
    except BaseException as error:
        return _failure(error, isinstance(error, EPublicationIncomplete))
    return None


def _run_publish_checked() -> _PublicationFailure | None:
    try:
        _run_publish_work()
    except BaseException as error:
        return _failure(error, isinstance(error, EPublicationIncomplete))
    return None


def _entry_result(result: _PublicationFailure | None, success: str) -> int:
    if result is None:
        print(success)
        return 0
    if result.control.category != "refused":
        _raise_failure(result)
    print("PUBLICATION_INCOMPLETE" if result.incomplete else "E_PUBLICATION_REFUSED")
    return 3


def run_installed_prepare_e_draft() -> int:
    """Clean fixed entry boundary; no selected owner remains in control frames."""
    return _entry_result(_run_prepare_checked(), "DRAFT_PREPARED")


def run_installed_publish_e() -> int:
    """Clean fixed entry boundary; simultaneous independent qualified phases."""
    return _entry_result(_run_publish_checked(), "PUBLICATION_OBSERVED")
