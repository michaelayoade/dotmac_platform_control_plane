"""Production secret seeding and atomic host materialization.

This is an operator service, not a runtime settings source. It talks to the
canonical OpenBao KV v2 API only when an operator invokes it, keeps values in
memory, and transfers a validated host bundle over SSH stdin. It never prints
or places a secret in a subprocess argument.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from vendor_cp.product_release_pins import (
    ProductReleasePin,
    parse_product_release_pins,
    render_product_release_pins,
)

LICENCE_SIGNING_PATH = "secret/dotmac/licensing/signing-key"
DATABASE_PATH = "secret/dotmac/vendor-control-plane/production/database"
RUNTIME_PATH = "secret/dotmac/vendor-control-plane/production/runtime"
DEPLOY_SSH_PATH = "secret/dotmac/vendor-control-plane/production/deploy-ssh"

SECRET_FIELDS: Mapping[str, frozenset[str]] = {
    LICENCE_SIGNING_PATH: frozenset({"key_id", "private_key_b64url"}),
    DATABASE_PATH: frozenset(
        {"admin_password", "app_user_password", "platform_api_password"}
    ),
    RUNTIME_PATH: frozenset({"jwt_secret", "session_hash_secret", "csrf_secret"}),
    DEPLOY_SSH_PATH: frozenset(
        {"private_key_openssh", "public_key_openssh", "username"}
    ),
}

OWNED_ENV_DECLARATIONS = frozenset({"VENDOR_DEPLOYMENT_PROFILE"})
PRODUCT_RELEASE_PINS_DECLARATION = "VENDOR_PRODUCT_RELEASE_PINS_JSON"

ENV_SECRET_KEYS = frozenset(
    {
        "VENDOR_DB_ADMIN_PASSWORD",
        "VENDOR_DB_APP_USER_PASSWORD",
        "VENDOR_DB_PLATFORM_API_PASSWORD",
        "JWT_SECRET",
        "SESSION_HASH_SECRET",
        "CSRF_SECRET",
        "VENDOR_LICENCE_SIGNING_KEY_ID",
    }
)

#: `dotmac_kernel.config.validate_settings` refuses a production `CSRF_SECRET`
#: three ways: still the dev default, fewer than this many bytes, or equal to
#: `JWT_SECRET`/`SESSION_HASH_SECRET`. Each raises in the application lifespan,
#: so each must be refused where the record is validated instead.
CSRF_SECRET_MIN_BYTES = 32

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SSH_PUBLIC_KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?$")


class ProductionSecretError(RuntimeError):
    """The production secret contract could not be established safely."""


class SecretReader(Protocol):
    """Narrow read/create seam used by the operator service and its tests."""

    def read_optional(self, path: str) -> dict[str, str] | None: ...

    def create(self, path: str, fields: Mapping[str, str]) -> None: ...


class VersionedSecretStore(Protocol):
    """The KV-v2 operations needed by the incident rotation coordinator."""

    def read_versioned(
        self, path: str, *, version: int | None = None
    ) -> VersionedSecretRecord: ...

    def cas_update(
        self, path: str, fields: Mapping[str, str], *, expected_version: int
    ) -> int: ...


@dataclass(frozen=True, slots=True, repr=False)
class HostSecretBundle:
    """Only the values a production host is permitted to retain."""

    admin_password: str
    app_user_password: str
    platform_api_password: str
    jwt_secret: str
    session_hash_secret: str
    csrf_secret: str
    licence_key_id: str
    licence_private_key_b64url: str
    deploy_public_key_openssh: str

    def to_json(self) -> str:
        """Encode only for an SSH stdin pipe; callers must never print it."""
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> HostSecretBundle:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError("host secret bundle is not valid JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != set(cls.__annotations__):
            raise ProductionSecretError("host secret bundle has an unexpected schema")
        if not all(isinstance(value, str) for value in parsed.values()):
            raise ProductionSecretError("host secret bundle values must be strings")
        bundle = cls(**parsed)
        validate_host_bundle(bundle)
        return bundle


@dataclass(frozen=True, slots=True)
class MaterializedHostSecrets:
    """Non-secret receipt returned after atomic installation."""

    env_file: Path
    signing_key_file: Path
    authorized_keys_file: Path


@dataclass(frozen=True, slots=True, repr=False)
class VersionedSecretRecord:
    """One validated KV record; values are deliberately absent from repr."""

    path: str
    version: int
    fields: Mapping[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ProductionSecretError("OpenBao record version must be positive")
        validate_record(self.path, self.fields)


@dataclass(frozen=True, slots=True, repr=False)
class RotatingSecretSet:
    """The five rotated values plus the CSRF value that must not rotate."""

    admin_password: str = field(repr=False)
    app_user_password: str = field(repr=False)
    platform_api_password: str = field(repr=False)
    jwt_secret: str = field(repr=False)
    session_hash_secret: str = field(repr=False)
    csrf_secret: str = field(repr=False)

    @classmethod
    def from_records(
        cls,
        database: Mapping[str, str],
        runtime: Mapping[str, str],
    ) -> RotatingSecretSet:
        validate_record(DATABASE_PATH, database)
        validate_record(RUNTIME_PATH, runtime)
        return cls(
            admin_password=database["admin_password"],
            app_user_password=database["app_user_password"],
            platform_api_password=database["platform_api_password"],
            jwt_secret=runtime["jwt_secret"],
            session_hash_secret=runtime["session_hash_secret"],
            csrf_secret=runtime["csrf_secret"],
        )

    def database_record(self) -> dict[str, str]:
        return {
            "admin_password": self.admin_password,
            "app_user_password": self.app_user_password,
            "platform_api_password": self.platform_api_password,
        }

    def runtime_record(self) -> dict[str, str]:
        return {
            "jwt_secret": self.jwt_secret,
            "session_hash_secret": self.session_hash_secret,
            "csrf_secret": self.csrf_secret,
        }

    def to_object(self) -> dict[str, str]:
        return asdict(self)


class RotationPhase(StrEnum):
    PREPARED = "prepared"
    OPENBAO_DATABASE_WRITTEN = "openbao_database_written"
    OPENBAO_COMMITTED = "openbao_committed"
    PROVED = "proved"
    ROLLBACK_OPENBAO_DATABASE_WRITTEN = "rollback_openbao_database_written"
    ROLLBACK_OPENBAO_COMMITTED = "rollback_openbao_committed"
    ROLLED_BACK = "rolled_back"


ROTATED_FIELD_NAMES = (
    "admin_password",
    "app_user_password",
    "platform_api_password",
    "jwt_secret",
    "session_hash_secret",
)


@dataclass(frozen=True, slots=True)
class SecretRotationReceipt:
    """Names and coordinates only; this receipt can safely enter an audit log."""

    operation_id: str
    target_host_id: str
    phase: RotationPhase
    database_prior_version: int
    runtime_prior_version: int
    database_candidate_version: int | None = None
    runtime_candidate_version: int | None = None
    database_rollback_version: int | None = None
    runtime_rollback_version: int | None = None
    rotated_fields: tuple[str, ...] = ROTATED_FIELD_NAMES
    preserved_fields: tuple[str, ...] = ("csrf_secret",)
    image_reference: str | None = None
    source_revision: str | None = None

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{32}", self.operation_id) is None:
            raise ProductionSecretError("rotation operation id is invalid")
        if self.target_host_id != "vendor-cp-prod":
            raise ProductionSecretError("rotation target host id is invalid")
        if self.database_prior_version < 1 or self.runtime_prior_version < 1:
            raise ProductionSecretError("rotation prior versions must be positive")
        if self.rotated_fields != ROTATED_FIELD_NAMES:
            raise ProductionSecretError("rotation field inventory is invalid")
        if self.preserved_fields != ("csrf_secret",):
            raise ProductionSecretError("rotation preserved field inventory is invalid")
        for value in (
            self.database_candidate_version,
            self.runtime_candidate_version,
            self.database_rollback_version,
            self.runtime_rollback_version,
        ):
            if value is not None and value < 1:
                raise ProductionSecretError("rotation candidate version is invalid")
        if (
            self.image_reference is not None
            and re.fullmatch(
                r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", self.image_reference
            )
            is None
        ):
            raise ProductionSecretError("rotation image reference is not immutable")
        if (
            self.source_revision is not None
            and re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is None
        ):
            raise ProductionSecretError("rotation source revision is invalid")

    def to_json(self) -> str:
        document = asdict(self)
        document["schema"] = "platform-secret-rotation-receipt.v1"
        document["phase"] = self.phase.value
        return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_json(cls, raw: str) -> SecretRotationReceipt:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError("rotation receipt is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ProductionSecretError("rotation receipt is not an object")
        if parsed.pop("schema", None) != "platform-secret-rotation-receipt.v1":
            raise ProductionSecretError("rotation receipt schema is invalid")
        try:
            parsed["phase"] = RotationPhase(parsed["phase"])
            parsed["rotated_fields"] = tuple(parsed["rotated_fields"])
            parsed["preserved_fields"] = tuple(parsed["preserved_fields"])
            return cls(**parsed)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProductionSecretError("rotation receipt fields are invalid") from exc


@dataclass(frozen=True, slots=True, repr=False)
class SecretRotationCustody:
    """Crash-recovery material held only in a protected local file."""

    operation_id: str
    database_prior_version: int
    runtime_prior_version: int
    prior: RotatingSecretSet = field(repr=False)
    candidate: RotatingSecretSet = field(repr=False)

    def to_json(self) -> str:
        document = {
            "schema": "platform-secret-rotation-custody.v1",
            "operation_id": self.operation_id,
            "database_prior_version": self.database_prior_version,
            "runtime_prior_version": self.runtime_prior_version,
            "prior": self.prior.to_object(),
            "candidate": self.candidate.to_object(),
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> SecretRotationCustody:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError("rotation custody is not valid JSON") from exc
        if not isinstance(parsed, dict) or parsed.pop("schema", None) != (
            "platform-secret-rotation-custody.v1"
        ):
            raise ProductionSecretError("rotation custody schema is invalid")
        try:
            prior = RotatingSecretSet(**parsed.pop("prior"))
            candidate = RotatingSecretSet(**parsed.pop("candidate"))
            custody = cls(prior=prior, candidate=candidate, **parsed)
        except (KeyError, TypeError) as exc:
            raise ProductionSecretError("rotation custody fields are invalid") from exc
        _validate_rotation(custody.prior, custody.candidate)
        return custody


@dataclass(frozen=True, slots=True, repr=False)
class HostSecretRotationPayload:
    """Secret-bearing target input; it is serialized only onto SSH stdin."""

    operation_id: str
    expected_image_reference: str
    expected_source_revision: str
    expected_adapter_digest: str
    desired: RotatingSecretSet = field(repr=False)
    replaced: RotatingSecretSet = field(repr=False)

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema": "platform-secret-host-rotation.v1",
                "operation_id": self.operation_id,
                "expected_image_reference": self.expected_image_reference,
                "expected_source_revision": self.expected_source_revision,
                "expected_adapter_digest": self.expected_adapter_digest,
                "desired": self.desired.to_object(),
                "replaced": self.replaced.to_object(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str) -> HostSecretRotationPayload:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError(
                "host rotation payload is not valid JSON"
            ) from exc
        if not isinstance(parsed, dict) or parsed.pop("schema", None) != (
            "platform-secret-host-rotation.v1"
        ):
            raise ProductionSecretError("host rotation payload schema is invalid")
        try:
            desired = RotatingSecretSet(**parsed.pop("desired"))
            replaced = RotatingSecretSet(**parsed.pop("replaced"))
            payload = cls(desired=desired, replaced=replaced, **parsed)
        except (KeyError, TypeError) as exc:
            raise ProductionSecretError(
                "host rotation payload fields are invalid"
            ) from exc
        _validate_rotation(payload.replaced, payload.desired)
        if (
            re.fullmatch(
                r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}",
                payload.expected_image_reference,
            )
            is None
        ):
            raise ProductionSecretError("rotation expected image is not immutable")
        if re.fullmatch(r"[0-9a-f]{40}", payload.expected_source_revision) is None:
            raise ProductionSecretError("rotation expected revision is invalid")
        if payload.expected_adapter_digest != rotation_adapter_digest():
            raise ProductionSecretError("rotation adapter digest is invalid")
        return payload


@dataclass(frozen=True, slots=True)
class HostRotationProof:
    """Names-only proof returned by the target adapter."""

    operation_id: str
    target_host_id: str
    image_reference: str
    source_revision: str
    adapter_digest: str
    database_roles_rotated: tuple[str, ...] = (
        "app_admin",
        "app_user",
        "platform_api",
    )
    runtime_material_rotated: tuple[str, ...] = (
        "jwt_secret",
        "session_hash_secret",
    )
    preserved_material: tuple[str, ...] = ("csrf_secret",)
    readiness: str = "passed"
    prior_authentication: str = "refused"
    plan_rollout_state: str = "unchanged"

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{32}", self.operation_id) is None:
            raise ProductionSecretError("host rotation proof operation id is invalid")
        if self.target_host_id != ROTATION_HOST_ID:
            raise ProductionSecretError("host rotation proof target is invalid")
        if (
            re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", self.image_reference)
            is None
        ):
            raise ProductionSecretError("host rotation proof image is not immutable")
        if re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is None:
            raise ProductionSecretError("host rotation proof revision is invalid")
        if self.adapter_digest != rotation_adapter_digest():
            raise ProductionSecretError("host rotation proof adapter is not approved")
        if self.database_roles_rotated != DATABASE_ROLE_NAMES:
            raise ProductionSecretError("host rotation proof role inventory is invalid")
        if self.runtime_material_rotated != ("jwt_secret", "session_hash_secret"):
            raise ProductionSecretError(
                "host rotation proof runtime inventory is invalid"
            )
        if self.preserved_material != ("csrf_secret",):
            raise ProductionSecretError(
                "host rotation proof preserved inventory is invalid"
            )
        if self.readiness != "passed":
            raise ProductionSecretError("host rotation proof readiness is invalid")
        if self.prior_authentication != "refused":
            raise ProductionSecretError(
                "host rotation proof prior-auth verdict is invalid"
            )
        if self.plan_rollout_state != "unchanged":
            raise ProductionSecretError("host rotation proof plan verdict is invalid")

    def to_json(self) -> str:
        document = asdict(self)
        document["schema"] = "platform-secret-host-proof.v1"
        return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_json(cls, raw: str) -> HostRotationProof:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError(
                "host rotation proof is not valid JSON"
            ) from exc
        if not isinstance(parsed, dict) or parsed.pop("schema", None) != (
            "platform-secret-host-proof.v1"
        ):
            raise ProductionSecretError("host rotation proof schema is invalid")
        try:
            for key in (
                "database_roles_rotated",
                "runtime_material_rotated",
                "preserved_material",
            ):
                parsed[key] = tuple(parsed[key])
            proof = cls(**parsed)
        except (KeyError, TypeError) as exc:
            raise ProductionSecretError(
                "host rotation proof fields are invalid"
            ) from exc
        return proof


@dataclass(frozen=True, slots=True)
class HistoricalHostRotationProof:
    """A retained target receipt, explicitly not a fresh live observation."""

    operation_id: str
    target_host_id: str
    image_reference: str
    source_revision: str
    adapter_digest: str
    outcome: str = "proved"

    def __post_init__(self) -> None:
        HostRotationProof(
            operation_id=self.operation_id,
            target_host_id=self.target_host_id,
            image_reference=self.image_reference,
            source_revision=self.source_revision,
            adapter_digest=self.adapter_digest,
        )
        if self.outcome != "proved":
            raise ProductionSecretError("historical host outcome is invalid")

    def to_json(self) -> str:
        document = asdict(self)
        document["schema"] = "platform-secret-host-historical-proof.v1"
        return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_json(cls, raw: str) -> HistoricalHostRotationProof:
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.pop("schema", None) != (
                "platform-secret-host-historical-proof.v1"
            ):
                raise ValueError
            return cls(**parsed)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ProductionSecretError("historical host proof is invalid") from exc


HostRotationResult = HostRotationProof | HistoricalHostRotationProof


def parse_host_rotation_result(raw: str) -> HostRotationResult:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProductionSecretError("host rotation result is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise ProductionSecretError("host rotation result is not an object")
    schema = parsed.get("schema")
    if schema == "platform-secret-host-proof.v1":
        return HostRotationProof.from_json(raw)
    if schema == "platform-secret-host-historical-proof.v1":
        return HistoricalHostRotationProof.from_json(raw)
    raise ProductionSecretError("host rotation result schema is invalid")


class OpenBaoClient:
    """Minimal KV v2 client whose errors never include response bodies."""

    def __init__(self, *, address: str, token: str, timeout: float = 15.0) -> None:
        address = address.rstrip("/")
        if not address.startswith(("http://", "https://")):
            raise ProductionSecretError("BAO_ADDR must be an HTTP(S) URL")
        if not token:
            raise ProductionSecretError("BAO_TOKEN is required")
        self._address = address
        self._token = token
        self._timeout = timeout

    def _url(self, path: str, *, version: int | None = None) -> str:
        if path not in SECRET_FIELDS:
            raise ProductionSecretError("OpenBao path is outside the approved set")
        relative = path.removeprefix("secret/")
        encoded = urllib.parse.quote(relative, safe="/")
        url = f"{self._address}/v1/secret/data/{encoded}"
        if version is not None:
            if version < 1:
                raise ProductionSecretError("OpenBao record version must be positive")
            url += "?" + urllib.parse.urlencode({"version": version})
        return url

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        version: int | None = None,
    ) -> dict[str, Any] | None:
        body = None
        headers = {"X-Vault-Token": self._token}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(  # noqa: S310 -- fixed operator URL
            self._url(path, version=version),
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 -- fixed operator URL
                request, timeout=self._timeout
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            exc.read()
            if method == "GET" and exc.code == 404:
                return None
            raise ProductionSecretError(
                f"OpenBao {method} failed for {path} with status {exc.code}"
            ) from None
        except urllib.error.URLError as exc:
            raise ProductionSecretError(
                f"OpenBao {method} failed for {path}: connection unavailable"
            ) from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError(
                f"OpenBao returned invalid JSON for {path}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ProductionSecretError(f"OpenBao returned a non-object for {path}")
        return parsed

    def read_optional(self, path: str) -> dict[str, str] | None:
        response = self._request("GET", path)
        if response is None:
            return None
        outer = response.get("data")
        fields = outer.get("data") if isinstance(outer, dict) else None
        if not isinstance(fields, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in fields.items()
        ):
            raise ProductionSecretError(f"OpenBao record {path} has invalid fields")
        result = dict(fields)
        validate_record(path, result)
        return result

    def create(self, path: str, fields: Mapping[str, str]) -> None:
        validate_record(path, fields)
        # KV v2 CAS=0 means create-only. A concurrent writer or a stale
        # operator run cannot overwrite an issuer key or password set.
        self._request("POST", path, {"options": {"cas": 0}, "data": dict(fields)})

    def read_versioned(
        self, path: str, *, version: int | None = None
    ) -> VersionedSecretRecord:
        response = self._request("GET", path, version=version)
        if response is None:
            raise ProductionSecretError(f"required OpenBao record {path} is absent")
        outer = response.get("data")
        fields = outer.get("data") if isinstance(outer, dict) else None
        metadata = outer.get("metadata") if isinstance(outer, dict) else None
        observed_version = (
            metadata.get("version") if isinstance(metadata, dict) else None
        )
        if not isinstance(fields, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in fields.items()
        ):
            raise ProductionSecretError(f"OpenBao record {path} has invalid fields")
        if not isinstance(observed_version, int) or observed_version < 1:
            raise ProductionSecretError(f"OpenBao record {path} has invalid metadata")
        if version is not None and observed_version != version:
            raise ProductionSecretError(
                f"OpenBao record {path} returned an unexpected version"
            )
        return VersionedSecretRecord(
            path=path,
            version=observed_version,
            fields=dict(fields),
        )

    def cas_update(
        self, path: str, fields: Mapping[str, str], *, expected_version: int
    ) -> int:
        validate_record(path, fields)
        if expected_version < 1:
            raise ProductionSecretError("OpenBao CAS version must be positive")
        try:
            response = self._request(
                "POST",
                path,
                {"options": {"cas": expected_version}, "data": dict(fields)},
            )
        except ProductionSecretError as exc:
            # OpenBao answers both stale-CAS and malformed writes with 400. The
            # record was validated above, so this names the only remaining
            # operator-relevant condition without including the response body.
            if "status 400" in str(exc) or "status 409" in str(exc):
                raise ProductionSecretError(
                    f"OpenBao CAS conflict for {path} at version {expected_version}"
                ) from None
            raise
        outer = response.get("data") if isinstance(response, dict) else None
        new_version = outer.get("version") if isinstance(outer, dict) else None
        if not isinstance(new_version, int) or new_version <= expected_version:
            raise ProductionSecretError(
                f"OpenBao update for {path} returned invalid metadata"
            )
        return new_version


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_deploy_keypair() -> tuple[str, str]:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise ProductionSecretError("ssh-keygen is required to seed deployment keys")
    with tempfile.TemporaryDirectory(prefix="vendor-cp-deploy-key-") as directory:
        key_file = Path(directory) / "id_ed25519"
        try:
            subprocess.run(  # noqa: S603 -- resolved executable, fixed arguments
                [
                    ssh_keygen,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "vendor-cp-prod-deploy",
                    "-f",
                    os.fspath(key_file),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ProductionSecretError(
                "could not generate the deployment key"
            ) from exc
        private_key = key_file.read_text(encoding="utf-8")
        public_key = key_file.with_suffix(".pub").read_text(encoding="utf-8").strip()
    return private_key, public_key


def generated_records(
    *,
    keypair_factory: Callable[[], tuple[str, str]] = _generate_deploy_keypair,
) -> dict[str, dict[str, str]]:
    """Generate one complete first-production secret set in memory."""
    private_key, public_key = keypair_factory()
    records = {
        LICENCE_SIGNING_PATH: {
            "key_id": "vendor-prod-1",
            "private_key_b64url": _b64url(secrets.token_bytes(32)),
        },
        DATABASE_PATH: {
            "admin_password": secrets.token_urlsafe(48),
            "app_user_password": secrets.token_urlsafe(48),
            "platform_api_password": secrets.token_urlsafe(48),
        },
        RUNTIME_PATH: {
            "jwt_secret": secrets.token_urlsafe(64),
            "session_hash_secret": secrets.token_urlsafe(64),
            # Generated with the other two, and only ever for an ABSENT record.
            # `seed_missing_records` never touches one that exists, so this does
            # not and cannot repair the production record — see `_remediation`.
            "csrf_secret": secrets.token_urlsafe(64),
        },
        DEPLOY_SSH_PATH: {
            "private_key_openssh": private_key,
            "public_key_openssh": public_key,
            "username": "root",
        },
    }
    for path, fields in records.items():
        validate_record(path, fields)
    return records


def seed_missing_records(
    client: SecretReader,
    *,
    keypair_factory: Callable[[], tuple[str, str]] = _generate_deploy_keypair,
) -> tuple[str, ...]:
    """Create absent records and preserve every existing value unchanged."""
    existing = {path: client.read_optional(path) for path in SECRET_FIELDS}
    for path, fields in existing.items():
        if fields is not None:
            validate_record(path, fields)
    if all(fields is not None for fields in existing.values()):
        return ()
    candidates = generated_records(keypair_factory=keypair_factory)
    created: list[str] = []
    for path, fields in existing.items():
        if fields is None:
            client.create(path, candidates[path])
            created.append(path)
    return tuple(created)


def _remediation(path: str, missing: Sequence[str]) -> str:
    """What an operator must actually DO, named in the refusal.

    `seed_missing_records` only CREATES absent records, so it can never repair
    an existing one — which is precisely the case a schema widening produces.
    A refusal that does not say so sends the reader to the command that cannot
    help.
    """
    if not missing:
        return (
            "The approved schema is fixed: remove the unexpected field rather "
            "than widening it here."
        )
    instruction = (
        f"`materialize_production_secrets.py seed` only CREATES absent records "
        f"and will not repair one that exists, so patch {path} directly to add "
        f"{', '.join(missing)}."
    )
    if "csrf_secret" in missing:
        instruction += (
            f" `csrf_secret` must be at least {CSRF_SECRET_MIN_BYTES} bytes and "
            "distinct from `jwt_secret` and `session_hash_secret`: kernel a98 "
            "`validate_settings` treats a production `CSRF_SECRET` that is "
            "unset, shorter, or equal to either as fatal."
        )
    return instruction


def validate_record(path: str, fields: Mapping[str, str]) -> None:
    expected = SECRET_FIELDS.get(path)
    if expected is None:
        raise ProductionSecretError("secret path is outside the approved set")
    if set(fields) != expected:
        # Field NAMES only. A record's VALUES never reach an error message, and
        # this is the one place where naming what is wrong risks naming what is
        # in it.
        missing = sorted(expected - set(fields))
        unexpected = sorted(set(fields) - expected)
        observed = []
        if missing:
            observed.append(f"missing {', '.join(missing)}")
        if unexpected:
            observed.append(f"unexpected {', '.join(unexpected)}")
        raise ProductionSecretError(
            f"OpenBao record {path} has an unexpected schema "
            f"({'; '.join(observed)}). {_remediation(path, missing)}"
        )
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise ProductionSecretError(f"OpenBao record {path} has an empty field")
    if path == LICENCE_SIGNING_PATH:
        key_id = fields["key_id"]
        if _KEY_ID_RE.fullmatch(key_id) is None:
            raise ProductionSecretError("licence signing key id is invalid")
        if _B64URL_RE.fullmatch(fields["private_key_b64url"]) is None:
            raise ProductionSecretError("licence signing key is not base64url")
        try:
            material = base64.b64decode(
                fields["private_key_b64url"]
                + "=" * (-len(fields["private_key_b64url"]) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ProductionSecretError("licence signing key is not base64url") from exc
        if len(material) != 32:
            raise ProductionSecretError("licence signing key must be 32 bytes")
    if path == RUNTIME_PATH:
        csrf_secret = fields["csrf_secret"]
        if len(csrf_secret.encode("utf-8")) < CSRF_SECRET_MIN_BYTES:
            raise ProductionSecretError(
                f"{RUNTIME_PATH} field csrf_secret must be at least "
                f"{CSRF_SECRET_MIN_BYTES} bytes"
            )
        if csrf_secret in {fields["jwt_secret"], fields["session_hash_secret"]}:
            raise ProductionSecretError(
                f"{RUNTIME_PATH} field csrf_secret must differ from jwt_secret "
                "and session_hash_secret"
            )
    if path == DEPLOY_SSH_PATH:
        if fields["username"] != "root":
            raise ProductionSecretError("production deploy SSH username must be root")
        if not fields["private_key_openssh"].startswith(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        ) or not fields["private_key_openssh"].endswith(
            "-----END OPENSSH PRIVATE KEY-----\n"
        ):
            raise ProductionSecretError("deployment private key is not OpenSSH")
        if _SSH_PUBLIC_KEY_RE.fullmatch(fields["public_key_openssh"]) is None:
            raise ProductionSecretError("deployment public key is not Ed25519 OpenSSH")
    for value in fields.values():
        if "\x00" in value or "\r" in value:
            raise ProductionSecretError(f"OpenBao record {path} has unsafe bytes")


def build_host_bundle(client: SecretReader) -> HostSecretBundle:
    records: dict[str, dict[str, str]] = {}
    for path in SECRET_FIELDS:
        fields = client.read_optional(path)
        if fields is None:
            raise ProductionSecretError(f"required OpenBao record {path} is absent")
        validate_record(path, fields)
        records[path] = fields
    bundle = HostSecretBundle(
        admin_password=records[DATABASE_PATH]["admin_password"],
        app_user_password=records[DATABASE_PATH]["app_user_password"],
        platform_api_password=records[DATABASE_PATH]["platform_api_password"],
        jwt_secret=records[RUNTIME_PATH]["jwt_secret"],
        session_hash_secret=records[RUNTIME_PATH]["session_hash_secret"],
        csrf_secret=records[RUNTIME_PATH]["csrf_secret"],
        licence_key_id=records[LICENCE_SIGNING_PATH]["key_id"],
        licence_private_key_b64url=records[LICENCE_SIGNING_PATH]["private_key_b64url"],
        deploy_public_key_openssh=records[DEPLOY_SSH_PATH]["public_key_openssh"],
    )
    validate_host_bundle(bundle)
    return bundle


def validate_host_bundle(bundle: HostSecretBundle) -> None:
    for value in asdict(bundle).values():
        if not value or "\x00" in value or "\r" in value:
            raise ProductionSecretError("host secret bundle has an unsafe value")
    validate_record(
        LICENCE_SIGNING_PATH,
        {
            "key_id": bundle.licence_key_id,
            "private_key_b64url": bundle.licence_private_key_b64url,
        },
    )
    if _SSH_PUBLIC_KEY_RE.fullmatch(bundle.deploy_public_key_openssh) is None:
        raise ProductionSecretError("host bundle deployment key is invalid")
    for value in (
        bundle.admin_password,
        bundle.app_user_password,
        bundle.platform_api_password,
        bundle.jwt_secret,
        bundle.session_hash_secret,
        bundle.csrf_secret,
    ):
        if "\n" in value or "=" in value:
            raise ProductionSecretError("environment secret is not URL-safe")
    # Re-asserted on the BUNDLE, not only on the record it came from: the bundle
    # is also reconstructed from JSON over an SSH pipe, and that path never sees
    # `validate_record`.
    if len(bundle.csrf_secret.encode("utf-8")) < CSRF_SECRET_MIN_BYTES:
        raise ProductionSecretError(
            f"host bundle csrf_secret is shorter than {CSRF_SECRET_MIN_BYTES} bytes"
        )
    if bundle.csrf_secret in {bundle.jwt_secret, bundle.session_hash_secret}:
        raise ProductionSecretError(
            "host bundle csrf_secret must differ from jwt_secret and "
            "session_hash_secret"
        )


def _atomic_write(
    path: Path,
    content: str,
    *,
    mode: int,
    owner: tuple[int, int] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    open_descriptor: int | None = descriptor
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        if owner is not None:
            os.fchown(descriptor, *owner)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            open_descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if open_descriptor is not None:
            os.close(open_descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _render_env(template: str, bundle: HostSecretBundle) -> str:
    replacements = {
        "VENDOR_DB_ADMIN_PASSWORD": bundle.admin_password,
        "VENDOR_DB_APP_USER_PASSWORD": bundle.app_user_password,
        "VENDOR_DB_PLATFORM_API_PASSWORD": bundle.platform_api_password,
        "JWT_SECRET": bundle.jwt_secret,
        "SESSION_HASH_SECRET": bundle.session_hash_secret,
        "CSRF_SECRET": bundle.csrf_secret,
        "VENDOR_LICENCE_SIGNING_KEY_ID": bundle.licence_key_id,
    }
    seen: set[str] = set()
    rendered: list[str] = []
    for line in template.splitlines():
        key, separator, _value = line.partition("=")
        if separator and key in replacements:
            if key in seen:
                raise ProductionSecretError(f"production env template repeats {key}")
            rendered.append(f"{key}={replacements[key]}")
            seen.add(key)
        else:
            rendered.append(line)
    missing = ENV_SECRET_KEYS - seen
    if missing:
        raise ProductionSecretError(
            "production env template is missing required secret keys"
        )
    return "\n".join(rendered) + "\n"


def reconcile_host_environment_declarations(
    *,
    env_template: Path,
    env_file: Path,
) -> tuple[str, ...]:
    """Reconcile assembly-owned, non-secret declarations without touching secrets.

    The OpenBao materializer renders the complete file only when it holds the
    complete secret bundle. Ordinary deploys hold no such bundle, but a checked-in
    non-secret declaration may still change between releases. This seam updates
    only the exact allowlist above, refuses duplicate declarations, preserves every
    other byte-bearing value, and atomically retains the file's mode and owner.
    """
    if not env_template.is_file() or env_template.is_symlink():
        raise ProductionSecretError("production env template must be a regular file")
    if not env_file.is_file() or env_file.is_symlink():
        raise ProductionSecretError("production env file must be a regular file")

    template_lines = env_template.read_text(encoding="utf-8").splitlines()
    current_lines = env_file.read_text(encoding="utf-8").splitlines()
    desired: dict[str, str] = {}
    for key in OWNED_ENV_DECLARATIONS:
        values = [
            line.partition("=")[2]
            for line in template_lines
            if line.partition("=")[:2] == (key, "=")
        ]
        if len(values) != 1:
            raise ProductionSecretError(
                f"production env template must declare {key} exactly once"
            )
        if not values[0] or "\x00" in values[0] or "\r" in values[0]:
            raise ProductionSecretError(
                f"production env template has an unsafe value for {key}"
            )
        desired[key] = values[0]

    positions: dict[str, list[int]] = {key: [] for key in OWNED_ENV_DECLARATIONS}
    for index, line in enumerate(current_lines):
        key, separator, _value = line.partition("=")
        if separator and key in positions:
            positions[key].append(index)
    repeated = sorted(key for key, found in positions.items() if len(found) > 1)
    if repeated:
        raise ProductionSecretError(
            f"production env file repeats owned declarations: {', '.join(repeated)}"
        )

    changed: list[str] = []
    for key in sorted(OWNED_ENV_DECLARATIONS):
        replacement = f"{key}={desired[key]}"
        found = positions[key]
        if found:
            if current_lines[found[0]] != replacement:
                current_lines[found[0]] = replacement
                changed.append(key)
        else:
            current_lines.append(replacement)
            changed.append(key)

    if changed:
        metadata = env_file.stat()
        _atomic_write(
            env_file,
            "\n".join(current_lines) + "\n",
            mode=stat.S_IMODE(metadata.st_mode),
            owner=(metadata.st_uid, metadata.st_gid),
        )
    return tuple(changed)


def pin_product_release(
    *,
    env_file: Path,
    product_code: str,
    artifact_digest: str,
    product_manifest_digest: str,
) -> bool:
    """Atomically add or replace one product's exact release evidence pin.

    This is deliberately separate from deployment-profile reconciliation: the
    assembly owns the profile declaration, while an operator owns the release
    selection. The updater requires the declaration exactly once, validates the
    complete existing object through the runtime's canonical parser, preserves
    every other byte in the secret-bearing file, and is a no-op for an already
    current pin.
    """
    if not env_file.is_file() or env_file.is_symlink():
        raise ProductionSecretError("production env file must be a regular file")

    try:
        selected = ProductReleasePin(
            artifact_digest=artifact_digest,
            product_manifest_digest=product_manifest_digest,
        )
        # Rendering an otherwise empty map exercises the same product-code
        # validation used for the complete declaration before touching disk.
        render_product_release_pins({product_code: selected})
    except ValueError as exc:
        raise ProductionSecretError(str(exc)) from exc

    content = env_file.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    positions: list[int] = []
    values: list[str] = []
    for index, line in enumerate(lines):
        physical_line = line.removesuffix("\n").removesuffix("\r")
        key, separator, value = physical_line.partition("=")
        if separator and key == PRODUCT_RELEASE_PINS_DECLARATION:
            positions.append(index)
            values.append(value)
    if len(positions) != 1:
        raise ProductionSecretError(
            f"production env file must declare {PRODUCT_RELEASE_PINS_DECLARATION} "
            "exactly once"
        )

    try:
        pins = dict(parse_product_release_pins(values[0]))
        pins[product_code] = selected
        rendered = render_product_release_pins(pins)
    except ValueError as exc:
        raise ProductionSecretError(str(exc)) from exc

    position = positions[0]
    original_line = lines[position]
    ending = (
        "\r\n"
        if original_line.endswith("\r\n")
        else ("\n" if original_line.endswith("\n") else "")
    )
    replacement = f"{PRODUCT_RELEASE_PINS_DECLARATION}={rendered}{ending}"
    if original_line == replacement:
        return False
    lines[position] = replacement

    metadata = env_file.stat()
    _atomic_write(
        env_file,
        "".join(lines),
        mode=stat.S_IMODE(metadata.st_mode),
        owner=(metadata.st_uid, metadata.st_gid),
    )
    return True


def materialize_host_bundle(
    bundle: HostSecretBundle,
    *,
    env_template: Path,
    env_file: Path,
    signing_key_file: Path,
    authorized_keys_file: Path,
    app_owner: tuple[int, int] | None,
) -> MaterializedHostSecrets:
    """Validate the bundle, then atomically replace each host-local file."""
    validate_host_bundle(bundle)
    template = env_template.read_text(encoding="utf-8")
    rendered_env = _render_env(template, bundle)

    signing_key_file.parent.mkdir(parents=True, exist_ok=True)
    signing_key_file.parent.chmod(0o700)
    if app_owner is not None:
        os.chown(signing_key_file.parent, *app_owner)

    authorized_keys_file.parent.mkdir(parents=True, exist_ok=True)
    authorized_keys_file.parent.chmod(0o700)
    existing_keys = (
        authorized_keys_file.read_text(encoding="utf-8").splitlines()
        if authorized_keys_file.exists()
        else []
    )
    if bundle.deploy_public_key_openssh not in existing_keys:
        existing_keys.append(bundle.deploy_public_key_openssh)
    authorized_keys = "\n".join(line for line in existing_keys if line) + "\n"

    _atomic_write(env_file, rendered_env, mode=0o600)
    _atomic_write(
        signing_key_file,
        bundle.licence_private_key_b64url + "\n",
        mode=0o600,
        owner=app_owner,
    )
    _atomic_write(authorized_keys_file, authorized_keys, mode=0o600)
    return MaterializedHostSecrets(
        env_file=env_file,
        signing_key_file=signing_key_file,
        authorized_keys_file=authorized_keys_file,
    )


def transfer_host_bundle(
    bundle: HostSecretBundle,
    *,
    target: str,
    target_dir: str,
    known_hosts_file: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Send the validated bundle only on SSH stdin to the installed receiver."""
    if re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+", target) is None:
        raise ProductionSecretError("SSH target has an unsafe shape")
    if (
        re.fullmatch(r"/[A-Za-z0-9._/-]+", target_dir) is None
        or ".." in Path(target_dir).parts
    ):
        raise ProductionSecretError("target directory must be an absolute safe path")
    command: Sequence[str] = (
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_file}",
        target,
        "env",
        f"PYTHONPATH={target_dir}/src",
        "python3",
        f"{target_dir}/scripts/materialize_production_secrets.py",
        "receive",
        "--env-template",
        f"{target_dir}/.env.production.example",
        "--env-file",
        f"{target_dir}/.env",
    )
    try:
        runner(command, input=bundle.to_json(), text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProductionSecretError("host secret transfer failed") from exc


def sync_github_deploy_key(
    client: SecretReader,
    *,
    repository: str,
    environment: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Install the deployment private key through ``gh`` stdin, never argv."""
    record = client.read_optional(DEPLOY_SSH_PATH)
    if record is None:
        raise ProductionSecretError(
            f"required OpenBao record {DEPLOY_SSH_PATH} is absent"
        )
    validate_record(DEPLOY_SSH_PATH, record)
    command = (
        "gh",
        "secret",
        "set",
        "VENDOR_PRODUCTION_SSH_KEY",
        "--repo",
        repository,
        "--env",
        environment,
    )
    try:
        runner(
            command,
            input=record["private_key_openssh"],
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProductionSecretError("GitHub deploy-key synchronization failed") from exc


def client_from_environment() -> OpenBaoClient:
    return OpenBaoClient(
        address=os.getenv("BAO_ADDR", "http://127.0.0.1:8200"),
        token=os.getenv("BAO_TOKEN", ""),
    )


# ── Production incident rotation ────────────────────────────────────────────

ROTATION_TARGET = "root@149.102.158.144"
ROTATION_HOST_ID = "vendor-cp-prod"
ROTATION_DEPLOY_DIR = Path("/opt/dotmac/vendor-control-plane")
_ROTATION_COMPOSE_BOOTSTRAP_PLACEHOLDER = "rotation-compose-parse-only"
ROTATION_ADAPTER_PATH = Path(
    "/usr/local/libexec/dotmac/platform-cp-secret-rotation-adapter.pyz"
)
ROTATION_TARGET_STATE_DIR = Path(
    "/var/lib/dotmac/incidents/platform-cp-secret-rotation"
)
DATABASE_ROLE_NAMES = ("app_admin", "app_user", "platform_api")
ROLLBACK_CONFIRMATION = "RESTORE-EXPOSED-MATERIAL-FOR-OUTAGE-CONTAINMENT"


def rotating_set_from_bundle(bundle: HostSecretBundle) -> RotatingSecretSet:
    return RotatingSecretSet(
        admin_password=bundle.admin_password,
        app_user_password=bundle.app_user_password,
        platform_api_password=bundle.platform_api_password,
        jwt_secret=bundle.jwt_secret,
        session_hash_secret=bundle.session_hash_secret,
        csrf_secret=bundle.csrf_secret,
    )


def _validate_rotation(prior: RotatingSecretSet, candidate: RotatingSecretSet) -> None:
    validate_record(DATABASE_PATH, prior.database_record())
    validate_record(RUNTIME_PATH, prior.runtime_record())
    validate_record(DATABASE_PATH, candidate.database_record())
    validate_record(RUNTIME_PATH, candidate.runtime_record())
    if candidate.csrf_secret != prior.csrf_secret:
        raise ProductionSecretError("rotation must preserve csrf_secret")
    prior_values = prior.to_object()
    candidate_values = candidate.to_object()
    unchanged = [
        name
        for name in ROTATED_FIELD_NAMES
        if candidate_values[name] == prior_values[name]
    ]
    if unchanged:
        raise ProductionSecretError(
            "rotation candidate did not replace every rotated field"
        )
    generated = [candidate_values[name] for name in ROTATED_FIELD_NAMES]
    if len(set(generated + [candidate.csrf_secret])) != len(generated) + 1:
        raise ProductionSecretError("rotation candidate values must be distinct")
    if any(_B64URL_RE.fullmatch(value) is None for value in generated):
        raise ProductionSecretError("rotation candidate is not URL-safe")


def generate_secret_rotation(
    database: VersionedSecretRecord,
    runtime: VersionedSecretRecord,
    *,
    token_factory: Callable[[int], str] = secrets.token_urlsafe,
) -> SecretRotationCustody:
    """Mint exactly one candidate set and preserve the current CSRF value."""
    if database.path != DATABASE_PATH or runtime.path != RUNTIME_PATH:
        raise ProductionSecretError("rotation source records are invalid")
    prior = RotatingSecretSet.from_records(database.fields, runtime.fields)
    candidate = RotatingSecretSet(
        admin_password=token_factory(48),
        app_user_password=token_factory(48),
        platform_api_password=token_factory(48),
        jwt_secret=token_factory(64),
        session_hash_secret=token_factory(64),
        csrf_secret=prior.csrf_secret,
    )
    _validate_rotation(prior, candidate)
    return SecretRotationCustody(
        operation_id=secrets.token_hex(16),
        database_prior_version=database.version,
        runtime_prior_version=runtime.version,
        prior=prior,
        candidate=candidate,
    )


def _write_new_protected(path: Path, content: str) -> None:
    if not path.is_absolute():
        raise ProductionSecretError("rotation custody path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ProductionSecretError("rotation custody parent must not be a symlink")
    path.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise ProductionSecretError("rotation custody already exists") from exc
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_protected(path: Path, *, label: str) -> str:
    if not path.is_file() or path.is_symlink():
        raise ProductionSecretError(f"{label} must be a regular file")
    metadata = path.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ProductionSecretError(f"{label} must have mode 0600")
    return path.read_text(encoding="utf-8")


def write_rotation_receipt(path: Path, receipt: SecretRotationReceipt) -> None:
    if not path.is_absolute():
        raise ProductionSecretError("rotation receipt path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    _atomic_write(path, receipt.to_json(), mode=0o600)


def read_rotation_receipt(path: Path) -> SecretRotationReceipt:
    return SecretRotationReceipt.from_json(
        _read_protected(path, label="rotation receipt")
    )


def read_rotation_custody(path: Path) -> SecretRotationCustody:
    return SecretRotationCustody.from_json(
        _read_protected(path, label="rotation custody")
    )


def prepare_secret_rotation(
    store: VersionedSecretStore,
    *,
    custody_file: Path,
    receipt_file: Path,
    expected_image_reference: str,
    expected_source_revision: str,
    token_factory: Callable[[int], str] = secrets.token_urlsafe,
) -> tuple[SecretRotationCustody, SecretRotationReceipt]:
    """Create or resume the one candidate set for an incident.

    Custody is written before either canonical record changes. A process death
    after either CAS therefore resumes from these bytes rather than minting a
    second set. The separate receipt contains names and versions only.
    """
    if custody_file.exists():
        custody = read_rotation_custody(custody_file)
        if not receipt_file.exists():
            receipt = SecretRotationReceipt(
                operation_id=custody.operation_id,
                target_host_id=ROTATION_HOST_ID,
                phase=RotationPhase.PREPARED,
                database_prior_version=custody.database_prior_version,
                runtime_prior_version=custody.runtime_prior_version,
                image_reference=expected_image_reference,
                source_revision=expected_source_revision,
            )
            write_rotation_receipt(receipt_file, receipt)
        else:
            receipt = read_rotation_receipt(receipt_file)
        if receipt.operation_id != custody.operation_id:
            raise ProductionSecretError("rotation receipt and custody disagree")
        if (receipt.image_reference, receipt.source_revision) != (
            expected_image_reference,
            expected_source_revision,
        ):
            raise ProductionSecretError("rotation expected identity changed on retry")
        return custody, receipt
    if receipt_file.exists():
        raise ProductionSecretError(
            "rotation receipt exists without custody; refuse to mint replacement values"
        )
    database = store.read_versioned(DATABASE_PATH)
    runtime = store.read_versioned(RUNTIME_PATH)
    custody = generate_secret_rotation(
        database,
        runtime,
        token_factory=token_factory,
    )
    _write_new_protected(custody_file, custody.to_json())
    receipt = SecretRotationReceipt(
        operation_id=custody.operation_id,
        target_host_id=ROTATION_HOST_ID,
        phase=RotationPhase.PREPARED,
        database_prior_version=database.version,
        runtime_prior_version=runtime.version,
        image_reference=expected_image_reference,
        source_revision=expected_source_revision,
    )
    write_rotation_receipt(receipt_file, receipt)
    return custody, receipt


def _ensure_candidate_record(
    store: VersionedSecretStore,
    *,
    path: str,
    prior_version: int,
    prior_fields: Mapping[str, str],
    candidate_fields: Mapping[str, str],
    recorded_candidate_version: int | None,
) -> int:
    current = store.read_versioned(path)
    if current.fields == candidate_fields:
        expected = recorded_candidate_version or prior_version + 1
        if current.version != expected:
            raise ProductionSecretError(
                f"OpenBao {path} candidate is at an unexpected version"
            )
        return current.version
    if current.version != prior_version or current.fields != prior_fields:
        raise ProductionSecretError(f"OpenBao {path} diverged before the rotation CAS")
    return store.cas_update(
        path,
        candidate_fields,
        expected_version=prior_version,
    )


def commit_openbao_rotation(
    store: VersionedSecretStore,
    custody: SecretRotationCustody,
    receipt: SecretRotationReceipt,
    *,
    receipt_file: Path,
) -> SecretRotationReceipt:
    """Commit both typed records, recording the partial-CAS boundary."""
    if receipt.operation_id != custody.operation_id:
        raise ProductionSecretError("rotation receipt and custody disagree")
    if receipt.phase in {
        RotationPhase.PROVED,
        RotationPhase.ROLLBACK_OPENBAO_COMMITTED,
        RotationPhase.ROLLED_BACK,
    }:
        return receipt
    database_version = _ensure_candidate_record(
        store,
        path=DATABASE_PATH,
        prior_version=custody.database_prior_version,
        prior_fields=custody.prior.database_record(),
        candidate_fields=custody.candidate.database_record(),
        recorded_candidate_version=receipt.database_candidate_version,
    )
    receipt = replace(
        receipt,
        phase=RotationPhase.OPENBAO_DATABASE_WRITTEN,
        database_candidate_version=database_version,
    )
    write_rotation_receipt(receipt_file, receipt)

    runtime_version = _ensure_candidate_record(
        store,
        path=RUNTIME_PATH,
        prior_version=custody.runtime_prior_version,
        prior_fields=custody.prior.runtime_record(),
        candidate_fields=custody.candidate.runtime_record(),
        recorded_candidate_version=receipt.runtime_candidate_version,
    )
    receipt = replace(
        receipt,
        phase=RotationPhase.OPENBAO_COMMITTED,
        runtime_candidate_version=runtime_version,
    )
    write_rotation_receipt(receipt_file, receipt)
    return receipt


def build_rotation_payload(
    _store: VersionedSecretStore,
    custody: SecretRotationCustody,
    receipt: SecretRotationReceipt,
) -> HostSecretRotationPayload:
    """Build the narrow incident projection without reading unrelated records."""
    return HostSecretRotationPayload(
        operation_id=custody.operation_id,
        expected_image_reference=receipt.image_reference or "",
        expected_source_revision=receipt.source_revision or "",
        expected_adapter_digest=rotation_adapter_digest(),
        desired=custody.candidate,
        replaced=custody.prior,
    )


def _run_quiet(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    command: Sequence[str],
    *,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    require_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            cwd=os.fspath(cwd) if cwd is not None else None,
            env=dict(env) if env is not None else None,
        )
    except OSError as exc:
        raise ProductionSecretError(
            "production rotation command was unavailable"
        ) from exc
    if require_success and result.returncode != 0:
        raise ProductionSecretError("production rotation command failed")
    return result


def _run_compose_quiet(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    deploy_dir: Path,
    *arguments: str,
    input_text: str | None = None,
    extra_environment: Mapping[str, str] | None = None,
    require_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run Compose with an inert, process-only bootstrap interpolation.

    The bootstrap password is intentionally absent after the database is first
    created, but Compose expands every service before executing even a read-only
    ``ps`` or an ``exec`` against the existing database.  The placeholder lets
    Compose parse that dormant declaration.  It is never written to ``.env``,
    never passed in argv, and no rotation command creates or recreates ``db``.
    """
    environment = dict(os.environ)
    if extra_environment is not None:
        environment.update(extra_environment)
    # Always override an inherited value. The rotation adapter must never
    # accidentally propagate real bootstrap material from its caller.
    environment["VENDOR_DB_BOOTSTRAP_PASSWORD"] = (
        _ROTATION_COMPOSE_BOOTSTRAP_PLACEHOLDER
    )
    command = (
        "docker",
        "compose",
        "--env-file",
        os.fspath(deploy_dir / ".env"),
        "-f",
        os.fspath(deploy_dir / "docker-compose.production.yml"),
        *arguments,
    )
    return _run_quiet(
        runner,
        command,
        input_text=input_text,
        cwd=deploy_dir,
        env=environment,
        require_success=require_success,
    )


def _running_identity(
    deploy_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> tuple[str, str]:
    container = _run_compose_quiet(
        runner,
        deploy_dir,
        "ps",
        "-q",
        "app",
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{12,64}", container) is None:
        raise ProductionSecretError("production app container identity is unavailable")
    image_reference = _run_quiet(
        runner,
        (
            "docker",
            "inspect",
            "--format",
            "{{.Config.Image}}",
            container,
        ),
    ).stdout.strip()
    if re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image_reference) is None:
        raise ProductionSecretError("production app image is not immutable")
    revision = _run_quiet(
        runner,
        (
            "docker",
            "image",
            "inspect",
            "--format",
            '{{index .Config.Labels "org.opencontainers.image.revision"}}',
            image_reference,
        ),
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ProductionSecretError("production app revision label is invalid")
    return image_reference, revision


def _capture_plan_rollout_state(
    deploy_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    # The bytes are classified as protected operational evidence. The target
    # adapter writes them only to its mode-0600 incident prestate file, compares
    # them directly (never hashes/prints/receipts them), and deletes that file
    # immediately after the target reaches PROVED.
    return _run_compose_quiet(
        runner,
        deploy_dir,
        "exec",
        "-T",
        "db",
        "pg_dump",
        "--username",
        "postgres",
        "--dbname",
        "vendor_control_plane",
        "--data-only",
        "--no-owner",
        "--no-privileges",
        "--table",
        "mod_deploy.deployment_plans",
        "--table",
        "mod_deploy.rollouts",
    ).stdout


def _apply_database_role_passwords(
    deploy_dir: Path,
    desired: RotatingSecretSet,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    # Every value enters psql on stdin. The three ALTERs share one explicit
    # transaction; a failure cannot leave a subset rotated.
    sql = (
        "\\set ON_ERROR_STOP on\n"
        f"\\set admin_password '{desired.admin_password}'\n"
        f"\\set app_user_password '{desired.app_user_password}'\n"
        f"\\set platform_api_password '{desired.platform_api_password}'\n"
        "BEGIN;\n"
        "ALTER ROLE app_admin PASSWORD :'admin_password';\n"
        "ALTER ROLE app_user PASSWORD :'app_user_password';\n"
        "ALTER ROLE platform_api PASSWORD :'platform_api_password';\n"
        "COMMIT;\n"
    )
    _run_compose_quiet(
        runner,
        deploy_dir,
        "exec",
        "-T",
        "db",
        "psql",
        "-X",
        "--quiet",
        "--username",
        "postgres",
        "--dbname",
        "vendor_control_plane",
        input_text=sql,
    )


def _tcp_authentication_succeeds(
    deploy_dir: Path,
    *,
    role: str,
    password: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> bool:
    if role not in {"app_admin", "app_user", "platform_api"}:
        raise ProductionSecretError("database role is outside the rotation set")
    shell = (
        "umask 077; credential=$(mktemp); "
        "trap 'rm -f \"$credential\"' EXIT HUP INT TERM; "
        "IFS= read -r password; "
        "printf '127.0.0.1:5432:vendor_control_plane:%s:%s\\n' \"$1\" "
        '"$password" >"$credential"; unset password; '
        'PGPASSFILE="$credential" psql -X --no-password --host 127.0.0.1 '
        '--username "$1" --dbname vendor_control_plane --command '
        "'SELECT 1' >/dev/null 2>&1"
    )
    result = _run_compose_quiet(
        runner,
        deploy_dir,
        "exec",
        "-T",
        "db",
        "sh",
        "-ceu",
        shell,
        "rotation-auth",
        role,
        input_text=password + "\n",
        require_success=False,
    )
    return result.returncode == 0


def _database_rotation_state(
    deploy_dir: Path,
    *,
    prior: RotatingSecretSet,
    candidate: RotatingSecretSet,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    prior_results: list[bool] = []
    candidate_results: list[bool] = []
    for role, prior_password, candidate_password in (
        ("app_admin", prior.admin_password, candidate.admin_password),
        ("app_user", prior.app_user_password, candidate.app_user_password),
        ("platform_api", prior.platform_api_password, candidate.platform_api_password),
    ):
        prior_results.append(
            _tcp_authentication_succeeds(
                deploy_dir, role=role, password=prior_password, runner=runner
            )
        )
        candidate_results.append(
            _tcp_authentication_succeeds(
                deploy_dir, role=role, password=candidate_password, runner=runner
            )
        )
    if all(prior_results) and not any(candidate_results):
        return "prior"
    if all(candidate_results) and not any(prior_results):
        return "candidate"
    raise ProductionSecretError("database credentials are in a mixed rotation state")


def materialize_rotated_environment(
    desired: RotatingSecretSet,
    replaced: RotatingSecretSet,
    *,
    env_file: Path,
) -> None:
    """Patch exactly five current declarations and preserve every other byte."""
    _validate_rotation(replaced, desired)
    if not env_file.is_file() or env_file.is_symlink():
        raise ProductionSecretError("production env file must be a regular file")

    replacements = {
        "VENDOR_DB_ADMIN_PASSWORD": (replaced.admin_password, desired.admin_password),
        "VENDOR_DB_APP_USER_PASSWORD": (
            replaced.app_user_password,
            desired.app_user_password,
        ),
        "VENDOR_DB_PLATFORM_API_PASSWORD": (
            replaced.platform_api_password,
            desired.platform_api_password,
        ),
        "JWT_SECRET": (replaced.jwt_secret, desired.jwt_secret),
        "SESSION_HASH_SECRET": (
            replaced.session_hash_secret,
            desired.session_hash_secret,
        ),
    }
    original = env_file.read_bytes()
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductionSecretError("production env file is not UTF-8") from exc
    lines = text.splitlines(keepends=True)
    positions: dict[str, list[int]] = {
        **{key: [] for key in replacements},
        "CSRF_SECRET": [],
    }
    for index, line in enumerate(lines):
        physical = line.removesuffix("\n").removesuffix("\r")
        key, separator, _value = physical.partition("=")
        if separator and key in positions:
            positions[key].append(index)
    if any(len(found) != 1 for found in positions.values()):
        raise ProductionSecretError(
            "production env must declare each rotation field exactly once"
        )
    csrf_line = lines[positions["CSRF_SECRET"][0]]
    csrf_physical = csrf_line.removesuffix("\n").removesuffix("\r")
    if csrf_physical.partition("=")[2] != desired.csrf_secret:
        raise ProductionSecretError("production env csrf_secret does not match custody")
    for key, (prior_value, candidate_value) in replacements.items():
        position = positions[key][0]
        original_line = lines[position]
        physical = original_line.removesuffix("\n").removesuffix("\r")
        if physical.partition("=")[2] != prior_value:
            raise ProductionSecretError(
                "production env rotation field does not match protected custody"
            )
        ending = (
            "\r\n"
            if original_line.endswith("\r\n")
            else ("\n" if original_line.endswith("\n") else "")
        )
        lines[position] = f"{key}={candidate_value}{ending}"
    rendered = "".join(lines)
    metadata = env_file.stat()
    _atomic_write(
        env_file,
        rendered,
        mode=stat.S_IMODE(metadata.st_mode),
        owner=(metadata.st_uid, metadata.st_gid),
    )


def _environment_rotation_state(
    env_file: Path,
    *,
    prior: RotatingSecretSet,
    candidate: RotatingSecretSet,
) -> str:
    if not env_file.is_file() or env_file.is_symlink():
        raise ProductionSecretError("production env file must be a regular file")
    values: dict[str, list[str]] = {
        "VENDOR_DB_ADMIN_PASSWORD": [],
        "VENDOR_DB_APP_USER_PASSWORD": [],
        "VENDOR_DB_PLATFORM_API_PASSWORD": [],
        "JWT_SECRET": [],
        "SESSION_HASH_SECRET": [],
        "CSRF_SECRET": [],
    }
    for line in env_file.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in values:
            values[key].append(value)
    if any(len(found) != 1 for found in values.values()):
        raise ProductionSecretError(
            "production env must declare each rotation field exactly once"
        )
    if values["CSRF_SECRET"][0] != prior.csrf_secret:
        raise ProductionSecretError("production env csrf_secret does not match custody")
    prior_expected = {
        "VENDOR_DB_ADMIN_PASSWORD": prior.admin_password,
        "VENDOR_DB_APP_USER_PASSWORD": prior.app_user_password,
        "VENDOR_DB_PLATFORM_API_PASSWORD": prior.platform_api_password,
        "JWT_SECRET": prior.jwt_secret,
        "SESSION_HASH_SECRET": prior.session_hash_secret,
    }
    candidate_expected = {
        "VENDOR_DB_ADMIN_PASSWORD": candidate.admin_password,
        "VENDOR_DB_APP_USER_PASSWORD": candidate.app_user_password,
        "VENDOR_DB_PLATFORM_API_PASSWORD": candidate.platform_api_password,
        "JWT_SECRET": candidate.jwt_secret,
        "SESSION_HASH_SECRET": candidate.session_hash_secret,
    }
    if all(values[key][0] == value for key, value in prior_expected.items()):
        return "prior"
    if all(values[key][0] == value for key, value in candidate_expected.items()):
        return "candidate"
    raise ProductionSecretError("production env is in a mixed rotation state")


def _jwt_for_secret(secret: str, *, operation_id: str) -> str:
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(
        json.dumps(
            {
                "sub": "00000000-0000-0000-0000-000000000001",
                "aud": "platform",
                "exp": int(time.time()) + 600,
                "jti": operation_id,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64url(
        hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    )
    return f"{header}.{payload}.{signature}"


def _prove_runtime_rotation(
    deploy_dir: Path,
    *,
    accepted: RotatingSecretSet,
    refused: RotatingSecretSet,
    operation_id: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    if accepted.csrf_secret != refused.csrf_secret:
        raise ProductionSecretError("runtime proof csrf inputs disagree")
    canary = f"rotation-{operation_id}"
    proof_input = json.dumps(
        {
            "refused_jwt": _jwt_for_secret(
                refused.jwt_secret,
                operation_id=operation_id,
            ),
            "accepted_jwt": _jwt_for_secret(
                accepted.jwt_secret,
                operation_id=operation_id,
            ),
            "canary": canary,
            "refused_session_hash": hmac.new(
                refused.session_hash_secret.encode(),
                canary.encode(),
                hashlib.sha256,
            ).hexdigest(),
            "accepted_session_hash": hmac.new(
                accepted.session_hash_secret.encode(),
                canary.encode(),
                hashlib.sha256,
            ).hexdigest(),
            "csrf_secret": accepted.csrf_secret,
        },
        separators=(",", ":"),
    )
    script = (
        "import json,sys; "
        "from dotmac_kernel import decode_access_token,hash_token; "
        "from dotmac_kernel.config import settings; "
        "p=json.load(sys.stdin); "
        "assert decode_access_token(p['refused_jwt']) is None; "
        "assert decode_access_token(p['accepted_jwt']) is not None; "
        "assert hash_token(p['canary']) == p['accepted_session_hash']; "
        "assert hash_token(p['canary']) != p['refused_session_hash']; "
        "assert settings.csrf_secret == p['csrf_secret']"
    )
    _run_compose_quiet(
        runner,
        deploy_dir,
        "exec",
        "-T",
        "app",
        "python",
        "-c",
        script,
        input_text=proof_input,
    )


def _runtime_rotation_state(
    deploy_dir: Path,
    *,
    prior: RotatingSecretSet,
    candidate: RotatingSecretSet,
    operation_id: str,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> str:
    for state, accepted, refused in (
        ("prior", prior, candidate),
        ("candidate", candidate, prior),
    ):
        try:
            _prove_runtime_rotation(
                deploy_dir,
                accepted=accepted,
                refused=refused,
                operation_id=operation_id,
                runner=runner,
            )
        except ProductionSecretError:
            continue
        return state
    raise ProductionSecretError("running app is in an unproved rotation state")


class TargetRotationPhase(StrEnum):
    PREPARED = "prepared"
    DATABASE_COMMITTED = "database_committed"
    ENVIRONMENT_WRITTEN = "environment_written"
    APP_RECREATED = "app_recreated"
    PROVED = "proved"


@dataclass(frozen=True, slots=True)
class TargetRotationReceipt:
    operation_id: str
    adapter_digest: str
    phase: TargetRotationPhase
    image_reference: str
    source_revision: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{32}", self.operation_id) is None:
            raise ProductionSecretError("target receipt operation id is invalid")
        if self.adapter_digest != rotation_adapter_digest():
            raise ProductionSecretError("target receipt adapter is not approved")
        if (
            re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", self.image_reference)
            is None
        ):
            raise ProductionSecretError("target receipt image is not immutable")
        if re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is None:
            raise ProductionSecretError("target receipt revision is invalid")

    def to_json(self) -> str:
        document = asdict(self)
        document["schema"] = "platform-secret-target-receipt.v1"
        document["phase"] = self.phase.value
        return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    @classmethod
    def from_json(cls, raw: str) -> TargetRotationReceipt:
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or parsed.pop("schema", None) != (
                "platform-secret-target-receipt.v1"
            ):
                raise ValueError
            parsed["phase"] = TargetRotationPhase(parsed["phase"])
            return cls(**parsed)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ProductionSecretError("target rotation receipt is invalid") from exc


def _write_target_receipt(path: Path, receipt: TargetRotationReceipt) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    owner = (0, 0) if path.parent == ROTATION_TARGET_STATE_DIR else None
    _atomic_write(path, receipt.to_json(), mode=0o600, owner=owner)


def _read_target_receipt(path: Path) -> TargetRotationReceipt:
    return TargetRotationReceipt.from_json(
        _read_protected(path, label="target rotation receipt")
    )


def apply_secret_rotation_on_target(
    payload: HostSecretRotationPayload,
    *,
    deploy_dir: Path = ROTATION_DEPLOY_DIR,
    host_id_file: Path = Path("/etc/dotmac-host-id"),
    state_dir: Path = ROTATION_TARGET_STATE_DIR,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> HostRotationResult:
    """Apply and prove a prepared rotation on the one named production host."""
    if host_id_file.read_text(encoding="utf-8").strip() != ROTATION_HOST_ID:
        raise ProductionSecretError("rotation target host identity mismatch")
    if deploy_dir != ROTATION_DEPLOY_DIR and host_id_file == Path(
        "/etc/dotmac-host-id"
    ):
        raise ProductionSecretError("rotation deploy directory is not canonical")
    if deploy_dir != ROTATION_DEPLOY_DIR and state_dir == ROTATION_TARGET_STATE_DIR:
        state_dir = deploy_dir / ".rotation-state"
    if deploy_dir == ROTATION_DEPLOY_DIR and state_dir != ROTATION_TARGET_STATE_DIR:
        raise ProductionSecretError("rotation target state directory is not canonical")
    for required in (
        deploy_dir / ".env",
        deploy_dir / "docker-compose.production.yml",
    ):
        if not required.is_file() or required.is_symlink():
            raise ProductionSecretError("rotation target installation is incomplete")

    desired = payload.desired
    _validate_rotation(payload.replaced, desired)
    image_reference, source_revision = _running_identity(deploy_dir, runner)
    if (image_reference, source_revision) != (
        payload.expected_image_reference,
        payload.expected_source_revision,
    ):
        raise ProductionSecretError("rotation target does not match expected identity")
    receipt_file = state_dir / "receipt.json"
    plan_file = state_dir / "plan-rollout.prestate"
    if receipt_file.exists():
        target_receipt = _read_target_receipt(receipt_file)
        if target_receipt.operation_id != payload.operation_id:
            raise ProductionSecretError("another target rotation is already recorded")
        if (target_receipt.image_reference, target_receipt.source_revision) != (
            image_reference,
            source_revision,
        ):
            raise ProductionSecretError("rotation target identity drifted")
    else:
        initial_state = (
            _database_rotation_state(
                deploy_dir,
                prior=payload.replaced,
                candidate=desired,
                runner=runner,
            ),
            _environment_rotation_state(
                deploy_dir / ".env", prior=payload.replaced, candidate=desired
            ),
            _runtime_rotation_state(
                deploy_dir,
                prior=payload.replaced,
                candidate=desired,
                operation_id=payload.operation_id,
                runner=runner,
            ),
        )
        if initial_state != ("prior", "prior", "prior"):
            raise ProductionSecretError(
                "unrecorded target is not entirely at protected prior state"
            )
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        state_dir.chmod(0o700)
        # A death after writing the protected plan bytes but before the names-
        # only receipt cannot have crossed a mutation boundary: the exact
        # all-prior sensitivity proof above makes replacement safe.
        plan_file.unlink(missing_ok=True)
        plan_state = _capture_plan_rollout_state(deploy_dir, runner)
        _write_new_protected(plan_file, plan_state)
        target_receipt = TargetRotationReceipt(
            operation_id=payload.operation_id,
            adapter_digest=rotation_adapter_digest(),
            phase=TargetRotationPhase.PREPARED,
            image_reference=image_reference,
            source_revision=source_revision,
        )
        _write_target_receipt(receipt_file, target_receipt)

    if target_receipt.phase is TargetRotationPhase.PROVED:
        # A process may have died after persisting PROVED but before deleting
        # the transient plan snapshot. The receipt is the historical result;
        # cleanup is safe and idempotent, and this path never calls it fresh.
        plan_file.unlink(missing_ok=True)
        return HistoricalHostRotationProof(
            operation_id=payload.operation_id,
            target_host_id=ROTATION_HOST_ID,
            image_reference=image_reference,
            source_revision=source_revision,
            adapter_digest=rotation_adapter_digest(),
        )
    if not plan_file.exists():
        raise ProductionSecretError("rotation target prestate is absent")

    database_state = _database_rotation_state(
        deploy_dir,
        prior=payload.replaced,
        candidate=desired,
        runner=runner,
    )
    env_state = _environment_rotation_state(
        deploy_dir / ".env", prior=payload.replaced, candidate=desired
    )
    runtime_state = _runtime_rotation_state(
        deploy_dir,
        prior=payload.replaced,
        candidate=desired,
        operation_id=payload.operation_id,
        runner=runner,
    )
    aggregate = (database_state, env_state, runtime_state)
    allowed = {
        ("prior", "prior", "prior"): TargetRotationPhase.PREPARED,
        ("candidate", "prior", "prior"): TargetRotationPhase.DATABASE_COMMITTED,
        (
            "candidate",
            "candidate",
            "prior",
        ): TargetRotationPhase.ENVIRONMENT_WRITTEN,
        (
            "candidate",
            "candidate",
            "candidate",
        ): TargetRotationPhase.APP_RECREATED,
    }
    observed_phase = allowed.get(aggregate)
    if observed_phase is None:
        raise ProductionSecretError("target is in a mixed rotation state")
    order = tuple(TargetRotationPhase)
    if order.index(target_receipt.phase) > order.index(observed_phase):
        raise ProductionSecretError("target state regressed behind its receipt")

    if database_state == "prior":
        _apply_database_role_passwords(deploy_dir, desired, runner)
        if (
            _database_rotation_state(
                deploy_dir,
                prior=payload.replaced,
                candidate=desired,
                runner=runner,
            )
            != "candidate"
        ):
            raise ProductionSecretError("database rotation did not converge")
        target_receipt = replace(
            target_receipt, phase=TargetRotationPhase.DATABASE_COMMITTED
        )
        _write_target_receipt(receipt_file, target_receipt)

    if env_state == "prior":
        materialize_rotated_environment(
            desired,
            payload.replaced,
            env_file=deploy_dir / ".env",
        )
        if (
            _environment_rotation_state(
                deploy_dir / ".env", prior=payload.replaced, candidate=desired
            )
            != "candidate"
        ):
            raise ProductionSecretError("environment rotation did not converge")
        target_receipt = replace(
            target_receipt, phase=TargetRotationPhase.ENVIRONMENT_WRITTEN
        )
        _write_target_receipt(receipt_file, target_receipt)

    if runtime_state == "candidate":
        after_image, after_revision = _running_identity(deploy_dir, runner)
        if (after_image, after_revision) != (image_reference, source_revision):
            raise ProductionSecretError("rotation changed the app image or revision")
    else:
        _run_compose_quiet(
            runner,
            deploy_dir,
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "--wait",
            "app",
            extra_environment={"VENDOR_APP_IMAGE": image_reference},
        )
        after_image, after_revision = _running_identity(deploy_dir, runner)
        if (after_image, after_revision) != (image_reference, source_revision):
            raise ProductionSecretError("rotation changed the app image or revision")
        target_receipt = replace(
            target_receipt, phase=TargetRotationPhase.APP_RECREATED
        )
        _write_target_receipt(receipt_file, target_receipt)
    _run_quiet(
        runner,
        (
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--header",
            "Host: vendor.dotmac.io",
            "http://127.0.0.1:8100/health/ready",
        ),
    )
    if (
        _runtime_rotation_state(
            deploy_dir,
            prior=payload.replaced,
            candidate=desired,
            operation_id=payload.operation_id,
            runner=runner,
        )
        != "candidate"
    ):
        raise ProductionSecretError("runtime rotation did not converge")
    if _capture_plan_rollout_state(deploy_dir, runner) != _read_protected(
        plan_file, label="target plan prestate"
    ):
        raise ProductionSecretError("rotation changed deployment plan or rollout state")
    target_receipt = replace(target_receipt, phase=TargetRotationPhase.PROVED)
    _write_target_receipt(receipt_file, target_receipt)
    plan_file.unlink()
    return HostRotationProof(
        operation_id=payload.operation_id,
        target_host_id=ROTATION_HOST_ID,
        image_reference=image_reference,
        source_revision=source_revision,
        adapter_digest=rotation_adapter_digest(),
    )


def transfer_rotation_payload(
    payload: HostSecretRotationPayload,
    *,
    known_hosts_file: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> HostRotationResult:
    """Run only the verified isolated adapter; payload exists on SSH stdin."""
    verify_rotation_adapter(known_hosts_file=known_hosts_file, runner=runner)
    command: Sequence[str] = (
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_file}",
        ROTATION_TARGET,
        "python3",
        "-I",
        os.fspath(ROTATION_ADAPTER_PATH),
    )
    result = _run_quiet(runner, command, input_text=payload.to_json())
    return parse_host_rotation_result(result.stdout)


def rotation_adapter_bytes() -> bytes:
    """Build the deterministic, stdlib-only host adapter archive."""
    package_dir = Path(__file__).resolve().parent
    entries = {
        "__main__.py": (
            b"from vendor_cp.production_secrets import host_adapter_main\n"
            b"raise SystemExit(host_adapter_main())\n"
        ),
        "vendor_cp/__init__.py": (package_dir / "__init__.py").read_bytes(),
        "vendor_cp/product_release_pins.py": (
            package_dir / "product_release_pins.py"
        ).read_bytes(),
        "vendor_cp/production_secrets.py": Path(__file__).read_bytes(),
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100444 << 16
            archive.writestr(info, entries[name])
    return output.getvalue()


def rotation_adapter_digest() -> str:
    """Return the exact adapter identity locally or from inside the archive."""
    invoked = Path(sys.argv[0])
    if invoked.is_file() and zipfile.is_zipfile(invoked):
        material = invoked.read_bytes()
    else:
        material = rotation_adapter_bytes()
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _adapter_ssh_prefix(known_hosts_file: Path) -> tuple[str, ...]:
    return (
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts_file}",
        ROTATION_TARGET,
    )


def install_rotation_adapter(
    *,
    known_hosts_file: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Atomically install the one digest-bound adapter outside the checkout."""
    archive = rotation_adapter_bytes()
    digest = rotation_adapter_digest()
    installer = rotation_adapter_installer_program()
    command = (
        *_adapter_ssh_prefix(known_hosts_file),
        "python3",
        "-c",
        installer,
        os.fspath(ROTATION_ADAPTER_PATH),
        digest,
        "/usr/local",
        "0",
        "0",
    )
    _run_quiet(
        runner,
        command,
        input_text=base64.b64encode(archive).decode("ascii"),
    )
    verify_rotation_adapter(known_hosts_file=known_hosts_file, runner=runner)
    return digest


def rotation_adapter_installer_program() -> str:
    """The exact atomic installer, exposed for unsafe-ancestry canaries."""
    return (
        "import base64,hashlib,os,stat,sys,tempfile,pathlib;"
        "p=pathlib.Path(sys.argv[1]);expected=sys.argv[2];"
        "anchor=pathlib.Path(sys.argv[3]);uid=int(sys.argv[4]);gid=int(sys.argv[5]);"
        "raw=base64.b64decode(sys.stdin.buffer.read(),validate=True);"
        "assert 'sha256:'+hashlib.sha256(raw).hexdigest()==expected;"
        "assert anchor in p.parents;"
        "chain=list(reversed(p.parents[:p.parents.index(anchor)+1]));"
        "[(d.mkdir(mode=0o755) if not d.exists() else None) for d in chain];"
        "assert all(stat.S_ISDIR(d.lstat().st_mode) and not d.is_symlink() "
        "and d.lstat().st_uid==uid and d.lstat().st_gid==gid "
        "and not stat.S_IMODE(d.lstat().st_mode)&0o022 for d in chain);"
        "fd,tmp=tempfile.mkstemp(prefix='.'+p.name+'.',dir=p.parent);"
        "os.fchmod(fd,0o555);os.fchown(fd,uid,gid);f=os.fdopen(fd,'wb');"
        "f.write(raw);f.flush();os.fsync(f.fileno());f.close();os.replace(tmp,p)"
    )


def verify_rotation_adapter(
    *,
    known_hosts_file: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Refuse a missing, writable, foreign-owned, symlinked or wrong adapter."""
    verifier = rotation_adapter_verifier_program()
    command = (
        *_adapter_ssh_prefix(known_hosts_file),
        "python3",
        "-c",
        verifier,
        os.fspath(ROTATION_ADAPTER_PATH),
        rotation_adapter_digest(),
        "0",
        "0",
        "/usr/local",
    )
    _run_quiet(runner, command)


def rotation_adapter_verifier_program() -> str:
    """The exact remote verifier, exposed so planted files exercise its bytes."""
    return (
        "import hashlib,os,stat,sys,pathlib;"
        "p=pathlib.Path(sys.argv[1]);s=p.lstat();uid=int(sys.argv[3]);gid=int(sys.argv[4]);"
        "anchor=pathlib.Path(sys.argv[5]);assert anchor in p.parents;"
        "chain=p.parents[:p.parents.index(anchor)+1];"
        "assert all(stat.S_ISDIR(d.lstat().st_mode) and not d.is_symlink() "
        "and d.lstat().st_uid==uid and d.lstat().st_gid==gid "
        "and not stat.S_IMODE(d.lstat().st_mode)&0o022 for d in chain);"
        "assert stat.S_ISREG(s.st_mode) and not p.is_symlink();"
        "assert s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==0o555;"
        "assert 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2]"
    )


def retire_rotation_adapter(
    *,
    known_hosts_file: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Remove only the exact adapter after the incident receipt is PROVED."""
    verify_rotation_adapter(known_hosts_file=known_hosts_file, runner=runner)
    remover = "import pathlib,sys;pathlib.Path(sys.argv[1]).unlink()"
    command = (
        *_adapter_ssh_prefix(known_hosts_file),
        "python3",
        "-c",
        remover,
        os.fspath(ROTATION_ADAPTER_PATH),
    )
    _run_quiet(runner, command)


def host_adapter_main() -> int:
    """The installed archive's only entry point."""
    try:
        if os.geteuid() != 0:
            raise ProductionSecretError("rotation adapter must run as root")
        raw = sys.stdin.read()
        try:
            preflight = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProductionSecretError(
                "host rotation payload is not valid JSON"
            ) from exc
        if (
            not isinstance(preflight, dict)
            or preflight.get("expected_adapter_digest") != rotation_adapter_digest()
        ):
            raise ProductionSecretError("rotation adapter identity mismatch")
        payload = HostSecretRotationPayload.from_json(raw)
        proof = apply_secret_rotation_on_target(payload)
        print(proof.to_json(), end="")
        return 0
    except ProductionSecretError as exc:
        print(f"production secret rotation refused: {exc}", file=sys.stderr)
        return 2


def complete_secret_rotation(
    receipt: SecretRotationReceipt,
    proof: HostRotationResult,
    *,
    receipt_file: Path,
    custody_file: Path,
) -> SecretRotationReceipt:
    if receipt.phase is not RotationPhase.OPENBAO_COMMITTED:
        raise ProductionSecretError("OpenBao rotation is not committed")
    if proof.operation_id != receipt.operation_id:
        raise ProductionSecretError("host proof names another rotation")
    if (proof.image_reference, proof.source_revision) != (
        receipt.image_reference,
        receipt.source_revision,
    ):
        raise ProductionSecretError("host proof identity differs from authorization")
    completed = replace(
        receipt,
        phase=RotationPhase.PROVED,
        image_reference=proof.image_reference,
        source_revision=proof.source_revision,
    )
    write_rotation_receipt(receipt_file, completed)
    # The canonical current and historical OpenBao versions now retain both
    # sets. The crash-recovery copy has served its purpose and must not become a
    # second secret store.
    custody_file.unlink(missing_ok=True)
    return completed


def execute_secret_rotation(
    store: VersionedSecretStore,
    *,
    custody_file: Path,
    receipt_file: Path,
    expected_image_reference: str,
    expected_source_revision: str,
    host_apply: Callable[[HostSecretRotationPayload], HostRotationResult],
    token_factory: Callable[[int], str] = secrets.token_urlsafe,
) -> SecretRotationReceipt:
    """Run or resume the ordered operation without exposing a partial record.

    `host_apply` is called only after BOTH OpenBao records are committed. A
    failed second CAS therefore cannot materialize a mixed bundle or touch the
    database/application, and a retry uses the protected custody set.
    """
    if receipt_file.exists() and not custody_file.exists():
        existing = read_rotation_receipt(receipt_file)
        if existing.phase is RotationPhase.PROVED:
            return existing
    custody, receipt = prepare_secret_rotation(
        store,
        custody_file=custody_file,
        receipt_file=receipt_file,
        expected_image_reference=expected_image_reference,
        expected_source_revision=expected_source_revision,
        token_factory=token_factory,
    )
    receipt = commit_openbao_rotation(
        store,
        custody,
        receipt,
        receipt_file=receipt_file,
    )
    proof = host_apply(build_rotation_payload(store, custody, receipt))
    return complete_secret_rotation(
        receipt,
        proof,
        receipt_file=receipt_file,
        custody_file=custody_file,
    )


def load_rotation_from_receipt(
    store: VersionedSecretStore,
    receipt: SecretRotationReceipt,
) -> SecretRotationCustody:
    if (
        receipt.database_candidate_version is None
        or receipt.runtime_candidate_version is None
    ):
        raise ProductionSecretError("rotation receipt has no committed candidates")
    prior_database = store.read_versioned(
        DATABASE_PATH, version=receipt.database_prior_version
    )
    prior_runtime = store.read_versioned(
        RUNTIME_PATH, version=receipt.runtime_prior_version
    )
    candidate_database = store.read_versioned(
        DATABASE_PATH, version=receipt.database_candidate_version
    )
    candidate_runtime = store.read_versioned(
        RUNTIME_PATH, version=receipt.runtime_candidate_version
    )
    custody = SecretRotationCustody(
        operation_id=receipt.operation_id,
        database_prior_version=receipt.database_prior_version,
        runtime_prior_version=receipt.runtime_prior_version,
        prior=RotatingSecretSet.from_records(
            prior_database.fields, prior_runtime.fields
        ),
        candidate=RotatingSecretSet.from_records(
            candidate_database.fields, candidate_runtime.fields
        ),
    )
    _validate_rotation(custody.prior, custody.candidate)
    return custody


def rollback_openbao_rotation(
    store: VersionedSecretStore,
    receipt: SecretRotationReceipt,
    *,
    receipt_file: Path,
    incident_confirmation: str,
) -> tuple[SecretRotationCustody, SecretRotationReceipt]:
    """Re-enable exposed material only as explicit outage containment."""
    if incident_confirmation != ROLLBACK_CONFIRMATION:
        raise ProductionSecretError(
            "rotation rollback is incident-only and requires exact confirmation"
        )
    if receipt.phase not in {
        RotationPhase.OPENBAO_COMMITTED,
        RotationPhase.PROVED,
        RotationPhase.ROLLBACK_OPENBAO_DATABASE_WRITTEN,
        RotationPhase.ROLLBACK_OPENBAO_COMMITTED,
    }:
        raise ProductionSecretError("rotation has not crossed the rollback boundary")
    custody = load_rotation_from_receipt(store, receipt)
    if receipt.phase is not RotationPhase.ROLLBACK_OPENBAO_COMMITTED:
        database_version = _ensure_restored_record(
            store,
            path=DATABASE_PATH,
            candidate_version=receipt.database_candidate_version,
            candidate_fields=custody.candidate.database_record(),
            restored_fields=custody.prior.database_record(),
            recorded_restored_version=receipt.database_rollback_version,
        )
        receipt = replace(
            receipt,
            phase=RotationPhase.ROLLBACK_OPENBAO_DATABASE_WRITTEN,
            database_rollback_version=database_version,
        )
        write_rotation_receipt(receipt_file, receipt)
        runtime_version = _ensure_restored_record(
            store,
            path=RUNTIME_PATH,
            candidate_version=receipt.runtime_candidate_version,
            candidate_fields=custody.candidate.runtime_record(),
            restored_fields=custody.prior.runtime_record(),
            recorded_restored_version=receipt.runtime_rollback_version,
        )
        receipt = replace(
            receipt,
            phase=RotationPhase.ROLLBACK_OPENBAO_COMMITTED,
            runtime_rollback_version=runtime_version,
        )
        write_rotation_receipt(receipt_file, receipt)
    return custody, receipt


def _ensure_restored_record(
    store: VersionedSecretStore,
    *,
    path: str,
    candidate_version: int | None,
    candidate_fields: Mapping[str, str],
    restored_fields: Mapping[str, str],
    recorded_restored_version: int | None,
) -> int:
    if candidate_version is None:
        raise ProductionSecretError("rotation receipt has no candidate version")
    current = store.read_versioned(path)
    if current.fields == restored_fields:
        expected = recorded_restored_version or candidate_version + 1
        if current.version != expected:
            raise ProductionSecretError(
                f"OpenBao {path} restored record is at an unexpected version"
            )
        return current.version
    if current.version != candidate_version or current.fields != candidate_fields:
        raise ProductionSecretError(f"OpenBao {path} diverged before rollback CAS")
    return store.cas_update(path, restored_fields, expected_version=candidate_version)


def build_rollback_payload(
    _store: VersionedSecretStore,
    custody: SecretRotationCustody,
    receipt: SecretRotationReceipt,
) -> HostSecretRotationPayload:
    return HostSecretRotationPayload(
        operation_id=custody.operation_id,
        expected_image_reference=receipt.image_reference or "",
        expected_source_revision=receipt.source_revision or "",
        expected_adapter_digest=rotation_adapter_digest(),
        desired=custody.prior,
        replaced=custody.candidate,
    )


def complete_rotation_rollback(
    receipt: SecretRotationReceipt,
    proof: HostRotationResult,
    *,
    receipt_file: Path,
) -> SecretRotationReceipt:
    if receipt.phase is not RotationPhase.ROLLBACK_OPENBAO_COMMITTED:
        raise ProductionSecretError("rotation rollback is not committed in OpenBao")
    if proof.operation_id != receipt.operation_id:
        raise ProductionSecretError("host proof names another rotation")
    rolled_back = replace(
        receipt,
        phase=RotationPhase.ROLLED_BACK,
        image_reference=proof.image_reference,
        source_revision=proof.source_revision,
    )
    write_rotation_receipt(receipt_file, rolled_back)
    return rolled_back
