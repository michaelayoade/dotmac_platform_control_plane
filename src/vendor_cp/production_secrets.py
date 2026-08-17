"""Production secret seeding and atomic host materialization.

This is an operator service, not a runtime settings source. It talks to the
canonical OpenBao KV v2 API only when an operator invokes it, keeps values in
memory, and transfers a validated host bundle over SSH stdin. It never prints
or places a secret in a subprocess argument.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
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
    RUNTIME_PATH: frozenset({"jwt_secret", "session_hash_secret"}),
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
        "VENDOR_LICENCE_SIGNING_KEY_ID",
    }
)

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SSH_PUBLIC_KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?$")


class ProductionSecretError(RuntimeError):
    """The production secret contract could not be established safely."""


class SecretReader(Protocol):
    """Narrow read/create seam used by the operator service and its tests."""

    def read_optional(self, path: str) -> dict[str, str] | None: ...

    def create(self, path: str, fields: Mapping[str, str]) -> None: ...


@dataclass(frozen=True, slots=True)
class HostSecretBundle:
    """Only the values a production host is permitted to retain."""

    admin_password: str
    app_user_password: str
    platform_api_password: str
    jwt_secret: str
    session_hash_secret: str
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

    def _url(self, path: str) -> str:
        if path not in SECRET_FIELDS:
            raise ProductionSecretError("OpenBao path is outside the approved set")
        relative = path.removeprefix("secret/")
        encoded = urllib.parse.quote(relative, safe="/")
        return f"{self._address}/v1/secret/data/{encoded}"

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
    ) -> dict[str, Any] | None:
        body = None
        headers = {"X-Vault-Token": self._token}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(  # noqa: S310 -- fixed operator URL
            self._url(path), data=body, headers=headers, method=method
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


def validate_record(path: str, fields: Mapping[str, str]) -> None:
    expected = SECRET_FIELDS.get(path)
    if expected is None:
        raise ProductionSecretError("secret path is outside the approved set")
    if set(fields) != expected:
        raise ProductionSecretError(f"OpenBao record {path} has an unexpected schema")
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
    ):
        if "\n" in value or "=" in value:
            raise ProductionSecretError("environment secret is not URL-safe")


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
