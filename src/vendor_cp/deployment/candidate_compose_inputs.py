"""Pure, redacted admission for the app-only D16 candidate Compose launch.

The per-run env file is parsed as literal data. No shell evaluates it, and this
module never returns its values. The caller still owns credential creation and
the actual subprocess; this module only returns a reviewed argv shape.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from sqlalchemy.engine import make_url

from vendor_cp.deployment.candidate_roles import CandidateRoles

DEFAULT_RUN_ROOT: Final = Path("/opt/dotmac/vendor-control-plane/candidate-runs")
DEFAULT_COMPOSE_FILE: Final = Path(
    "/opt/dotmac/vendor-control-plane/docker-compose.candidate.yml"
)
COMPOSE_SHA256: Final = (
    "d452382e11296a2c41bd9f171921ab8e1f0e7dea0eaa41b72f331801c828fee1"
)
IMAGE_REPOSITORY: Final = "ghcr.io/michaelayoade/dotmac_vendor_control_plane"
LICENCE_KEY_HOST_FILE: Final = Path(
    "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
)
DOCKER_CLIENT_PATH: Final = "/usr/bin:/bin"
LOCAL_DOCKER_HOST: Final = "unix:///var/run/docker.sock"
_RUN_ID: Final = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY: Final = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_DATABASE: Final = re.compile(r"[a-z][a-z0-9_]*\Z")

# This is the application subset of .env.production.example, plus the two
# candidate URLs. Compose-only knobs, role passwords, migration authority and
# relay worker settings are intentionally absent. Each name here has a reader
# in the app's kernel/vendor settings or its declared production profile.
ALLOWED_APP_ENV_KEYS: Final = frozenset(
    {
        "DATABASE_URL",
        "PLATFORM_DATABASE_URL",
        "APP_ENV",
        "SERVER_NAME",
        "ENVIRONMENT",
        "VENDOR_DEPLOYMENT_PROFILE",
        "PLATFORM_ROOT_DOMAIN",
        "TRUSTED_HOSTS",
        "TENANCY",
        "JWT_SECRET",
        "SESSION_HASH_SECRET",
        "CSRF_ENABLED",
        "CSRF_SECRET",
        "RATE_LIMIT_ENABLED",
        "VENDOR_PROVIDER_MODE",
        "VENDOR_PRODUCT_RELEASE_PINS_JSON",
        "VENDOR_PRODUCT_MANIFEST_DIRECTORY",
        "VENDOR_LICENCE_SIGNING_MODE",
        "VENDOR_LICENCE_SIGNING_KEY_FILE",
        "VENDOR_LICENCE_SIGNING_KEY_ID",
        "VENDOR_LICENCE_OVERLAP_KEY_FILE",
        "VENDOR_LICENCE_OVERLAP_KEY_ID",
        "VENDOR_LICENCE_DELIVERY_MODE",
        "VENDOR_RELAY_EXPECTED",
    }
)
_REQUIRED_LITERAL: Final = {
    "APP_ENV": "production",
    "SERVER_NAME": "vendor-cp-prod",
    "ENVIRONMENT": "production",
    "VENDOR_DEPLOYMENT_PROFILE": "production-bootstrap",
    "PLATFORM_ROOT_DOMAIN": "vendor.dotmac.io",
    "TRUSTED_HOSTS": "vendor.dotmac.io",
    "TENANCY": "multi",
    "CSRF_ENABLED": "true",
    "RATE_LIMIT_ENABLED": "true",
    "VENDOR_PROVIDER_MODE": "fake",
    "VENDOR_PRODUCT_MANIFEST_DIRECTORY": "/run/dotmac/product-manifests",
    "VENDOR_LICENCE_SIGNING_MODE": "configured",
    "VENDOR_LICENCE_SIGNING_KEY_FILE": (
        "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
    ),
    "VENDOR_LICENCE_DELIVERY_MODE": "logging",
    "VENDOR_RELAY_EXPECTED": "false",
}
_REQUIRED_NONEMPTY: Final = frozenset(
    {
        "DATABASE_URL",
        "PLATFORM_DATABASE_URL",
        "JWT_SECRET",
        "SESSION_HASH_SECRET",
        "CSRF_SECRET",
        "VENDOR_LICENCE_SIGNING_KEY_ID",
        "VENDOR_PRODUCT_RELEASE_PINS_JSON",
    }
)


class CandidateInputRefused(RuntimeError):
    """Names a failed field or invariant, never a credential value."""


@dataclass(frozen=True, slots=True)
class CandidateComposeLaunch:
    run_id: str
    image: str
    port: int
    argv: tuple[str, ...]
    compose_env: tuple[tuple[str, str], ...]
    env_file: Path = field(repr=False)
    docker_config: Path

    def subprocess_env(self, inherited: Mapping[str, str]) -> dict[str, str]:
        """Discard inherited Docker/Compose settings and admit only fixed inputs."""
        return {
            "PATH": DOCKER_CLIENT_PATH,
            "DOCKER_HOST": LOCAL_DOCKER_HOST,
            "DOCKER_CONFIG": str(self.docker_config),
            **dict(self.compose_env),
        }


def _invocation_uid() -> int:
    return os.geteuid()


def _require_no_symlinks(path: Path) -> None:
    if not path.is_absolute():
        raise CandidateInputRefused("candidate path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except OSError:
            raise CandidateInputRefused("candidate path component is absent") from None
        if stat.S_ISLNK(mode):
            raise CandidateInputRefused("candidate path contains a symlink")


def _require_file_shape(path: Path, *, uid: int, mode: int, directory: bool) -> None:
    _require_no_symlinks(path)
    info = path.stat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode):
        raise CandidateInputRefused("candidate path has the wrong file type")
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
        raise CandidateInputRefused("candidate path owner or mode is invalid")


def _require_empty_docker_config(path: Path, *, uid: int) -> None:
    _require_file_shape(path, uid=uid, mode=0o700, directory=True)
    try:
        if any(path.iterdir()):
            raise CandidateInputRefused("candidate Docker config is not empty")
    except OSError:
        raise CandidateInputRefused("candidate Docker config is unreadable") from None


def _require_reviewed_compose(path: Path, *, uid: int) -> None:
    _require_no_symlinks(path)
    try:
        info = path.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, uid}
            or stat.S_IMODE(info.st_mode) != 0o644
        ):
            raise CandidateInputRefused("candidate Compose owner or mode is invalid")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise CandidateInputRefused("candidate Compose file is unreadable") from None
    if digest != COMPOSE_SHA256:
        raise CandidateInputRefused("candidate Compose bytes differ from review")


def _read_literal_env(path: Path) -> dict[str, str]:
    if path.stat().st_size > 65_536:
        raise CandidateInputRefused("candidate app.env exceeds the size limit")
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise CandidateInputRefused("candidate app.env is unreadable") from None
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            continue
        if "\r" in line or "\x00" in line or "=" not in line:
            raise CandidateInputRefused("candidate app.env has an invalid literal line")
        key, value = line.split("=", 1)
        if not _KEY.fullmatch(key) or key not in ALLOWED_APP_ENV_KEYS:
            raise CandidateInputRefused("candidate app.env has an unknown key")
        if key in values:
            raise CandidateInputRefused(f"candidate app.env repeats {key}")
        if "${" in value or "$(" in value or "`" in value:
            raise CandidateInputRefused(f"candidate app.env has shell syntax in {key}")
        values[key] = value
    for key, expected in _REQUIRED_LITERAL.items():
        if values.get(key) != expected:
            raise CandidateInputRefused(f"candidate app.env requires exact {key}")
    for key in _REQUIRED_NONEMPTY:
        if not values.get(key):
            raise CandidateInputRefused(f"candidate app.env requires {key}")
    if len(values["CSRF_SECRET"]) < 32 or len(values["JWT_SECRET"]) < 32:
        raise CandidateInputRefused("candidate runtime secret length is invalid")
    if values["CSRF_SECRET"] in {values["JWT_SECRET"], values["SESSION_HASH_SECRET"]}:
        raise CandidateInputRefused("candidate runtime secrets must be distinct")
    return values


def _require_candidate_url(value: str, *, role: str, database: str, key: str) -> str:
    try:
        url = make_url(value)
    except Exception:  # noqa: BLE001 -- never disclose parser text with credentials
        raise CandidateInputRefused(f"{key} is not a usable candidate URL") from None
    if (
        url.drivername != "postgresql+psycopg"
        or url.username != role
        or not url.password
        or url.host != "db"
        or url.port != 5432
        or url.database != database
        or url.query
    ):
        raise CandidateInputRefused(f"{key} does not name its candidate role/database")
    return url.password


def build_candidate_compose_launch(
    *,
    run_id: str,
    selected_image: str,
    expected_digest: str,
    candidate_port: int,
    database: str,
    env_file: Path,
    licence_key_host_file: Path,
) -> CandidateComposeLaunch:
    """Validate the host inputs and return argv without any secret material."""
    if not _RUN_ID.fullmatch(run_id):
        raise CandidateInputRefused("candidate run id must be 32 lowercase hex")
    if not _DIGEST.fullmatch(expected_digest):
        raise CandidateInputRefused("expected image digest is invalid")
    if selected_image != f"{IMAGE_REPOSITORY}@{expected_digest}":
        raise CandidateInputRefused("selected image does not match the expected digest")
    if (
        isinstance(candidate_port, bool)
        or not isinstance(candidate_port, int)
        or not 1024 <= candidate_port <= 65535
        or candidate_port == 8100
    ):
        raise CandidateInputRefused("candidate port must be 1024-65535 and not 8100")
    if not _DATABASE.fullmatch(database):
        raise CandidateInputRefused("candidate database name is invalid")
    run_dir = DEFAULT_RUN_ROOT / run_id
    if env_file != run_dir / "app.env":
        raise CandidateInputRefused("candidate app.env path is not canonical")
    # The deployed key lives below a 0700 UID-10001 directory (bootstrap's
    # custody contract). The deploy account cannot lstat it. This exact path
    # check is not a substitute for a privileged pre-launch shape/custody
    # verifier, which remains unimplemented; no caller may treat this pure
    # launch plan as authorization to start a production candidate.
    if licence_key_host_file != LICENCE_KEY_HOST_FILE:
        raise CandidateInputRefused("licence key host path is not canonical")
    uid = _invocation_uid()
    _require_file_shape(run_dir, uid=uid, mode=0o700, directory=True)
    _require_file_shape(env_file, uid=uid, mode=0o600, directory=False)
    docker_config = run_dir / "docker-config"
    _require_empty_docker_config(docker_config, uid=uid)
    _require_reviewed_compose(DEFAULT_COMPOSE_FILE, uid=uid)
    values = _read_literal_env(env_file)
    roles = CandidateRoles.for_run(database=database, run_id=run_id)
    app_password = _require_candidate_url(
        values["DATABASE_URL"], role=roles.app, database=database, key="DATABASE_URL"
    )
    platform_password = _require_candidate_url(
        values["PLATFORM_DATABASE_URL"],
        role=roles.platform,
        database=database,
        key="PLATFORM_DATABASE_URL",
    )
    if app_password == platform_password:
        raise CandidateInputRefused(
            "candidate app and platform credentials must differ"
        )
    project = f"vcp-d16-{run_id}"
    argv = (
        "docker",
        "compose",
        "-p",
        project,
        "-f",
        str(DEFAULT_COMPOSE_FILE),
        "up",
        "-d",
        "--wait",
        "--pull",
        "never",
        "--no-deps",
        "candidate-app",
    )
    compose_env = (
        ("VENDOR_CANDIDATE_APP_IMAGE", selected_image),
        ("VENDOR_CANDIDATE_RUN_ID", run_id),
        ("VENDOR_CANDIDATE_APP_PORT", str(candidate_port)),
        ("VENDOR_LICENCE_SIGNING_KEY_HOST_FILE", str(LICENCE_KEY_HOST_FILE)),
    )
    return CandidateComposeLaunch(
        run_id=run_id,
        image=selected_image,
        port=candidate_port,
        argv=argv,
        compose_env=compose_env,
        env_file=env_file,
        docker_config=docker_config,
    )
