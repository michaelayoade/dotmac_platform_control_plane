"""Exercise an isolated OpenBao 2.5.3 SSH CA with real signed certificates.

No value returned by initialization, unseal, token creation, or a private KV
read is rendered, logged, passed to a child process, or stored in the report.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

VERSION = "2.5.3"
IMAGE_RE = re.compile(r"^openbao/openbao@sha256:[0-9a-f]{64}$")
RFC1918 = tuple(
    ipaddress.ip_network(block)
    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
PRINCIPAL = "gate0-fixture-controller"
SOURCE_ADDRESS = "192.0.2.0/24"
REPLACEMENT_ADDRESS = "198.51.100.0/24"
ROLE = "ssh-fixture/sign/controller"
PRIVATE_PATHS = (
    "secret/data/gate0-fixture/signer",
    "secret/data/gate0-fixture/attester",
)
TRUST_PATH = "secret/data/gate0-fixture/public-trust"
CASE_NAMES = (
    "strict_user_ed25519_certificate",
    "backend_omitted_critical_uses_default",
    "backend_empty_critical_uses_default",
    "strict_wrong_principal_refused",
    "strict_host_certificate_refused",
    "strict_extension_override_refused",
    "strict_critical_override_refused",
    "strict_extra_parameter_refused",
    "strict_other_sign_path_refused",
    "strict_signer_private_read_refused",
    "strict_attester_private_read_refused",
    "runner_public_trust_read_refused",
    "issuer_public_trust_read_allowed",
    "issuer_sign_refused",
    "issuer_signer_private_read_refused",
    "issuer_attester_private_read_refused",
    "role_wrong_principal_refused",
    "role_host_certificate_refused",
    "role_extension_override_refused",
    "weakened_policy_replaces_source_address",
)


class ProofFailure(Exception):
    """Public-safe failure. Never attach a request, response, or child output."""


class ApiStatus(Exception):
    def __init__(self, status: int):
        super().__init__(f"OpenBao HTTP status {status}")
        self.status = status


def policy(*, permit_critical_override: bool, key_id: str) -> str:
    """Exact signing path and closed request-parameter list.

    The weakened policy differs in one allowed parameter only. In OpenBao
    2.5.3, an empty allowed-parameter value list permits any value for that
    named parameter; it does not admit other parameter names.
    """
    critical = '    "critical_options" = []\n' if permit_critical_override else ""
    return (
        f'path "{ROLE}" {{\n'
        '  capabilities = ["update"]\n'
        "  allowed_parameters = {\n"
        '    "public_key" = []\n'
        f'    "valid_principals" = ["{PRINCIPAL}"]\n'
        '    "cert_type" = ["user"]\n'
        f'    "key_id" = ["{key_id}"]\n'
        f"{critical}"
        "  }\n"
        "}\n"
    )


def issuer_policy() -> str:
    return f'path "{TRUST_PATH}" {{ capabilities = ["read"] }}\n'


def safe_report(
    *, image: str, image_id: str, version: str, passed: list[str]
) -> dict[str, Any]:
    if not IMAGE_RE.fullmatch(image) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_id
    ):
        raise ProofFailure("image coordinates are not immutable SHA-256 identifiers")
    if version != VERSION:
        raise ProofFailure("OpenBao server version is not 2.5.3")
    if len(passed) != len(CASE_NAMES) or set(passed) != set(CASE_NAMES):
        raise ProofFailure("conformance cases are missing or duplicated")
    return {
        "schema": "Gate0OpenBaoSSHPolicyFixture.v1",
        "scope": "disposable preparation fixture; no deployed-policy approval",
        "image": image,
        "image_id": image_id,
        "server_version": version,
        "passed_cases": passed,
        "passed_count": len(passed),
    }


def command(argv: list[str], *, stage: str | None = None) -> str:
    label = stage or argv[0]
    try:
        # All executables and arguments are fixture-owned; no shell or secrets.
        result = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ProofFailure(
            f"required command unavailable or timed out: {label}"
        ) from None
    if result.returncode:
        raise ProofFailure(f"required command failed: {label}")
    return result.stdout.strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def api_opener() -> urllib.request.OpenerDirector:
    # Never inherit HTTP_PROXY/HTTPS_PROXY and never forward token headers.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def require_internal_ipv4(value: object) -> str:
    if not isinstance(value, str):
        raise ProofFailure("Docker internal network address is missing")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ProofFailure("Docker internal network address is malformed") from None
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in block for block in RFC1918
    ):
        raise ProofFailure("Docker internal network address is outside RFC1918 IPv4")
    return str(address)


class Bao:
    def __init__(self, address: str):
        self.origin = f"http://{require_internal_ipv4(address)}:8200/v1/"
        self.opener = api_opener()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(  # noqa: S310 - inspected internal Docker IP
            self.origin + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=5) as response:  # noqa: S310
                data = response.read(2_000_000)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise ApiStatus(exc.code) from None
        except (urllib.error.URLError, TimeoutError):
            raise ProofFailure("disposable OpenBao API unavailable") from None
        if not data:
            return {}
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            raise ProofFailure("OpenBao returned malformed JSON") from None
        if not isinstance(value, dict):
            raise ProofFailure("OpenBao returned an unexpected response shape")
        return value


def required_data(response: dict[str, Any], name: str) -> str:
    data = response.get("data")
    value = data.get(name) if isinstance(data, dict) else None
    if not isinstance(value, str) or not value:
        raise ProofFailure(f"OpenBao response lacks required {name} field")
    return value


def refused(call: Any, name: str, allowed: tuple[int, ...] = (400, 403)) -> str:
    try:
        call()
    except ApiStatus as exc:
        if exc.status not in allowed:
            raise ProofFailure(
                f"{name} returned unexpected HTTP status {exc.status}"
            ) from None
        return name
    raise ProofFailure(f"{name} unexpectedly succeeded")


def _section(output: str, heading: str) -> list[str]:
    lines = output.splitlines()
    marker = f"{heading}:"
    for index, line in enumerate(lines):
        if line.strip() == f"{marker} (none)":
            return ["(none)"]
        if line.strip() == marker:
            result: list[str] = []
            for following in lines[index + 1 :]:
                if not following.startswith("\t\t") and not following.startswith(
                    "                "
                ):
                    break
                result.append(following.strip())
            return result
    raise ProofFailure(f"ssh-keygen did not show {heading}")


def verify_certificate(
    cert: Path, public_key: Path, *, key_id: str, address: str
) -> None:
    output = command(["ssh-keygen", "-Lf", str(cert)])
    key_line = command(["ssh-keygen", "-lf", str(public_key)])
    fingerprint = re.search(r"SHA256:[A-Za-z0-9+/]+", key_line)
    if fingerprint is None or fingerprint.group() not in output:
        raise ProofFailure("certificate does not identify the generated public key")
    if not re.search(
        r"Type: ssh-ed25519-cert-v01@openssh\.com user certificate", output
    ):
        raise ProofFailure("certificate is not an Ed25519 user certificate")
    if f'Key ID: "{key_id}"' not in output:
        raise ProofFailure("certificate key ID differs from fixture run")
    if _section(output, "Principals") != [PRINCIPAL]:
        raise ProofFailure("certificate principals differ from exact fixture principal")
    if _section(output, "Critical Options") != [f"source-address {address}"]:
        raise ProofFailure("certificate source-address differs from expected value")
    extensions = _section(output, "Extensions") if "Extensions:" in output else []
    if extensions not in ([], ["(none)"]):
        raise ProofFailure("certificate has unrequested extensions")


def _container_config() -> str:
    # Only non-secret server configuration is in argv. Storage is tmpfs.
    return (
        "printf '%s\\n' 'ui = false' 'disable_mlock = true' "
        "'log_level = \"error\"' "
        "'storage \"file\" {' '  path = \"/bao/file\"' '}' "
        "'listener \"tcp\" {' '  address = \"0.0.0.0:8200\"' "
        "'  tls_disable = true' '}' "
        "> /tmp/gate0-openbao.hcl; exec bao server -config=/tmp/gate0-openbao.hcl"
    )


def container_address(name: str, network: str) -> str:
    try:
        inspected = json.loads(
            command(
                ["docker", "container", "inspect", name],
                stage="docker-container-network-inspect",
            )
        )
    except ValueError:
        raise ProofFailure(
            "Docker container inspection returned malformed JSON"
        ) from None
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ProofFailure("Docker did not inspect one owned fixture container")
    item = inspected[0]
    if not isinstance(item, dict) or item.get("Name") != f"/{name}":
        raise ProofFailure("Docker inspected a different container")
    config = item.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(labels, dict)
        or labels.get("dotmac.gate0-policy-instance") != name
    ):
        raise ProofFailure("Docker container lacks its instance label")
    settings = item.get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    if not isinstance(networks, dict) or set(networks) != {network}:
        raise ProofFailure(
            "Docker container is not isolated on its one internal network"
        )
    endpoint = networks[network]
    if not isinstance(endpoint, dict):
        raise ProofFailure("Docker internal network endpoint is malformed")
    return require_internal_ipv4(endpoint.get("IPAddress"))


def start_container(image: str) -> tuple[str, str, str, str]:
    if not IMAGE_RE.fullmatch(image):
        raise ProofFailure("--image must be openbao/openbao@sha256:<64 lowercase hex>")
    try:
        details = json.loads(
            command(["docker", "image", "inspect", image], stage="docker-image-inspect")
        )
    except ValueError:
        raise ProofFailure("Docker image inspection returned malformed JSON") from None
    if not isinstance(details, list) or len(details) != 1:
        raise ProofFailure("pinned OpenBao image is not installed")
    digests = details[0].get("RepoDigests")
    if not isinstance(digests, list) or image not in digests:
        raise ProofFailure(
            "installed image does not attest the requested registry digest"
        )
    image_id = details[0].get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_id
    ):
        raise ProofFailure("Docker image ID is not a SHA-256 identifier")
    name = f"gate0-policy-proof-{uuid.uuid4().hex}"
    network = f"{name}-net"
    instance_label = f"dotmac.gate0-policy-instance={name}"
    try:
        command(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--label",
                instance_label,
                network,
            ],
            stage="docker-network-create",
        )
        command(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--pull=never",
                "--name",
                name,
                "--network",
                network,
                "--label",
                instance_label,
                "--tmpfs",
                "/bao/file:rw,nosuid,nodev,size=32m",
                "--entrypoint",
                "/bin/sh",
                image,
                "-ec",
                _container_config(),
            ],
            stage="docker-run",
        )
        address = container_address(name, network)
        return name, network, address, image_id
    except BaseException as original:
        cleanup_errors = cleanup_resources(name, network)
        if cleanup_errors:
            cleanup_message = f"fixture cleanup failed: {'; '.join(cleanup_errors)}"
            if isinstance(original, ProofFailure):
                raise ProofFailure(f"{original}; {cleanup_message}") from None
            original.add_note(cleanup_message)
        raise


def stop_container(name: str) -> None:
    if not re.fullmatch(r"gate0-policy-proof-[0-9a-f]{32}", name):
        raise ProofFailure("refusing to stop a container outside this fixture")
    listed = command(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            f"label=dotmac.gate0-policy-instance={name}",
            "--format",
            "{{.Names}}",
        ],
        stage="docker-container-list",
    )
    if not listed:
        return  # --rm already removed a container that exited on its own
    if listed != name:
        raise ProofFailure("Docker returned an unexpected fixture container name")
    label = command(
        [
            "docker",
            "inspect",
            "--format",
            '{{index .Config.Labels "dotmac.gate0-policy-instance"}}',
            name,
        ],
        stage="docker-container-inspect",
    )
    if label != name:
        raise ProofFailure("refusing to stop a container without its instance label")
    command(["docker", "stop", name], stage="docker-stop")


def stop_network(name: str) -> None:
    if not re.fullmatch(r"gate0-policy-proof-[0-9a-f]{32}-net", name):
        raise ProofFailure("refusing to remove a network outside this fixture")
    listed = command(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=dotmac.gate0-policy-instance={name.removesuffix('-net')}",
            "--format",
            "{{.Name}}",
        ],
        stage="docker-network-list",
    )
    if not listed:
        return
    if listed != name:
        raise ProofFailure("Docker returned an unexpected fixture network name")
    label = command(
        [
            "docker",
            "network",
            "inspect",
            "--format",
            '{{index .Labels "dotmac.gate0-policy-instance"}}',
            name,
        ],
        stage="docker-network-inspect",
    )
    if label != name.removesuffix("-net"):
        raise ProofFailure("refusing to remove a network without its instance label")
    command(["docker", "network", "rm", name], stage="docker-network-rm")


def cleanup_resources(name: str, network: str) -> list[str]:
    errors: list[str] = []
    for cleanup, target in ((stop_container, name), (stop_network, network)):
        try:
            cleanup(target)
        except ProofFailure as exc:
            errors.append(str(exc))
        except BaseException:
            # Still inspect the other owned resource; never render an
            # unexpected exception that might contain response material.
            errors.append("unexpected fixture cleanup error")
    return errors


def initialize(bao: Bao) -> tuple[str, str]:
    for _ in range(40):
        try:
            health = bao.request("GET", "sys/health")
            break
        except ApiStatus as exc:
            if exc.status == 501:  # uninitialized is a live, ready server
                break
            raise ProofFailure("unexpected pre-init OpenBao health status") from None
        except ProofFailure:
            time.sleep(0.25)
    else:
        raise ProofFailure("disposable OpenBao did not become ready")
    response = bao.request(
        "PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
    )
    keys = response.get("keys")
    root = response.get("root_token")
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], str):
        raise ProofFailure("OpenBao initialization did not return one unseal share")
    if not isinstance(root, str) or not root:
        raise ProofFailure("OpenBao initialization did not return a root token")
    bao.request("PUT", "sys/unseal", {"key": keys[0]})
    health = bao.request("GET", "sys/health")
    version = health.get("version")
    if version != VERSION:
        raise ProofFailure("OpenBao server version is not 2.5.3")
    return root, version


def configure(bao: Bao, root: str, key_id: str) -> tuple[str, str, str]:
    bao.request("POST", "sys/mounts/ssh-fixture", {"type": "ssh"}, root)
    bao.request("POST", "ssh-fixture/config/ca", {"generate_signing_key": True}, root)
    bao.request(
        "POST",
        "ssh-fixture/roles/controller",
        {
            "key_type": "ca",
            "allow_user_certificates": True,
            "allow_host_certificates": False,
            "allowed_users": PRINCIPAL,
            "default_user": PRINCIPAL,
            "allow_user_key_ids": True,
            "allowed_user_key_lengths": {"ed25519": [0]},
            "allowed_extensions": "",
            "default_extensions": {},
            "allowed_critical_options": "source-address",
            "default_critical_options": {"source-address": SOURCE_ADDRESS},
            "ttl": "300s",
            "max_ttl": "300s",
        },
        root,
    )
    bao.request(
        "POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, root
    )
    for path in PRIVATE_PATHS:
        material = secrets.token_urlsafe(32)
        bao.request(
            "POST",
            path,
            {"data": {"fixture_material": material}},
            root,
        )
        root_read = bao.request("GET", path, token=root)
        if root_read.get("data", {}).get("data") != {"fixture_material": material}:
            raise ProofFailure("private fixture record was not readable by root")
    bao.request("POST", TRUST_PATH, {"data": {"fixture": "public"}}, root)
    for name, weak in (("strict", False), ("weakened", True)):
        bao.request(
            "PUT",
            f"sys/policies/acl/gate0-{name}",
            {"policy": policy(permit_critical_override=weak, key_id=key_id)},
            root,
        )
    bao.request(
        "PUT",
        "sys/policies/acl/gate0-issuer",
        {"policy": issuer_policy()},
        root,
    )

    def token_for(name: str) -> str:
        response = bao.request(
            "POST",
            "auth/token/create",
            {
                "policies": [f"gate0-{name}"],
                "ttl": "10m",
                "renewable": False,
                "no_default_policy": True,
            },
            root,
        )
        auth = response.get("auth")
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token:
            raise ProofFailure("scoped token creation returned no token")
        lookup = bao.request("POST", "auth/token/lookup", {"token": token}, root)
        policies = lookup.get("data", {}).get("policies")
        if not isinstance(policies, list) or set(policies) != {f"gate0-{name}"}:
            raise ProofFailure(
                "scoped token has policies beyond its one fixture policy"
            )
        return token

    return token_for("strict"), token_for("weakened"), token_for("issuer")


def exercise(
    bao: Bao,
    root: str,
    strict: str,
    weakened: str,
    issuer: str,
    directory: Path,
    key_id: str,
) -> list[str]:
    key = directory / "controller-key"
    command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    public_path = key.with_suffix(".pub")
    public_key = public_path.read_text(encoding="ascii").strip()
    if not public_key.startswith("ssh-ed25519 "):
        raise ProofFailure("ssh-keygen did not generate an Ed25519 public key")
    request = {
        "public_key": public_key,
        "valid_principals": PRINCIPAL,
        "cert_type": "user",
        "key_id": key_id,
    }
    passed: list[str] = []

    def signed(token: str, payload: dict[str, Any], case: str, address: str) -> None:
        cert_text = required_data(
            bao.request("POST", ROLE, payload, token), "signed_key"
        )
        cert = directory / f"{case}-cert.pub"
        cert.write_text(cert_text, encoding="ascii")
        cert.chmod(0o600)
        verify_certificate(cert, public_path, key_id=key_id, address=address)
        passed.append(case)

    signed(strict, request, CASE_NAMES[0], SOURCE_ADDRESS)
    signed(root, request, CASE_NAMES[1], SOURCE_ADDRESS)
    signed(root, {**request, "critical_options": {}}, CASE_NAMES[2], SOURCE_ADDRESS)
    negatives = (
        (CASE_NAMES[3], strict, ROLE, {**request, "valid_principals": "other"}),
        (CASE_NAMES[4], strict, ROLE, {**request, "cert_type": "host"}),
        (CASE_NAMES[5], strict, ROLE, {**request, "extensions": {"permit-pty": ""}}),
        (
            CASE_NAMES[6],
            strict,
            ROLE,
            {**request, "critical_options": {"source-address": REPLACEMENT_ADDRESS}},
        ),
        (CASE_NAMES[7], strict, ROLE, {**request, "ttl": "600s"}),
        (CASE_NAMES[8], strict, "ssh-fixture/sign/other", request),
    )
    for name, token, path, payload in negatives:
        passed.append(
            refused(
                lambda token=token, path=path, payload=payload: bao.request(
                    "POST", path, payload, token
                ),
                name,
                (403,),
            )
        )
    for name, path in zip(CASE_NAMES[9:11], PRIVATE_PATHS, strict=True):
        passed.append(
            refused(
                lambda path=path: bao.request("GET", path, token=strict), name, (403,)
            )
        )
    passed.append(
        refused(
            lambda: bao.request("GET", TRUST_PATH, token=strict), CASE_NAMES[11], (403,)
        )
    )
    trust = bao.request("GET", TRUST_PATH, token=issuer)
    if trust.get("data", {}).get("data") != {"fixture": "public"}:
        raise ProofFailure("issuer token did not read the public trust fixture")
    passed.append(CASE_NAMES[12])
    passed.append(
        refused(
            lambda: bao.request("POST", ROLE, request, issuer), CASE_NAMES[13], (403,)
        )
    )
    for name, path in zip(CASE_NAMES[14:16], PRIVATE_PATHS, strict=True):
        passed.append(
            refused(
                lambda path=path: bao.request("GET", path, token=issuer), name, (403,)
            )
        )
    role_negatives = (
        (CASE_NAMES[16], {**request, "valid_principals": "other"}),
        (CASE_NAMES[17], {**request, "cert_type": "host"}),
        (CASE_NAMES[18], {**request, "extensions": {"permit-pty": ""}}),
    )
    for name, payload in role_negatives:
        passed.append(
            refused(
                lambda payload=payload: bao.request("POST", ROLE, payload, root),
                name,
                (400,),
            )
        )
    signed(
        weakened,
        {**request, "critical_options": {"source-address": REPLACEMENT_ADDRESS}},
        CASE_NAMES[19],
        REPLACEMENT_ADDRESS,
    )
    return passed


def run(image: str) -> dict[str, Any]:
    name, network, address, image_id = start_container(image)
    pending: BaseException | None = None
    try:
        bao = Bao(address)
        root, version = initialize(bao)
        key_id = f"gate0-fixture-{uuid.uuid4().hex}"
        strict, weakened, issuer = configure(bao, root, key_id)
        with tempfile.TemporaryDirectory(prefix="gate0-ssh-policy-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            passed = exercise(bao, root, strict, weakened, issuer, directory, key_id)
        report = safe_report(
            image=image, image_id=image_id, version=version, passed=passed
        )
    except BaseException as original:
        pending = original
        raise
    finally:
        cleanup_errors = cleanup_resources(name, network)
        if cleanup_errors:
            cleanup_message = f"fixture cleanup failed: {'; '.join(cleanup_errors)}"
            if pending is None:
                raise ProofFailure(cleanup_message)
            if isinstance(pending, ProofFailure | ApiStatus):
                raise ProofFailure(f"{pending}; {cleanup_message}") from None
            pending.add_note(cleanup_message)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="exact OpenBao 2.5.3 image digest"
    )
    args = parser.parse_args(argv)
    try:
        report = run(args.image)
    except (ProofFailure, ApiStatus) as exc:
        print(f"OpenBao SSH-policy conformance failed: {exc}", file=sys.stderr)
        return 1
    except BaseException:
        print(
            "OpenBao SSH-policy conformance failed: unexpected driver error",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
