"""Runtime-free invariants for the disposable OpenBao proof driver."""

from __future__ import annotations

import importlib.util
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

PROOF_PATH = (
    Path(__file__).resolve().parents[2] / "openbao_policy_conformance" / "proof.py"
)
_spec = importlib.util.spec_from_file_location(
    "_gate0_openbao_policy_proof", PROOF_PATH
)
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load OpenBao proof from {PROOF_PATH}")
proof = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proof)

CASE_NAMES = proof.CASE_NAMES
IMAGE_RE = proof.IMAGE_RE
PRINCIPAL = proof.PRINCIPAL
ROLE = proof.ROLE
SOURCE_ADDRESS = proof.SOURCE_ADDRESS
TRUST_PATH = proof.TRUST_PATH
ApiStatus = proof.ApiStatus
Bao = proof.Bao
ProofFailure = proof.ProofFailure
api_opener = proof.api_opener
command = proof.command
container_address = proof.container_address
issuer_policy = proof.issuer_policy
main = proof.main
policy = proof.policy
refused = proof.refused
run = proof.run
safe_report = proof.safe_report
start_container = proof.start_container
stop_container = proof.stop_container
verify_certificate = proof.verify_certificate

IMAGE = "openbao/openbao@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


class PolicyConformanceUnitTests(unittest.TestCase):
    def test_proof_origin_is_exact_repo_file(self) -> None:
        self.assertEqual(Path(proof.__file__).resolve(), PROOF_PATH)

    def test_strict_policy_names_one_sign_path_and_closed_parameters(self) -> None:
        strict = policy(permit_critical_override=False, key_id="fixture-run")
        weak = policy(permit_critical_override=True, key_id="fixture-run")
        expected = (
            f'path "{ROLE}" {{\n'
            '  capabilities = ["update"]\n'
            "  allowed_parameters = {\n"
            '    "public_key" = []\n'
            '    "valid_principals" = ["gate0-fixture-controller"]\n'
            '    "cert_type" = ["user"]\n'
            '    "key_id" = ["fixture-run"]\n'
            "  }\n"
            "}\n"
        )
        self.assertEqual(strict, expected)
        self.assertEqual(
            weak,
            expected.replace(
                '    "key_id" = ["fixture-run"]\n',
                '    "key_id" = ["fixture-run"]\n' '    "critical_options" = []\n',
            ),
        )
        permissive_extra_path = strict + (
            'path "ssh-fixture/sign/*" { capabilities = ["update"] }\n'
        )
        with self.assertRaises(AssertionError):
            self.assertEqual(permissive_extra_path, expected)
        self.assertEqual(
            issuer_policy(), f'path "{TRUST_PATH}" {{ capabilities = ["read"] }}\n'
        )
        self.assertNotIn(ROLE, issuer_policy())

    def test_uncertain_docker_run_failure_stops_only_own_container_then_network(
        self,
    ) -> None:
        events: list[str] = []
        owner: dict[str, str] = {}

        def fake_command(argv: list[str], *, stage: str | None = None) -> str:
            assert stage is not None
            events.append(stage)
            if stage == "docker-image-inspect":
                return json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE]}])
            if stage == "docker-network-create":
                owner["network"] = argv[-1]
                owner["name"] = argv[-1].removesuffix("-net")
                return owner["network"]
            if stage == "docker-run":
                self.assertEqual(argv[argv.index("--name") + 1], owner["name"])
                raise ProofFailure(
                    "required command unavailable or timed out: docker-run"
                )
            if stage == "docker-container-list":
                self.assertIn(
                    f"label=dotmac.gate0-policy-instance={owner['name']}", argv
                )
                return owner["name"]
            if stage == "docker-container-inspect":
                return owner["name"]
            if stage == "docker-stop":
                self.assertEqual(argv[-1], owner["name"])
                return owner["name"]
            if stage == "docker-network-list":
                self.assertIn(
                    f"label=dotmac.gate0-policy-instance={owner['name']}", argv
                )
                return owner["network"]
            if stage == "docker-network-inspect":
                return owner["name"]
            if stage == "docker-network-rm":
                self.assertEqual(argv[-1], owner["network"])
                return owner["network"]
            self.fail(f"unexpected fixture stage: {stage}")

        with patch.object(proof, "command", side_effect=fake_command):
            with self.assertRaisesRegex(ProofFailure, "timed out: docker-run"):
                start_container(IMAGE)
        self.assertEqual(
            events,
            [
                "docker-image-inspect",
                "docker-network-create",
                "docker-run",
                "docker-container-list",
                "docker-container-inspect",
                "docker-stop",
                "docker-network-list",
                "docker-network-inspect",
                "docker-network-rm",
            ],
        )

    def test_uncertain_run_absence_is_distinct_from_inspection_failure(self) -> None:
        stages: list[str] = []
        owner: dict[str, str] = {}

        def fake_command(argv: list[str], *, stage: str | None = None) -> str:
            assert stage is not None
            stages.append(stage)
            if stage == "docker-image-inspect":
                return json.dumps([{"Id": IMAGE_ID, "RepoDigests": [IMAGE]}])
            if stage == "docker-network-create":
                owner["network"] = argv[-1]
                owner["name"] = argv[-1].removesuffix("-net")
                return owner["network"]
            if stage == "docker-run":
                raise ProofFailure("required command failed: docker-run")
            if stage == "docker-container-list":
                return ""
            if stage == "docker-network-list":
                return owner["network"]
            if stage == "docker-network-inspect":
                return owner["name"]
            if stage == "docker-network-rm":
                return ""
            self.fail(f"unexpected fixture stage: {stage}")

        with patch.object(proof, "command", side_effect=fake_command):
            with self.assertRaisesRegex(ProofFailure, "failed: docker-run"):
                start_container(IMAGE)
        self.assertNotIn("docker-stop", stages)
        self.assertIn("docker-network-rm", stages)

        def inspection_fails(argv: list[str], *, stage: str | None = None) -> str:
            if stage == "docker-container-list":
                raise ProofFailure("required command failed: docker-container-list")
            return fake_command(argv, stage=stage)

        stages.clear()
        with patch.object(proof, "command", side_effect=inspection_fails):
            with self.assertRaisesRegex(
                ProofFailure,
                "failed: docker-run; fixture cleanup failed: "
                "required command failed: docker-container-list",
            ):
                start_container(IMAGE)
        self.assertIn("docker-network-rm", stages)

    def test_foreign_container_label_is_never_stopped(self) -> None:
        name = "gate0-policy-proof-" + "a" * 32
        stages: list[str] = []

        def fake_command(argv: list[str], *, stage: str | None = None) -> str:
            assert stage is not None
            stages.append(stage)
            if stage == "docker-container-list":
                return name
            if stage == "docker-container-inspect":
                return "foreign-instance"
            self.fail(f"unexpected fixture stage: {stage}")

        with patch.object(proof, "command", side_effect=fake_command):
            with self.assertRaisesRegex(ProofFailure, "without its instance label"):
                stop_container(name)
        self.assertNotIn("docker-stop", stages)

    def test_unexpected_exception_keeps_original_and_checks_both_resources(
        self,
    ) -> None:
        name = "gate0-policy-proof-" + "a" * 32
        network = name + "-net"
        original = OSError("private-value-must-not-be-rendered")
        checked: list[str] = []

        def stop_owned_container(owned_name: str) -> None:
            checked.append(owned_name)

        def stop_owned_network(owned_network: str) -> None:
            checked.append(owned_network)
            raise ProofFailure("required command failed: docker-network-rm")

        with (
            patch.object(
                proof,
                "start_container",
                return_value=(name, network, "172.18.0.2", IMAGE_ID),
            ),
            patch.object(proof, "initialize", side_effect=original),
            patch.object(proof, "stop_container", side_effect=stop_owned_container),
            patch.object(proof, "stop_network", side_effect=stop_owned_network),
        ):
            with self.assertRaises(OSError) as caught:
                run(IMAGE)
        self.assertIs(caught.exception, original)
        self.assertEqual(checked, [name, network])
        self.assertIn("fixture cleanup failed", caught.exception.__notes__[0])
        self.assertNotIn("private-value", caught.exception.__notes__[0])

    def test_keyboard_interrupt_checks_both_resources(self) -> None:
        name = "gate0-policy-proof-" + "b" * 32
        network = name + "-net"
        checked: list[str] = []
        with (
            patch.object(
                proof,
                "start_container",
                return_value=(name, network, "172.18.0.3", IMAGE_ID),
            ),
            patch.object(proof, "initialize", side_effect=KeyboardInterrupt()),
            patch.object(
                proof,
                "stop_container",
                side_effect=lambda owned_name: checked.append(owned_name),
            ),
            patch.object(
                proof,
                "stop_network",
                side_effect=lambda owned_network: checked.append(owned_network),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                run(IMAGE)
        self.assertEqual(checked, [name, network])

    def test_cli_redacts_unexpected_exception(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                proof,
                "run",
                side_effect=ValueError("private-value-must-not-be-rendered"),
            ),
            patch("sys.stderr", output),
        ):
            self.assertEqual(main(["--image", IMAGE]), 1)
        self.assertEqual(
            output.getvalue(),
            "OpenBao SSH-policy conformance failed: unexpected driver error\n",
        )

    def test_api_transport_disables_proxies_and_redirects(self) -> None:
        with patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:9"}):
            opener = api_opener()
        proxy_handlers = [
            handler
            for handler in opener.handlers
            if handler.__class__.__name__ == "ProxyHandler"
        ]
        # urllib omits an explicitly empty ProxyHandler from .handlers; the
        # inherited environment proxy handler must therefore be absent.
        self.assertEqual(proxy_handlers, [])
        redirects = [
            handler
            for handler in opener.handlers
            if handler.__class__.__name__ == "NoRedirect"
        ]
        self.assertEqual(len(redirects), 1)
        self.assertIsNone(
            redirects[0].redirect_request(
                None, None, 302, "", {}, "http://example.invalid"
            )
        )

    def test_container_address_is_owned_single_network_rfc1918(self) -> None:
        name = "gate0-policy-proof-" + "a" * 32
        network = name + "-net"

        def document(
            address: str,
            *,
            label: str | None = None,
            networks: dict[str, object] | None = None,
        ) -> str:
            return json.dumps(
                [
                    {
                        "Name": f"/{name}",
                        "Config": {
                            "Labels": {"dotmac.gate0-policy-instance": label or name}
                        },
                        "NetworkSettings": {
                            "Networks": networks or {network: {"IPAddress": address}}
                        },
                    }
                ]
            )

        with patch.object(proof, "command", return_value=document("172.18.0.2")):
            self.assertEqual(container_address(name, network), "172.18.0.2")
        self.assertEqual(Bao("172.18.0.2").origin, "http://172.18.0.2:8200/v1/")
        for address in (
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",  # noqa: S104 - refusal case, never a listener address
            "192.0.2.10",
            "8.8.8.8",
            "::1",
            "not-an-ip",
        ):
            with self.subTest(address=address):
                with patch.object(proof, "command", return_value=document(address)):
                    with self.assertRaises(ProofFailure):
                        container_address(name, network)
                with self.assertRaises(ProofFailure):
                    Bao(address)
        with patch.object(
            proof, "command", return_value=document("172.18.0.2", label="foreign")
        ):
            with self.assertRaisesRegex(ProofFailure, "instance label"):
                container_address(name, network)
        with patch.object(
            proof,
            "command",
            return_value=document(
                "172.18.0.2",
                networks={
                    network: {"IPAddress": "172.18.0.2"},
                    "bridge": {"IPAddress": "172.17.0.2"},
                },
            ),
        ):
            with self.assertRaisesRegex(ProofFailure, "one internal network"):
                container_address(name, network)

    def test_report_accepts_only_fixed_public_fields_and_complete_cases(self) -> None:
        report = safe_report(
            image=IMAGE, image_id=IMAGE_ID, version="2.5.3", passed=list(CASE_NAMES)
        )
        self.assertEqual(report["passed_count"], len(CASE_NAMES))
        self.assertEqual(
            set(report),
            {
                "schema",
                "scope",
                "image",
                "image_id",
                "server_version",
                "passed_cases",
                "passed_count",
            },
        )
        with self.assertRaises(ProofFailure):
            safe_report(
                image=IMAGE, image_id=IMAGE_ID, version="2.5.4", passed=list(CASE_NAMES)
            )
        with self.assertRaises(ProofFailure):
            safe_report(
                image=IMAGE,
                image_id=IMAGE_ID,
                version="2.5.3",
                passed=list(CASE_NAMES[:-1]),
            )
        self.assertIsNone(IMAGE_RE.fullmatch("openbao/openbao:2.5.3"))

    def test_refusal_fails_on_success_or_unexpected_status(self) -> None:
        def rejected() -> None:
            raise ApiStatus(403)

        self.assertEqual(refused(rejected, "private_read"), "private_read")
        with self.assertRaises(ProofFailure):
            refused(lambda: None, "private_read")
        with self.assertRaises(ProofFailure):
            refused(lambda: (_ for _ in ()).throw(ApiStatus(500)), "private_read")

    def test_parser_reads_real_openssh_certificate(self) -> None:
        with TemporaryDirectory(prefix="gate0-cert-parser-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            ca = directory / "ca"
            user = directory / "user"
            for key in (ca, user):
                command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
            command(
                [
                    "ssh-keygen",
                    "-q",
                    "-s",
                    str(ca),
                    "-I",
                    "fixture-run",
                    "-n",
                    PRINCIPAL,
                    "-O",
                    "clear",
                    "-O",
                    f"source-address={SOURCE_ADDRESS}",
                    str(user.with_suffix(".pub")),
                ]
            )
            verify_certificate(
                directory / "user-cert.pub",
                user.with_suffix(".pub"),
                key_id="fixture-run",
                address=SOURCE_ADDRESS,
            )
            with self.assertRaises(ProofFailure):
                verify_certificate(
                    directory / "user-cert.pub",
                    user.with_suffix(".pub"),
                    key_id="fixture-run",
                    address="198.51.100.0/24",
                )


if __name__ == "__main__":
    unittest.main()
