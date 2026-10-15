"""Source fixtures only; protected native installation is separate evidence."""

# ruff: noqa: F811 -- pytest injects imported fixture names.

import os
import stat
from types import SimpleNamespace

import pytest
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_runner_installation as loader
from vendor_cp.deployment.gate0_role_custody import ProviderRefused


def fake_files(monkeypatch, *, kind=stat.S_IFREG, owner=0, mode=0o600):
    opened = []
    closed = []

    def open_file(path, flags, *, dir_fd=None):
        opened.append((path, flags, dir_fd))
        return len(opened) + 10

    def metadata(fd):
        is_file = fd == 13
        return SimpleNamespace(
            st_mode=(kind | mode) if is_file else stat.S_IFDIR | 0o755,
            st_uid=owner if is_file else 0,
            st_size=3,
            st_dev=1,
            st_ino=fd,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

    reads = iter([b"abc", b""])
    monkeypatch.setattr(loader.os, "open", open_file)
    monkeypatch.setattr(loader.os, "fstat", metadata)
    monkeypatch.setattr(loader.os, "close", closed.append)
    monkeypatch.setattr(loader.os, "read", lambda *_: next(reads))
    return opened, closed


def test_held_ancestor_walk_and_nofollow_nonblocking(monkeypatch):
    opened, closed = fake_files(monkeypatch)
    assert loader._protected_read("/run/input") == b"abc"
    assert opened[1][2] == 11 and opened[2][2] == 12
    assert all(
        flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK for _, flags, _ in opened
    )
    assert sorted(closed) == [11, 12, 13]


@pytest.mark.parametrize(
    "kind,owner,mode",
    [
        (stat.S_IFIFO, 0, 0o600),
        (stat.S_IFLNK, 0, 0o600),
        (stat.S_IFREG, 5, 0o600),
        (stat.S_IFREG, 0, 0o622),
    ],
)
def test_fifo_symlink_owner_and_write_modes_refuse_before_read(
    monkeypatch, kind, owner, mode
):
    _, closed = fake_files(monkeypatch, kind=kind, owner=owner, mode=mode)
    monkeypatch.setattr(loader.os, "read", lambda *_: pytest.fail("read unsafe object"))
    with pytest.raises(ProviderRefused):
        loader._protected_read("/run/input")
    assert 13 in closed


@pytest.mark.parametrize(
    "path", ["relative", "/run/../secret", "/run//input", "/run/./input"]
)
def test_noncanonical_path_refuses(path):
    with pytest.raises(ProviderRefused):
        loader._protected_read(path)


def test_installed_entry_has_no_path_override():
    with pytest.raises(TypeError):
        loader.InstalledRunnerCollection.from_installed("/workflow/input")


def test_job_qualification_binds_actual_uid_and_run(monkeypatch):
    installed = loader.InstalledRunnerCollection(
        "sha256:" + "1" * 64,
        12,
        13,
        "https://cp.example",
        None,
        b"{}",
        (),
        "human-reference",
        "/fixed",
        "/fixed/claimed",
        b"{}",
    )
    monkeypatch.setattr(loader.os, "getuid", lambda: 11)
    with pytest.raises(ProviderRefused):
        installed.require_actual_job()


def test_trust_record_cannot_synthesize_floor_or_accept_revoked_key(monkeypatch):
    import base64
    import hashlib

    from vendor_cp.deployment.gate0_framing import canonical

    key = bytes(32)
    role = {"key_id": "issuer", "public_key_b64": base64.b64encode(key).decode()}
    values = {
        "record": canonical(
            {
                "version": 1,
                "trusted_key_ids": {
                    "issuer": "sha256:" + hashlib.sha256(key).hexdigest()
                },
                "revoked_key_ids": ["issuer"],
            }
        ),
        "floor": canonical(
            {"key_id": "issuer", "minimum_version": 1, "source_ref": "qualified"}
        ),
        "qualification": b"native",
    }
    monkeypatch.setattr(
        loader,
        "_read_pin",
        lambda value: (SimpleNamespace(sha256="1" * 64), values[value]),
    )
    with pytest.raises(ProviderRefused):
        loader._trust(
            dict(
                record="record",
                floor="floor",
                qualification="qualification",
                source_ref="qualified",
            ),
            role,
        )


@pytest.mark.parametrize(
    "changed",
    [
        "case_kind",
        "launch_packet_digest",
        "local_packet_digest",
        "window_digest",
        "machine_id_digest",
        "not_before",
        "expires_at",
    ],
)
def test_case_root_terms_cannot_be_swapped_before_ssh_or_trust(monkeypatch, changed):
    from datetime import UTC, datetime

    from vendor_cp.deployment.gate0_framing import canonical

    shared, frozen, local_raw = b"shared", b"frozen", b"local"
    packet = {
        "capture": {"window_digest": "sha256:" + "1" * 64},
        "case_kind": "consume_replay",
        "not_before": "2026-10-15T00:00:00Z",
        "expires_at": "2026-10-15T00:05:00Z",
    }
    local = {
        "host_role": "issuer",
        "shared_run_digest": loader._hash(shared),
        "capture": packet["capture"],
        "run_end": packet["expires_at"],
        "machine_id_digest": "sha256:" + "2" * 64,
    }
    binding = dict(
        host_role="issuer",
        case_kind=packet["case_kind"],
        launch_packet_digest=loader._hash(shared),
        local_packet_digest=loader._hash(local_raw),
        window_digest=packet["capture"]["window_digest"],
        machine_id_digest=local["machine_id_digest"],
        network_measurement_digest="sha256:" + "3" * 64,
        not_before=packet["not_before"],
        expires_at=packet["expires_at"],
    )
    binding[changed] = (
        ("sha256:" + "9" * 64)
        if changed.endswith("digest")
        else (
            "withdrawal_later_use" if changed == "case_kind" else "2026-10-15T01:00:00Z"
        )
    )
    selected = SimpleNamespace(
        window=SimpleNamespace(document={}, digest=packet["capture"]["window_digest"])
    )
    monkeypatch.setattr(loader, "RunnerProjectionCase", lambda *_: selected)
    monkeypatch.setattr(loader, "parse_run_document", lambda _: packet)
    monkeypatch.setattr(loader, "_local_packet", lambda _: local)
    values = {"shared": shared, "frozen": frozen, "local": local_raw}
    monkeypatch.setattr(loader, "_read_pin", lambda value: (None, values[value]))
    fields = (
        "shared_packet frozen_window command_id hosts ssh_binary keygen "
        "private_key certificate known_hosts issuer_trust attester_trust"
    ).split()
    document = dict.fromkeys(fields)
    document.update(
        shared_packet="shared",
        frozen_window="frozen",
        hosts={
            "IDP3": {"binding": binding, "local_packet": "local", "endpoint": None},
            "NS3": None,
        },
    )
    assert canonical(binding)
    with pytest.raises(ProviderRefused):
        loader._case(document, 12, datetime.now(UTC), 1.0)


@pytest.fixture
def installed_model(window_document, monkeypatch):
    """Complete closed real DTOs; only protected OS reads/runtime identity isolated.

    No semantic campaign is run. Certificates are deterministic test-only public
    fixture bytes; this creates no installed key or production qualification.
    """
    import base64
    import hashlib
    from copy import deepcopy
    from datetime import UTC, datetime, timedelta
    from pathlib import Path
    from uuid import UUID

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        SSHCertificateBuilder,
        SSHCertificateType,
    )
    from test_gate0_launch import synthetic_local_packet

    from vendor_cp.deployment.gate0_attester import ssh_public_fingerprint
    from vendor_cp.deployment.gate0_framing import canonical
    from vendor_cp.deployment.gate0_window import FrozenIssuerWindow

    files = {}

    def pin(path, raw):
        files[path] = raw
        return {"path": path, "digest": loader._hash(raw)}

    root = "/run/dotmac-gate0-collector"
    source_names = (
        "gate0_runner_installation",
        "gate0_runner_tokens",
        "gate0_runner_ssh",
        "gate0_runner_handoff",
        "gate0_runner_collector_handoff",
        "gate0_collection",
    )
    descriptor = {
        "schema": "Gate0RunnerCollectionInstallation.v1",
        "campaign_digest": "sha256:" + "a" * 64,
        "collector_uid": 1001,
        "receiver_uid": 1002,
        "origin": "https://cp.example",
        "broker": {
            "origin": "https://broker.example",
            "path": "/job/2/token",
            "query": "api-version=2&job=2",
            "qualification": pin(
                root + "/broker-native", b"independent-broker-receipt"
            ),
        },
        "job": dict(
            window_document["github"], runner_group_id="42", runner_name="isolated-a9"
        ),
        "source_revision": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "executable": pin("/usr/bin/python3", b"qualified-interpreter"),
        "source_files": {
            name: pin(
                str(Path(loader.__file__).parent / (name + ".py")),
                ("qualified-source:" + name).encode(),
            )
            for name in source_names
        },
        "holder_qualification": pin(root + "/holder-native", b"qualified-holder"),
        "receiver_qualification": pin(root + "/receiver-native", b"qualified-receiver"),
        "qualification": None,
        "cases": [],
        "withdrawal_reference": "human-B-withdrawal",
        "output_directory": root + "/session/evidence",
        "marker": root + "/session/claimed",
    }
    now = datetime.now(UTC).replace(microsecond=0)
    ca = Ed25519PrivateKey.from_private_bytes(bytes([80]) * 32)
    for index, kind in enumerate(("consume_replay", "withdrawal_later_use")):
        start = (
            now - timedelta(seconds=2) if index == 0 else now + timedelta(seconds=121)
        )
        end = now + timedelta(seconds=120 if index == 0 else 240)
        key = Ed25519PrivateKey.from_private_bytes(bytes([index + 1]) * 32)
        certificate = (
            SSHCertificateBuilder()
            .public_key(key.public_key())
            .serial(index + 1)
            .type(SSHCertificateType.USER)
            .key_id(("case-" + str(index)).encode())
            .valid_principals([b"dotmac-gate0-controller"])
            .valid_after(int(start.timestamp()))
            .valid_before(int(end.timestamp()))
            .sign(ca)
            .public_bytes()
        )
        window_doc = deepcopy(window_document)
        window_doc.update(
            case_kind=kind,
            window_id="window-" + str(index),
            not_before=start.isoformat().replace("+00:00", "Z"),
            expires_at=end.isoformat().replace("+00:00", "Z"),
        )
        window_doc["controller"].update(
            lease_id="lease-" + str(index),
            fingerprint=ssh_public_fingerprint(key.public_key()),
            certificate_digest=loader._hash(certificate),
            ca_fingerprint=ssh_public_fingerprint(ca.public_key()),
        )
        window = FrozenIssuerWindow.parse(canonical(window_doc))
        public = bytes([11]) * 32
        role = dict(
            key_id="public-role",
            public_key_b64=base64.b64encode(public).decode(),
            source_revision="c" * 40,
            image_digest="sha256:" + "d" * 64,
            profile_digest="sha256:" + "e" * 64,
        )
        packet = dict(
            schema="Gate0RunIdentity.v1",
            run_id=window_doc["github"]["run_id"],
            run_attempt=window_doc["github"]["run_attempt"],
            case_kind=kind,
            not_before=window_doc["not_before"],
            expires_at=window_doc["expires_at"],
            capture=dict(
                window_digest=window.digest,
                plan_id=str(UUID(int=20 + index)),
                plan_digest="sha256:" + str(index + 1) * 64,
                target_id=window_doc["target"]["id"],
                approval_request_id=str(UUID(int=30 + index)),
            ),
            roles={"issuer": role, "attester": role},
            controller_ca_fingerprint=window_doc["controller"]["ca_fingerprint"],
            management_key_fingerprint=window_doc["controller"]["fingerprint"],
        )
        shared = canonical(packet)
        prefix = root + "/case-" + str(index)
        case = dict(
            shared_packet=pin(prefix + "/shared", shared),
            frozen_window=pin(prefix + "/window", window.canonical_bytes),
            command_id=str(UUID(int=40 + index)),
            hosts={},
            ssh_binary=pin("/usr/bin/ssh", b"ssh"),
            keygen=pin("/usr/bin/ssh-keygen", b"keygen"),
            private_key=pin(
                prefix + "/private",
                key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()),
            ),
            certificate=pin(prefix + "/certificate", certificate),
            known_hosts=pin(
                prefix + "/known-hosts",
                b"\n".join(
                    (host.lower() + "-" + str(index)).encode()
                    + b" "
                    + Ed25519PrivateKey.from_private_bytes(bytes([90 + number]) * 32)
                    .public_key()
                    .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                    for number, host in enumerate(("IDP3", "NS3"))
                )
                + b"\n",
            ),
        )
        for host, host_role in (("IDP3", "issuer"), ("NS3", "attester")):
            local = synthetic_local_packet()
            if host_role == "attester":
                for field in (
                    "issuer_uid",
                    "capture_sender_uid",
                    "management_identity",
                    "cli_digest",
                    "issuer_sshd_config_digest",
                ):
                    del local[field]
                local.update(
                    attester_uid=1201,
                    management_uid=1202,
                    sshd_config_digest="sha256:" + "4" * 64,
                    management_sshd_config_digest="sha256:" + "5" * 64,
                )
                from vendor_cp.deployment.gate0_launch import SLOTS

                local["installation_digests"] = {
                    slot: "sha256:" + "6" * 64 for slot in (*SLOTS, "management")
                }
                local["ssh_endpoints"] = {
                    name: dict(
                        local_address="10.0.0.1",
                        local_port=2224 if name == "attester" else 2225,
                        remote_address="10.0.0.3",
                    )
                    for name in ("management", "attester")
                }
            local.update(
                host_role=host_role,
                run_end=packet["expires_at"],
                shared_run_digest=loader._hash(shared),
                capture=packet["capture"],
            )
            local_raw = canonical(local)
            binding = dict(
                host_role=host_role,
                case_kind=kind,
                launch_packet_digest=loader._hash(shared),
                local_packet_digest=loader._hash(local_raw),
                window_digest=window.digest,
                machine_id_digest=local["machine_id_digest"],
                network_measurement_digest="sha256:" + "7" * 64,
                not_before=packet["not_before"],
                expires_at=packet["expires_at"],
            )
            case["hosts"][host] = dict(
                binding=binding,
                local_packet=pin(prefix + "/" + host, local_raw),
                endpoint=dict(
                    host="10.0.0.1",
                    port=2224,
                    source="10.0.0.3",
                    user="fixed-" + host_role,
                    host_key_alias=host.lower() + "-" + str(index),
                ),
            )
        for role_name in ("issuer", "attester"):
            case[role_name + "_trust"] = dict(
                record=pin(
                    prefix + "/" + role_name + "-trust",
                    canonical(
                        dict(
                            version=7,
                            trusted_key_ids={
                                "public-role": "sha256:"
                                + hashlib.sha256(public).hexdigest()
                            },
                            revoked_key_ids=[],
                        )
                    ),
                ),
                floor=pin(
                    prefix + "/" + role_name + "-floor",
                    canonical(
                        dict(
                            key_id="public-role",
                            minimum_version=7,
                            source_ref="qualified-public-source",
                        )
                    ),
                ),
                source_ref="qualified-public-source",
                qualification=pin(
                    prefix + "/" + role_name + "-native", b"native-public-trust"
                ),
            )
        descriptor["cases"].append(case)

    def seal():
        accepted = dict(
            schema="Gate0RunnerCollectionQualification.v1",
            campaign_digest=descriptor["campaign_digest"],
            collector_uid=descriptor["collector_uid"],
            receiver_uid=descriptor["receiver_uid"],
            job=descriptor["job"],
            source_revision=descriptor["source_revision"],
            image_digest=descriptor["image_digest"],
            executable_digest=descriptor["executable"]["digest"],
            installation_digest=loader._hash(
                canonical({k: v for k, v in descriptor.items() if k != "qualification"})
            ),
            holder_qualification_digest=descriptor["holder_qualification"]["digest"],
            receiver_qualification_digest=descriptor["receiver_qualification"][
                "digest"
            ],
            broker={k: descriptor["broker"][k] for k in ("origin", "path", "query")},
            native_receipt_digest="sha256:" + "8" * 64,
        )
        accepted["broker"]["qualification_digest"] = descriptor["broker"][
            "qualification"
        ]["digest"]
        descriptor["qualification"] = pin(
            root + "/native-qualification", canonical(accepted)
        )
        files[loader._INSTALLATION] = canonical(descriptor)

    seal()
    env = {
        "GITHUB_REPOSITORY": "repository",
        "GITHUB_REPOSITORY_ID": "repository_id",
        "GITHUB_REPOSITORY_OWNER_ID": "repository_owner_id",
        "GITHUB_RUN_ID": "run_id",
        "GITHUB_RUN_ATTEMPT": "run_attempt",
        "GITHUB_REF": "ref",
        "GITHUB_WORKFLOW_REF": "workflow_ref",
        "GITHUB_WORKFLOW_SHA": "workflow_sha",
        "GITHUB_EVENT_NAME": "event_name",
        "RUNNER_GROUP_ID": "runner_group_id",
        "RUNNER_NAME": "runner_name",
    }
    for name, key in env.items():
        monkeypatch.setenv(name, descriptor["job"][key])
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "https://broker.example/job/2/token?api-version=2&job=2",
    )
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "actual-job-test-credential")
    monkeypatch.setattr(loader.os, "getuid", lambda: 1001)
    monkeypatch.setattr(loader.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(loader.os, "readlink", lambda _: "/usr/bin/python3")
    monkeypatch.setattr(loader, "_protected_read", lambda path, **_: files[path])
    return SimpleNamespace(descriptor=descriptor, files=files, seal=seal, pin=pin)


def test_complete_root_descriptor_loads_with_future_b_inert(
    installed_model, monkeypatch
):
    from vendor_cp.deployment.gate0_runner_ssh import (
        OwnedAttesterSession,
        OwnedIssuerSession,
    )
    from vendor_cp.deployment.gate0_runner_tokens import InstalledJobTokens
    from vendor_cp.deployment.gate0_runtime import BoundedHarnessVerifier

    def premature(*_, **__):
        pytest.fail("inert installation activated trust/verifier/SSH/token")

    monkeypatch.setattr(loader.RehearsalIssuerTrustState, "start", premature)
    monkeypatch.setattr(loader.RunnerSshInstallation, "__init__", premature)
    monkeypatch.setattr(InstalledJobTokens, "from_installed", premature)
    monkeypatch.setattr(OwnedIssuerSession, "__init__", premature)
    monkeypatch.setattr(OwnedAttesterSession, "__init__", premature)
    monkeypatch.setattr(BoundedHarnessVerifier, "__init__", premature)
    installed = loader.InstalledRunnerCollection.from_installed()
    a, b = installed.cases
    assert type(a.projection) is loader.RunnerProjectionCase
    assert a.projection.wall_origin == b.projection.wall_origin
    assert a.projection.monotonic_origin == b.projection.monotonic_origin
    assert a.projection.start < a.projection.monotonic_origin < b.projection.start
    assert a.projection.deadline < b.projection.start
    assert installed.broker.query == "api-version=2&job=2"
    assert (
        b.projection.window.document["github"] == a.projection.window.document["github"]
    )
    assert a.issuer_trust.minimum_version == b.attester_trust.minimum_version == 7


@pytest.mark.parametrize(
    "change",
    [
        "executable-path",
        "executable-bytes",
        "source-path",
        "source-bytes",
        "source-roster",
        "native-qualification",
        "native-receipt-malformed",
        "actual-job",
        "frozen-job",
        "case-swap",
        "case-B-command",
        "case-B-controller",
        "case-B-local",
    ],
)
def test_complete_descriptor_rejects_individual_qualification_and_case_swaps(
    installed_model, monkeypatch, change
):
    from vendor_cp.deployment.gate0_framing import canonical, strict_object

    model, doc = installed_model, installed_model.descriptor
    if change == "executable-path":
        doc["executable"] = model.pin("/other/python3", b"qualified-interpreter")
        model.seal()
    elif change == "executable-bytes":
        model.files[doc["executable"]["path"]] = b"substituted-interpreter"
    elif change == "source-path":
        doc["source_files"]["gate0_runner_tokens"] = model.pin(
            "/other/tokens.py", b"source"
        )
        model.seal()
    elif change == "source-bytes":
        model.files[doc["source_files"]["gate0_runner_tokens"]["path"]] = (
            b"substituted-source"
        )
    elif change == "source-roster":
        del doc["source_files"]["gate0_runner_collector_handoff"]
        model.seal()
    elif change.startswith("native-"):
        receipt = strict_object(model.files[doc["qualification"]["path"]])
        receipt["job"]["runner_name"] = (
            "other-job"
            if change == "native-qualification"
            else receipt["job"]["runner_name"]
        )
        if change == "native-receipt-malformed":
            receipt["native_receipt_digest"] = "not-a-receipt"
        doc["qualification"] = model.pin(
            doc["qualification"]["path"], canonical(receipt)
        )
        model.files[loader._INSTALLATION] = canonical(doc)
    elif change == "actual-job":
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "999")
    elif change == "frozen-job":
        doc["job"]["sub"] = "other-subject"
        model.seal()
    elif change == "case-swap":
        doc["cases"].reverse()
        model.seal()
    elif change == "case-B-command":
        doc["cases"][1]["command_id"] = doc["cases"][0]["command_id"]
        model.seal()
    elif change == "case-B-controller":
        doc["cases"][1]["certificate"] = doc["cases"][0]["certificate"]
        model.seal()
    elif change == "case-B-local":
        doc["cases"][1]["hosts"]["NS3"]["local_packet"] = doc["cases"][0]["hosts"][
            "NS3"
        ]["local_packet"]
        model.seal()
    with pytest.raises(ProviderRefused):
        loader.InstalledRunnerCollection.from_installed()
