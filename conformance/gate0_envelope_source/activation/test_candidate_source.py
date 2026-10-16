"""AUTHORED, NOT EXECUTED. Synthetic source qualification, never native evidence."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, mock_open, patch

import render as renderer
from native_readback import PUBLIC_ENV, fixed_exec_start, show_vector, timespan_us

ROOT = Path(__file__).parent


def fixture():
    document = dict(
        schema="DotmacGate0R4CandidateInputs.v1",
        purpose="synthetic-test-only",
        source_revision=renderer.REVISION,
        design_sha256=renderer.DESIGN,
        review_sha256=renderer.REVIEW,
        campaign="a" * 64,
        instances=[],
    )
    for index, (case, role) in enumerate(sorted(renderer.SELECTIONS)):
        instance = "test-only-" + str(index)
        root = "/var/lib/dotmac-gate0/" + "a" * 64 + "/" + case + "-" + role
        unit = "dotmac-gate0-" + instance
        ready, expired, service = (
            unit + "-ready.target",
            unit + "-expired.target",
            unit + ".service",
        )
        rosters = {
            k: {p: [] for p in renderer.DEPENDENCIES}
            for k in ("ready", "timer", "expired", "service")
        }
        rosters["service"].update(
            Requisite=[ready],
            After=[ready, "system.slice"],
            Requires=["system.slice"],
            Conflicts=[expired],
        )
        rosters["ready"].update(Before=[service], Conflicts=[expired])
        rosters["timer"]["Before"] = [expired]
        rosters["expired"]["Conflicts"] = [ready, service]
        inside = (
            "/usr/local/libexec/dotmac-gate0/"
            + "a" * 64
            + "/"
            + case
            + "-"
            + role
            + "-inside"
        )

        def mount(destination, kind, source, options):
            return dict(
                destination=destination, type=kind, source=source, options=options
            )

        mounts = [
            mount(
                "/run/dotmac-gate0",
                "bind",
                root + "/runtime-tmpfs",
                ["rw", "nodev", "nosuid", "noexec"],
            ),
            mount(
                "/sys/fs/cgroup",
                "cgroup2",
                "cgroup2",
                ["rw", "nodev", "nosuid", "noexec"],
            ),
            mount("/proc", "proc", "proc", ["nodev", "nosuid", "noexec"]),
            mount("/sys", "sysfs", "sysfs", ["ro"]),
            mount("/etc/machine-id", "bind", "/etc/machine-id", ["ro"]),
        ]
        if role == "attester":
            mounts += [
                mount(
                    # Fixed OCI metadata/synthetic input; no temporary file opened here.
                    "/tmp",  # noqa: S108
                    "bind",
                    root + "/auth-tmpfs",
                    ["rw", "nodev", "nosuid", "noexec"],
                ),
                mount(
                    "/run/dotmac-gate0/auth-info",
                    "bind",
                    root + "/auth-tmpfs",
                    ["rw", "nodev", "nosuid", "noexec"],
                ),
            ]
        else:
            mounts += [
                # Fixed OCI metadata/synthetic input; no temporary file opened here.
                mount("/tmp", "tmpfs", "tmpfs", ["rw", "nodev", "nosuid", "noexec"]),  # noqa: S108
                mount(
                    "/run/dotmac-gate0/management/identity",
                    "bind",
                    root + "/sender-identity",
                    ["ro"],
                ),
            ]
        item = dict(
            case=case,
            role=role,
            instance=instance,
            boot_id="11111111-1111-1111-1111-111111111111",
            not_before_wall_us=1_000_000_000,
            not_before_mono_us=20_000_000,
            e_wall_us=1_100_000_000,
            e_mono_us=120_000_000,
            r_us=20_000_000,
            t_us=5_000_000,
            s_us=135_000_000,
            c_us=140_000_000,
            accuracy_us=1,
            cpu_quota_percent=50,
            memory_max_bytes=1_000_000,
            tasks_max=50,
            diagnostic_max_bytes=8192,
            python_path="/usr/bin/python3.12",
            manager_version="255.4",
            kernel_release="test-only",
            netns_device=1,
            netns_inode=123,
            rosters=rosters,
            service_readback=dict(
                FragmentPath="/run/systemd/transient/" + service,
                ExecStart="{ path="
                + inside
                + " ; argv[]="
                + inside
                + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
                " ; pid=123 ; code=(null) ; status=0/0 }",
                TimeoutStopUSec="5s",
                CPUQuotaPerSecUSec="500ms",
                MemoryMax="1000000",
                TasksMax="50",
            ),
            oci=dict(
                version="1.1.0",
                env=list(PUBLIC_ENV),
                cwd="/app",
                apparmor_profile="test-only",
                mounts=mounts,
                devices=[],
                device_allowlist=[],
                seccomp=dict(
                    defaultAction="SCMP_ACT_ERRNO",
                    architectures=["SCMP_ARCH_X86_64"],
                    syscalls=[],
                ),
                masked_paths=[],
                readonly_paths=[],
            ),
            public_pins={
                k: dict(sha256="1" * 64, mode=0o600, size=1)
                for k in (
                    "systemd_run",
                    "systemctl",
                    "runc",
                    "python",
                    "manager",
                    "machine_id",
                    "public_packet",
                    "local_packet",
                    "network",
                    "native_proof",
                    "rootfs_manifest",
                )
            },
        )
        for key in (
            "image_digest",
            "rootfs_tree_digest",
            "uid_review_digest",
            "network_measurement_digest",
            "clock_mapping_digest",
            "native_proof_digest",
        ):
            item[key] = "1" * 64
        document["instances"].append(item)
    return document


def templates():
    return {p.name: p.read_text() for p in ROOT.glob("*.in")}


def runtime(public):
    source = (
        (ROOT / "runtime-checks.py.in")
        .read_text()
        .replace("@@PUBLIC_LITERAL@@", repr(public))
        .replace(
            "@@NATIVE_READBACK_SOURCE@@", (ROOT / "native_readback.py").read_text()
        )
    )
    namespace = {"os": os}
    # Fixed synthetic template only; all native boundaries mocked.
    exec(compile(source, "synthetic-runtime-checks", "exec"), namespace)  # noqa: S102
    return namespace


class CandidateSourceTests(unittest.TestCase):
    def test_positive_four_instances_and_canonical_reorder(self):
        document = fixture()

        def reverse(v):
            if isinstance(v, dict):
                return {k: reverse(x) for k, x in reversed(list(v.items()))}
            if isinstance(v, list):
                return [reverse(x) for x in v]
            return v

        output = renderer.candidate_files(document, templates())
        self.assertEqual(len(output), 24)
        scripts = [
            v.decode() for k, v in output.items() if k.startswith("/usr/local/libexec/")
        ]
        self.assertEqual(len(scripts), 8)
        self.assertTrue(all("'fixture_only': True" in s for s in scripts))
        self.assertEqual(
            renderer.canonical(document), renderer.canonical(reverse(document))
        )
        self.assertEqual(
            output, renderer.candidate_files(reverse(document), templates())
        )

    def test_native_timespans_and_bad_precision(self):
        for raw, expected in {
            "0": 0,
            "1us": 1,
            "1.001ms": 1001,
            "1.000001s": 1000001,
            "2h 1min 2.000003s": 7262000003,
            "1month 1d": 2716200000000,
        }.items():
            self.assertEqual(timespan_us(raw), expected)
        for raw in (
            "infinity",
            "1000000",
            "0us",
            "1.0000001s",
            "1.1us",
            "1s 1s",
            "1us 1s",
            "1s  1us",
            "01s",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                timespan_us(raw)

    def test_manager_omission_and_pid_strings(self):
        self.assertEqual(show_vector("", ["Version"])[-1], "--property=Version")
        self.assertNotIn("", show_vector("", ["Version"]))
        ns = runtime(dict(fixture_only=False, e_mono_us=10**18, s_us=10**18))
        ns["clocks"] = lambda: None

        class Result:
            returncode = 0
            stdout = b"MainPID=123\n"

        with patch.object(ns["subprocess"], "run", return_value=Result()) as call:
            self.assertEqual(
                ns["show"]("fixed.service", ["MainPID"]), {"MainPID": "123"}
            )
            self.assertEqual(call.call_args.args[0][-1], "fixed.service")

    def test_lower_bounds_and_window_duration(self):
        item = fixture()["instances"][0]
        for wall, mono in (
            (999_999_999, 20_000_000),
            (1_000_000_000, 19_999_999),
            (1_100_000_000, 120_000_000),
        ):
            ns = runtime(
                {
                    "fixture_only": False,
                    **{
                        k: item[k]
                        for k in (
                            "boot_id",
                            "not_before_wall_us",
                            "not_before_mono_us",
                            "e_wall_us",
                            "e_mono_us",
                            "s_us",
                        )
                    },
                }
            )
            with (
                patch("builtins.open", mock_open(read_data=item["boot_id"] + "\n")),
                patch.object(ns["os"], "geteuid", return_value=0),
                patch.object(ns["time"], "time_ns", return_value=wall * 1000),
                patch.object(ns["time"], "monotonic_ns", return_value=mono * 1000),
                self.assertRaises(SystemExit),
            ):
                ns["clocks"]()
        for changes in (
            {"not_before_wall_us": 1_100_000_000},
            {"not_before_mono_us": 1},
            {"not_before_wall_us": 1, "not_before_mono_us": 1},
        ):
            document = fixture()
            document["instances"][0].update(changes)
            with self.assertRaises(ValueError):
                renderer.candidate_files(document, templates())

    def test_fixed_semantics_and_env_tamper(self):
        for key, bad in (
            ("TimeoutStopUSec", "6s"),
            ("CPUQuotaPerSecUSec", "1s"),
            (
                "ExecStart",
                "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no ; }",
            ),
        ):
            document = fixture()
            document["instances"][0]["service_readback"][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                renderer.candidate_files(document, templates())
        for key, value in (
            ("env", PUBLIC_ENV + ["PYTHONPATH=/tmp"]),
            ("env", PUBLIC_ENV + ["TOKEN=test-only"]),
            ("env", PUBLIC_ENV + [PUBLIC_ENV[0]]),
            # Fixed OCI metadata/synthetic input; no temporary file opened here.
            ("cwd", "/tmp"),  # noqa: S108
        ):
            document = fixture()
            document["instances"][0]["oci"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                renderer.candidate_files(document, templates())
        inside = "/fixed-inside"
        good = (
            "{ path="
            + inside
            + " ; argv[]="
            + inside
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
            " ; pid=123 ; code=(null) ; status=0/0 }"
        )
        self.assertTrue(fixed_exec_start(good, inside))
        with self.assertRaises(ValueError):
            fixed_exec_start(
                good.replace("argv[]=" + inside, "argv[]=" + inside + " extra"), inside
            )

    def test_output_symlink_nooverwrite_and_retained_directory_fd(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(OSError):
                renderer.create_output_directory(root / "link" / "out")
            fd = renderer.create_output_directory(root / "out")
            try:
                with self.assertRaises(OSError):
                    renderer.create_output_directory(root / "out")
                (root / "out").rename(root / "retained")
                (root / "out").symlink_to(root / "real", target_is_directory=True)
                renderer.write_candidate(fd, "safe.candidate", b"test-only")
                self.assertEqual(
                    (root / "retained" / "safe.candidate").read_bytes(), b"test-only"
                )
                self.assertFalse((root / "real" / "safe.candidate").exists())
                with self.assertRaises(OSError):
                    renderer.write_candidate(fd, "safe.candidate", b"overwrite")
            finally:
                os.close(fd)

    def test_descriptor_binding_rejects_substitution_and_quota(self):
        ns = runtime(
            dict(
                fixture_only=False,
                diagnostic_max_bytes=8192,
                descriptor_path="/test-only/binding",
                diagnostic_path="/test-only/diagnostics",
            )
        )
        ns["protected"] = lambda *a, **k: 17

        class Metadata:
            st_mode = 0o100600
            st_size = 3
            st_dev = 1
            st_ino = 17
            st_rdev = 0

        identity_probe = Mock(wraps=ns["descriptor_identity"])
        with (
            patch.object(ns["os"], "fstat", return_value=Metadata()),
            patch.object(ns["os"], "read", return_value=b"{}\n"),
            patch.object(ns["os"], "close"),
            patch.dict(ns, descriptor_identity=identity_probe),
        ):
            with self.assertRaises(SystemExit) as substituted:
                ns["verify_descriptors"]()
        self.assertEqual(identity_probe.call_args_list, [call(0), call(1), call(2)])
        self.assertEqual(substituted.exception.code, 125)
        # Full valid identity map, but inherited hard/soft bound is wrong.
        ns["descriptor_identity"] = lambda fd: dict(
            device=1, inode=fd, type=0o100000, rdev=0
        )
        binding = {str(fd): ns["descriptor_identity"](fd) for fd in (0, 1, 2)}
        import json

        raw = json.dumps(binding).encode()

        class File:
            st_mode = 0o100600
            st_size = len(raw)
            st_dev = 1
            st_ino = 2
            st_rdev = 0

        class Null:
            st_mode = 0o20666
            st_rdev = os.makedev(1, 3)

        def metadata(fd):
            return Null() if fd == 0 else File()

        with (
            patch.object(ns["os"], "fstat", side_effect=metadata),
            patch.object(ns["os"], "read", return_value=raw),
            patch.object(ns["os"], "close"),
            patch.object(
                ns["resource"], "getrlimit", return_value=(9999, 9999)
            ) as quota,
        ):
            with self.assertRaises(SystemExit) as refused:
                ns["verify_descriptors"]()
        quota.assert_called_once_with(ns["resource"].RLIMIT_FSIZE)
        self.assertEqual(refused.exception.code, 125)


if __name__ == "__main__":
    unittest.main()
