"""AUTHORED ONLY. Mocked source tests; never native evidence or installed input."""

import copy
import errno
import struct
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, call, mock_open, patch

import adapter as a
import scratch_helper as h


def fixture(case="pre-guard-stop"):
    record = dict(
        schema="DotmacNativeEnvelopeFixture.v1",
        isolation_scope="disposable-task-vm-only",
        case=case,
        instance="a" * 64,
        boot_id="11111111-1111-1111-1111-111111111111",
        not_before_wall_us=1000000000,
        not_before_mono_us=10000000,
        e_wall_us=1100000000,
        e_mono_us=110000000,
        r_us=20000000,
        t_us=5000000,
        s_us=125000000,
        c_us=130000000,
        accuracy_us=1,
        observer_accuracy_us=1,
        cpu_quota_percent=50,
        memory_max_bytes=1000000,
        tasks_max=50,
        diagnostic_max_bytes=8192,
        evidence_max_bytes=16384,
        manager_version="255.4",
        kernel_release="synthetic-only",
        yama_scope=1,
        libc_abi="linux-x86_64-glibc-ptrace-long",
        image_digest="1" * 64,
        rootfs_tree_digest="1" * 64,
        installation_evidence_digest="1" * 64,
    )
    p = a.paths(record)
    u = p["units"]
    names = (
        "adapter",
        "helper",
        "python",
        "runc",
        "libc",
        "systemd_run",
        "systemctl",
        "manager",
        "bundle_config",
        "rootfs_manifest",
        "installation_evidence",
    ) + tuple(k for k in u if k != "service")
    record["pins"] = {k: dict(sha256="1" * 64, size=1, mode=0o600) for k in names}
    for key in (
        "adapter",
        "helper",
        "python",
        "runc",
        "systemd_run",
        "systemctl",
        "manager",
    ):
        record["pins"][key]["mode"] = 0o755
    rosters = {k: {d: [] for d in a.DEPS} for k in u}
    rosters["service"].update(
        Requisite=[u["ready"]],
        After=[u["ready"], "system.slice"],
        Requires=["system.slice"],
        Conflicts=[u["expired"]],
    )
    rosters["ready"].update(Before=[u["service"]], Conflicts=[u["expired"]])
    rosters["timer"]["Before"] = [u["expired"]]
    rosters["expired"]["Conflicts"] = [u["ready"], u["service"]]
    rosters["observer"].update(
        Requires=["system.slice"],
        After=["system.slice"],
        Conflicts=[u["observer_expired"]],
    )
    rosters["observer_timer"]["Before"] = [u["observer_expired"]]
    rosters["observer_expired"]["Conflicts"] = [u["observer"]]
    record["rosters"] = rosters
    return record


class RunFixture:
    """All native boundaries mocked; no socket/ptrace/process/filesystem effect."""

    def __init__(self, case):
        self.record = fixture(case)
        self.p = a.paths(self.record)
        self.bound = dict(invocation="b" * 32, process=dict(pid=123, start=77, ppid=1))
        self.observer = dict(invocation="c" * 32, process=dict(pid=456, start=88))
        self.trace = Mock()
        self.trace.old_exec_tid.return_value = 123
        self.peer = Mock()
        self.peer.getsockopt.return_value = struct.pack("3i", 123, 0, 0)
        self.peer.recvmsg.return_value = (a.MARKER, [], 0, None)
        self.peer.send.return_value = 1
        self.server = Mock()
        self.server.accept.return_value = (self.peer, None)
        self.client = Mock()
        self.client.stdout.fileno.return_value = 31
        self.client.wait.return_value = 137
        self.groups = Mock()
        self.groups.evidence = []
        self.observer_group = Mock()
        self.observer_group.evidence = {}
        self.stack = ExitStack()

    def __enter__(self):
        def enter(target, *args, **kwargs):
            return self.stack.enter_context(patch(target, *args, **kwargs))

        self.clock = enter(
            "adapter.clock",
            side_effect=lambda record, eligibility=False: 20000000
            if eligibility
            else 126000000,
        )
        enter("adapter.time.monotonic_ns", return_value=20000000000)
        enter("adapter.prerequisites", return_value={"python": (1, 2), "runc": (3, 4)})
        self.observer_check = enter(
            "adapter.validate_observer", return_value=self.observer
        )

        def show(record, unit, keys):
            if keys == ("LoadState",):
                return {"LoadState": "not-found"}
            return {"MainPID": "123", "InvocationID": self.bound["invocation"]}

        enter("adapter.show", side_effect=show)
        enter("adapter.roster", return_value={})
        enter("adapter.GroupsObserver", return_value=self.observer_group)
        enter("adapter.exclusive")
        enter("adapter.protected", return_value=17)
        enter("adapter.os.open", return_value=18)
        enter("adapter.os.close")
        enter("adapter.os.chmod")
        enter("adapter.os.path.lexists", return_value=False)
        enter("adapter.os.getpid", return_value=456)
        enter("adapter.os.fstat", return_value=Mock(st_size=0))
        enter("adapter.os.pidfd_open", return_value=27)
        enter("adapter.os.waitpid", return_value=(123, 9))
        enter("adapter.os.set_blocking")
        enter("adapter.os.read", return_value=b"")
        enter("adapter.fd_identity", return_value=[1, 2, 0o100000, 0])
        enter("adapter.socket.socket", return_value=self.server)
        enter("adapter.subprocess.Popen", return_value=self.client)
        self.snapshot = enter("adapter.target_snapshot", return_value=self.bound)
        enter("adapter.tracer_identity")
        enter("adapter.tracee_descriptors")
        enter("adapter.Groups", return_value=self.groups)
        self.trace_factory = enter("adapter.Trace", return_value=self.trace)
        enter("adapter.wait_event", return_value=0)
        self.process = enter(
            "adapter.process_snapshot", return_value=self.bound["process"]
        )
        self.retire = enter(
            "adapter.retirement", return_value={"mocked_source_evidence_only": True}
        )
        enter(
            "adapter.select.select",
            side_effect=lambda readers, *args: (readers, [], []),
        )
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)


class SourceTests(unittest.TestCase):
    def test_closed_record_positive_and_selector_rejection(self):
        for case in ("pre-guard-stop", "runc-exec-stop"):
            record = fixture(case)
            p, _ = a.validate_record(record)
            self.assertLess(len(p["socket"].encode()), 108)
            self.assertEqual(a.launch_vector(record, p)[-1], a.HELPER)
            self.assertEqual(
                a.runc_vector(p),
                [
                    a.RUNC,
                    "--root",
                    p["runc_root"],
                    "run",
                    "--keep",
                    "--bundle",
                    p["bundle"],
                    p["instance"],
                ],
            )
        for key in (
            "pid",
            "command",
            "argv",
            "ptrace",
            "unit_properties",
            "qualified",
            "reaped",
        ):
            record = fixture()
            record[key] = True
            with self.assertRaises(a.Incomplete):
                a.validate_record(record)
        record = fixture()
        record["rosters"]["service"]["Requires"] = [a.paths(record)["units"]["ready"]]
        with self.assertRaises(a.Incomplete):
            a.validate_record(record)

    def test_original_bounds_and_budget_tampering(self):
        for changes in (
            {"s_us": 125000001},
            {"c_us": 130000001},
            {"t_us": 21000000},
            {"not_before_mono_us": 1},
            {"observer_accuracy_us": 5000001},
            {"r_us": None},
        ):
            record = fixture()
            record.update(changes)
            with self.assertRaises(a.Incomplete):
                a.validate_record(record)
        record = fixture()
        for wall, mono, eligibility in (
            (1000000000, 9999999, True),
            (1100000000, 120000000, True),
            (1100000000, 130000000, False),
        ):
            with (
                patch("builtins.open", mock_open(read_data=record["boot_id"] + "\n")),
                patch("adapter.time.time_ns", return_value=wall * 1000),
                patch("adapter.time.monotonic_ns", return_value=mono * 1000),
                self.assertRaises(a.Incomplete),
            ):
                a.clock(record, eligibility)

    def test_two_positive_source_flows_have_exact_trace_sequence(self):
        for case in ("pre-guard-stop", "runc-exec-stop"):
            with RunFixture(case) as f:
                result = a.run(f.record)
                expected = [
                    call(a.SEIZE, 0),
                    call(a.INTERRUPT),
                    call(a.SETOPTIONS, a.TRACEEXEC | a.EXITKILL),
                ]
                if case == "runc-exec-stop":
                    expected.append(call(a.CONT))
                self.assertEqual(f.trace.operation.call_args_list, expected)
                self.assertEqual(f.observer_check.call_count, 2)
                self.assertFalse(result["overall_native_pass"])
                self.assertEqual(
                    result["status"],
                    "target-cutoff-observed-observer-retirement-pending",
                )
                self.assertEqual(
                    f.retire.call_args.args[-1],
                    {"before_us": 126000000, "after_us": 126000000},
                )
                if case == "pre-guard-stop":
                    f.peer.send.assert_not_called()
                else:
                    f.peer.send.assert_called_once_with(a.RELEASE)

    def test_identity_drift_blocks_interrupt_or_runc_acceptance(self):
        with RunFixture("pre-guard-stop") as f:
            drift = copy.deepcopy(f.bound)
            drift["process"]["start"] = 78
            f.snapshot.side_effect = [f.bound, drift]
            with self.assertRaises(a.Incomplete):
                a.run(f.record)
            self.assertEqual(f.trace.operation.call_args_list, [call(a.SEIZE, 0)])
        with RunFixture("runc-exec-stop") as f:
            f.process.return_value = {"pid": 123, "start": 78, "ppid": 1}
            with self.assertRaises(a.Incomplete):
                a.run(f.record)
            self.assertEqual(f.trace.operation.call_args_list.count(call(a.CONT)), 1)

    def test_peer_tampering_blocks_attach(self):
        with RunFixture("pre-guard-stop") as f:
            f.peer.getsockopt.return_value = struct.pack("3i", 123, 99, 0)
            with self.assertRaises(a.Incomplete):
                a.run(f.record)
            f.trace_factory.assert_not_called()

    def test_real_process_identity_parser_rejects_argv_uid_or_child_drift(self):
        group = "/system.slice/synthetic.service/launcher"
        argv = [a.PYTHON, "-I", a.HELPER]
        fields = ["S", "1"] + ["0"] * 17 + ["77"] + ["0"] * 3
        values = {
            "stat": ("123 (synthetic helper) " + " ".join(fields)).encode(),
            "cmdline": ("\0".join(argv) + "\0").encode(),
            "cgroup": ("0::" + group + "\n").encode(),
            "status": b"Uid:\t0 0 0 0\nGid:\t0 0 0 0\nTracerPid:\t0\n",
            "task/123/children": b"",
        }

        def probe(changes):
            data = {**values, **changes}
            with (
                patch("adapter.proc_bytes", side_effect=lambda pid, leaf: data[leaf]),
                patch("adapter.os.readlink", return_value=a.PYTHON),
                patch("adapter.os.stat", return_value=Mock(st_dev=1, st_ino=2)),
                patch("adapter.os.listdir", return_value=["123"]),
            ):
                return a.process_snapshot(123, group, a.PYTHON, (1, 2), argv)

        self.assertEqual(probe({})["start"], 77)
        for changes in (
            {"cmdline": values["cmdline"] + b"extra\0"},
            {"task/123/children": b"234\n"},
            {"status": b"Uid:\t0 0 10031 0\nGid:\t0 0 0 0\n"},
        ):
            with self.assertRaises(a.Incomplete):
                probe(changes)

    def test_observer_drift_blocks_attach(self):
        with RunFixture("pre-guard-stop") as f:
            f.observer_check.side_effect = [f.observer, {"invocation": "d" * 32}]
            with self.assertRaises(a.Incomplete):
                a.run(f.record)
            f.trace_factory.assert_not_called()

    def test_death_or_unexpected_stop_never_passes(self):
        with RunFixture("pre-guard-stop") as f:
            with (
                patch("adapter.os.waitpid", return_value=(123, 15)),
                self.assertRaises(a.Incomplete),
            ):
                a.run(f.record)
        # Real wait-event decoder: a SIGSTOP is not the expected INTERRUPT event.
        with (
            patch("adapter.clock"),
            patch("adapter.os.waitpid", return_value=(123, (19 << 8) | 0x7F)),
            self.assertRaises(a.Incomplete),
        ):
            a.wait_event(fixture(), 123, 128)

    def test_early_or_crossing_wait_interval_refuses_late_pid1_facts(self):
        # Even an otherwise accepting mocked retirement with later PID1/timer
        # facts must not receive an early/cross-S/out-of-C wait observation.
        for before, after in (
            (124999990, 124999991),
            (124999999, 125000001),
            (129999999, 130000000),
            (125000002, 125000001),
        ):
            with RunFixture("pre-guard-stop") as f:
                observed = iter((before, after))
                f.clock.side_effect = (
                    lambda record, eligibility=False, observed=observed: 20000000
                    if eligibility
                    else next(observed)
                )
                f.retire.return_value = {
                    "service": {"ExecMainExitTimestampMonotonic": "126000000"},
                    "expired_enter": {"ActiveEnterTimestampMonotonic": "126000001"},
                    "timer_trigger": {"LastTriggerUSecMonotonic": "2min 5s"},
                }
                with (
                    self.subTest(before=before, after=after),
                    self.assertRaises(a.Incomplete),
                ):
                    a.run(f.record)
                f.retire.assert_not_called()

    def test_retirement_attribution_and_stable_identity(self):
        record = fixture()
        p = a.paths(record)
        bound = {"invocation": "b" * 32, "process": {"pid": 123, "start": 77}}
        base = dict(
            LoadState="loaded",
            InvocationID="b" * 32,
            ActiveState="failed",
            SubState="failed",
            MainPID="0",
            Result="signal",
            ExecMainCode="2",
            ExecMainStatus="9",
            ExecMainExitTimestampMonotonic="125000020",
            ControlGroup="",
        )

        def probe(
            changes=None,
            gone=True,
            empty=True,
            stable=True,
            entered="125000010",
            trigger="2min 5s",
            observed=None,
        ):
            values = {**base, **(changes or {})}
            second = dict(values)
            if not stable:
                second["InvocationID"] = "c" * 32
            observations = [
                values,
                {"ActiveEnterTimestampMonotonic": entered},
                {"LastTriggerUSecMonotonic": trigger},
                second,
            ]
            groups = Mock()
            groups.evidence = []
            groups.empty.return_value = empty
            if observed is None:
                observed = {"before_us": 125000001, "after_us": 125000002}
            with (
                patch("adapter.clock", return_value=126000000),
                patch("adapter.show", side_effect=observations),
                patch("adapter.roster", return_value={}),
                patch("adapter.select.select", return_value=([27], [], [])),
                patch("adapter.original_gone", return_value=gone),
            ):
                return a.retirement(record, p, bound, 27, groups, 9, observed)

        positive = probe()
        self.assertTrue(positive["original_process_disappeared"])
        self.assertEqual(
            positive["wait_observed_interval"],
            {"before_us": 125000001, "after_us": 125000002},
        )
        # Conflicts without an ordering edge admits either valid completion order.
        self.assertEqual(
            probe(entered="125000030")["service"]["ExecMainExitTimestampMonotonic"],
            "125000020",
        )
        self.assertEqual(probe({"Result": "success"})["service"]["ExecMainStatus"], "9")
        for changes in (
            {"ExecMainExitTimestampMonotonic": "124999999"},
            {"ExecMainExitTimestampMonotonic": "130000000"},
            {"ExecMainStatus": "15"},
            {"InvocationID": "c" * 32},
        ):
            with self.assertRaises(a.Incomplete):
                probe(changes)
        for values in ({"gone": False}, {"empty": False}, {"stable": False}):
            with self.assertRaises(a.Incomplete):
                probe(**values)
        for values in (
            {"entered": "124999999"},
            {"entered": "130000000"},
            {"trigger": "2min 4.999999s"},
            {"trigger": "2min 10s"},
            {"trigger": "2min 5.000011s"},
            {"observed": {"before_us": 124999999, "after_us": 125000001}},
        ):
            with self.assertRaises(a.Incomplete):
                probe(**values)

    def test_retained_event_read_failure_is_not_empty(self):
        groups = object.__new__(a.Groups)
        identity = [1, 2, 0o100000, 0]
        groups.handles = [(17, 18, identity, identity)]
        with (
            patch("adapter.fd_identity", return_value=identity),
            patch("adapter.os.pread", return_value=b"populated 0\nfrozen 0\n"),
        ):
            self.assertTrue(groups.empty())
        with (
            patch("adapter.fd_identity", return_value=identity),
            patch("adapter.os.pread", return_value=b"populated 1\nfrozen 0\n"),
        ):
            self.assertFalse(groups.empty())
        with (
            patch("adapter.fd_identity", return_value=identity),
            patch(
                "adapter.os.pread",
                side_effect=OSError(errno.ENODEV, "synthetic removed handle"),
            ),
            self.assertRaises(OSError),
        ):
            groups.empty()

    def test_zero_options_and_exact_native_span(self):
        trace = object.__new__(a.Trace)
        trace.pid = 123
        trace.libc = Mock()
        trace.libc.ptrace.return_value = 0
        with self.assertRaises(a.Incomplete):
            trace.operation(a.SEIZE, a.EXITKILL)
        with self.assertRaises(a.Incomplete):
            trace.operation(a.SETOPTIONS, a.TRACEEXEC)
        self.assertEqual(a.timespan("2min 5.000001s"), 125000001)
        self.assertEqual(a.number("123"), 123)
        for value in ("infinity", "125000001", "1.0000001s", "1s 1s"):
            with self.assertRaises(a.Incomplete):
                a.timespan(value)

    def test_helper_rendezvous_close_precedes_guard_and_fixed_exec(self):
        record = fixture("runc-exec-stop")
        p = a.paths(record)
        peer = Mock()
        events = []
        peer.fileno.return_value = 3
        peer.getsockopt.return_value = struct.pack("3i", 456, 0, 0)
        peer.send.side_effect = lambda value: events.append("marker") or len(value)
        peer.recv.side_effect = lambda count: events.append("release") or b"R"
        peer.close.side_effect = lambda: events.append("close")
        metadata = Mock(st_mode=0o140600, st_uid=0, st_gid=0)
        with (
            patch("scratch_helper.__file__", h.HELPER),
            patch("scratch_helper.sys.argv", [h.HELPER]),
            patch("scratch_helper.load_selection", return_value=(record, p)),
            patch("scratch_helper.protected", return_value=17),
            patch("scratch_helper.os.close"),
            patch("scratch_helper.os.fstat", return_value=Mock(st_mode=0o40700)),
            patch("scratch_helper.os.stat", return_value=metadata),
            patch("scratch_helper.os.get_inheritable", return_value=False),
            patch("scratch_helper.socket.socket", return_value=peer),
            patch(
                "scratch_helper.runtime_guard",
                side_effect=lambda *args: events.append("guard"),
            ),
            patch(
                "scratch_helper.os.execve",
                side_effect=lambda *args: events.append("exec"),
            ) as execute,
        ):
            h.main()
            execute.assert_called_once_with(a.RUNC, a.runc_vector(p), {})
        self.assertEqual(events, ["marker", "release", "close", "guard", "exec"])


if __name__ == "__main__":
    unittest.main()
