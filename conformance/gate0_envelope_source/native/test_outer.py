"""Authored only: mocked existing-owner seam tests, never native evidence."""

import array
import errno
import hashlib
import json
import socket
import stat
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import adapter as a
import outer as o
from test_adapter import fixture as r2_fixture
from test_adapter import live_fixture, source_bound


def fixture():
    record = r2_fixture()
    # Explicit synthetic regular-file bound; not an installed numeric default.
    record["evidence_max_bytes"] = record["diagnostic_max_bytes"]
    return record


def metadata(size=0, inode=2, **changes):
    values = dict(
        st_dev=1,
        st_ino=inode,
        st_mode=stat.S_IFREG | 0o600,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_size=size,
        st_mtime_ns=10,
        st_ctime_ns=10,
        st_rdev=0,
    )
    values.update(changes)
    return SimpleNamespace(**values)


def bound():
    return dict(
        invocation="b" * 32,
        process=dict(
            pid=123,
            start=77,
            ppid=1,
            exe_device=1,
            exe_inode=2,
            cgroup=a.paths(fixture())["observer_group"],
        ),
    )


def packet(record=None):
    record = record or fixture()
    return dict(
        schema=a.OWNER_SCHEMA,
        instance=record["instance"],
        boot_id=record["boot_id"],
        observer=bound(),
    )


def observation(record, observer, retained):
    return dict(
        schema="DotmacNativeEnvelopeTargetObservation.v1",
        status="target-cutoff-observed-observer-retirement-pending",
        case=record["case"],
        instance=record["instance"],
        boot_id=record["boot_id"],
        original_s_us=record["s_us"],
        original_c_us=record["c_us"],
        held_boundary="helper-before-first-runtime-guard",
        target=source_bound(a.paths(record)),
        retirement=dict(
            service={},
            expired={},
            expired_enter={},
            timer_trigger={},
            groups=[],
            traced_wait_status=9,
            wait_observed_interval={"before_us": 126000000, "after_us": 126000001},
            post_s_live_witness=live_fixture(
                record,
                a.paths(record),
                source_bound(a.paths(record)),
                observer["process"]["pid"],
            ),
            original_process_disappeared=True,
            retained_recursive_populated_zero=True,
        ),
        observer=observer,
        observer_cgroup={"group": retained["group"], "event": retained["event"]},
        systemd_run_exit=137,
        actual_stdout_empty_eof=True,
        overall_native_pass=False,
    )


class OwnerTests(unittest.TestCase):
    def test_exact_seven_templates_have_original_bounds_and_only_observer_ready_edges(
        self,
    ):
        record = fixture()
        p = a.paths(record)
        replace = dict(
            S_US=record["s_us"],
            C_US=record["c_us"],
            T_US=record["t_us"],
            ACCURACY_US=record["accuracy_us"],
            OBSERVER_ACCURACY_US=record["observer_accuracy_us"],
            DIAGNOSTIC_MAX=record["diagnostic_max_bytes"],
            CPU_QUOTA=record["cpu_quota_percent"],
            MEMORY_MAX=record["memory_max_bytes"],
            TASKS_MAX=record["tasks_max"],
            OUTPUT=p["observer_output"],
            DIAGNOSTIC=p["observer_diagnostic"],
        )
        replace.update({key.upper(): value for key, value in p["units"].items()})
        for kind, source in o.TEMPLATES.items():
            for key, value in replace.items():
                source = source.replace("@@" + key + "@@", str(value))
            raw = source.encode("ascii")
            record["pins"][kind].update(
                size=len(raw), sha256=hashlib.sha256(raw).hexdigest()
            )
        rendered = o.fragments(record, p)
        self.assertEqual(
            set(rendered),
            {
                "ready",
                "timer",
                "expired",
                "observer",
                "observer_timer",
                "observer_expired",
                "observer_ready",
            },
        )
        self.assertIn(b"OnBootSec=125000000us\n", rendered["timer"])
        self.assertIn(b"OnBootSec=130000000us\n", rendered["observer_timer"])
        self.assertEqual(
            [
                line
                for line in rendered["observer_expired"].decode().splitlines()
                if line.startswith("Conflicts=")
            ],
            [
                "Conflicts="
                + p["units"]["observer_ready"]
                + " "
                + p["units"]["observer"]
            ],
        )
        self.assertIn(b"ExecStart=" + a.ADAPTER.encode() + b"\n", rendered["observer"])
        self.assertIn(
            ("StandardOutput=append:" + p["observer_output"] + "\n").encode(),
            rendered["observer"],
        )
        for kind, source in rendered.items():
            self.assertNotIn(b"[Install]", source)
            if kind == "observer":
                self.assertIn(
                    ("After=" + p["units"]["observer_ready"] + "\n").encode(), source
                )
                self.assertIn(
                    ("Requisite=" + p["units"]["observer_ready"] + "\n").encode(),
                    source,
                )
            else:
                self.assertNotIn(b"After=", source)
            self.assertNotIn(b"Requires=", source)
        record["pins"]["observer"]["sha256"] = "2" * 64
        with self.assertRaises(ValueError):
            o.fragments(record, p)

    def receive(
        self, changes=None, rights=(17, 18), flags=0, extra=False, ancillary=None
    ):
        record = fixture()
        p = a.paths(record)
        peer = Mock()
        server = Mock()
        server.accept.return_value = (peer, None)
        peer.getsockopt.return_value = struct.pack("3i", 123, 0, 0)
        document = {**packet(record), **(changes or {})}
        raw = json.dumps(document).encode()
        if ancillary is None:
            ancillary = [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", rights).tobytes(),
                )
            ]
        peer.recvmsg.side_effect = [
            (raw, ancillary, flags, None),
            (b"x", [], 0, None)
            if extra
            else BlockingIOError(errno.EAGAIN, "synthetic no extra packet"),
        ]
        with (
            patch("outer.os.get_inheritable", return_value=False),
            patch("outer.os.close"),
        ):
            return o.receive(
                Mock(OWNER_SCHEMA=a.OWNER_SCHEMA, closed=a.closed), record, p, server
            )

    def test_rights_protocol_exact_and_canonical_identity_fields(self):
        self.assertEqual(self.receive()[3], [17, 18])
        for rights in ((), (17,), (17, 18, 19)):
            with self.subTest(rights=rights), self.assertRaises(ValueError):
                self.receive(rights=rights)
        for flags in (socket.MSG_TRUNC, socket.MSG_CTRUNC):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.receive(flags=flags)
        for changes in (
            {"schema": "foreign"},
            {"instance": "c" * 64},
            {"boot_id": "foreign"},
            {"pid": 999},
        ):
            with self.assertRaises((ValueError, a.Incomplete)):
                self.receive(changes=changes)
        with self.assertRaises(ValueError):
            self.receive(extra=True)
        with self.assertRaises(ValueError):
            self.receive(ancillary=[(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"x")])

    def test_failed_or_late_binding_never_acknowledges(self):
        peer = Mock()
        peer.send.return_value = len(a.OWNER_ACK)
        record = fixture()
        p = a.paths(record)
        for failure in (
            ValueError("wrong peer/identity/ns/fds"),
            a.Incomplete("late original eligibility"),
        ):
            with (
                patch("outer.prepare", return_value=(p, {}, 10, 11, Mock())),
                patch(
                    "outer.receive",
                    return_value=(peer, (123, 0, 0), packet(), [17, 18]),
                ),
                patch("outer.bind_observer", side_effect=failure),
                patch("outer.os.close"),
                patch("outer.finish") as finish,
            ):
                with self.assertRaises((ValueError, a.Incomplete)):
                    o.run(a, record)
                peer.send.assert_not_called()
                finish.assert_not_called()

    def test_bind_requires_kernel_peer_actual_invocation_start_and_namespaces(self):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        actual = dict(
            MainPID="123",
            InvocationID=observer["invocation"],
            ExecStart="fixed",
            ActiveState="active",
        )
        fake = Mock(PYTHON=a.PYTHON)
        fake.show.return_value = actual
        fake.service_base.return_value = {}
        fake.process_snapshot.return_value = observer["process"]
        fake.protected.return_value = 21
        fake.fd_identity.side_effect = lambda fd: [
            1,
            fd if fd not in (17, 18) else fd + 4,
            stat.S_IFDIR if fd in (17, 21) else stat.S_IFREG,
            0,
        ]
        for credentials, document in (
            ((123, 1, 0), packet()),
            ((999, 0, 0), packet()),
            (
                (123, 0, 0),
                {**packet(), "observer": {**observer, "invocation": "c" * 32}},
            ),
            (
                (123, 0, 0),
                {
                    **packet(),
                    "observer": {
                        **observer,
                        "process": {**observer["process"], "start": 78},
                    },
                },
            ),
        ):
            with self.assertRaises(ValueError):
                o.bind_observer(
                    fake,
                    record,
                    p,
                    {"python": (1, 2)},
                    credentials,
                    document,
                    [17, 18],
                    10,
                    11,
                )
        with patch("outer.os.stat", side_effect=[metadata(inode=1), metadata(inode=2)]):
            with self.assertRaises(ValueError):
                o.bind_observer(
                    fake,
                    record,
                    p,
                    {"python": (1, 2)},
                    (123, 0, 0),
                    packet(),
                    [17, 18],
                    10,
                    11,
                )

    def test_retained_event_removed_or_populated_never_becomes_empty(self):
        retained = dict(
            directory=17,
            events=18,
            group=[1, 2, stat.S_IFDIR, 0],
            event=[1, 3, stat.S_IFREG, 0],
        )
        fake = Mock()
        fake.fd_identity.side_effect = [retained["group"], retained["event"]]
        with patch("outer.os.pread", return_value=b"populated 0\nfrozen 0\n"):
            o.recursive_empty(fake, retained)
        for value in (
            b"",
            b"populated 1\n",
            b"populated 0\npopulated 0\n",
            b"populated 0\nforeign 0\n",
        ):
            fake.fd_identity.side_effect = [retained["group"], retained["event"]]
            with (
                patch("outer.os.pread", return_value=value),
                self.assertRaises(ValueError),
            ):
                o.recursive_empty(fake, retained)
        fake.fd_identity.side_effect = [retained["group"], retained["event"]]
        with (
            patch(
                "outer.os.pread",
                side_effect=OSError(errno.ENODEV, "synthetic removed event"),
            ),
            self.assertRaises(OSError),
        ):
            o.recursive_empty(fake, retained)

    def test_output_single_json_original_bounds_and_retained_identity(self):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        retained = dict(group=[1, 2, stat.S_IFDIR, 0], event=[1, 3, stat.S_IFREG, 0])
        good = observation(record, observer, retained)
        for changes in (
            {},
            {"overall_native_pass": True},
            {"original_s_us": 1},
            {"observer": {}},
            {"observer_cgroup": {}},
            {"instance": "c" * 64},
            {"actual_stdout_empty_eof": False},
            {"systemd_run_exit": 0},
        ):
            document = {**good, **changes}
            raw = (
                json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            info = metadata(size=len(raw))
            with (
                patch("outer.fixed_sink", return_value=info),
                patch("outer.os.fstat", return_value=info),
                patch("outer.os.pread", return_value=raw),
            ):
                if changes:
                    with self.assertRaises(ValueError):
                        o.output_document(
                            Mock(
                                closed=a.closed,
                                validate_live_witness=a.validate_live_witness,
                                death_interval=a.death_interval,
                            ),
                            record,
                            p,
                            observer,
                            retained,
                            10,
                            {"python": (1, 2), "runc": (3, 4)},
                        )
                else:
                    self.assertEqual(
                        o.output_document(
                            Mock(
                                closed=a.closed,
                                validate_live_witness=a.validate_live_witness,
                                death_interval=a.death_interval,
                            ),
                            record,
                            p,
                            observer,
                            retained,
                            10,
                            {"python": (1, 2), "runc": (3, 4)},
                        ),
                        good,
                    )
        for raw in (b"", b"{}\n{}\n", b"{}\n\n", b"{} trailing"):
            with (
                patch("outer.fixed_sink", return_value=metadata(size=len(raw))),
                patch("outer.os.pread", return_value=raw),
                self.assertRaises((ValueError, a.Incomplete)),
            ):
                o.output_document(
                    Mock(
                        closed=a.closed,
                        validate_live_witness=a.validate_live_witness,
                        death_interval=a.death_interval,
                    ),
                    record,
                    p,
                    observer,
                    retained,
                    10,
                    {"python": (1, 2), "runc": (3, 4)},
                )

    def finish(self, changes=None, gone=True, pidfd=True, empty=True, late=False):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        retained = dict(
            pidfd=27, group=[1, 2, stat.S_IFDIR, 0], event=[1, 3, stat.S_IFREG, 0]
        )
        values = dict(
            LoadState="loaded",
            InvocationID=observer["invocation"],
            ActiveState="inactive",
            SubState="dead",
            MainPID="0",
            Result="success",
            ExecMainCode="1",
            ExecMainStatus="0",
            ExecMainExitTimestampMonotonic="126000000",
            ControlGroup="",
        )
        values.update(changes or {})
        fake = Mock(number=a.number)
        fake.show.return_value = values
        fake.original_gone.return_value = gone
        if late == "final":
            fake.clock.side_effect = [
                126000000,
                a.Incomplete("original C reached at final read"),
            ]
        elif late:
            fake.clock.side_effect = a.Incomplete("original C reached")
        with (
            patch("outer.select.select", return_value=([27] if pidfd else [], [], [])),
            patch(
                "outer.recursive_empty",
                side_effect=None if empty else ValueError("populated"),
            ),
            patch("outer.timer"),
            patch("outer.fixed_sink"),
            patch(
                "outer.output_document",
                return_value=observation(record, observer, retained),
            ),
        ):
            return o.finish(
                fake,
                record,
                p,
                observer,
                retained,
                10,
                11,
                {"python": (1, 2), "runc": (3, 4)},
            )

    def test_normal_retirement_positive_and_signal_zombie_foreign_hard_c_refusals(self):
        result = self.finish()
        self.assertFalse(result["overall_native_pass"])
        self.assertFalse(result["target_observation"]["overall_native_pass"])
        for changes in (
            {"Result": "signal"},
            {"ExecMainCode": "2"},
            {"ExecMainStatus": "9"},
            {"ExecMainStatus": "125"},
            {"InvocationID": "c" * 32},
            {"ExecMainExitTimestampMonotonic": "130000000"},
            {"ExecMainExitTimestampMonotonic": "124999999"},
            {"LoadState": "not-found"},
            {"ActiveState": "failed"},
        ):
            with self.assertRaises(ValueError):
                self.finish(changes)
        for options in (
            {"gone": False},
            {"pidfd": False},
            {"empty": False},
            {"late": True},
            {"late": "final"},
        ):
            with self.assertRaises((ValueError, a.Incomplete)):
                self.finish(**options)
        # Same original start still present, including Z, is never original_gone.
        fields = ["Z", "1"] + ["0"] * 17 + ["77"] + ["0"] * 3
        with patch(
            "adapter.proc_bytes",
            return_value=("123 (observer) " + " ".join(fields)).encode(),
        ):
            self.assertFalse(a.original_gone(123, 77))

    def test_closed_action_uses_original_eligibility_and_never_retries(self):
        record = fixture()
        p = a.paths(record)
        fake = Mock()
        with patch("outer.subprocess.run", return_value=Mock(returncode=1)) as command:
            with self.assertRaises(ValueError):
                o.fixed_action(fake, record, p, "arm-observer")
            self.assertEqual(command.call_count, 1)
            self.assertEqual(
                command.call_args.args[0],
                [
                    "/usr/bin/systemctl",
                    "--system",
                    "--no-pager",
                    "start",
                    p["units"]["observer_timer"],
                ],
            )
        with patch("outer.subprocess.run") as command:
            with self.assertRaises(ValueError):
                o.fixed_action(fake, record, p, "stop")
            command.assert_not_called()

    def test_sink_substitution_hardlink_overflow_and_output_nonempty_refuse(self):
        fake = Mock()
        fake.protected.return_value = 20
        fake.fd_identity.side_effect = lambda fd: [1, fd, stat.S_IFREG, 0]
        for info in (
            metadata(st_nlink=2),
            metadata(st_uid=1),
            metadata(st_mode=stat.S_IFREG | 0o644),
            metadata(size=101),
        ):
            with (
                patch("outer.os.fstat", return_value=info),
                self.assertRaises(ValueError),
            ):
                o.fixed_sink(fake, "/fixed", 10, 100)
        with (
            patch("outer.os.fstat", return_value=metadata()),
            patch("outer.os.close"),
            self.assertRaises(ValueError),
        ):
            o.fixed_sink(fake, "/fixed", 10, 100)
        with (
            patch("outer.os.fstat", return_value=metadata(size=1)),
            self.assertRaises(ValueError),
        ):
            o.fixed_sink(fake, "/fixed", 10, 100, empty=True)


class AdditionalOwnerTests(unittest.TestCase):
    def test_fixed_source_loader_authenticates_exact_bytes_and_avoids_any_pyc(self):
        record = fixture()
        source = b"marker = 'synthetic-only'\n"
        record["pins"]["adapter"].update(
            size=len(source), sha256=hashlib.sha256(source).hexdigest(), mode=0o755
        )
        module = SimpleNamespace(validate_record=Mock())
        with (
            patch("outer.protected", side_effect=[17, 18]),
            patch("outer.bounded", side_effect=[json.dumps(record).encode(), source]),
            patch(
                "outer.os.fstat",
                side_effect=[metadata(), metadata(st_mode=stat.S_IFREG | 0o755)],
            ),
            patch("outer.os.close"),
            patch("outer.types.ModuleType", return_value=module),
            patch("outer.exec", create=True) as execute,
        ):
            actual, loaded = o.load()
            self.assertEqual(actual, record)
            self.assertIs(loaded, module)
            self.assertEqual(execute.call_args.args[0].co_filename, o.ADAPTER)
            self.assertIs(execute.call_args.args[1], module.__dict__)
            module.validate_record.assert_called_once_with(record)
        record["pins"]["adapter"]["sha256"] = "2" * 64
        with (
            patch("outer.protected", side_effect=[17, 18]),
            patch("outer.bounded", side_effect=[json.dumps(record).encode(), source]),
            patch(
                "outer.os.fstat",
                side_effect=[metadata(), metadata(st_mode=stat.S_IFREG | 0o755)],
            ),
            patch("outer.os.close"),
            patch("outer.exec", create=True) as execute,
        ):
            with self.assertRaises(ValueError):
                o.load()
            execute.assert_not_called()

    def test_valid_binding_retains_original_handles_and_rejects_wrong_fds(self):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        actual = dict(
            MainPID="123",
            InvocationID=observer["invocation"],
            ExecStart="fixed",
            ActiveState="active",
        )
        identities = {"python": (1, 2)}

        def run(wrong=None):
            fake = Mock(PYTHON=a.PYTHON)
            fake.show.return_value = actual
            fake.service_base.return_value = {}
            fake.process_snapshot.return_value = observer["process"]
            fake.protected.return_value = 21
            fake.fd_identity.side_effect = lambda fd: [
                1,
                21 if fd in (17, 21) else 22,
                stat.S_IFDIR if fd in (17, 21) else stat.S_IFREG,
                0,
            ]

            def fileinfo(fd):
                return metadata(
                    inode=10 if fd == 10 else 11,
                    st_mode=stat.S_IFDIR | 0o755 if fd == 17 else stat.S_IFREG | 0o600,
                )

            def pathinfo(path):
                if "/ns/" in path:
                    return metadata(inode=1)
                if path.endswith("/fd/0"):
                    return metadata(
                        st_mode=stat.S_IFCHR | 0o666,
                        st_rdev=99 if wrong == 0 else o.os.makedev(1, 3),
                    )
                number = int(path.rsplit("/", 1)[1])
                return metadata(inode=99 if wrong == number else 9 + number)

            with (
                patch("outer.os.stat", side_effect=pathinfo),
                patch("outer.os.fstat", side_effect=fileinfo),
                patch("outer.os.open", return_value=22),
                patch("outer.os.listdir", return_value=["123"]),
                patch("outer.os.pidfd_open", return_value=27),
                patch("outer.before_start"),
            ):
                return o.bind_observer(
                    fake, record, p, identities, (123, 0, 0), packet(), [17, 18], 10, 11
                )

        observer, retained = run()
        self.assertEqual(observer, bound())
        self.assertEqual(retained["pidfd"], 27)
        for wrong in (0, 1, 2):
            with self.assertRaises(ValueError):
                run(wrong)

    def test_successful_owner_acknowledges_once_before_finishing_and_stays_unqualified(
        self,
    ):
        record = fixture()
        p = a.paths(record)
        peer = Mock()
        peer.send.return_value = len(a.OWNER_ACK)
        retained = {}
        result = {"overall_native_pass": False}
        events = []
        peer.send.side_effect = lambda value: events.append("ack") or len(value)
        with (
            patch("outer.prepare", return_value=(p, {}, 10, 11, Mock())),
            patch(
                "outer.receive", return_value=(peer, (123, 0, 0), packet(), [17, 18])
            ),
            patch("outer.bind_observer", return_value=(bound(), retained)),
            patch("outer.fixed_sink"),
            patch("outer.os.close"),
            patch("adapter.clock"),
            patch(
                "outer.finish",
                side_effect=lambda *args: events.append("finish") or result,
            ),
        ):
            self.assertIs(o.run(a, record), result)
            self.assertEqual(events, ["ack", "finish"])
            peer.send.assert_called_once_with(a.OWNER_ACK)

    def test_partial_arm_or_slow_setup_never_starts_observer_or_retries(self):
        record = fixture()
        p = a.paths(record)
        pin_paths = {
            kind: "/etc/systemd/system/" + unit
            for kind, unit in p["units"].items()
            if kind != "service"
        }
        fake = Mock()
        fake.validate_record.return_value = (p, pin_paths)
        fake.protected.return_value = 17
        fake.show.side_effect = (
            lambda record, unit, keys: {"LoadState": "not-found"}
            if keys == ("LoadState",)
            else {"LastTriggerUSecMonotonic": "0"}
            if keys == ("LastTriggerUSecMonotonic",)
            else {"ActiveState": "inactive"}
        )
        for failing_check, expected in (
            ("timer", ["reload", "arm-observer"]),
            (
                "before_start",
                ["reload", "arm-observer", "arm-observer-ready", "arm-target"],
            ),
        ):
            actions = []
            with (
                patch(
                    "outer.os.fstat",
                    return_value=metadata(st_mode=stat.S_IFDIR | 0o700),
                ),
                patch("outer.os.close"),
                patch("outer.os.path.lexists", return_value=False),
                patch("outer.fragments", return_value={}),
                patch("outer.sinks", return_value=(10, 11)),
                patch("outer.owner_server", return_value=Mock()),
                patch(
                    "outer.fixed_action",
                    side_effect=lambda _a,
                    _r,
                    _p,
                    action,
                    actions=actions: actions.append(action),
                ),
                patch(
                    "outer." + failing_check,
                    side_effect=ValueError("synthetic partial setup"),
                ),
            ):
                with self.assertRaises(ValueError):
                    o.prepare(fake, record)
                self.assertEqual(actions, expected)
        fake.clock.side_effect = a.Incomplete(
            "original eligibility exhausted during setup"
        )
        with patch("outer.subprocess.run") as command, self.assertRaises(a.Incomplete):
            o.fixed_action(fake, record, p, "arm-target")
        command.assert_not_called()

    def test_adapter_owner_protocol_failure_blocks_rendezvous_completion(self):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        groups = SimpleNamespace(directory=17, events=18)
        for credentials, ack, flags in (
            ((123, 0, 0), a.OWNER_ACK, 0),
            ((123, 1, 0), a.OWNER_ACK, 0),
            ((123, 0, 0), b"foreign", 0),
            ((123, 0, 0), a.OWNER_ACK, socket.MSG_TRUNC),
        ):
            peer = Mock()
            peer.getsockopt.return_value = struct.pack("3i", *credentials)
            peer.sendmsg.side_effect = lambda buffers, rights: len(buffers[0])
            peer.recvmsg.return_value = (ack, [], flags, None)
            with (
                patch("adapter.clock"),
                patch("adapter.protected", return_value=20),
                patch(
                    "adapter.os.fstat",
                    return_value=metadata(st_mode=stat.S_IFDIR | 0o700),
                ),
                patch(
                    "adapter.os.stat",
                    return_value=metadata(st_mode=stat.S_IFSOCK | 0o600),
                ),
                patch("adapter.os.close"),
                patch("adapter.socket.socket", return_value=peer),
            ):
                if credentials[1] or ack != a.OWNER_ACK or flags:
                    with self.assertRaises(a.Incomplete):
                        a.owner_rendezvous(record, p, observer, groups)
                else:
                    a.owner_rendezvous(record, p, observer, groups)
                    rights = peer.sendmsg.call_args.args[1][0]
                    self.assertEqual(list(rights[2]), [17, 18])


class R4OwnerAdmissionTests(unittest.TestCase):
    def test_observer_start_is_job_fail_and_never_pulls_or_rearms_own_ready(self):
        record = fixture()
        p = a.paths(record)
        fake = Mock()
        with patch("outer.subprocess.run", return_value=Mock(returncode=0)) as command:
            o.fixed_action(fake, record, p, "start-observer")
            self.assertEqual(
                command.call_args.args[0],
                [
                    "/usr/bin/systemctl",
                    "--system",
                    "--no-pager",
                    "--job-mode=fail",
                    "start",
                    p["units"]["observer"],
                ],
            )
            self.assertNotIn(p["units"]["observer_ready"], command.call_args.args[0])
        with patch("outer.subprocess.run", return_value=Mock(returncode=1)) as command:
            with self.assertRaises(ValueError):
                o.fixed_action(fake, record, p, "start-observer")
            self.assertEqual(
                command.call_count, 1
            )  # Pending original-C stop is not replaced/retried.
        self.assertIn("Requisite=@@OBSERVER_READY@@\n", o.TEMPLATES["observer"])
        self.assertIn("After=@@OBSERVER_READY@@\n", o.TEMPLATES["observer"])
        self.assertNotIn("Requires=", o.TEMPLATES["observer"])
        self.assertNotIn("After=", o.TEMPLATES["observer_expired"])
        self.assertIn(
            "Conflicts=@@OBSERVER_READY@@ @@OBSERVER@@\n",
            o.TEMPLATES["observer_expired"],
        )
        self.assertEqual(o.TEMPLATES["observer_ready"].count("StopWhenUnneeded=no"), 1)

    def test_already_expired_ready_or_late_userspace_cannot_submit_observer(self):
        record = fixture()
        p = a.paths(record)
        fake = Mock()

        def roster(record, p, kind, expected):
            if kind == "observer_ready":
                raise a.Incomplete("actual original-C ready target is inactive")

        fake.roster.side_effect = roster
        fake.show.return_value = {"LastTriggerUSecMonotonic": "0"}
        with patch("outer.fixed_action") as action, self.assertRaises(a.Incomplete):
            o.before_start(fake, record, p)
        action.assert_not_called()
        fake.clock.side_effect = a.Incomplete(
            "after original C; no userspace clock assumption"
        )
        with patch("outer.subprocess.run") as command, self.assertRaises(a.Incomplete):
            o.fixed_action(fake, record, p, "start-observer")
        command.assert_not_called()
        # A process stalled before its first clock is gated by manager Requisite,
        # not a test claim that its userspace eventually checks a clock.
        self.assertIn("Requisite=@@OBSERVER_READY@@", o.TEMPLATES["observer"])

    def test_outer_rejects_missing_pre_s_stale_or_unjoined_witness(self):
        record = fixture()
        p = a.paths(record)
        observer = bound()
        retained = dict(group=[1, 2, stat.S_IFDIR, 0], event=[1, 3, stat.S_IFREG, 0])
        good = observation(record, observer, retained)
        for changes in (
            {"before_us": 124999999},
            {"state": "Z"},
            {"tracer_pid": 999},
            {"pidfd_ready": True},
            {"after_us": 130000000},
            {"after_us": 126000001},
            {"case": "runc-exec-stop"},
            None,
        ):
            document = json.loads(json.dumps(good))
            if changes is None:
                del document["retirement"]["post_s_live_witness"]
            else:
                document["retirement"]["post_s_live_witness"].update(changes)
            raw = (
                json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            info = metadata(size=len(raw))
            fake = Mock(
                closed=a.closed,
                validate_live_witness=a.validate_live_witness,
                death_interval=a.death_interval,
            )
            with (
                patch("outer.fixed_sink", return_value=info),
                patch("outer.os.fstat", return_value=info),
                patch("outer.os.pread", return_value=raw),
                self.assertRaises((ValueError, a.Incomplete)),
            ):
                o.output_document(
                    fake,
                    record,
                    p,
                    observer,
                    retained,
                    10,
                    {"python": (1, 2), "runc": (3, 4)},
                )

    def test_v1_outer_entry_refuses_before_fixed_adapter_execution(self):
        record = fixture()
        record["schema"] = "DotmacNativeEnvelopeFixture.v1"
        with (
            patch("outer.protected", return_value=17),
            patch("outer.os.fstat", return_value=metadata()),
            patch("outer.os.close"),
            patch("outer.bounded", return_value=json.dumps(record).encode()),
            patch("outer.exec", create=True) as execute,
            self.assertRaises(ValueError),
        ):
            o.load()
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
