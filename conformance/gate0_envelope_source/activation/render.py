"""Offline candidate-source renderer. No installation or qualification capability.

Input is PUBLIC ONLY. Expected pins are comparisons, never acceptance evidence.
Output is mode0600 candidate source; execution permission is never granted here.
"""

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from native_readback import PUBLIC_ENV, fixed_exec_start, timespan_us

DESIGN = "c089e8186dc838b19f4a1fcf669b17331aecaf267a2070c2fda52a2b39b7e81e"
REVIEW = "7d165bda8f17746279ca0996f15a8ca00feb0ad46db4b9ee9206b9565bb1da39"
REVISION = "c25c83b6d352c20c164ff4c1f26b3b4833a8388f"
SELECTIONS = {
    ("consume-replay", "issuer"),
    ("consume-replay", "attester"),
    ("withdrawal-later-use", "issuer"),
    ("withdrawal-later-use", "attester"),
}
DEPENDENCIES = (
    "Requires",
    "Wants",
    "BindsTo",
    "Upholds",
    "Requisite",
    "After",
    "Before",
    "Conflicts",
    "PartOf",
)
SERVICE = {
    "LoadState": "loaded",
    "Type": "exec",
    "ExitType": "main",
    "DefaultDependencies": "no",
    "Restart": "no",
    "SuccessExitStatus": "",
    "RemainAfterExit": "no",
    "KillMode": "control-group",
    "KillSignal": "9",
    "FinalKillSignal": "9",
    "SendSIGKILL": "yes",
    "Delegate": "yes",
    "DelegateSubgroup": "launcher",
    "User": "0",
    "Group": "0",
    "LimitCORE": "0",
    "DropInPaths": "",
    "ExecStop": "",
    "ExecStopPost": "",
    "SuccessAction": "none",
    "FailureAction": "none",
    "OnSuccess": "",
    "OnFailure": "",
}
SERVICE_INPUT = {
    "FragmentPath",
    "ExecStart",
    "TimeoutStopUSec",
    "CPUQuotaPerSecUSec",
    "MemoryMax",
    "TasksMax",
} | set(DEPENDENCIES)


def fail(message):
    raise ValueError(message)


def exact(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        fail("missing/unknown fields: " + label)


def integer(value, label, minimum=1):
    if type(value) is not int or value < minimum:
        fail("invalid integer: " + label)


def digest(value):
    if (
        type(value) is not str
        or re.fullmatch("[0-9a-f]{64}", value) is None
        or value == "0" * 64
    ):
        fail("missing/invalid digest")


def text(value, pattern, label):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        fail("invalid " + label)


def parse_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result


def rosters(value, ready, service, expired):
    exact(value, ("ready", "timer", "expired", "service"), "rosters")
    for kind, roster in value.items():
        exact(roster, DEPENDENCIES, kind + " roster")
        for _key, words in roster.items():
            if type(words) is not list or len(words) != len(set(words)):
                fail("dependency roster must be a unique list")
            if any(
                type(w) is not str or re.fullmatch("[A-Za-z0-9_.@:-]+", w) is None
                for w in words
            ):
                fail("invalid dependency")
        # Native implicit slice edges require exact readback; arbitrary edges refuse.
        allowable = {"system.slice", "-.slice"} if kind == "service" else set()
        special = {
            ("service", "Requisite"): {ready},
            ("service", "After"): {ready},
            ("expired", "Conflicts"): {ready, service},
            ("ready", "Conflicts"): {expired},
            ("service", "Conflicts"): {expired},
            ("ready", "Before"): {service},
            ("timer", "Before"): {expired},
        }
        for key, words in roster.items():
            permitted = allowable | special.get((kind, key), set())
            if not set(words) <= permitted:
                fail("dependency widening")
        if any(ready in roster[k] for k in ("Requires", "Wants", "BindsTo", "Upholds")):
            fail("ready pull-in forbidden")
    if (
        value["service"]["Requisite"] != [ready]
        or ready not in value["service"]["After"]
    ):
        fail("required Requisite+After absent")
    if set(value["expired"]["Conflicts"]) != {ready, service}:
        fail("expired conflicts must be exact")


def pin(value):
    exact(value, ("sha256", "mode", "size"), "public file pin")
    digest(value["sha256"])
    integer(value["size"], "size", 0)
    if value["mode"] not in (0o444, 0o600, 0o644, 0o555, 0o755):
        fail("unsupported public file mode")


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def candidate_files(document, templates):
    exact(
        document,
        (
            "schema",
            "purpose",
            "source_revision",
            "design_sha256",
            "review_sha256",
            "campaign",
            "instances",
        ),
        "document",
    )
    if (
        document["schema"],
        document["source_revision"],
        document["design_sha256"],
        document["review_sha256"],
    ) != ("DotmacGate0R4CandidateInputs.v1", REVISION, DESIGN, REVIEW):
        fail("source/design selection mismatch")
    if document["purpose"] not in ("candidate", "synthetic-test-only"):
        fail("invalid candidate purpose")
    campaign = document["campaign"]
    text(campaign, "[0-9a-f]{64}", "campaign hash")
    if type(document["instances"]) is not list or len(document["instances"]) != 4:
        fail("four instances required")
    output = {}
    selected, ids, once_paths = set(), set(), set()
    for item in document["instances"]:
        exact(
            item,
            (
                "case",
                "role",
                "instance",
                "boot_id",
                "e_wall_us",
                "e_mono_us",
                "not_before_wall_us",
                "not_before_mono_us",
                "diagnostic_max_bytes",
                "r_us",
                "t_us",
                "s_us",
                "c_us",
                "accuracy_us",
                "cpu_quota_percent",
                "memory_max_bytes",
                "tasks_max",
                "python_path",
                "oci",
                "public_pins",
                "image_digest",
                "rootfs_tree_digest",
                "uid_review_digest",
                "network_measurement_digest",
                "clock_mapping_digest",
                "native_proof_digest",
                "rosters",
                "service_readback",
                "manager_version",
                "kernel_release",
                "netns_device",
                "netns_inode",
            ),
            "instance",
        )
        case, role, instance = item["case"], item["role"], item["instance"]
        if (case, role) not in SELECTIONS or (case, role) in selected:
            fail("selection mismatch")
        selected.add((case, role))
        text(instance, "[a-z0-9][a-z0-9-]{0,79}", "instance")
        if instance in ids:
            fail("instance reuse")
        ids.add(instance)
        text(item["boot_id"], "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", "boot ID")
        for key in (
            "not_before_wall_us",
            "not_before_mono_us",
            "diagnostic_max_bytes",
            "e_wall_us",
            "e_mono_us",
            "r_us",
            "t_us",
            "s_us",
            "c_us",
            "accuracy_us",
            "cpu_quota_percent",
            "memory_max_bytes",
            "tasks_max",
        ):
            integer(item[key], key)
        wall_duration = item["e_wall_us"] - item["not_before_wall_us"]
        mono_duration = item["e_mono_us"] - item["not_before_mono_us"]
        if not 0 < wall_duration <= 300_000_000 or mono_duration != wall_duration:
            fail("original window mapping/duration inconsistent")
        if (
            item["t_us"] > item["r_us"]
            or item["c_us"] != item["e_mono_us"] + item["r_us"]
            or item["s_us"] != item["c_us"] - item["t_us"]
        ):
            fail("original E/R/T/S/C mapping inconsistent")
        if item["accuracy_us"] > item["t_us"]:
            fail("timer accuracy exceeds stop budget")
        text(
            item["python_path"], "/usr/bin/python3(\\.[0-9]+)?", "qualified Python path"
        )
        text(
            item["manager_version"],
            "255([. -][A-Za-z0-9_.+() -]+)?",
            "qualified manager version",
        )
        text(item["kernel_release"], "[A-Za-z0-9_.+-]+", "qualified kernel release")
        integer(item["netns_device"], "netns device", 0)
        integer(item["netns_inode"], "netns inode")
        for key in (
            "image_digest",
            "rootfs_tree_digest",
            "uid_review_digest",
            "network_measurement_digest",
            "clock_mapping_digest",
            "native_proof_digest",
        ):
            digest(item[key])
        root = "/var/lib/dotmac-gate0/" + campaign + "/" + case + "-" + role
        libexec = (
            "/usr/local/libexec/dotmac-gate0/" + campaign + "/" + case + "-" + role
        )
        unit = "dotmac-gate0-" + instance
        names = dict(
            ready=unit + "-ready.target",
            timer=unit + "-cutoff.timer",
            expired=unit + "-expired.target",
            service=unit + ".service",
        )
        rosters(item["rosters"], names["ready"], names["service"], names["expired"])
        paths = {
            "systemd_run": "/usr/bin/systemd-run",
            "systemctl": "/usr/bin/systemctl",
            "runc": "/usr/sbin/runc",
            "python": item["python_path"],
            "manager": "/usr/lib/systemd/systemd",
            "machine_id": "/etc/machine-id",
            "public_packet": root + "/public-packet.json",
            "local_packet": root + "/local-packet.json",
            "network": root + "/network.json",
            "native_proof": root + "/native-proof.json",
            "rootfs_manifest": root + "/rootfs-manifest.json",
        }
        exact(item["public_pins"], paths, "public pins")
        for value in item["public_pins"].values():
            pin(value)
        if item["public_pins"]["native_proof"]["sha256"] != item["native_proof_digest"]:
            fail("native proof pin mismatch")
        files = {path: item["public_pins"][key] for key, path in paths.items()}
        subst = {
            "INSTANCE": instance,
            "CAMPAIGN": campaign,
            "CASE": case,
            "ROLE": role,
            "T_US": str(item["t_us"]),
            "S_US": str(item["s_us"]),
            "ACCURACY_US": str(item["accuracy_us"]),
            "QUALIFIED_PYTHON_PATH": item["python_path"],
            "DIAGNOSTIC_MAX_BYTES": str(item["diagnostic_max_bytes"]),
            "CPU_QUOTA_PERCENT": str(item["cpu_quota_percent"]),
            "MEMORY_MAX_BYTES": str(item["memory_max_bytes"]),
            "TASKS_MAX": str(item["tasks_max"]),
        }
        for kind, template in (
            ("ready", "ready.target.in"),
            ("timer", "cutoff.timer.in"),
            ("expired", "expired.target.in"),
        ):
            raw = replace(templates[template], subst).encode("utf-8")
            path = "/etc/systemd/system/" + names[kind]
            output[path] = raw
            files[path] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "mode": 0o644,
                "size": len(raw),
            }
        config = oci(item["oci"], item, root)
        raw = canonical(config)
        output[root + "/bundle/config.json"] = raw
        files[root + "/bundle/config.json"] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "mode": 0o600,
            "size": len(raw),
        }
        manager = {}
        for kind in ("ready", "timer", "expired"):
            manager[kind] = {
                "LoadState": "loaded",
                "DefaultDependencies": "no",
                "DropInPaths": "",
                "FragmentPath": "/etc/systemd/system/" + names[kind],
                **{k: " ".join(v) for k, v in item["rosters"][kind].items()},
            }
        manager["ready"].update(
            ActiveState="active", SubState="active", StopWhenUnneeded="no"
        )
        manager["expired"].update(ActiveState="inactive", SubState="dead")
        timer = item["service_readback"]
        exact(timer, SERVICE_INPUT - set(DEPENDENCIES), "service readback")
        if any(type(v) is not str or "\n" in v or "\r" in v for v in timer.values()):
            fail("invalid native service readback")
        if timer["MemoryMax"] != str(item["memory_max_bytes"]) or timer[
            "TasksMax"
        ] != str(item["tasks_max"]):
            fail("resource readback mismatch")
        if timer["FragmentPath"] != "/run/systemd/transient/" + names["service"]:
            fail("fixed transient fragment path mismatch")
        fixed_exec_start(timer["ExecStart"], libexec + "-inside")
        if (
            timespan_us(timer["TimeoutStopUSec"]) != item["t_us"]
            or timespan_us(timer["CPUQuotaPerSecUSec"])
            != item["cpu_quota_percent"] * 10000
        ):
            fail("stop/quota readback semantics mismatch")
        manager["timer"].update(
            ActiveState="active",
            SubState="waiting",
            NextElapseUSecMonotonic=item["s_us"],
            AccuracyUSec=item["accuracy_us"],
            RandomizedDelayUSec=0,
            WakeSystem="no",
            RemainAfterElapse="yes",
            Unit=names["expired"],
        )
        # Duration-bearing manager fields are compared as exact microseconds.
        manager["service"] = {
            **SERVICE,
            **timer,
            **{k: " ".join(v) for k, v in item["rosters"]["service"].items()},
            "ControlGroup": "/system.slice/" + names["service"],
        }
        manager["service"].update(
            TimeoutStopUSec=item["t_us"],
            CPUQuotaPerSecUSec=item["cpu_quota_percent"] * 10000,
            LimitFSIZE=str(item["diagnostic_max_bytes"]),
        )
        del manager["service"]["ExecStart"]
        once = root + "/activation-once"
        if once in once_paths:
            fail("once guard reuse")
        once_paths.add(once)
        public = {
            k: item[k]
            for k in (
                "instance",
                "boot_id",
                "not_before_wall_us",
                "not_before_mono_us",
                "e_wall_us",
                "e_mono_us",
                "s_us",
                "c_us",
                "diagnostic_max_bytes",
            )
        }
        public.update(
            files=files,
            units=names,
            manager=manager,
            once_path=once,
            fixture_only=document["purpose"] == "synthetic-test-only",
            manager_version=item["manager_version"],
            kernel_release=item["kernel_release"],
            netns_path="/run/netns/" + instance,
            netns_device=item["netns_device"],
            netns_inode=item["netns_inode"],
            tmpfs_paths=[root + "/runtime-tmpfs"]
            + ([root + "/auth-tmpfs"] if role == "attester" else []),
        )
        public.update(
            inside_path=libexec + "-inside",
            diagnostic_path=root + "/runtime-diagnostics",
            descriptor_path=root + "/descriptor-binding.json",
        )
        stable_public = json.loads(canonical(public))
        checks = replace(
            templates["runtime-checks.py.in"],
            {
                "PUBLIC_LITERAL": repr(stable_public),
                "NATIVE_READBACK_SOURCE": (
                    Path(__file__).parent / "native_readback.py"
                ).read_text(encoding="utf-8"),
            },
        )
        for name, hook in (
            ("activation.py.in", "activation_checks()"),
            ("inside.py.in", "inside_checks()"),
        ):
            text_source = templates[name]
            marker = (
                "QUALIFIED_ACTIVATION_CHECKS"
                if name == "activation.py.in"
                else "QUALIFIED_INSIDE_CHECKS_AND_NESTED_CGROUP_SETUP"
            )
            source = replace(text_source, {**subst, marker: checks + "\n" + hook})
            # Public installation refusals are silent; successful exec retains
            # the actual manager/service streams and status without a wrapper.
            first, body = source.split("\n", 1)
            guarded = (
                first
                + "\ndef _fixed():\n"
                + "".join("    " + line + "\n" for line in body.splitlines())
            )
            guarded += (
                "\ntry:\n    _fixed()\nexcept Exception:\n"
                "    raise SystemExit(125) from None\n"
            )
            output[libexec + ("-inside" if name == "inside.py.in" else "")] = (
                guarded.encode("utf-8")
            )
    if selected != SELECTIONS:
        fail("incomplete selections")
    return output


def replace(source, values):
    def one(match):
        key = match.group(1)
        if key not in values:
            fail("unresolved template input: " + key)
        return values[key]

    return re.sub(r"@@([A-Z_]+)@@", one, source)


def oci(value, item, root):
    # No arbitrary JSON patch or additional process/mount fields.
    exact(
        value,
        (
            "version",
            "env",
            "cwd",
            "apparmor_profile",
            "mounts",
            "devices",
            "device_allowlist",
            "seccomp",
            "masked_paths",
            "readonly_paths",
        ),
        "OCI inputs",
    )
    text(value["version"], "1\\.[0-9]+\\.[0-9]+", "accepted OCI version")
    if value["cwd"] != "/app" or value["env"] != PUBLIC_ENV:
        fail("fixed public image environment/cwd mismatch")
    text(value["apparmor_profile"], "[A-Za-z0-9_.-]+", "LSM profile")
    if value["apparmor_profile"] == "unconfined":
        fail("unreviewed unconfined fallback")
    # Nested native policy documents remain public installation-owner data.
    # Every mount is closed and cannot select the host network/cgroup/socket tree.
    if type(value["mounts"]) is not list or not value["mounts"]:
        fail("exact mounts missing")
    mounts = {}
    destinations = {
        "/run/dotmac-gate0",
        "/sys/fs/cgroup",
        "/proc",
        "/sys",
        "/etc/machine-id",
        # Fixed OCI metadata/synthetic input; no temporary file opened here.
        "/tmp",  # noqa: S108
        "/dev",
        "/dev/pts",
        # Fixed OCI metadata/synthetic input; no temporary file opened here.
        "/dev/shm",  # noqa: S108
    }
    destinations.add(
        "/run/dotmac-gate0/auth-info"
        if item["role"] == "attester"
        else "/run/dotmac-gate0/management/identity"
    )
    for mount in value["mounts"]:
        exact(mount, ("destination", "type", "source", "options"), "mount")
        destination = mount["destination"]
        if (
            type(destination) is not str
            or destination not in destinations
            or destination in mounts
        ):
            fail("invalid mount destination")
        if mount["type"] not in ("bind", "proc", "sysfs", "cgroup2", "tmpfs", "devpts"):
            fail("unexpected mount type")
        if type(mount["options"]) is not list or any(
            type(x) is not str for x in mount["options"]
        ):
            fail("invalid mount options")
        source = mount["source"]
        if type(source) is not str or ".." in source.split("/"):
            fail("invalid mount source")
        if mount["type"] == "bind" and source not in (
            root + "/runtime-tmpfs",
            root + "/auth-tmpfs",
            "/etc/machine-id",
            root + "/sender-identity",
        ):
            fail("host bind outside closed installation paths")
        allowed = {
            "/run/dotmac-gate0": ("bind", root + "/runtime-tmpfs"),
            "/etc/machine-id": ("bind", "/etc/machine-id"),
            "/run/dotmac-gate0/auth-info": ("bind", root + "/auth-tmpfs"),
            "/run/dotmac-gate0/management/identity": (
                "bind",
                root + "/sender-identity",
            ),
            # Fixed OCI metadata/synthetic input; no temporary file opened here.
            "/tmp": ("bind", root + "/auth-tmpfs")  # noqa: S108
            if item["role"] == "attester"
            else ("tmpfs", "tmpfs"),
            "/sys/fs/cgroup": ("cgroup2", "cgroup2"),
            "/proc": ("proc", "proc"),
            "/sys": ("sysfs", "sysfs"),
            "/dev": ("tmpfs", "tmpfs"),
            "/dev/pts": ("devpts", "devpts"),
            # Fixed OCI metadata/synthetic input; no temporary file opened here.
            "/dev/shm": ("tmpfs", "tmpfs"),  # noqa: S108
        }
        if (mount["type"], source) != allowed[destination] or set(mount["options"]) & {
            "rbind",
            "shared",
            "rshared",
            "slave",
            "rslave",
            "dev",
            "suid",
            "exec",
        }:
            fail("mount identity/propagation widening")
        if "ro" in mount["options"] and "rw" in mount["options"]:
            fail("ambiguous mount access")
        mounts[destination] = mount

    def require(destination, kind, source=None, options=()):
        m = mounts.get(destination)
        if (
            m is None
            or m["type"] != kind
            or (source is not None and m["source"] != source)
            or not set(options) <= set(m["options"])
        ):
            fail("missing required namespace mount: " + destination)

    require(
        "/run/dotmac-gate0",
        "bind",
        root + "/runtime-tmpfs",
        ("rw", "nodev", "nosuid", "noexec"),
    )
    require("/sys/fs/cgroup", "cgroup2", options=("rw", "nodev", "nosuid", "noexec"))
    require("/proc", "proc")
    require("/sys", "sysfs", options=("ro",))
    require("/etc/machine-id", "bind", "/etc/machine-id", ("ro",))
    if item["role"] == "attester":
        # Fixed OCI metadata/synthetic input; no temporary file opened here.
        require("/tmp", "bind", root + "/auth-tmpfs")  # noqa: S108
        require("/run/dotmac-gate0/auth-info", "bind", root + "/auth-tmpfs")
    else:
        # Fixed OCI metadata/synthetic input; no temporary file opened here.
        require("/tmp", "tmpfs")  # noqa: S108
        require(
            "/run/dotmac-gate0/management/identity",
            "bind",
            root + "/sender-identity",
            ("ro",),
        )
    if type(value["seccomp"]) is not dict or not value["seccomp"]:
        fail("qualified seccomp policy missing")
    if value["seccomp"].get("defaultAction") == "SCMP_ACT_ALLOW":
        fail("unqualified allow-all seccomp")
    for key in ("devices", "device_allowlist", "masked_paths", "readonly_paths"):
        if type(value[key]) is not list:
            fail("exact OCI native policy missing")
    minimal = {
        "/dev/null": (1, 3),
        "/dev/zero": (1, 5),
        "/dev/random": (1, 8),
        "/dev/urandom": (1, 9),
    }
    for device in value["devices"]:
        exact(
            device,
            ("path", "type", "major", "minor", "fileMode", "uid", "gid"),
            "device",
        )
        if (
            device["path"] not in minimal
            or device["type"] != "c"
            or (device["major"], device["minor"]) != minimal[device["path"]]
            or device["uid"] != 0
            or device["gid"] != 0
            or device["fileMode"] != 0o666
        ):
            fail("device exposure widening")
    for rule in value["device_allowlist"]:
        exact(rule, ("allow", "type", "major", "minor", "access"), "device rule")
        if (
            type(rule["allow"]) is not bool
            or rule["type"] != "c"
            or (rule["major"], rule["minor"]) not in minimal.values()
            or rule["access"] not in ("r", "w", "rw", "rwm")
        ):
            fail("device rule widening")
    for key in ("masked_paths", "readonly_paths"):
        if any(
            type(p) is not str or not p.startswith("/") or ".." in p.split("/")
            for p in value[key]
        ):
            fail("invalid isolation path")
    policy = value["seccomp"]
    exact(policy, ("defaultAction", "architectures", "syscalls"), "seccomp policy")
    if (
        policy["defaultAction"]
        not in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS")
        or policy["architectures"] != ["SCMP_ARCH_X86_64"]
        or type(policy["syscalls"]) is not list
    ):
        fail("unsupported closed seccomp policy")
    for rule in policy["syscalls"]:
        exact(rule, ("names", "action"), "seccomp syscall rule")
        if (
            rule["action"] != "SCMP_ACT_ALLOW"
            or type(rule["names"]) is not list
            or any(
                type(n) is not str or re.fullmatch("[a-z0-9_]+", n) is None
                for n in rule["names"]
            )
        ):
            fail("unsupported syscall rule")
    template = (Path(__file__).parent / "oci-config.json.in").read_text(
        encoding="utf-8"
    )
    replacements = {
        "ACCEPTED_OCI_VERSION": value["version"],
        "ACCEPTED_READONLY_ROOTFS": root + "/rootfs",
        "QUALIFIED_FIXED_PUBLIC_ENV_JSON": json.dumps(value["env"]),
        "QUALIFIED_IMAGE_CWD": value["cwd"],
        "QUALIFIED_LSM_PROFILE": value["apparmor_profile"],
        "INSTANCE": item["instance"],
        "DIAGNOSTIC_MAX_BYTES": str(item["diagnostic_max_bytes"]),
    }
    for token, key in (
        ("MOUNTS", "mounts"),
        ("DEVICES", "devices"),
        ("DEVICE_ALLOWLIST", "device_allowlist"),
        ("SECCOMP", "seccomp"),
        ("MASKED_PATHS", "masked_paths"),
        ("READONLY_PATHS", "readonly_paths"),
    ):
        replacements[
            "QUALIFIED_EXACT_" + token + "_JSON"
            if token in ("MOUNTS", "DEVICES")
            else "QUALIFIED_" + token + "_JSON"
        ] = json.dumps(value[key])
    return json.loads(
        replace(template, replacements), object_pairs_hook=parse_no_duplicates
    )


def create_output_directory(path):
    raw = os.fspath(path)
    if ".." in raw.split("/"):
        fail("output parent traversal forbidden")
    absolute = os.path.abspath(raw)
    parts = absolute.strip("/").split("/")
    if not parts or not parts[-1]:
        fail("new output leaf required")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            os.close(parent)
            parent = child
        # Offline ownership is the current author, not the production root rule.
        s = os.fstat(parent)
        if s.st_uid != os.geteuid():
            fail("output parent must belong to current author")
        os.mkdir(parts[-1], 0o700, dir_fd=parent)
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        result = os.open(
            parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        after = os.fstat(result)
        if (before.st_dev, before.st_ino) != (
            after.st_dev,
            after.st_ino,
        ) or after.st_uid != os.geteuid():
            os.close(result)
            fail("output directory identity changed")
        os.fchmod(result, 0o700)
        return result
    finally:
        os.close(parent)


def write_candidate(directory, name, raw):
    if "/" in name or name in ("", ".", ".."):
        fail("flat candidate name required")
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def main():
    if len(sys.argv) != 3:
        fail("usage: render.py PUBLIC-INPUT.json NEW-CANDIDATE-DIRECTORY")
    source = Path(__file__).parent
    # Do not execute/import templates, call subprocesses or touch any host target.
    document = json.loads(
        Path(sys.argv[1]).read_text(encoding="utf-8"),
        object_pairs_hook=parse_no_duplicates,
    )
    templates = {p.name: p.read_text(encoding="utf-8") for p in source.glob("*.in")}
    output = candidate_files(document, templates)
    manifest = {
        "schema": "DotmacGate0R4CandidateOutput.v1",
        "status": "candidate-unqualified",
        "purpose": document["purpose"],
        "input_sha256": hashlib.sha256(canonical(document)).hexdigest(),
        "source_revision": REVISION,
        "design_sha256": DESIGN,
        "review_sha256": REVIEW,
        "files": [],
    }
    destination = create_output_directory(sys.argv[2])
    try:
        for index, (path, raw) in enumerate(sorted(output.items())):
            name = str(index).zfill(2) + "-" + path.rsplit("/", 1)[1] + ".candidate"
            write_candidate(destination, name, raw)
            manifest["files"].append(
                {
                    "candidate": name,
                    "intended_path": path,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                    "installation_mode": 0o644
                    if path.startswith("/etc/systemd/")
                    else 0o600
                    if path.endswith(".json")
                    else 0o755,
                }
            )
        write_candidate(destination, "manifest.json", canonical(manifest))
    finally:
        os.close(destination)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        raise SystemExit(
            "candidate rendering refused; no installation performed"
        ) from None
