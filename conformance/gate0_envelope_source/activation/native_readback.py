"""Pure fixed-boundary parsers shared by offline source and inline runtime."""

import re

PUBLIC_ENV = [
    "PATH=/opt/venv/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "VIRTUAL_ENV=/opt/venv",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONUNBUFFERED=1",
]


def timespan_us(value):
    """v255 FORMAT_TIMESPAN finite grammar, integer arithmetic only.

    Aligned with current CP _timer_microseconds pure boundary parser; numeric
    PID/status fields never pass through this duration-specific decoder.
    """
    if type(value) is not str or not 1 <= len(value) <= 63:
        raise ValueError("invalid finite timespan")
    if value == "0":
        return 0
    units = {
        "y": 31557600000000,
        "month": 2629800000000,
        "w": 604800000000,
        "d": 86400000000,
        "h": 3600000000,
        "min": 60000000,
        "s": 1000000,
        "ms": 1000,
        "us": 1,
    }
    total, previous = 0, 2**64
    parts = value.split(" ")
    for index, part in enumerate(parts):
        match = re.fullmatch(
            r"([1-9][0-9]*)(?:\.([0-9]+))?(y|month|w|d|h|min|s|ms|us)", part
        )
        if match is None:
            raise ValueError("invalid finite timespan")
        whole, fraction, unit = match.groups()
        scale = units[unit]
        if scale >= previous:
            raise ValueError("ambiguous unit ordering")
        component = int(whole) * scale
        if fraction is not None:
            precision = {"s": 6, "ms": 3}.get(unit)
            if (
                precision is None
                or len(fraction) > precision
                or index != len(parts) - 1
            ):
                raise ValueError("precision loss")
            component += int(fraction) * 10 ** (precision - len(fraction))
        total += component
        if total >= 2**64 - 1:
            raise ValueError("nonfinite timespan")
        previous = scale
    return total


def fixed_exec_start(value, path):
    prefix = "{ path=" + path + " ; argv[]=" + path + " ; ignore_errors=no ; "
    if (
        type(value) is not str
        or not value.startswith(prefix)
        or value.count("path=") != 1
        or not value.endswith(" }")
    ):
        raise ValueError("fixed zero-argv ExecStart mismatch")
    tail = value[len(prefix) : -2]
    pairs = tail.split(" ; ")
    expected = ("start_time", "stop_time", "pid", "code", "status")
    parsed = {}
    for part in pairs:
        key, sep, raw = part.partition("=")
        if (
            not sep
            or key not in expected
            or key in parsed
            or not raw
            or any(c in raw for c in "{}\r\n;")
        ):
            raise ValueError("unknown ExecStart metadata")
        parsed[key] = raw
    if tuple(parsed) != expected or re.fullmatch("[0-9]+", parsed["pid"]) is None:
        raise ValueError("invalid ExecStart metadata")
    # Dynamic timestamps/status are observational metadata, never command slots.
    if (
        re.fullmatch(r"(?:\(null\)|[A-Za-z_]+)", parsed["code"]) is None
        or re.fullmatch(r"[0-9]+(?:/[A-Za-z0-9_+-]+)?", parsed["status"]) is None
    ):
        raise ValueError("invalid ExecStart status")
    return True


def show_vector(unit, keys):
    vector = [
        "/usr/bin/systemctl",
        "--system",
        "--no-pager",
        "show",
        "--all",
        "--property=" + ",".join(sorted(keys)),
    ]
    return vector + ([unit] if unit else [])
