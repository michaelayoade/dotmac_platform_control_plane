"""Finite binary stdio protocol. No shell, line buffering or unbounded reads."""

from __future__ import annotations

import json
import math
import os
import select
import struct
from time import monotonic
from typing import cast


class ServiceRefused(ValueError):
    def __init__(self) -> None:
        super().__init__("gate0_service_refused")


def canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceRefused()
        result[key] = value
    return result


def strict_object(encoded: bytes, maximum: int = 256 * 1024) -> dict[str, object]:
    if type(encoded) is not bytes or not 0 < len(encoded) <= maximum:
        raise ServiceRefused()

    def reject_constant(_value: str) -> object:
        raise ServiceRefused()

    try:
        result = json.loads(
            encoded, object_pairs_hook=_object, parse_constant=reject_constant
        )
        if type(result) is not dict:
            raise ServiceRefused()
        return cast(dict[str, object], result)
    except (ValueError, UnicodeError, RecursionError):
        raise ServiceRefused() from None


class FramedChannel:
    """4-byte unsigned network length + strict UTF-8 JSON object.

    Own no descriptors. One original elapsed deadline covers input and output;
    each direction has a finite frame/byte budget. Production uses dedicated
    process-owned stdio pipes, never descriptors concurrently used elsewhere.
    """

    def __init__(
        self,
        input_fd: int,
        output_fd: int,
        *,
        deadline: float,
        maximum_frames: int = 16,
    ) -> None:
        if (
            not math.isfinite(deadline)
            or not 0 < deadline - monotonic() <= 600
            or not 1 <= maximum_frames <= 16
        ):
            raise ServiceRefused()
        if os.isatty(input_fd) or os.isatty(output_fd):
            raise ServiceRefused()
        # Dedicated process descriptors only: nonblocking syscalls close the
        # readiness-to-I/O race without trusting a pipe/socket low-water mark.
        os.set_blocking(input_fd, False)
        os.set_blocking(output_fd, False)
        self.input_fd, self.output_fd = input_fd, output_fd
        self.deadline, self.maximum_frames = deadline, maximum_frames
        self._received = self._sent = self._input_bytes = self._output_bytes = 0

    def require_open(self) -> None:
        if monotonic() >= self.deadline:
            raise ServiceRefused()

    def _wait(self, fd: int, *, write: bool) -> None:
        self.require_open()
        timeout = self.deadline - monotonic()
        if timeout <= 0:
            raise ServiceRefused()
        readable, writable, _ = select.select(
            [] if write else [fd], [fd] if write else [], [], timeout
        )
        if not (writable if write else readable):
            raise ServiceRefused()
        self.require_open()

    def _read(self, size: int, *, allow_eof: bool = False) -> bytes | None:
        result = bytearray()
        while len(result) < size:
            self._wait(self.input_fd, write=False)
            try:
                chunk = os.read(self.input_fd, min(size - len(result), 65536))
            except BlockingIOError:
                continue
            if not chunk:
                if allow_eof and not result:
                    return None
                raise ServiceRefused()
            result.extend(chunk)
        self.require_open()
        return bytes(result)

    def receive(self, *, allow_eof: bool = False) -> dict[str, object] | None:
        if self._received >= self.maximum_frames:
            raise ServiceRefused()
        header = self._read(4, allow_eof=allow_eof)
        if header is None:
            return None
        size = struct.unpack("!I", header)[0]
        if not 0 < size <= 256 * 1024 or self._input_bytes + size > 2 * 1024 * 1024:
            raise ServiceRefused()
        self._received += 1
        self._input_bytes += size
        body = self._read(size)
        if body is None:
            raise ServiceRefused()
        return strict_object(body)

    def send(self, document: dict[str, object]) -> None:
        self.require_open()
        body = canonical(document)
        if (
            not 0 < len(body) <= 256 * 1024
            or self._sent >= self.maximum_frames
            or self._output_bytes + len(body) > 2 * 1024 * 1024
        ):
            raise ServiceRefused()
        self._sent += 1
        self._output_bytes += len(body)
        remaining = memoryview(struct.pack("!I", len(body)) + body)
        # Pipes only promise PIPE_BUF writable bytes after readiness. A larger
        # blocking write could defeat the deadline even after select succeeds.
        while remaining:
            self._wait(self.output_fd, write=True)
            try:
                written = os.write(self.output_fd, remaining[:512])
            except BlockingIOError:
                continue
            if written <= 0:
                raise ServiceRefused()
            remaining = remaining[written:]
        self.require_open()
