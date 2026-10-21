"""Single-writer local git authority. Remote publication must succeed before serve."""

import fcntl
import os
import subprocess
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from .contracts import Json, canonical_json, read_json, require


class GitLedger:
    def __init__(self, root: str | Path, *, remote: str | None = "origin") -> None:
        self.root = Path(root).resolve()
        self.remote = remote
        self._mutex = threading.RLock()
        require((self.root / ".git").is_dir(), "ledger_unavailable")

    def git(self, *args: str) -> bytes:
        result = subprocess.run(  # noqa: S603 - fixed git executable, typed argv
            ["/usr/bin/git", "-C", str(self.root), *args],
            capture_output=True,
            timeout=60,
        )
        require(result.returncode == 0, "ledger_unavailable")
        return result.stdout

    @contextmanager
    def transaction(self) -> Iterator["GitLedger"]:
        with self._mutex, (self.root / ".git" / "deploy-agent.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            require(not self.git("status", "--porcelain"), "ledger_dirty")
            require(
                not self.git(
                    "log",
                    "--format=",
                    "--name-only",
                    "--diff-filter=MD",
                    "--",
                    "desired",
                    "applied",
                    "keys",
                    "commands",
                    "quarantine",
                ).strip(),
                "ledger_rewritten",
            )
            if self.remote:
                self.git("fetch", self.remote)
                branch = self.git("symbolic-ref", "--short", "HEAD").decode().strip()
                require(
                    self.git("rev-parse", "HEAD")
                    == self.git("rev-parse", f"{self.remote}/{branch}"),
                    "ledger_conflict",
                )
            yield self

    def records(self, prefix: str = "") -> list[tuple[str, bytes]]:
        names = self.git("ls-tree", "-r", "--name-only", "HEAD").decode().splitlines()
        return [
            (name, self.git("show", f"HEAD:{name}"))
            for name in sorted(names)
            if name.startswith(prefix) and name.endswith(".json")
        ]

    def read(self, name: str) -> bytes | None:
        for path, raw in self.records(name):
            if path == name:
                return raw
        return None

    def append(self, name: str, value: object) -> bool:
        return self.append_many({name: value})

    def append_many(self, values: Mapping[str, object]) -> bool:
        pending = {}
        for name, value in values.items():
            require(
                not Path(name).is_absolute() and ".." not in Path(name).parts,
                "ledger_path",
            )
            raw = canonical_json(value)
            existing = self.read(name)
            if existing is not None:
                require(existing == raw, "ledger_conflict")
            else:
                pending[name] = raw
        for name, raw in pending.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.is_symlink(), "ledger_path")
            with target.open("xb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        if pending:
            self.git("add", "--", *pending)
            self.git("commit", "-m", "deploy-agent append " + ",".join(pending))
            if self.remote:
                self.git("push", self.remote, "HEAD")
        return bool(pending)

    def events(self) -> list[tuple[str, Json]]:
        # Git commit order, not filename order, defines latest state.
        names = (
            self.git("log", "--reverse", "--format=", "--name-only", "--diff-filter=A")
            .decode()
            .splitlines()
        )
        return [
            (name, read_json(self.git("show", f"HEAD:{name}")))
            for name in names
            if name.endswith(".json")
        ]
