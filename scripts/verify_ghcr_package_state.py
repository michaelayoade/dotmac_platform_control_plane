#!/usr/bin/env python3
"""Compare the live GHCR package against the frozen pre-rename capture.

Operator tool, not a CI gate: it needs a credential holding `read:packages`,
and that scope is deliberately short-lived. CI has no such credential and must
not be given one to make this runnable.

Run it after the repository rename:

    python3 scripts/verify_ghcr_package_state.py

Exit status is 0 only when every check passes. Each failure prints what was
expected, what was observed, and why the difference matters.

## What it refuses to do

It does not compare version COUNTS. A count is satisfied by a package whose
versions were all replaced, which is the failure most worth catching. Digests
are compared as sets, and a missing digest and an unexpected one are reported
separately so a replacement does not read as two unrelated problems.

It does not check the old repository URL. GitHub redirects it after a rename,
so resolving the old coordinate proves nothing; the canonical `full_name`
reported for the NEW coordinate is the thing that must have changed.

It cannot see the permission-inheritance or Actions-access settings, because
the REST payload does not carry them. It says so rather than passing silently
over a comparison it never made.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CAPTURE = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "operations"
    / "pre-rename-ghcr-package-state.json"
)


def _gh_json(path: str, paginate: bool = False) -> Any:
    argv = ["gh", "api"]
    if paginate:
        argv.append("--paginate")
    argv.append(path)
    done = subprocess.run(argv, capture_output=True, text=True)
    if done.returncode != 0:
        stderr = done.stderr.strip()
        if "read:packages" in stderr:
            raise SystemExit(
                f"the active credential cannot read packages: {stderr}\n"
                "this tool needs a short-lived read:packages scope"
            )
        raise SystemExit(f"gh api {path} failed: {stderr}")
    return json.loads(done.stdout)


def main() -> int:
    frozen = json.loads(CAPTURE.read_text())
    package_name = frozen["package"]["name"]
    expected_repo_id = frozen["linked_repository"]["id"]

    live = _gh_json(f"user/packages/container/{package_name}")
    live_versions = _gh_json(
        f"user/packages/container/{package_name}/versions?per_page=100",
        paginate=True,
    )

    failures: list[str] = []

    repository = live.get("repository") or {}
    if not repository:
        failures.append(
            "LINKAGE LOST: the package reports no linked repository. Reconnect "
            "it WITHOUT renaming or republishing the package."
        )
    else:
        live_repo_id = repository.get("id")
        if live_repo_id != expected_repo_id:
            failures.append(
                f"REPOSITORY IDENTITY: expected id {expected_repo_id}, "
                f"observed {live_repo_id} ({repository.get('full_name')!r}). "
                "The id is the stable coordinate; a different one means this "
                "is a different repository, whatever it is called."
            )

    if live.get("visibility") != frozen["package"]["visibility"]:
        failures.append(
            f"PACKAGE VISIBILITY: expected "
            f"{frozen['package']['visibility']!r}, observed "
            f"{live.get('visibility')!r}. A package that changed visibility "
            "during a rename is a security change, not bookkeeping."
        )

    expected_private = frozen["linked_repository"]["private"]
    if repository and repository.get("private") != expected_private:
        failures.append(
            f"REPOSITORY VISIBILITY: expected private={expected_private}, "
            f"observed private={repository.get('private')}."
        )

    frozen_digests = {version["digest"] for version in frozen["versions"]}
    live_digests = {version["name"] for version in live_versions}

    missing = sorted(frozen_digests - live_digests)
    unexpected = sorted(live_digests - frozen_digests)
    if missing:
        failures.append(
            f"{len(missing)} captured digest(s) are GONE: {missing}. "
            "Published digests are immutable; a disappearance is deletion."
        )
    if unexpected:
        # New builds after the capture are legitimate. Report, never fail.
        print(
            f"note: {len(unexpected)} digest(s) published since the capture: "
            f"{unexpected}",
            file=sys.stderr,
        )

    print(
        "not compared (absent from the REST payload): "
        + ", ".join(frozen["not_observable_via_rest"])
        + " — read these from the package settings page if they must match.",
        file=sys.stderr,
    )
    print(
        "not compared here: whether the NEW repository name is canonical. "
        "GitHub redirects the old URL, so resolving it proves nothing.",
        file=sys.stderr,
    )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(
        f"PASS: package {package_name!r} still {live.get('visibility')}, "
        f"linked to repository id {expected_repo_id}, and all "
        f"{len(frozen_digests)} captured digests are present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
