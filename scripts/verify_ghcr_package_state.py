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

## The two settings it cannot see, and why that is a FAILURE

Permission inheritance and Actions access are part of the desired post-rename
state, and no REST endpoint exposes either for a user-owned container package —
`/permissions`, `/actions-access` and `/repositories` all answer 404. They are
web-UI-only settings.

The tempting shape is to note that and move on. This tool does the opposite:
an unmeasured required setting is a FAILURE, not a footnote. A snapshot-and-
compare that certifies "unchanged" across two fields neither side ever measured
would be the wrong outcome dressed as evidence — and for Actions access
specifically, silence would quietly bless an organization-wide grant.

Note also that Actions access is a SPECIFICATION, not a preservation: the
desired state is the source repository alone. If the observed set is broader,
the correct action is to narrow it and say so, not to record that it survived.

Pass `--settings-unobservable` to acknowledge that both were checked and are
genuinely unreadable through tooling. That still does not make them verified —
it downgrades them to a loud, dated, human-owed obligation and prints what a
person must read off the settings page.
"""

from __future__ import annotations

import json
import re
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


#: A package name that could not be a shell metacharacter, an option, or a path
#: traversal. Checked rather than trusted: the name is read out of the capture
#: file, and a capture file is data on disk like any other.
SAFE_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


def _require_safe_name(name: str) -> str:
    if not SAFE_NAME.fullmatch(name):
        raise SystemExit(
            f"refusing to build a request from package name {name!r}: it is "
            "not a plain package identifier"
        )
    return name


def _gh_json(path: str, paginate: bool = False) -> Any:
    argv = ["gh", "api"]
    if paginate:
        argv.append("--paginate")
    argv.append(path)
    # S603 is ignored for this file in pyproject.toml. The premise it warns
    # about — an argument of unknown provenance reaching an executed command —
    # is removed by `_require_safe_name` above, which REFUSES rather than
    # escapes. argv is also a list, so no shell parses any of it.
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


def _settings_verdicts(frozen: dict[str, Any], acknowledged: bool) -> list[str]:
    """Required settings that were never measured are reported, never skipped."""
    required = frozen.get("required_settings") or {}
    unmeasured = [
        name
        for name, spec in required.items()
        if isinstance(spec, dict) and "desired" in spec and spec.get("observed") is None
    ]
    if not unmeasured:
        return []
    if acknowledged:
        print(
            "UNVERIFIED (acknowledged): "
            + ", ".join(sorted(unmeasured))
            + " — no REST endpoint exposes these; a person must read them off "
            "the package settings page, before and after. Desired state: "
            "permission inheritance ENABLED, Actions access restricted to the "
            "source repository ALONE. If the observed grant is broader, narrow "
            "it and record the change — it did not 'survive the rename'.",
            file=sys.stderr,
        )
        return []
    return [
        "REQUIRED SETTINGS NEVER MEASURED: "
        + ", ".join(sorted(unmeasured))
        + ". These are part of the desired post-rename state, so passing over "
        "them would certify fields neither side observed. Measure them from the "
        "package settings page, or re-run with --settings-unobservable to "
        "record them as a human-owed obligation."
    ]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    acknowledged = "--settings-unobservable" in args
    frozen = json.loads(CAPTURE.read_text())
    package_name = _require_safe_name(frozen["package"]["name"])
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

    failures.extend(_settings_verdicts(frozen, acknowledged))

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

    desired = frozen.get("desired_post_rename") or {}
    wanted_name = desired.get("linked_repository_full_name")
    live_name = repository.get("full_name") if repository else None
    if wanted_name and live_name and wanted_name != live_name:
        print(
            f"note: linkage still reads {live_name!r}; the desired post-rename "
            f"coordinate is {wanted_name!r}. GitHub redirects the old URL, so "
            "resolving it is not evidence the rename happened.",
            file=sys.stderr,
        )

    print(
        f"PASS: package {package_name!r} still {live.get('visibility')}, "
        f"linked to repository id {expected_repo_id}, and all "
        f"{len(frozen_digests)} captured digests are present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
