#!/usr/bin/env python3
"""Decide whether one exact source revision may become a candidate image.

A pasted digest is not deployment evidence, and neither is a pasted run id. This
verifier turns "CI was green" from a claim into seven separate checks, each of
which has a way of being false that the others do not catch.

## The seven

1. **The run belongs to this repository.** A run id is just an integer; the API
   will happily describe someone else's.
2. **It is the workflow we mean.** A successful run of a different workflow in
   the same repository is also "a successful run".
3. **It reached a successful TERMINAL conclusion.** `status` and `conclusion`
   are different fields, and an in-progress run has no conclusion at all.
4. **It ran on protected main, from this repository.** A fork's pull-request run
   carries a `head_sha` too.
5. **Its head is a full 40-character SHA**, not a branch name or a short ref.
6. **That SHA is still current main.** A green run on a commit three merges ago
   describes a tree nobody is deploying.
7. **Every required gate actually ran and passed.** This is the one the other
   six do not cover, and it is the one that matters most: a workflow reports
   SUCCESS at the run level when one of its jobs was skipped. A required gate
   that never ran looks exactly like a required gate that passed.

Check 7 reads CHECK-RUNS at the SHA rather than jobs within the run, because the
required set spans several workflows — verifying only the named run's own jobs
would silently exempt every gate produced by another one.

Exits 0 when the revision may be built, and non-zero with the reason otherwise.
No network write, no token beyond read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Final

API: Final[str] = "https://api.github.com"
SHA_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")

#: Conclusions that are NOT a pass, named individually rather than as "anything
#: but success". `skipped` is first because it is the one that reads as success
#: at the workflow level, and `neutral` is here because it is the conclusion a
#: check reports when it declines to have an opinion.
NON_PASSING: Final[tuple[str, ...]] = (
    "skipped",
    "neutral",
    "cancelled",
    "timed_out",
    "action_required",
    "stale",
    "failure",
)


def _get(path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dotmac-candidate-verifier",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def _paged_check_runs(repository: str, sha: str, token: str) -> list[dict[str, Any]]:
    """Every check-run at `sha`, following pagination.

    Paginated deliberately: the default page size would silently truncate a
    growing required set, and a gate that fell off page one would be reported
    absent — or worse, a future one would be reported present because nothing
    noticed the list was short.
    """
    runs: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = _get(
            f"/repos/{repository}/commits/{sha}/check-runs?per_page=100&page={page}",
            token,
        )
        batch = payload.get("check_runs") or []
        runs.extend(batch)
        if len(runs) >= int(payload.get("total_count", len(runs))) or not batch:
            return runs
        page += 1


def verify(
    *,
    run_id: str,
    repository: str,
    workflow_path: str,
    branch: str,
    expect_head: str,
    required: frozenset[str],
    token: str,
) -> list[str]:
    """Every reason this revision may not be built, or an empty list."""
    problems: list[str] = []
    try:
        run = _get(f"/repos/{repository}/actions/runs/{run_id}", token)
    except urllib.error.HTTPError as error:
        return [f"run {run_id} could not be read from {repository}: HTTP {error.code}"]

    # 1 — the run belongs to this repository.
    actual_repository = (run.get("repository") or {}).get("full_name")
    if actual_repository != repository:
        problems.append(
            f"run {run_id} belongs to {actual_repository!r}, not {repository!r}"
        )

    # 2 — it is the workflow we mean.
    if run.get("path") != workflow_path:
        problems.append(
            f"run {run_id} is workflow {run.get('path')!r}, not {workflow_path!r}"
        )

    # 3 — a successful TERMINAL conclusion.
    if run.get("status") != "completed":
        problems.append(f"run {run_id} is {run.get('status')!r}, not completed")
    if run.get("conclusion") != "success":
        problems.append(
            f"run {run_id} concluded {run.get('conclusion')!r}, not success"
        )

    # 4 — protected main, from this repository rather than a fork.
    if run.get("head_branch") != branch:
        problems.append(
            f"run {run_id} ran on {run.get('head_branch')!r}, not {branch!r}"
        )
    head_repository = (run.get("head_repository") or {}).get("full_name")
    if head_repository != repository:
        problems.append(
            f"run {run_id} has head repository {head_repository!r} — a fork may "
            "not produce a production candidate"
        )

    # 5 — a full 40-character SHA.
    head_sha = str(run.get("head_sha") or "")
    if not SHA_PATTERN.match(head_sha):
        problems.append(f"run {run_id} head_sha {head_sha!r} is not a 40-hex SHA")
        return problems

    # 6 — the run describes the revision the CALLER is acting on.
    #
    # This used to be "still current `main`", and the two callers wanted
    # different things from it. Building a candidate does want the tip: an image
    # built from a superseded commit describes a tree nobody is deploying.
    # DEPLOYING wants the revision the artifact was actually built from, which
    # the release receipt fixes forever and which is almost never the tip.
    #
    # While those were one value, the only deployable image was the one built
    # from the tip of `main` — so there was no reverse path at all, because the
    # running bytes are by definition not the tip. The caller now states which
    # revision it means; what is checked has not weakened.
    if head_sha != expect_head:
        problems.append(
            f"run {run_id} describes {head_sha}, but this operation is about "
            f"{expect_head} on {branch} — a green run on a different commit "
            "describes a tree nobody is deploying"
        )

    # 7 — every required gate ran, and passed.
    observed = {
        str(check.get("name")): (
            str(check.get("status")),
            str(check.get("conclusion")),
        )
        for check in _paged_check_runs(repository, head_sha, token)
    }
    for gate in sorted(required):
        if gate not in observed:
            problems.append(
                f"required gate {gate!r} produced no check-run at {head_sha}"
            )
            continue
        status, conclusion = observed[gate]
        if status != "completed":
            problems.append(f"required gate {gate!r} is {status!r}, not completed")
        elif conclusion in NON_PASSING:
            problems.append(
                f"required gate {gate!r} concluded {conclusion!r} — a run reports "
                "success at the workflow level even when a required job skipped"
            )
        elif conclusion != "success":
            problems.append(f"required gate {gate!r} concluded {conclusion!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-path", default=".github/workflows/ci.yml")
    parser.add_argument("--branch", default="main")
    parser.add_argument(
        "--expect-head",
        required=True,
        help=(
            "the revision this operation is about. A candidate BUILD passes "
            "current main; a DEPLOY passes the image source revision its "
            "release receipt fixed. Two identities, deliberately not one."
        ),
    )
    parser.add_argument("--gates", default=".github/candidate/required-gates.json")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("GITHUB_TOKEN is required to read the run", file=sys.stderr)
        return 2

    with open(args.gates, encoding="utf-8") as handle:
        required = frozenset(json.load(handle)["gates"])
    if not required:
        print(
            "the required-gate set is empty; an admission rule that requires "
            "nothing admits everything",
            file=sys.stderr,
        )
        return 2

    problems = verify(
        run_id=args.run_id,
        repository=args.repository,
        workflow_path=args.workflow_path,
        branch=args.branch,
        expect_head=args.expect_head,
        required=required,
        token=token,
    )
    if problems:
        print(
            f"REFUSED: {len(problems)} problem(s) with run {args.run_id}",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"ACCEPTED: run {args.run_id} is a successful {args.workflow_path} run on "
        f"{args.branch} at {args.expect_head}, with all {len(required)} required "
        "gates completed and passing"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
