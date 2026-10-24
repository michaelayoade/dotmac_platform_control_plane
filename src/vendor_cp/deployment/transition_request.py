"""Author the closed CP authorization request; never execute a transition.

Only the reviewed workflow calls this adapter. GitHub context is supplied via
runner environment, never taken from the operator's closed plan document.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, TypedDict, cast

from vendor_cp.deploy_agent.contracts import (
    Digest,
    Identifier,
    _shape,
    canonical_json,
    read_json,
    require,
    sha,
)
from vendor_cp.deployment.cp_transition import (
    PLAN_FIELDS,
    CpTransitionIdentity,
    CpTransitionRequestV1,
    TransitionSideV1,
    raw_digest,
    request_digest,
    validate_request,
)

REPOSITORY = "michaelayoade/dotmac_platform_control_plane"
REPOSITORY_ID = "1317527604"
REPOSITORY_OWNER_ID = "32591929"
WORKFLOW_PATH = ".github/workflows/authorize-cp-transition.yml"
PREDICATE_TYPE = "https://dotmac.io/attestations/cp-transition-authorization/v1"


class TransitionPlanV1(TypedDict):
    """Operator-reviewed data only; no signing or execution identity fields."""

    product: Literal["dotmac_vendor_control_plane"]
    environment: Literal["production"]
    host: Identifier
    database: Identifier
    cluster_system_identifier: str
    database_oid: int
    source: TransitionSideV1
    target: TransitionSideV1
    previous_receipt_digest: Digest | None
    plan_digest: Digest


def author_request(
    plan_raw: bytes,
    *,
    context: Mapping[str, str],
    expected_revision: str,
    now: datetime,
) -> CpTransitionRequestV1:
    """Validate exact plan and reviewed workflow context before authoring bytes.

    The revision identifies the authorization workflow, independently of both
    image source revisions and any image build run. Host identity remains
    untrusted intent until compared with the separately installed host policy.
    """
    require(now.tzinfo is not None)
    sha(expected_revision, prefix=False)
    expected = {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
        "GITHUB_REPOSITORY_OWNER_ID": REPOSITORY_OWNER_ID,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": expected_revision,
        "GITHUB_WORKFLOW_SHA": expected_revision,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    require(all(context.get(key) == value for key, value in expected.items()))
    numbers: list[int] = []
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = context.get(key, "")
        require(value.isascii() and value.isdecimal() and int(value) > 0)
        numbers.append(int(value))
    actor = context.get("GITHUB_ACTOR", "")
    _shape(actor, Identifier)
    document = read_json(plan_raw)
    _shape(document, TransitionPlanV1)
    plan = cast(TransitionPlanV1, document)
    identity = CpTransitionIdentity(
        plan["host"],
        plan["database"],
        plan["cluster_system_identifier"],
        plan["database_oid"],
    )
    request = cast(
        CpTransitionRequestV1,
        {
            **{
                key: cast(dict[str, object], plan)[key]
                for key in (*PLAN_FIELDS, "plan_digest")
            },
            "schema": "dotmac.cp_transition_request/1",
            "authorization_run_id": numbers[0],
            "authorization_run_attempt": numbers[1],
            "trusted_actor": actor,
            # Leave an hour for publication; never accept operator expiry input.
            "expires_at": (now.astimezone(UTC) + timedelta(hours=23))
            .isoformat()
            .replace("+00:00", "Z"),
        },
    )
    return validate_request(request, identity=identity, now=now)


def write_authorization(request: CpTransitionRequestV1, output: Path) -> dict[str, str]:
    """Write canonical request and the verifier's exact three-field predicate."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw = canonical_json(request)
    (output / "request.json").write_bytes(raw)
    predicate = {
        "request_digest": request_digest(request),
        "trusted_actor": request["trusted_actor"],
        "environment": "production",
    }
    (output / "predicate.json").write_bytes(canonical_json(predicate))
    return {"subject_digest": raw_digest(raw), "predicate_type": PREDICATE_TYPE}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = author_request(
        args.plan.read_bytes(),
        context=os.environ,
        expected_revision=args.expected_revision,
        now=datetime.now(UTC),
    )
    metadata = write_authorization(request, args.output)
    # These values are computed, bounded strings; no operator data enters outputs.
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in metadata.items():
            stream.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
