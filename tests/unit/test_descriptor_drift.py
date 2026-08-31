"""Descriptor-versus-database drift, planted in BOTH directions.

The check exists because nothing compared `deploy/product.toml` to a live
database, in either direction, and a create-only bootstrap advanced the database
under it for a day without anything noticing. So the tests here are not only
"does it find the thing that went wrong" — they are:

* a MATCHING pair must pass, with a non-zero count of subjects compared. A
  checker that refuses everything passes every planted-violation test and is
  useless, and a checker that examined nothing returns the same empty findings
  list as a clean database;
* a planted UNDECLARED object must fail. This is the direction that would have
  caught the bootstrap, and it is the one a conformance check normally lacks:
  every declared schema still existed that day, so "does everything declared
  exist?" was green on a database that had moved;
* a planted MISSING declared object must fail, because the mirrored defect —
  a descriptor advanced while a migration rolled back — is the one that breaks
  by accident, writing a file being more reliable than migrating a database.

The conforming capture is BUILT FROM the accepted descriptor rather than pasted
from a production read. Pasting would make every test here a test of a
transcript, and would go stale the first time the descriptor legitimately moves.
"""

from __future__ import annotations

import json
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from vendor_cp.cli import main
from vendor_cp.descriptor import Direction, IncompleteCapture, Subject, compare

ROOT = Path(__file__).resolve().parents[2]
ACCEPTED = ROOT / "deploy" / "product.toml"


def accepted() -> dict[str, Any]:
    return tomllib.loads(ACCEPTED.read_text(encoding="utf-8"))


def conforming_capture(descriptor: dict[str, Any]) -> dict[str, Any]:
    """The catalogue a database matching `descriptor` exactly would report.

    Shaped like `vendor_cp/recovery/capture_catalog.sql`'s output, and carrying
    the cluster owner as a superuser because a real capture does — the check has
    to leave it alone rather than report it as undeclared drift forever.
    """
    database = descriptor["database"]
    table_privileges: list[dict[str, Any]] = []
    schema_privileges: list[dict[str, Any]] = []
    for entry in database["isolation"]:
        target = schema_privileges if entry["scope"] == "schema" else table_privileges
        for identity in entry["objects"]:
            for privilege in entry["privileges"]:
                target.append(
                    {
                        "role": entry["role"],
                        "scope": entry["scope"],
                        "identity": identity,
                        "privilege": privilege,
                        "holds": not entry["denied"],
                    }
                )
    return {
        "schemas": list(database["expected_schemas"]),
        "migration_heads": list(descriptor["migration"]["expected_heads"]),
        "roles": [
            {"name": role["name"], "superuser": False} for role in database["roles"]
        ]
        + [{"name": "postgres", "superuser": True}],
        "effective_privileges": table_privileges,
        "effective_schema_privileges": schema_privileges,
    }


def directions(report: Any, subject: Subject) -> dict[Direction, set[str]]:
    found: dict[Direction, set[str]] = {
        Direction.DECLARED_ABSENT: set(),
        Direction.PRESENT_UNDECLARED: set(),
    }
    for finding in report.findings:
        if finding.subject is subject:
            found[finding.direction].add(finding.identity)
    return found


# ── the matching pair, and its non-vacuity ──────────────────────────────────


def test_a_matching_descriptor_and_capture_agree() -> None:
    """DIRECTION TWO of the sensitivity proof, and the half usually skipped."""
    descriptor = accepted()
    report = compare(descriptor, conforming_capture(descriptor))
    assert report.findings == ()
    assert report.clean


def test_a_clean_report_says_how_much_it_compared() -> None:
    """An empty findings list is also what a check that examined nothing
    produces. The counts are what tell those apart."""
    descriptor = accepted()
    report = compare(descriptor, conforming_capture(descriptor))
    assert report.compared[Subject.SCHEMA] >= 7
    assert report.compared[Subject.MIGRATION_HEAD] >= 6
    assert report.compared[Subject.ROLE] >= 5
    assert report.compared[Subject.PRIVILEGE] > 0


def test_the_cluster_owner_is_not_reported_as_undeclared() -> None:
    """A superuser is not part of the product's role closure — the recovery
    bundle refuses to carry one — so reporting it every run would train a reader
    to skip the role section, which is where a real extra login role would be."""
    descriptor = accepted()
    report = compare(descriptor, conforming_capture(descriptor))
    assert (
        "postgres" not in directions(report, Subject.ROLE)[Direction.PRESENT_UNDECLARED]
    )


# ── present but undeclared: the direction that would have caught this ───────


def test_a_planted_undeclared_schema_is_reported() -> None:
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["schemas"].append("mod_planted")
    report = compare(descriptor, capture)
    assert not report.clean
    assert directions(report, Subject.SCHEMA)[Direction.PRESENT_UNDECLARED] == {
        "mod_planted"
    }
    assert directions(report, Subject.SCHEMA)[Direction.DECLARED_ABSENT] == set()


def test_a_planted_undeclared_migration_head_is_reported() -> None:
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["migration_heads"].append("zz_0001_planted")
    report = compare(descriptor, capture)
    assert directions(report, Subject.MIGRATION_HEAD)[Direction.PRESENT_UNDECLARED] == {
        "zz_0001_planted"
    }


def test_a_planted_undeclared_login_role_is_reported() -> None:
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["roles"].append({"name": "planted_operator", "superuser": False})
    report = compare(descriptor, capture)
    assert directions(report, Subject.ROLE)[Direction.PRESENT_UNDECLARED] == {
        "planted_operator"
    }


def test_a_broken_seal_is_an_undeclared_ability() -> None:
    """`platform_api` holding DELETE on the delivery-target projection again is
    not a missing declaration — it is an ability nobody declared, and it folds
    onto the same direction as an undeclared schema for that reason."""
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    for fact in capture["effective_privileges"]:
        if fact["privilege"] == "DELETE":
            fact["holds"] = True
    report = compare(descriptor, capture)
    assert directions(report, Subject.PRIVILEGE)[Direction.PRESENT_UNDECLARED] == {
        "platform_api DELETE on public.licence_delivery_targets"
    }


# ── declared but absent: the mirrored defect ────────────────────────────────


def test_a_declared_schema_the_database_lacks_is_reported() -> None:
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["schemas"].remove("mod_deploy")
    report = compare(descriptor, capture)
    assert directions(report, Subject.SCHEMA)[Direction.DECLARED_ABSENT] == {
        "mod_deploy"
    }


def test_a_declared_head_that_never_ran_is_reported() -> None:
    """The descriptor-ahead-of-the-migration case: a file written while the
    upgrade rolled back claims revisions the database does not have."""
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["migration_heads"].remove("dc_0002_canonical_plan_digest")
    report = compare(descriptor, capture)
    assert directions(report, Subject.MIGRATION_HEAD)[Direction.DECLARED_ABSENT] == {
        "dc_0002_canonical_plan_digest"
    }


def test_an_over_revoked_role_is_reported() -> None:
    """The failure the permission half of the isolation contract exists for: a
    role revoked from everything passes every `cannot reach` assertion and
    cannot run the product."""
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    for fact in capture["effective_schema_privileges"]:
        if fact["role"] == "platform_api":
            fact["holds"] = False
    report = compare(descriptor, capture)
    absent = directions(report, Subject.PRIVILEGE)[Direction.DECLARED_ABSENT]
    assert "platform_api USAGE on mod_deploy" in absent


def test_an_unobserved_privilege_is_not_a_quiet_pass() -> None:
    """A declaration the capture has no reading for is unsupported, not met.

    Reading a missing observation as `holds=False` would silently satisfy every
    denial in the file — the whole isolation contract would pass on an empty
    capture.
    """
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["effective_privileges"] = []
    report = compare(descriptor, capture)
    absent = directions(report, Subject.PRIVILEGE)[Direction.DECLARED_ABSENT]
    assert "platform_api DELETE on public.licence_delivery_targets" in absent


# ── the incident itself, replayed ───────────────────────────────────────────


def test_the_pre_bootstrap_descriptor_fails_against_the_post_bootstrap_database() -> (
    None
):
    """The check, run against the state that actually existed on 2026-08-30.

    The descriptor as it stood declared five module schemas, four heads and no
    seal, while the database the bootstrap left held seven schemas and six
    heads. Every declared object still existed — which is why a declared-only
    check reported nothing — and every finding below is in the second direction.
    """
    post = accepted()
    capture = conforming_capture(post)

    pre = deepcopy(post)
    pre["database"]["expected_schemas"] = [
        name for name in post["database"]["expected_schemas"] if name != "mod_deploy"
    ]
    pre["migration"]["expected_heads"] = [
        "v016_licensing_authority",
        "ap_0002_outbox_relay",
        "ea_0003_platform_audit_log",
        "rl_0001_release_artifacts",
    ]
    pre["database"]["isolation"] = [
        {
            **entry,
            "objects": [name for name in entry["objects"] if name != "mod_deploy"],
        }
        for entry in post["database"]["isolation"]
        if not entry["code"].startswith("platform-api-cannot-delete")
        and not entry["code"].startswith("platform-api-keeps")
    ]

    report = compare(pre, capture)
    assert not report.clean

    schemas = directions(report, Subject.SCHEMA)
    assert schemas[Direction.PRESENT_UNDECLARED] == {"mod_deploy"}
    assert schemas[Direction.DECLARED_ABSENT] == set()

    heads = directions(report, Subject.MIGRATION_HEAD)
    assert heads[Direction.PRESENT_UNDECLARED] == {
        "0028_machine_attribution",
        "dc_0002_canonical_plan_digest",
        "v018_licence_delivery_intents",
    }
    assert heads[Direction.DECLARED_ABSENT] == {"v016_licensing_authority"}


# ── incomplete evidence is not a verdict ────────────────────────────────────


@pytest.mark.parametrize(
    "key",
    [
        "schemas",
        "migration_heads",
        "roles",
        "effective_privileges",
        "effective_schema_privileges",
    ],
)
def test_a_capture_missing_a_key_refuses_rather_than_reporting_clean(
    key: str,
) -> None:
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    del capture[key]
    with pytest.raises(IncompleteCapture):
        compare(descriptor, capture)


def test_a_descriptor_with_no_database_contract_refuses() -> None:
    descriptor = accepted()
    del descriptor["database"]
    with pytest.raises(IncompleteCapture):
        compare(descriptor, conforming_capture(accepted()))


# ── the operator surface ────────────────────────────────────────────────────


def _write(tmp_path: Path, capture: dict[str, Any]) -> str:
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture), encoding="utf-8")
    return str(path)


def test_the_command_exits_zero_on_a_clean_comparison(tmp_path: Path) -> None:
    descriptor = accepted()
    code = main(
        [
            "--format",
            "json",
            "admin",
            "descriptor-drift",
            "--descriptor",
            str(ACCEPTED),
            "--capture",
            _write(tmp_path, conforming_capture(descriptor)),
        ]
    )
    assert code == 0


def test_the_command_exits_six_on_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`6`, not `3`: nothing refused anything — something is not what it
    claimed to be, and a caller treating that as a refusal would retry forever."""
    descriptor = accepted()
    capture = conforming_capture(descriptor)
    capture["schemas"].append("mod_planted")
    code = main(
        [
            "--format",
            "json",
            "admin",
            "descriptor-drift",
            "--descriptor",
            str(ACCEPTED),
            "--capture",
            _write(tmp_path, capture),
        ]
    )
    assert code == 6
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["refusal_code"] == "integrity.declaration_mismatch"
    assert "mod_planted" in envelope["message"]


def test_the_command_reports_an_absent_capture_as_missing_evidence(
    tmp_path: Path,
) -> None:
    """`4`, because nothing looked. A path that names no file is a different
    fact from a comparison that found a disagreement."""
    code = main(
        [
            "--format",
            "json",
            "admin",
            "descriptor-drift",
            "--descriptor",
            str(ACCEPTED),
            "--capture",
            str(tmp_path / "absent.json"),
        ]
    )
    assert code == 4
