"""The accepted descriptor is a promoted candidate, and its declarations are derived.

Two independent claims live here, and they fail for different reasons.

**The mechanism.** ADR-0017 § 2 gives the descriptor three lifetimes: a source
contract that is reviewed, an immutable candidate that is built, and an accepted
descriptor that describes the deployment which currently exists. Only the last
of those is a file anybody edits by habit, and editing it to agree with a
database inverts the model — the database becomes the authority and the
descriptor becomes a transcript of it. Worse, once hand-editing is ordinary the
next DRIFT is indistinguishable from the next CORRECTION. So the accepted
descriptor must hold the exact bytes of a candidate the ledger records, and a
candidate's bytes may never change once recorded.

**The derivation.** A candidate that agrees with production because somebody
read production and typed it in can only ever agree with production, including
where production is wrong. So the post-bootstrap candidate's database
declarations are re-derived here from the composed migrations themselves — the
revision graph's effective heads, the schemas the lineages create, and the
privilege changes `v017` and `dc_0001` perform — and the descriptor is checked
against THOSE. Agreement with a measured catalogue is then a consequence rather
than the method, and a disagreement is a real finding instead of a typo.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Final

import pytest
from alembic.script import ScriptDirectory
from dotmac_deployment_control import versions_dir as deployment_control_versions_dir

from vendor_cp.migrations import composed_version_locations, make_alembic_config

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
ACCEPTED = DEPLOY / "product.toml"
LEDGER = DEPLOY / "descriptor-promotions.json"
RECONCILIATION = (
    ROOT / "docs" / "operations" / "descriptor-reconciliation-2026-08-31.md"
)
V017 = ROOT / "alembic" / "versions" / "v017_deployment_target_authority.py"

#: The bootstrap receipt this promotion repairs, and the descriptor digest that
#: receipt binds. Both are coordinates of an operation that already happened on
#: a host, so they are recorded rather than derived — but every place they
#: appear must agree, which is what the tests below check.
RECEIPT_SHA256: Final = (
    "sha256:ffce65ec6e755c83d8a1418d382fae3966b7ef2e7955f1d15f22af926451d272"
)
BOOTSTRAP_SOURCE_DESCRIPTOR_SHA256: Final = (
    "sha256:99eef0cc82bc73065c17c543e7a3d8824e825d3c97da22bd4e73f648e0b2daeb"
)

#: A dummy DSN. `make_alembic_config` builds a `Config` and constructs no
#: engine, so this is never dialled — deny case D1 depends on it not being.
OFFLINE_DSN: Final = "postgresql+psycopg://descriptor@127.0.0.1:5432/none"

_CREATE_SCHEMA = re.compile(
    r"CREATE SCHEMA(?:\s+IF NOT EXISTS)?\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _ledger() -> list[dict[str, object]]:
    document = json.loads(LEDGER.read_text(encoding="utf-8"))
    assert document["schema"] == "DescriptorPromotionLedger.v1"
    promotions = document["promotions"]
    assert isinstance(promotions, list) and promotions
    return promotions


def _descriptor() -> dict[str, object]:
    return tomllib.loads(ACCEPTED.read_text(encoding="utf-8"))


def _isolation(code: str) -> dict[str, object]:
    database = _descriptor()["database"]
    assert isinstance(database, dict)
    entries = database["isolation"]
    assert isinstance(entries, list)
    matching = [entry for entry in entries if entry["code"] == code]
    assert len(matching) == 1, f"{code} is declared {len(matching)} times"
    return matching[0]


def composed_effective_heads() -> tuple[str, ...]:
    """The revisions `alembic_version` holds after the composed lineage runs.

    NOT `ScriptDirectory.get_heads()`, which answers a different question. The
    graph has eight heads; two of them are named in another revision's
    `depends_on`, and Alembic prunes a subsumed dependency from the version
    table rather than leaving it there as a second row. Comparing the descriptor
    against the graph's heads would demand two rows the database will never hold
    — and it is the SAME pruning that explains why the pre-bootstrap descriptor
    declared four heads with no kernel revision among them.
    """
    script = ScriptDirectory.from_config(make_alembic_config(OFFLINE_DSN))
    heads = set(script.get_heads())
    dependencies: set[str] = set()
    for revision in script.walk_revisions("base", "heads"):
        declared = revision.dependencies or ()
        names: Iterable[str] = (declared,) if isinstance(declared, str) else declared
        dependencies.update(names)
    return tuple(sorted(heads - dependencies))


def composed_schemas() -> frozenset[str]:
    """`public` plus every schema a composed migration creates."""
    found = {"public"}
    for location in composed_version_locations().split():
        for revision in sorted(Path(location).glob("*.py")):
            found.update(_CREATE_SCHEMA.findall(revision.read_text(encoding="utf-8")))
    return frozenset(found)


# ── the mechanism ───────────────────────────────────────────────────────────


def test_the_accepted_descriptor_is_a_candidate_byte_for_byte() -> None:
    """The one assertion that makes hand-editing impossible rather than discouraged."""
    latest = _ledger()[-1]
    candidate = ROOT / str(latest["candidate"])
    assert candidate.is_file(), candidate
    assert ACCEPTED.read_bytes() == candidate.read_bytes(), (
        "deploy/product.toml is not the bytes of the candidate the ledger "
        f"promotes ({latest['candidate']}). The accepted descriptor is never "
        "edited: author a NEW candidate under deploy/candidates/, append a "
        "promotion to deploy/descriptor-promotions.json, and copy the candidate "
        "over the accepted descriptor."
    )


def test_the_byte_comparison_can_still_fail(tmp_path: Path) -> None:
    """SENSITIVITY. Equality between a file and a copy of itself is also what a
    broken predicate reports, so plant the edit the rule exists to refuse."""
    planted = tmp_path / "product.toml"
    planted.write_bytes(ACCEPTED.read_bytes() + b"\n# a hand edit\n")
    latest = _ledger()[-1]
    candidate = ROOT / str(latest["candidate"])
    assert planted.read_bytes() != candidate.read_bytes()


def test_every_recorded_candidate_still_hashes_to_its_recorded_digest() -> None:
    """A candidate is immutable once promoted. Editing one in place would make a
    promotion record name bytes that no longer exist, which is the same defect
    as editing the accepted descriptor with an extra step."""
    for entry in _ledger():
        if entry["candidate"] is None:
            continue
        candidate = ROOT / str(entry["candidate"])
        assert candidate.is_file(), candidate
        assert _digest(candidate.read_bytes()) == entry["descriptor_sha256"], (
            f"{entry['candidate']} no longer hashes to the digest its promotion "
            "records; a promoted candidate is immutable"
        )


def test_the_promotion_chain_is_unbroken() -> None:
    """Each promotion supersedes exactly the digest before it, so the accepted
    descriptor's whole ancestry is one chain rather than a pile of files."""
    promotions = _ledger()
    assert promotions[0]["supersedes"] is None
    for previous, entry in zip(promotions, promotions[1:], strict=False):
        assert entry["supersedes"] == previous["descriptor_sha256"], entry


def test_exactly_one_entry_predates_the_mechanism() -> None:
    """The ledger starts at a fact, not at a gap.

    The descriptor that existed before this ledger had no candidate, and saying
    so once is honest. Saying it twice would be a second file edited in place
    wearing the first one's excuse.
    """
    pre = [entry for entry in _ledger() if entry["kind"] == "pre_mechanism"]
    assert len(pre) == 1
    assert pre == [_ledger()[0]]
    assert pre[0]["candidate"] is None
    assert str(pre[0]["descriptor_sha256"]).startswith("sha256:")


def test_the_current_promotion_is_recorded_as_a_repair() -> None:
    """It names the operation, the receipt, and where the record lives.

    A reconciliation that reads like routine maintenance teaches the next reader
    that descriptors drift and get tidied up, which is the opposite of the
    lesson.
    """
    latest = _ledger()[-1]
    assert latest["kind"] == "reconciliation"
    repairs = latest["repairs"]
    assert isinstance(repairs, dict)
    assert repairs["operation"] == "scripts/bootstrap/bootstrap_once.sh"
    assert repairs["receipt_sha256"] == RECEIPT_SHA256
    assert (
        repairs["receipt_bound_descriptor_sha256"] == BOOTSTRAP_SOURCE_DESCRIPTOR_SHA256
    )
    assert (ROOT / str(repairs["record"])).is_file()


def test_the_reconciliation_record_names_what_it_repairs() -> None:
    """The record is the part a human reads, so the coordinates have to be in it
    rather than only in the machine-readable ledger beside it."""
    text = RECONCILIATION.read_text(encoding="utf-8")
    assert RECEIPT_SHA256.removeprefix("sha256:")[:16] in text
    assert BOOTSTRAP_SOURCE_DESCRIPTOR_SHA256.removeprefix("sha256:")[:8] in text
    assert "bootstrap_once.sh" in text


# ── the derivation ──────────────────────────────────────────────────────────


def test_the_declared_heads_are_the_composed_effective_heads() -> None:
    """Recomputed from the installed lineages, offline, with no database."""
    migration = _descriptor()["migration"]
    assert isinstance(migration, dict)
    assert tuple(migration["expected_heads"]) == composed_effective_heads()


def test_the_effective_head_derivation_is_not_the_graph_heads() -> None:
    """NON-VACUITY for the test above.

    If pruning were a no-op the derivation would be `get_heads()` under another
    name, and the test would pass while proving nothing about the version table.
    Two dependencies really are subtracted here.
    """
    script = ScriptDirectory.from_config(make_alembic_config(OFFLINE_DSN))
    graph_heads = set(script.get_heads())
    effective = set(composed_effective_heads())
    assert effective < graph_heads
    assert graph_heads - effective == {"cg_0001_agreements", "li_0001_licensing"}


def test_the_declared_schemas_are_the_schemas_the_lineages_create() -> None:
    database = _descriptor()["database"]
    assert isinstance(database, dict)
    assert frozenset(database["expected_schemas"]) == composed_schemas()


def test_mod_deploy_is_declared_because_a_composed_migration_creates_it() -> None:
    """The declaration whose absence was the drift, tied to the statement that
    produced it rather than to a catalogue read."""
    source = (
        Path(deployment_control_versions_dir()) / "dc_0001_deployment_control.py"
    ).read_text(encoding="utf-8")
    assert "mod_deploy" in _CREATE_SCHEMA.findall(source)
    database = _descriptor()["database"]
    assert isinstance(database, dict)
    assert "mod_deploy" in database["expected_schemas"]


def test_the_new_schema_inherits_the_isolation_its_grant_states() -> None:
    """`dc_0001` grants schema USAGE to `platform_api` and `app_admin`, and to
    no other role. The descriptor's two schema-scoped entries must say the same
    thing from both sides."""
    source = (
        Path(deployment_control_versions_dir()) / "dc_0001_deployment_control.py"
    ).read_text(encoding="utf-8")
    grant = re.search(r"GRANT USAGE ON SCHEMA mod_deploy TO ([^;]+);", source)
    assert grant is not None
    granted = {role.strip() for role in grant.group(1).split(",")}
    assert granted == {"platform_api", "app_admin"}

    permitted = _isolation("platform-api-can-reach-platform-schemas")
    denied = _isolation("app-user-cannot-reach-platform-schemas")
    assert "mod_deploy" in permitted["objects"]
    assert permitted["denied"] is False
    assert "mod_deploy" in denied["objects"]
    assert denied["denied"] is True
    assert "app_user" not in granted


def test_the_delivery_target_seal_is_declared_exactly_as_v017_performs_it() -> None:
    """Both halves, read out of the revision that does the work.

    `v017` revokes ONE privilege on ONE table and its own post-condition refuses
    a broader outcome — the reconciler needs INSERT and UPDATE and staging needs
    SELECT. A descriptor that declared only the denial would be satisfied by a
    role revoked from everything, which is the failure `v017` explicitly guards
    against, so the retention half is declared too.
    """
    source = V017.read_text(encoding="utf-8")
    assert 'ONLINE_ROLE = "platform_api"' in source
    assert 'PROJECTION_TABLE = "licence_delivery_targets"' in source
    assert 'REVOKED_PRIVILEGE = "DELETE"' in source
    retained = re.search(r"for privilege in \(([^)]+)\)", source)
    assert retained is not None
    retained_privileges = tuple(
        item.strip().strip('"') for item in retained.group(1).split(",") if item.strip()
    )
    assert retained_privileges == ("SELECT", "INSERT", "UPDATE")

    sealed = _isolation("platform-api-cannot-delete-the-delivery-target-projection")
    assert sealed["role"] == "platform_api"
    assert sealed["scope"] == "table"
    assert sealed["objects"] == ["public.licence_delivery_targets"]
    assert sealed["privileges"] == ["DELETE"]
    assert sealed["denied"] is True

    writable = _isolation("platform-api-keeps-the-delivery-target-projection-writable")
    assert writable["role"] == "platform_api"
    assert writable["scope"] == "table"
    assert writable["objects"] == ["public.licence_delivery_targets"]
    assert tuple(writable["privileges"]) == retained_privileges
    assert writable["denied"] is False


@pytest.mark.parametrize(
    "path", ["image.reference", "image.source_revision", "assembly.manifest_digest"]
)
def test_the_application_half_was_carried_forward_unchanged(path: str) -> None:
    """The bootstrap was CREATE-ONLY, and this is where that shows up in the file.

    It ran the composed migrations in a short-lived `ops` container and did not
    replace, restart or repin the running application, so the halves of the
    descriptor that describe the APPLICATION must not have moved across this
    promotion. ADR-0017 § 2's refusal is exactly this: a descriptor that
    advanced its image would claim a deployment nobody performed, and every
    later drift check would report one.

    The values are recorded in the promotion rather than inferred, so a future
    promotion that advances the image has to say so here instead of arriving as
    a database repair.
    """
    carried = _ledger()[-1]["carried_forward"]
    assert isinstance(carried, dict)
    section, key = path.split(".")
    block = _descriptor()[section]
    assert isinstance(block, dict)
    assert block[key] == carried[path]


def test_the_promotion_names_the_sections_it_changed() -> None:
    """A repair of the database half says so. A promotion that touched the
    application half and called itself a database repair is the shape this
    keeps from passing quietly."""
    assert _ledger()[-1]["changed_sections"] == ["migration", "database"]
