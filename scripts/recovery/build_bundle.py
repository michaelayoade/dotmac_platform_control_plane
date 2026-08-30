#!/usr/bin/env python3
"""Turn a captured catalogue into a `PostgresRecoveryBundleV1` manifest.

Operator tool. Reads the JSON `capture_catalog.sql` emits and hands it to
`dotmac_deployment_foundation.recovery`, which owns every decision — the role
closure, the completeness refusals, the comparison. Nothing here re-implements
a check; if this file starts deciding whether a recovery is sound, the facility
has been forked into the product and the point is lost.

Two things it does own, because they are product shape rather than facility
policy:

* **Which roles reach the bundle.** `RoleFact` refuses a SUPERUSER, so the
  cluster owner cannot be carried. That exclusion is PRINTED rather than
  silent: a product role that had wrongly become superuser would otherwise
  vanish from the bundle at exactly the moment it most needed reporting.
* **Which privilege reading feeds which field.** The capture emits table and
  schema effective privileges separately; both go into
  `effective_privileges`, because the facility's isolation check reads that one
  field for both scopes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from dotmac_deployment_foundation.recovery import (
    BundleComponent,
    CatalogEvidence,
    DefaultPrivilegeFact,
    EffectivePrivilegeFact,
    ExtensionFact,
    FunctionSecurityFact,
    MembershipFact,
    OwnershipFact,
    PolicyFact,
    PrivilegeFact,
    RlsFact,
    RoleFact,
    TablespaceDecision,
    build_manifest,
    derive_role_closure,
)


def _digest(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evidence_from_capture(raw: dict[str, Any]) -> tuple[CatalogEvidence, list[str]]:
    """Build the facility's evidence type, reporting excluded superusers."""
    excluded = [r["name"] for r in raw["roles"] if r["superuser"]]
    roles = tuple(
        RoleFact(
            name=r["name"],
            can_login=r["can_login"],
            inherit=r["inherit"],
            superuser=False,
            createrole=r["createrole"],
            createdb=r["createdb"],
            replication=r["replication"],
            bypassrls=r["bypassrls"],
            connection_limit=r["connection_limit"],
        )
        for r in raw["roles"]
        if not r["superuser"]
    )
    effective = tuple(
        EffectivePrivilegeFact(
            role=e["role"],
            identity=e["identity"],
            privilege=e["privilege"],
            holds=e["holds"],
            scope=e["scope"],
        )
        for e in (*raw["effective_privileges"], *raw["effective_schema_privileges"])
    )
    return (
        CatalogEvidence(
            roles=roles,
            memberships=tuple(
                MembershipFact(
                    member=m["member"],
                    role=m["role"],
                    admin_option=m["admin_option"],
                    inherit_option=m["inherit_option"],
                    set_option=m["set_option"],
                )
                for m in raw["memberships"]
            ),
            ownership=tuple(
                OwnershipFact(kind=o["kind"], identity=o["identity"], owner=o["owner"])
                for o in raw["ownership"]
            ),
            privileges=tuple(
                PrivilegeFact(
                    scope=p["scope"],
                    identity=p["identity"],
                    grantee=p["grantee"],
                    privilege=p["privilege"],
                    grantor=p["grantor"],
                    grantable=p["grantable"],
                )
                for p in raw["privileges"]
            ),
            effective_privileges=effective,
            functions=tuple(
                FunctionSecurityFact(
                    signature=f["signature"],
                    owner=f["owner"],
                    security_definer=f["security_definer"],
                    public_may_execute=f["public_may_execute"],
                    executors=tuple(f["executors"]),
                )
                for f in raw["functions"]
            ),
            default_privileges=tuple(
                DefaultPrivilegeFact(
                    owner=d["owner"],
                    schema=d["schema"],
                    object_kind=d["object_kind"],
                    grantee=d["grantee"],
                    privilege=d["privilege"],
                )
                for d in raw["default_privileges"]
            ),
            policies=tuple(
                PolicyFact(
                    table=p["table"],
                    name=p["name"],
                    command=p["command"],
                    roles=tuple(p["roles"]),
                    permissive=p["permissive"],
                )
                for p in raw["policies"]
            ),
            row_security=tuple(
                RlsFact(table=r["table"], enabled=r["enabled"], forced=r["forced"])
                for r in raw["row_security"]
            ),
            extensions=tuple(
                ExtensionFact(name=e["name"], version=e["version"], schema=e["schema"])
                for e in raw["extensions"]
            ),
            schemas=tuple(raw["schemas"]),
            migration_heads=tuple(raw["migration_heads"]),
            tablespaces=TablespaceDecision(kind="none"),
        ),
        excluded,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True)
    parser.add_argument("--dump-digest", required=True)
    parser.add_argument("--product", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--postgres-major", type=int, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--captured-at", type=int, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    raw = json.loads(Path(args.capture).read_text())
    evidence, excluded = evidence_from_capture(raw)
    if excluded:
        print(
            f"excluded {len(excluded)} SUPERUSER role(s) from the bundle: "
            f"{excluded}. A bundle refuses to carry one — restoring a superuser "
            "turns possession of the artefact into possession of the cluster. "
            "A PRODUCT role in this list is a finding to fix at the source, not "
            "an expected cluster owner.",
            file=sys.stderr,
        )

    closure = derive_role_closure(evidence)
    print(f"role closure ({len(closure.required)}):", file=sys.stderr)
    for name in sorted(closure.required):
        print(f"  {name} — {closure.reason_for(name)}", file=sys.stderr)

    component_digests = {
        BundleComponent.DATABASE_DUMP.value: args.dump_digest,
        BundleComponent.ROLE_CLOSURE.value: _digest(sorted(closure.required)),
        BundleComponent.ROLE_ATTRIBUTES.value: _digest(raw["roles"]),
        BundleComponent.MEMBERSHIPS.value: _digest(raw["memberships"]),
        BundleComponent.OBJECT_OWNERSHIP.value: _digest(raw["ownership"]),
        BundleComponent.DEFAULT_PRIVILEGES.value: _digest(raw["default_privileges"]),
        BundleComponent.SCHEMA_PRIVILEGES.value: _digest(
            [p for p in raw["privileges"] if p["scope"] == "schema"]
        ),
        BundleComponent.OBJECT_PRIVILEGES.value: _digest(
            [p for p in raw["privileges"] if p["scope"] == "table"]
        ),
        BundleComponent.FINE_GRAINED_ACLS.value: _digest(raw["functions"]),
        BundleComponent.ROW_SECURITY.value: _digest(
            {"policies": raw["policies"], "row_security": raw["row_security"]}
        ),
        BundleComponent.EXTENSIONS.value: _digest(raw["extensions"]),
        BundleComponent.TABLESPACES.value: _digest({"kind": "none"}),
        BundleComponent.MIGRATION_HEADS.value: _digest(raw["migration_heads"]),
    }

    manifest = build_manifest(
        product=args.product,
        environment=args.environment,
        postgres_major=args.postgres_major,
        source_revision=args.source_revision,
        captured_at_epoch=args.captured_at,
        evidence=evidence,
        component_digests=component_digests,
    )
    Path(args.out).write_text(json.dumps(json.loads(manifest.to_json()), indent=2))
    print(f"manifest {manifest.sha256_digest()} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
