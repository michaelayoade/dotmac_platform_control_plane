"""Turn a captured catalogue into a `PostgresRecoveryBundleV1` manifest.

Migrated verbatim in behaviour from `scripts/recovery/build_bundle.py`. The
facility owns every decision — the role closure, the completeness refusals, the
comparison — and nothing here re-implements a check. If this module starts
deciding whether a recovery is sound, the facility has been forked into the
product and the point is lost.

Two things it does own, because they are product shape rather than facility
policy:

* **Which roles reach the bundle.** `RoleFact` refuses a SUPERUSER, so the
  cluster owner cannot be carried. That exclusion is REPORTED rather than
  silent: a product role that had wrongly become superuser would otherwise
  vanish from the bundle at exactly the moment it most needed reporting.
* **Which privilege reading feeds which field.** The capture emits table and
  schema effective privileges separately; both go into `effective_privileges`,
  because the facility's isolation check reads that one field for both scopes.

## The import is deliberately late, and its absence is deliberately `4`

`dotmac-deployment-foundation` is NOT a declared dependency of this assembly,
and pinning one would be a composition decision this lane does not own. The old
script imported it at module scope anyway, so it was a file that could only ever
run somewhere nobody had checked. Importing inside the function makes the
absence a runtime answer instead of a collection error, and the answer is
"unavailable evidence", not "refused" — the facility was never asked.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class BundleResult:
    """What building a manifest produced, in this product's own types.

    Concrete strings rather than the facility's objects: the caller renders
    this, and handing a CLI a facility type would make the output shape depend
    on a package version the assembly does not pin.
    """

    manifest_json: str
    manifest_digest: str
    excluded_superusers: tuple[str, ...]
    role_closure: tuple[tuple[str, str], ...]


def component_digest(value: object) -> str:
    """The canonical digest of one bundle component.

    Sorted keys and no whitespace, so the same facts digest the same way
    whatever order the capture emitted them in.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_bundle(
    capture: dict[str, Any],
    *,
    dump_digest: str,
    product: str,
    environment: str,
    postgres_major: int,
    source_revision: str,
    captured_at_epoch: int,
) -> BundleResult:
    """Map one capture onto the facility's evidence type and build its manifest."""
    from dotmac_deployment_foundation.recovery import (  # noqa: PLC0415 - see docstring
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

    excluded = tuple(str(r["name"]) for r in capture["roles"] if r["superuser"])
    evidence = CatalogEvidence(
        roles=tuple(
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
            for r in capture["roles"]
            if not r["superuser"]
        ),
        memberships=tuple(
            MembershipFact(
                member=m["member"],
                role=m["role"],
                admin_option=m["admin_option"],
                inherit_option=m["inherit_option"],
                set_option=m["set_option"],
            )
            for m in capture["memberships"]
        ),
        ownership=tuple(
            OwnershipFact(kind=o["kind"], identity=o["identity"], owner=o["owner"])
            for o in capture["ownership"]
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
            for p in capture["privileges"]
        ),
        effective_privileges=tuple(
            EffectivePrivilegeFact(
                role=e["role"],
                identity=e["identity"],
                privilege=e["privilege"],
                holds=e["holds"],
                scope=e["scope"],
            )
            for e in (
                *capture["effective_privileges"],
                *capture["effective_schema_privileges"],
            )
        ),
        functions=tuple(
            FunctionSecurityFact(
                signature=f["signature"],
                owner=f["owner"],
                security_definer=f["security_definer"],
                public_may_execute=f["public_may_execute"],
                executors=tuple(f["executors"]),
            )
            for f in capture["functions"]
        ),
        default_privileges=tuple(
            DefaultPrivilegeFact(
                owner=d["owner"],
                schema=d["schema"],
                object_kind=d["object_kind"],
                grantee=d["grantee"],
                privilege=d["privilege"],
            )
            for d in capture["default_privileges"]
        ),
        policies=tuple(
            PolicyFact(
                table=p["table"],
                name=p["name"],
                command=p["command"],
                roles=tuple(p["roles"]),
                permissive=p["permissive"],
            )
            for p in capture["policies"]
        ),
        row_security=tuple(
            RlsFact(table=r["table"], enabled=r["enabled"], forced=r["forced"])
            for r in capture["row_security"]
        ),
        extensions=tuple(
            ExtensionFact(name=e["name"], version=e["version"], schema=e["schema"])
            for e in capture["extensions"]
        ),
        schemas=tuple(capture["schemas"]),
        migration_heads=tuple(capture["migration_heads"]),
        tablespaces=TablespaceDecision(kind="none"),
    )

    closure = derive_role_closure(evidence)
    component_digests = {
        BundleComponent.DATABASE_DUMP.value: dump_digest,
        BundleComponent.ROLE_CLOSURE.value: component_digest(sorted(closure.required)),
        BundleComponent.ROLE_ATTRIBUTES.value: component_digest(capture["roles"]),
        BundleComponent.MEMBERSHIPS.value: component_digest(capture["memberships"]),
        BundleComponent.OBJECT_OWNERSHIP.value: component_digest(capture["ownership"]),
        BundleComponent.DEFAULT_PRIVILEGES.value: component_digest(
            capture["default_privileges"]
        ),
        BundleComponent.SCHEMA_PRIVILEGES.value: component_digest(
            [p for p in capture["privileges"] if p["scope"] == "schema"]
        ),
        BundleComponent.OBJECT_PRIVILEGES.value: component_digest(
            [p for p in capture["privileges"] if p["scope"] == "table"]
        ),
        BundleComponent.FINE_GRAINED_ACLS.value: component_digest(capture["functions"]),
        BundleComponent.ROW_SECURITY.value: component_digest(
            {
                "policies": capture["policies"],
                "row_security": capture["row_security"],
            }
        ),
        BundleComponent.EXTENSIONS.value: component_digest(capture["extensions"]),
        BundleComponent.TABLESPACES.value: component_digest({"kind": "none"}),
        BundleComponent.MIGRATION_HEADS.value: component_digest(
            capture["migration_heads"]
        ),
    }

    manifest = build_manifest(
        product=product,
        environment=environment,
        postgres_major=postgres_major,
        source_revision=source_revision,
        captured_at_epoch=captured_at_epoch,
        evidence=evidence,
        component_digests=component_digests,
    )
    return BundleResult(
        manifest_json=json.dumps(json.loads(manifest.to_json()), indent=2),
        manifest_digest=str(manifest.sha256_digest()),
        excluded_superusers=excluded,
        role_closure=tuple(
            (str(name), str(closure.reason_for(name)))
            for name in sorted(closure.required)
        ),
    )


__all__ = ["BundleResult", "build_bundle", "component_digest"]
