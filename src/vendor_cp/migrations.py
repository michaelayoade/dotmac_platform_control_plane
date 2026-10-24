"""Compose the vendor migration lineage with the kernel's shipped base lineage.

The vendor control-plane database runs the KERNEL base migrations (shipped as
`dotmac_kernel` package data, located via the public `versions_dir()`), the
installed Release Catalog, Entitlement Allocation, Approvals, Commercial
Agreements, Licensing and Deployment Control module lineages, PLUS this repo's
own `alembic/versions` — one revision graph, eight separately-owned lineages.
Because all shared packages are installed dependencies (not fixed repo paths),
`version_locations` is composed programmatically rather than hard-coded in
`alembic.ini`.

Import-safe: builds an Alembic `Config` only — it constructs no engine (deny-case
D1) and imports only the kernel's PUBLIC `migrations` surface (deny-case D5).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from vendor_cp.deployment.cp_transition import (
        ArtifactStore,
        CpTransitionRequestV1,
        RecoveryContexts,
        VerifiedAuthorization,
    )
    from vendor_cp.deployment.transition_fence import FenceProof

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RevisionError
from alembic.util.exc import CommandError
from dotmac_approvals.migrations import versions_dir as approvals_versions_dir
from dotmac_commercial_agreements import (
    versions_dir as commercial_agreements_versions_dir,
)
from dotmac_deployment_control import versions_dir as deployment_control_versions_dir
from dotmac_entitlement_allocation import (
    versions_dir as entitlement_allocation_versions_dir,
)
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_kernel.planes import MODULE_PLANES_ENV_VAR
from dotmac_kernel.prerequisites import BINDINGS_ENV_VAR
from dotmac_licensing import versions_dir as licensing_versions_dir
from dotmac_release_catalog import versions_dir as release_catalog_versions_dir
from sqlalchemy import Connection, text
from sqlalchemy.exc import SQLAlchemyError

#: Where the Vendor lineage and `alembic.ini` live, when they are not beside a
#: checkout. An overridable knob with a documented default, per the repository's
#: "everything by config" rule.
#:
#: This exists because the assembly is INSTALLED AS A WHEEL now. The three paths
#: below used to be derived from `__file__` with `parents[2]`, which silently
#: assumed `src/vendor_cp/migrations.py` inside a source tree; from
#: `site-packages/vendor_cp/migrations.py` that expression resolves to the
#: interpreter's library directory and the lineage is simply not there.
#:
#: The migration lineage is deliberately NOT packaged into the wheel. Poetry
#: would place a top-level `alembic` directory at the wheel root, colliding with
#: the Alembic distribution's own import name — a name collision is a worse
#: failure than a configured path. So the image copies the lineage as DATA and
#: names where it put it.
MIGRATION_ROOT_ENV_VAR: Final[str] = "VENDOR_MIGRATION_ROOT"


class MigrationRootNotFound(RuntimeError):
    """The migration lineage is not where this process was told to look."""


#: The checkout layout, used when the environment says nothing. Correct for
#: development, tests and CI, all of which run from a source tree.
_CHECKOUT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


def migration_root() -> Path:
    """The directory holding `alembic.ini` and `alembic/versions`.

    Resolved on every call rather than frozen at import, so a process that sets
    the variable before running a migration gets the directory it named — and so
    a test can point it somewhere without reloading the module.

    Refuses rather than guessing: a root with no `alembic.ini` in it is reported
    with the variable to set, because the alternative is Alembic failing later
    with a message about a missing revision that says nothing about the cause.
    """
    configured = os.environ.get(MIGRATION_ROOT_ENV_VAR, "").strip()
    root = Path(configured).resolve() if configured else _CHECKOUT_ROOT
    if not (root / "alembic.ini").is_file():
        raise MigrationRootNotFound(
            f"no alembic.ini under {root}. This assembly is installed as a "
            "wheel and the migration lineage travels beside the deployment as "
            f"data, so set {MIGRATION_ROOT_ENV_VAR} to the directory holding "
            "`alembic.ini` and `alembic/versions`."
        )
    return root


def alembic_dir() -> Path:
    """The Alembic script location."""
    return migration_root() / "alembic"


def vendor_versions_dir() -> Path:
    """This assembly's own revision directory."""
    return alembic_dir() / "versions"


def composed_version_locations(*, root: Path | None = None) -> str:
    """Kernel, six independent modules and Vendor migration lineages."""
    vendor = (
        root / "alembic" / "versions" if root is not None else vendor_versions_dir()
    )
    return (
        f"{kernel_versions_dir()} "
        f"{release_catalog_versions_dir()} "
        f"{entitlement_allocation_versions_dir()} "
        f"{approvals_versions_dir()} "
        f"{commercial_agreements_versions_dir()} "
        f"{licensing_versions_dir()} "
        f"{deployment_control_versions_dir()} "
        f"{vendor}"
    )


#: The ONLY target the deploy path applies.
#:
#: `ap_0001_approvals` grants `platform_api` full DML on the approvals module's
#: tables and vendor `v012` takes it away; both run in ONE transaction, so the
#: grant is never a committed state. That guarantee has one reachable hole, and
#: it is an ordinary command rather than an exotic one: `alembic upgrade
#: ap_0001_approvals` stops after the module's own migration and COMMITS the
#: grant. Nothing about it looks dangerous, which is why the deploy path refuses
#: it rather than documenting it.
COMPOSED_TARGET: Final[str] = "heads"


def deploy_target_refusal(target: str) -> str | None:
    """Why the deploy path will not apply `target`, or `None` if it will.

    A function rather than a check inside the script, because the script is a
    thin adapter and this is the decision.
    """
    if target == COMPOSED_TARGET:
        return None
    return (
        f"refusing to upgrade to {target!r}: the deploy path applies composed "
        f"{COMPOSED_TARGET!r} only.\n"
        "A partial upgrade can stop after `ap_0001_approvals` and COMMIT the "
        "module DML grant that vendor `v012` exists to remove — the shadow "
        "composition is read-only only because both run in one transaction.\n"
        "Drive an intermediate target through `make_alembic_config` (the "
        "rehearsals do) if that is genuinely what you want."
    )


DEPLOYMENT_CONTROL_BARRIER: Final[str] = "dc_0015_plan_purpose"


class MigrationTransitionRefused(RuntimeError):
    """The supported deploy path cannot safely cross the source transition.

    Historical sources require the private, connection-bound capability issued
    by native_upgrade after verified retained evidence and live observations.
    Direct Alembic/rehearsal configurations are outside this bounded guard.
    """


def _has_data_bearing_relations(connection: Connection) -> bool:
    """Read the actual user catalogue; an empty version table proves nothing.

    Tables (including partitions and foreign tables), views, materialized views
    and sequences count even when empty. Only PostgreSQL-owned system namespaces
    and public.alembic_version are excluded. No application schema whitelist
    may hide an unversioned estate.
    """
    return bool(
        connection.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE c.relkind IN ('r', 'p', 'f', 'v', 'm', 'S') "
                "AND n.nspname NOT IN ('pg_catalog', 'information_schema') "
                "AND n.nspname !~ '^pg_toast($|_)' "
                "AND NOT (n.nspname = 'public' "
                "AND c.relname = 'alembic_version'))"
            )
        ).scalar_one()
    )


def _source_heads(connection: Connection) -> tuple[str, ...]:
    return MigrationContext.configure(
        connection, opts={"version_table_schema": "public"}
    ).get_current_heads()


def _revision_ancestry(script: ScriptDirectory, heads: tuple[str, ...]) -> set[str]:
    """Exact revision identities, following both lineage and dependency edges."""
    reached: set[str] = set()
    visiting: set[str] = set()

    def visit(revision_id: str, *, recorded_head: bool = False) -> None:
        if not isinstance(revision_id, str) or not revision_id.strip():
            raise MigrationTransitionRefused("malformed source migration heads")
        revision = script.get_revision(revision_id)
        # Persisted heads must be exact. Graph-owned dependency edges may use
        # Alembic branch labels, which resolve to their canonical revision here.
        if revision is None or (recorded_head and revision.revision != revision_id):
            raise MigrationTransitionRefused("unknown or noncanonical migration head")
        canonical = revision.revision
        if canonical in visiting:
            raise MigrationTransitionRefused("cyclic source migration ancestry")
        if canonical in reached:
            return
        visiting.add(canonical)
        for edge in (revision.down_revision, revision.dependencies):
            if edge is not None:
                for parent in (edge,) if isinstance(edge, str) else edge:
                    visit(parent)
        visiting.remove(canonical)
        reached.add(canonical)

    for head in heads:
        visit(head, recorded_head=True)
    return reached


def require_deploy_transition(connection: Connection, config: Config) -> None:
    """Refuse unsafe source states BEFORE run_migrations can issue any DDL.

    Called on the deploy connection inside its existing transaction. Existing
    databases may proceed only if the barrier is already in their ancestry.
    Fresh installation requires an empty catalogue. Historical transitions
    require native_upgrade's one-use capability on this exact transaction.
    """
    try:
        if connection.dialect.name != "postgresql":
            raise MigrationTransitionRefused(
                "deploy transition inspection requires PostgreSQL"
            )
        script = ScriptDirectory.from_config(config)
        # A missing/invalid barrier or target graph cannot authorize freshness.
        if DEPLOYMENT_CONTROL_BARRIER not in _revision_ancestry(
            script, tuple(script.get_heads())
        ):
            raise MigrationTransitionRefused("target graph lacks transition barrier")
        heads = _source_heads(connection)
        if len(set(heads)) != len(heads):
            raise MigrationTransitionRefused("duplicate source migration heads")
        reached = _revision_ancestry(script, heads)
        if not heads:
            if not _has_data_bearing_relations(connection):
                return
            raise MigrationTransitionRefused(
                "unversioned database contains user relations; freshness unproven"
            )
        # Reject impossible head sets rather than admitting a partial stamp.
        for head in heads:
            if head in _revision_ancestry(script, tuple(h for h in heads if h != head)):
                raise MigrationTransitionRefused("source heads overlap in ancestry")
        permission = config.attributes.get("_cp_transition_permission")
        if permission is not None:
            _consume_transition_permission(connection, config, heads, permission)
            return
        if DEPLOYMENT_CONTROL_BARRIER in reached:
            return
        raise MigrationTransitionRefused(
            f"source database has not reached {DEPLOYMENT_CONTROL_BARRIER}; "
            "the supported deploy path refuses this transition before DDL. "
            "Use the protected CP transition owner with verified retained evidence."
        )
    except (
        CommandError,
        RevisionError,
        SQLAlchemyError,
        ValueError,
        TypeError,
    ) as error:
        raise MigrationTransitionRefused(
            "source migration state could not be verified; refusing before DDL"
        ) from error


# Private process-local witnesses are never accepted from environment, JSON or
# a public Config flag. Durable claim creation below prevents a second issuance
# for the same reservation even after a process crash.
_TRANSITION_PERMISSIONS: dict[
    object, tuple[Connection, object, tuple[str, ...], tuple[str, ...], str]
] = {}


def _consume_transition_permission(
    connection: Connection, config: Config, heads: tuple[str, ...], permission: object
) -> None:
    from vendor_cp.deployment.image_heads import composed_effective_heads

    try:
        issued = _TRANSITION_PERMISSIONS.pop(permission)
    except (KeyError, TypeError) as error:
        raise MigrationTransitionRefused(
            "missing or consumed transition permission"
        ) from error
    bound_connection, transaction, source, target, tree_digest = issued
    if (
        connection is not bound_connection
        or connection.get_transaction() is not transaction
        or tuple(sorted(heads)) != source
        or config.attributes.get("_cp_migration_tree_digest") != tree_digest
        or composed_effective_heads(config) != target
    ):
        raise MigrationTransitionRefused(
            "transition permission connection or state drift"
        )


def _observe_transition_connection(
    connection: Connection,
    fence_connection: Connection,
    request: CpTransitionRequestV1,
    fence_proof: FenceProof,
) -> None:
    from vendor_cp.deploy_agent.contracts import require
    from vendor_cp.deployment.transition_fence import (
        WRITER_ROLES,
        FenceProof,
        fence_is_holding,
    )

    require(connection.dialect.name == fence_connection.dialect.name == "postgresql")
    require(connection is not fence_connection, "independent_fence_observer_required")
    require(connection.in_transaction() and not connection.in_nested_transaction())
    require(connection.get_execution_options().get("isolation_level") != "AUTOCOMMIT")
    # Engine-level isolation defaults need not appear in execution options.
    # Inspect the actual PostgreSQL driver state, not a configuration hint.
    require(
        getattr(fence_connection.connection.dbapi_connection, "autocommit", False)
        is True,
        "fence_observer_autocommit_required",
    )
    # Match transport coordinates without ever rendering or retaining a DSN.
    require(
        (connection.engine.url.host, connection.engine.url.port)
        == (fence_connection.engine.url.host, fence_connection.engine.url.port),
        "migration_server_mismatch",
    )
    observed = connection.execute(
        text(
            "SELECT current_database(), (SELECT oid FROM pg_database "
            "WHERE datname = current_database()), "
            "current_user, pg_backend_pid(), pg_postmaster_start_time(), "
            "(SELECT backend_start FROM pg_stat_activity "
            "WHERE pid = pg_backend_pid()), "
            "inet_server_addr()::text, inet_server_port()"
        )
    ).one()
    require(
        observed[0] == request["database"] and observed[1] == request["database_oid"]
    )
    require(observed[2] == "app_admin", "migration_role_mismatch")
    server = fence_connection.execute(
        text(
            "SELECT system_identifier::text, pg_postmaster_start_time(), "
            "inet_server_addr()::text, inet_server_port() FROM pg_control_system()"
        )
    ).one()
    require(server[0] == request["cluster_system_identifier"])
    require(
        (server[1], server[2], server[3]) == (observed[4], observed[6], observed[7])
    )
    backend = fence_connection.execute(
        text(
            "SELECT datname, datid, usename, backend_start "
            "FROM pg_stat_activity WHERE pid = :pid"
        ),
        {"pid": observed[3]},
    ).one()
    require(tuple(backend) == (observed[0], observed[1], observed[2], observed[5]))
    # Parse the existing owner's closed proof rather than trusting hand-built
    # role omissions; the configured writer inventory remains authoritative.
    proof = FenceProof.from_document(
        fence_proof.to_document(), expected_digest=fence_proof.digest()
    )
    require(proof.database == request["database"])
    require(set(proof.fenced_roles) | set(proof.absent_roles) == set(WRITER_ROLES))
    require(fence_is_holding(fence_connection, proof), "latest_fence_not_holding")
    require(
        not fence_connection.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_database d, "
                "LATERAL aclexplode(COALESCE(d.datacl, "
                "acldefault('d', d.datdba))) acl "
                "WHERE d.datname = :db AND acl.grantee = 0 "
                "AND acl.privilege_type = 'CONNECT')"
            ),
            {"db": request["database"]},
        ).scalar_one(),
        "public_can_reconnect",
    )
    require(
        tuple(sorted(_source_heads(connection))) == tuple(request["source"]["heads"]),
        "source_heads_drift",
    )


def _verified_migration_tree(
    repository_root: Path,
    revision: str,
    *,
    git_binary: Path,
    git_binary_digest: str,
) -> tuple[str, bytes]:
    """Bind protected Alembic files to exact target Git blobs, before imports.

    Package-owned lineages remain installed dependency owners. This checks the
    CP-owned execution tree only, not package or application artifact identity.
    """
    from vendor_cp.deploy_agent.contracts import canonical_json, require
    from vendor_cp.deployment import cp_transition as cp

    require(repository_root.is_absolute(), "migration_root_not_absolute")
    configured = os.environ.get(MIGRATION_ROOT_ENV_VAR, "").strip()
    require(
        not configured or Path(configured) == repository_root, "migration_root_override"
    )
    directory = cp._open_directory(repository_root)
    os.close(directory)
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None)
    require(
        cp._protected_executable_digest(git_binary) == git_binary_digest,
        "git_binary_mismatch",
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*args: str) -> bytes:
        completed = subprocess.run(  # noqa: S603 - protected pinned binary, fixed argv
            [
                str(git_binary),
                "--no-replace-objects",
                "-C",
                str(repository_root),
                *args,
            ],
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        require(completed.returncode == 0, "migration_git_read_failed")
        return completed.stdout

    entries = git(
        "ls-tree", "-rz", "--full-tree", revision, "--", "alembic.ini", "alembic"
    )
    expected: dict[str, bytes] = {}
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, _blob = header.split(b" ")
        path = raw_path.decode("utf-8")
        require(
            mode in {b"100644", b"100755"} and kind == b"blob",
            "migration_tree_nonregular_entry",
        )
        require(path == "alembic.ini" or path.startswith("alembic/"))
        require(".." not in Path(path).parts and path not in expected)
        require(
            not path.endswith((".pyc", ".pyo"))
            and "__pycache__" not in Path(path).parts
        )
        expected[path] = git("show", f"{revision}:{path}")
    require(
        {"alembic.ini", "alembic/env.py"} <= set(expected)
        and any(name.startswith("alembic/versions/") for name in expected),
        "migration_tree_incomplete",
    )
    actual = {"alembic.ini"}
    for parent, directories, files in os.walk(
        repository_root / "alembic", followlinks=False
    ):
        directory = cp._open_directory(Path(parent))
        os.close(directory)
        for name in directories:
            directory = cp._open_directory(Path(parent) / name)
            os.close(directory)
        actual.update(
            str((Path(parent) / name).relative_to(repository_root)) for name in files
        )
    require(actual == set(expected), "migration_tree_file_set_mismatch")
    for path, raw in expected.items():
        require(
            cp._read_protected(repository_root / path) == raw,
            "migration_tree_bytes_mismatch",
        )
    document = canonical_json(
        {
            "schema": "dotmac.cp_transition_migration_tree/1",
            "revision": revision,
            "files": {
                path: cp.raw_digest(raw) for path, raw in sorted(expected.items())
            },
        }
    )
    return cp.raw_digest(document), document


def native_upgrade(
    connection: Connection,
    *,
    fence_connection: Connection,
    request: CpTransitionRequestV1,
    authorization: VerifiedAuthorization,
    store: ArtifactStore,
    host_nonce: str,
    reservation_digest: str,
    genesis_digest: str,
    restore_digest: str,
    fence_digest: str,
    recovery: RecoveryContexts,
    fence_proof: FenceProof,
    evidence: Mapping[str, str],
    repository_root: Path,
    git_binary: Path,
    git_binary_digest: str,
) -> None:
    """Apply the composed CP graph once on the caller's exact transaction.

    This narrow source-only executor does not create an engine, commit, relax
    the generic deploy guard, or accept asserted permission flags. The caller
    holds the CP lock and owns independently measured source/restore evidence.
    """
    from alembic import command

    from vendor_cp.deploy_agent.contracts import canonical_json, require
    from vendor_cp.deployment import cp_transition as cp
    from vendor_cp.deployment.image_heads import composed_effective_heads

    tree_digest, tree = _verified_migration_tree(
        repository_root,
        request["target"]["revision"],
        git_binary=git_binary,
        git_binary_digest=git_binary_digest,
    )
    config = deploy_config(None, root=repository_root)
    config.set_main_option("prepend_sys_path", "")
    config.attributes["_cp_migration_tree_digest"] = tree_digest
    require(connection.in_transaction(), "migration_transaction_required")
    transaction = connection.get_transaction()
    require(
        getattr(connection.connection.dbapi_connection, "autocommit", False) is False,
        "migration_transaction_required",
    )
    cp.verify_authorization(request, authorization)
    cp.validate_request(
        request,
        identity=cp.CpTransitionIdentity(
            request["host"],
            request["database"],
            request["cluster_system_identifier"],
            request["database_oid"],
        ),
        now=datetime.now(UTC),
    )
    require(reservation_digest == cp.request_digest(request), "reservation_mismatch")
    require(fence_proof.fence_id == host_nonce, "transition_fence_identity_mismatch")
    require(
        evidence.get("source-genesis") == genesis_digest
        and evidence.get("recovery-restored") == restore_digest
        and evidence.get("fence-source-rechecked") == fence_digest,
        "transition_prefix_mismatch",
    )
    cp.verify_transition_prefix(
        request,
        authorization=authorization,
        store=store,
        host_nonce=host_nonce,
        evidence=evidence,
        recovery=recovery,
    )
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        target = composed_effective_heads(config)
    finally:
        sys.dont_write_bytecode = previous_bytecode
    require(tuple(request["target"]["heads"]) == target, "target_heads_mismatch")
    _observe_transition_connection(connection, fence_connection, request, fence_proof)
    try:
        require(store.read(tree_digest) == tree, "migration_tree_retention_mismatch")
    except FileNotFoundError:
        require(store.put(tree) == tree_digest)
    # Deterministic per reservation: changed stage digests cannot obtain another
    # execution attempt. Exclusive durable creation consumes even failed runs.
    store.put(
        canonical_json(
            {
                "schema": "dotmac.cp_transition_migration_claim/1",
                "request_digest": reservation_digest,
                "host_nonce": host_nonce,
                "migration_tree_digest": tree_digest,
            }
        )
    )
    permission = object()
    _TRANSITION_PERMISSIONS[permission] = (
        connection,
        connection.get_transaction(),
        tuple(request["source"]["heads"]),
        target,
        tree_digest,
    )
    config.attributes["connection"] = connection
    config.attributes["_cp_transition_permission"] = permission
    prior_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        command.upgrade(config, COMPOSED_TARGET)
        require(
            connection.get_transaction() is transaction
            and transaction is not None
            and transaction.is_active,
            "migration_transaction_changed",
        )
        require(
            tuple(sorted(_source_heads(connection))) == target, "target_heads_mismatch"
        )
    finally:
        sys.dont_write_bytecode = prior_bytecode
        _TRANSITION_PERMISSIONS.pop(permission, None)


def deploy_config(url: str | None, *, root: Path | None = None) -> Config:
    """`make_alembic_config`, plus the deploy path's transaction guards.

    `env.py` reads `require_composed_heads` and asserts, on the live connection,
    the source before any DDL and that every composed lineage reached its head
    afterwards — so a half-composed database
    rolls back instead of committing. Rehearsals deliberately do not set it: a
    partial upgrade is the whole point there.
    """
    config = (
        make_alembic_config(url)
        if root is None
        else make_alembic_config(url, root=root)
    )
    config.attributes["require_composed_heads"] = True
    return config


def make_alembic_config(url: str | None, *, root: Path | None = None) -> Config:
    """An Alembic `Config` wired to all lineages and the given database URL.

    Used by both the deploy entrypoint (`dotmac-platform admin migrate`) and the
    migration rehearsals, so CLI-vs-test composition can never diverge.
    """
    root = migration_root() if root is None else root
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("version_locations", composed_version_locations(root=root))
    # env.py reads the migration URL from the environment. DATABASE_URL is set too
    # because env.py imports `dotmac_kernel.messaging`, which eagerly constructs the
    # kernel engine from DATABASE_URL at import (it never connects here).
    if url is not None:
        os.environ["MIGRATION_DATABASE_URL"] = url
        os.environ.setdefault("DATABASE_URL", url)
    # `alembic heads`, `history` and `show` build the revision map WITHOUT
    # running `env.py`, so a lineage that resolves its `depends_on` from the
    # installed bindings and plane selections would see neither. These two
    # variables are the one channel both entry points share; setting them here
    # keeps an INSPECTED graph identical to the one an upgrade applies.
    #
    # ASSIGNED, never `setdefault`. These name THIS assembly's declarations, and
    # the assembly is authoritative for them — so a value already exported into
    # the process must lose, not win. `setdefault` had it exactly backwards: a
    # stale or foreign `DOTMAC_MIGRATION_BINDINGS` left over from another
    # assembly, a test, or a shell would survive, and `make_alembic_config`
    # would then inspect a different graph from the one it applies. That is the
    # precise failure the comment above claims to prevent.
    #
    # `DATABASE_URL` above is deliberately NOT in this group: it is the
    # deployment's own runtime DSN, which this function does not own and must
    # not overwrite — it only supplies a fallback so importing the kernel does
    # not fail. `MIGRATION_DATABASE_URL` is owned here and is assigned.
    os.environ[BINDINGS_ENV_VAR] = (
        "vendor_cp.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
    )
    os.environ[MODULE_PLANES_ENV_VAR] = (
        "vendor_cp.migration_bindings:ASSEMBLY_MODULE_PLANES"
    )
    return cfg


__all__ = [
    "COMPOSED_TARGET",
    "DEPLOYMENT_CONTROL_BARRIER",
    "MigrationTransitionRefused",
    "MIGRATION_ROOT_ENV_VAR",
    "MigrationRootNotFound",
    "alembic_dir",
    "composed_version_locations",
    "deploy_config",
    "deploy_target_refusal",
    "make_alembic_config",
    "native_upgrade",
    "migration_root",
    "require_deploy_transition",
    "vendor_versions_dir",
]
