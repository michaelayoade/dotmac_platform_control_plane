# D16 candidate PostgreSQL roles under the original writer fence

> Source contract for the role-lifecycle slice. Michael ruled on 2026-09-29
> that the writer fence closes before the old app and relay stop, and that
> candidate readiness uses distinct database identities. This source slice
> authorizes no Compose service, credential file, image admission, workload
> launch, host provisioning, or production deployment.

## Boundary and ordering

The original `fence_is_holding` proof denies `CONNECT` to `PUBLIC`, original
writers and their then-existing role members, and proves their sessions gone
from the target database. Granting `CONNECT` back to `app_user` or
`platform_api` for a candidate check would also admit an independently
started old image using those credentials. Neither ordinary role regains
`CONNECT` before the candidate has passed readiness. Temporary candidate
connectivity therefore requires a distinct staged proof; it must never be
called `fence_is_holding`.

1. Route to maintenance and prove it serves 503. Fence `PUBLIC`, original
   writers and all their then-existing members. Prove the strict fence;
   then stop the old app and relay and drain to two consecutive zero-session
   observations.
2. Create and verify the recovery bundle, migrate as the owner, and prove
   exact target migration heads while the **same original** strict fence
   holds. The bundle precedes candidate role creation, so `globals.sql`
   must exclude these ephemeral identities; the bundle owner independently
   proves that ordering and catalog claim.
3. Only then create two run-scoped `NOLOGIN` PostgreSQL roles using a
   privileged superuser connection, not `app_admin` (`NOCREATEROLE`). The
   host adapter must constrain that connection to the approved local socket;
   this source check verifies superuser and autocommit, not connection origin.
   Each has exactly one `INHERIT TRUE, SET FALSE, ADMIN FALSE` membership:

   | Candidate role | Sole parent | Later URL |
   | --- | --- | --- |
   | app | `app_user` | `DATABASE_URL` |
   | platform | `platform_api` | `PLATFORM_DATABASE_URL` |

   Neither role may inherit `app_admin`, the database owner, the other
   candidate's parent, or a dispatcher, including through its allowed
   parent's transitive memberships. The source refuses an existing candidate
   role name; the host adapter must issue a fresh run ID and prevent reuse
   across completed runs. The original `FenceProof`, digest and fence id
   remain immutable;
   no refence or replacement proof may absorb temporary membership. That
   expected membership delta makes original `fence_is_holding` false.
4. After a separate credential installer has placed a password verifier on
   each role, enable only those two logins and give each direct `CONNECT` on
   the target database. Original roles and `PUBLIC` remain denied. Before
   activation and at every staged verification, inspect every other
   `pg_database.datallowconn` database, including `postgres` and `template1`
   when connectable. Refuse effective candidate `CONNECT` there whether it
   comes through `PUBLIC`, inherited membership, or a direct grant: `LOGIN`
   is cluster-wide, and an exact target-DB ACL alone cannot prove isolation.
5. The staged database verifier binds run, original proof digest and fence id;
   requires the exact original-plus-two membership delta and exactly the two
   candidate direct `CONNECT` grantees; and refuses original-writer
   connectivity or sessions, altered role options or ACLs, and any effective
   candidate access to another connectable database. Image, migration-head,
   and URL-mapping checks belong to a later app-preflight slice. No staged
   verdict authorizes public routing.
6. Stop the candidate process and prove its sessions gone across the cluster.
   Disable candidate logins and revoke their direct `CONNECT`; the host
   destroys transient credential material. Atomically revoke memberships
   and drop both roles before any original ACL restore. Partial deactivation
   or cleanup must be restartable while refusing privilege, membership or
   ACL drift. Generic `restore_writers` refuses while a candidate remains
   a writer member; the candidate-aware wrapper also refuses if either role
   remains. Re-prove the strict fence against the unchanged original proof,
   then restore its ACL exactly.

No candidate dispatcher role is created. A live relay could claim and deliver
production events after the recovery bundle but before the rollback decision,
making that bundle an unsafe fallback. No event worker runs in the staged
window; relay liveness is proved only after normal startup and ACL restore.

On failure after the fence closes, stop candidate processes, remove candidate
connectivity, refence and drain, and retain maintenance. Do not claim a strict
fence until it is re-proved. A host failure that cannot re-prove it requires
explicit operator recovery, never silent traffic resumption.

This is a bounded transition guarantee. Once the original ACL is restored,
ordinary app roles and credentials work again. Host access to those
credentials can start an old image out of band. Temporary candidate identities
do not cryptographically bind a workload to an image; supported deployment
and rollback paths must reject incompatible images, and host access controls
govern out-of-band starts. Durable workload identity is a separate design.

Real PostgreSQL 16 tests must prove membership syntax and inherited
privileges, denied cross-role privileges, recursive fence capture, legacy
reconnect denial during staging, owner migration access, staged-verifier
refusals, deactivation and exact ACL restoration, and failure compensation.
The test fixture may restrict other-database `CONNECT` only on an explicitly
disposable cluster and must restore the prior decomposed ACL grants even on
failure. Production ACL/HBA provisioning, bundle verification and host
rehearsal remain separate gates. The verifier is a point-in-time catalog
observation; the host must recheck immediately before accepting readiness
and control concurrent privileged changes.
