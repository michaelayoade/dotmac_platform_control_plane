# D16 candidate app readiness under a writer fence

> Source contract for the Compose and app-preflight slice. The PostgreSQL
> identity lifecycle is owned by [D16 candidate roles](d16-candidate-roles.md).
> Neither source slice authorizes a production deployment or host provisioning.

## Isolated candidate app

After the role contract's strict fence, verified recovery bundle, owner
migration, and candidate-role activation gates, launch only a candidate app
from the exact selected immutable image. Use the standalone
`docker-compose.candidate.yml` alone, never as an override of the production
Compose file: merging would import the normal app and relay environment and
their old-role database URLs. No candidate relay or dispatcher runs before
the final restore/startup decision. Set `VENDOR_RELAY_EXPECTED=false` only for
this isolated preflight; its `/health/ready` verdict covers app/database and
queue-derived readiness, not relay liveness or full production readiness.

The app receives two distinct candidate URLs: `DATABASE_URL` uses the
run-scoped app role, and `PLATFORM_DATABASE_URL` uses the run-scoped platform
role. Dedicated per-run environment files are `0600`, owned by the account
invoking Compose, and held in a directory inaccessible to other accounts.
They may contain the runtime's other required secret material under existing
custody rules, but must contain no old database password, owner credential,
or dispatcher credential. The candidate credentials must be absent from the
shared production `.env`, command arguments, SQL/log output, and the normal
app container. Deployment orchestration must consume the reviewed role state
machine; it must not recreate one in shell.

A distinct staged-readiness verdict binds the role contract's run and
unchanged fence proof to the expected image, exact database heads, and
candidate URL-to-role mapping. It also requires that contract's staged
database proof immediately before readiness acceptance. This point-in-time
observation does not authorize public routing; the host must control
concurrent privileged ACL/catalog changes. After preflight, hand control back
to the role contract for candidate shutdown and exact ACL restoration. Then
start the normal app and relay with the new image, prove full readiness
including relay liveness, and only then restore public routing. On failure,
retain maintenance and follow the role contract's recovery path; a failed
candidate check never makes the old shared roles connectable merely for
another health check.

## Evidence and open activation gates

An isolated candidate app must prove its bounded `/health/ready` verdict
with the temporary DSNs while no relay worker can claim production events.
Startup and preflight must be proved not to commit domain, settings, audit,
or outbox changes. `read_only: true` constrains the container filesystem,
not its inherited PostgreSQL privileges: a before/after database observation
on a disposable migrated database is required before pre-rollback preflight
can run against production. Full readiness is separately proved after normal
app and relay startup and before routing.

The pure Compose-input builder pins the standalone file to reviewed SHA-256
bytes and a root/deploy-owned `0644` regular file. It requires an empty,
deploy-owned `0700` per-run Docker config and forces the local Unix Docker
socket. The caller-supplied expected image digest still needs binding to an
approved release receipt and fence state. The builder does not close the
time-of-check/time-of-use gap before Compose execution. The deploy account
also cannot inspect the UID-10001-held licence signing key beneath its
`0700` directory. Privileged key-custody verification and execution binding
remain unimplemented pre-launch gates; the privileged launcher must verify
the named external Docker network and volume before use.

The role contract owns bundle-before-role ordering and the `globals.sql`
exclusion proof. Its bundle owner must verify those claims independently;
this slice does not claim a bundle or release receipt exists for a production
attempt. A host rehearsal must bind the approved image and receipt, role
proof, separately provisioned target-only production ACL/HBA, key custody,
Compose bytes, external resources, and mutation-free readiness before
deployment wiring is accepted.

The dedicated non-production test host for isolated container/PostgreSQL
tests is `root@85.190.246.211`. This document does not authorize nginx
installation, public routing changes, shared-host service changes, or
production activation there.
