# ADR-0010: Move licence delivery to Integrator after Deployment Control

- **Status:** Accepted
- **Date:** 2026-08-20
- **Owners:** Vendor control plane / Deployment Control / Dotmac Integrator

## Context

ADR-0009 moves issuer authority to `dotmac-licensing` without combining that
database cutover with a cross-application transport migration. It therefore
retains five Vendor delivery/evidence tables and the local logging/offline
delivery paths temporarily.

That retention is not the final owner assignment. Fleet ADR-0024 gives
`dotmac-integration` the installation, binding, secret-reference, inbox/outbox,
delivery-attempt, retry, checkpoint, health and repair engine, run by the
independently deployed `dotmac_integrator` thin assembly. Connector plugins own
wire translation and I/O. Products do not maintain a second transport ledger.

Licence delivery also needs an authoritative destination. The local
`licence_delivery_targets` table is deliberately only a narrow projection; it
must not become the Deployment entity by accident. `dotmac-deployment-control`
is the released owner of deployment identity and desired state, but it is not
yet composed here. Moving delivery first would force Integrator either to trust
the temporary projection or invent a second destination map.

The current Vendor paths do not justify that inversion. Production bootstrap
withholds their routes, connected replay is not mounted, `LoggingTransport`
performs no handoff, and `OfflineBundleTransport` is an explicit operator
export. They are a bounded transition surface, not a transport platform to
extend.

## Decision

Licence delivery moves in a separate cutover **after Deployment Control and
before Brand Profiles**. ADR-0007's sequence is amended accordingly.

This ADR authorizes the sequence and the ownership target. It does not authorize
a production activation, an unnamed host operation, a placeholder connector, or
changes in another repository without its own focused change.

### 1. Freeze the temporary Vendor path

Until the cutover, Vendor may preserve the existing logging and authenticated
offline-bundle behavior. It may not add a network transport, provider client,
provider credential, schedule, checkpoint, lease, backoff policy or new retry
owner. Issuer work emits module facts; it does not grow the temporary delivery
implementation.

### 2. Compose Deployment Control first

The Deployment Control slice makes `mod_deploy` the one owner of deployment
identity and desired state. Any continuing `licence_delivery_targets` rows are
then a rebuildable projection reconciled from that owner, never an independently
registered destination. Integrator routing must bind to the Deployment Control
reference established before connector I/O; payload or connector metadata may
only corroborate it.

### 3. Vendor authors the product ports

Vendor then publishes versioned, authenticated, provider-neutral ports and a
digest-pinned descriptor for exactly three operations:

1. a durable delivery-intent handoff containing the issuance reference, digest
   and Deployment Control reference, but not the signed envelope;
2. an exact-artifact read returning the immutable module-owned envelope for that
   issuance; and
3. an acknowledgement command carrying the transport-authenticated deployment
   identity and durable Integrator receipt identity.

The envelope is fetched only for dispatch and is never copied into a generic
event, retry row, log or diagnostic. Private signing material never crosses the
port. Keyring distribution remains a separate trust-bootstrap concern and is
not bundled beside the document it authenticates.

Valid acknowledgements delegate to `dotmac-licensing`, the lifecycle owner.
Unverified, malformed, unknown and conflicting observations remain durable
Integrator inbox/reconciliation evidence; Vendor does not keep a second raw
acknowledgement ledger after cutover.

### 4. Integrator owns transport execution

The consuming change exact-pins a published `dotmac-integration` release and a
real connector distribution selected for the named transport. No dummy plugin
is permitted merely to satisfy composition. The module owns installations,
capability bindings, held secret references, delivery attempts, idempotency,
leases, retry/backoff, dead-letter/reconciliation states, checkpoints, health,
audit and repair. The connector owns only protocol translation and external I/O.

Integrator reads Vendor and writes the deployment only through the published
ports. It never reads Vendor, Deployment Control or product databases, imports
their ORM, or selects a destination from provider-controlled input.

### 5. Prove, seal, activate, then retire

The delivery cutover has these gates:

1. Deployment Control is composed and the destination reference resolves to its
   authority.
2. Vendor's port descriptor, delivery-intent, exact-artifact and acknowledgement
   contracts are checked in and authenticated.
3. The exact Integration and connector releases are installed in mirror mode.
   Mirror may compare canonical intent, digest, destination and expected wire
   request; it claims, sends and settles nothing.
4. A named non-production deployment shows zero unexplained drift for the
   agreed window, including retries and acknowledgements.
5. Vendor's local delivery writer and replay/export mutations are sealed before
   the Integrator binding becomes writable. There is never a dual-send window.
6. One enabled binding proves issue → fetch exact envelope → deliver → receiver
   apply → authenticated acknowledgement → module lifecycle, with Integrator
   receipts explaining every step.
7. The fallback window ends only after reconciliation. A fallback first disables
   the Integrator binding, reconciles every receipt, and only then may explicitly
   re-enable the old path; the two paths never write concurrently.

The estate premise is re-observed at execution time on a target Michael names.
If all five Vendor delivery/evidence tables are empty, a forward Vendor revision
may recheck them under lock and drop them with their writers. If any row exists,
the empty-estate path stops. A separate populated-estate ADR must export through
APIs, preserve immutable identities, attempt chronology and acknowledgement
evidence, reconcile the Integrator receipts, seal the old writer, and only then
retire the tables. Cross-database SQL and synthetic evidence are forbidden.

## Ownership after cutover

| Concern | Owner |
| --- | --- |
| Licence lineage, envelope, lifecycle, valid acknowledgements, revocation | `dotmac-licensing` |
| Private signing-key custody and authenticated licence artifact/ack adapters | Vendor control plane |
| Deployment identity and desired destination | `dotmac-deployment-control` |
| Bindings, secrets, inbox/outbox, attempts, retry, checkpoints, health and repair | `dotmac-integration` in `dotmac_integrator` |
| Wire authentication, translation and I/O | selected connector distribution |
| Applying the licence to local entitlements | receiving product |

## Retirement definition

The cutover is not complete while Vendor still owns any of these:

- `licence_delivery_targets`, `licence_deliveries`,
  `licence_delivery_states`, `licence_delivery_attempts` or
  `licence_ack_records`;
- `licensing/transport.py`, `licensing/delivery_ops.py`, the delivery projection
  writer or its replay/export/repair routes;
- `VENDOR_LICENCE_DELIVERY_MODE` or a Vendor delivery retry/health policy; or
- Vendor delivery-attempt, target, replay, bundle or quarantine audit actions.

The replacement Vendor surface is thin: immutable artifact reads and
authenticated acknowledgement delegation only. Adoption evidence is recorded
only after the enabled Integrator path runs and the Vendor transport writer is
absent.

## Consequences

- Deployment Control remains the next implementation slice after Licensing.
- Licence delivery is the following slice and blocks Brand Profiles in this
  programme, so the temporary transport cannot disappear from the roadmap.
- The issuer PR stays focused and reviewable; it does not pretend a second
  application's cutover happened locally.
- The current zero Governance connector baseline is not evidence that Vendor
  owns retry. It only says the detector found no direct external connector
  spelling; the semantic owner remains Integrator.
