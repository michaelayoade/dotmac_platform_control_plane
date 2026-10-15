# Gate-0 authority database measurement

`relay.runner.authority_database_runtime()` returns the existing configured
kernel singleton. It opens no session, constructs no dispatcher and supplies
the same delivery runtime used by `composed()`. Its lazy configured-runtime
import remains at the existing importer path and symbol inventory.

`deployment.gate0_database.qualify_authority_database()` first validates an
exact `DatabaseExpectation`, then imports that accessor inside its invocation.
The input has no credential, DSN, executable selector or qualification boolean.
All schema/head lists are nonempty, unique tuples with at most 64 entries;
names and revision lengths are bounded. Image/descriptor/source evidence must
agree through the existing `image_heads.compare_heads` owner before database
initialization is reached.

The qualifier uses that runtime's `platform_session_factory` and a repeatable-read, read-only
transaction. It sets transaction-local statement and lock deadlines (at most
2000 ms per statement) before identity/catalogue reads. It compares database,
current role, server IP/port and TLS state; refuses superuser, createdb,
createrole, replication or bypass-RLS roles; requires login; compares the exact
non-system schema set and the actual `public.alembic_version` head set against
the reviewed image and descriptor. Catalogue/head reads are capped at 65 rows
and refuse overflow. It reads no product table data and performs no migration,
DDL, role change, reset or commit. Every acquired session is rolled back and
closed, including refusal; database errors are translated to sanitized refusal.
The installed online role must have explicit metadata read privilege; this
source does not grant it or fall back to a privileged role.

A successful `DatabaseQualification` retains the identical runtime object.
Pass its runtime to `OwnerWindowReader` and check `require_runtime()` when
integrating it with an issuer. The issuer's mutation sessions must continue to
come from that admission reader's runtime. The result is in-process measured
evidence; trusted Python remains trusted, and constructor discipline is not an
isolation boundary against arbitrary Python execution.

This measurement does **not** qualify native driver connect or pool checkout
bounds, total lifetime, authenticated TLS peer identity or a protected private
route. Server IP/port and TLS-state equality alone cannot establish those
properties. A protected launch owner must bind the expected endpoint to the
accepted TLS peer or authenticated private route and prove native acquisition
bounds plus a total process deadline **before invoking the qualifier**. The
installed adapter must refuse an unqualified launch. No Python alarm or
statement timeout is advertised as a native-call termination proof. SQL reads
also require the original launch deadline to remain enforced by that qualified
supervisor. Transport and launch remain separately unqualified by this module.

Hosted test source covers actual singleton/accessor identity, unchanged relay
delivery wiring, early invalid-input refusal, read-only statements and cleanup,
wrong database/role/endpoint/TLS/schema/head vectors, and real PostgreSQL
catalogue measurement against an isolated synthetic installation. The migration
fixture's explicit metadata grant is synthetic evidence, not a production
privilege claim. Tests have not been executed locally; source AST and pinned
Ruff checks are the permitted local validation for this slice.
