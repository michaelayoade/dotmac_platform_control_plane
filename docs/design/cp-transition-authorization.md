# CP schema-transition authorization producer

Source-only implementation under the 2026-10-24 D16 amendment. This change
provides the request producer and authorization-only workflow. It establishes
neither environment protection nor host installation, a successful attestation
run, migration acceptance, image publication, deployment or D16 closure.

`.github/workflows/authorize-cp-transition.yml` accepts only manual dispatch on
protected `main`, in this repository, at the exact reviewed main revision
specified by `expected_workflow_revision`. The `production` environment gates
the job. The checkout uses that same immutable revision, with persisted Git
credentials disabled. The runner is GitHub-hosted Ubuntu 24.04. The workflow
has contents-read, OIDC-token-write and attestations-write permissions only;
no repository secrets, SSH, persistent signing key, image build, registry push
or host execution appears in the workflow. The attestation action explicitly
disables registry publication and artifact storage records, so it does not
need artifact-metadata permission.

## Operator input and authored output

`plan` is the exact closed `TransitionPlanV1` JSON in
`src/vendor_cp/deployment/transition_request.py`: product, environment, host,
database, cluster system identifier, database OID, source, target, previous
receipt digest (explicitly null for genesis), and plan digest. Each side is
closed over image digest, source revision, raw descriptor-byte digest and a
nonempty sorted unique migration-head set. Both images are immutable SHA-256
digests and must differ. The plan digest covers every field except itself,
using the existing CP `transition_plan_digest` convention. Duplicate JSON
members, unknown fields and mismatches refuse before signing.

The authoring adapter reuses `validate_request` and the CP contracts. It
validates the exact workflow/repository/ref/hosted-runner context, derives run
ID, attempt and actor from GitHub's runner environment, and sets expiry to
23 hours after its UTC clock. Operators cannot provide run identity, actor,
expiry, signing fields or a host nonce. A rerun creates a distinct request
while preserving its reviewed plan digest. Workflow revision is independent
of either image's source revision and any image build run identity.

The generated `request.json` is canonical CP JSON with no trailing newline.
The attestation uses the explicit subject name `request.json` and SHA-256 of
those exact bytes. Its predicate type is
`https://dotmac.io/attestations/cp-transition-authorization/v1` and its predicate
has exactly the three fields expected by `GhAttestationVerifier`:

```json
{"request_digest":"sha256:<canonical-request-digest>","trusted_actor":"<github.actor>","environment":"production"}
```

The upload artifact retains the request, predicate and Sigstore bundle for
30 days. Request authorization expires after 23 hours regardless of artifact
retention. The workflow makes no claim to observe source bytes or execute a
migration. The host independently compares installed identity and measured
source evidence, verifies the signed authorization, then generates its nonce
and consumes a durable single-use reservation before any side effect.

Only public parser dependencies required to import the established CP owner
(`cryptography`, `cffi`, `pycparser`) are installed. Their exact versions and
wheel hashes come from the reviewed `poetry.lock`; pip requires hashes,
disables dependency resolution, uses public PyPI and accepts wheels only.
This avoids installing private application dependencies in the signing job.

## Required preflight outside source implementation

Before anyone dispatches this workflow or installs host trust:

1. Independently verify GitHub's actual main branch/ruleset protection and the
   production environment configuration through authoritative GitHub state.
   The single authorized repository owner, `michaelayoade` (numeric ID
   `32591929`), may dispatch and must manually approve the protected production
   job. Require selected-main deployment restriction, that owner as the sole
   required reviewer, `prevent_self_review: false`, and
   `can_admins_bypass: false`. The producer and workflow bind both
   `GITHUB_ACTOR_ID` to the owner ID and `GITHUB_TRIGGERING_ACTOR` to the owner
   login, allowing that owner's reruns while refusing other initiators. Review
   who can change workflows, environment rules and branch protection. YAML's
   `environment: production` and `github.ref_protected` do not prove these rules.
2. Retain a fresh, independently checked
   closed `dotmac.cp_transition_environment_protection/2` record with
   `approval_model: "single-user-manual"`, `prevent_self_review: false`,
   `can_admins_bypass: false`, and reviewer IDs exactly `[32591929]`.
   Separately require the authored request actor to be the owner login.
   Include repository and owner IDs, exact workflow revision and expiry,
   and bind the raw-byte digest in the separately installed
   trust policy. This installed proof is a trusted snapshot of current
   configuration, not a historical review record. The verifier validates the
   exact hosted job and attempt that minted the attestation; it does not infer
   approval from terminal workflow success. The producer does not create this
   proof or infer reviewers from `github.actor`.
3. Separately approve and root-install the host identity, database and cluster
   identity, database OID, immutable reviewed workflow revision, predicate URI,
   pinned `gh` binary/digest/config directory, root-protected Docker and Git
   executable paths and SHA-256 digests, environment proof path/digest,
   and protected evidence store. Every ancestor and artifact must satisfy the
   host verifier's root ownership and write restrictions. There are no guessed
   production identity, reviewer, binary, path or workflow-revision defaults.
4. Validate the installed `gh attestation verify` API/output shape against an
   actual protected authorization artifact and exact expected certificate
   fields, predicate and subject before accepting the installation. A mocked
   unit fixture is not evidence of Sigstore issuance or protection settings.
   Host replay/expiry checks and fenced migration/restore/readiness proof are
   still required. Authorization is distinct from live-cutover approval.

The owner must approve the GitHub environment gate manually; an agent cannot
approve or bypass it. Refresh GitHub's actual settings before installing the
proof; an environment with `can_admins_bypass: true` is not ready.

The read-only GitHub repository connector on 2026-10-24 returned repository
`michaelayoade/dotmac_platform_control_plane`, ID `1317527604`, owner
`michaelayoade`, owner ID `32591929`, default branch `main`. These public
identity values are checked by both producer and workflow. That metadata query
did not inspect or verify branch/environment protection.

## Committed-migration continuation

The 2026-10-26 source amendment permits one separate request variant through
the existing operator and protected workflow. `CommittedMigrationPlanV1`
retains the historical source, exact prior application target and predecessor,
and adds an independently installed `operator_revision` plus a closed `basis`.
The new plan digest includes a fixed continuation discriminator. The workflow
still derives actor, run, attempt and expiry from its own protected context;
the signed request digest commits to all continuation pins. The existing V1
request and pre-restore held-fence loader do not accept this failure frontier.

An independently protected `dotmac.cp_committed_migration_context/1` file
binds the original request, reservation, authorization transcript, migration
claim and tree, post-commit migration and target-head evidence, failure,
quiescence snapshots, recovery bundle and original/current fence proofs.
The failed prefix has no candidate-ready or later successful checkpoint.
Candidate cleanup on failure retains its quiescence proof and snapshots but
does not retain a successful closure stage; the continuation validates those
actual bytes directly and independently measures current candidate absence.
It must not manufacture a missing historical stage.

Historical authorization is evidence only. Its separately pinned context
contains the original trust policy/protection snapshot and protected raw
`invocation.json` and `result.json` paths and digests. Their closed records bind
the original request/run, work directory and failed owner result. The original
`started_unix` and `completed_unix` bound execution; validate expiry and
protection at both bounds, and verified issuance before that window. An
attestation timestamp alone is insufficient, and this checker never creates
a fresh execution witness from retained JSON.

Under the canonical lock, admission verifies the retained prefix and original
backup checksums, then measures current target heads, immutable application
identity, maintenance, stopped incumbents, absent candidates, zero writers,
strict ACL and original grant lineage. The complete canonical quiescence
measurement must match across contexts, including catalogue, relation storage,
counters, sequences and restart/reset facts. Snapshot request/nonce envelopes
remain distinct. The existing target-only CONNECT check also runs before
reservation and rebind, with no exception for system databases or PUBLIC grants.

Fresh request reservation precedes an exclusive frontier reservation in the
**original attempt store**, keyed only by original request digest and nonce.
This prevents sibling contexts and distinct fresh artifact directories from
consuming the same frontier. The fence proof's ID is not a database-side
durable replay marker. Partial reservations remain consumed; neither is
deleted or retried. Rebind uses the existing public fence owner and retains
the original ACL baseline.

Both request variants use one candidate/readiness/ACL/routing suffix. The
continuation performs no capture, scratch restore or migration. Its distinct
`dotmac.cp_committed_migration_receipt/1` verifies the original prefix and fresh
suffix in their own contexts. Routing verification and subsequent V1 history
explicitly dispatch this receipt type; historical recovery bindings remain
under the original request key. Failed suffixes remain fenced and do not form
a new resumable frontier. Returning to the old schema requires separately
authorized recovery.

This contract authorizes source implementation and isolated tests. Release,
installation, any maintenance-database ACL repair, fresh protected job approval
and live execution require their own concrete gates and authority.

## Immutable action sources and validation

Pins were resolved through the official GitHub REST tag references and checked
against the official action source on 2026-10-24:

| Action | Tag | Immutable commit / primary source |
| --- | --- | --- |
| checkout | v7.0.1 | [3d3c42e5aac5ba805825da76410c181273ba90b1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1) |
| setup-python | v7.0.0 | [5fda3b95a4ea91299a34e894583c3862153e4b97](https://github.com/actions/setup-python/commit/5fda3b95a4ea91299a34e894583c3862153e4b97) |
| attest | v4 | [1e69f48acb82d1966a394da916b4c1698aa569d6](https://github.com/actions/attest/blob/1e69f48acb82d1966a394da916b4c1698aa569d6/action.yml) |
| upload-artifact | v7.0.2 | [cf430e030ddbb5b0abf93d22962f4752f3646cd9](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9) |

The pinned [attest documentation](https://github.com/actions/attest/blob/1e69f48acb82d1966a394da916b4c1698aa569d6/README.md)
defines custom predicates, keyless issuance, `bundle-path`, explicit subjects,
and disabling storage records. Attestation verification still belongs to the
host's pinned `GhAttestationVerifier` trust policy.

On the authorized dedicated test server / hosted CI, run:

```sh
poetry run pytest -q tests/unit/test_transition_request.py tests/unit/test_cp_transition.py
poetry run ruff check src/vendor_cp/deployment/transition_request.py tests/unit/test_transition_request.py
poetry run ruff format --check src/vendor_cp/deployment/transition_request.py tests/unit/test_transition_request.py
actionlint .github/workflows/authorize-cp-transition.yml
```

The unit suite exercises the CLI, exact consumer roundtrip/predicate, output
bytes, rerun identity, closed-field injection, every plan side/binding and
untrusted workflow context. Actionlint validates syntax and GitHub expression
contexts without triggering a workflow. Live dispatch, trust installation and
production mutation require their separately authorized and verified steps.

### PostgreSQL catalogue parse comparison

Recovery retains both raw catalogues and their actual digests. All non-catalogue
source-observation fields remain exact. The protected restore evidence also
retains a closed `cp_catalogue_restore_comparison/1` record bound to the request,
nonce, source database identity, both catalogues and the independently observed
PostgreSQL parser identity. Every unaffected category, constraint identity and
metadata flag must agree. Changed ordinary local table CHECK expressions are
parsed into separate temporary views against the same restored table; complete
`pg_get_viewdef(..., false)` outputs must agree. This delegates cast resolution
to PostgreSQL without running the views or rewriting constraints. Temporary DDL
is rolled back and a fresh catalogue measurement must equal the original
restored bytes. The core independently requires the parser to be in a different
cluster from production. Unsupported shapes and incomplete proof coverage
refuse. Like other measured host-stage records, offline verification establishes
bindings and does not assert provenance against a malicious root.
