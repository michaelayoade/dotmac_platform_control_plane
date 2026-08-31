# Vendor Control Plane production deployment

The production control plane is `vendor.dotmac.io` on the explicitly selected
host `149.102.158.144`. It is a separate third-plane assembly. It does not share
Sub's database, import Sub, or become authoritative for Sub's subscribers. Sub
remains live at `selfcare.dotmac.io`; Vendor consumes only product-emitted,
digest-bound release evidence.

## Build once and deploy by digest

Production never builds from a checkout. `Build immutable production image`
runs on a disposable GitHub-hosted runner, uses a BuildKit secret to resolve the
six exact Forgejo package pins, publishes one SHA-tagged GHCR image, and emits
its immutable registry digest. `Deploy immutable image to production` accepts
only that digest shape, requires the `production` environment approval, verifies
the named `vendor-cp-prod` target, and transfers only the deployment adapter.

The host then performs one ordered operation:

1. atomically reconcile the exact assembly-owned, non-secret deployment-profile
   declaration from the versioned template while preserving every held secret
   and operator-owned value;
2. pull the exact digest;
3. generate an ephemeral verifier for the separate `postgres` cluster-bootstrap
   role and start PostgreSQL;
4. reconcile the product-manifest volume to UID/GID 10001 and mode `0750`
   through the isolated, capability-limited `manifest-init` service;
5. verify that initialization created `app_admin` as a non-superuser,
   `BYPASSRLS` database/schema owner and removed the bootstrap verifier;
6. take a host-local `pg_dump` backup;
7. run `dotmac-platform admin migrate`, the owner that composes all eight
   lineages, as an installed console script inside the `ops` container;
8. replace the app and prove `/health` on the loopback port while declaring
   `Host: vendor.dotmac.io`, so the probe passes through the same trusted-host
   boundary as production traffic rather than weakening it for an IP-only probe.

The official Postgres image creates `POSTGRES_USER=postgres` as its bootstrap
superuser on a fresh volume. The first-cluster initializer creates the distinct
permanent `app_admin` migrator with `NOSUPERUSER`, `NOCREATEROLE`, `BYPASSRLS`,
database ownership, and `public` schema ownership before any kernel or module
DDL. It also creates the kernel's two narrow dispatcher login roles, so later
kernel revisions do not need to grant cluster-wide role authority to the
migrator, then removes the ephemeral bootstrap password. The deploy owner
verifies the final role and ownership contract before backup or migration because
`module_database_roles.v1` fails closed on a superuser migrator. The bootstrap
role never runs an application migration and its password is not retained in
the host environment.

The automatic deployment reconciliation allowlist contains only
`VENDOR_DEPLOYMENT_PROFILE`. It exists because the initial host bundle
predated `production-bootstrap`; re-rendering the complete file would require
OpenBao custody and a broad `sed` would risk secrets. The service refuses
duplicates, changes no other declaration, and preserves mode and ownership.
Release selection remains an explicit operator action: the same service's
`pin-product-release` command validates the complete declaration through the
runtime's canonical parser, changes exactly one product, and atomically
preserves every other byte, mode, and owner in the secret-bearing `.env` file.

The database, product-manifest documents, `.env`, and signing key stay on the
host. The app image and Postgres image are immutable digest references. Neither
PostgreSQL nor the application port is publicly bound; nginx is the only public
entry point. The named product-manifest volume is initialized by the deployment
owner before the app starts: the long-running app mounts it read-only, while the
one-off ops profile is the only UID 10001 process that mounts it read-write.

## One-time host contract

The canonical production OpenBao locations are:

- licence signing key: `secret/dotmac/licensing/signing-key`, containing exactly
  `key_id` and `private_key_b64url`;
- production database roles:
  `secret/dotmac/vendor-control-plane/production/database`, containing exactly
  `admin_password`, `app_user_password`, and `platform_api_password`;
- kernel runtime secrets:
  `secret/dotmac/vendor-control-plane/production/runtime`, containing exactly
  `jwt_secret` and `session_hash_secret`;
- deploy SSH identity:
  `secret/dotmac/vendor-control-plane/production/deploy-ssh`, containing exactly
  `private_key_openssh`, `public_key_openssh`, and `username`.

Never paste their values into a command, ticket, log, or tracked file. Use the
checked-in `vendor_cp.production_secrets` operator service. Its OpenBao writes
use KV v2 `cas=0`, so it creates an absent record but never overwrites an
existing issuer key or password set. It validates all four complete schemas
before materialization and atomically replaces each host-local file. Database
passwords are URL-safe because the composed runtime URLs hold them without
logging or transformation.

There is deliberately no persistent GHCR pull credential in OpenBao or on the
host. Each approved deployment pipes the same-repository, package-read
`GITHUB_TOKEN` over SSH stdin. The host logs in through a temporary Docker
configuration under `/run`, deploys the exact digest, logs out, and removes the
configuration on exit.

From an operator context that can authenticate to OpenBao, reach the named
host, and manage this repository's `production` environment, run the versioned
adapter from the exact `main` revision:

```bash
KNOWN_HOSTS=<approved-known-hosts-file>
PYTHONPATH=src python3 scripts/materialize_production_secrets.py seed
ssh -o "UserKnownHostsFile=$KNOWN_HOSTS" root@149.102.158.144 \
  "install -d /opt/dotmac/vendor-control-plane/{scripts,src/vendor_cp}"
rsync -azR -e "ssh -o UserKnownHostsFile=$KNOWN_HOSTS" \
  .env.production.example \
  scripts/materialize_production_secrets.py \
  src/vendor_cp/product_release_pins.py \
  src/vendor_cp/production_secrets.py \
  root@149.102.158.144:/opt/dotmac/vendor-control-plane/
PYTHONPATH=src python3 scripts/materialize_production_secrets.py push \
  --target root@149.102.158.144 \
  --target-dir /opt/dotmac/vendor-control-plane \
  --known-hosts "$KNOWN_HOSTS"
PYTHONPATH=src python3 scripts/materialize_production_secrets.py \
  sync-github-deploy-key \
  --repository michaelayoade/dotmac_vendor_control_plane \
  --environment production
```

`seed` prints record paths only. `push` transfers a validated bundle only on SSH
stdin and excludes the deployment private key. `sync-github-deploy-key` passes
that held private key to `gh secret set` only on stdin. Install this exact
adapter and both versioned service modules on the target before `push`; never
re-create the contract with shell substitutions.

Prepare the GitHub `production` environment with:

- variable `VENDOR_PRODUCTION_HOST=149.102.158.144`;
- variable `VENDOR_PRODUCTION_USER`;
- variable `VENDOR_PRODUCTION_DEPLOY_DIR=/opt/dotmac/vendor-control-plane`;
- secret `VENDOR_PRODUCTION_SSH_KEY`;
- secret `VENDOR_PRODUCTION_KNOWN_HOSTS`;
- required reviewers enabled.

Verify the required reviewer in GitHub's live environment settings before any
dispatch. The first production dispatch on 2026-08-17 was held at that gate and
released only after the connected owner approved the exact main SHA, immutable
digest, and named target. A protected-branch policy alone is insufficient.

After the signing key has been held at its canonical host path, transfer only
the versioned bootstrap script, nginx files, and environment example to a
temporary directory on the named server, then run:

```bash
CERTBOT_EMAIL=<operator-email> bash scripts/bootstrap_production_host.sh
```

`CERTBOT_EMAIL` is required only when the host has no registered Certbot
account. A host with an existing account reuses that account rather than
duplicating its contact declaration; bootstrap still refuses to register an
account without a contact. The production host currently carries the retained
Marketing certificate and its registered Certbot account, so the Vendor
certificate uses that existing account.

The first run creates `.env` from `.env.production.example` and intentionally
stops. The checked-in materializer owns filling every secret field; inspect the
result without printing its values. The `/etc/dotmac-host-id` marker is written
atomically only after the signing key, certificate hostname and lifetime,
final nginx configuration, and populated host environment are all present. A
failed partial bootstrap therefore cannot authorize a deployment. Keep
`VENDOR_PRODUCT_RELEASE_PINS_JSON={}` for the first healthy boot.

## First release

After this change is merged and its required CI is green, dispatch `Build
immutable production image` on `main`. Copy only the emitted `sha256:...` digest
into `Deploy immutable image to production`, enter target
`vendor-cp-prod`, and approve the protected environment after confirming the
host and digest.

Create the initial platform admin through the kernel-owned session boundary;
the password is prompted and never accepted on argv:

```bash
cd /opt/dotmac/vendor-control-plane
docker compose --env-file .env -f docker-compose.production.yml \
  --profile ops run --rm --no-deps ops \
  dotmac-platform admin create <operator-email> --password-stdin
```

The password arrives on **stdin**, never as the value of a flag: `/proc`
exposes another process's command line for as long as it runs, and a
registration token leaked into a transcript on this fleet exactly that way.
`--password-file` takes a path this host already holds if you would rather not
pipe it.

The `cd` above is the Compose project directory, which is where the compose
file and `.env` live — not an import root. Nothing in the image resolves code
relative to it.

## Adopt the current Sub release evidence

The current production evidence to ingest is:

- product: `dotmac-sub`;
- version: `7.187.1`;
- source revision: `121e1592db795d339c1bc6279277797891d41064`;
- production release revision: `4489ca1712f3c263d914f2af0ebfcf044aa70605`;
- OCI digest: `sha256:27b5324e765add48214b3668d39bb19557acbfac4c8a7edd98a4fb22b6e0c19a`;
- product-manifest digest:
  `sha256:e6e8ac94cf4d7840c4d61408add9727b26d60319c2d34fd61d04db8b2ced0f66`;
- producing build run: `32002740276`;
- successful production deploy run: `32009246911`.

Download the exact canonical manifest artifact from that run. Do not recreate
JSON from remembered capability codes. Verify its digest before mounting it
read-only into a one-off `ops` container and invoke
`dotmac-platform release record` with the identities above. Only after
ingestion succeeds, use the versioned operator seam rather than editing the
secret-bearing file:

```bash
PYTHONPATH=src python3 scripts/materialize_production_secrets.py \
  pin-product-release \
  --env-file .env \
  --product-code dotmac-sub \
  --artifact-digest <exact-published-OCI-digest> \
  --product-manifest-digest <exact-canonical-manifest-digest>
```

Then redeploy the same approved image digest so application boot consumes the
new pin. The command prints only the product code and whether a change was
needed; it never prints the `.env` file or any held value.

That earns Release Catalog's first real cutover only after the old Vendor
artifact writer is proven retired and the running application resolves the
held document through this exact pin. Entitlement Allocation is already the
greenfield production authority under `v014`; this release evidence supplies
its product-scoped catalogue input rather than creating another writer.

## Rollback

Redeploy the previous known-good application digest. Schema rollback is not an
automatic operation: forward-fix by default. If a migration makes that
impossible, stop the app and restore the pre-migration custom-format dump into a
new database/volume before changing traffic. Never silently run Alembic down or
delete the current production volume.
