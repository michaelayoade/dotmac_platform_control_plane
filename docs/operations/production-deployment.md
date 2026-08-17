# Vendor Control Plane production deployment

The production control plane is `vendor.dotmac.io` on the explicitly selected
host `149.102.158.144`. It is a separate third-plane assembly. It does not share
Sub's database, import Sub, or become authoritative for Sub's subscribers. Sub
remains live at `selfcare.dotmac.io`; Vendor consumes only product-emitted,
digest-bound release evidence.

## Build once and deploy by digest

Production never builds from a checkout. `Build immutable production image`
runs on a disposable GitHub-hosted runner, uses a BuildKit secret to resolve the
three exact Forgejo package pins, publishes one SHA-tagged GHCR image, and emits
its immutable registry digest. `Deploy immutable image to production` accepts
only that digest shape, requires the `production` environment approval, verifies
the named `vendor-cp-prod` target, and transfers only the deployment adapter.

The host then performs one ordered operation:

1. atomically reconcile the exact assembly-owned, non-secret deployment-profile
   declaration from the versioned template while preserving every held secret
   and operator-owned value;
2. pull the exact digest;
3. start/verify PostgreSQL;
4. take a host-local `pg_dump` backup;
5. run `scripts/migrate.py`, the owner that composes all five lineages;
6. demote the first-cluster `app_admin` bootstrap superuser;
7. replace the app and prove `/health` on the loopback port.

The reconciliation allowlist contains only
`VENDOR_DEPLOYMENT_PROFILE`. It exists because the initial host bundle
predated `production-bootstrap`; re-rendering the complete file would require
OpenBao custody and a broad `sed` would risk secrets. The service refuses
duplicates, changes no other declaration, and preserves mode and ownership.

The database, product-manifest documents, `.env`, and signing key stay on the
host. The app image and Postgres image are immutable digest references. Neither
PostgreSQL nor the application port is publicly bound; nginx is the only public
entry point.

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
adapter and its `src/vendor_cp/production_secrets.py` service on the target
before `push`; never re-create the contract with shell substitutions.

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

The first run creates `.env` from `.env.production.example` and intentionally
stops. The checked-in materializer owns filling every secret field; inspect the
result without printing its values. Keep `VENDOR_PRODUCT_RELEASE_PINS_JSON={}`
for the first healthy boot.

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
  --profile ops run --rm ops scripts/create_platform_admin.py <operator-email>
```

## Adopt the current Sub release evidence

The current production evidence to ingest is:

- product: `dotmac-sub`;
- version: `7.177.0`;
- source revision: `e2c3bb041d96570b4ad07cdedf8616c34d829f47`;
- OCI digest: `sha256:8fce022f80d76c92ed07ed0a1beca1924b74b9276ce3b6fbd51e7e607d51cafd`;
- product-manifest digest:
  `sha256:76296d9d615dca4afb2574fca71e2bf140a5a7f7481082c734668018a7f9b1eb`;
- producing build run: `31753249550`.

Download the exact canonical manifest artifact from that run. Do not recreate
JSON from remembered capability codes. Verify its digest before mounting it
read-only into a one-off `ops` container and invoke
`scripts/catalogue_product_release.py` with the identities above. Only after
the ingestion succeeds should `.env` pin `dotmac-sub` to the two exact digests
and the app be restarted.

That earns Release Catalog's first real cutover only after the old Vendor
artifact writer is proven retired. It does not cut over Entitlement Allocation:
that module remains shadow-installed until the checked-in historical mapping,
duplicate normalization, parity, and one-writer gates all pass.

## Rollback

Redeploy the previous known-good application digest. Schema rollback is not an
automatic operation: forward-fix by default. If a migration makes that
impossible, stop the app and restore the pre-migration custom-format dump into a
new database/volume before changing traffic. Never silently run Alembic down or
delete the current production volume.
