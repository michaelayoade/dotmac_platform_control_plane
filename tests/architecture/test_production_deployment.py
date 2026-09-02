"""Production deployment is immutable, isolated, and fail-closed.

These are shape guards for the deployment boundary rather than a substitute for
the live first-deploy rehearsal.  They prevent the cheap regressions that would
turn the production host back into a build machine, expose PostgreSQL, mount
source code, or start the application before its backup and composed migrations.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _commands(script: str) -> str:
    """The script with its comment lines blanked, for ORDERING assertions.

    `str.index` finds the first occurrence, and a comment that explains the
    order necessarily quotes the same literals the probes search for — so a
    paragraph beginning "`compose up -d app` is the SEVENTH action" makes the
    ordering guard measure the prose instead of the script. Measured: it did.

    This is the same correction as `test_the_import_path_guard_can_still_see_an
    _assignment` below. The property is about what the script DOES, and writing
    down why is exactly the documentation these rules most want to exist.
    """
    return "\n".join(
        "" if line.lstrip().startswith("#") else line for line in script.splitlines()
    )


def test_runtime_image_uses_a_build_secret_and_runs_unprivileged() -> None:
    dockerfile = _text("Dockerfile")

    assert dockerfile.startswith("# syntax=docker/dockerfile:")
    assert dockerfile.count("python:3.12-slim@sha256:") == 2
    assert "--require-hashes --only-binary=:all:" in dockerfile
    assert ".github/bootstrap/poetry-requirements.txt" in dockerfile
    assert "--mount=type=secret,id=forgejo_token" in dockerfile
    assert "POETRY_HTTP_BASIC_FORGEJO_PASSWORD" in dockerfile
    assert not re.search(
        r"^(?:ARG|ENV) .*FORGEJO.*(?:TOKEN|PASSWORD)", dockerfile, re.M
    )
    assert "poetry install --only main --no-root" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'CMD ["uvicorn", "vendor_cp.main:app"' in dockerfile

    cmd = dockerfile.split("CMD ", 1)[1]
    assert "migrate" not in cmd.lower()
    assert "alembic" not in cmd.lower()


def test_the_runtime_image_installs_the_wheel_and_carries_no_source_tree() -> None:
    """The assembly is INSTALLED, and the runtime stage has nothing else to run.

    Three properties, and the third is what makes the first two provable. The
    wheel is built and installed, so `vendor_cp` has distribution metadata and
    `dotmac-platform` is a console script. There is no `PYTHONPATH`, so nothing
    is imported from a directory somebody copied. And the runtime stage copies
    no `src` and no `scripts` AT ALL, so a checkout-relative invocation has
    nothing to resolve against — it fails loudly instead of quietly running
    whichever bytes were last written there.

    The builder stage runs `dotmac-platform --version` against the freshly
    installed wheel, which fails the BUILD if the entry point is not wired.
    """
    dockerfile = _text("Dockerfile")
    runtime = dockerfile.split("AS runtime", 1)[1]
    builder = dockerfile.split("AS runtime", 1)[0]

    # `poetry build` with no `--format`, deliberately: BOTH distributions are
    # produced so the release receipt can carry a per-file digest for each
    # (this repository's ADR-0018 § 2.1). Only the wheel is installed — the
    # sdist exists to answer "which source archive corresponds to this image?"
    # without a rebuild, and the build refuses if either one is missing.
    assert "poetry build --no-interaction" in builder
    assert "--format wheel" not in builder
    assert "no wheel was built" in builder
    assert "no sdist was built" in builder
    assert '/bin/pip" install --no-deps --no-index dist/*.whl' in builder
    assert "/bin/dotmac-platform" in builder
    assert "--version" in builder

    # The property is that nothing SETS an import path, not that the word is
    # unmentionable. A blunt substring test failed on the comment explaining the
    # absence — which is the documentation this rule most wants written, and is
    # the same mistake as a ledger checking a name instead of an identity.
    assignments = [
        line
        for line in dockerfile.splitlines()
        if not line.lstrip().startswith("#") and "PYTHONPATH=" in line
    ]
    assert assignments == [], assignments
    assert "COPY --chown=10001:10001 src" not in runtime
    assert "COPY --chown=10001:10001 scripts" not in runtime
    assert "VENDOR_MIGRATION_ROOT=/app" in runtime
    assert "COPY --chown=10001:10001 alembic ./alembic" in runtime


def test_the_import_path_guard_can_still_see_an_assignment() -> None:
    """SENSITIVITY. An empty offender list is also what a broken check returns,
    and this one has already been wrong once in the permissive direction.

    The planted value is deliberately NOT the production shape. The guard's
    property is "something assigns an import path", which any path proves, and
    `vendor_cp.installed_surface` is the owner of production-shape detection —
    with its own two-directional sensitivity proof. Planting the real string
    here would put a production-shaped occurrence into a file the ratchet
    scans, which would then have to be declared as debt it is not.
    """
    planted = [
        "# There is deliberately no PYTHONPATH here.",
        "ENV PYTHONPATH=/opt/elsewhere \\",
    ]
    assignments = [
        line
        for line in planted
        if not line.lstrip().startswith("#") and "PYTHONPATH=" in line
    ]
    assert assignments == ["ENV PYTHONPATH=/opt/elsewhere \\"]


def test_the_ops_container_runs_the_console_script_not_an_interpreter() -> None:
    """`run ... ops dotmac-platform ...` must reach the CLI, not `python <path>`.

    The ops service used to declare `entrypoint: ["python"]`, which turned the
    first argument of every `docker compose run` into a FILE PATH resolved
    against `/app`. That worked only because the image copied `scripts/` in.
    With no entrypoint the command is executed directly, so what runs is the
    installed console script and a path would resolve against nothing.
    """
    compose = _text("docker-compose.production.yml")
    ops = compose.split("  ops:" + chr(10), 1)[1]

    assert "entrypoint:" not in ops
    assert 'command: ["dotmac-platform", "diagnose", "self"]' in ops
    assert "scripts/" not in ops


def test_production_compose_pulls_only_and_keeps_state_private() -> None:
    compose = _text("docker-compose.production.yml")

    assert "build:" not in compose
    assert "image: ${VENDOR_APP_IMAGE:?" in compose
    assert '"127.0.0.1:${VENDOR_APP_PORT:-8100}:8000"' in compose
    assert "vendor_postgres_data:/var/lib/postgresql/data" in compose
    assert "vendor_product_manifests:/run/dotmac/product-manifests:ro" in compose
    assert "vendor_product_manifests:/run/dotmac/product-manifests:rw" in compose
    assert "${VENDOR_LICENCE_SIGNING_KEY_HOST_FILE:?" in compose
    assert (
        ":/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key:ro"
        in compose
    )
    assert 'profiles: ["ops"]' in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "headers={'Host': 'vendor.dotmac.io'}" in compose
    assert "vendor_backend:\n    internal: true" in compose
    assert 'com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"' in compose

    manifest_init = compose.split("  manifest-init:\n", 1)[1].split("  app:\n", 1)[0]
    assert 'profiles: ["ops"]' in manifest_init
    assert 'user: "0:0"' in manifest_init
    assert "network_mode: none" in manifest_init
    assert "vendor_product_manifests:/manifests:rw" in manifest_init
    assert "chown 10001:10001 /manifests" in manifest_init
    assert "chmod 0750 /manifests" in manifest_init
    assert "cap_drop:" in manifest_init and "- ALL" in manifest_init
    assert "cap_add:" in manifest_init and "- CHOWN" in manifest_init
    assert "- FOWNER" in manifest_init
    assert "no-new-privileges:true" in manifest_init

    db_block = compose.split("  db:\n", 1)[1].split("  app:\n", 1)[0]
    assert "ports:" not in db_block
    assert "POSTGRES_USER: postgres" in db_block
    assert "POSTGRES_PASSWORD: ${VENDOR_DB_BOOTSTRAP_PASSWORD:?" in db_block
    assert "POSTGRES_PASSWORD: ${VENDOR_DB_ADMIN_PASSWORD" not in db_block
    assert "pg_isready -U app_admin" in db_block


def test_database_initialization_never_embeds_passwords() -> None:
    initializer = _text("deploy/postgres/init-roles.sh")

    assert "\\getenv admin_password VENDOR_DB_ADMIN_PASSWORD" in initializer
    assert "\\getenv app_user_password VENDOR_DB_APP_USER_PASSWORD" in initializer
    assert (
        "\\getenv platform_api_password VENDOR_DB_PLATFORM_API_PASSWORD" in initializer
    )
    assert "CREATE ROLE app_admin LOGIN NOSUPERUSER BYPASSRLS" in initializer
    assert "CREATE ROLE outbox_dispatcher LOGIN NOSUPERUSER NOBYPASSRLS" in initializer
    assert (
        "CREATE ROLE platform_outbox_dispatcher LOGIN NOSUPERUSER NOBYPASSRLS"
        in initializer
    )
    assert (
        "ALTER ROLE app_admin NOSUPERUSER NOCREATEROLE BYPASSRLS LOGIN" in initializer
    )
    assert "ALTER ROLE app_admin PASSWORD :'admin_password'" in initializer
    assert 'ALTER DATABASE :"database_name" OWNER TO app_admin' in initializer
    assert "ALTER SCHEMA public OWNER TO app_admin" in initializer
    assert "ALTER ROLE postgres PASSWORD NULL" in initializer
    assert "PASSWORD :'app_user_password'" in initializer
    assert "PASSWORD :'platform_api_password'" in initializer
    assert "set -x" not in initializer


def test_platform_admin_bootstrap_uses_kernel_transaction_authority() -> None:
    """The bootstrap moved from a script into the installed CLI; the rules did not.

    It reads the same three properties out of `vendor_cp.cli.commands` that it
    used to read out of `scripts/create_platform_admin.py`: the kernel owns the
    transaction, no second engine is built, and the password never appears as
    the value of a flag. The secret rule is now checked in its strongest form —
    the parser is built and every option name inspected — in
    `tests/architecture/test_installed_cli.py`.
    """
    bootstrap = _text("src/vendor_cp/cli/commands.py")
    runtime = _text("src/vendor_cp/cli/runtime.py")

    assert "platform_session" in runtime
    assert "upsert_platform_admin" in bootstrap
    assert "read_secret" in bootstrap
    assert "create_engine" not in bootstrap
    assert "sessionmaker" not in bootstrap
    assert '"--password"' not in bootstrap


def test_deploy_backs_up_and_runs_the_composed_migration_owner_before_app() -> None:
    deploy = _text("scripts/deploy_production.sh")
    compose = _text("docker-compose.production.yml")

    assert "docker compose" in deploy
    assert "docker compose build" not in deploy
    # The INSTALLED console script, not a path into the image. `scripts/` is
    # not copied into the runtime stage at all any more, so a path here would
    # resolve against nothing.
    assert "ops dotmac-platform admin migrate" in deploy
    assert "scripts/migrate.py" not in deploy
    assert "alembic upgrade" not in deploy
    assert "ghcr.io/michaelayoade/dotmac_vendor_control_plane@${DIGEST}" in deploy
    assert "APP_ENV=production" in deploy
    assert "SERVER_NAME=vendor-cp-prod" in deploy

    commands = _commands(deploy)
    # Two DISTINCT literals, because "pg_dump" is a substring of "pg_dumpall"
    # and `str.index` returns the first hit: after the globals capture landed,
    # a probe for "pg_dump" resolved to the globals line and the dump itself
    # was ordered by nothing. The dump is identified by `--format custom`,
    # which only it carries.
    globals_capture = commands.index("pg_dumpall")
    backup = commands.index("--format custom")
    bootstrap_password = commands.index("secrets.token_urlsafe")
    start_db = commands.index("up -d --wait db")
    initialize_manifests = commands.index("run --rm --no-deps manifest-init")
    verify_roles = commands.index("module database role contract is not satisfied")
    migrate = commands.index("dotmac-platform admin migrate")
    replace = commands.index("up -d app")
    assert (
        bootstrap_password
        < start_db
        < initialize_manifests
        < verify_roles
        < globals_capture
        < backup
        < migrate
        < replace
    )
    assert "ALTER ROLE app_admin" not in deploy
    assert '"false|false|true|true"' in deploy
    assert '--header "Host: vendor.dotmac.io"' in deploy
    assert (
        "VENDOR_DB_BOOTSTRAP_PASSWORD"
        not in compose.split("  app:\n", 1)[1].split("  ops:\n", 1)[0]
    )
    assert "VENDOR_DB_BOOTSTRAP_PASSWORD" not in compose.split("  ops:\n", 1)[1]


def test_production_environment_has_no_secret_defaults() -> None:
    example = _text(".env.production.example")

    required_empty = {
        "VENDOR_DB_ADMIN_PASSWORD",
        "VENDOR_DB_APP_USER_PASSWORD",
        "VENDOR_DB_PLATFORM_API_PASSWORD",
        "JWT_SECRET",
        "SESSION_HASH_SECRET",
        # Declared 2026-09-01. Kernel a98 makes a production CSRF_SECRET fatal
        # three ways, and this template previously declared `CSRF_ENABLED=true`
        # and no secret at all — so a host materialized from it could not boot
        # the artifact.
        "CSRF_SECRET",
    }
    values = dict(
        line.split("=", 1)
        for line in example.splitlines()
        if line and not line.startswith("#") and "=" in line
    )
    assert required_empty <= values.keys()
    assert all(values[key] == "" for key in required_empty)
    assert values["ENVIRONMENT"] == "production"
    assert values["PLATFORM_ROOT_DOMAIN"] == "vendor.dotmac.io"
    assert values["VENDOR_LICENCE_SIGNING_MODE"] == "configured"
    assert values["VENDOR_PRODUCT_RELEASE_PINS_JSON"] == "{}"
    # The profile is required on the host, not defaulted in the image. Since
    # ADR-0015 the loader ALSO refuses an absent profile in a production
    # environment, so this line is the cheap early check rather than the only
    # thing between the host and `full` — which would publish every withheld
    # surface, the provisioning laboratory included.
    assert values["VENDOR_DEPLOYMENT_PROFILE"] == "production-bootstrap"
    assert "grep -Fqx 'VENDOR_DEPLOYMENT_PROFILE=production-bootstrap'" in _text(
        "scripts/deploy_production.sh"
    )


def test_image_workflow_builds_on_github_hosted_runner_and_publishes_a_digest() -> None:
    workflow = _text(".github/workflows/production-image.yml")

    assert "runs-on: ubuntu-latest" in workflow
    assert "self-hosted" not in workflow
    assert "docker build" in workflow
    assert "docker push" in workflow
    assert "id=forgejo_token,env=FORGEJO_READ_TOKEN" in workflow
    assert "${{ steps.publish.outputs.digest }}" in workflow
    assert ":latest" not in workflow


def test_image_smokes_use_the_production_database_dialect() -> None:
    """No artifact check may run against a dialect production does not use.

    The candidate battery moved out of the workflow and into
    `.github/candidate/acceptance.sh`, which builds its DSNs through one `dsn`
    helper rather than repeating a literal — so the assertion is on the scheme
    and the roles, which is the property, rather than on a string that happened
    to be spelled out when the checks lived inline.
    """
    workflow = _text(".github/workflows/ci.yml")
    assert "sqlite+pysqlite" not in workflow
    assert "DATABASE_URL=postgresql+psycopg://app_user@" in workflow
    assert "PLATFORM_DATABASE_URL=postgresql+psycopg://platform_api@" in workflow

    acceptance = _text(".github/candidate/acceptance.sh")
    assert "sqlite+pysqlite" not in acceptance
    assert "postgresql+psycopg://%s:%s@127.0.0.1" in acceptance
    for role in ("app_admin", "app_user", "platform_api"):
        assert f"dsn {role}" in acceptance


def test_image_smokes_prove_the_built_bytes_publish_no_api_documentation() -> None:
    """The route inventory is checked on the ARTIFACT, not only in the suite.

    The smoke passes no `ENVIRONMENT`, which is exactly the point:
    `classify_environment` fails closed, so an image with no declared
    environment resolves the PRODUCTION policy — and the assertion below then
    proves the image it just built serves neither browser documentation page and
    satisfies the production gate. A unit test proves the source is right; this
    proves the thing that gets deployed is (ADR-0016).
    """
    for path in (
        ".github/workflows/ci.yml",
        ".github/candidate/acceptance.sh",
    ):
        source = _text(path)
        assert "import vendor_cp.api_documentation as policy" in source
        assert "policy.classify_environment(None) == policy.PRODUCTION" in source
        assert "'/docs', '/docs/oauth2-redirect', '/redoc'" in source
        assert "policy.audit_api_documentation(" in source


def test_every_test_job_runs_on_a_github_hosted_runner() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert "self-hosted" not in workflow
    # Four since `kernel-pin` joined: check, postgres, image, kernel-pin.
    # A count, and therefore two-directional — a job that stops being
    # hosted fails here as loudly as one that is added.
    assert workflow.count("runs-on: ubuntu-latest") == 4
    assert "DOCKER_BUILDKIT=1 docker build" in workflow
    assert "from vendor_cp.main import app" in workflow
    assert "postgresql+psycopg://app_admin@localhost:5439/vendor_cp_test" in workflow
    test_compose = _text("docker-compose.test.yml")
    assert "POSTGRES_USER: postgres" in test_compose
    assert (
        "./deploy/postgres/init-roles.sh:/docker-entrypoint-initdb.d/" in test_compose
    )


def test_hosted_ci_executes_the_manifest_volume_initializer() -> None:
    workflow = _text(".github/workflows/ci.yml")

    assert "Rehearse production manifest-volume ownership" in workflow
    assert "run --rm --no-deps manifest-init" in workflow
    assert "postgres:16 stat -c '%u:%g %a' /manifests" in workflow
    assert 'test "$observed" = "10001:10001 750"' in workflow


def test_deploy_workflow_requires_the_named_target_and_an_immutable_digest() -> None:
    workflow = _text(".github/workflows/production-deploy.yml")

    assert "runs-on: ubuntu-latest" in workflow
    assert "self-hosted" not in workflow
    assert "environment: production" in workflow
    assert '"$TARGET_SERVER_NAME" != "vendor-cp-prod"' in workflow
    assert "sha256:[0-9a-f]{64}" in workflow
    # A digest an operator pasted is not evidence. The deploy verifies the CI
    # run that produced the revision, then requires the release receipt that
    # binds these exact bytes to it.
    assert "verify_source_revision.py" in workflow
    assert "release-receipt-${SOURCE_SHA}" in workflow
    assert "dotmac-candidate-release-receipt/1" in workflow
    assert "VENDOR_PRODUCTION_KNOWN_HOSTS" in workflow
    assert "VENDOR_PRODUCTION_SSH_KEY" in workflow
    reconcile = workflow.index("Reconcile assembly-owned host declarations")
    deploy = workflow.index("Deploy the approved digest")
    assert reconcile < deploy
    assert "--env-template .env.production.example" in workflow
    assert "--env-file .env" in workflow


def test_deploy_uses_an_ephemeral_registry_credential_over_stdin() -> None:
    workflow = _text(".github/workflows/production-deploy.yml")
    wrapper = _text("scripts/deploy_production_with_registry_token.sh")
    operations = _text("docs/operations/production-deployment.md")

    assert "GHCR_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in workflow
    assert "printf '%s' \"$GHCR_TOKEN\"" in workflow
    assert "deploy_production_with_registry_token.sh" in workflow
    assert 'DOCKER_CONFIG="$(mktemp -d /run/vendor-cp-docker.' in wrapper
    assert "--password-stdin" in wrapper
    assert "trap cleanup EXIT HUP INT TERM" in wrapper
    assert 'rm -rf -- "$DOCKER_CONFIG"' in wrapper
    assert ".docker/config" not in wrapper
    assert "production/ghcr-read" not in operations


def test_deployment_adapter_includes_the_owned_secret_materializer() -> None:
    workflow = _text(".github/workflows/production-deploy.yml")
    service = _text("src/vendor_cp/production_secrets.py")
    operations = _text("docs/operations/production-deployment.md")

    assert "scripts/materialize_production_secrets.py" in workflow
    assert "src/vendor_cp/production_secrets.py" in workflow
    assert "src/vendor_cp/product_release_pins.py" in workflow
    assert "pin-product-release" in _text("scripts/materialize_production_secrets.py")
    assert '"options": {"cas": 0}' in service
    assert service.count("secret/dotmac/vendor-control-plane/production/") == 3
    assert "secret/dotmac/licensing/signing-key" in service
    assert "production/ghcr-read" not in service
    assert "required reviewer" in operations.lower()
    assert "first production dispatch on 2026-08-17 was held at that gate" in operations


def test_nginx_contract_routes_only_to_the_loopback_vendor_app() -> None:
    nginx = _text("deploy/nginx/vendor.dotmac.io.conf")

    assert "server_name vendor.dotmac.io;" in nginx
    assert "proxy_pass http://127.0.0.1:8100;" in nginx
    assert (
        "ssl_certificate /etc/letsencrypt/live/vendor.dotmac.io/fullchain.pem;" in nginx
    )
    assert (
        "ssl_certificate_key /etc/letsencrypt/live/vendor.dotmac.io/privkey.pem;"
        in nginx
    )


def test_host_bootstrap_requires_held_key_and_a_registered_certbot_contact() -> None:
    bootstrap = _text("scripts/bootstrap_production_host.sh")

    assert "CERTBOT_EMAIL" in bootstrap
    assert "certbot show_account --non-interactive" in bootstrap
    assert "--register-unsafely-without-email" not in bootstrap
    assert "vendor-cp-prod" in bootstrap
    assert (
        "/run/secrets/dotmac/vendor-control-plane/licence-signing/primary.key"
        in bootstrap
    )
    assert "secret/dotmac/licensing/signing-key" in bootstrap
    assert "certbot certonly" in bootstrap


def test_the_deploy_refuses_a_fatal_environment_before_it_touches_anything() -> None:
    """The failure must arrive before the migrations, not in the lifespan.

    `compose up -d app` is the SEVENTH action this script takes. The image is
    pulled, the database started, the manifest volume initialised, the role and
    ownership contracts read, a backup taken and THE MIGRATIONS APPLIED before
    the application is ever started — so a configuration error left to the
    application's own `validate_settings` call arrives with the schema already
    advanced and the service down.

    Both checks are asserted, and they are not redundant. The env-file greps are
    a dependency-free floor that needs no image; the artifact's verdict cannot
    drift from the kernel, because it IS the kernel's function.
    """
    deploy = _text("scripts/deploy_production.sh")
    commands = _commands(deploy)

    csrf_present = commands.index("CSRF_SECRET is absent or empty")
    csrf_length = commands.index("CSRF_SECRET is shorter than 32 bytes")
    csrf_distinct = commands.index("CSRF_SECRET must differ from JWT_SECRET")
    verdict = commands.index("the image refuses this host environment")
    start_db = commands.index("up -d --wait db")
    migrate = commands.index("dotmac-platform admin migrate")

    assert csrf_present < csrf_length < csrf_distinct < verdict < start_db < migrate
    # The artifact's own function, not a re-implementation of its rules.
    assert "validate_settings" in deploy
    assert "--network none" in deploy


def test_the_recovery_bundle_is_atomic_and_gates_the_migration() -> None:
    """A dump alone restored with 114 missing-role errors and looked recovered.

    `pg_dump` of one database carries ACLs and policies but never roles,
    memberships or tablespaces — those are CLUSTER objects. So the backup is a
    bundle, it is published with one rename, and the migration does not start
    without it.
    """
    deploy = _text("scripts/deploy_production.sh")
    commands = _commands(deploy)

    # Stripping either of these by flag would reproduce, deliberately, the exact
    # state the rehearsal found by accident.
    assert "--no-owner" not in commands
    assert "--no-privileges" not in commands

    assert "pg_dumpall" in commands
    assert "--globals-only" in commands
    assert "--no-role-passwords" in commands
    # The cluster dump runs as the container-local superuser: `app_admin` is
    # NOSUPERUSER by contract and owns one database.
    assert "--user postgres" in commands

    # Published with a single rename, from a dot-prefixed temporary directory no
    # reader will mistake for a bundle.
    assert 'mktemp -d "${BACKUP_DIR}/.bundle-' in commands
    assert 'mv "$BUNDLE_TMP" "$BUNDLE_PATH"' in commands

    publish = commands.index('mv "$BUNDLE_TMP" "$BUNDLE_PATH"')
    verify = commands.index("sha256sum --quiet --check SHA256SUMS")
    migrate = commands.index("dotmac-platform admin migrate")
    assert publish < verify < migrate, (
        "the bundle must be published and re-verified from its published "
        "location BEFORE the schema advances; a rollback discovered to be "
        "absent afterwards is not a rollback"
    )


def test_the_bundle_refuses_a_globals_capture_that_carries_a_verifier() -> None:
    """`--no-role-passwords` is a flag, and a flag can be dropped.

    Both directions, on the detector the script actually uses rather than on a
    paraphrase of it: a clean capture is admitted and a verifier-bearing one is
    refused. A check only ever seen refusing might refuse everything.
    """
    deploy = _text("scripts/deploy_production.sh")
    pattern = re.compile(r"SCRAM-SHA-256\$|PASSWORD '(md5|SCRAM)")

    assert "SCRAM-SHA-256" in deploy, "the script no longer looks for a verifier"

    clean = "CREATE ROLE app_admin;\nALTER ROLE app_admin WITH LOGIN BYPASSRLS;\n"
    scram = (
        "CREATE ROLE app_admin;\n"
        "ALTER ROLE app_admin WITH LOGIN PASSWORD 'SCRAM-SHA-256$4096:a$b:c';\n"
    )
    md5 = "CREATE ROLE app_admin;\nALTER ROLE app_admin WITH PASSWORD 'md5beef';\n"

    assert not pattern.search(clean)
    assert pattern.search(scram)
    assert pattern.search(md5)


def test_the_five_declared_roles_are_the_ones_the_bundle_checks_for() -> None:
    """The script's role list is not a literal somebody kept in step by hand.

    It is checked against `deploy/product.toml`'s own `[[database.roles]]`, so a
    role added to the cluster contract and forgotten in the capture check fails
    here rather than at a restore nobody runs.
    """
    deploy = _text("scripts/deploy_production.sh")
    declared = {
        str(role["name"])
        for role in tomllib.loads(_text("deploy/product.toml"))["database"]["roles"]
    }
    assert declared, "the descriptor declares no database roles"
    for name in declared:
        assert name in deploy, f"the bundle check does not name role {name}"


def test_the_preflight_never_prints_a_secret_value() -> None:
    """The one check that reads secrets is the one that must not echo them.

    Lengths and equality only: `${#csrf_secret}` and `!=`. A bare `$csrf_secret`
    inside a message would put a production credential into a deploy log.
    """
    deploy = _text("scripts/deploy_production.sh")
    preflight = deploy[
        deploy.index("readonly CSRF_REMEDY") : deploy.index("HOST_ID_FILE is missing")
    ]

    assert "${#csrf_secret}" in preflight
    for message in re.findall(r'die "([^"]*)"', preflight):
        assert "$csrf_secret" not in message, message
    assert "unset csrf_secret" in preflight


def test_the_remediation_names_the_record_the_field_and_the_constraint() -> None:
    """One action for the operator, not a discovery.

    `seed` only CREATES absent records, so naming it alone would send the reader
    to the command that cannot repair an existing one — which is exactly the
    case here.
    """
    deploy = _text("scripts/deploy_production.sh")
    remedy = deploy[deploy.index("readonly CSRF_REMEDY") :].split('"')[1]

    assert "secret/dotmac/vendor-control-plane/production/runtime" in remedy
    assert "csrf_secret" in remedy
    assert "32 bytes" in remedy
    assert "distinct from jwt_secret and session_hash_secret" in remedy
    assert "will not repair one that already exists" in remedy


def test_the_console_login_claim_matches_the_measured_artifact() -> None:
    """Canonical prose may not outlive the phase it describes.

    Three documents and one profile rationale said the assembly declares no
    form-parsing library and `POST /platform/login` cannot read its own form.
    `python-multipart` is a main dependency and the acceptance battery drives
    that login to a console session inside the built artifact, so the claim is
    false wherever it is still stated as present tense.

    Gated on the FACT, not on a banned phrase: while the dependency is declared
    and the battery drives the login, the claim is forbidden; if either ever
    stops holding, this test stops requiring its absence.
    """
    declares_form_parser = "python-multipart" in _text("pyproject.toml")
    battery = _text(".github/candidate/acceptance.sh")
    drives_the_login = (
        "/platform/login" in battery and "form login yields a session" in battery
    )
    assert (
        declares_form_parser and drives_the_login
    ), "the premise changed; revisit the claim rather than this assertion"

    present_tense = (
        "the assembly declares no form-parsing library",
        "cannot read its own form",
    )
    for relative in (
        "src/vendor_cp/deployment_profile.py",
        "docs/ARCHITECTURE.md",
    ):
        text = _text(relative)
        for claim in present_tense:
            assert claim not in text, f"{relative} still states: {claim}"


def test_the_ordering_guard_reads_the_script_and_not_its_explanation() -> None:
    """SENSITIVITY. A helper that stripped nothing would pass every test above.

    `_commands` earns its place only if the unstripped text actually differs —
    and it does: the preflight paragraph explains the order by quoting the very
    command whose position the guard measures.
    """
    deploy = _text("scripts/deploy_production.sh")

    assert _commands(deploy) != deploy
    assert deploy.index("up -d app") < _commands(deploy).index("up -d app"), (
        "no comment mentions the command the ordering guard probes for, so this "
        "helper is currently inert — keep it, but the sensitivity claim is stale"
    )
