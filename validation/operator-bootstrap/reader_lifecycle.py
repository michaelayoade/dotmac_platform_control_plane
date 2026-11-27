"""Bounded operator reader adapter; source preparation conveys no live authority.

All core namespaces and effects are supplied by the separately gated launcher.
No candidate source, credential store, registry client or module loader lives here.
"""
import time

USER = "cp-bundle-reader"
TOKEN_NAME = "cp-artifact-bootstrap-20261127-r2"
SCOPE = "read:package"


class Refused(Exception):
    """Only fixed, nonsecret adapter refusal codes may be raised here."""


def make_reader_backend(cfg, host_gate, runtime, audit, sql, orchestrator,
                        request, acquire):
    """Adapt already verified core namespaces and narrowly injected effects."""
    if cfg.get("cp_require_restricted") is not False:
        raise Refused("reader_configuration")

    class ReaderBackend(host_gate["Backend"]):
        def __init__(self):
            super().__init__(cfg, runtime, audit, {}, sql)
            self.orchestrator = orchestrator
            self.mint_attempted = False

        def create_user(self, *args, **kwargs):
            raise Refused("reader_principal_mutation_forbidden")

        def request(self, kind, value, **kwargs):
            if kind != "reader_get" or kwargs:
                raise Refused("reader_api_mutation_forbidden")
            result = request(kind, value)
            if (type(result) is not dict or set(result) != {"status"}
                    or type(result["status"]) is not int
                    or not 100 <= result["status"] <= 599):
                raise Refused("reader_http_shape")
            return result

        def acquire(self, value):
            # The injected owner verifies all fourteen pinned artifacts and
            # returns a nonsecret attestation; no arbitrary result is journaled.
            return acquire(value)

        def require_reader_ready(self, meta, *, zero_tokens=True):
            if type(meta) is not dict or type(meta.get("tokens")) is not list:
                raise Refused("reader_metadata_shape")
            if zero_tokens and meta["tokens"] != []:
                raise Refused("reader_tokens_not_zero")
            if any(meta.get(key) != [] for key in (
                    "public_keys", "gpg_keys", "owned_repos", "collaborations", "access_rows")):
                raise Refused("reader_direct_grants_or_keys")
            self.require_cp_identity(meta, 10)
            if meta["users"][0].get("is_restricted") is not False:
                raise Refused("reader_restricted_flag")
            self.require_cp_team(meta, 6, member_count=1)
            units = meta["teams"][0]["units"]
            kinds = [u["type"] for u in units]
            if (any(type(kind) is not int or kind <= 0 for kind in kinds)
                    or len(kinds) != len(set(kinds))):
                raise Refused("reader_duplicate_or_invalid_unit")
            orgs = meta.get("org_memberships")
            if (type(orgs) is not list or len(orgs) != 1
                    or type(orgs[0]) is not dict or "is_owner" not in orgs[0]
                    or (orgs[0]["is_owner"] is not None
                        and orgs[0]["is_owner"] is not False)):
                raise Refused("reader_org_owner_flag")
            # JSON null means the optional column is unavailable/unknown; it
            # is never interpreted as False. Non-owner authority is established
            # by exact sole team6/read-role membership and the core no-Owners
            # audit, together with the fixed identity and grant checks above.
            # Core readiness checks intentionally expect zero tokens. Validate
            # the actual token set separately above; normalize only this audit.
            self.require_cp_ready({**meta, "tokens": []}, 6, 10)

        def mint(self, username, name, scope):
            if (username, name, scope) != (USER, TOKEN_NAME, SCOPE):
                raise Refused("reader_mint_scope")
            if self.mint_attempted:
                raise Refused("reader_remint_forbidden")
            self.mint_attempted = True
            self.check_container("forgejo")
            return self.runtime["docker"]([
                "exec", "-u", "git", self.cfg["forgejo_container_id"],
                "forgejo", "admin", "user", "generate-access-token",
                "--username", USER, "--token-name", TOKEN_NAME,
                "--scopes", SCOPE, "--raw"], sensitive=True)

    return ReaderBackend()


def _status(io, value):
    result = io.request("reader_get", value)
    if (type(result) is not dict or set(result) != {"status"}
            or type(result["status"]) is not int):
        raise Refused("reader_http_shape")
    return result["status"]


def run_reader(cfg, io, log):
    """One mint, fixed GET, injected acquisition and one exact-row cleanup.

    A lost mint response may be reconciled by fresh metadata, but cannot prove
    same-token 401. An uncertain DELETE is never repeated. The caller retains
    quarantine unless this function and its journal both report success.
    """
    core = io.orchestrator
    baseline = binding = value = None
    mint_attempted = revoke_attempted = acquired = cleaned = False
    failure = "reader_interrupted_or_io_refusal"
    started = int(time.time())
    try:
        if cfg.get("cp_require_restricted") is not False:
            raise Refused("reader_configuration")
        baseline = io.metadata(USER)
        io.require_reader_ready(baseline)
        log.write("reader_preaudit_ready")
        if _status(io, None) not in (401, 403, 404):
            raise Refused("reader_anonymous_control")
        if _status(io, "0" * 40) not in (401, 403, 404):
            raise Refused("reader_bad_credential_control")
        log.write("reader_negative_controls_passed")
        if io.metadata(USER) != baseline:
            raise Refused("reader_premint_drift")
        log.write("before_mint_reader", token_name=TOKEN_NAME, scope=SCOPE)
        mint_attempted = True
        value = core["token_value"](io.mint(USER, TOKEN_NAME, SCOPE))
        after = io.metadata(USER)
        binding = core["identify_token"](baseline, after, USER, TOKEN_NAME,
                                         SCOPE, "reader", started)
        # The SQL namespace independently refuses reserved IDs and all loose
        # bindings before any credentialed positive request or acquisition.
        io.sql["build_revocation_sql"](binding)
        io.require_reader_ready(after, zero_tokens=False)
        log.write("reader_token_bound", binding=binding)
        if _status(io, value) != 200:
            raise Refused("reader_positive_not_200")
        log.write("reader_same_token_200")
        attestation = io.acquire(value)
        if (type(attestation) is not dict
                or type(attestation.get("artifact_count")) is not int
                or attestation["artifact_count"] != 14
                or type(attestation.get("artifacts")) is not dict
                or len(attestation["artifacts"]) != 14
                or any(type(name) is not str or not name
                       or type(digest) is not str or len(digest) != 64
                       or any(c not in "0123456789abcdef" for c in digest)
                       for name, digest in attestation["artifacts"].items())):
            raise Refused("reader_acquisition_attestation")
        acquired = True
        log.write("reader_acquisition_completed")
    except Refused:
        failure = "reader_invariant_refused"
    except BaseException:
        failure = "reader_interrupted_or_io_refusal"
    finally:
        if mint_attempted and not revoke_attempted:
            try:
                if binding is None:
                    after = io.metadata(USER)
                    binding = core["identify_token"](baseline, after, USER,
                        TOKEN_NAME, SCOPE, "reader", started)
                io.sql["build_revocation_sql"](binding)
                revoke_attempted = True
                cleaned = core["finish_revocation"](
                    io, log, baseline, binding, value, "reader_get")
                if cleaned:
                    fresh = io.metadata(USER)
                    io.require_reader_ready(fresh)
                    if fresh != baseline:
                        raise Refused("reader_final_metadata_drift")
                    log.write("reader_fresh_ready_audit")
            except BaseException:
                cleaned = False
                failure = "reader_cleanup_incomplete_reconcile_exact_recorded_token"
        value = None
    passed = acquired and cleaned and not log.failed
    log.finish("READER_BOOTSTRAP_PASSED" if passed else "STOPPED_READER_RETAINED_STATE",
               failure=None if passed else failure)
    return passed
