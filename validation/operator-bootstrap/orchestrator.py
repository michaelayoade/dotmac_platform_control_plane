"""Effect-injected host-gated stages. No invocation grants execution authority."""
import re
import time


class Stopped(Exception):
    pass


def token_value(raw):
    if not isinstance(raw, bytes) or not re.fullmatch(rb"[0-9a-f]{40}\n?", raw):
        raise Stopped("mint_shape")
    return raw.strip().decode("ascii")


def stable_owner(meta):
    return {k: v for k, v in meta.items() if k != "tokens"}


def identify_token(before, after, username, name, scope, kind, started):
    if stable_owner(before) != stable_owner(after):
        raise Stopped("principal_drift")
    old = before.get("tokens")
    new = after.get("tokens")
    if not isinstance(old, list) or not isinstance(new, list):
        raise Stopped("token_metadata_shape")
    if any(t.get("name") == name for t in old):
        raise Stopped("token_name_not_fresh")
    added = [t for t in new if t not in old]
    if len(new) != len(old) + 1 or len(added) != 1 or any(t not in new for t in old):
        raise Stopped("token_set_drift")
    row = added[0]
    users = before.get("users", [])
    if len(users) != 1:
        raise Stopped("principal_count")
    uid = users[0].get("id")
    if (type(uid) is not int or uid <= 0 or type(row.get("id")) is not int or row["id"] <= 0
            or type(row.get("uid")) is not int or row["uid"] != uid
            or row.get("name") != name or row.get("scope") != scope
            or type(row.get("created_unix")) is not int
            or not started - 120 <= row["created_unix"] <= int(time.time()) + 120):
        raise Stopped("new_token_binding")
    return {"kind": kind, "token_id": row["id"], "user_id": uid, "username": username,
            "token_name": name, "scope": scope, "created_unix": row["created_unix"]}


def finish_revocation(io, log, baseline, binding, value, get_kind):
    # One write intent and one DELETE only. A lost response is not retried here.
    log.write("before_exact_revocation", binding=binding)
    io.revoke(binding)
    after = io.metadata(binding["username"])
    if stable_owner(after) != stable_owner(baseline) or after.get("tokens") != baseline.get("tokens"):
        raise Stopped("revocation_metadata_not_restored")
    log.write("revocation_committed_absence", binding=binding)
    if value is None:
        log.write("revocation_effect_unavailable_lost_mint_response", binding=binding)
        return False
    if io.request(get_kind, value).get("status") != 401:
        raise Stopped("revoked_token_not_401")
    log.write("same_token_401", binding=binding)
    return True


def run_canary(cfg, io, log):
    user = cfg["canary_username"]
    name = cfg["canary_token_name"]
    baseline = None
    binding = None
    value = None
    mint_attempted = False
    revoke_attempted = False
    started = int(time.time())
    passed = False
    failure = "unknown_or_interrupted"
    try:
        io.require_absent(user)
        log.write("before_create_canary", username=user)
        io.create_user(user, restricted=True)
        baseline = io.metadata(user)
        io.require_canary(baseline)
        if baseline.get("tokens") != []:
            raise Stopped("canary_tokens_not_empty")
        uid = baseline["users"][0]["id"]
        log.write("canary_created", user_id=uid)
        log.write("before_mint_canary", token_name=name, scope="read:user")
        if io.metadata(user) != baseline:
            raise Stopped("premint_canary_drift")
        mint_attempted = True
        value = token_value(io.mint(user, name, "read:user"))
        after = io.metadata(user)
        binding = identify_token(baseline, after, user, name, "read:user", "canary", started)
        log.write("canary_token_bound", binding=binding)
        if io.request("canary_get", value).get("status") != 200:
            raise Stopped("canary_baseline_not_200")
        log.write("canary_same_token_200")
        revoke_attempted = True  # Set before the intent write; never retry on I/O failure.
        passed = finish_revocation(io, log, baseline, binding, value, "canary_get")
        failure = "canary_effect_not_proven"
    except Stopped as error:
        failure = str(error)
    except BaseException:
        failure = "unknown_or_interrupted"
    finally:
        # This first cleanup DELETE is part of the future exact live authorization.
        # Reconciliation is read-only; an uncertain prior DELETE is never repeated.
        if mint_attempted and not revoke_attempted and not log.failed:
            try:
                if binding is None:
                    after = io.metadata(user)
                    binding = identify_token(baseline, after, user, name, "read:user", "canary", started)
                revoke_attempted = True
                finish_revocation(io, log, baseline, binding, value, "canary_get")
            except BaseException:
                failure = "cleanup_incomplete_reconcile_exact_recorded_token"
        value = None
    status = "CANARY_PASSED" if passed else "STOPPED_CANARY_RETAINED_STATE"
    log.finish(status, failure=None if passed else failure)
    return passed


def run_bootstrap(cfg, io, log):
    # The entrypoint must validate an externally accepted, hash-pinned canary
    # receipt from these exact source bytes and container images BEFORE this call.
    owner = "dotmac-admin"
    name = cfg["bootstrap_token_name"]
    baseline = None
    binding = None
    value = None
    mint_attempted = False
    revoke_attempted = False
    setup_passed = False
    cleanup_passed = False
    failure = "unknown_or_interrupted"
    started = int(time.time())
    try:
        io.require_absent("cp-bundle-reader", team_absent=True)
        log.write("before_create_cp_reader", username="cp-bundle-reader")
        io.create_user("cp-bundle-reader", restricted=cfg["cp_require_restricted"])
        cp = io.metadata("cp-bundle-reader")
        io.require_cp_ungranted(cp)
        cp_uid = cp["users"][0]["id"]
        log.write("cp_reader_created", user_id=cp_uid)
        baseline = io.metadata(owner)
        io.require_owner(baseline)
        if any(t.get("name") == name for t in baseline.get("tokens", [])):
            raise Stopped("bootstrap_token_name_exists")
        log.write("before_mint_bootstrap", token_name=name, scope="write:organization")
        if io.metadata(owner) != baseline:
            raise Stopped("premint_owner_drift")
        mint_attempted = True
        value = token_value(io.mint(owner, name, "write:organization"))
        after = io.metadata(owner)
        binding = identify_token(baseline, after, owner, name, "write:organization", "bootstrap", started)
        log.write("bootstrap_token_bound", binding=binding)
        if io.request("bootstrap_positive_get", value).get("status") != 200:
            raise Stopped("bootstrap_baseline_not_200")
        log.write("bootstrap_same_token_200")
        log.write("before_create_exact_cp_team")
        created = io.request("create_team", value)
        if created.get("status") != 201 or type(created.get("team_id")) is not int or created["team_id"] <= 0:
            raise Stopped("team_create_not_bound")
        team_id = created["team_id"]
        log.write("cp_team_created", team_id=team_id)
        io.require_cp_join_target(io.metadata("cp-bundle-reader"), team_id, cp_uid)
        log.write("before_add_exact_cp_member", team_id=team_id)
        if io.request("add_member", value, team_id=team_id).get("status") != 204:
            raise Stopped("cp_membership_not_204")
        io.require_cp_ready(io.metadata("cp-bundle-reader"), team_id, cp_uid)
        log.write("cp_metadata_ready")
        setup_passed = True
        failure = "bootstrap_revocation_unproven"
    except Stopped as error:
        failure = str(error)
    except BaseException:
        failure = "unknown_or_interrupted"
    finally:
        if mint_attempted and not revoke_attempted and not log.failed:
            try:
                if binding is None:
                    after = io.metadata(owner)
                    binding = identify_token(baseline, after, owner, name, "write:organization", "bootstrap", started)
                revoke_attempted = True
                cleanup_passed = finish_revocation(io, log, baseline, binding, value,
                                                    "bootstrap_revoked_get")
            except BaseException:
                failure = "bootstrap_cleanup_incomplete_reconcile_exact_recorded_token"
        value = None
    passed = setup_passed and cleanup_passed
    log.finish("BOOTSTRAP_PASSED" if passed else "STOPPED_BOOTSTRAP_RETAINED_STATE",
               failure=None if passed else failure)
    return passed
