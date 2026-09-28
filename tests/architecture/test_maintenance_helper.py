"""The nginx maintenance helper's exit codes describe the state it leaves.

`deploy/host/dotmac-vendor-maintenance` is a root-owned, checked-in-only
script (D16 PR 3): nothing in this repository or its CI installs it. These
are STATIC TEXT AND PARSE checks only, over the helper script, the
maintenance nginx config, the sudoers fragment and the bootstrap script's
managed-mode branch — there is no stubbed `nginx`, `systemctl` or `curl`
harness here, so a passing test proves the SCRIPT SAYS the right thing
(the control-flow shape is present in the text), not that a live host
behaves that way. Behavioural coverage of the actual switch/validate/
reload/drain/proof/revert state machine remains a follow-up; see
`docs/operations/maintenance-helper.md`'s "Known limitation" section.

Every guard below carries a sensitivity note (inline, near the assertions
it protects) naming the planted defect it would catch, mirroring the
convention in `test_production_deployment.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HELPER = "deploy/host/dotmac-vendor-maintenance"
BOOTSTRAP = "scripts/bootstrap_production_host.sh"
LIVE_CONF = "deploy/nginx/vendor.dotmac.io.conf"
MAINTENANCE_CONF = "deploy/nginx/vendor.dotmac.io.maintenance.conf"
SUDOERS = "deploy/host/sudoers.d/dotmac-vendor-maintenance"

MARKER_HEADER = "X-Dotmac-Maintenance"

# Every function the helper defines, in file order. Used to compute each
# function's body span so guards can tell "this token is inside function X"
# from "this token is at top level" without relying on raw text order
# (which, for a script whose functions are all defined before they are
# dispatched, would otherwise put a function's body ahead of the dispatch
# code that actually calls it at runtime).
HELPER_FUNCTIONS = (
    "log",
    "fail",
    "handle_exit",
    "usage",
    "require_root_owned_and_not_group_or_other_writable",
    "require_managed_dir_mode",
    "nginx_master_is_live",
    "require_nginx_master",
    "require_same_filesystem",
    "capture_and_validate_prior_state",
    "status_for_conf",
    "marker_for_conf",
    "switch_enabled_site",
    "validate_config",
    "worker_title_is_shutting_down",
    "no_worker_is_shutting_down",
    "wait_for_no_shutting_down_workers",
    "reload_and_prove_drain",
    "probe_public",
    "prove_public",
    "prove_public_with_settle",
    "app_health_is_ready",
    "do_revert",
    "attempt_switch_and_prove_or_revert",
)


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _code_only(script: str) -> str:
    """The script with comment-only lines blanked.

    Several guards below count literal tokens (`$1`, `eval`, `ln -sfn`).
    The header comment and inline notes legitimately describe those tokens
    in prose (e.g. "never `ln -sfn`", "the ONLY place this script reads its
    own $1"), so counting raw text would make the guard fire on
    documentation, not on code. Blanking comment lines is the same
    correction `test_production_deployment.py::_commands` makes for
    ordering assertions.
    """
    return "\n".join(
        "" if line.lstrip().startswith("#") else line for line in script.splitlines()
    )


def _function_body(script: str, name: str) -> str:
    match = re.search(
        r"^" + re.escape(name) + r"\(\) \{\n(.*?)\n\}\n",
        script,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"could not find function {name!r} in {HELPER}"
    return match.group(1)


def _function_spans(script: str, names: tuple[str, ...]) -> list[tuple[int, int]]:
    """(start, end) character offsets of each named function's BODY.

    Offsets are into `script` (not `_code_only(script)`), spanning just the
    body text between the opening `name() {` line and the closing `}` line
    — i.e. excluding the signature and brace themselves.
    """
    spans = []
    for name in names:
        match = re.search(
            r"^" + re.escape(name) + r"\(\) \{\n(.*?)\n\}\n",
            script,
            re.MULTILINE | re.DOTALL,
        )
        assert match, f"could not find function {name!r} in {HELPER}"
        spans.append(match.span(1))
    return spans


def _outside_all_spans(pos: int, spans: list[tuple[int, int]]) -> bool:
    return not any(start <= pos < end for start, end in spans)


# ---------------------------------------------------------------------------
# 1. Exactly two verbs; extra arguments are rejected.
# ---------------------------------------------------------------------------


def test_the_helper_declares_exactly_two_verbs_and_rejects_extra_arguments() -> None:
    script = _text(HELPER)

    assert (
        '"$#" -ne 1' in script
    ), "must reject any call that isn't exactly one argument"

    # The verb-VALIDATION case (top of the file, right after VERB="$1") is
    # the first `case "$VERB" in ... esac` in the file; the verb-DISPATCH
    # case (the real logic) is the second. This test targets the first.
    case_match = re.search(r'case "\$VERB" in\n(.*?)\nesac', script, re.DOTALL)
    assert case_match, "expected a case statement validating $VERB"
    case_block = case_match.group(0)
    verb_arms = re.findall(r"^\s{4}([a-z*][a-z*-]*)\)", case_block, re.MULTILINE)
    assert set(verb_arms) == {"maintenance-on", "routing-restore", "*"}, verb_arms
    assert "*) usage ;;" in case_block

    # Sensitivity: a version accepting any number of arguments (e.g. testing
    # "$#" -lt 1 instead of -ne 1) would let `maintenance-on extra-garbage`
    # through silently — this assertion specifically requires -ne 1, so a
    # near-miss switch to -lt/-gt is caught. A version that drops the `*)`
    # catch-all arm entirely is caught by the exact-set assertion above.
    assert '"$#" -lt 1' not in script


# ---------------------------------------------------------------------------
# 2. Atomic switch: mv -T, never ln -sfn, in the helper.
# ---------------------------------------------------------------------------


def test_the_switch_uses_mv_dash_t_and_never_ln_sfn() -> None:
    script = _text(HELPER)
    code = _code_only(script)  # the header/inline comments name `ln -sfn` as
    # the anti-pattern being avoided — that mention must not itself trip
    # this guard, so it is checked against CODE only.

    assert "mv -T" in code
    # A defect that reused `ln -sfn` for the "revert" path specifically
    # would slip past a check that only looked at the first occurrence, so
    # this scans the whole (code-only) file.
    assert code.count("ln -sfn") == 0

    # Sensitivity: replacing `mv -T "$tmp_link" "$ENABLED_LINK"` with a bare
    # `mv "$tmp_link" "$ENABLED_LINK"` (destination-is-a-directory hazard)
    # drops the first assertion to false. Reintroducing `ln -sfn` anywhere
    # (the non-atomic near-miss this whole test exists to catch) flips the
    # second assertion.


# ---------------------------------------------------------------------------
# 3. nginx -t precedes every reload.
# ---------------------------------------------------------------------------


def test_nginx_dash_t_precedes_every_reload() -> None:
    script = _text(HELPER)

    # `readonly RELOAD_CMD=...` assigns the NAME with no `$`; the only place
    # the script ever expands `$RELOAD_CMD` (actually invokes the reload) is
    # inside reload_and_prove_drain, guarded by `if ! $RELOAD_CMD; then`.
    assert script.count("$RELOAD_CMD") == 1
    reload_body = _function_body(script, "reload_and_prove_drain")
    assert "if ! $RELOAD_CMD; then" in reload_body

    # reload_and_prove_drain is called from two places: attempt_switch_and_
    # prove_or_revert (the forward switch) and do_revert (a revert). In
    # BOTH, `validate_config` (nginx -t) must run, and its failure branch
    # must complete (via `fail`, which exits), strictly before the call to
    # reload_and_prove_drain.
    for fn_name in ("attempt_switch_and_prove_or_revert", "do_revert"):
        body = _function_body(script, fn_name)
        if_idx = body.index("if ! validate_config")
        fi_idx = body.index("\n    fi\n", if_idx)
        reload_idx = body.index("reload_and_prove_drain")
        assert if_idx < fi_idx < reload_idx, (
            f"{fn_name}: nginx -t must run, and its failure branch must "
            "complete, before the reload is ever reached"
        )

    # Sensitivity: moving the `reload_and_prove_drain` call ahead of the
    # `if ! validate_config` check (or inside its failure branch) in either
    # function fails that function's ordering assertion — exactly the
    # reload-before-validate defect this test exists to catch. A near-miss
    # that renames one of the two functions is caught by `_function_body`
    # raising instead of silently skipping the check.


# ---------------------------------------------------------------------------
# 4. No FAIL_CODE=65 in any code path reachable after MUTATED=1.
# ---------------------------------------------------------------------------


def test_no_fail_code_65_is_reachable_after_the_first_mutation() -> None:
    """FAIL_CODE=65 never appears on any path that runs after MUTATED=1.

    Method: this cannot be a plain "text position after MUTATED=1" check,
    because `switch_enabled_site` (the only place MUTATED is ever set to 1)
    is a function DEFINED near the top of the file but CALLED only later,
    from the verb-dispatch case at the bottom (`do_revert` and
    `attempt_switch_and_prove_or_revert`, both invoked only from the second
    `case "$VERB" in ... esac` block). So instead this traces the verb-
    dispatch structure directly:

    1. Every function body is checked in isolation (via `_function_body`);
       a FAIL_CODE=65 assignment is only allowed inside the four PRECONDITION
       functions (`require_root_owned_and_not_group_or_other_writable`,
       `require_managed_dir_mode`, `require_same_filesystem`,
       `capture_and_validate_prior_state`), all of which run unconditionally
       at top level BEFORE the verb-dispatch case even starts, and none of
       which calls `switch_enabled_site`.
    2. The verb-dispatch case's `routing-restore` arm has one more
       FAIL_CODE=65 (the app-health precondition) that is NOT inside a
       function — it is inline in the arm. That is allowed only because it
       is lexically positioned before the arm's call into
       `attempt_switch_and_prove_or_revert` (the only mutation point in that
       arm), which this test checks explicitly.
    3. No other function, and no other position in the dispatch case
       (including the `maintenance-on` arm, which has no such precondition
       and so must contain zero FAIL_CODE=65 occurrences), may set
       FAIL_CODE=65.
    """
    script = _text(HELPER)

    allowed_functions = {
        "require_root_owned_and_not_group_or_other_writable",
        "require_managed_dir_mode",
        "require_nginx_master",
        "require_same_filesystem",
        "capture_and_validate_prior_state",
    }
    for fn_name in HELPER_FUNCTIONS:
        body = _function_body(script, fn_name)
        count = body.count("FAIL_CODE=65")
        if fn_name in allowed_functions:
            assert count > 0, f"expected {fn_name} to still set FAIL_CODE=65"
            assert (
                "switch_enabled_site" not in body
            ), f"{fn_name} is a precondition function and must never mutate"
        else:
            assert count == 0, (
                f"{fn_name} must never set FAIL_CODE=65 "
                "(only the two precondition functions may)"
            )

    # The verb-dispatch case: split into the maintenance-on and
    # routing-restore arms exactly as in test 5 below.
    maintenance_on_start = script.rindex("maintenance-on)")
    routing_restore_start = script.rindex("routing-restore)")
    assert maintenance_on_start < routing_restore_start
    maintenance_on_arm = script[maintenance_on_start:routing_restore_start]
    routing_restore_arm = script[routing_restore_start:]

    assert maintenance_on_arm.count("FAIL_CODE=65") == 0, (
        "maintenance-on has no pre-mutation precondition of its own; any "
        "FAIL_CODE=65 here would not be provably pre-mutation"
    )

    restore_65_positions = [
        m.start() for m in re.finditer("FAIL_CODE=65", routing_restore_arm)
    ]
    assert len(restore_65_positions) == 1, restore_65_positions
    mutation_call_idx = routing_restore_arm.index("attempt_switch_and_prove_or_revert")
    assert restore_65_positions[0] < mutation_call_idx, (
        "routing-restore's FAIL_CODE=65 (the app-health precondition) must "
        "sit before the call that can mutate the enabled-site symlink"
    )

    # Sensitivity: planting `FAIL_CODE=65` inside `attempt_switch_and_prove_
    # or_revert` (a function reachable only after switch_enabled_site) is
    # caught by the per-function loop above, since that function is not in
    # `allowed_functions`. Planting it in the routing-restore arm AFTER the
    # `attempt_switch_and_prove_or_revert` call is caught by the ordering
    # assertion on `restore_65_positions[0]`. Moving the existing, legitimate
    # app-health FAIL_CODE=65 into the maintenance-on arm is caught by the
    # maintenance-on arm's zero-count assertion.


# ---------------------------------------------------------------------------
# 5. An EXIT trap is installed and maps codes by MUTATED.
# ---------------------------------------------------------------------------


def test_an_exit_trap_is_installed_and_maps_undocumented_codes_by_mutated() -> None:
    script = _text(HELPER)

    assert "trap handle_exit EXIT" in script
    handle_exit_body = _function_body(script, "handle_exit")
    assert 'case "$rc" in' in handle_exit_body
    assert "0 | 64 | 65 | 66 | 67 | 75) ;;" in handle_exit_body
    assert '"$MUTATED" -eq 1' in handle_exit_body
    assert "rc=67" in handle_exit_body
    assert "rc=65" in handle_exit_body

    # The remap DIRECTION matters, not just that both codes appear somewhere
    # in the function: MUTATED=1 must map to 67, MUTATED=0 must map to 65 —
    # reversed, an unmutated failure would be misreported as "state unknown"
    # (needlessly paging a human) and a post-mutation failure would be
    # misreported as "nothing happened" (actively dangerous: an operator or
    # PR 4 could retry or proceed believing the host is untouched). Split the
    # body on its `if`/`else`/`fi` and check each branch independently.
    then_start = handle_exit_body.index('if [ "$MUTATED" -eq 1 ]; then') + len(
        'if [ "$MUTATED" -eq 1 ]; then'
    )
    else_idx = handle_exit_body.index("else", then_start)
    fi_idx = handle_exit_body.index("fi", else_idx)
    then_branch = handle_exit_body[then_start:else_idx]
    else_branch = handle_exit_body[else_idx + len("else") : fi_idx]
    assert "rc=67" in then_branch and "rc=65" not in then_branch, then_branch
    assert "rc=65" in else_branch and "rc=67" not in else_branch, else_branch

    # The trap must be installed (`trap handle_exit EXIT`) AFTER `MUTATED=0`
    # is declared, so the trap's very first possible firing already has a
    # defined $MUTATED to branch on.
    assert script.index("MUTATED=0") < script.index("trap handle_exit EXIT")

    # Sensitivity: removing the `trap handle_exit EXIT` line entirely would
    # let an unset-variable or unexpected `set -e` failure surface a raw,
    # undocumented exit code straight to the caller — the first assertion
    # catches that. Changing the case arm to omit one of the six documented
    # codes (e.g. dropping `75`) would make a legitimate lock-contention exit
    # get needlessly remapped — caught by the exact-list assertion. Swapping
    # the two remap directions (`rc=65` under `MUTATED -eq 1`, `rc=67` under
    # the `else`) is caught directly by the then/else branch split above —
    # this is the fix for a previously FALSE sensitivity claim in this same
    # test, which asserted this defect was "caught" by the no-FAIL_CODE=65-
    # after-mutation test elsewhere; that test does not exercise handle_exit
    # at all, so it could not have caught a reversed remap.


# ---------------------------------------------------------------------------
# 6. The reload command never runs bare, only inside a checked construct.
# ---------------------------------------------------------------------------


def test_the_reload_command_never_runs_bare() -> None:
    script = _text(HELPER)
    code = _code_only(script)

    assert code.count("$RELOAD_CMD") == 1
    assert "if ! $RELOAD_CMD; then" in code

    # Sensitivity: a rewrite that ran `$RELOAD_CMD` as a bare statement
    # (relying on `set -e` to abort the script on failure, rather than
    # returning 1 for the caller to revert) would still make `if ! $RELOAD_
    # CMD; then` disappear from the code — this assertion catches that
    # directly, distinct from test 3's ordering check.


# ---------------------------------------------------------------------------
# 7. No `validate_config || true`.
# ---------------------------------------------------------------------------


def test_validate_config_is_never_allowed_to_silently_succeed() -> None:
    script = _text(HELPER)
    code = _code_only(script)

    assert "validate_config || true" not in code
    # Every call to validate_config must be inside an `if` (or `if !`)
    # construct, i.e. its exit status is checked, never discarded.
    calls = [m.start() for m in re.finditer(r"\bvalidate_config\b", code)]
    # One is the function's own definition line (`validate_config() {`);
    # every other occurrence is a call site.
    call_sites = [
        pos
        for pos in calls
        if not code[pos : pos + len("validate_config() {")].startswith(
            "validate_config() {"
        )
    ]
    assert call_sites, "expected at least one call site"
    for pos in call_sites:
        preceding_line_start = code.rfind("\n", 0, pos) + 1
        line = code[preceding_line_start : code.index("\n", pos)]
        assert "if ! validate_config" in line, line

    # Sensitivity: `validate_config || true` (or any bare `validate_config`
    # not wrapped in `if !`) would make an `nginx -t` REJECTION invisible —
    # the switch would proceed to reload a config nginx itself refused. Both
    # the substring check and the per-call-site `if !` check independently
    # catch that; the substring check specifically catches the exact
    # `|| true` near-miss named in the packet.


# ---------------------------------------------------------------------------
# 8. No `%header{`.
# ---------------------------------------------------------------------------


def test_no_curl_header_expression_syntax() -> None:
    script = _text(HELPER)
    assert "%header{" not in script

    # Sensitivity: `%header{X-Dotmac-Maintenance}` relies on a curl version
    # newer than what every target host is guaranteed to have. Reintroducing
    # it anywhere (even inside a comment describing an alternative) would
    # trip this guard — deliberately conservative, since the point is that
    # this syntax must not even be suggested as an option in this file.


# ---------------------------------------------------------------------------
# 9. Every curl invocation carries -q, --connect-timeout and --max-time.
# ---------------------------------------------------------------------------


def test_every_curl_invocation_carries_q_and_both_timeouts() -> None:
    script = _text(HELPER)

    call_lines = [line for line in script.splitlines() if '"$CURL_BIN"' in line]
    assert len(call_lines) == 2, call_lines  # probe_public, app_health_is_ready
    for line in call_lines:
        stripped = line.strip()
        assert stripped.startswith('status="$("$CURL_BIN" -q '), stripped
        assert "--connect-timeout 5" in line
        assert "--max-time 10" in line

    # Sensitivity: `-q` must be curl's FIRST flag (so a stray ~/.curlrc on
    # the host cannot inject extra behaviour); the `startswith` check on the
    # exact prefix `"$CURL_BIN" -q ` catches a rewrite that moved `-q` later
    # in the argument list. Dropping either timeout flag from just one of
    # the two call sites is caught because both lines are checked
    # independently, not just the first match.


# ---------------------------------------------------------------------------
# 10. `#!/bin/bash` and `trap '' HUP INT TERM PIPE` are present.
# ---------------------------------------------------------------------------


def test_shebang_and_signal_trap_are_present() -> None:
    script = _text(HELPER)
    lines = script.splitlines()
    assert lines[0] == "#!/bin/bash"
    assert "trap '' HUP INT TERM PIPE" in script

    # Sensitivity: `#!/usr/bin/env bash` (PATH-dependent) instead of the
    # pinned `#!/bin/bash` would still satisfy a bare `"bash" in lines[0]`
    # check but fails this exact-match one. Trapping only `HUP` (the
    # previous, narrower version) would leave the helper interruptible by
    # Ctrl-C (INT) or a deploy orchestrator's cancellation signal (TERM)
    # mid-mutation — this exact-string check on all three signals together
    # catches a regression back to the narrower trap.


# ---------------------------------------------------------------------------
# 11. The lock is not under /run/lock, and contention exits 75.
# ---------------------------------------------------------------------------


def test_the_lock_is_root_owned_and_contention_exits_75() -> None:
    """The lock target is root-owned and not under the world-writable /run/lock.

    NOTE — this test's scope is deliberately narrower than "the lock cannot
    be taken by anyone": ownership alone does not stop a local user who can
    still merely OPEN the directory (root ownership does not require a
    restrictive mode) from contending for the flock. That gap is what
    `test_the_managed_directory_mode_is_restrictive` below closes — the two
    tests are complementary, not redundant.
    """
    script = _text(HELPER)

    assert "/run/lock" not in script
    assert 'exec 9<"$MANAGED_DIR"' in script
    assert "flock -n 9" in script
    assert "FAIL_CODE=75" in script
    assert "another dotmac-vendor-maintenance" in script

    # Sensitivity: switching the lock target to `/run/lock/dotmac-vendor-
    # maintenance` (world-writable by default on most distros, letting any
    # local user create contention or, worse, a symlink race) would keep
    # `flock -n 9` intact but fail the `/run/lock` absence check and the
    # `exec 9<"$MANAGED_DIR"` exact-match check.


# ---------------------------------------------------------------------------
# 11b. The managed directory's mode is 0700 or 0750, not merely root-owned.
# ---------------------------------------------------------------------------


def test_the_managed_directory_mode_is_restrictive() -> None:
    script = _text(HELPER)

    mode_body = _function_body(script, "require_managed_dir_mode")
    assert "700 | 750) ;;" in mode_body

    # The check must actually be CALLED, against MANAGED_DIR, before the
    # verb-dispatch case begins (i.e. unconditionally, for both verbs).
    call_idx = script.index('require_managed_dir_mode "$MANAGED_DIR"')
    dispatch_start = script.rindex('case "$VERB" in')
    assert call_idx < dispatch_start

    # Sensitivity: a version that only checked group/other-WRITE bits (the
    # pre-existing `require_root_owned_and_not_group_or_other_writable`,
    # which accepts e.g. 0755) would let any local user OPEN the directory
    # and contend for the lock even though they could never WRITE into it —
    # the exact `700 | 750` case-arm match catches a rewrite that widened
    # this to also accept, say, `755`. Removing the call entirely (or moving
    # it inside a dispatch arm, so only one verb gets checked) is caught by
    # the call-site-before-dispatch ordering assertion.


# ---------------------------------------------------------------------------
# 12. The temporary link path is inside the managed directory.
# ---------------------------------------------------------------------------


def test_the_temporary_link_is_created_inside_the_managed_directory() -> None:
    script = _text(HELPER)
    switch_body = _function_body(script, "switch_enabled_site")

    assert 'tmp_link="${MANAGED_DIR}/$(basename "$ENABLED_LINK").tmp.$$"' in switch_body
    assert 'ln -s "$target" "$tmp_link"' in switch_body
    assert 'mv -T "$tmp_link" "$ENABLED_LINK"' in switch_body

    # Sensitivity: creating the temporary link under `$(dirname "$ENABLED_
    # LINK")` (i.e. directly in sites-enabled/) instead of `$MANAGED_DIR`
    # would still work functionally, but would leave a stray, live-looking
    # file in sites-enabled/ if the run crashed between `ln -s` and `mv -T`
    # (nginx does not include unresolvable dangling names, but a partially
    # written one is a live risk). The exact-string check on `$MANAGED_DIR`
    # catches that relocation.


# ---------------------------------------------------------------------------
# 13. The marker header name matches between the conf and the helper, and
#     the proof requires the marker (not just the status code).
# ---------------------------------------------------------------------------


def test_marker_header_name_matches_and_the_proof_requires_it() -> None:
    script = _text(HELPER)
    maintenance = _text(MAINTENANCE_CONF)

    assert f'MARKER_HEADER="{MARKER_HEADER}"' in script
    assert f"add_header {MARKER_HEADER} vendor-cp always;" in maintenance
    assert 'MARKER_VALUE="vendor-cp"' in script

    prove_body = _function_body(script, "prove_public")
    assert "PROVE_WANT_MARKER" in prove_body
    assert "PROVE_WANT_STATUS" in prove_body
    assert prove_body.count("return 1") >= 3

    maintenance_on_start = script.rindex("maintenance-on)")
    routing_restore_start = script.rindex("routing-restore)")
    assert maintenance_on_start < routing_restore_start
    maintenance_on_block = script[maintenance_on_start:routing_restore_start]
    assert "PROVE_WANT_STATUS=503" in maintenance_on_block
    assert 'PROVE_WANT_MARKER="present"' in maintenance_on_block

    # Sensitivity: a maintenance conf with a differently-cased or differently
    # named header would still add SOME header, so a test only checking
    # `"add_header" in maintenance` would pass while the helper's proof
    # silently never sees its expected header — the exact-constant match
    # catches that. Separately, the packet is explicit that a bare 503 is
    # not proof, because the app's own /health/ready also returns 503 when
    # the database is fenced; dropping `PROVE_WANT_MARKER="present"` from
    # the maintenance-on block would pass a false "maintenance is on"
    # verdict during an unrelated database outage — this assertion on that
    # block specifically requires both status AND marker.


# ---------------------------------------------------------------------------
# 14. The sudoers fragment has exactly two commands and no wildcards.
# ---------------------------------------------------------------------------


def test_sudoers_fragment_lists_exactly_two_commands_with_no_wildcards() -> None:
    sudoers = _text(SUDOERS)

    cmnd_alias_match = re.search(
        r"^Cmnd_Alias VENDOR_MAINT = (.+)$", sudoers, re.MULTILINE
    )
    assert cmnd_alias_match, "expected a Cmnd_Alias line naming VENDOR_MAINT"
    commands = [c.strip() for c in cmnd_alias_match.group(1).split(",")]
    assert commands == [
        "/usr/local/sbin/dotmac-vendor-maintenance maintenance-on",
        "/usr/local/sbin/dotmac-vendor-maintenance routing-restore",
    ]

    assert "*" not in sudoers
    assert "ALL=(root) NOPASSWD: VENDOR_MAINT" in sudoers
    assert "<DEPLOY_USER>" in sudoers  # placeholder, substituted at install time

    # Sensitivity: a fragment listing the bare binary with no verb, or with
    # a trailing wildcard, would let the deploy user run ANY verb — including
    # a future one — as root with no password. The exact-match-list
    # assertion and the `"*" not in sudoers` check both independently catch
    # that.


# ---------------------------------------------------------------------------
# 15. The maintenance conf equals the live conf except for the 443
#     `location /` block.
# ---------------------------------------------------------------------------


def _split_around_second_location_root(text: str) -> tuple[str, str]:
    """Split `text` into (prefix, suffix) around the SECOND `location / {`.

    Both configs share an identical port-80 server block, whose own
    `location / { return 301 ...; }` is the first `location / {` in the
    file. The second is the 443 block's, which is the ONLY block the
    maintenance config is allowed to change.
    """
    marker = "\n    location / {\n"
    first = text.index(marker)
    second = text.index(marker, first + 1)
    body_start = second + len(marker)
    close = text.index("\n    }\n", body_start)
    body_end = close + len("\n    }\n")
    return text[:second], text[body_end:]


def test_maintenance_conf_equals_live_conf_except_for_the_443_location_block() -> None:
    live = _text(LIVE_CONF)
    maintenance = _text(MAINTENANCE_CONF)

    live_prefix, live_suffix = _split_around_second_location_root(live)
    maintenance_prefix, maintenance_suffix = _split_around_second_location_root(
        maintenance
    )

    assert live_prefix == maintenance_prefix, (
        "port-80 block, and the 443 block's server_name/TLS/includes/"
        "client_max_body_size, must be byte-identical"
    )
    assert live_suffix == maintenance_suffix

    assert "proxy_pass" not in maintenance
    assert "return 503;" in maintenance
    assert f"add_header {MARKER_HEADER} vendor-cp always;" in maintenance
    assert "add_header Retry-After 120 always;" in maintenance

    # Sensitivity: this test was written by first confirming it FAILS if a
    # single TLS line is perturbed — e.g. changing
    # `ssl_certificate_key /etc/letsencrypt/live/vendor.dotmac.io/privkey.pem;`
    # to a different path in only the maintenance file breaks live_prefix ==
    # maintenance_prefix. A near-miss that only changes the `location /`
    # body (the intended difference) must NOT fail this test — that is
    # exactly what the `location /` exclusion is for.


# ---------------------------------------------------------------------------
# 16. Bootstrap: inside the managed branch, no `ln -sfn` on the enabled
#     link, and it takes the same lock directory as the helper.
# ---------------------------------------------------------------------------


def test_bootstrap_managed_branch_never_relinks_and_shares_the_helpers_lock_dir() -> (
    None
):
    helper = _text(HELPER)
    bootstrap = _text(BOOTSTRAP)

    helper_managed_dir_match = re.search(r'readonly MANAGED_DIR="([^"]+)"', helper)
    bootstrap_managed_dir_match = re.search(
        r'readonly MANAGED_NGINX_DIR="([^"]+)"', bootstrap
    )
    assert helper_managed_dir_match and bootstrap_managed_dir_match
    assert helper_managed_dir_match.group(1) == bootstrap_managed_dir_match.group(1), (
        "the helper's lock directory and bootstrap's managed nginx "
        "directory must be the literal same path"
    )

    assert 'exec 8<"$MANAGED_NGINX_DIR"' in bootstrap
    assert "flock -w 60 8" in bootstrap, (
        "the lock wait must be BOUNDED, so a stuck concurrent run fails "
        "this bootstrap loudly rather than hanging it indefinitely"
    )

    # Isolate the PRE-certificate managed branch: `if is_nginx_site_managed;
    # then ... else`. Since D16 PR 3's second fix round, this branch does
    # NOTHING but set a flag — no lock, no conf install — because the lock
    # and the conf installs both moved to AFTER certificate issuance (see
    # the next test).
    branch_match = re.search(
        r"if is_nginx_site_managed; then\n(.*?)\n    else\n",
        bootstrap,
        re.DOTALL,
    )
    assert branch_match, "expected an is_nginx_site_managed branch"
    pre_cert_branch = branch_match.group(1)
    assert "ln -sfn" not in pre_cert_branch
    assert "install_managed_conf_atomically" not in pre_cert_branch
    assert "flock" not in pre_cert_branch
    assert "exec 8" not in pre_cert_branch

    # The lock-and-install block (AFTER certificate issuance) must contain
    # both installs.
    post_cert_match = re.search(
        r'if \[\[ "\$site_is_managed" -eq 1 \]\]; then\n(.*?)\n    else\n',
        bootstrap,
        re.DOTALL,
    )
    assert post_cert_match, "expected a site_is_managed post-certificate branch"
    post_cert_branch = post_cert_match.group(1)
    assert "install_managed_conf_atomically" in post_cert_branch
    assert post_cert_branch.count("install_managed_conf_atomically") == 2
    assert "ln -sfn" not in post_cert_branch

    # The bare `ln -sfn` in the whole file must be exactly the one
    # pre-conversion (unmanaged) call, not a second one hiding anywhere in
    # managed mode.
    code = _code_only(bootstrap)
    assert code.count("ln -sfn") == 1
    assert 'ln -sfn "$NGINX_AVAILABLE" "$NGINX_ENABLED"' in code

    # Sensitivity: a bootstrap re-run that called `ln -sfn` inside either
    # managed-mode branch (e.g. "just to be safe") would fight the helper
    # for ownership of the enabled-site symlink and could switch a host that
    # a deploy had deliberately left in maintenance back to live — the two
    # branch-scoped substring checks and the whole-file count all
    # independently catch that. A lock-directory typo (a literal path
    # differing from the helper's) would let bootstrap and the helper
    # mutate concurrently without contention — caught by the
    # literal-equality assertion. Restoring the old unbounded `flock 8`
    # (rather than `flock -w 60 8`) is caught by the exact-string bound
    # check.


# ---------------------------------------------------------------------------
# 16b. Bootstrap never holds the lock across certificate issuance.
# ---------------------------------------------------------------------------


def test_bootstrap_never_holds_the_lock_across_certificate_issuance() -> None:
    bootstrap = _text(BOOTSTRAP)

    # The bare top-level CALL (inside main(), not the function definition
    # `issue_production_certificate() {`) is the only place the certificate
    # is actually issued.
    call_idx = bootstrap.index("\n    issue_production_certificate\n")
    lock_idx = bootstrap.index("flock -w 60 8")
    assert call_idx < lock_idx, (
        "the lock must be acquired AFTER certificate issuance, never held "
        "across it — ACME network I/O can block far longer than any "
        "concurrent maintenance-helper run should ever have to wait"
    )

    # Sensitivity: moving `issue_production_certificate` back inside (or
    # after) the lock-held block — the exact defect this fix round
    # corrects — flips this ordering assertion. A near-miss that keeps the
    # call before the lock but renames one of the two anchor strings is
    # caught by `.index()` raising `ValueError` instead of silently passing.


# ---------------------------------------------------------------------------
# 17. No `eval`, and no `$1` beyond verb parsing.
# ---------------------------------------------------------------------------


def test_no_eval_and_no_top_level_positional_args_beyond_verb_parsing() -> None:
    """No `eval`; no reference to the SCRIPT's own `$1` outside verb parsing.

    `$1` also appears inside several functions below verb parsing (e.g.
    `switch_enabled_site`'s `local target="$1"`, `do_revert`'s `local
    prior="$1"`) — those are ordinary bash FUNCTION ARGUMENTS, a different
    `$1` than the script's own `argv`, and are not what this guard is
    about. The packet's "no $1 beyond verb parsing" is interpreted here as:
    outside every function body, the script's own `$1` is read in exactly
    one place (`VERB="$1"`) and nowhere else at top level. This is computed
    with `_function_spans`, not a flat substring count, precisely so
    legitimate function-parameter `$1` usage does not trip the guard.
    """
    script = _text(HELPER)
    code = _code_only(script)

    assert "eval" not in code

    # Spans are computed against `code` (not `script`): `_code_only` blanks
    # comment lines to empty strings, which shifts character offsets versus
    # the original script, so spans and the `$1` search below must both run
    # against the SAME text or the offsets silently misalign.
    spans = _function_spans(code, HELPER_FUNCTIONS)
    top_level_dollar_1 = [
        m.start()
        for m in re.finditer(r"\$1\b", code)
        if _outside_all_spans(m.start(), spans)
    ]
    assert len(top_level_dollar_1) == 1, top_level_dollar_1
    (pos,) = top_level_dollar_1
    line_start = code.rfind("\n", 0, pos) + 1
    line_end = code.index("\n", pos)
    assert code[line_start:line_end].strip() == 'VERB="$1"'

    # Sensitivity: adding a second top-level read of the script's own
    # arguments (e.g. an ad hoc `echo "called with $1"` dropped in outside
    # any function, or a rewrite that inlined verb dispatch without a
    # function wrapper around a `$1`-reading helper) raises the top-level
    # count above 1. Because the check is span-based, it does NOT
    # false-positive on the several legitimate function-local `$1` uses
    # this script already has — confirmed by reading `switch_enabled_site`,
    # `do_revert`, `attempt_switch_and_prove_or_revert`,
    # `require_root_owned_and_not_group_or_other_writable`, `status_for_conf`
    # and `marker_for_conf`, all of which use `$1` purely as their own
    # function argument.


# ---------------------------------------------------------------------------
# 18. MUTATED=1 precedes ln -s in switch_enabled_site.
# ---------------------------------------------------------------------------


def test_mutated_is_set_before_the_temporary_link_is_created() -> None:
    script = _text(HELPER)
    switch_body = _function_body(script, "switch_enabled_site")

    mutated_idx = switch_body.index("MUTATED=1")
    ln_idx = switch_body.index('ln -s "$target" "$tmp_link"')
    assert mutated_idx < ln_idx, (
        "MUTATED must flip before the FIRST filesystem call this function "
        "makes (the temporary ln -s), not just before the mv -T that "
        "repoints ENABLED_LINK — deliberately conservative, so a failed "
        "ln -s is treated as state-unknown (67), never nothing-happened (65)"
    )

    # Sensitivity: moving `MUTATED=1` to just before the `mv -T` line (a
    # seemingly-more-precise placement, since `mv -T` is the step that
    # actually repoints ENABLED_LINK) would flip this ordering assertion —
    # exactly the near-miss this test exists to catch, since a failed `ln -s`
    # under that placement would incorrectly report 65 ("nothing happened")
    # despite having just written a stray temporary link under MANAGED_DIR.


# ---------------------------------------------------------------------------
# 19. capture_and_validate_prior_state runs before the first possible switch.
# ---------------------------------------------------------------------------


def test_capture_and_validate_prior_state_runs_before_the_verb_dispatch() -> None:
    script = _text(HELPER)

    # The bare top-level call (not the function definition
    # "capture_and_validate_prior_state() {") is the only place this
    # function is actually invoked.
    call_idx = script.index("capture_and_validate_prior_state\n")
    dispatch_start = script.rindex('case "$VERB" in')
    assert call_idx < dispatch_start, (
        "CAPTURED_PRIOR must be set before the verb-dispatch case — the "
        "only place that can reach switch_enabled_site — begins; both "
        "verb arms unconditionally reference $CAPTURED_PRIOR"
    )

    # Sensitivity: moving the call inside one dispatch arm (e.g. "only
    # capture it for routing-restore, since maintenance-on rarely needs it")
    # would leave $CAPTURED_PRIOR unset for the other arm's do_revert /
    # attempt_switch_and_prove_or_revert calls, which unconditionally
    # reference it — this ordering assertion is what keeps that invariant
    # checkable from the text alone.


# ---------------------------------------------------------------------------
# 20. A drain timeout (reload_rc == 2) goes straight to 67, with no revert.
# ---------------------------------------------------------------------------


def test_a_drain_timeout_skips_the_revert_and_goes_straight_to_67() -> None:
    script = _text(HELPER)
    body = _function_body(script, "attempt_switch_and_prove_or_revert")

    start = body.index('if [ "$reload_rc" -eq 2 ]; then')
    fi_idx = body.index("\n    fi\n", start)
    block = body[start:fi_idx]

    assert "FAIL_CODE=67" in block
    assert "do_revert" not in block, (
        "a drain timeout is an AMBIGUOUS worker mix — attempting a revert "
        "on top of an already-ambiguous state could make things worse, so "
        "this path must go straight to 67 without one"
    )

    # Sensitivity: adding a `do_revert "$CAPTURED_PRIOR"` call inside this
    # specific block (the fix described in the packet's own exit-code
    # contract: "a drain timeout after the reload is 67, and it is never
    # `|| true`") would flip the `not in` assertion. A near-miss that added
    # the call just AFTER this `fi` (i.e. in the general reload_rc != 0
    # path) would not trip this test, but IS a different, already-existing
    # code path (the `reload_rc -ne 0` block below) that legitimately does
    # revert for a non-drain-timeout reload failure.


# ---------------------------------------------------------------------------
# 21. The maintenance-on short-circuit calls the drain check before proving.
# ---------------------------------------------------------------------------


def test_maintenance_on_short_circuit_waits_for_drain_before_proving() -> None:
    script = _text(HELPER)

    maintenance_on_start = script.rindex("maintenance-on)")
    routing_restore_start = script.rindex("routing-restore)")
    arm = script[maintenance_on_start:routing_restore_start]

    short_circuit_start = arm.index(
        'if [ "$CAPTURED_PRIOR" = "$MAINTENANCE_CONF" ]; then'
    )
    switch_call_idx = arm.index("attempt_switch_and_prove_or_revert")
    short_circuit_block = arm[short_circuit_start:switch_call_idx]

    assert "wait_for_no_shutting_down_workers" in short_circuit_block
    wait_idx = short_circuit_block.index("wait_for_no_shutting_down_workers")
    prove_idx = short_circuit_block.index("PROVE_WANT_STATUS=503")
    assert wait_idx < prove_idx, (
        "the drain-wait must run BEFORE the proof — a worker still mid-"
        "shutdown from an earlier timed-out drain could otherwise still be "
        "serving live traffic even though the 503 proof passes"
    )
    # On timeout, this path must exit 67 immediately (never fall through to
    # the proof, let alone to attempt_switch_and_prove_or_revert, which
    # could switch back toward live) — the FIRST FAIL_CODE=67 in this block
    # is the wait's own failure handler, and it must sit strictly between
    # the wait call and the proof assignment.
    first_fail_idx = short_circuit_block.index("FAIL_CODE=67")
    assert wait_idx < first_fail_idx < prove_idx

    # Sensitivity: dropping the `wait_for_no_shutting_down_workers` call
    # entirely (reverting to the pre-fix-round short circuit) empties
    # `short_circuit_block` of that substring, failing the first assertion.
    # Moving it to AFTER `PROVE_WANT_STATUS=503` (proving before checking
    # drain) flips the ordering assertion — exactly the HIGH-severity defect
    # named in this fix round's packet.


# ---------------------------------------------------------------------------
# 22. The live conf hides the marker header from the upstream app.
# ---------------------------------------------------------------------------


def test_live_conf_hides_the_marker_header_from_the_upstream() -> None:
    live = _text(LIVE_CONF)

    assert f"proxy_hide_header {MARKER_HEADER};" in live

    # Must sit inside the 443 `location /` block, before `proxy_pass` (order
    # doesn't strictly matter to nginx here, but the header must be hidden
    # on THIS block, not the port-80 redirect block, which has no proxy_pass
    # at all).
    second_location = live.index(
        "\n    location / {\n", live.index("\n    location / {\n") + 1
    )
    proxy_pass_idx = live.index("proxy_pass", second_location)
    hide_idx = live.index(f"proxy_hide_header {MARKER_HEADER};", second_location)
    assert second_location < hide_idx < proxy_pass_idx

    # Sensitivity: without `proxy_hide_header`, a compromised or
    # misconfigured upstream could forge `X-Dotmac-Maintenance` on its own
    # 503/200 responses — routing-restore's proof requires the marker be
    # ABSENT, so a forged marker would make a genuinely-restored live proof
    # falsely fail (or, worse, a forged marker on a live response could mask
    # a real problem). Removing the directive drops the first assertion;
    # moving it to the port-80 block (which never proxies) would not appear
    # inside this function's `second_location`-scoped search, catching that
    # misplacement too.

    # This addition is entirely inside the 443 `location /` block, which
    # `test_maintenance_conf_equals_live_conf_except_for_the_443_location_
    # block` above deliberately excludes from its prefix/suffix comparison
    # — confirmed by re-reading that test: it still holds unchanged.


def test_the_drain_checks_fail_closed_without_a_live_nginx_master() -> None:
    """A missing, stale or foreign pid file must never let a drain check pass.

    Sensitivity: restoring `[ -n "$master_pid" ] || return 0` in
    `no_worker_is_shutting_down`, or dropping `require_nginx_master` from the
    top-level preconditions, fails this test.
    """
    script = _text(HELPER)
    body = script[script.index("no_worker_is_shutting_down() {") :]
    body = body[: body.index("\n}\n")]
    assert 'nginx_master_is_live "$master_pid" || return 1' in body
    assert "|| return 0" not in body
    assert "\nrequire_nginx_master\n" in script
    assert '[ "$comm" = "nginx" ]' in script


def test_the_function_registry_matches_the_helper() -> None:
    """HELPER_FUNCTIONS must list every function the helper defines, in file
    order, so no new function escapes the guards that scope by function body.

    Sensitivity: adding a function to the helper without listing it here (or
    listing one that no longer exists, or reordering) fails this test.
    """
    defined = tuple(
        re.findall(r"^([a-z_][a-z0-9_]*)\(\) \{", _text(HELPER), flags=re.MULTILINE)
    )
    assert defined == HELPER_FUNCTIONS
