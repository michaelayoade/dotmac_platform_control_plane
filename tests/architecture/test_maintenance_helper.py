"""The nginx maintenance helper proves its own switch, and only that switch.

`deploy/host/dotmac-vendor-maintenance` is a root-owned, checked-in-only
script (D16 PR 3): nothing in this repository or its CI installs it. These
are static shape guards over the script text, the maintenance nginx config,
and the sudoers fragment — there is no live nginx or curl target to run
against here, so a passing test proves the SCRIPT SAYS the right thing, not
that the host does it. That is why every guard below plants a defect and
shows the assertion actually catches it (documented inline as a sensitivity
note), mirroring the convention in `test_production_deployment.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HELPER = "deploy/host/dotmac-vendor-maintenance"
LIVE_CONF = "deploy/nginx/vendor.dotmac.io.conf"
MAINTENANCE_CONF = "deploy/nginx/vendor.dotmac.io.maintenance.conf"
SUDOERS = "deploy/host/sudoers.d/dotmac-vendor-maintenance"

MARKER_HEADER = "X-Dotmac-Maintenance"


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _code_only(script: str) -> str:
    """The script with comment-only lines blanked.

    Several guards below count literal tokens (`$1`, `eval`). The header
    comment and inline notes legitimately describe those tokens in prose
    (e.g. "the ONLY place this script reads $1"), so counting raw text would
    make the guard fire on documentation, not on code. Blanking comment
    lines is the same correction `test_production_deployment.py::_commands`
    makes for ordering assertions.
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


# ---------------------------------------------------------------------------
# 1. Exactly two verbs; extra arguments are rejected.
# ---------------------------------------------------------------------------


def test_the_helper_declares_exactly_two_verbs_and_rejects_extra_arguments() -> None:
    script = _text(HELPER)

    assert '"$#" -ne 1' in script, (
        "must reject any call that isn't exactly one argument"
    )
    assert "maintenance-on" in script
    assert "routing-restore" in script

    case_match = re.search(r'case "\$VERB" in\n(.*?)\nesac', script, re.DOTALL)
    assert case_match, "expected a case statement validating $VERB"
    case_block = case_match.group(0)
    # exactly the two known verbs plus a catch-all default that calls usage
    verb_arms = re.findall(r"^\s{4}([a-z*][a-z*-]*)\)", case_block, re.MULTILINE)
    assert set(verb_arms) == {"maintenance-on", "routing-restore", "*"}, verb_arms
    assert "*) usage ;;" in case_block

    # Sensitivity: a version accepting any number of arguments (e.g. testing
    # "$#" -lt 1 instead of -ne 1) would let `maintenance-on extra-garbage`
    # through silently — this assertion specifically requires -ne 1, so a
    # near-miss switch to -lt/-gt would be caught, and a version that drops
    # the arm entirely (`--) usage ;;` deleted) fails the arm-count assertion.
    assert '"$#" -lt 1' not in script


# ---------------------------------------------------------------------------
# 2. Atomic switch: mv -T, never ln -sfn.
# ---------------------------------------------------------------------------


def test_the_switch_uses_mv_dash_t_and_never_ln_sfn() -> None:
    script = _text(HELPER)
    code = _code_only(script)  # the header comment names `ln -sfn` as the
    # anti-pattern being avoided ("never ln -sfn") — that mention must not
    # itself trip this guard, so it is checked against CODE only.

    assert "mv -T" in code
    # the temporary symlink itself is created with a plain `ln -s`, immediately
    # followed by the atomic rename — a defect that reused `ln -sfn` for the
    # "revert" path specifically would slip past a check that only looked at
    # the first occurrence, so this scans the whole (code-only) file.
    assert code.count("ln -sfn") == 0

    # Sensitivity: replacing `mv -T "$tmp_link" "$ENABLED_LINK"` with a bare
    # `mv "$tmp_link" "$ENABLED_LINK"` changes behaviour if the destination is
    # ever unexpectedly a directory (mv would move *into* it instead of
    # replacing it) — dropping `-T` drops the first assertion above to false.
    # Reintroducing `ln -sfn` anywhere (the non-atomic near-miss this whole
    # test exists to catch) flips the second assertion.


# ---------------------------------------------------------------------------
# 3. nginx -t precedes every reload.
# ---------------------------------------------------------------------------


def test_nginx_dash_t_precedes_every_reload() -> None:
    script = _text(HELPER)

    # `readonly RELOAD_CMD=...` assigns the NAME with no `$`; the only place
    # the script ever expands `$RELOAD_CMD` (actually invokes the reload) is
    # inside reload_and_wait_for_drain.
    assert script.count("$RELOAD_CMD") == 1
    reload_body = _function_body(script, "reload_and_wait_for_drain")
    assert "$RELOAD_CMD" in reload_body

    # The only caller of reload_and_wait_for_drain is switch_validate_or_bail.
    # `if ! validate_config; then` is the nginx -t check; the reload must sit
    # AFTER that if-block's closing `fi` (i.e. only reached once validation
    # already succeeded — the failure branch calls fail(), which exits, so it
    # never falls through to the reload).
    switch_body = _function_body(script, "switch_validate_or_bail")
    if_idx = switch_body.index("if ! validate_config")
    fi_idx = switch_body.index("\n    fi\n")
    reload_idx = switch_body.index("reload_and_wait_for_drain")

    assert if_idx < fi_idx < reload_idx, (
        "nginx -t must run, and the failure branch must complete, "
        "before the reload is ever reached"
    )

    # Sensitivity: moving the `reload_and_wait_for_drain` call to before the
    # `if ! validate_config` check (or inside the failure branch) would make
    # this comparison fail — that is exactly the defect (reload-before-validate)
    # this test exists to catch. A near-miss that keeps the correct order but
    # renames the function is caught by the two occurrence-count assertions
    # above (they would drop to zero).


# ---------------------------------------------------------------------------
# 4. Marker header name matches between the maintenance conf and the helper.
# ---------------------------------------------------------------------------


def test_marker_header_name_matches_between_conf_and_helper() -> None:
    script = _text(HELPER)
    maintenance = _text(MAINTENANCE_CONF)

    assert f'MARKER_HEADER="{MARKER_HEADER}"' in script
    assert f"add_header {MARKER_HEADER} vendor-cp always;" in maintenance
    assert 'MARKER_VALUE="vendor-cp"' in script

    # Sensitivity: a maintenance conf with a differently-cased or differently
    # named header (e.g. "X-DotMac-Maintenance") would still add SOME header,
    # so a test only checking `"add_header" in maintenance` would pass while
    # the helper's proof silently never sees its expected header. Matching
    # the exact constant string against the conf's exact directive catches
    # that drift.


# ---------------------------------------------------------------------------
# 5. The proof requires the marker, not just the status code.
# ---------------------------------------------------------------------------


def test_the_proof_requires_the_marker_not_just_the_status_code() -> None:
    script = _text(HELPER)

    prove_body = _function_body(script, "prove_public")
    assert "PROVE_WANT_MARKER" in prove_body
    assert "PROVE_WANT_STATUS" in prove_body
    # both a status mismatch and a marker mismatch must independently fail
    # the probe (each guarded by its own `return 1`)
    assert prove_body.count("return 1") >= 3

    # `maintenance-on)`/`routing-restore)` each appear twice: once in the
    # top verb-validation case (empty `;;` arms) and once in the bottom
    # dispatch case (the real logic). `rindex` targets the bottom (dispatch)
    # occurrence, which is later in the file.
    maintenance_on_start = script.rindex("maintenance-on)")
    routing_restore_start = script.rindex("routing-restore)")
    assert maintenance_on_start < routing_restore_start
    maintenance_on_block = script[maintenance_on_start:routing_restore_start]
    assert "PROVE_WANT_STATUS=503" in maintenance_on_block
    assert 'PROVE_WANT_MARKER="present"' in maintenance_on_block

    # Sensitivity: the packet is explicit that a bare 503 is not proof,
    # because the app's own /health/ready also returns 503 when the database
    # is fenced. A defect that dropped the PROVE_WANT_MARKER="present" check
    # (proving only PROVE_WANT_STATUS=503) would pass a false "maintenance is
    # on" verdict during an unrelated database outage — this assertion on the
    # maintenance-on block specifically requires both.


# ---------------------------------------------------------------------------
# 6. Sudoers: exactly two commands, no wildcards.
# ---------------------------------------------------------------------------


def test_sudoers_fragment_lists_exactly_two_commands_with_no_wildcards() -> None:
    sudoers = _text(SUDOERS)

    cmnd_alias_match = re.search(
        r"^Cmnd_Alias VENDOR_MAINT = (.+)$", sudoers, re.MULTILINE
    )
    assert cmnd_alias_match, "expected a Cmnd_Alias line naming VENDOR_MAINT"
    commands = [c.strip() for c in cmnd_alias_match.group(1).split(",")]
    assert len(commands) == 2, commands
    assert commands == [
        "/usr/local/sbin/dotmac-vendor-maintenance maintenance-on",
        "/usr/local/sbin/dotmac-vendor-maintenance routing-restore",
    ]

    assert "*" not in sudoers
    assert "ALL=(root) NOPASSWD: VENDOR_MAINT" in sudoers
    assert "<DEPLOY_USER>" in sudoers  # placeholder, substituted at install time

    # Sensitivity: a fragment listing the bare binary with no verb
    # (`/usr/local/sbin/dotmac-vendor-maintenance` alone, or with a trailing
    # wildcard like `*`) would let the deploy user run ANY verb — including a
    # future one — as root with no password. The exact-match-list assertion
    # and the `"*" not in sudoers` check both independently catch that.


# ---------------------------------------------------------------------------
# 7. The maintenance conf equals the live conf except for `location /`.
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
    # maintenance_prefix (both files' TLS lines sit before the second
    # `location / {`). A near-miss that only changes the `location /` body
    # (the intended difference) must NOT fail this test — that is exactly
    # what the `location /` exclusion is for.


# ---------------------------------------------------------------------------
# 8. No use of $1 beyond the verb; no eval.
# ---------------------------------------------------------------------------


def test_no_reference_to_positional_args_beyond_the_verb_and_no_eval() -> None:
    script = _text(HELPER)
    code = _code_only(script)

    assert code.count("$1") == 1, 'the only $1 must be the single VERB="$1" capture'
    assert "$2" not in code
    assert "eval" not in code

    # Sensitivity: a helper function written as `switch_target() { ln -s "$1"
    # ... }` (positional args instead of the SWITCH_TO/SWITCH_VALIDATE_TARGET
    # globals this script uses) would push the `$1` count above 1 — this
    # guard is what keeps verb parsing as the single, auditable place this
    # script reads its own arguments. Comment-only mentions of "$1" (this
    # file's header prose) do not count, because `_code_only` blanks them
    # first — the same correction `test_production_deployment.py::_commands`
    # makes.
