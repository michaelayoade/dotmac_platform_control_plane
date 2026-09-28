# The vendor.dotmac.io nginx maintenance helper

This describes `deploy/host/dotmac-vendor-maintenance`, checked in only.
Nothing in this repository or its CI installs it. Every step below is
**Michael-only**, on the host he names, and until D16 PR 4 lands and calls
it, this helper is unused.

## What it does

`dotmac-vendor-maintenance` is a narrowly scoped, root-owned nginx
maintenance switch with exactly two verbs:

- `maintenance-on` — switch public routing to a 503 maintenance response and
  prove the switch before returning.
- `routing-restore` — switch public routing back to the live proxy and prove
  the switch before returning.

It validates the candidate config with `nginx -t`, switches atomically
(never `ln -sfn`), reloads (waiting, bounded, for old workers to actually
drain and a new worker to appear), and proves its own switch against the
public endpoint over three consecutive fresh connections, with a short
settle-and-retry allowance, before it will report success. It does **not**
decide when it is safe to restore public routing — that precondition
(compatible heads, health and ACL restoration already proven) is the
deploy's job, in D16 PR 4. This helper only proves the mechanical switch it
just performed, against **this host's own nginx**.

**This is not a public-path proof if anything sits in front of
`vendor.dotmac.io`.** If a CDN, WAF, or load balancer terminates TLS or
caches responses in front of this host, a 503 proved against this host's
loopback-resolved nginx does not mean the public internet sees maintenance,
and a 200 proved here does not mean the public internet sees live traffic.
**Michael-only precondition, before the first rehearsal:** confirm nothing
sits in front of `vendor.dotmac.io` (DNS resolves directly to this host, no
CDN/WAF/LB in the path), or extend the proof to go through that layer
instead of `--resolve`-ing straight to `127.0.0.1`.

The helper's lock is a `flock` on a read-only file descriptor opened against
`/etc/nginx/dotmac/vendor/` itself (root-owned, not the world-writable
`/run/lock`); `bootstrap_production_host.sh` takes the same lock in managed
mode. Contention exits `75` immediately, distinct from every other failure.

The helper captures whichever config the enabled link is ACTUALLY pointing
at when it starts (`readlink -f`, refusing if it isn't a symlink to exactly
`live.conf` or `maintenance.conf`) and reverts to that captured state on any
failure — never to a hard-coded "other" file. If routing is already in the
requested state, the helper does not switch at all; it only proves. Before
that idempotent `maintenance-on` proof, it also waits (bounded, 90s) for any
worker still mid-shutdown from an EARLIER, possibly timed-out, drain to
actually finish — an old worker can otherwise keep serving live traffic even
though the enabled link already points at `maintenance.conf`. A
`maintenance-on` proof (or drain-wait) failure while already in maintenance
stays in maintenance and exits 67 — it never reverts to live.

The helper's own drain proof combines two independent signals after every
reload: the pre-reload worker PIDs must all be gone, a new worker must exist,
AND no surviving worker may still carry nginx's own "worker process is
shutting down" process title. The PID comparison alone can be fooled by PID
reuse or a master restart between checks; the title check is re-read fresh
from the CURRENT master's actual children on every poll for exactly that
reason.

`trap '' HUP INT TERM PIPE` means none of those signals can interrupt an
in-flight mutation. PIPE matters for a caller on a non-pty SSH pipe: when it
disconnects, the helper's next write to stderr fails with EPIPE (absorbed by
`log`) instead of killing the process. `SIGKILL` cannot be ignored, so a
caller-imposed kill can still interrupt a mutation (see the runtime bound
below).

See `deploy/host/dotmac-vendor-maintenance`'s header comment for the full
exit-code contract; it is summarized below.

## What is installed, where, owner and mode

| Path | Content | Owner | Mode |
| --- | --- | --- | --- |
| `/usr/local/sbin/dotmac-vendor-maintenance` | `deploy/host/dotmac-vendor-maintenance` | `root:root` | `0755` |
| `/etc/nginx/dotmac/vendor/` (the directory itself) | — | `root:root` | `0750` (or `0700`) |
| `/etc/nginx/dotmac/vendor/live.conf` | `deploy/nginx/vendor.dotmac.io.conf` | `root:root` | `0644` |
| `/etc/nginx/dotmac/vendor/maintenance.conf` | `deploy/nginx/vendor.dotmac.io.maintenance.conf` | `root:root` | `0644` |
| `/etc/sudoers.d/dotmac-vendor-maintenance` | `deploy/host/sudoers.d/dotmac-vendor-maintenance`, with `<DEPLOY_USER>` substituted | `root:root` | `0440` |

**The managed directory's own mode matters, not just its files':** the lock
is an `flock` on an fd opened against `/etc/nginx/dotmac/vendor/` itself, so
anyone able to `open()` that directory can contend for (and, on a
world-readable directory, potentially interfere with) the lock. The helper
refuses to run (exit 65) unless that directory is exactly `0700` or `0750`
— a more permissive mode (e.g. the `0755` used before this fix round) is
rejected. The helper also refuses (exit 65) unless
`/etc/nginx/sites-enabled/` is root-owned, not group/other-writable, AND on
the SAME filesystem as `/etc/nginx/dotmac/vendor/` (`stat -c %d`) — `mv -T`
is only atomic within one filesystem.

The enabled site remains `/etc/nginx/sites-enabled/vendor.dotmac.io`; the
helper only ever repoints that one symlink between the two files above. The
helper's temporary link is created INSIDE `/etc/nginx/dotmac/vendor/` (not
under `sites-enabled/`) and `mv -T`'d into place — this relies on
`/etc/nginx/dotmac/vendor/` and `/etc/nginx/sites-enabled/` being the same
filesystem, which they are on a standard single-disk `/etc` (both under the
host's root filesystem); if a deployment ever mounts `/etc/nginx` split
across filesystems, `mv -T` would silently fall back to a non-atomic
copy-and-unlink and this assumption must be re-verified before relying on
the helper. Any stray temporary link left by a crashed run is cleaned up,
under the lock, the next time the helper runs.

**Bootstrap owns the managed `live.conf`/`maintenance.conf` content — the
helper only owns which one is enabled.** After the one-time conversion
below, `scripts/bootstrap_production_host.sh` re-installs both managed
files (atomically: write to a temp file in the same directory, then
`mv -T`) on every run, and takes the same lock the helper does while doing
it. It never runs `ln -sfn` on the enabled link once it is managed, and it
reloads only if the link currently resolves to `live.conf` — a bootstrap
re-run that happens to land while a deploy has the host in maintenance
does not touch the enabled link or force an unexpected reload.

## The one-time `sites-enabled` conversion

Before this conversion, `scripts/bootstrap_production_host.sh` installs the
live config as a **plain file** at `/etc/nginx/sites-available/vendor.dotmac.io`
(`install -m 0644 ...`) and points `/etc/nginx/sites-enabled/vendor.dotmac.io`
at it with `ln -sfn` (see that script's `NGINX_AVAILABLE`/`NGINX_ENABLED`
constants and its cert-issuance step, which reinstalls the same file's
*content* in place rather than switching a symlink). That shape does not
give the helper anything to atomically switch between: there is only one
managed file, not two named targets. Pre-conversion, bootstrap's behaviour
is completely unchanged from before this helper existed.

This is a one-time, Michael-only host conversion, done once before the
first `maintenance-on` rehearsal:

```console
$ sudo install -d -m 0750 -o root -g root /etc/nginx/dotmac/vendor
$ sudo install -m 0644 /etc/nginx/sites-available/vendor.dotmac.io \
    /etc/nginx/dotmac/vendor/live.conf
$ sudo install -m 0644 deploy/nginx/vendor.dotmac.io.maintenance.conf \
    /etc/nginx/dotmac/vendor/maintenance.conf
$ sudo ln -s /etc/nginx/dotmac/vendor/live.conf /etc/nginx/sites-enabled/vendor.dotmac.io.tmp.$$
$ sudo mv -T /etc/nginx/sites-enabled/vendor.dotmac.io.tmp.$$ \
    /etc/nginx/sites-enabled/vendor.dotmac.io
$ sudo nginx -t && sudo systemctl reload nginx
```

After this, `/etc/nginx/sites-enabled/vendor.dotmac.io` is a symlink to
`/etc/nginx/dotmac/vendor/live.conf`. From this point on, `bootstrap_production_host.sh`
detects the conversion (the enabled link resolves inside
`/etc/nginx/dotmac/vendor/`) and switches into managed mode: it re-installs
both managed files on every run as described above, and never writes to or
re-links `/etc/nginx/sites-available/vendor.dotmac.io` or the enabled link
again. **`/etc/nginx/sites-available/vendor.dotmac.io` is NOT harmless to
leave in place indefinitely** — it is simply unreferenced once the enabled
link points elsewhere; a future bootstrap re-run does not read or write it
anymore, and it should be treated as dead weight to remove during a later
cleanup, not as a live fallback.

## Installing the sudoers fragment

```console
$ : "${VENDOR_PRODUCTION_USER:?VENDOR_PRODUCTION_USER must be set before installing the sudoers fragment}"
$ sudo install -d -m 0755 /etc/sudoers.d
$ sed 's/<DEPLOY_USER>/'"$VENDOR_PRODUCTION_USER"'/' \
    deploy/host/sudoers.d/dotmac-vendor-maintenance \
    | sudo tee /etc/sudoers.d/dotmac-vendor-maintenance.tmp >/dev/null
$ grep -q '<DEPLOY_USER>' /etc/sudoers.d/dotmac-vendor-maintenance.tmp \
    && { echo "placeholder not substituted"; exit 1; } || true
$ sudo visudo -cf /etc/sudoers.d/dotmac-vendor-maintenance.tmp
$ sudo mv /etc/sudoers.d/dotmac-vendor-maintenance.tmp /etc/sudoers.d/dotmac-vendor-maintenance
$ sudo chown root:root /etc/sudoers.d/dotmac-vendor-maintenance
$ sudo chmod 0440 /etc/sudoers.d/dotmac-vendor-maintenance
```

`$VENDOR_PRODUCTION_USER` is the same value as the GitHub Actions repository
variable `vars.VENDOR_PRODUCTION_USER` consumed by
`.github/workflows/production-deploy.yml` as `TARGET_USER`.

## Proof: `sudo -n -l` lists exactly the two commands

Run as the deploy user:

```console
$ sudo -n -l
User <deploy user> may run the following commands on <host>:
    (root) NOPASSWD: /usr/local/sbin/dotmac-vendor-maintenance maintenance-on
    (root) NOPASSWD: /usr/local/sbin/dotmac-vendor-maintenance routing-restore
```

If anything else appears — a wildcard, a third command, or a password
requirement — stop and fix the sudoers fragment before rehearsing.

## One-time rehearsal

**Michael-only preconditions, before the first rehearsal:**

- The host's nginx `worker_shutdown_timeout` (in `nginx.conf`'s `http {}`
  block, or per-`server`) must be set BELOW the helper's `DRAIN_BOUND_SECONDS`
  (90s) — for example `worker_shutdown_timeout 75s;`. If it isn't, a
  legitimately long-lived connection (a slow client streaming a response)
  can make nginx take longer than 90s to actually finish shutting an old
  worker down, and the helper will report a false `67` (state unknown) for
  a drain that was, in fact, still healthily in progress. Confirm this
  before the first rehearsal, and after any nginx config change that
  touches it.
- During the rehearsal, while a `maintenance-on` or `routing-restore` is
  draining, run `ps -o pid,args -C nginx` and confirm an old worker shows the
  literal title `nginx: worker process is shutting down`. If the host's nginx
  never shows that title, the helper's process-title drain check cannot see
  draining workers; report it before relying on the helper.
- Confirm the host's actual nginx pid file path matches the helper's
  `NGINX_PID_FILE` constant (`/run/nginx.pid`) — `nginx -T | grep pid` or
  the distro's nginx.conf `pid` directive. A mismatch here makes every
  drain/title check silently see "no master pid" and skip straight to
  "not shutting down", masking a real stuck drain.

Run once, as the deploy user, before D16 PR 4 is allowed to call this helper
in production:

```console
$ sudo /usr/local/sbin/dotmac-vendor-maintenance maintenance-on
# expected: exits 0; logs (via `logger -t dotmac-vendor-maintenance`, also
# visible with `journalctl -t dotmac-vendor-maintenance`) show the switch,
# the reload, and "proved 503 + marker on 3 fresh connections".
$ curl -sS -D - -o /dev/null https://vendor.dotmac.io/health/ready
# expected: HTTP/1.1 503, with `X-Dotmac-Maintenance: vendor-cp` and
# `Retry-After: 120` headers present.

$ sudo /usr/local/sbin/dotmac-vendor-maintenance routing-restore
# expected: exits 0; logs show the precondition check against
# http://127.0.0.1:8100/health/ready, the switch, the reload, and "proved
# 200 without marker on 3 fresh connections".
$ curl -sS -D - -o /dev/null https://vendor.dotmac.io/health/ready
# expected: HTTP/1.1 200, with no X-Dotmac-Maintenance header.
```

## Exit codes and what an operator does

Every code below describes the state AFTER any mutation, not just the
immediate failure. Once the enabled-site symlink has been switched even
once in a given run, `65` is never reachable again — an EXIT trap inside
the helper remaps any exit code outside `{0,64,65,66,67,75}` to `65` before
a mutation and `67` after one, so an operator never sees a raw or
undocumented status.

| Code | Meaning | Operator action |
| --- | --- | --- |
| `0` | ok | none — the switch (or, if already in the target state, the proof) is proven |
| `64` | usage error: unknown verb, missing verb, or extra arguments | nothing was touched; fix the invocation |
| `65` | refused, or failed, BEFORE any mutation — state is unchanged (a stat/ownership/mode precondition on the managed directory or `sites-enabled/`, a cross-filesystem mismatch between them, an unmanaged or unresolved enabled-link target, or the `routing-restore` app-health precondition) | nothing was switched; read the `logger` output, fix the precondition, retry |
| `66` | the public proof failed after a successful switch and reload | the helper reverted to the CAPTURED PRIOR config, reloaded, and PROVED the revert; read the logs to understand why the public proof failed (app not actually ready, DNS/TLS drift, a CDN/WAF/LB in front — see above) before retrying |
| `67` | state is **UNKNOWN**: a revert could not be proved, a drain timed out (an ambiguous old/new worker mix), or an unexpected error occurred after a mutation | page a human immediately; do not retry automatically; check `nginx -T`, the enabled-site symlink target, `systemctl status nginx`, and the public endpoint by hand before touching anything else |
| `75` | another run (the helper or a concurrent `bootstrap_production_host.sh`) holds the lock | nothing was touched; wait for the other run to finish, or investigate why it is stuck, before retrying |

## Relationship to the deploy (D16 PR 4)

This helper is checked in only. `deploy_production.sh` (D16 PR 4) is the
intended caller: it runs `maintenance-on` before a migration, and only calls
`routing-restore` after it has independently proven compatible heads,
application health, and ACL restoration — this helper does not make that
judgment call. Until PR 4 lands and wires the sudoers-gated call, this
helper is unused in production.

### Worst-case runtime — a PR 4 constraint

Computed from the helper's own constants, a single invocation that switches,
fails its proof, and reverts (proving the revert too) bounds at:

```
2 × ( DRAIN_BOUND_SECONDS
      + PROOF_SETTLE_RETRIES × (PROOF_ATTEMPTS × curl --max-time)
      + (PROOF_SETTLE_RETRIES − 1) × PROOF_SETTLE_SLEEP_SECONDS )
= 2 × ( 90 + 3 × (3 × 10) + 2 × 1 )
= 2 × 182
= 364 seconds (≈ 6.1 minutes)
```

This counts a forward drain that succeeds just inside its bound, a failed
forward proof, a revert drain and a revert proof. `routing-restore` adds its
app-health probe (at most 10s) before any switch: **374s nominal**. The
`maintenance-on` already-in-maintenance short-circuit (drain-wait, then one
proof) bounds at `90 + 92 = 182`s; `routing-restore`'s already-live
short-circuit (health probe, then one proof, no drain-wait) at `10 + 92 = 102`s.

Not counted, because the helper does not bound them itself: `nginx -t` time,
`systemctl reload` time, and the per-poll overhead of the drain loops (a
`cat`, a `pgrep` and a `ps` per child, about once a second).

**PR 4 must give the helper at least this much headroom — recommend
7 minutes (420s) — and must NOT wrap `dotmac-vendor-maintenance` in a
shorter `timeout`.** A caller-imposed timeout shorter than the helper's own
worst case can kill the process mid-mutation despite the trap-blocked
signals above (`SIGKILL` cannot be trapped), defeating the entire
state-truthful exit-code contract this helper exists to provide.

### Per-exit-code state, by verb

Replaces any blanket "stay in maintenance and do not fence" — PR 4 must
consult this per-code table instead:

| Code | `maintenance-on` leaves the host... | `routing-restore` leaves the host... | PR 4 action |
| --- | --- | --- | --- |
| `0` | in maintenance, proven | live, proven | proceed (fence/migrate for `maintenance-on`; resume traffic for `routing-restore`) |
| `64` | untouched, in its prior state (usually live) | untouched, in its prior state (usually maintenance) | do not fence or migrate; fix the invocation and retry |
| `65` | untouched, in its prior state (usually live) | untouched, in its prior state (usually maintenance) | do not fence or migrate; fix the failed precondition and retry |
| `66` | reverted to the CAPTURED PRIOR state, proven (usually back to live) | reverted to the CAPTURED PRIOR state, proven (usually back to maintenance) | do not fence or migrate; read the logs before retrying |
| `67` | **unknown** | **unknown** | page a human immediately; do not fence or migrate; do not retry automatically |
| `75` | not touched by THIS run; the state is whatever the lock holder is doing, possibly mid-switch | not touched by THIS run; the state is whatever the lock holder is doing, possibly mid-switch | do not fence or migrate; wait for the lock holder or investigate, then retry |

A nonzero exit from either verb is never a signal to proceed as if routing
were in the requested state.

## Known limitation: no behavioural rehearsal in CI

The architecture tests in `tests/architecture/test_maintenance_helper.py`
are static text/parse checks only — there is no stubbed `nginx`,
`systemctl`, or `curl` harness exercising the helper's actual control flow
(the switch/validate/reload/drain/proof/revert state machine, the EXIT
trap's remapping, or the idempotent-verb short-circuits). That behavioural
coverage remains a follow-up; until it exists, the one-time rehearsal above
is the only exercise of the real code paths, and it must be repeated after
any change to the helper.
