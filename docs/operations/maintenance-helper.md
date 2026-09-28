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
(never `ln -sfn`), reloads, and proves its own switch against the public
endpoint over three fresh connections before it will report success. It
does **not** decide when it is safe to restore public routing — that
precondition (compatible heads, health and ACL restoration already proven)
is the deploy's job, in D16 PR 4. This helper only proves the mechanical
switch it just performed.

A failed post-migration deploy stays in maintenance: `routing-restore`
refuses to run at all unless the app's own loopback health check is already
200, and if the proof after switching fails, it reverts to maintenance
(not to live) and proves the marker is back.

See `deploy/host/dotmac-vendor-maintenance`'s header comment for the full
exit-code contract; it is summarized below.

## What is installed, where, owner and mode

| Path | Content | Owner | Mode |
| --- | --- | --- | --- |
| `/usr/local/sbin/dotmac-vendor-maintenance` | `deploy/host/dotmac-vendor-maintenance` | `root:root` | `0755` |
| `/etc/nginx/dotmac/vendor/live.conf` | `deploy/nginx/vendor.dotmac.io.conf` | `root:root` | `0644` |
| `/etc/nginx/dotmac/vendor/maintenance.conf` | `deploy/nginx/vendor.dotmac.io.maintenance.conf` | `root:root` | `0644` |
| `/etc/sudoers.d/dotmac-vendor-maintenance` | `deploy/host/sudoers.d/dotmac-vendor-maintenance`, with `<DEPLOY_USER>` substituted | `root:root` | `0440` |

The enabled site remains `/etc/nginx/sites-enabled/vendor.dotmac.io`; the
helper only ever repoints that one symlink between the two files above.

## The one-time `sites-enabled` conversion

`scripts/bootstrap_production_host.sh` today installs the live config as a
**plain file** at `/etc/nginx/sites-available/vendor.dotmac.io`
(`install -m 0644 ...`) and points `/etc/nginx/sites-enabled/vendor.dotmac.io`
at it with `ln -sfn` (see that script's `NGINX_AVAILABLE`/`NGINX_ENABLED`
constants and its cert-issuance step, which reinstalls the same file's
*content* in place rather than switching a symlink). That shape does not
give the helper anything to atomically switch between: there is only one
managed file, not two named targets.

This is a one-time, Michael-only host conversion, done once before the
first `maintenance-on` rehearsal, and it does not change
`bootstrap_production_host.sh`:

```console
$ sudo install -d -m 0755 /etc/nginx/dotmac/vendor
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
`/etc/nginx/dotmac/vendor/live.conf`, which the helper will repoint between
`live.conf` and `maintenance.conf`. `/etc/nginx/sites-available/vendor.dotmac.io`
is left in place, unreferenced; a future bootstrap re-run reinstalling it is
harmless because nothing in `sites-enabled` points at it anymore.

## Installing the sudoers fragment

```console
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

| Code | Meaning | Operator action |
| --- | --- | --- |
| `0` | ok | none — the switch is proven |
| `64` | usage error: unknown verb, missing verb, or extra arguments | nothing was touched; fix the invocation |
| `65` | validation failed: a precondition was not met, or `nginx -t` rejected the candidate config | nothing was switched that was not switched back, and nothing was reloaded; read the `logger` output, fix the config or the precondition, retry |
| `66` | proof failed after a successful switch and reload | the helper reverted and PROVED the revert; read the logs to understand why the public proof failed (app not actually ready, DNS/TLS drift, etc.) before retrying |
| `67` | revert failed | state is **UNKNOWN** — page a human immediately; do not retry automatically; check `nginx -T`, the enabled-site symlink target, and the public endpoint by hand before touching anything else |

## Relationship to the deploy (D16 PR 4)

This helper is checked in only. `deploy_production.sh` (D16 PR 4) is the
intended caller: it runs `maintenance-on` before a migration, and only calls
`routing-restore` after it has independently proven compatible heads,
application health, and ACL restoration — this helper does not make that
judgment call. Until PR 4 lands and wires the sudoers-gated call, this
helper is unused in production.
