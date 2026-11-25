# registry-reader-issuance: per-app read-only Forgejo token -> GitHub environment secret

Fleet pattern. One JSON config per app (see `example-erp.config.json`; REPLACE- values make it refuse
until filled). No OpenBao copy. Token lives only as the GitHub environment secret. This v2 copy is SOURCE PREPARATION ONLY.
No issuer/dry-run, tests, SSH, network, Docker, import, build or install was executed during preparation.
Only syntax/AST/static inspection was performed; hosted validation and independent review remain required.
The value flows ssh stdout -> `audit.py shape-gate` (40-hex check) -> `gh secret set` stdin. Never argv/file/tty.

Files: `audit.py` (read-only audit, env read-back, compare), `issue.sh` (Mac), `test_issuance.py` (mocked).
Receipts (non-secret JSON + sha256) go to `receipts/<app>/<UTC stamp>/` (override base: `REGISTRY_READER_OUT`).

Reviewed-bytes pin: `issue.sh` holds `EXPECTED_MANIFEST` (sha256 of `SHA256SUMS`, which lists every other file) and
first checks owner/mode (600/700)/no symlinks/no extra files, then `shasum -a 256 -c SHA256SUMS`; audit.py goes over ssh
only after that. issue.sh cannot list itself, so the reviewer records `shasum -a 256 issue.sh` (register) as the final pin.
SSH: `audit.py ssh_base` is the single transport builder for metadata collection and minting.
It fixes `/usr/bin/ssh -F /dev/null -T`, strict reviewed known_hosts only, ed25519 host keys,
public-key authentication and an explicit identity path. It disables host-key updates/commands,
multiplexing, proxying, canonicalization, local commands, and all forwarding. Connection timeout
is 6 seconds with one attempt. The destination is `registry_ssh_expected_hostname`, with explicit
`ssh_user` and port 22. `registry_ssh_alias` remains a label for existing per-app configs; it does
not select the route. Add required `ssh_identity_file` as an absolute simple path for the reviewed
identity; the preparer never opens that key. Other per-app fields remain configurable.

The reviewed `registry_known_hosts` (default `../erp-registry-verification-20261029/`, or
`known_hosts_file`) remains mandatory. Its ownership, mode, regular-file status and nonempty size
are checked. The configured destination must match an enrolled ed25519 key in that file; each SSH
connection authenticates it with strict checking and no global/ambient known_hosts sources.
`pin` only validates the static explicit route and known_hosts file; it performs no SSH command,
uses no `ssh -G` and explicitly reports `host_key_verified: false`. It proves neither connectivity
nor possession of the host key. `ssh-argv` emits the same NUL-delimited argv for issue.sh minting;
mint stdin is `/dev/null`, while collection supplies only the source on stdin.

Hosted tests must run under the dedicated test owner using the established hosted unittest
invocation for `test_issuance.py`. They copy source to a private fixture, assert exactly one fixed SSH
binary literal, replace it with an absolute fake executable, and repin that fixture. Production
source remains fixed to `/usr/bin/ssh`; PATH cannot replace it. The fake refuses any transport argv
that differs from the reviewed options or configured route. Tests cover refusal before mint/secret,
ambient config isolation, generic routes/identities, missing identities, unsafe route values and
static pin semantics. No live handshake, key validity, production authorization, effective remote
capability or end-to-end custody is established by mocks. Original source and its historical
receipts remain in `../registry-reader-issuance` unchanged; receipts were not copied into v2.

## Operator order
1. Forgejo prerequisites (Michael, registry host, Forgejo admin; verify flags with `--help` first):
   - create user (non-admin, restricted, random password never stored, no keys, no repos), e.g.
     `forgejo admin user create --username U --email U@invalid --random-password --must-change-password=false`
   - create team T in org O through the API so only packages is granted (admin password is prompted by curl, never in argv):
     `curl -u ADMIN -X POST -H 'Content-Type: application/json' https://REGISTRY/api/v1/orgs/O/teams -d '{"name":"T","permission":"read","includes_all_repositories":false,"can_create_org_repo":false,"units_map":{"repo.packages":"read"}}'`
     then `curl -u ADMIN -X PUT https://REGISTRY/api/v1/teams/<TEAM_ID>/members/U`. UI creation is also fine if every
     unit other than packages is None: the audit accepts packages=read(1) with every other unit row at mode 0, and
     refuses any other nonzero mode. U must be the team's only member and must not be in Owners.
   - Prove token revocation works, then set `revoke_verified` true and fill `revoke_command_template`.
2. Pre-audit: `python3 -I audit.py pre --config CFG --out receipts/pre.json` (must pass: user/team ok, 0 tokens).
3. Dry run, then issue: `./issue.sh CFG` (dry-run: pin, fresh pre-audit, env read-back), then `./issue.sh CFG --apply`.
   It refuses on any drift: env policy {custom:true, protected:false}, branches exactly [main], can_admins_bypass false,
   secret absent. Then mint -> set -> env read-back -> post-audit -> compare.
4. Post-audit (done by issue.sh; re-run by hand): `audit.py post --config CFG --since <UTC> --name <token name>`;
   `audit.py compare receipts/pre.json receipts/post.json`. Expect exactly 1 token, scope `read:package`, in window.
5. Non-main test dispatch: throwaway branch at main sha, dispatch the consuming workflow from it; the environment
   must refuse (0 steps run). Then delete the branch. If NOT refused, roll back (below).

"main only" holds only if no `pull_request_target`/`workflow_run` workflow can use the environment. issue.sh reads
the repo's workflows at main (gh api contents) and refuses if any workflow other than `consumer_workflow` names the
environment, or if the consumer has either trigger (substring check, fail-closed).

## Failure after mint
issue.sh prints the revoke command for the token name, how to list the ID (`audit.py tokens --config CFG`), and
`gh secret delete`. It exits nonzero. Nothing secret is printed.

## Rollback
Revoke the token (revoke_command_template), `gh secret delete NAME --env ENV --repo R`, disable the consuming workflow
(`gh workflow disable`). Other principals/tokens are untouched.

## Rotation (every rotate_by_days; record the date in the register)
Pre-audit requires 0 tokens and an absent secret, so: revoke the old token, `gh secret delete`, then run the order from step 2.
Token names are `<token_name>-<UTC stamp>` so reissue never collides.

## Assumptions to verify before use (nothing was run against real hosts)
- Forgejo CLI: `forgejo admin user generate-access-token --username --token-name --scopes read:package --raw`; run as the
  `git` user in the container (`docker exec -u git`); may need `--config`. Output = 40 hex (shape gate refuses otherwise).
- Token revocation route/CLI (config template is operator-supplied). No native token expiry assumed.
- DB columns: user.is_restricted/is_admin/type/login_type, access_token.scope, team.authorize, team_unit.type/access_mode
  (packages=9, read=1), team_repo, public_key.owner_id, gpg_key.owner_id, collaboration, access.
- Restricted user can still read org packages via team membership (set `require_restricted` false if it cannot).
- GitHub API: environments/{env} returns can_admins_bypass; secrets list gives updated_at. 120 s clock-skew tolerance.
