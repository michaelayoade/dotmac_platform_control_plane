#!/usr/bin/env python3
"""Read-only audit + helpers for issuing a per-app Forgejo read token into a GitHub env secret.

Names, IDs, scopes and timestamps only. Never selects token hashes, salts or last-eight.
Subcommands: pre, post, compare, env, pin, config-shell, revoke-cmd, tokens,
shape-gate (validates then feeds a gh command's stdin), collect (runs ON the registry host).
"""
import argparse
import base64
import os
import datetime
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time

SKEW = 120  # seconds of tolerated Mac<->registry clock difference (verify acceptable)
NAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,100}$')
SECRET_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,99}$')
HOST_RE = re.compile(r'^[A-Za-z0-9_.-]{1,100}$')
PATH_RE = re.compile(r'^[A-Za-z0-9_./-]{1,200}\.ya?ml$')
STAMP_LEN = len('YYYYmmddTHHMMSSZ') + 1  # '-' + UTC stamp
DEFAULT_KNOWN_HOSTS = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else '/nonexistent',
    '..', 'erp-registry-verification-20261029', 'registry_known_hosts'))
TOKEN_SHAPE = re.compile(rb'[0-9a-f]{40}')  # used with fullmatch  # Forgejo access token: 40 hex (verify)
SCOPE = 'read:package'
UNIT_PACKAGES = 9      # Forgejo unit type for packages (matches existing ci-readers audit; verify)
MODE_READ = 1          # access_mode: 0 none, 1 read, 2 write, 3 admin, 4 owner (verify)
KEYS = {
    'app': NAME_RE, 'github_repo': REPO_RE, 'github_environment': NAME_RE,
    'secret_name': SECRET_RE, 'forgejo_user': NAME_RE, 'forgejo_org': NAME_RE,
    'forgejo_team': NAME_RE, 'token_name': NAME_RE, 'registry_ssh_alias': HOST_RE,
    'registry_ssh_expected_hostname': HOST_RE, 'forgejo_container': NAME_RE,
    'ssh_user': NAME_RE, 'consumer_workflow': PATH_RE,
}
OPTIONAL = {'forgejo_container_user': (NAME_RE, 'git'), 'forgejo_cli': (NAME_RE, 'forgejo'),
            'deploy_branch': (NAME_RE, 'main')}
OTHER = {'rotate_by_days', 'revoke_command_template', 'revoke_verified', 'require_restricted',
         'known_hosts_file', 'ssh_identity_file'}


class Refused(Exception):
    pass


def no_core():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def sha(obj):
    return hashlib.sha256(canon(obj).encode()).hexdigest()


def load_config(path):
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raise Refused('config unreadable or not JSON')
    if not isinstance(raw, dict):
        raise Refused('config must be an object')
    allowed = set(KEYS) | set(OPTIONAL) | OTHER
    if set(raw) - allowed:
        raise Refused('unknown config keys: ' + ','.join(sorted(set(raw) - allowed)))
    cfg = {}
    for k, rx in KEYS.items():
        v = raw.get(k)
        if not isinstance(v, str) or not rx.match(v):
            raise Refused('config key missing or malformed: ' + k)
        cfg[k] = v
    for k, (rx, default) in OPTIONAL.items():
        v = raw.get(k, default)
        if not isinstance(v, str) or not rx.match(v):
            raise Refused('config key malformed: ' + k)
        cfg[k] = v
    if len(cfg['token_name']) > 64 - STAMP_LEN:
        raise Refused('token_name too long: token_name-STAMP must fit 64 chars')
    r = raw.get('rotate_by_days')
    if not isinstance(r, int) or isinstance(r, bool) or not 1 <= r <= 365:
        raise Refused('rotate_by_days must be an integer 1..365')
    cfg['rotate_by_days'] = r
    t = raw.get('revoke_command_template')
    if not isinstance(t, str) or not t.strip():
        raise Refused('revoke_command_template required')
    cfg['revoke_command_template'] = t
    for k in ('revoke_verified',):
        if not isinstance(raw.get(k, False), bool):
            raise Refused(k + ' must be boolean')
    cfg['revoke_verified'] = raw.get('revoke_verified', False)
    rr = raw.get('require_restricted', True)
    if not isinstance(rr, bool):
        raise Refused('require_restricted must be boolean')
    cfg['require_restricted'] = rr
    kh = raw.get('known_hosts_file', DEFAULT_KNOWN_HOSTS)
    if not isinstance(kh, str) or not re.match(r'^/[A-Za-z0-9_./-]{1,200}$', kh):
        raise Refused('known_hosts_file must be an absolute simple path')
    cfg['known_hosts_file'] = kh
    identity = raw.get('ssh_identity_file')
    if not isinstance(identity, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,200}', identity):
        raise Refused('ssh_identity_file must be an explicit absolute simple path')
    cfg['ssh_identity_file'] = identity
    for key in ('registry_ssh_expected_hostname', 'ssh_user'):
        if cfg[key].startswith('-') or not KEYS[key].fullmatch(cfg[key]):
            raise Refused('unsafe direct SSH route: ' + key)
    if any('REPLACE-' in str(v) for v in cfg.values()):
        raise Refused('config still contains REPLACE- placeholders')
    return cfg


# ---------------------------------------------------------------- registry host side
def sql(user, org, team):
    for v in (user, org, team):
        if not NAME_RE.match(v):
            raise Refused('bad name')
    u = "'%s'" % user.lower()
    o = "'%s'" % org.lower()
    t = "'%s'" % team.lower()
    # Column names are Forgejo 11-ish schema (verify). No token_hash/token_salt/token_last_eight selected.
    return r'''
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT json_build_object(
  'database', current_database(),
  'server_version_num', current_setting('server_version_num'),
  'transaction_read_only', current_setting('transaction_read_only'),
  'users', COALESCE((SELECT json_agg(json_build_object(
    'id', x.id, 'name', x.name, 'type', x.type, 'is_admin', x.is_admin,
    'is_restricted', x.is_restricted, 'is_active', x.is_active,
    'prohibit_login', x.prohibit_login, 'login_type', x.login_type,
    'login_source', x.login_source, 'must_change_password', x.must_change_password
  ) ORDER BY x.id) FROM "user" x WHERE lower(x.name) = %(u)s), '[]'::json),
  'public_keys', COALESCE((SELECT json_agg(json_build_object('id', k.id, 'name', k.name) ORDER BY k.id)
    FROM public_key k JOIN "user" x ON x.id = k.owner_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'gpg_keys', COALESCE((SELECT json_agg(json_build_object('id', k.id) ORDER BY k.id)
    FROM gpg_key k JOIN "user" x ON x.id = k.owner_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'owned_repos', COALESCE((SELECT json_agg(json_build_object('id', r.id, 'name', r.name) ORDER BY r.id)
    FROM repository r JOIN "user" x ON x.id = r.owner_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'collaborations', COALESCE((SELECT json_agg(json_build_object('repo_id', c.repo_id) ORDER BY c.id)
    FROM collaboration c JOIN "user" x ON x.id = c.user_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'access_rows', COALESCE((SELECT json_agg(json_build_object('repo_id', a.repo_id, 'mode', a.mode) ORDER BY a.id)
    FROM access a JOIN "user" x ON x.id = a.user_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'org_memberships', COALESCE((SELECT json_agg(json_build_object(
    'org_id', ou.org_id, 'org_name', o.name, 'is_owner', to_jsonb(ou)->'is_owner'
  ) ORDER BY ou.org_id) FROM org_user ou JOIN "user" x ON x.id = ou.uid
    JOIN "user" o ON o.id = ou.org_id WHERE lower(x.name) = %(u)s), '[]'::json),
  'team_memberships', COALESCE((SELECT json_agg(json_build_object(
    'team_id', tm.id, 'team_name', tm.name, 'org_id', tm.org_id, 'org_name', og.name,
    'authorization', COALESCE(to_jsonb(tm)->'authorize', to_jsonb(tm)->'access_mode')
  ) ORDER BY tm.id) FROM team_user tu2 JOIN team tm ON tm.id = tu2.team_id
    JOIN "user" og ON og.id = tm.org_id JOIN "user" x ON x.id = tu2.uid
    WHERE lower(x.name) = %(u)s), '[]'::json),
  'teams', COALESCE((SELECT json_agg(json_build_object(
    'team_id', tm.id, 'team_name', tm.name, 'org_id', tm.org_id, 'org_name', og.name,
    'authorization', COALESCE(to_jsonb(tm)->'authorize', to_jsonb(tm)->'access_mode'),
    'includes_all_repositories', to_jsonb(tm)->'includes_all_repositories',
    'can_create_org_repo', to_jsonb(tm)->'can_create_org_repo',
    'team_repo_count', (SELECT count(*) FROM team_repo tr WHERE tr.team_id = tm.id),
    'member_count', (SELECT count(*) FROM team_user t3 WHERE t3.team_id = tm.id),
    'units', COALESCE((SELECT json_agg(json_build_object(
      'type', to_jsonb(tu)->'type', 'access_mode', to_jsonb(tu)->'access_mode'
    ) ORDER BY tu.id) FROM team_unit tu WHERE tu.team_id = tm.id), '[]'::json)
  ) ORDER BY tm.id) FROM team tm JOIN "user" og ON og.id = tm.org_id
    WHERE lower(og.name) = %(o)s AND lower(tm.name) = %(t)s), '[]'::json),
  'tokens', COALESCE((SELECT json_agg(json_build_object(
    'id', a.id, 'uid', a.uid, 'name', a.name, 'scope', a.scope, 'created_unix', a.created_unix
  ) ORDER BY a.id) FROM access_token a JOIN "user" x ON x.id = a.uid
    WHERE lower(x.name) = %(u)s), '[]'::json)
);
ROLLBACK;
''' % {'u': u, 'o': o, 't': t}


def collect_remote(user, org, team):
    """Runs on the registry host: local Unix docker daemon, empty client config, READ ONLY txn."""
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}

    def docker(args, stdin=None):
        with tempfile.TemporaryDirectory(prefix='rri-docker-') as cfgdir:
            r = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', '--config', cfgdir, *args],
                               input=stdin, capture_output=True, text=True, timeout=30, env=env, check=False)
        if r.returncode or len(r.stdout) > 1024 * 1024:
            raise Refused('docker step failed')
        return r.stdout
    ids = docker(['ps', '--filter', 'label=com.docker.compose.service=forgejo-db', '--format', '{{.ID}}']).split()
    if len(ids) != 1 or not re.fullmatch(r'[0-9a-f]{12,64}', ids[0]):
        raise Refused('database container ambiguity')
    out = docker(['exec', '-i', '-u', 'postgres', ids[0], 'env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
                  'PGPASSFILE=/dev/null', 'PGSERVICEFILE=/dev/null', 'psql', '-X', '-qAt', '--no-password',
                  '-h', '/var/run/postgresql', '-p', '5432', '-U', 'forgejo', '-d', 'forgejo',
                  '--set', 'ON_ERROR_STOP=1', '-f', '-'], stdin=sql(user, org, team))
    lines = [ln for ln in out.splitlines() if ln.startswith('{')]
    if len(lines) != 1:
        raise Refused('metadata output shape')
    data = json.loads(lines[0])
    data['database_container_id'] = ids[0]
    return data


# ---------------------------------------------------------------- Mac side transport
def known_hosts_path(cfg):
    p = cfg['known_hosts_file']
    try:
        st = os.lstat(p)
    except OSError:
        raise Refused('reviewed known_hosts file missing')
    import stat as _st
    if (not _st.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022
            or st.st_nlink != 1 or st.st_size == 0):
        raise Refused('known_hosts file must be a non-empty regular file owned by you, not group/other writable')
    return p


def ssh_base(cfg):
    """One explicit direct route for collect and mint; never load ambient SSH config.

    The identity path is configuration, not credential material; this helper never opens it.
    registry_ssh_alias is retained as a label for existing per-app configurations only.
    """
    options = [
        'BatchMode=yes', 'ConnectTimeout=6', 'ConnectionAttempts=1',
        'StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'KnownHostsCommand=none',
        'UserKnownHostsFile=' + known_hosts_path(cfg), 'GlobalKnownHostsFile=/dev/null',
        'HostKeyAlgorithms=ssh-ed25519', 'IdentityFile=' + cfg['ssh_identity_file'],
        'IdentitiesOnly=yes', 'PreferredAuthentications=publickey',
        'ClearAllForwardings=yes', 'ForwardAgent=no', 'ForwardX11=no',
        'ControlMaster=no', 'ControlPath=none', 'ControlPersist=no',
        'PermitLocalCommand=no', 'ProxyCommand=none', 'ProxyJump=none',
        'CanonicalizeHostname=no',
    ]
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-T']
    for option in options:
        argv.extend(['-o', option])
    return argv + ['-l', cfg['ssh_user'], '-p', '22', cfg['registry_ssh_expected_hostname']]


def pin_check(cfg):
    # Static route validation only. Host-key authentication happens on each real connection.
    # No ssh -G: the reviewed direct route is independent of ~/.ssh/config and system config.
    argv = ssh_base(cfg)
    return {'alias': cfg['registry_ssh_alias'], 'hostname': cfg['registry_ssh_expected_hostname'],
            'user': cfg['ssh_user'], 'port': 22, 'route_explicit': True,
            'host_key_verified': False, 'ssh_argv': argv}


def fetch(cfg):
    pin_check(cfg)
    src = open(__file__).read()
    cmd = ssh_base(cfg) + ['/usr/bin/python3', '-I', '-S', '-B', '-', 'collect',
                           cfg['forgejo_user'], cfg['forgejo_org'], cfg['forgejo_team']]
    r = subprocess.run(cmd, input=src, capture_output=True, text=True, timeout=90)
    if r.returncode:
        raise Refused('remote collect failed')
    try:
        data = json.loads(r.stdout)
    except ValueError:
        raise Refused('remote collect output not JSON')
    if not isinstance(data, dict):
        raise Refused('remote collect output shape')
    return data


# ---------------------------------------------------------------- evaluation
def chk(checks, name, ok, detail=None):
    checks.append({'check': name, 'ok': bool(ok), 'detail': detail})


def evaluate(meta, cfg, mode, since=None, name=None, now=None):
    now = int(now if now is not None else time.time())
    c = []
    chk(c, 'db_read_only_transaction', meta.get('transaction_read_only') == 'on' and meta.get('database') == 'forgejo')
    users = meta.get('users', [])
    chk(c, 'user_exists_once', len(users) == 1, {'count': len(users)})
    u = users[0] if len(users) == 1 else {}
    chk(c, 'user_is_individual', u.get('type') == 0, {'type': u.get('type')})
    chk(c, 'user_not_admin', u.get('is_admin') is False, {'is_admin': u.get('is_admin')})
    if cfg['require_restricted']:
        chk(c, 'user_restricted', u.get('is_restricted') is True, {'is_restricted': u.get('is_restricted')})
    chk(c, 'user_active', u.get('is_active') is True, {'is_active': u.get('is_active')})
    chk(c, 'user_prohibit_login_false_and_no_forced_password_change',
        u.get('prohibit_login') is False and u.get('must_change_password') is False,
        {'prohibit_login': u.get('prohibit_login'), 'must_change_password': u.get('must_change_password')})
    chk(c, 'user_no_ssh_gpg_keys', not meta.get('public_keys') and not meta.get('gpg_keys'),
        {'public_key_ids': [k.get('id') for k in meta.get('public_keys', [])],
         'gpg_key_ids': [k.get('id') for k in meta.get('gpg_keys', [])]})
    chk(c, 'user_no_repos_or_collaborations',
        not meta.get('owned_repos') and not meta.get('collaborations') and not meta.get('access_rows'),
        {'owned_repo_ids': [r.get('id') for r in meta.get('owned_repos', [])],
         'collaboration_repo_ids': [r.get('repo_id') for r in meta.get('collaborations', [])],
         'access_row_repo_ids': [r.get('repo_id') for r in meta.get('access_rows', [])]})
    tm = meta.get('team_memberships', [])
    team_l, org_l = cfg['forgejo_team'].lower(), cfg['forgejo_org'].lower()
    chk(c, 'team_membership_exactly_configured_team',
        len(tm) == 1 and str(tm[0].get('team_name', '')).lower() == team_l
        and str(tm[0].get('org_name', '')).lower() == org_l,
        {'teams': [{'id': t.get('team_id'), 'name': t.get('team_name'), 'org': t.get('org_name')} for t in tm]})
    chk(c, 'user_not_in_owners',
        not any(str(t.get('team_name', '')).lower() == 'owners' or (isinstance(t.get('authorization'), int)
                                                                  and t['authorization'] >= 4) for t in tm))
    teams = meta.get('teams', [])
    chk(c, 'team_exists_once', len(teams) == 1, {'count': len(teams)})
    t = teams[0] if len(teams) == 1 else {}
    units = t.get('units', [])
    chk(c, 'team_authorization_read', t.get('authorization') == MODE_READ, {'authorization': t.get('authorization')})
    pk = [x for x in units if x.get('type') == UNIT_PACKAGES]
    other = [x for x in units if x.get('type') != UNIT_PACKAGES]
    # UI-created teams carry a row for every unit type at mode 0 (none); any nonzero mode besides 9:1 refuses.
    chk(c, 'team_units_packages_read_only',
        len(pk) == 1 and pk[0].get('access_mode') == MODE_READ and all(x.get('access_mode') == 0 for x in other),
        {'units': units, 'access_mode_recorded': [x.get('access_mode') for x in units]})
    chk(c, 'team_sole_member', t.get('member_count') == 1, {'member_count': t.get('member_count')})
    chk(c, 'team_no_all_repos_no_create_no_team_repos',
        t.get('includes_all_repositories') is False and t.get('can_create_org_repo') is False
        and t.get('team_repo_count') == 0,
        {k: t.get(k) for k in ('includes_all_repositories', 'can_create_org_repo', 'team_repo_count')})
    toks = meta.get('tokens', [])
    summary = [{'id': k.get('id'), 'name': k.get('name'), 'scope': k.get('scope'),
                'created_unix': k.get('created_unix')} for k in toks]
    if mode == 'pre':
        chk(c, 'pre_zero_tokens', len(toks) == 0, {'count': len(toks), 'tokens': summary})
    else:
        lo = since - SKEW
        hi = now + SKEW
        okname = len(toks) == 1 and (toks[0].get('name') == name if name else
                                     (toks[0].get('name') == cfg['token_name']
                                      or str(toks[0].get('name', '')).startswith(cfg['token_name'] + '-')))
        chk(c, 'post_exactly_one_token', len(toks) == 1, {'count': len(toks), 'tokens': summary})
        chk(c, 'post_token_name', okname)
        chk(c, 'post_scope_exactly_read_package', len(toks) == 1 and toks[0].get('scope') == SCOPE,
            {'scope': toks[0].get('scope') if len(toks) == 1 else None})
        chk(c, 'post_created_in_window', len(toks) == 1 and isinstance(toks[0].get('created_unix'), int)
            and lo <= toks[0]['created_unix'] <= hi, {'window_unix': [lo, hi]})
        chk(c, 'post_token_owned_by_user', len(toks) == 1 and toks[0].get('uid') == u.get('id'))
    return c


def finish(body):
    body['report_sha256'] = None
    body['report_sha256'] = sha(body)  # hashed with the field set to null
    return body


def iso_to_unix(s):
    try:
        return int(datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ')
                   .replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        raise Refused('--since must be UTC like 2026-11-03T12:00:00Z')


def run_audit(cfg, mode, since_s, name, out):
    since = iso_to_unix(since_s) if since_s else None
    meta = fetch(cfg)
    checks = evaluate(meta, cfg, mode, since, name)
    body = {'tool': 'registry-reader-issuance/audit', 'mode': mode, 'app': cfg['app'],
            'config_sha256': sha({k: v for k, v in cfg.items()}), 'since_utc': since_s,
            'token_name_expected': name,
            'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'ok': all(x['ok'] for x in checks), 'checks': checks, 'metadata': meta,
            'secrets_in_report': 'none: no token hash/salt/last-eight selected', 'mutation_performed': False}
    finish(body)
    text = json.dumps(body, indent=2, sort_keys=True)
    if out:
        with open(out, 'w') as f:
            f.write(text + '\n')
    print(text)
    return 0 if body['ok'] else 1


def compare(pre_path, post_path):
    pre, post = (json.load(open(p)) for p in (pre_path, post_path))
    c = []
    for label, r in (('pre', pre), ('post', post)):
        chk(c, label + '_report_hash_intact', r.get('report_sha256') == sha_of_body(r))
        chk(c, label + '_ok', r.get('ok') is True)
    chk(c, 'modes', pre.get('mode') == 'pre' and post.get('mode') == 'post')
    chk(c, 'same_config', pre.get('config_sha256') == post.get('config_sha256'))
    pm, qm = dict(pre.get('metadata', {})), dict(post.get('metadata', {}))
    ptok, qtok = pm.pop('tokens', None), qm.pop('tokens', None)
    diff = sorted(k for k in set(pm) | set(qm) if pm.get(k) != qm.get(k))
    chk(c, 'nothing_else_changed', not diff, {'differing_metadata_keys': diff})
    chk(c, 'tokens_0_to_1', ptok == [] and isinstance(qtok, list) and len(qtok) == 1,
        {'pre': len(ptok or []), 'post': len(qtok or [])})
    chk(c, 'post_not_before_pre', post.get('observed_at_utc', '') >= pre.get('observed_at_utc', 'z'))
    body = {'tool': 'registry-reader-issuance/compare', 'ok': all(x['ok'] for x in c), 'checks': c,
            'pre_sha256': pre.get('report_sha256'), 'post_sha256': post.get('report_sha256')}
    finish(body)
    print(json.dumps(body, indent=2, sort_keys=True))
    return 0 if body['ok'] else 1


def sha_of_body(r):
    d = {k: v for k, v in r.items() if k != 'report_sha256'}
    d['report_sha256'] = None
    return sha(d)


# ---------------------------------------------------------------- GitHub environment (names only)
def gh_get(path):
    r = subprocess.run(['gh', 'api', path], capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise Refused('gh api read failed: ' + path)
    try:
        return json.loads(r.stdout)
    except ValueError:
        raise Refused('gh api output not JSON')


def paged(base, path, key):
    d = gh_get(base + path + '?per_page=100')
    items = d.get(key)
    if not isinstance(items, list) or d.get('total_count') != len(items):
        raise Refused('paginated list incomplete or unexpected: ' + path)
    return d


def env_snapshot(cfg):
    base = 'repos/%s/environments/%s' % (cfg['github_repo'], cfg['github_environment'])
    e = gh_get(base)
    pol = paged(base, '/deployment-branch-policies', 'branch_policies')
    sec = paged(base, '/secrets', 'secrets')
    var = paged(base, '/variables', 'variables')
    return {
        'deployment_branch_policy': e.get('deployment_branch_policy'),
        'can_admins_bypass': e.get('can_admins_bypass'),
        'branch_policies': sorted(({'name': p.get('name'), 'type': p.get('type')}
                                   for p in pol.get('branch_policies', [])), key=canon),
        'secrets': sorted({s['name']: s.get('updated_at') for s in sec.get('secrets', [])}.items()),
        'variables': sorted(v.get('name') for v in var.get('variables', [])),
    }


def parse_ts(s):
    try:
        return int(datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ')
                   .replace(tzinfo=datetime.timezone.utc).timestamp())
    except (ValueError, TypeError):
        return None


def workflow_checks(cfg, c):
    """Read-only: 'main only' holds only if no other workflow at the branch can use the environment."""
    base = 'repos/%s/contents/' % cfg['github_repo']
    ref = '?ref=' + cfg['deploy_branch']
    listing = gh_get(base + '.github/workflows' + ref)
    if not isinstance(listing, list):
        raise Refused('workflow listing unexpected')
    refs, consumer = [], None
    for f in listing:
        path = f.get('path', '')
        if f.get('type') != 'file' or not path.endswith(('.yml', '.yaml')):
            continue
        d = gh_get(base + path + ref)
        if d.get('encoding') != 'base64' or not d.get('content'):
            raise Refused('workflow content unreadable: ' + path)
        text = base64.b64decode(d['content']).decode('utf-8', 'replace')
        if path == cfg['consumer_workflow']:
            consumer = text
        elif cfg['github_environment'] in text:
            refs.append(path)
    chk(c, 'no_other_workflow_references_environment', not refs, {'workflows': refs})
    chk(c, 'consumer_workflow_present', consumer is not None, {'path': cfg['consumer_workflow']})
    chk(c, 'consumer_no_pull_request_target_or_workflow_run',
        consumer is not None and not re.search(r'pull_request_target|workflow_run', consumer))


def env_check(cfg, phase, since_s, pre_path, out):
    snap = env_snapshot(cfg)
    c = []
    workflow_checks(cfg, c)
    chk(c, 'deployment_branch_policy_custom_only',
        snap['deployment_branch_policy'] == {'custom_branch_policies': True, 'protected_branches': False},
        snap['deployment_branch_policy'])
    chk(c, 'branch_policies_exactly_deploy_branch',
        snap['branch_policies'] == [{'name': cfg['deploy_branch'], 'type': 'branch'}], snap['branch_policies'])
    chk(c, 'can_admins_bypass_false', snap['can_admins_bypass'] is False, snap['can_admins_bypass'])
    names = [n for n, _ in snap['secrets']]
    if phase == 'pre':
        chk(c, 'secret_absent', cfg['secret_name'] not in names, {'secret_names': names})
    else:
        since = iso_to_unix(since_s)
        upd = dict(snap['secrets']).get(cfg['secret_name'])
        ts = parse_ts(upd)
        chk(c, 'secret_present', cfg['secret_name'] in names, {'secret_names': names})
        chk(c, 'secret_updated_in_window', ts is not None and since - SKEW <= ts <= int(time.time()) + SKEW,
            {'updated_at': upd})
        if pre_path:
            pre = json.load(open(pre_path))['snapshot']
            same = all(pre[k] == snap[k] for k in ('deployment_branch_policy', 'can_admins_bypass',
                                                   'branch_policies', 'variables'))
            others_pre = sorted(n for n, _ in pre['secrets'])
            others_now = sorted(n for n in names if n != cfg['secret_name'])
            chk(c, 'environment_otherwise_unchanged', same and others_pre == others_now)
    body = {'tool': 'registry-reader-issuance/env', 'phase': phase, 'repo': cfg['github_repo'],
            'environment': cfg['github_environment'], 'ok': all(x['ok'] for x in c), 'checks': c,
            'snapshot': snap, 'names_only': True}
    finish(body)
    text = json.dumps(body, indent=2, sort_keys=True)
    if out:
        with open(out, 'w') as f:
            f.write(text + '\n')
    print(text)
    return 0 if body['ok'] else 1


# ---------------------------------------------------------------- misc commands
def revoke_cmd(cfg, name, tid):
    return (cfg['revoke_command_template'].replace('{user}', cfg['forgejo_user'])
            .replace('{token_name}', name).replace('{token_id}', tid or '<ID: run audit.py tokens>')
            .replace('{container}', cfg['forgejo_container']).replace('{alias}', cfg['registry_ssh_alias']))


def shape_gate(cmd):
    """stdin = mint output. Validate shape, then feed it only to `gh secret set ...` stdin."""
    if len(cmd) < 3 or cmd[:3] != ['gh', 'secret', 'set']:
        raise Refused('shape-gate only wraps: gh secret set ...')
    data = sys.stdin.buffer.read(256)
    if data.endswith(b'\n'):
        data = data[:-1]
    if not TOKEN_SHAPE.fullmatch(data):
        sys.stderr.write('REFUSED: mint output failed the shape check (value not shown)\n')
        return 10
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    p.communicate(data)
    data = b''
    return 0 if p.returncode == 0 else 11


def main(argv):
    no_core()
    ap = argparse.ArgumentParser(prog='audit.py')
    sub = ap.add_subparsers(dest='command', required=True)
    for m in ('pre', 'post'):
        p = sub.add_parser(m)
        p.add_argument('--config', required=True)
        p.add_argument('--out')
        if m == 'post':
            p.add_argument('--since', required=True)
            p.add_argument('--name')
    p = sub.add_parser('compare')
    p.add_argument('pre')
    p.add_argument('post')
    p = sub.add_parser('env')
    p.add_argument('phase', choices=['pre', 'post'])
    p.add_argument('--config', required=True)
    p.add_argument('--since')
    p.add_argument('--pre-file')
    p.add_argument('--out')
    for m in ('pin', 'config-shell', 'tokens', 'ssh-argv'):
        p = sub.add_parser(m)
        p.add_argument('--config', required=True)
    p = sub.add_parser('revoke-cmd')
    p.add_argument('--config', required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--id')
    p = sub.add_parser('shape-gate')
    p.add_argument('gcmd', nargs=argparse.REMAINDER)
    p = sub.add_parser('collect')
    p.add_argument('user')
    p.add_argument('org')
    p.add_argument('team')
    a = ap.parse_args(argv)
    try:
        if a.command == 'collect':
            print(json.dumps(collect_remote(a.user, a.org, a.team)))
            return 0
        if a.command == 'compare':
            return compare(a.pre, a.post)
        if a.command == 'shape-gate':
            return shape_gate(a.gcmd[1:] if a.gcmd[:1] == ['--'] else a.gcmd)
        cfg = load_config(a.config)
        if a.command in ('pre', 'post'):
            if a.command == 'post' and a.name and not NAME_RE.match(a.name):
                raise Refused('bad --name')
            return run_audit(cfg, a.command, getattr(a, 'since', None), getattr(a, 'name', None), a.out)
        if a.command == 'env':
            if a.phase == 'post' and not a.since:
                raise Refused('--since required for post')
            return env_check(cfg, a.phase, a.since, a.pre_file, a.out)
        if a.command == 'pin':
            print(json.dumps(pin_check(cfg)))
            return 0
        if a.command == 'ssh-argv':
            sys.stdout.buffer.write(b'\0'.join(x.encode() for x in ssh_base(cfg)) + b'\0')
            return 0
        if a.command == 'config-shell':
            for k, v in (('APP', cfg['app']), ('REPO', cfg['github_repo']), ('ENVN', cfg['github_environment']),
                         ('SECRET', cfg['secret_name']), ('FUSER', cfg['forgejo_user']),
                         ('TOKEN_BASE', cfg['token_name']), ('ALIAS', cfg['registry_ssh_alias']),
                         ('CONTAINER', cfg['forgejo_container']), ('CUSER', cfg['forgejo_container_user']),
                         ('CLI', cfg['forgejo_cli']), ('REVOKE_VERIFIED', 'yes' if cfg['revoke_verified'] else 'no'),
                         ('KNOWN_HOSTS', known_hosts_path(cfg))):
                print('%s=%s' % (k, v))
            return 0
        if a.command == 'revoke-cmd':
            print(revoke_cmd(cfg, a.name, a.id))
            return 0
        if a.command == 'tokens':
            meta = fetch(cfg)
            print(json.dumps([{'id': k.get('id'), 'name': k.get('name'), 'scope': k.get('scope'),
                               'created_unix': k.get('created_unix')} for k in meta.get('tokens', [])]))
            return 0
    except Refused as e:
        sys.stderr.write('REFUSED: %s\n' % e)
        return 2
    except Exception as e:  # fail closed, type only
        sys.stderr.write('REFUSED: unexpected %s\n' % type(e).__name__)
        return 2
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
