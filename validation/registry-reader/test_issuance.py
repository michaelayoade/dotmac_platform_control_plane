"""Hosted-only mocked tests. SSH uses a repinned private fixture with an absolute fake executable.
Never run locally; no network or real host connections are required by these tests.
"""
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import audit  # noqa: E402


def jwrite(obj, path):
    with open(path, 'w') as f:
        json.dump(obj, f)


def jread(path):
    with open(path) as f:
        return json.load(f)


def tread(path):
    with open(path, 'rb') as f:
        return f.read()
SENTINEL = '5e17f0a1' * 5  # 40 hex, passes the shape gate; must never appear anywhere
REPO, ENVN, SECRET = 'acme/widget', 'forgejo-registry-read-main', 'WIDGET_READ_TOKEN'

FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, sys, time
st = os.environ['FAKE_STATE']
a = sys.argv[1:]
open(st + '/argv.log', 'a').write(json.dumps(['ssh'] + a) + '\n')
required = ['BatchMode=yes', 'ConnectTimeout=6', 'ConnectionAttempts=1',
    'StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'KnownHostsCommand=none',
    'UserKnownHostsFile=' + os.environ['FAKE_KNOWN_HOSTS'], 'GlobalKnownHostsFile=/dev/null',
    'HostKeyAlgorithms=ssh-ed25519', 'IdentityFile=' + os.environ['FAKE_IDENTITY'],
    'IdentitiesOnly=yes', 'PreferredAuthentications=publickey', 'ClearAllForwardings=yes',
    'ForwardAgent=no', 'ForwardX11=no', 'ControlMaster=no', 'ControlPath=none',
    'ControlPersist=no', 'PermitLocalCommand=no', 'ProxyCommand=none', 'ProxyJump=none',
    'CanonicalizeHostname=no']
expected = ['-F', '/dev/null', '-T']
for option in required: expected += ['-o', option]
expected += ['-l', os.environ['FAKE_SSH_USER'], '-p', '22', os.environ['FAKE_SSH_HOST']]
if a[:len(expected)] != expected:
    sys.stderr.write('fake transport refused unsafe argv\n'); sys.exit(90)
if os.environ.get('FAKE_TRANSPORT_FAIL'):
    sys.stderr.write('fake transport refused handshake\n'); sys.exit(91)
line = ' '.join(a)
if 'generate-access-token' in line:
    if os.environ.get('FAKE_MINT_FAIL'):
        sys.stderr.write('forgejo: mint failed\n'); sys.exit(1)
    name = a[a.index('--token-name') + 1]
    json.dump({'name': name, 'created': int(time.time())}, open(st + '/minted.json', 'w'))
    if os.environ.get('FAKE_SIGNAL'):
        import signal; os.kill(os.getppid(), signal.SIGTERM); time.sleep(0.5)
    sys.stdout.write(os.environ['FAKE_TOKEN'] + '\n'); sys.exit(0)
if ' collect ' in line + ' ':
    sys.stdin.read()
    db = json.load(open(st + '/db.json'))
    if os.path.exists(st + '/minted.json'):
        m = json.load(open(st + '/minted.json'))
        db['tokens'] = db['tokens'] + [{'id': 77, 'uid': 9, 'name': m['name'], 'scope': os.environ.get('FAKE_SCOPE', 'read:package'), 'created_unix': m['created']}]
        if os.environ.get('FAKE_POST_EXTRA_TOKEN'):
            db['tokens'].append({'id': 78, 'uid': 9, 'name': 'other', 'scope': 'read:package', 'created_unix': m['created']})
        if os.environ.get('FAKE_POST_DRIFT'):
            db['public_keys'] = [{'id': 1, 'name': 'k'}]
    print(json.dumps(db)); sys.exit(0)
sys.exit(3)
'''

FAKE_GH = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, time
st = os.environ['FAKE_STATE']
a = sys.argv[1:]
open(st + '/argv.log', 'a').write(json.dumps(['gh'] + a) + '\n')
env = json.load(open(st + '/env.json'))
if a[:1] == ['api']:
    import base64
    full = a[1]; p = full.split('?')[0]
    cbase = 'repos/acme/widget/contents/'
    if p.startswith(cbase):
        if not full.endswith('?ref=main'): sys.exit(4)
        rel = p[len(cbase):]
        if rel == '.github/workflows':
            out = [{'name': k.split('/')[-1], 'path': k, 'type': 'file'} for k in sorted(env['workflows'])]
        elif rel in env['workflows']:
            out = {'path': rel, 'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(env['workflows'][rel].encode()).decode()}
        else: sys.exit(1)
        print(json.dumps(out)); sys.exit(0)
    if p.endswith('/deployment-branch-policies'): out = {'total_count': len(env['policies']), 'branch_policies': env['policies']}
    elif p.endswith('/secrets'):
        if not full.endswith('?per_page=100'): sys.exit(4)
        out = {'total_count': env.get('secrets_total', len(env['secrets'])), 'secrets': env['secrets']}
    elif p.endswith('/variables'): out = {'total_count': 0, 'variables': []}
    else: out = {'deployment_branch_policy': env['dbp'], 'can_admins_bypass': env['bypass']}
    print(json.dumps(out)); sys.exit(0)
if a[:2] == ['secret', 'set']:
    data = sys.stdin.buffer.read()
    open(st + '/gh_stdin_record.json', 'w').write(json.dumps({'len': len(data), 'sha256': hashlib.sha256(data).hexdigest()}))
    if os.environ.get('FAKE_GH_FAIL'):
        sys.stderr.write('gh: HTTP 500\n'); sys.exit(1)
    env['secrets'].append({'name': a[2], 'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})
    json.dump(env, open(st + '/env.json', 'w')); sys.exit(0)
sys.exit(3)
'''

BASE_DB = {
    'database': 'forgejo', 'server_version_num': '160014', 'transaction_read_only': 'on',
    'users': [{'id': 9, 'name': 'widget-reader', 'type': 0, 'is_admin': False, 'is_restricted': True,
               'is_active': True, 'prohibit_login': False, 'login_type': 0, 'login_source': 0,
               'must_change_password': False}],
    'public_keys': [], 'gpg_keys': [], 'owned_repos': [], 'collaborations': [], 'access_rows': [],
    'org_memberships': [{'org_id': 2, 'org_name': 'acme-org', 'is_owner': None}],
    'team_memberships': [{'team_id': 5, 'team_name': 'widget-readers', 'org_id': 2, 'org_name': 'acme-org',
                          'authorization': 1}],
    'teams': [{'team_id': 5, 'team_name': 'widget-readers', 'org_id': 2, 'org_name': 'acme-org',
               'authorization': 1, 'includes_all_repositories': False, 'can_create_org_repo': False,
               'team_repo_count': 0, 'member_count': 1, 'units': [{'type': 9, 'access_mode': 1}]}],
    'tokens': [], 'database_container_id': 'abcdef012345',
}
BASE_ENV = {'dbp': {'custom_branch_policies': True, 'protected_branches': False}, 'bypass': False,
            'policies': [{'id': 1, 'name': 'main', 'type': 'branch'}], 'secrets': [],
            'workflows': {'.github/workflows/widget-lock.yml': 'on:\n  workflow_dispatch:\njobs:\n  a:\n    environment: forgejo-registry-read-main\n',
                          '.github/workflows/ci.yml': 'on: push\njobs: {}\n'}}
CONFIG = {
    'app': 'widget', 'github_repo': REPO, 'github_environment': ENVN, 'secret_name': SECRET,
    'forgejo_user': 'widget-reader', 'forgejo_org': 'acme-org', 'forgejo_team': 'widget-readers',
    'token_name': 'widget-read', 'rotate_by_days': 90, 'registry_ssh_alias': 'registry-test',
    'registry_ssh_expected_hostname': 'registry.test.invalid', 'forgejo_container': 'forgejo-test',
    'revoke_verified': True, 'ssh_user': 'root', 'ssh_identity_file': '/reviewed/test_identity', 'consumer_workflow': '.github/workflows/widget-lock.yml',
    'revoke_command_template': 'curl -X DELETE -u ADMIN https://registry.test.invalid/api/v1/users/{user}/tokens/{token_name}',
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = self.tmp.name
        self.state, self.bin, self.out = t + '/state', t + '/bin', t + '/receipts'
        os.mkdir(self.state), os.mkdir(self.bin)
        for n, s in (('ssh', FAKE_SSH), ('gh', FAKE_GH)):
            with open(self.bin + '/' + n, 'w') as f:
                f.write(s)
            os.chmod(self.bin + '/' + n, 0o700)
        self.db, self.env = copy.deepcopy(BASE_DB), copy.deepcopy(BASE_ENV)
        self.cfg = copy.deepcopy(CONFIG)
        self.cfg['known_hosts_file'] = t + '/kh'
        with open(t + '/kh', 'w') as f:
            f.write('registry.test.invalid ssh-ed25519 AAAA\n')
        os.chmod(t + '/kh', 0o600)
        self.extra = {}
        # The production binary is fixed; tests alter only a private copied fixture and repin it.
        # No runtime override can redirect production SSH. Never execute the production issuer here.
        import shutil
        self.fixture = t + '/fixture'
        shutil.copytree(HERE, self.fixture, ignore=shutil.ignore_patterns('receipts', '__pycache__'))
        os.chmod(self.fixture, 0o700)
        audit_path = self.fixture + '/audit.py'
        source = tread(audit_path).decode()
        self.assertEqual(source.count("argv = ['/usr/bin/ssh',"), 1)
        with open(audit_path, 'w') as f:
            f.write(source.replace("argv = ['/usr/bin/ssh',", 'argv = [' + repr(self.bin + '/ssh') + ','))
        manifest_path = self.fixture + '/SHA256SUMS'
        names = [line.split('  ', 1)[1] for line in tread(manifest_path).decode().splitlines()]
        manifest = ''.join(hashlib.sha256(tread(self.fixture + '/' + name)).hexdigest() + '  ' + name + '\n'
                           for name in names)
        with open(manifest_path, 'w') as f:
            f.write(manifest)
        issue_path = self.fixture + '/issue.sh'
        issue_source = tread(issue_path).decode()
        with open(issue_path, 'w') as f:
            f.write(re.sub(r'(?m)^EXPECTED_MANIFEST=[0-9a-f]{64}$',
                           'EXPECTED_MANIFEST=' + hashlib.sha256(manifest.encode()).hexdigest(),
                           issue_source))

    def rd(self):
        base = self.out + '/widget'
        runs = os.listdir(base)
        self.assertEqual(len(runs), 1)
        return base + '/' + runs[0]

    def run_issue(self, *args, apply=True, script=None):
        jwrite(self.db, self.state + '/db.json')
        jwrite(self.env, self.state + '/env.json')
        jwrite(self.cfg, self.state + '/cfg.json')
        env = {'PATH': self.bin + ':' + os.environ['PATH'], 'HOME': self.tmp.name, 'FAKE_STATE': self.state,
               'FAKE_TOKEN': SENTINEL, 'REGISTRY_READER_OUT': self.out,
               'FAKE_KNOWN_HOSTS': self.cfg['known_hosts_file'],
               'FAKE_IDENTITY': str(self.cfg.get('ssh_identity_file') or ''),
               'FAKE_SSH_USER': self.cfg['ssh_user'],
               'FAKE_SSH_HOST': self.cfg['registry_ssh_expected_hostname'], **self.extra}
        argv = ['bash', (script or self.fixture) + '/issue.sh', self.state + '/cfg.json'] + (['--apply'] if apply else [])
        r = subprocess.run(argv + list(args), capture_output=True, text=True, env=env, timeout=120)
        return r

    def assert_no_sentinel(self, r):
        self.assertNotIn(SENTINEL, r.stdout)
        self.assertNotIn(SENTINEL, r.stderr)
        for root, _, files in os.walk(self.tmp.name):
            for fn in files:
                p = os.path.join(root, fn)
                if p.startswith(self.bin):
                    continue  # fake executables read the sentinel from env only; they contain no value
                self.assertNotIn(SENTINEL.encode(), tread(p), p)

    def argv_log(self):
        return tread(self.state + '/argv.log').decode() if os.path.exists(self.state + '/argv.log') else ''

    def minted(self):
        return os.path.exists(self.state + '/minted.json')


class HappyPath(Base):
    def test_happy_and_no_leak(self):
        r = self.run_issue()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK: widget-read-', r.stdout)
        rec = jread(self.state + '/gh_stdin_record.json')
        self.assertEqual(rec, {'len': 40, 'sha256': hashlib.sha256(SENTINEL.encode()).hexdigest()})
        self.assertNotIn(SENTINEL, self.argv_log())
        self.assertIn('--scopes read:package', self.argv_log().replace('", "', ' '))
        self.assertIn('--raw', self.argv_log())
        for f in ('pre.json', 'post.json', 'compare.json', 'env-pre.json', 'env-post.json'):
            self.assertTrue(os.path.exists(self.rd() + '/' + f), f)
            self.assertEqual(stat.S_IMODE(os.stat(self.rd() + '/' + f).st_mode), 0o600)
        post = jread(self.rd() + '/post.json')
        self.assertTrue(post['ok'])
        self.assertEqual(len(post['report_sha256']), 64)
        self.assert_no_sentinel(r)

    def test_dry_run_mints_nothing(self):
        r = self.run_issue(apply=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('DRY-RUN OK', r.stdout)
        self.assertFalse(self.minted())
        self.assertNotIn('generate-access-token', self.argv_log())

    def test_revoke_not_verified_refuses_apply(self):
        self.cfg['revoke_verified'] = False
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.minted())


class PreAuditRefusals(Base):
    def refused(self, why):
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertFalse(self.minted(), why)
        self.assertNotIn('generate-access-token', self.argv_log(), why)
        self.assertNotIn('secret', ' '.join(json.loads(x)[1] for x in self.argv_log().splitlines() if x.startswith('["gh"')) .replace('api', ''))
        return r

    def test_tokens_already_present(self):
        self.db['tokens'] = [{'id': 1, 'uid': 9, 'name': 'old', 'scope': 'read:package', 'created_unix': 1}]
        self.refused('tokens')
        self.assertIn('pre_zero_tokens', tread(self.rd() + '/pre.json').decode())

    def test_wrong_team_permission(self):
        self.db['teams'][0]['units'] = [{'type': 9, 'access_mode': 2}]
        self.refused('write')

    def test_extra_unit(self):
        self.db['teams'][0]['units'].append({'type': 1, 'access_mode': 1})
        self.refused('extra unit')

    def test_user_is_admin(self):
        self.db['users'][0]['is_admin'] = True
        self.refused('admin')

    def test_user_not_restricted(self):
        self.db['users'][0]['is_restricted'] = False
        self.refused('restricted')

    def test_user_in_owners(self):
        self.db['team_memberships'].append({'team_id': 1, 'team_name': 'Owners', 'org_id': 2,
                                            'org_name': 'acme-org', 'authorization': 4})
        self.refused('owners')

    def test_user_missing(self):
        self.db['users'] = []
        self.refused('missing')


class EnvRefusals(Base):
    def test_policy_drift(self):
        self.env['dbp'] = {'custom_branch_policies': False, 'protected_branches': True}
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.minted())

    def test_extra_branch_policy(self):
        self.env['policies'].append({'id': 2, 'name': 'dev', 'type': 'branch'})
        self.assertNotEqual(self.run_issue().returncode, 0)
        self.assertFalse(self.minted())

    def test_admin_bypass(self):
        self.env['bypass'] = True
        self.assertNotEqual(self.run_issue().returncode, 0)
        self.assertFalse(self.minted())

    def test_secret_already_exists(self):
        self.env['secrets'] = [{'name': SECRET, 'created_at': '2026-01-01T00:00:00Z', 'updated_at': '2026-01-01T00:00:00Z'}]
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.minted())
        self.assertIn('secret_absent', tread(self.rd() + '/env-pre.json').decode())


class PostMintFailures(Base):
    def check_revoke(self, r):
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('FAILED after the mint step', r.stderr)
        self.assertRegex(r.stderr, r'/tokens/widget-read-\d{8}T\d{6}Z')
        self.assertIn('gh secret delete ' + SECRET, r.stderr)
        self.assert_no_sentinel(r)

    def test_mint_failure(self):
        self.extra['FAKE_MINT_FAIL'] = '1'
        r = self.run_issue()
        self.check_revoke(r)
        self.assertNotIn('"secret", "set"', self.argv_log().replace('", "', '", "'))
        self.assertFalse(os.path.exists(self.state + '/gh_stdin_record.json'))

    def test_gh_failure_after_mint(self):
        self.extra['FAKE_GH_FAIL'] = '1'
        r = self.run_issue()
        self.check_revoke(r)
        self.assertTrue(self.minted())

    def test_post_audit_extra_token(self):
        self.extra['FAKE_POST_EXTRA_TOKEN'] = '1'
        self.check_revoke(self.run_issue())

    def test_post_audit_wrong_scope(self):
        self.extra['FAKE_SCOPE'] = 'read:package,read:user'
        self.check_revoke(self.run_issue())

    def test_post_audit_other_row_drift(self):
        self.extra['FAKE_POST_DRIFT'] = '1'
        r = self.run_issue()
        self.check_revoke(r)

    def test_bad_shape_never_reaches_gh(self):
        self.extra['FAKE_TOKEN'] = 'not-a-token'
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.state + '/gh_stdin_record.json'))
        self.assertNotIn('not-a-token', r.stdout + r.stderr)


class Fixups(Base):
    def refused_nomint(self, r=None):
        r = r or self.run_issue()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertFalse(self.minted())
        return r

    def test_c1_ui_created_team_all_units_mode_zero_accepted(self):
        self.db['teams'][0]['units'] = [{'type': i, 'access_mode': 1 if i == 9 else 0} for i in range(1, 10)]
        r = self.run_issue(apply=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_c1_other_unit_nonzero_refused(self):
        self.db['teams'][0]['units'] = [{'type': i, 'access_mode': 1 if i in (9, 3) else 0} for i in range(1, 10)]
        self.refused_nomint()

    def test_c1_packages_missing_or_unknown_mode_refused(self):
        self.db['teams'][0]['units'] = [{'type': 3, 'access_mode': 0}]
        self.refused_nomint()
        self.db['teams'][0]['units'] = [{'type': 9, 'access_mode': 1}, {'type': 3, 'access_mode': None}]
        self.refused_nomint()

    def test_user_prohibit_login_must_change_member_count(self):
        for mut in (lambda: self.db['users'][0].update(prohibit_login=True),
                    lambda: self.db['users'][0].update(must_change_password=True),
                    lambda: self.db['teams'][0].update(member_count=2)):
            self.setUp()
            mut()
            self.refused_nomint()

    def test_receipts_under_app_and_stamp(self):
        r = self.run_issue()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(self.rd(), r'/receipts/widget/\d{8}T\d{6}Z$')

    def test_ssh_hardening_options_and_docker_host(self):
        r = self.run_issue()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [json.loads(x) for x in self.argv_log().splitlines()]
        sshs = [x for x in lines if x[0] == 'ssh' and x[1] != '-G']
        self.assertEqual(len(sshs), 3)  # pre-collect, mint, post-collect
        for a in sshs:
            j = ' '.join(a)
            self.assertIn('UserKnownHostsFile=' + self.cfg['known_hosts_file'], j)
            self.assertIn('GlobalKnownHostsFile=/dev/null', j)
            self.assertIn('StrictHostKeyChecking=yes', j)
        mint = [a for a in sshs if 'generate-access-token' in ' '.join(a)][0]
        self.assertIn('--host unix:///var/run/docker.sock exec', ' '.join(mint))
        destination = mint.index(self.cfg['registry_ssh_expected_hostname'])
        self.assertEqual(mint[destination + 1:destination + 3], ['docker', '--host'])
        self.assertNotIn('-n', mint[destination + 1:])

    def test_ssh_user_pin_and_known_hosts_mandatory(self):
        os.remove(self.cfg['known_hosts_file'])
        self.refused_nomint()
        self.setUp()
        os.chmod(self.cfg['known_hosts_file'], 0o666)
        self.refused_nomint()

    def test_transport_refusal_stops_before_mint_and_secret(self):
        self.extra['FAKE_TRANSPORT_FAIL'] = '1'
        self.refused_nomint()
        self.assertFalse(os.path.exists(self.state + '/gh_stdin_record.json'))
        self.assertEqual(len(self.argv_log().splitlines()), 1)

    def test_configured_direct_user_host_and_identity_are_usable(self):
        self.cfg.update(ssh_user='operator', registry_ssh_expected_hostname='other.test.invalid',
                        ssh_identity_file='/reviewed/other_identity')
        r = self.run_issue()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('registry-test', self.argv_log())  # label cannot choose route

    def test_ambient_config_cannot_change_route(self):
        os.mkdir(self.tmp.name + '/.ssh')
        with open(self.tmp.name + '/.ssh/config', 'w') as f:
            f.write('Host *\n HostName attacker.invalid\n ProxyCommand /bad/proxy\n'
                    ' ControlMaster auto\n ControlPath /bad/socket\n ForwardAgent yes\n')
        r = self.run_issue()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('attacker.invalid', self.argv_log())
        self.assertNotIn('"-G"', self.argv_log())

    def test_missing_identity_and_option_route_refused(self):
        for key, value in (('ssh_identity_file', None), ('ssh_identity_file', 'relative/key'),
                           ('ssh_identity_file', '/key\nInjected=yes'),
                           ('ssh_user', '-root'), ('registry_ssh_expected_hostname', '-bad')):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.cfg[key] = value
                self.refused_nomint()
                self.assertEqual(self.argv_log(), '')

    def test_token_name_too_long_refused_in_config(self):
        cfg = dict(CONFIG, token_name='a' * 48)
        with tempfile.TemporaryDirectory() as d:
            jwrite(cfg, d + '/c.json')
            with self.assertRaises(audit.Refused):
                audit.load_config(d + '/c.json')
            jwrite(dict(CONFIG, token_name='a' * 47), d + '/c.json')
            audit.load_config(d + '/c.json')

    def test_secret_list_pagination_mismatch_refused(self):
        self.env['secrets_total'] = 150
        self.refused_nomint()

    def test_shape_gate_rejects_41_byte_double_newline(self):
        jwrite(self.env, self.state + '/env.json')
        env = {'PATH': self.bin + ':' + os.environ['PATH'], 'FAKE_STATE': self.state}
        for payload, rc in ((SENTINEL + '\n\n', 10), (SENTINEL + '\n', 0), (SENTINEL + 'a', 10), ('', 10)):
            if os.path.exists(self.state + '/gh_stdin_record.json'):
                os.remove(self.state + '/gh_stdin_record.json')
            r = subprocess.run([sys.executable, '-I', '-S', HERE + '/audit.py', 'shape-gate', '--', 'gh', 'secret', 'set', 'X', '--env', 'E', '--repo', 'a/b'],
                               input=payload, capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, rc, repr(payload))
            if rc == 10:
                self.assertFalse(os.path.exists(self.state + '/gh_stdin_record.json'))
            self.assertNotIn(SENTINEL, r.stdout + r.stderr)

    def test_signal_after_mint_prints_revoke(self):
        self.extra['FAKE_SIGNAL'] = '1'
        r = self.run_issue()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('interrupted by signal', r.stderr)
        self.assertRegex(r.stderr, r'/tokens/widget-read-\d{8}T\d{6}Z')
        self.assert_no_sentinel(r)

    def test_other_workflow_referencing_environment_refused(self):
        self.env['workflows']['.github/workflows/ci.yml'] = 'jobs:\n  x:\n    environment: forgejo-registry-read-main\n'
        self.refused_nomint()

    def test_consumer_with_risky_trigger_refused(self):
        for trig in ('pull_request_target', 'workflow_run'):
            self.setUp()
            self.env['workflows']['.github/workflows/widget-lock.yml'] += 'on:\n  %s:\n' % trig
            self.refused_nomint()

    def test_consumer_missing_refused(self):
        del self.env['workflows']['.github/workflows/widget-lock.yml']
        self.refused_nomint()


class SourcePin(Base):
    def copy_tree(self):
        import shutil
        d = self.tmp.name + '/copy'
        shutil.copytree(self.fixture, d, ignore=shutil.ignore_patterns('receipts', '__pycache__'))
        os.chmod(d, 0o700)
        return d

    def test_pristine_copy_runs(self):
        d = self.copy_tree()
        self.assertEqual(self.run_issue(apply=False, script=d).returncode, 0)

    def test_tampered_source_refused_before_anything(self):
        d = self.copy_tree()
        with open(d + '/audit.py', 'a') as f:
            f.write('\n# tampered\n')
        r = self.run_issue(script=d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('differ from reviewed manifest', r.stderr)
        self.assertEqual(self.argv_log(), '')

    def test_manifest_pin_mismatch_refused(self):
        d = self.copy_tree()
        with open(d + '/SHA256SUMS') as f:
            first = f.read().splitlines()[0]
        with open(d + '/SHA256SUMS', 'a') as f:
            f.write(first + '\n')  # still parses and verifies, but the pinned digest differs
        r = self.run_issue(script=d)
        self.assertIn('pin mismatch', r.stderr)
        self.assertEqual(self.argv_log(), '')

    def test_symlink_wrong_mode_and_extra_entry_refused(self):
        d = self.copy_tree()
        os.chmod(d + '/README.md', 0o644)
        self.assertEqual(self.run_issue(script=d).returncode, 1)
        os.chmod(d + '/README.md', 0o600)
        os.rename(d + '/README.md', d + '/README.real')
        os.symlink(d + '/README.real', d + '/README.md')
        self.assertEqual(self.run_issue(script=d).returncode, 1)
        os.remove(d + '/README.md'); os.rename(d + '/README.real', d + '/README.md')
        with open(d + '/extra.py', 'w') as f:
            f.write('x')
        r = self.run_issue(script=d)
        self.assertIn('unsafe source directory', r.stderr)
        self.assertEqual(self.argv_log(), '')


class Units(unittest.TestCase):
    def test_example_config_refuses_until_filled(self):
        with self.assertRaises(audit.Refused):
            audit.load_config(HERE + '/example-erp.config.json')
        ex = jread(HERE + '/example-erp.config.json')
        self.assertEqual((ex['github_repo'], ex['github_environment'], ex['secret_name'], ex['forgejo_user'],
                          ex['forgejo_org'], ex['forgejo_team'], ex['rotate_by_days']),
                         ('michaelayoade/dotmac_erp', 'forgejo-registry-read-main', 'FORGEJO_BUNDLE_READ_TOKEN',
                          'erp-bundle-reader', 'dotmac', 'erp-bundle-readers', 90))

    def test_pin_is_static_and_does_not_claim_handshake(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            cfg = audit.load_config(self._cfg(d))
            cfg['known_hosts_file'] = d + '/kh'
            with open(cfg['known_hosts_file'], 'w') as f:
                f.write('registry.test.invalid ssh-ed25519 AAAA\n')
            with patch.object(audit.subprocess, 'run', side_effect=AssertionError('no subprocess')):
                pin = audit.pin_check(cfg)
            self.assertTrue(pin['route_explicit'])
            self.assertFalse(pin['host_key_verified'])
            self.assertEqual(pin['ssh_argv'][0:4], ['/usr/bin/ssh', '-F', '/dev/null', '-T'])
            self.assertEqual(pin['ssh_argv'][-5:], ['-l', 'root', '-p', '22', 'registry.test.invalid'])

    def test_sql_selects_no_credential_columns_and_is_read_only(self):
        q = audit.sql('u', 'o', 't')
        for bad in ('token_hash', 'token_salt', 'token_last_eight', 'UPDATE ', 'INSERT ', 'DELETE '):
            self.assertNotIn(bad, q)
        self.assertIn('READ ONLY', q)
        with self.assertRaises(audit.Refused):
            audit.sql("x'; drop", 'o', 't')

    def test_compare_detects_change(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = audit.load_config(self._cfg(d))
            pre = self._report(audit, cfg, 'pre', [])
            post_meta_tokens = [{'id': 1, 'uid': 9, 'name': 'widget-read-x', 'scope': 'read:package', 'created_unix': int(time.time())}]
            post = self._report(audit, cfg, 'post', post_meta_tokens, since=int(time.time()) - 5)
            jwrite(pre, d + '/pre.json'); jwrite(post, d + '/post.json')
            self.assertEqual(audit.compare(d + '/pre.json', d + '/post.json'), 0)
            post['metadata']['team_memberships'] = []
            post = audit.finish(post)
            jwrite(post, d + '/post.json')
            self.assertEqual(audit.compare(d + '/pre.json', d + '/post.json'), 1)
            post['ok'] = True  # tampering with the body without rehash
            jwrite(post, d + '/post.json')
            self.assertEqual(audit.compare(d + '/pre.json', d + '/post.json'), 1)

    def _cfg(self, d):
        jwrite(CONFIG, d + '/c.json')
        return d + '/c.json'

    def _report(self, audit, cfg, mode, tokens, since=None):
        meta = copy.deepcopy(BASE_DB)
        meta['tokens'] = tokens
        checks = audit.evaluate(meta, cfg, mode, since)
        return audit.finish({'mode': mode, 'config_sha256': audit.sha(cfg), 'ok': all(c['ok'] for c in checks),
                             'checks': checks, 'metadata': meta,
                             'observed_at_utc': '2026-11-03T12:00:0%dZ' % (1 if mode == 'post' else 0)})


if __name__ == '__main__':
    unittest.main(verbosity=2)
