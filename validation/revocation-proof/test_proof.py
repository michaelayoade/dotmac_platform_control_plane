"""Hosted-runner-only stdlib mocked tests; never contact Docker, HTTP, or SSH.

Source preparation does not authorize a production proof or cleanup ceremony.
"""
import base64
import copy
import hashlib
import io
import stat
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import proof  # noqa: E402

TOKEN = '5e17f0a1' * 5  # Synthetic shape-valid sentinel, never a credential.
PASSWORD = 'synthetic-password-sentinel-only'
ACCESS = ('public_keys', 'gpg_keys', 'owned_repos', 'collaborations', 'access_rows',
          'org_memberships', 'team_memberships', 'teams')


def config():
    return {
        'schema': 'cp_reader_revocation_proof.v1',
        'run': 'cp-revoke-proof-test-20261125', 'host': 'dotmac-s3',
        'forgejo_container_id': 'a' * 64, 'database_container_id': 'b' * 64,
        'forgejo_image_id': 'sha256:' + 'c' * 64,
        'database_image_id': 'sha256:' + 'd' * 64,
        'username': 'cp-revoke-proof-user-20261125', 'user_id': 901,
        'admin_username': 'approved_test_operator',
        'operator_profile_reference': 'synthetic-profile-reference',
        'authorization_reference': 'synthetic-authorization-reference',
        'exclusive_user_mutation_window_reference': 'synthetic-exclusive-window-reference',
        'helper_source_sha256': hashlib.sha256((HERE / 'proof.py').read_bytes()).hexdigest(),
    }


def metadata(cfg, minted=False):
    result = {
        'database': 'forgejo', 'server_version_num': '160000',
        'transaction_read_only': 'on',
        'database_container_id': cfg['database_container_id'][:12],
        'users': [{'id': cfg['user_id'], 'name': cfg['username'], 'type': 0,
                   'is_admin': False, 'is_restricted': True, 'is_active': True,
                   'prohibit_login': False, 'must_change_password': False,
                   'login_type': 0, 'login_source': 0}],
        'tokens': [],
    }
    result.update({key: [] for key in ACCESS})
    if minted:
        result['tokens'] = [{'id': 731, 'uid': cfg['user_id'], 'name': cfg['run'],
                             'scope': 'read:user', 'created_unix': int(time.time())}]
    return result


class ProofTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'receipt'
        self.commands = []
        self.requests = []
        self.durable_stages = []
        self.collect_calls = []
        self.snapshots = [metadata(self.cfg), metadata(self.cfg),
                          metadata(self.cfg, True), metadata(self.cfg)]
        self.http_codes = [200, 204, 401]
        self.mint_error = None
        self.mint_output = (TOKEN + '\n').encode()
        self.http_error_method = None
        self.fsyncs = 0
        self.file_fsync_error_at = None
        self.dump_error_at = None
        self.directory_fail_stage = None
        self.dump_count = 0
        self.file_fsync_count = 0
        self.stderr = io.StringIO()

    def receipt(self):
        return json.loads((self.output / 'receipt.json').read_text())

    def assert_durable_intent(self, stage, flag):
        receipt = self.receipt()
        self.assertTrue(receipt[flag])
        self.assertEqual(receipt['stages'][-1], stage)
        self.assertIn(stage, self.durable_stages)

    def fake_fsync_directory(self, path):
        self.fsyncs += 1
        if Path(path) == self.output and (self.output / 'receipt.json').exists():
            stage = self.receipt()['stages'][-1]
            if stage == self.directory_fail_stage:
                raise OSError(TOKEN + PASSWORD)
            self.durable_stages.append(stage)

    def fake_docker(self, args, *, sensitive=False):
        self.commands.append((list(args), sensitive))
        if args[:3] == ['inspect', '--format', '{{.Id}} {{.Image}}']:
            self.assertEqual(len(args), 4)
            for kind in ('forgejo', 'database'):
                if args[3] == self.cfg[kind + '_container_id']:
                    return (args[3] + ' ' + self.cfg[kind + '_image_id'] + '\n').encode()
            self.fail('unexpected container inspection')
        prefix = ['exec', '-u', 'git', self.cfg['forgejo_container_id'], 'forgejo']
        self.assertEqual(args[:5], prefix)
        if args[5:] == ['--version']:
            self.assertFalse(sensitive)
            return b'Forgejo version 11.0.16\n'
        self.assertEqual(args[5:], ['admin', 'user', 'generate-access-token', '--username',
                                   self.cfg['username'], '--token-name', self.cfg['run'],
                                   '--scopes', 'read:user', '--raw'])
        self.assertTrue(sensitive)
        self.assert_durable_intent('before_single_mint', 'mint_attempted')
        if self.mint_error:
            raise self.mint_error
        return self.mint_output

    def fake_http(self, method, path, header):
        self.requests.append((method, path, header))
        if method == 'DELETE':
            self.assert_durable_intent('before_single_exact_id_delete', 'delete_attempted')
            self.assertEqual(path, '/api/v1/users/' + self.cfg['username'] + '/tokens/731')
            self.assertRegex(path.rsplit('/', 1)[1], r'^[1-9][0-9]*$')
            expected = 'Basic ' + base64.b64encode(
                (self.cfg['admin_username'] + ':' + PASSWORD).encode()).decode()
            self.assertEqual(header, expected)
        else:
            self.assertEqual((method, path, header), ('GET', '/api/v1/user', 'token ' + TOKEN))
        if method == self.http_error_method:
            raise TimeoutError(TOKEN + PASSWORD)
        return self.http_codes[len(self.requests) - 1]

    def fake_collect(self, *args):
        self.collect_calls.append(args)
        self.assertEqual(args, (self.cfg['username'], 'dotmac', 'cp-revoke-proof-unused-20261125'))
        value = self.snapshots[len(self.collect_calls) - 1]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)

    def run_mocked(self):
        # Patching the effect boundaries is mandatory; no real transport may execute.
        original_dump = json.dump

        def dump(*args, **kwargs):
            self.dump_count += 1
            if self.dump_count == self.dump_error_at:
                args[1].write('{partial')
                raise OSError(TOKEN + PASSWORD)
            return original_dump(*args, **kwargs)

        def file_fsync(fd):
            self.file_fsync_count += 1
            if self.file_fsync_count == self.file_fsync_error_at:
                raise OSError(TOKEN + PASSWORD)

        with mock.patch.object(proof, 'docker', side_effect=self.fake_docker), \
             mock.patch.object(proof, 'http_status', side_effect=self.fake_http), \
             mock.patch.object(proof, 'fsync_directory', side_effect=self.fake_fsync_directory), \
             mock.patch.object(proof.os, 'fsync', side_effect=file_fsync) as fsync, \
             mock.patch.object(proof.json, 'dump', side_effect=dump), \
             mock.patch.object(proof.sys, 'stderr', self.stderr), \
             mock.patch.object(proof.getpass, 'getpass', side_effect=AssertionError('no prompt')), \
             mock.patch.object(proof.subprocess, 'run', side_effect=AssertionError('no subprocess')):
            result = proof.run_proof(self.cfg, 'e' * 64, self.output,
                                     {'collect_remote': self.fake_collect}, PASSWORD)
            if self.dump_error_at != 1:
                self.assertGreater(fsync.call_count, 0)
        return result

    def assert_stopped(self, mint_count, methods):
        self.assertEqual(self.run_mocked(), 2)
        receipt = self.receipt()
        self.assertEqual(receipt['status'], 'STOPPED_RETAINED_STATE_NO_RETRY')
        self.assertEqual(sum('generate-access-token' in args for args, _ in self.commands), mint_count)
        self.assertEqual([r[0] for r in self.requests], methods)
        self.assert_no_secret_artifacts()

    def assert_no_secret_artifacts(self):
        for path in self.output.rglob('*'):
            if path.is_file():
                text = path.read_text()
                self.assertNotIn(TOKEN, text)
                self.assertNotIn(PASSWORD, text)
                self.assertNotIn('Basic ', text)
                self.assertNotIn('token ' + TOKEN, text)
                self.assertNotIn(base64.b64encode((self.cfg['admin_username'] + ':' + PASSWORD).encode()).decode(), text)
        self.assertEqual({p.name for p in self.output.iterdir()}, {'receipt.json'})

    def test_complete_proof_exact_delete_and_same_token(self):
        self.assertEqual(self.run_mocked(), 0)
        self.assertEqual([r[0] for r in self.requests], ['GET', 'DELETE', 'GET'])
        self.assertEqual(len(self.collect_calls), 4)
        self.assertEqual(sum('generate-access-token' in args for args, _ in self.commands), 1)
        receipt = self.receipt()
        self.assertEqual(receipt['status'], 'REVOCATION_PROOF_PASSED_DISPOSABLE_USER_RETAINED')
        self.assertEqual(receipt['token_id'], 731)
        self.assertIn('exact_token_absent_metadata_unchanged', receipt['stages'])
        self.assertGreater(self.fsyncs, 4)
        self.assert_no_secret_artifacts()

    def test_delete_timeout_never_retries_or_remints(self):
        self.http_error_method = 'DELETE'
        self.assert_stopped(1, ['GET', 'DELETE'])
        self.assertTrue(self.receipt()['delete_attempted'])
        self.assertEqual(len(self.collect_calls), 3)

    def test_mint_timeout_never_retries(self):
        self.mint_error = TimeoutError(TOKEN + PASSWORD)
        self.assert_stopped(1, [])
        self.assertTrue(self.receipt()['mint_attempted'])
        self.assertFalse(self.receipt()['delete_attempted'])
        self.assertEqual(len(self.collect_calls), 2)

    def test_malformed_mint_stops_before_metadata_or_http(self):
        self.mint_output = b'not-a-token\n'
        self.assert_stopped(1, [])
        self.assertEqual(len(self.collect_calls), 2)

    def test_missing_baseline_metadata_never_mints(self):
        self.snapshots[0].pop('public_keys')
        self.assert_stopped(0, [])

    def test_missing_minted_metadata_never_deletes(self):
        self.snapshots[2].pop('tokens')
        self.assert_stopped(1, [])

    def test_unavailable_minted_metadata_never_deletes(self):
        self.snapshots[2] = TimeoutError(TOKEN + PASSWORD)
        self.assert_stopped(1, [])

    def test_extra_token_never_deletes(self):
        self.snapshots[2]['tokens'].append(dict(self.snapshots[2]['tokens'][0], id=732))
        self.assert_stopped(1, [])

    def test_uid_drift_never_deletes(self):
        self.snapshots[2]['tokens'][0]['uid'] += 1
        self.assert_stopped(1, [])

    def test_scope_drift_never_deletes(self):
        self.snapshots[2]['tokens'][0]['scope'] = 'all'
        self.assert_stopped(1, [])

    def test_pre_delete_get_failure_stops(self):
        self.http_codes[0] = 401
        self.assert_stopped(1, ['GET'])
        self.assertFalse(self.receipt()['delete_attempted'])

    def test_delete_non204_stops_without_post_checks(self):
        self.http_codes[1] = 404
        self.assert_stopped(1, ['GET', 'DELETE'])
        self.assertEqual(len(self.collect_calls), 3)

    def test_token_remains_in_metadata_stops_before_post_get(self):
        self.snapshots[3] = metadata(self.cfg, True)
        self.assert_stopped(1, ['GET', 'DELETE'])

    def test_post_delete_get_must_be401(self):
        self.http_codes[2] = 200
        self.assert_stopped(1, ['GET', 'DELETE', 'GET'])

    def test_fresh_pre_mint_metadata_drift_prevents_actual_mint(self):
        self.snapshots[1]['server_version_num'] = '160001'
        self.assert_stopped(0, [])
        self.assertEqual(self.receipt()['refusal'], 'metadata_drift_before_mint')
        self.assertTrue(self.receipt()['mint_attempted'])
        self.assertEqual(len(self.collect_calls), 2)

    def test_fresh_pre_mint_uid_change_prevents_actual_mint(self):
        self.snapshots[1]['users'][0]['id'] += 1
        self.assert_stopped(0, [])
        self.assertEqual(self.receipt()['refusal'], 'metadata_user_state')

    def assert_receipt_write_failure(self, expected_dump_count):
        self.assertEqual(self.run_mocked(), 2)
        self.assertEqual(self.dump_count, expected_dump_count)
        self.assertEqual(self.stderr.getvalue(),
                         'STOP: receipt_write_failed; retain partial files and reconcile state\n')
        self.assertNotIn(TOKEN, self.stderr.getvalue())
        self.assertNotIn(PASSWORD, self.stderr.getvalue())
        self.assertEqual(sum('generate-access-token' in args for args, _ in self.commands), 0)
        self.assertEqual(self.requests, [])

    def test_initial_receipt_disk_failure_preserves_partial_without_retry(self):
        self.dump_error_at = 1
        self.assert_receipt_write_failure(1)
        self.assertEqual(self.commands, [])
        self.assertEqual((self.output / '.receipt.tmp').read_text(), '{partial')
        self.assertFalse((self.output / 'receipt.json').exists())

    def test_before_mint_file_fsync_failure_retains_last_receipt_and_intent(self):
        self.file_fsync_error_at = 3
        self.assert_receipt_write_failure(3)
        self.assertEqual(self.receipt()['stages'][-1], 'isolated_zero_token_baseline')
        partial = json.loads((self.output / '.receipt.tmp').read_text())
        self.assertTrue(partial['mint_attempted'])
        self.assertEqual(partial['stages'][-1], 'before_single_mint')
        self.assertEqual(len(self.collect_calls), 1)

    def test_before_mint_directory_fsync_failure_never_mints(self):
        self.directory_fail_stage = 'before_single_mint'
        self.assert_receipt_write_failure(3)
        self.assertEqual(self.receipt()['stages'][-1], 'before_single_mint')
        self.assertTrue(self.receipt()['mint_attempted'])
        self.assertNotIn('before_single_mint', self.durable_stages)
        self.assertEqual(len(self.collect_calls), 1)

    def test_stopped_receipt_failure_is_not_recursively_retried(self):
        self.snapshots[0].pop('tokens')
        self.dump_error_at = 2
        self.assert_receipt_write_failure(2)
        self.assertEqual(self.receipt()['stages'], ['attempt_recorded_no_retry'])
        self.assertEqual((self.output / '.receipt.tmp').read_text(), '{partial')

    def test_delete_intent_receipt_failure_prevents_delete_without_retry(self):
        self.file_fsync_error_at = 6
        self.assertEqual(self.run_mocked(), 2)
        self.assertEqual(self.dump_count, 6)
        self.assertEqual([r[0] for r in self.requests], ['GET'])
        self.assertEqual(sum('generate-access-token' in args for args, _ in self.commands), 1)
        self.assertEqual(len(self.collect_calls), 3)
        self.assertEqual(self.receipt()['stages'][-1], 'same_token_get_200')
        partial = json.loads((self.output / '.receipt.tmp').read_text())
        self.assertEqual(partial['stages'][-1], 'before_single_exact_id_delete')
        self.assertTrue(partial['delete_attempted'])
        self.assertEqual(self.stderr.getvalue(),
                         'STOP: receipt_write_failed; retain partial files and reconcile state\n')
        for artifact in self.output.iterdir():
            self.assertNotIn(TOKEN, artifact.read_text())
            self.assertNotIn(PASSWORD, artifact.read_text())

    def test_apply_checks_trusted_ancestors_before_config_read(self):
        with mock.patch.object(proof.resource, 'setrlimit'), \
             mock.patch.object(proof.os, 'umask'), \
             mock.patch.object(proof.os, 'geteuid', return_value=0), \
             mock.patch.object(proof.socket, 'gethostname', return_value='dotmac-s3'), \
             mock.patch.object(proof.sys, 'argv', ['proof.py', '--apply', '--config', '/root/test.json']), \
             mock.patch.object(proof, 'trusted_root_parents',
                               side_effect=proof.Refused('unsafe_root_input_parent')) as trust, \
             mock.patch.object(proof, 'load_config') as load, \
             mock.patch.object(proof, 'run_proof') as run, \
             mock.patch.object(proof.getpass, 'getpass') as prompt:
            with self.assertRaisesRegex(proof.Refused, 'unsafe_root_input_parent'):
                proof.main()
            trust.assert_called_once_with('/root/test.json')
            load.assert_not_called()
            run.assert_not_called()
            prompt.assert_not_called()

    def test_apply_rereads_and_refuses_config_change_before_prompt(self):
        changed = dict(self.cfg, user_id=self.cfg['user_id'] + 1)
        with mock.patch.object(proof.resource, 'setrlimit'), \
             mock.patch.object(proof.os, 'umask'), \
             mock.patch.object(proof.os, 'geteuid', return_value=0), \
             mock.patch.object(proof.socket, 'gethostname', return_value='dotmac-s3'), \
             mock.patch.object(proof.sys, 'argv', ['proof.py', '--apply', '--config', '/root/test.json',
                                                 '--expect-digest', 'e' * 64]), \
             mock.patch.object(proof, 'trusted_root_parents') as trust, \
             mock.patch.object(proof, 'apply_ready'), \
             mock.patch.object(proof, 'load_config',
                               side_effect=[(self.cfg, 'e' * 64), (changed, 'f' * 64)]) as load, \
             mock.patch.object(proof, 'run_proof') as run, \
             mock.patch.object(proof.getpass, 'getpass') as prompt:
            with self.assertRaisesRegex(proof.Refused, 'config_changed'):
                proof.main()
            self.assertEqual(trust.call_count, 2)
            self.assertEqual(load.call_count, 2)
            run.assert_not_called()
            prompt.assert_not_called()

    def test_trusted_root_parents_rejects_unsafe_ancestors(self):
        good = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        proof_path = '/root/private/config.json'
        with mock.patch.object(proof.Path, 'lstat', return_value=good) as lstat:
            proof.trusted_root_parents(proof_path)
            self.assertEqual(lstat.call_count, 3)
        for bad in (mock.Mock(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                    mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
                    mock.Mock(st_mode=stat.S_IFLNK | 0o755, st_uid=0)):
            with self.subTest(mode=bad.st_mode, uid=bad.st_uid):
                with mock.patch.object(proof.Path, 'lstat', return_value=bad):
                    with self.assertRaisesRegex(proof.Refused, 'unsafe_root_input_parent'):
                        proof.trusted_root_parents(proof_path)

    def test_existing_output_prevents_replay_before_effects(self):
        self.output.mkdir()
        marker = self.output / 'receipt.json'
        marker.write_text('retained prior attempt')
        with mock.patch.object(proof, 'docker') as docker, \
             mock.patch.object(proof, 'http_status') as http, \
             mock.patch.object(proof, 'fsync_directory') as fsync:
            with self.assertRaises(FileExistsError):
                proof.run_proof(self.cfg, 'e' * 64, self.output,
                                {'collect_remote': mock.Mock()}, PASSWORD)
            docker.assert_not_called()
            http.assert_not_called()
            fsync.assert_not_called()
        self.assertEqual(marker.read_text(), 'retained prior attempt')

    def test_minted_ids_are_exact_positive_integers(self):
        stamp = int(time.time())
        for token_id in (0, -1, True, '731', 7.31):
            with self.subTest(token_id=token_id):
                meta = metadata(self.cfg, True)
                meta['tokens'][0]['id'] = token_id
                with self.assertRaises(proof.Refused):
                    proof.minted_row(meta, self.cfg, self.cfg['run'], stamp, stamp)

    def test_minted_name_and_creation_window_are_bound(self):
        stamp = int(time.time())
        for key, value in [('name', 'another-run'), ('created_unix', stamp - 121),
                           ('created_unix', stamp + 121), ('created_unix', str(stamp))]:
            with self.subTest(key=key, value=value):
                meta = metadata(self.cfg, True)
                meta['tokens'][0][key] = value
                with self.assertRaises(proof.Refused):
                    proof.minted_row(meta, self.cfg, self.cfg['run'], stamp, stamp)

    def test_metadata_refuses_access_user_and_database_drift(self):
        mutations = [('database', 'other'), ('transaction_read_only', 'off'),
                     ('database_container_id', 'f' * 12), ('users', []), ('tokens', None)]
        mutations.extend((key, [{'id': 1}]) for key in ACCESS)
        for key, value in mutations:
            with self.subTest(key=key):
                meta = metadata(self.cfg)
                meta[key] = value
                with self.assertRaises(proof.Refused):
                    proof.check_metadata(meta, self.cfg, 0)
        for key, value in [('is_admin', True), ('is_active', False), ('is_restricted', False),
                           ('id', 902), ('name', 'wrong'), ('type', False)]:
            with self.subTest(user_field=key):
                meta = metadata(self.cfg)
                meta['users'][0][key] = value
                with self.assertRaises(proof.Refused):
                    proof.check_metadata(meta, self.cfg, 0)

    def test_load_config_exact_shape_and_digest(self):
        path = Path(self.temp.name) / 'config.json'
        raw = json.dumps(self.cfg).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        loaded, sha = proof.load_config(path)
        self.assertEqual(loaded, self.cfg)
        self.assertEqual(sha, hashlib.sha256(raw).hexdigest())
        proof.apply_ready(loaded)

    def test_config_refusals(self):
        path = Path(self.temp.name) / 'config.json'
        cases = [('extra', True), ('schema', 'wrong'), ('host', 'other'),
                 ('run', 'production'), ('username', 'existing-user'),
                 ('forgejo_container_id', 'a' * 12), ('database_container_id', True)]
        for key, value in cases:
            with self.subTest(key=key):
                cfg = dict(self.cfg, **{key: value})
                path.write_text(json.dumps(cfg))
                path.chmod(0o600)
                with self.assertRaises(proof.Refused):
                    proof.load_config(path)
        path.write_text(json.dumps(self.cfg))
        path.chmod(0o666)
        with self.assertRaises(proof.Refused):
            proof.load_config(path)

    def test_apply_refuses_unbound_authority_or_identity(self):
        cases = [('forgejo_container_id', None), ('database_container_id', 'b' * 12),
                 ('forgejo_image_id', 'latest'), ('database_image_id', None),
                 ('helper_source_sha256', '0' * 64), ('user_id', True), ('user_id', 0),
                 ('operator_profile_reference', ''), ('authorization_reference', ' '),
                 ('exclusive_user_mutation_window_reference', ''),
                 ('exclusive_user_mutation_window_reference', None),
                 ('admin_username', self.cfg['username']), ('admin_username', 'bad/name')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                with self.assertRaises(proof.Refused):
                    proof.apply_ready(dict(self.cfg, **{key: value}))


if __name__ == '__main__':
    unittest.main()
