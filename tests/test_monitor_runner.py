"""Independent observation, storage isolation and saved freshness contracts."""
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, monitor_config, monitor_runner as runner, storage


def configuration(**changes):
    value = {'schema': 1, 'enabled': True, 'endpoints': [
        {'id': 'mail', 'host': '127.0.0.1', 'port': 443, 'server_name': 'example.com'}]}
    value.update(changes)
    return monitor_config.validate(value)


def verified(days=90, checked=1000):
    return {'ok': True, 'value': {'status': 'ok', 'code': None, 'peer_address': '127.0.0.1',
                                'not_after': checked + days * 86400,
                                'fingerprint_sha256': 'a' * 64, 'tls_version': 'TLSv1.3'}, 'code': None}


class MonitorRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'observer'
        self.cfg = configuration()
        self.clock = self.enterContext(patch.object(runner.time, 'time', return_value=1000.0))
        self.worker = self.enterContext(patch.object(runner.monitor_worker, 'execute', return_value=verified()))
        for method in ('cli', 'cf', 'discover', 'issue', 'update'):
            self.enterContext(patch.object(core, method, side_effect=AssertionError('manager boundary used')))
        self.enterContext(patch('socket.getaddrinfo', side_effect=AssertionError('unmocked network')))
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('unmocked network')))

    def saved(self):
        return json.loads((self.directory / runner.STATE_FILE).read_text())

    def store(self, value):
        storage.atomic_json(self.directory / runner.STATE_FILE, value)

    def test_probe_is_independent_read_only_and_reports_a_verified_connection(self):
        before = list(self.root.iterdir())
        with patch.object(storage, 'atomic_json', side_effect=AssertionError('probe wrote state')), \
                patch.object(storage, 'operation_lock', side_effect=AssertionError('probe created lock')):
            result = runner.probe(self.cfg)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['action'], 'probe')
        self.assertTrue(result['observation']['complete'])
        row = result['observation']['endpoints'][0]
        self.assertEqual((row['id'], row['peer_address'], row['days_remaining']), ('mail', '127.0.0.1', 90))
        self.assertTrue(row['verified'])
        self.assertEqual(row['fingerprint_sha256'], 'a' * 64)
        self.assertEqual(result['delivery'], [])
        self.assertEqual(list(self.root.iterdir()), before)
        self.assertEqual(self.worker.call_args.args[0], 'probe')
        self.assertIsNone(self.worker.call_args.args[3])

    def test_disabled_policy_never_creates_state_or_runs_a_worker(self):
        cfg = configuration(enabled=False, endpoints=[])
        for call in (lambda: runner.probe(cfg), lambda: runner.run(cfg, self.directory, True),
                     lambda: runner.status(cfg, self.directory)):
            self.assertEqual(call()['status'], 'disabled')
        self.worker.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_selection_skips_disabled_targets_and_refuses_unknown_or_disabled_ids(self):
        endpoints = [{'id': 'disabled', 'enabled': False, 'host': '127.0.0.1', 'port': 993,
                      'server_name': 'example.com'},
                     {'id': 'enabled', 'host': '127.0.0.1', 'port': 443, 'server_name': 'example.com'}]
        cfg = configuration(endpoints=endpoints)
        self.assertEqual([r['id'] for r in runner.probe(cfg)['observation']['endpoints']], ['enabled'])
        self.worker.reset_mock()
        self.assertEqual(runner.probe(cfg, 'enabled')['status'], 'ok')
        self.assertEqual(self.worker.call_count, 1)
        for selected in ('disabled', 'missing'):
            self.worker.reset_mock()
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                runner.probe(cfg, selected)
            self.worker.assert_not_called()

    def test_expiry_thresholds_use_fractional_days_and_inclusive_boundaries(self):
        for days, expected in ((90, 'ok'), (21.00001, 'ok'), (21, 'warning'),
                               (7.00001, 'warning'), (7, 'critical'), (-.01, 'critical')):
            with self.subTest(days=days):
                self.worker.return_value = verified(days)
                result = runner.probe(self.cfg)
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['observation']['endpoints'][0]['days_remaining'], days)

    def test_tls_failure_preserves_unknown_certificate_and_distinguishes_worker_failure(self):
        failure = {'status': 'error', 'code': 'tls_expired', 'peer_address': '127.0.0.1',
                   'not_after': None, 'fingerprint_sha256': None, 'tls_version': None}
        self.worker.return_value = {'ok': True, 'value': failure, 'code': None}
        result = runner.probe(self.cfg)
        self.assertEqual(result['status'], 'critical')
        self.assertTrue(result['observation']['complete'])
        self.assertIsNone(result['observation']['endpoints'][0]['days_remaining'])
        for code, expected in (('worker_timeout', 'worker_timeout'), ('raw-secret', 'worker_invalid_result'),
                               ([], 'worker_invalid_result')):
            with self.subTest(code=code):
                self.worker.return_value = {'ok': False, 'value': None, 'code': code}
                result = runner.probe(self.cfg)
                self.assertFalse(result['observation']['complete'])
                self.assertEqual(result['observation']['endpoints'][0]['code'], expected)
                self.assertNotIn('raw-secret', json.dumps(result))

    def test_invalid_worker_certificate_data_cannot_become_a_healthy_observation(self):
        cases = [None, {}, {'status': 'unknown'}]
        for key, bad in (('not_after', 'raw-secret'), ('fingerprint_sha256', 'bad'),
                         ('peer_address', 'not-an-address'), ('tls_version', 'SSLv3'),
                         ('code', 'tls_untrusted')):
            value = verified()['value']
            value[key] = bad
            cases.append(value)
        bad = verified()['value']
        bad.update(status='error', code=[])
        cases.append(bad)
        for value in cases:
            with self.subTest(value=value):
                self.worker.return_value = {'ok': True, 'value': value, 'code': None}
                result = runner.probe(self.cfg)
                self.assertEqual(result['status'], 'critical')
                self.assertFalse(result['observation']['complete'])
                self.assertEqual(result['observation']['endpoints'][0]['code'], 'worker_invalid_result')
                self.assertNotIn('raw-secret', json.dumps(result))

    def test_run_serializes_under_its_own_lock_and_saves_only_public_observations(self):
        def observe(kind, endpoint, timeout, descriptor):
            self.assertEqual(kind, 'probe')
            self.assertEqual(os.fstat(descriptor).st_ino, (self.directory / 'run.lock').stat().st_ino)
            with storage.open_private(self.directory / 'run.lock') as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return verified()
        self.worker.side_effect = observe
        result = runner.run(self.cfg, self.directory)
        saved = self.saved()
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(saved['identity'], self.cfg['identity'])
        self.assertEqual(saved['report'], result['observation'])
        self.assertEqual(saved['channels'], {})
        self.assertNotIn('ca_pem', json.dumps(saved))
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory / runner.STATE_FILE).stat().st_mode & 0o777, 0o600)
        before = (self.directory / runner.STATE_FILE).read_bytes()
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'ok')
        self.assertEqual((self.directory / runner.STATE_FILE).read_bytes(), before)

    def test_corrupt_or_unsafe_state_is_not_overwritten_and_prevents_any_network(self):
        runner.run(self.cfg, self.directory)
        file = self.directory / runner.STATE_FILE
        self.worker.reset_mock()
        for raw in (b'{', b'{"schema":1,"schema":1}', b'{"x":1e999}', b'{"x":' + b'1' * 5000 + b'}'):
            with self.subTest(raw=raw[:20]):
                file.write_bytes(raw)
                with self.assertRaises(ValueError):
                    runner.run(self.cfg, self.directory)
                self.assertEqual(file.read_bytes(), raw)
                self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'invalid')
                self.worker.assert_not_called()
        file.chmod(0o644)
        with self.assertRaises(core.Error):
            runner.run(self.cfg, self.directory)
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'invalid')
        self.worker.assert_not_called()

    def test_busy_monitor_does_not_touch_observations_or_manager_state(self):
        runner.run(self.cfg, self.directory)
        before = (self.directory / runner.STATE_FILE).read_bytes()
        self.worker.reset_mock()
        with storage.operation_lock(self.directory):
            with self.assertRaises(BlockingIOError):
                runner.run(self.cfg, self.directory)
            self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'busy')
        self.assertEqual((self.directory / runner.STATE_FILE).read_bytes(), before)
        self.worker.assert_not_called()

    def test_status_missing_never_creates_paths_or_calls_a_worker(self):
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'missing')
        self.assertFalse(self.directory.exists())
        storage.ensure_private_directory(self.directory)
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'missing')
        self.assertEqual(list(self.directory.iterdir()), [])
        with storage.operation_lock(self.directory):
            pass
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'missing')
        self.assertFalse((self.directory / runner.STATE_FILE).exists())
        self.worker.assert_not_called()

    def test_status_fresh_boundary_stale_future_and_configuration_change(self):
        runner.run(self.cfg, self.directory)
        self.worker.reset_mock()
        self.clock.return_value = 1900
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'ok')
        self.clock.return_value = 1900.0001
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'stale')
        self.clock.return_value = 999
        self.assertEqual(runner.status(self.cfg, self.directory)['status'], 'future')
        changed = configuration(warning_days=30)
        self.assertEqual(runner.status(changed, self.directory)['status'], 'configuration_changed')
        self.worker.assert_not_called()

    def test_configuration_change_retains_one_previous_generation_without_old_sends(self):
        runner.run(self.cfg, self.directory)
        original = self.saved()
        changed = configuration(warning_days=30)
        runner.run(changed, self.directory)
        second = self.saved()
        self.assertEqual(second['previous'], {key: value for key, value in original.items() if key != 'previous'})
        self.assertEqual(second['channels'], {})
        third = configuration(warning_days=40)
        runner.run(third, self.directory)
        self.assertEqual(self.saved()['previous']['identity'], changed['identity'])
        self.assertNotIn('previous', self.saved()['previous'])
        self.assertTrue(all(call.args[0] == 'probe' for call in self.worker.call_args_list))

    def test_backwards_clock_refuses_saved_future_and_inflight_time_reversal(self):
        runner.run(self.cfg, self.directory)
        before = (self.directory / runner.STATE_FILE).read_bytes()
        self.worker.reset_mock()
        self.clock.return_value = 999
        with self.assertRaisesRegex(ValueError, 'clock_moved_backwards'):
            runner.run(self.cfg, self.directory)
        self.worker.assert_not_called()
        self.assertEqual((self.directory / runner.STATE_FILE).read_bytes(), before)
        self.clock.side_effect = [1000, 999]
        with self.assertRaisesRegex(ValueError, 'clock_moved_backwards'):
            runner.probe(self.cfg)

    def test_clock_rollback_after_preflight_cannot_replace_the_previous_checkpoint(self):
        runner.run(self.cfg, self.directory)
        path = self.directory / runner.STATE_FILE
        before = (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        self.worker.reset_mock()
        # Preflight passes at 1001, then observation starts after a backward
        # step. Its own 999..1000 timestamps are internally consistent.
        self.clock.side_effect = [1001, 999, 999.5, 1000]
        with patch.object(runner, '_save', wraps=runner._save) as save, \
                patch.object(runner, '_send') as send:
            with self.assertRaisesRegex(ValueError, 'clock_moved_backwards'):
                runner.run(self.cfg, self.directory, send=True)
        self.worker.assert_called_once()
        self.assertEqual(self.worker.call_args.args[0], 'probe')
        save.assert_not_called()
        send.assert_not_called()
        self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), before)

    def test_configured_state_cannot_overlap_manager_certificate_or_application_paths(self):
        for path in (Path('relative'), self.root / '..' / 'escape', core.STATE, core.STATE / 'child',
                     core.STATE.parent, core.CONFIG.parent, core.LIVE.parent,
                     Path(runner.__file__).resolve().parents[1] / 'state'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.run(self.cfg, path)
        self.worker.assert_not_called()

    def test_installed_custom_state_cannot_bypass_installer_lock(self):
        installed = '/opt/cgp-certificate-manager/cgp_cert_manager/monitor_runner.py'
        custom = self.root / 'custom-observer'
        before = list(self.root.iterdir())
        with patch.object(runner, '__file__', installed), \
                patch.object(storage, 'validate_tree') as inspect, \
                patch.object(storage, 'operation_lock') as lock, \
                patch.object(storage, 'atomic_json') as write:
            with self.assertRaisesRegex(ValueError, 'installed_state_override'):
                runner.run(self.cfg, custom, send=True)
        inspect.assert_not_called()
        lock.assert_not_called()
        write.assert_not_called()
        self.worker.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), before)
        self.assertFalse(custom.exists())

    def test_installed_default_and_separate_checkout_custom_state_remain_supported(self):
        installed = '/opt/cgp-certificate-manager/cgp_cert_manager/monitor_runner.py'
        with patch.object(runner, '__file__', installed), \
                patch.object(monitor_config, 'STATE', self.directory):
            result = runner.run(self.cfg, monitor_config.STATE)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.saved()['identity'], self.cfg['identity'])
        custom = self.root / 'checkout-observer'
        checkout = self.root / 'checkout' / 'cgp_cert_manager' / 'monitor_runner.py'
        with patch.object(runner, '__file__', str(checkout)):
            result = runner.run(self.cfg, custom)
        self.assertEqual(result['status'], 'ok')
        self.assertTrue((custom / runner.STATE_FILE).is_file())
        self.assertEqual(self.worker.call_count, 2)
        self.assertTrue(all(call.args[0] == 'probe' for call in self.worker.call_args_list))

    def test_installed_source_symlink_still_requires_default_state(self):
        target = self.root / 'versioned-app'
        target.mkdir()
        alias = self.root / 'installed-app'
        alias.symlink_to(target, target_is_directory=True)
        module = alias / 'cgp_cert_manager' / 'monitor_runner.py'
        custom = self.root / 'custom-observer'
        with patch.object(runner, 'INSTALLED_ROOT', alias), \
                patch.object(runner, '__file__', str(module)), \
                patch.object(storage, 'validate_tree') as inspect, \
                patch.object(storage, 'operation_lock') as lock, \
                patch.object(storage, 'atomic_json') as write:
            with self.assertRaisesRegex(ValueError, 'installed_state_override'):
                runner.run(self.cfg, custom, send=True)
        inspect.assert_not_called()
        lock.assert_not_called()
        write.assert_not_called()
        self.worker.assert_not_called()
        self.assertFalse(custom.exists())
        self.assertTrue(alias.is_symlink())

    def test_observation_write_failure_never_begins_notification_delivery(self):
        with patch.object(storage, 'atomic_json', side_effect=OSError('private-secret')):
            with self.assertRaises(OSError):
                runner.run(self.cfg, self.directory, send=True)
        self.assertTrue(all(call.args[0] == 'probe' for call in self.worker.call_args_list))
        self.assertFalse((self.directory / runner.STATE_FILE).exists())


if __name__ == '__main__':
    unittest.main()
