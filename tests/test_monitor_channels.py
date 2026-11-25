"""Four-channel configuration, durable delivery and provider cooldown contracts."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from cgp_cert_manager import (monitor_cli as cli, monitor_config as config,
                             monitor_runner as runner, monitor_state as state,
                             notify_transport, storage)
from test_monitor_state import STAMP, checkpoint, event, record, report


ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = {'outcome': 'accepted', 'code': None}


def envelope(result):
    return {'ok': True, 'code': None, 'value': result}


class MonitorChannelTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.config_path = self.private / 'config.json'
        self.directory = self.root / 'monitor-state'
        self.path = self.directory / runner.STATE_FILE
        self.credentials = {
            'smtp': 'PRIVATE_SMTP_PASSWORD', 'webhook': 'PRIVATE_WEBHOOK_TOKEN',
            'telegram': '123456789:' + 'A' * 35, 'mqtt': 'PRIVATE_MQTT_PASSWORD',
        }
        self.files = {}
        for kind, value in self.credentials.items():
            self.files[kind] = self.write(self.private / (kind + '-secret'), value + '\n')
        self.raw = {
            'schema': 1, 'enabled': True,
            'endpoints': [{'id': 'mail', 'host': 'mail.example.com', 'port': 443,
                           'server_name': 'mail.example.com'}],
            'notifications': {'enabled': True, 'timeout_seconds': 2,
                              'retry_seconds': 10, 'repeat_seconds': 60,
                              'channels': [
                {'id': 'smtp', 'kind': 'smtp', 'host': 'private-relay.example.test',
                 'security': 'tls', 'from': 'private-sender@example.test',
                 'to': ['private-recipient@example.test'], 'username': 'PRIVATE_SMTP_USER',
                 'password_file': str(self.files['smtp'])},
                {'id': 'webhook', 'kind': 'webhook',
                 'url': 'https://private-hook.example.test/private-route',
                 'token_file': str(self.files['webhook'])},
                {'id': 'telegram', 'kind': 'telegram', 'chat_id': '-1001234567890',
                 'token_file': str(self.files['telegram'])},
                {'id': 'mqtt', 'kind': 'mqtt', 'host': 'private-broker.example.test',
                 'topic': 'private/monitor/events', 'username': 'PRIVATE_MQTT_USER',
                 'password_file': str(self.files['mqtt'])},
            ]},
        }
        self.network = [self.enterContext(patch.object(owner, name,
                        side_effect=AssertionError('Cross-channel tests must remain offline')))
                        for owner, name in ((socket, 'getaddrinfo'), (socket, 'create_connection'),
                                            (socket.socket, 'connect'), (socket.socket, 'connect_ex'))]
        self.addCleanup(self.assert_offline)

    def assert_offline(self):
        for call in self.network:
            call.assert_not_called()

    def write(self, path, value):
        path.write_text(value, encoding='utf-8')
        path.chmod(0o600)
        return path

    def load(self, kinds=None):
        raw = deepcopy(self.raw)
        if kinds is not None:
            raw['notifications']['channels'] = [channel for channel in raw['notifications']['channels']
                                                if channel['kind'] in kinds]
        self.write(self.config_path, json.dumps(raw))
        return config.load(self.config_path)

    def start(self, kinds=None):
        cfg = self.load(kinds)
        value = checkpoint()
        value['identity'] = cfg['identity']
        with storage.operation_lock(self.directory):
            runner._save(self.path, value)
        return cfg, value

    def disk(self):
        return state.validate(config.read_json(self.path, state.MAX_STATE))

    def send(self, cfg, value, result=ACCEPTED, now=STAMP + 10, times=None, config_path=None):
        with patch.object(runner, '_time', return_value=now, side_effect=times), \
                patch.object(runner.monitor_worker, 'execute', return_value=envelope(result)) as worker:
            observed = runner._send(cfg, value, self.path, 19, config_path)
        return observed, worker

    def assert_public(self, value):
        encoded = json.dumps(value, sort_keys=True)
        forbidden = [*self.credentials.values(), str(self.private), 'PRIVATE_SMTP_USER',
                     'PRIVATE_MQTT_USER', 'private-relay', 'private-sender', 'private-recipient',
                     'private-hook', 'private-broker', 'private/monitor/events', '-1001234567890',
                     'secrets', 'password_file', 'token_file', 'retry_after_seconds']
        for text in forbidden:
            self.assertNotIn(text, encoded)

    def invoke(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = cli.main(['--config', str(self.config_path), '--state-dir', str(self.directory),
                             *args])
        self.assertEqual(errors.getvalue(), '')
        self.assert_public(output.getvalue())
        return code, output.getvalue()

    def test_example_is_disabled_with_four_channels_and_needs_no_credentials(self):
        raw = json.loads((ROOT / 'examples/monitor.example.json').read_text())
        with patch.object(notify_transport, '_secret', side_effect=AssertionError('Read disabled credential')):
            cfg = config.validate(raw)
        self.assertFalse(cfg['enabled'])
        self.assertFalse(cfg['notifications']['enabled'])
        self.assertEqual([channel['kind'] for channel in cfg['notifications']['channels']],
                         ['smtp', 'webhook', 'telegram', 'mqtt'])
        self.assertTrue(all(channel['enabled'] is False for channel in cfg['notifications']['channels']))
        self.assertFalse(self.directory.exists())

    def test_four_channel_config_is_passive_and_snapshots_credentials_without_paths(self):
        before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                  for path in self.files.values()}
        with patch.object(runner.monitor_worker, 'execute') as worker, \
                patch.object(storage, 'operation_lock') as lock, \
                patch.object(storage, 'atomic_json') as write:
            cfg = self.load()
        worker.assert_not_called()
        lock.assert_not_called()
        write.assert_not_called()
        self.assertEqual([channel['kind'] for channel in cfg['notifications']['channels']],
                         ['smtp', 'webhook', 'telegram', 'mqtt'])
        self.assertEqual(cfg['notifications']['channels'][2]['chat_id'], -1001234567890)
        self.assertEqual(cfg['notifications']['channels'][3]['port'], 8883)
        self.assertEqual(cfg['notifications']['channels'][3]['security'], 'tls')
        self.assertNotIn(str(self.private), json.dumps(cfg))
        self.assertFalse(self.directory.exists())
        for path, expected in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), expected)

    def test_new_credentials_bind_identity_by_content_and_duplicate_channels_fail(self):
        for kind, field in (('telegram', 'token_file'), ('mqtt', 'password_file')):
            with self.subTest(kind=kind):
                original = self.load([kind])
                channel = next(item for item in self.raw['notifications']['channels'] if item['kind'] == kind)
                copy = self.write(self.private / (kind + '-copy'), self.files[kind].read_text())
                channel[field] = str(copy)
                self.assertEqual(self.load([kind])['identity'], original['identity'])
                rotated = ('987654321:' + 'B' * 35) if kind == 'telegram' else 'ROTATED_MQTT_PASSWORD'
                self.write(copy, rotated)
                self.assertNotEqual(self.load([kind])['identity'], original['identity'])
        duplicated = deepcopy(self.raw)
        duplicated['notifications']['channels'][2]['id'] = 'smtp'
        with self.assertRaisesRegex(ValueError, 'duplicate_channel'):
            config.validate(duplicated)
        too_many = deepcopy(self.raw)
        too_many['notifications']['channels'].append({'id': 'fifth', 'kind': 'mqtt', 'enabled': False})
        with self.assertRaises(ValueError):
            config.validate(too_many)

    def test_disabled_new_channels_do_not_read_missing_files_or_enable_notifications(self):
        self.raw['enabled'] = False
        self.raw['notifications'].pop('enabled')
        for channel in self.raw['notifications']['channels']:
            channel['enabled'] = False
        for path in self.files.values():
            path.unlink()
        with patch.object(notify_transport, '_secret', side_effect=AssertionError('Read disabled credential')), \
                patch.object(runner.monitor_worker, 'execute') as worker:
            cfg = self.load()
            self.assertFalse(cfg['notifications']['enabled'])
            code, output = self.invoke('--run', '--send', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['status'], 'disabled')
        worker.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_cli_summary_and_missing_status_do_not_expose_new_channel_routing(self):
        self.load()
        before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                  for path in [self.config_path, *self.files.values()]}
        with patch.object(runner.monitor_worker, 'execute') as worker:
            code, output = self.invoke('--check-config', '--json')
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output), {'schema': 1, 'action': 'check-config', 'status': 'valid',
                             'enabled': True, 'endpoints': 1, 'channels': 4, 'notifications_enabled': True})
            code, output = self.invoke('--check-config')
            self.assertEqual(code, 0)
            self.assertIn('Configured notification channels: 4\n', output)
            code, output = self.invoke('--status', '--json')
            self.assertEqual((code, json.loads(output)['status']), (2, 'missing'))
        worker.assert_not_called()
        self.assertFalse(self.directory.exists())
        for path, expected in before.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), expected)

    def test_private_new_channel_file_failure_is_sanitized_before_any_worker(self):
        for kind in ('telegram', 'mqtt'):
            with self.subTest(kind=kind), patch.object(runner.monitor_worker, 'execute') as worker:
                self.load([kind])
                self.files[kind].chmod(0o644)
                code, output = self.invoke('--check-config', '--json')
                self.assertEqual((code, json.loads(output)['error']), (2, 'configuration_invalid'))
                self.files[kind].chmod(0o600)
                worker.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_lazy_dispatch_uses_the_requested_extension_with_the_same_event_and_budget(self):
        from cgp_cert_manager import notify_mqtt, notify_telegram
        cfg = self.load(['telegram', 'mqtt'])
        notification = event()
        for channel, module in zip(cfg['notifications']['channels'], (notify_telegram, notify_mqtt)):
            with self.subTest(kind=channel['kind']), patch.object(module, 'deliver', return_value=ACCEPTED) as send:
                self.assertEqual(notify_transport.deliver(channel, notification, timeout_seconds=2), ACCEPTED)
            send.assert_called_once()
            self.assertEqual(send.call_args.kwargs, {})
            prepared, forwarded, body, timeout = send.call_args.args
            self.assertIs(prepared, channel)
            self.assertIs(forwarded, notification)
            self.assertEqual(json.loads(body), notification)
            self.assertEqual(timeout, 2)

    def test_retry_hint_is_strict_and_only_valid_for_a_telegram_rate_limit(self):
        cfg = self.load()
        telegram = cfg['notifications']['channels'][2]
        good = {'outcome': 'rejected', 'code': 'telegram_rate_limited'}
        self.assertIn(good['code'], state.DELIVERY_CODES)
        for hint in (None, 1, 2**31 - 1):
            value = dict(good)
            if hint is not None:
                value['retry_after_seconds'] = hint
            with self.subTest(valid=hint), patch.object(runner.monitor_worker, 'execute', return_value=envelope(value)):
                self.assertEqual(runner._deliver(telegram, event(), 2, 19), value)
        invalid = [{**good, 'retry_after_seconds': hint}
                   for hint in (False, True, 0, -1, 2**31, 1.0, '60', None, [], {})]
        invalid += [
            {'outcome': 'accepted', 'code': None, 'retry_after_seconds': 60},
            {'outcome': 'uncertain', 'code': 'telegram_rate_limited', 'retry_after_seconds': 60},
            {'outcome': 'rejected', 'code': 'telegram_rejected', 'retry_after_seconds': 60},
            {**good, 'retry_after_seconds': 60, 'raw_reply': 'PRIVATE_PROVIDER_RESPONSE'},
        ]
        for value in invalid:
            with self.subTest(value=value), patch.object(runner.monitor_worker, 'execute', return_value=envelope(value)):
                self.assertEqual(runner._deliver(telegram, event(), 2, 19),
                                 {'outcome': 'uncertain', 'code': 'worker_invalid_result'})
        for channel in cfg['notifications']['channels'][:2] + cfg['notifications']['channels'][3:]:
            with self.subTest(kind=channel['kind']), patch.object(runner.monitor_worker, 'execute',
                    return_value=envelope({**good, 'retry_after_seconds': 60})):
                self.assertEqual(runner._deliver(channel, event(), 2, 19),
                                 {'outcome': 'uncertain', 'code': 'worker_invalid_result'})

    def test_retry_hint_becomes_only_a_deadline_after_the_attempt_finishes(self):
        for hint in (1, 30, 2**31 - 1):
            with self.subTest(hint=hint):
                cfg, value = self.start(['telegram'])
                outcome = {'outcome': 'rejected', 'code': 'telegram_rate_limited', 'retry_after_seconds': hint}
                result, worker = self.send(cfg, value, outcome, times=[STAMP + 10, STAMP + 12])
                pending = self.disk()['channels']['telegram']['pending']
                self.assertEqual(pending['retry_at'], STAMP + 12 + max(10, hint))
                self.assertEqual(set(pending), {'event', 'key', 'attempts', 'retry_at', 'outcome', 'code'})
                self.assertEqual(set(result[0]), {'id', 'outcome', 'code', 'event_id'})
                self.assertEqual(pending['event'], worker.call_args.args[1]['event'])
                self.assert_public(result)
                self.assert_public(self.disk())

    def test_four_channels_keep_separate_intents_cooldowns_and_success_suppression(self):
        cfg, value = self.start()
        sent = {}

        def attempt(kind, payload, timeout, descriptor):
            channel = payload['channel']['id']
            self.assertEqual((kind, timeout, descriptor), ('notify', 2, 19))
            pending = self.disk()['channels'][channel]['pending']
            self.assertEqual((pending['outcome'], pending['code'], pending['attempts']),
                             ('uncertain', 'not_confirmed', 1))
            self.assertEqual(pending['event'], payload['event'])
            self.assert_public(self.disk())
            sent[channel] = deepcopy(payload['event'])
            return envelope({'outcome': 'rejected', 'code': 'telegram_rate_limited', 'retry_after_seconds': 40}
                            if channel == 'telegram' else
                            {'outcome': 'uncertain', 'code': 'mqtt_submission_uncertain'}
                            if channel == 'mqtt' else ACCEPTED)

        with patch.object(runner, '_time', return_value=STAMP + 10), \
                patch.object(runner.monitor_worker, 'execute', side_effect=attempt):
            first = runner._send(cfg, value, self.path, 19, self.config_path)
        self.assertEqual([row['outcome'] for row in first], ['accepted', 'accepted', 'rejected', 'uncertain'])
        self.assertEqual(len({item['id'] for item in sent.values()}), 4)
        value = self.disk()
        value['report'] = report(stamp=STAMP + 18)
        runner._save(self.path, value)
        second, worker = self.send(cfg, value, now=STAMP + 20)
        self.assertEqual([row['outcome'] for row in second], ['suppressed', 'suppressed', 'deferred', 'accepted'])
        worker.assert_called_once()
        self.assertEqual(worker.call_args.args[1]['channel']['id'], 'mqtt')
        self.assertEqual(worker.call_args.args[1]['event'], sent['mqtt'])
        value = self.disk()
        value['report'] = report(stamp=STAMP + 48)
        runner._save(self.path, value)
        third, worker = self.send(cfg, value, now=STAMP + 50)
        self.assertEqual([row['outcome'] for row in third], ['suppressed', 'suppressed', 'accepted', 'suppressed'])
        worker.assert_called_once()
        self.assertEqual(worker.call_args.args[1]['event'], sent['telegram'])
        self.assertTrue(all(item['pending'] is None for item in self.disk()['channels'].values()))
        self.assert_public([first, second, third, self.disk()])

    def test_telegram_cooldown_defers_changed_condition_and_recovery_until_exact_deadline(self):
        for status in ('warning', 'ok'):
            with self.subTest(status=status):
                cfg, value = self.start(['telegram'])
                self.send(cfg, value, {'outcome': 'rejected', 'code': 'telegram_rate_limited',
                                      'retry_after_seconds': 40})
                old = deepcopy(self.disk()['channels']['telegram']['pending'])
                value['report'] = report(status, stamp=STAMP + 20)
                runner._save(self.path, value)
                result, worker = self.send(cfg, value, now=STAMP + 50 - .01)
                self.assertEqual(result[0]['outcome'], 'deferred')
                worker.assert_not_called()
                self.assertEqual(self.disk()['channels']['telegram']['pending'], old)
                self.assertIsNone(self.disk()['channels']['telegram']['superseded'])
                result, worker = self.send(cfg, value, now=STAMP + 50)
                current = self.disk()['channels']['telegram']
                self.assertEqual(result[0]['outcome'], 'accepted')
                self.assertNotEqual(result[0]['event_id'], old['event']['id'])
                self.assertEqual(current['superseded']['event_id'], old['event']['id'])
                self.assertEqual(current['superseded']['code'], 'telegram_rate_limited')
                self.assertEqual(worker.call_args.args[1]['event']['kind'], 'recovery' if status == 'ok' else 'alert')
                self.assertIs(current['incident'], status != 'ok')
                self.assert_public(current)

    def test_schema_one_keeps_old_records_and_new_codes_without_a_raw_hint(self):
        cfg, value = self.start()
        for channel, code in (('smtp', 'smtp_rejected'), ('webhook', 'webhook_submission_uncertain'),
                              ('telegram', 'telegram_rate_limited'), ('mqtt', 'mqtt_submission_uncertain')):
            item = record(value['report'])
            item['pending']['code'] = code
            item['pending']['outcome'] = 'rejected' if channel in ('smtp', 'telegram') else 'uncertain'
            value['channels'][channel] = item
        runner._save(self.path, value)
        self.assertEqual(self.disk(), value)
        self.assertEqual(self.disk()['schema'], 1)
        value['channels']['telegram']['pending']['retry_after_seconds'] = 60
        with self.assertRaises(ValueError):
            state.validate(value)

    def test_new_channel_routing_rotation_retains_old_pending_without_retargeting(self):
        for kind, field, destination in (('telegram', 'chat_id', '-1001234567891'),
                                          ('mqtt', 'topic', 'private/new-events')):
            with self.subTest(kind=kind):
                cfg, value = self.start([kind])
                code = 'telegram_submission_uncertain' if kind == 'telegram' else 'mqtt_submission_uncertain'
                first, _ = self.send(cfg, value, {'outcome': 'uncertain', 'code': code})
                old = self.disk()
                channel = next(item for item in self.raw['notifications']['channels'] if item['kind'] == kind)
                channel[field] = destination
                changed = self.load([kind])
                with patch.object(runner, '_time', return_value=STAMP + 20):
                    self.assertEqual(runner.status(changed, self.directory)['status'], 'configuration_changed')
                with patch.object(runner, '_time', side_effect=[STAMP + 20, STAMP + 23]), \
                        patch.object(runner, 'observe', return_value=report('ok', stamp=STAMP + 20)), \
                        patch.object(runner.monitor_worker, 'execute') as worker:
                    result = runner.run(changed, self.directory, send=True, config_path=self.config_path)
                worker.assert_not_called()
                saved = self.disk()
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(saved['identity'], changed['identity'])
                self.assertNotEqual(saved['identity'], old['identity'])
                self.assertEqual(saved['previous'], {key: item for key, item in old.items() if key != 'previous'})
                self.assertEqual(saved['previous']['channels'][kind]['pending']['event']['id'], first[0]['event_id'])
                self.assertEqual(saved['channels'][kind], state.channel())
                self.assert_public(saved)
                self.assertNotIn(destination, json.dumps(saved))

    def test_real_config_rotation_between_new_channels_blocks_the_second_attempt(self):
        cfg, value = self.start(['telegram', 'mqtt'])

        def first(*args):
            self.assertEqual(args[1]['channel']['kind'], 'telegram')
            raw = json.loads(self.config_path.read_text())
            raw['notifications']['channels'][1]['topic'] = 'private/rotated-before-second'
            self.write(self.config_path, json.dumps(raw))
            return envelope(ACCEPTED)

        with patch.object(runner, '_time', return_value=STAMP + 10), \
                patch.object(runner.monitor_worker, 'execute', side_effect=first) as worker:
            with self.assertRaisesRegex(runner.MonitorError, 'configuration_changed'):
                runner._send(cfg, value, self.path, 19, self.config_path)
        worker.assert_called_once()
        saved = self.disk()
        self.assertEqual(set(saved['channels']), {'telegram'})
        self.assertIsNone(saved['channels']['telegram']['pending'])
        self.assertIsNotNone(saved['channels']['telegram']['last'])
        self.assert_public(saved)
