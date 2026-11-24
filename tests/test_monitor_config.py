"""Private monitor configuration snapshots, strict schema and bounded inputs."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cgp_cert_manager import core, monitor_config as config, notify_transport, storage, tlsprobe


def settings(**changes):
    return dict({'schema': 1, 'enabled': False, 'endpoints': []}, **changes)


def endpoint(**changes):
    return dict({'id': 'mail', 'host': '127.0.0.1', 'port': 443,
                 'server_name': 'mail.example.test'}, **changes)


def channel(**changes):
    return dict({'id': 'ops', 'kind': 'webhook',
                 'url': 'https://hooks.example.test/notification'}, **changes)


class MonitorConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.path = self.private / 'config.json'
        self.out, self.err = io.StringIO(), io.StringIO()
        self.enterContext(redirect_stdout(self.out))
        self.enterContext(redirect_stderr(self.err))
        self.forbidden = [self.enterContext(patch.object(module, name,
                          side_effect=AssertionError('Configuration caused a side effect')))
                          for module, name in (
            (socket, 'getaddrinfo'), (socket, 'create_connection'), (socket, 'socket'),
            (tlsprobe, 'observe'), (notify_transport, 'deliver'),
            (storage, 'operation_lock'), (storage, 'ensure_private_directory'),
            (storage, 'atomic_json'), (storage, 'atomic_text'),
        )]
        self.addCleanup(self.assert_passive)

    def assert_passive(self):
        for call in self.forbidden:
            call.assert_not_called()
        self.assertEqual(self.out.getvalue(), '')
        self.assertEqual(self.err.getvalue(), '')

    def write(self, value, path=None):
        path = path or self.path
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode('utf-8'))
        path.chmod(0o600)
        return path

    def invalid(self, value, code=None):
        with self.assertRaises((ValueError, core.Error)) as raised:
            config.validate(value)
        if code is not None:
            self.assertEqual(str(raised.exception), code)
        self.assertNotIn('PRIVATE_CONFIGURATION_VALUE', str(raised.exception))

    def read_during(self, callback):
        actual = storage.open_private

        @contextmanager
        def opened(path):
            with actual(path) as stream:
                yield SimpleNamespace(fileno=stream.fileno,
                                      buffer=SimpleNamespace(read=lambda size: callback(stream, size)))

        return patch.object(storage, 'open_private', opened)

    def test_disabled_defaults_load_without_writing_or_creating_state(self):
        self.write(settings())
        before = self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns
        result = config.load(self.path)
        self.assertFalse(result['enabled'])
        self.assertEqual(result['endpoints'], [])
        self.assertEqual((result['timeout_seconds'], result['warning_days'], result['critical_days'],
                          result['max_age_seconds']), (15, 21, 7, 900))
        self.assertEqual(result['notifications'], {'enabled': False, 'channels': [],
                         'repeat_seconds': 86400, 'retry_seconds': 300, 'timeout_seconds': 15})
        self.assertRegex(result['identity'], r'^[0-9a-f]{64}$')
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_ino, self.path.stat().st_mtime_ns), before)
        self.assertEqual(list(self.private.iterdir()), [self.path])

    def test_enabled_endpoints_are_canonical_and_do_not_change_original_configuration(self):
        raw = settings(enabled=True, endpoints=[endpoint(id='off', enabled=False),
                       endpoint(id='smtp_1', host='MAIL.EXAMPLE.TEST',
                                server_name='MAIL.EXAMPLE.TEST', protocol='smtp_starttls')])
        original = deepcopy(raw)
        result = config.validate(raw)
        self.assertEqual(raw, original)
        self.assertEqual(result['endpoints'][0]['enabled'], False)
        self.assertEqual(result['endpoints'][1], {'id': 'smtp_1', 'enabled': True, 'probe': {
            'host': 'mail.example.test', 'port': 443, 'server_name': 'mail.example.test',
            'protocol': 'smtp_starttls', 'ca_pem': None}})
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_configuration_identity_binds_credentials_and_policy_but_not_source_paths(self):
        first = self.write(b'PRIVATE_CONFIGURATION_VALUE\n', self.private / 'token-one')
        second = self.write(first.read_bytes(), self.private / 'token-two')
        raw = settings(enabled=True, endpoints=[endpoint()], notifications={
            'enabled': True, 'channels': [channel(token_file=str(first))]})
        result = config.validate(raw)
        identity = result['identity']
        self.assertEqual(config.validate(dict(reversed(list(raw.items()))))['identity'], identity)
        raw['notifications']['channels'][0]['token_file'] = str(second)
        self.assertEqual(config.validate(raw)['identity'], identity)
        self.assertNotIn('PRIVATE_CONFIGURATION_VALUE', identity)
        self.assertNotIn(str(first), json.dumps(result))
        self.assertNotIn('token_file', result['notifications']['channels'][0])
        self.write(b'ROTATED_PRIVATE_TOKEN', second)
        self.assertNotEqual(config.validate(raw)['identity'], identity)
        changed = deepcopy(raw)
        changed['warning_days'] = 30
        self.assertNotEqual(config.validate(changed)['identity'], config.validate(raw)['identity'])
        changed = deepcopy(raw)
        changed['endpoints'][0]['server_name'] = 'different.example.test'
        self.assertNotEqual(config.validate(changed)['identity'], config.validate(raw)['identity'])

    def test_strict_json_rejects_duplicates_nonfinite_invalid_encoding_and_huge_integers(self):
        bad = (b'{"schema":1,"schema":1}', b'{"nested":{"value":1,"value":2}}',
               b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
               b'{"value":1e309}', b'{"value":-1e309}', b'{"value":"\xff"}',
               b'{', b'{"value":' + b'9' * 5000 + b'}')
        for data in bad:
            with self.subTest(data=data[:40]):
                self.write(data)
                with self.assertRaises(ValueError):
                    config.read_json(self.path)
        self.assertEqual(config.decode(b'{"fraction":1.25,"values":[0,-2.5e-1]}'),
                         {'fraction': 1.25, 'values': [0, -0.25]})

    def test_root_schema_is_explicit_and_unknown_fields_are_refused(self):
        values = [None, [], 'PRIVATE_CONFIGURATION_VALUE', {}, settings(schema=True),
                  settings(schema=2), settings(schema='1'), settings(enabled=1),
                  settings(enabled=None), settings(extra='PRIVATE_CONFIGURATION_VALUE')]
        values += [{key: value for key, value in settings().items() if key != missing}
                   for missing in ('schema', 'enabled', 'endpoints')]
        for value in values:
            with self.subTest(value=value):
                self.invalid(value)

    def test_endpoint_shapes_duplicates_and_disabled_selection_fail_closed(self):
        for endpoints in (None, {}, (), [None], ['PRIVATE_CONFIGURATION_VALUE'],
                          [endpoint(extra=True)], [endpoint(port=True)], [endpoint(id=True)],
                          [endpoint(), endpoint()], [endpoint(enabled=1)]):
            with self.subTest(endpoints=endpoints):
                self.invalid(settings(endpoints=endpoints))
        for missing in ('id', 'host', 'port', 'server_name'):
            incomplete = endpoint()
            del incomplete[missing]
            self.invalid(settings(endpoints=[incomplete]))
        self.invalid(settings(enabled=True), 'no_enabled_endpoints')
        self.invalid(settings(enabled=True, endpoints=[endpoint(enabled=False)]), 'no_enabled_endpoints')
        self.assertFalse(config.validate(settings(endpoints=[endpoint(enabled=False)]))['endpoints'][0]['enabled'])
        # Disabled targets still have to be valid configurations.
        self.invalid(settings(endpoints=[endpoint(enabled=False, protocol='plaintext')]))

    def test_endpoint_and_channel_cardinality_limits_accept_the_exact_boundaries(self):
        raw = settings(enabled=True, endpoints=[endpoint(id='target_' + str(n)) for n in range(16)],
                       notifications={'enabled': True, 'channels': [channel(id='channel_' + str(n)) for n in range(4)]})
        result = config.validate(raw)
        self.assertEqual(len(result['endpoints']), 16)
        self.assertEqual(len(result['notifications']['channels']), 4)
        over_endpoints = deepcopy(raw)
        over_endpoints['endpoints'].append(endpoint(id='too_many'))
        self.invalid(over_endpoints)
        raw['notifications']['channels'].append(channel(id='too_many'))
        self.invalid(raw)

    def test_notifications_are_explicit_and_disabled_channels_need_no_secret_file(self):
        disabled = {'id': 'off', 'kind': 'smtp', 'enabled': False,
                    'username': 'u', 'password_file': '/missing/private/credential'}
        raw = settings(notifications={'enabled': False, 'channels': [disabled]})
        self.assertEqual(config.validate(raw)['notifications']['channels'],
                         [{'id': 'off', 'kind': 'smtp', 'enabled': False}])
        for notifications in (None, [], {'unexpected': True}, {'enabled': 1}, {'channels': None},
                              {'channels': {}}, {'channels': [None]}, {'channels': [channel(id=None)]},
                              {'channels': [channel(), channel()]}, {'enabled': True},
                              {'enabled': True, 'channels': [disabled]}):
            with self.subTest(notifications=notifications):
                self.invalid(settings(notifications=notifications))
        self.invalid(settings(notifications={'channels': [channel(url='http://PRIVATE_CONFIGURATION_VALUE')]}))

    def test_numeric_limits_use_integers_and_allow_exact_threshold_boundaries(self):
        top = (('timeout_seconds', 1, 30), ('warning_days', 1, 365),
               ('critical_days', 0, 364), ('max_age_seconds', 30, 86400))
        notifications = (('repeat_seconds', 60, 604800), ('retry_seconds', 10, 86400),
                         ('timeout_seconds', 1, 30))
        for nested, limits in ((False, top), (True, notifications)):
            for key, low, high in limits:
                for value in (low, high):
                    raw = settings(warning_days=365, critical_days=0)
                    target = raw.setdefault('notifications', {}) if nested else raw
                    target[key] = value
                    result = config.validate(raw)
                    self.assertEqual((result['notifications'] if nested else result)[key], value)
                for value in (low - 1, high + 1, True, float(low), 'PRIVATE_CONFIGURATION_VALUE', None):
                    with self.subTest(nested=nested, key=key, value=value):
                        raw = settings(warning_days=365, critical_days=0)
                        target = raw.setdefault('notifications', {}) if nested else raw
                        target[key] = value
                        self.invalid(raw, 'invalid_number')
        for critical, warning in ((7, 7), (8, 7)):
            self.invalid(settings(critical_days=critical, warning_days=warning), 'invalid_expiry_thresholds')

    def test_identifiers_and_generic_numbers_exclude_ambiguous_values(self):
        for value in ('a', '0', 'smtp_1-primary', 'a' * 64):
            self.assertEqual(config.identifier(value), value)
        for value in (None, 1, True, '', 'a' * 65, 'A', 'é', 'a.b', '_first', '-first',
                      'a\n', '\ta', 'a b', '../secret'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^invalid_identifier$'):
                config.identifier(value)
        for value in (0, 1.5, 1e15):
            self.assertEqual(config.number(value), value)
        for value in (True, '1', None, -1, 10 ** 400, float('nan'), float('inf'), -float('inf')):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^invalid_number$'):
                config.number(value)

    def test_json_size_is_bounded_before_and_during_read(self):
        self.write(b'{}' + b' ' * (config.MAX_CONFIG - 2))
        self.assertEqual(config.read_json(self.path), {})
        self.write(b'{}' + b' ' * (config.MAX_CONFIG - 1))
        with self.assertRaisesRegex(ValueError, '^input_too_large$'):
            config.read_json(self.path)
        self.write(b'{}')

        def append_before_read(stream, size):
            with self.path.open('ab') as output:
                output.write(b' ' * size)
            return stream.buffer.read(size)

        with self.read_during(append_before_read), self.assertRaisesRegex(ValueError, '^input_too_large$'):
            config.read_json(self.path, limit=64)

    def test_in_place_rewrite_with_restored_mtime_is_detected_from_the_open_inode(self):
        self.write({'value': 'before'})
        before = self.path.stat()

        def change_after_read(stream, size):
            result = stream.buffer.read(size)
            self.path.write_bytes(result.replace(b'before', b'after!'))
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
            return result

        with self.read_during(change_after_read), self.assertRaisesRegex(ValueError, '^input_changed$'):
            config.read_json(self.path)
        self.assertEqual(self.path.stat().st_size, before.st_size)
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_atomic_source_replacement_is_not_mistaken_for_an_unchanged_snapshot(self):
        self.write({'value': 'old'})
        replacement = self.write({'value': 'new'}, self.private / 'replacement.json')

        def replace_after_read(stream, size):
            result = stream.buffer.read(size)
            os.replace(replacement, self.path)
            return result

        with self.read_during(replace_after_read), self.assertRaisesRegex(ValueError, '^input_changed$'):
            config.read_json(self.path)

    def test_missing_unsafe_linked_and_nonregular_sources_are_not_repaired(self):
        with self.assertRaises(FileNotFoundError):
            config.load(self.path)
        self.assertFalse(self.path.exists())
        self.write(settings())
        self.path.chmod(0o644)
        with self.assertRaises(storage.StorageError):
            config.load(self.path)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)
        self.path.chmod(0o600)
        link = self.private / 'alias.json'
        link.symlink_to(self.path)
        with self.assertRaises(storage.StorageError):
            config.load(link)
        self.assertTrue(link.is_symlink())
        link.unlink()
        os.link(self.path, link)
        with self.assertRaises(storage.StorageError):
            config.load(self.path)
        self.assertEqual(link.stat().st_nlink, 2)
        link.unlink()
        fifo = self.private / 'config.fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(storage.StorageError):
            config.load(fifo)

    def test_trusted_nonprivate_configuration_parent_remains_supported(self):
        self.private.chmod(0o755)
        self.write(settings())
        self.assertFalse(config.load(self.path)['enabled'])
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o755)
        alias = self.root / 'linked-parent'
        alias.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(storage.StorageError):
            config.load(alias / self.path.name)
