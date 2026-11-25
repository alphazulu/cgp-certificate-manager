"""Explicit, private configuration for the independent network observer."""
import hashlib
import json
import math
import os
from pathlib import Path
import re

from . import storage


CONFIG = Path('/etc/cgp-monitor/config.json')
STATE = Path('/var/lib/cgp-monitor')
MAX_CONFIG = 256 * 1024
MAX_ENDPOINTS = 16
MAX_CHANNELS = 4
ENDPOINT_KEYS = {'id', 'enabled', 'host', 'port', 'server_name', 'protocol', 'ca_file'}


def require(condition, code='invalid_configuration'):
    if not condition:
        raise ValueError(code)


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', value),
            'invalid_identifier')
    return value


def number(value, minimum=0, maximum=1e15, integer=False):
    require(type(value) in ((int,) if integer else (int, float)), 'invalid_number')
    require(minimum <= value <= maximum and math.isfinite(value), 'invalid_number')
    return value


def keys(value, allowed, required=()):
    require(type(value) is dict and set(value) <= set(allowed) and set(required) <= set(value))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def _constant(_value):
    raise ValueError('nonfinite_json')


def _float(value):
    result = float(value)
    require(math.isfinite(result), 'nonfinite_json')
    return result


def decode(data):
    """Strict JSON without duplicate properties, NaN or unbounded integers."""
    return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=_constant, parse_float=_float)


def read_json(path, limit=MAX_CONFIG):
    """Capture one bounded, checked private inode without creating any file."""
    with storage.open_private(path) as stream:
        before = os.fstat(stream.fileno())
        require(before.st_size <= limit, 'input_too_large')
        data = stream.buffer.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= limit, 'input_too_large')
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(all(getattr(before, field) == getattr(after, field) for field in fields),
            'input_changed')
    return decode(data)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def validate(value):
    """Normalize a complete snapshot; prepared secrets must remain in memory."""
    from . import notify_transport, tlsprobe
    keys(value, {'schema', 'enabled', 'endpoints', 'notifications', 'timeout_seconds',
                 'warning_days', 'critical_days', 'max_age_seconds'},
         {'schema', 'enabled', 'endpoints'})
    require(type(value['schema']) is int and value['schema'] == 1)
    require(type(value['enabled']) is bool)
    result = {'schema': 1, 'enabled': value['enabled'], 'endpoints': []}
    for key, default, low, high in (('timeout_seconds', 15, 1, 30),
                                   ('warning_days', 21, 1, 365),
                                   ('critical_days', 7, 0, 364),
                                   ('max_age_seconds', 900, 30, 86400)):
        result[key] = number(value.get(key, default), low, high, integer=True)
    require(result['critical_days'] < result['warning_days'], 'invalid_expiry_thresholds')
    endpoints = value['endpoints']
    require(type(endpoints) is list and len(endpoints) <= MAX_ENDPOINTS)
    names = set()
    for endpoint in endpoints:
        keys(endpoint, ENDPOINT_KEYS, {'id', 'host', 'port', 'server_name'})
        name = identifier(endpoint['id'])
        require(name not in names, 'duplicate_endpoint')
        names.add(name)
        enabled = endpoint.get('enabled', True)
        require(type(enabled) is bool)
        probe = tlsprobe.prepare({key: item for key, item in endpoint.items()
                                  if key not in ('id', 'enabled')})
        result['endpoints'].append({'id': name, 'enabled': enabled, 'probe': probe})
    require(not result['enabled'] or any(e['enabled'] for e in result['endpoints']),
            'no_enabled_endpoints')
    notifications = value.get('notifications', {})
    keys(notifications, {'enabled', 'channels', 'repeat_seconds', 'retry_seconds', 'timeout_seconds'})
    options = {'enabled': notifications.get('enabled', False), 'channels': []}
    require(type(options['enabled']) is bool)
    for key, default, low, high in (('repeat_seconds', 86400, 60, 604800),
                                   ('retry_seconds', 300, 10, 86400),
                                   ('timeout_seconds', 15, 1, 30)):
        options[key] = number(notifications.get(key, default), low, high, integer=True)
    channels = notifications.get('channels', [])
    require(type(channels) is list and len(channels) <= MAX_CHANNELS)
    names = set()
    for channel in channels:
        require(type(channel) is dict)
        name = identifier(channel.get('id'))
        require(name not in names, 'duplicate_channel')
        names.add(name)
        options['channels'].append(notify_transport.prepare(channel))
    require(not options['enabled'] or any(c['enabled'] for c in options['channels']),
            'no_enabled_channels')
    result['notifications'] = options
    # Stored only in private state, never in observations or notification bodies.
    result['identity'] = digest(result)
    return result


def load(path=CONFIG):
    return validate(read_json(path))
