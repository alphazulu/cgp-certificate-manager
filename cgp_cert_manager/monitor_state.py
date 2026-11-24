"""Validated public observations and private notification checkpoints."""
import ipaddress
import re

from . import monitor_config as config, notify_transport, tlsprobe


MAX_STATE = 2 * 1024 * 1024
WORKER_CODES = frozenset({'worker_timeout', 'worker_failed', 'worker_start_failed',
                          'worker_invalid_result'})
PROBE_CODES = frozenset({'invalid_endpoint', 'ca_unavailable', 'dns_failed', 'connect_failed',
                         'timeout', 'protocol_error', 'starttls_unavailable', 'starttls_rejected',
                         'tls_expired', 'tls_not_yet_valid', 'tls_hostname_mismatch', 'tls_untrusted',
                         'tls_verification_failed', 'tls_handshake_failed', 'certificate_unreadable'}) | WORKER_CODES
DELIVERY_CODES = notify_transport.CODES | WORKER_CODES | {'not_confirmed'}
LEVELS = ('ok', 'warning', 'critical')
ROW_KEYS = {'id', 'host', 'port', 'server_name', 'protocol', 'status', 'code', 'verified',
            'checked_at', 'not_after', 'fingerprint_sha256', 'peer_address', 'tls_version',
            'days_remaining'}


def exact(value, fields):
    config.keys(value, fields, fields)


def hex_value(value, length):
    config.require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value))


def level(days, warning, critical):
    return 'critical' if days <= critical else ('warning' if days <= warning else 'ok')


def overall(rows):
    return max((row['status'] for row in rows), key=LEVELS.index)


def rows(value, warning, critical):
    config.require(type(value) is list and 1 <= len(value) <= config.MAX_ENDPOINTS)
    identifiers = set()
    for row in value:
        exact(row, ROW_KEYS)
        name = config.identifier(row['id'])
        config.require(name not in identifiers)
        identifiers.add(name)
        # This validates only public endpoint syntax; no CA or system store is read.
        tlsprobe.prepare({key: row[key] for key in ('host', 'port', 'server_name', 'protocol')})
        config.number(row['checked_at'])
        config.require(type(row['verified']) is bool and row['status'] in LEVELS)
        if row['peer_address'] is not None:
            config.require(type(row['peer_address']) is str and len(row['peer_address']) <= 64)
            ipaddress.ip_address(row['peer_address'])
        if row['verified']:
            config.number(row['not_after'])
            config.number(row['days_remaining'], -1e15, 1e15)
            hex_value(row['fingerprint_sha256'], 64)
            config.require(row['code'] is None and row['peer_address'] is not None
                           and row['tls_version'] in ('TLSv1.2', 'TLSv1.3'))
            days = (row['not_after'] - row['checked_at']) / 86400
            config.require(row['days_remaining'] == days
                           and row['status'] == level(days, warning, critical))
        else:
            config.require(type(row['code']) is str and row['code'] in PROBE_CODES
                           and row['status'] == 'critical')
            config.require(all(row[key] is None for key in
                               ('not_after', 'days_remaining', 'fingerprint_sha256', 'tls_version')))
    return value


def report(value):
    exact(value, {'schema', 'generated_at', 'completed_at', 'warning_days', 'critical_days',
                  'complete', 'status', 'endpoints'})
    config.require(type(value['schema']) is int and value['schema'] == 1)
    config.number(value['generated_at'])
    config.number(value['completed_at'], value['generated_at'])
    warning = config.number(value['warning_days'], 1, 365, integer=True)
    critical = config.number(value['critical_days'], 0, warning - 1, integer=True)
    rows(value['endpoints'], warning, critical)
    config.require(all(value['generated_at'] <= row['checked_at'] <= value['completed_at']
                       for row in value['endpoints']))
    config.require(type(value['complete']) is bool
                   and value['complete'] == all(row['code'] not in WORKER_CODES for row in value['endpoints'])
                   and value['status'] == overall(value['endpoints']))
    return value


def event_key(event):
    return config.digest({'kind': event['kind'], 'endpoints':
                          [(row['id'], row['status'], row['code']) for row in event['endpoints']]})


def event(value, observation):
    exact(value, {'schema', 'id', 'kind', 'observed_at', 'status', 'endpoints'})
    config.require(type(value['schema']) is int and value['schema'] == 1)
    hex_value(value['id'], 32)
    config.require(value['kind'] in ('alert', 'recovery'))
    config.number(value['observed_at'])
    config.require(value['observed_at'] <= observation['completed_at'])
    rows(value['endpoints'], observation['warning_days'], observation['critical_days'])
    config.require(all(row['checked_at'] <= value['observed_at'] for row in value['endpoints']))
    config.require(value['status'] == overall(value['endpoints'])
                   and (value['kind'] == 'recovery') == (value['status'] == 'ok'))


def _channel(value, observation):
    exact(value, {'incident', 'last', 'pending', 'superseded'})
    config.require(type(value['incident']) is bool)
    last, pending = value['last'], value['pending']
    if last is not None:
        exact(last, {'key', 'at', 'event_id', 'kind'})
        hex_value(last['key'], 64)
        hex_value(last['event_id'], 32)
        config.number(last['at'])
        config.require(last['kind'] in ('alert', 'recovery'))
    if pending is not None:
        exact(pending, {'key', 'event', 'attempts', 'retry_at', 'outcome', 'code'})
        event(pending['event'], observation)
        hex_value(pending['key'], 64)
        config.require(pending['key'] == event_key(pending['event']))
        config.number(pending['attempts'], 1, 2**31 - 1, integer=True)
        config.number(pending['retry_at'], pending['event']['observed_at'])
        config.require(pending['outcome'] in ('rejected', 'uncertain')
                       and type(pending['code']) is str and pending['code'] in DELIVERY_CODES)
    config.require(value['incident'] == bool(pending is not None or (last and last['kind'] == 'alert')))
    previous = value['superseded']
    if previous is not None:
        exact(previous, {'event_id', 'kind', 'outcome', 'code', 'attempts', 'observed_at'})
        hex_value(previous['event_id'], 32)
        config.require(previous['kind'] in ('alert', 'recovery')
                       and previous['outcome'] in ('rejected', 'uncertain')
                       and type(previous['code']) is str and previous['code'] in DELIVERY_CODES)
        config.number(previous['attempts'], 1, 2**31 - 1, integer=True)
        config.number(previous['observed_at'])
        config.require(previous['observed_at'] <= observation['completed_at'])


def validate(value, previous=False):
    fields = {'schema', 'identity', 'report', 'channels'}
    exact(value, fields if previous else fields | {'previous'})
    config.require(type(value['schema']) is int and value['schema'] == 1)
    hex_value(value['identity'], 64)
    if value['report'] is not None:
        report(value['report'])
    config.require(type(value['channels']) is dict and len(value['channels']) <= config.MAX_CHANNELS)
    config.require(value['report'] is not None or not value['channels'])
    for name, channel in value['channels'].items():
        config.identifier(name)
        _channel(channel, value['report'])
    if not previous and value['previous'] is not None:
        validate(value['previous'], previous=True)
    return value


def fresh(identity, previous=None):
    return {'schema': 1, 'identity': identity, 'report': None, 'channels': {}, 'previous': previous}


def channel():
    return {'incident': False, 'last': None, 'pending': None, 'superseded': None}
