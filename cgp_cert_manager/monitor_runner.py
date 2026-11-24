"""Independent network observations and explicit, durable notification attempts."""
import copy
import fcntl
import os
from pathlib import Path
import time
import uuid

from . import core, monitor_config as config, monitor_state as state, monitor_worker, storage


STATE_FILE = 'observations.json'
INSTALLED_ROOT = Path('/opt/cgp-certificate-manager')


class MonitorError(ValueError):
    pass


def _path(value):
    path = Path(value)
    config.require(path.is_absolute() and '..' not in path.parts, 'invalid_state_path')
    for protected in (core.STATE, core.CONFIG.parent, core.LIVE.parent,
                      Path(__file__).resolve().parents[1]):
        config.require(path != protected and protected not in path.parents
                       and path not in protected.parents, 'protected_state_path')
    return path


def _time():
    return float(config.number(time.time()))


def _result(action, status, observation=None, delivery=None, error=None):
    return {'schema': 1, 'action': action, 'status': status, 'observation': observation,
            'delivery': [] if delivery is None else delivery, 'error': error}


def _targets(cfg, selected):
    targets = cfg['endpoints']
    if selected is not None:
        targets = [item for item in targets if item['id'] == selected]
        config.require(bool(targets), 'unknown_endpoint')
        config.require(targets[0]['enabled'], 'endpoint_disabled')
    return [item for item in targets if item['enabled']]


def _row(endpoint, envelope, checked, cfg):
    public = {key: endpoint['probe'][key] for key in ('host', 'port', 'server_name', 'protocol')}
    result = {'id': endpoint['id'], **public, 'status': 'critical', 'code': 'worker_invalid_result',
              'verified': False, 'checked_at': checked, 'not_after': None,
              'fingerprint_sha256': None, 'peer_address': None, 'tls_version': None,
              'days_remaining': None}
    if envelope['ok'] is False:
        if type(envelope['code']) is str and envelope['code'] in state.WORKER_CODES:
            result['code'] = envelope['code']
        return result
    value = envelope['value']
    try:
        state.exact(value, {'status', 'code', 'peer_address', 'not_after',
                            'fingerprint_sha256', 'tls_version'})
        config.require(value['status'] in ('ok', 'error'))
        result.update({key: value[key] for key in
                       ('code', 'peer_address', 'not_after', 'fingerprint_sha256', 'tls_version')})
        result['verified'] = value['status'] == 'ok'
        if result['verified']:
            config.number(value['not_after'])
            result['days_remaining'] = (value['not_after'] - checked) / 86400
            result['status'] = state.level(result['days_remaining'], cfg['warning_days'], cfg['critical_days'])
        state.rows([result], cfg['warning_days'], cfg['critical_days'])
    except (ValueError, TypeError, core.Error):
        return {'id': endpoint['id'], **public, 'status': 'critical', 'code': 'worker_invalid_result',
                'verified': False, 'checked_at': checked, 'not_after': None,
                'fingerprint_sha256': None, 'peer_address': None, 'tls_version': None,
                'days_remaining': None}
    return result


def observe(cfg, selected=None, lock_fd=None):
    targets = _targets(cfg, selected)
    if not cfg['enabled']:
        return None
    start = _time()
    rows = []
    for endpoint in targets:
        value = monitor_worker.execute('probe', endpoint['probe'], cfg['timeout_seconds'], lock_fd)
        checked = _time()
        config.require(checked >= start, 'clock_moved_backwards')
        rows.append(_row(endpoint, value, checked, cfg))
    report = {'schema': 1, 'generated_at': start, 'completed_at': _time(),
              'warning_days': cfg['warning_days'], 'critical_days': cfg['critical_days'],
              'complete': all(row['code'] not in state.WORKER_CODES for row in rows),
              'status': state.overall(rows), 'endpoints': rows}
    return state.report(report)


def probe(cfg, selected=None):
    report = observe(cfg, selected)
    return _result('probe', report['status'] if report else 'disabled', report)


def _load(path, identity):
    try:
        return state.validate(config.read_json(path, state.MAX_STATE))
    except FileNotFoundError:
        return state.fresh(identity)


def _save(path, value):
    state.validate(value)
    # Refuse growth before the write; all event lists and retained generations
    # are separately bounded, and no prepared credential enters this object.
    monitor_worker._encoded(value, state.MAX_STATE)
    storage.atomic_json(path, value)


def _pending(event, key):
    return {'event': event, 'key': key, 'attempts': 0, 'retry_at': 0,
            'outcome': 'uncertain', 'code': 'not_confirmed'}


def _supersede(pending):
    return {'event_id': pending['event']['id'], 'kind': pending['event']['kind'],
            'observed_at': pending['event']['observed_at'], 'outcome': pending['outcome'],
            'code': pending['code'], 'attempts': pending['attempts']}


def _notification(record, report, now, options):
    kind = 'alert' if report['status'] != 'ok' else ('recovery' if record['incident'] else None)
    if kind is None:
        return None, 'suppressed'
    event = {'schema': 1, 'id': uuid.uuid4().hex, 'kind': kind,
             'observed_at': report['completed_at'], 'status': report['status'],
             'endpoints': copy.deepcopy(report['endpoints'])}
    key = state.event_key(event)
    pending, last = record['pending'], record['last']
    if pending is not None:
        if pending['key'] == key:
            return pending, 'deferred' if now < pending['retry_at'] else 'send'
        record['superseded'] = _supersede(pending)
    elif last is not None and last['key'] == key and now - last['at'] < options['repeat_seconds']:
        return None, 'suppressed'
    return _pending(event, key), 'send'


def _deliver(channel, event, timeout, descriptor):
    envelope = monitor_worker.execute('notify', {'channel': channel, 'event': event}, timeout, descriptor)
    if not envelope['ok']:
        return {'outcome': 'uncertain', 'code': envelope['code']}
    result = envelope['value']
    try:
        state.exact(result, {'outcome', 'code'})
        config.require((result['outcome'] == 'accepted' and result['code'] is None)
                       or (result['outcome'] in ('rejected', 'uncertain')
                           and result['code'] in state.DELIVERY_CODES))
        return result
    except (ValueError, TypeError):
        return {'outcome': 'uncertain', 'code': 'worker_invalid_result'}


def _send(cfg, checkpoint, path, descriptor, config_path):
    results = []
    options = cfg['notifications']
    for channel in options['channels']:
        name = channel['id']
        if not options['enabled'] or not channel['enabled']:
            results.append({'id': name, 'outcome': 'disabled', 'code': None, 'event_id': None})
            continue
        record = checkpoint['channels'].setdefault(name, state.channel())
        now = _time()
        config.require(now >= checkpoint['report']['completed_at'], 'clock_moved_backwards')
        pending, action = _notification(record, checkpoint['report'], now, options)
        if action != 'send':
            results.append({'id': name, 'outcome': action,
                            'code': pending['code'] if pending else None,
                            'event_id': pending['event']['id'] if pending else None})
            continue
        if config_path is not None and config.load(config_path)['identity'] != cfg['identity']:
            raise MonitorError('configuration_changed')
        record['pending'] = pending
        record['incident'] = True
        pending.update(attempts=pending['attempts'] + 1, retry_at=now + options['retry_seconds'],
                       outcome='uncertain', code='not_confirmed')
        _save(path, checkpoint)  # Durable intent must precede every external send.
        result = _deliver(channel, pending['event'], options['timeout_seconds'], descriptor)
        finished = _time()
        config.require(finished >= now, 'clock_moved_backwards')
        if result['outcome'] == 'accepted':
            record['last'] = {'key': pending['key'], 'at': finished,
                              'event_id': pending['event']['id'], 'kind': pending['event']['kind']}
            record['pending'] = None
            record['incident'] = pending['event']['kind'] == 'alert'
        else:
            pending.update(result, retry_at=finished + options['retry_seconds'])
        _save(path, checkpoint)
        results.append({'id': name, **result, 'event_id': pending['event']['id']})
    return results


def run(cfg, directory=config.STATE, send=False, config_path=None):
    if not cfg['enabled']:
        return _result('run', 'disabled')
    directory = _path(directory)
    config.require(Path(__file__).resolve().parents[1] != INSTALLED_ROOT.resolve()
                   or directory == config.STATE, 'installed_state_override')
    storage.validate_tree(directory)
    with storage.operation_lock(directory) as lock:
        storage.validate_tree(directory, missing_ok=False)
        path = directory / STATE_FILE
        checkpoint = _load(path, cfg['identity'])
        now = _time()
        if checkpoint['report'] is not None:
            config.require(checkpoint['report']['completed_at'] <= now, 'clock_moved_backwards')
        for record in checkpoint['channels'].values():
            config.require(record['last'] is None or record['last']['at'] <= now, 'clock_moved_backwards')
        if checkpoint['identity'] != cfg['identity']:
            previous = {key: value for key, value in checkpoint.items() if key != 'previous'}
            checkpoint = state.fresh(cfg['identity'], previous)
        report = observe(cfg, lock_fd=lock.fileno())
        config.require(report['generated_at'] >= now, 'clock_moved_backwards')
        checkpoint['report'] = report
        _save(path, checkpoint)
        delivery = _send(cfg, checkpoint, path, lock.fileno(), config_path) if send else []
        _save(path, checkpoint)
        failed = (any(row['outcome'] in ('rejected', 'uncertain', 'deferred') for row in delivery)
                  or any(record['pending'] is not None for record in checkpoint['channels'].values()))
        return _result('run', 'delivery_failed' if failed else report['status'], report, delivery)


def status(cfg, directory=config.STATE):
    if not cfg['enabled']:
        return _result('status', 'disabled')
    directory = _path(directory)
    try:
        storage.check_private_directory(directory)
        with storage.open_private(directory / 'run.lock') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            storage.validate_tree(directory, missing_ok=False)
            checkpoint = _load(directory / STATE_FILE, cfg['identity'])
    except FileNotFoundError:
        return _result('status', 'missing')
    except BlockingIOError:
        return _result('status', 'busy')
    except (ValueError, TypeError, OSError, core.Error):
        return _result('status', 'invalid')
    report = checkpoint['report']
    if checkpoint['identity'] != cfg['identity']:
        return _result('status', 'configuration_changed', report)
    if report is None:
        return _result('status', 'missing')
    now = _time()
    if report['completed_at'] > now or any(record['last'] is not None and record['last']['at'] > now
                                          for record in checkpoint['channels'].values()):
        return _result('status', 'future', report)
    if now - report['generated_at'] > cfg['max_age_seconds']:
        return _result('status', 'stale', report)
    delivery = []
    for name, record in checkpoint['channels'].items():
        pending, last = record['pending'], record['last']
        delivery.append({'id': name,
                         'outcome': pending['outcome'] if pending else ('accepted' if last else 'suppressed'),
                         'code': pending['code'] if pending else None,
                         'event_id': pending['event']['id'] if pending else (last['event_id'] if last else None)})
    failed = any(record['pending'] is not None for record in checkpoint['channels'].values())
    return _result('status', 'delivery_failed' if failed else report['status'], report, delivery)
