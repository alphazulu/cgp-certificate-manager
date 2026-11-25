"""Explicit network observations, independent of certificate renewal and recovery."""
import argparse
import json
from pathlib import Path
import sys

from . import __version__, monitor_config as config, monitor_runner


SAFE_ERRORS = frozenset({'invalid_state_path', 'protected_state_path', 'unknown_endpoint',
                         'update_pending', 'update_gate_unsafe',
                         'installed_state_override',
                         'endpoint_disabled', 'clock_moved_backwards', 'configuration_changed',
                         'invalid_identifier', 'invalid_expiry_thresholds', 'no_enabled_endpoints',
                         'no_enabled_channels', 'duplicate_endpoint', 'duplicate_channel',
                         'invalid_endpoint', 'ca_unavailable', 'input_too_large', 'input_changed'})


def _show(value, as_json):
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return
    print('CGP monitor: ' + value['status'])
    if value.get('error'):
        print('Reason: ' + value['error'])
    if value.get('action') == 'check-config' and value['status'] == 'valid':
        print('Enabled: ' + str(value['enabled']).lower())
        print('Configured endpoints: ' + str(value['endpoints']))
        print('Configured notification channels: ' + str(value['channels']))
        print('Notification policy enabled: ' + str(value['notifications_enabled']).lower())
    report = value.get('observation')
    if report is not None:
        for row in report['endpoints']:
            detail = row['code'] or ('%.2f days remaining' % row['days_remaining'])
            print(row['id'] + ': ' + row['status'] + ' (' + detail + ')')
    for delivery in value.get('delivery', []):
        print('Notification ' + delivery['id'] + ': ' + delivery['outcome'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--config', type=Path, default=config.CONFIG)
    parser.add_argument('--state-dir', type=Path, default=config.STATE)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--endpoint', metavar='ID')
    parser.add_argument('--send', action='store_true', help='Allow configured notifications with --run')
    action = parser.add_mutually_exclusive_group(required=True)
    for name in ('check-config', 'probe', 'status', 'run'):
        action.add_argument('--' + name, dest='action', action='store_const', const=name)
    args = parser.parse_args(argv)
    if args.send and args.action != 'run':
        parser.error('--send requires --run')
    if args.endpoint is not None and args.action != 'probe':
        parser.error('--endpoint requires --probe')
    if not args.config.is_absolute() or '..' in args.config.parts:
        parser.error('--config requires an absolute path without parent traversal')
    phase = 'configuration_invalid'
    try:
        if args.endpoint is not None:
            config.identifier(args.endpoint)
        cfg = config.load(args.config)
        phase = 'operation_failed'
        if args.action == 'check-config':
            # Project public flags to booleans; prepared configuration also holds secrets.
            result = {'schema': 1, 'action': args.action, 'status': 'valid',
                      'enabled': cfg['enabled'] is True, 'endpoints': len(cfg['endpoints']),
                      'channels': len(cfg['notifications']['channels']),
                      'notifications_enabled': cfg['notifications']['enabled'] is True}
        elif args.action == 'probe':
            result = monitor_runner.probe(cfg, args.endpoint)
        elif args.action == 'status':
            result = monitor_runner.status(cfg, args.state_dir)
        else:
            result = monitor_runner.run(cfg, args.state_dir, args.send, args.config)
    except KeyboardInterrupt:
        result = monitor_runner._result(args.action, 'error', error='interrupted')
        _show(result, args.json)
        return 130
    except Exception as exc:
        code = str(exc)
        if isinstance(exc, BlockingIOError):
            code = 'busy'
        elif isinstance(exc, FileNotFoundError) and phase == 'configuration_invalid':
            code = 'configuration_missing'
        elif code not in SAFE_ERRORS:
            code = phase
        result = monitor_runner._result(args.action, 'error', error=code)
    _show(result, args.json)
    if result['status'] in ('ok', 'valid', 'disabled'):
        return 0
    return 1 if result['status'] in ('warning', 'critical') else 2


if __name__ == '__main__':
    raise SystemExit(main())
