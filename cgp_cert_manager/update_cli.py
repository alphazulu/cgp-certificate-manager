"""Offline update preparation, explicit installation approval and recovery."""
import argparse
import json
from pathlib import Path
import re
import sys

from . import __version__


TRUST_FILE = Path('/etc/cgp-update/trust.json')
STATE_DIR = Path('/var/lib/cgp-update')
INSTALLED_ROOT = Path('/opt/cgp-certificate-manager')


def _failure(action, code):
    return {'schema': 1, 'action': action, 'status': 'error', 'plan': None, 'error': code}


def _render(result, as_json):
    if as_json:
        return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
    lines = ['CGP update: ' + result['status']]
    if result['error'] is not None:
        lines.append('Reason: ' + result['error'])
    if result['plan'] is not None:
        lines.extend(['Plan:', json.dumps(result['plan'], indent=2, sort_keys=True,
                                         ensure_ascii=True, allow_nan=False)])
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--trust-file', type=Path, default=TRUST_FILE)
    parser.add_argument('--state-dir', type=Path, default=STATE_DIR)
    parser.add_argument('--installed-root', type=Path, default=INSTALLED_ROOT)
    parser.add_argument('--confirm-update', metavar='TOKEN')
    parser.add_argument('--json', action='store_true')
    for name in ('manifest', 'signature', 'archive'):
        parser.add_argument('--' + name, type=Path)
    actions = parser.add_mutually_exclusive_group(required=True)
    for name in ('check', 'prepare', 'status', 'review', 'apply', 'recover'):
        actions.add_argument('--' + name, dest='action', action='store_const', const=name)
    args = parser.parse_args(argv)
    artifacts = {'manifest_path': args.manifest, 'signature_path': args.signature,
                 'archive_path': args.archive}
    if args.action not in ('check', 'prepare'):
        if any(path is not None for path in artifacts.values()):
            parser.error('--' + args.action + ' does not accept --manifest, --signature or --archive')
    elif any(path is None for path in artifacts.values()):
        parser.error('--check and --prepare require --manifest, --signature and --archive')
    if args.action == 'apply':
        if args.confirm_update is None or not re.fullmatch(r'[0-9a-f]{64}', args.confirm_update):
            parser.error('--apply requires --confirm-update with an exact lowercase 64-hex token')
    elif args.confirm_update is not None:
        parser.error('--confirm-update requires --apply')
    for name in ('trust_file', 'state_dir', 'installed_root', 'manifest', 'signature', 'archive'):
        path = getattr(args, name)
        if path is not None and (not path.is_absolute() or '..' in path.parts):
            parser.error('--' + name.replace('_', '-') + ' requires an absolute path without parent traversal')
    options = {'trust_path': args.trust_file, 'installed_root': args.installed_root,
               'state_dir': args.state_dir}
    if args.action in ('check', 'prepare'):
        options.update(artifacts)
    if args.action == 'apply':
        options['confirmation_token'] = args.confirm_update
    try:
        if args.action in ('check', 'prepare'):
            from . import update_plan as backend
        else:
            from . import update_apply as backend
        result = getattr(backend, args.action)(**options)
        if args.action == 'status' and result is None:
            from . import update_plan
            result = update_plan.status(**options)
        code = 0 if result['status'] in ('verified', 'prepared', 'review_ready', 'applied', 'rolled_back') else 2
        rendered = _render(result, args.json)
    except KeyboardInterrupt:
        print(_render(_failure(args.action, 'interrupted'), args.json))
        return 130
    except Exception:
        result = _failure(args.action, 'update_failed')
        rendered = _render(result, args.json)
        code = 2
    print(rendered)
    return code


if __name__ == '__main__':
    sys.exit(main())
