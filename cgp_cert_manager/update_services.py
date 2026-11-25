"""Bounded local systemd quiescence for application updates; never start units."""
import subprocess
import time


TIMERS = ('cgp-letsencrypt.timer', 'cgp-monitor.timer')
SERVICES = ('cgp-letsencrypt.service', 'cgp-monitor.service')
TIMEOUT_SECONDS = 15
MAX_OUTPUT = 4096
CODES = frozenset({'systemd_unavailable', 'systemd_invalid_response',
                   'systemd_service_active', 'systemd_timers_active'})
_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat', 'SYSTEMD_PAGERSECURE': '1'}


class SystemdError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _run(arguments, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemdError('systemd_unavailable')
    try:
        result = subprocess.run(['/usr/bin/systemctl', '--no-pager', '--no-ask-password', *arguments],
                                env=dict(_ENV), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=remaining, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise SystemdError('systemd_unavailable') from None
    if result.returncode:
        raise SystemdError('systemd_unavailable')
    if type(result.stdout) is not bytes or len(result.stdout) > MAX_OUTPUT:
        raise SystemdError('systemd_invalid_response')
    return result.stdout


def _state(unit, deadline, require_fresh, recovery, missing_units):
    properties = ['LoadState', 'ActiveState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload']
    if recovery and unit in SERVICES:
        properties += ['MainPID', 'ControlPID', 'ControlGroup']
    output = _run(['show', unit, '--all', *['--property=' + name for name in properties]], deadline)
    try:
        lines = output.decode('ascii').splitlines()
        fields = dict(line.split('=', 1) for line in lines)
    except (UnicodeError, ValueError):
        raise SystemdError('systemd_invalid_response') from None
    if (not output.endswith(b'\n') or len(lines) != len(properties)
            or set(fields) != set(properties) or fields['NeedDaemonReload'] not in ('yes', 'no')
            or (require_fresh and fields['NeedDaemonReload'] != 'no')):
        raise SystemdError('systemd_invalid_response')
    if fields['LoadState'] == 'not-found':
        # Only the coordinator's already classified rename gaps may be absent.
        # A restarted manager can have no cached unit while its old file is in
        # the retained slot. Do not try stopping a unit systemd cannot load.
        if (not recovery or unit not in missing_units or fields['ActiveState'] != 'inactive'
                or fields['FragmentPath'] != '' or fields['DropInPaths'] != ''
                or fields['NeedDaemonReload'] != 'no'):
            raise SystemdError('systemd_invalid_response')
    elif (fields['LoadState'] != 'loaded' or fields['FragmentPath'] != '/etc/systemd/system/' + unit
          or fields['DropInPaths'] not in ('', '/etc/systemd/system/cgp-letsencrypt.timer.d/90-cgp-manager.conf'
                                         if unit == TIMERS[0] else '')):
        raise SystemdError('systemd_invalid_response')
    if recovery and unit in SERVICES:
        # Failed is quiescent only with no main/control process AND no retained
        # cgroup. systemd keeps a failed unit's cgroup while residual processes
        # remain; zero tracked PIDs alone would not exclude those children.
        if fields['MainPID'] != '0' or fields['ControlPID'] != '0' or fields['ControlGroup'] != '':
            raise SystemdError('systemd_service_active')
    return fields


def _observe(deadline, require_fresh, recovery=False, missing_units=()):
    result = {'timers': {}, 'services': {}}
    unloaded = set()
    for group, units in (('timers', TIMERS), ('services', SERVICES)):
        for unit in units:
            fields = _state(unit, deadline, require_fresh, recovery, missing_units)
            state = fields['ActiveState']
            if group == 'services' and state in ('active', 'activating', 'deactivating', 'reloading'):
                raise SystemdError('systemd_service_active')
            if state not in ('active', 'inactive') and not (recovery and group == 'services' and state == 'failed'):
                raise SystemdError('systemd_invalid_response')
            if fields['LoadState'] == 'not-found':
                unloaded.add(unit)
            result[group][unit] = state
    return result, unloaded


def _inactive(result):
    if any(value != 'inactive' for value in result['timers'].values()):
        raise SystemdError('systemd_timers_active')
    return result


def observe():
    """Report timer activity; refuse running/unknown services and unknown units."""
    return _observe(time.monotonic() + TIMEOUT_SECONDS, require_fresh=True)[0]


def stop(*, recovery=False, missing_units=()):
    """Stop and verify both timers; preserve enablement and refuse busy services."""
    if (set(missing_units) - set((*TIMERS, *SERVICES))) or (missing_units and not recovery):
        raise SystemdError('systemd_invalid_response')
    deadline = time.monotonic() + TIMEOUT_SECONDS
    # A pending replacement can legitimately leave systemd's cache dirty.
    # Recovery must still stop timers before restoring files and reloading.
    _, unloaded = _observe(deadline, require_fresh=False, recovery=recovery, missing_units=missing_units)
    present = [unit for unit in TIMERS if unit not in unloaded]
    if present:
        _run(['stop', *present], deadline)
    return _inactive(_observe(deadline, require_fresh=False, recovery=recovery, missing_units=missing_units)[0])


def reload(*, recovery=False):
    """Reload unit files and verify quiescence; never start or enable a unit."""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    _run(['daemon-reload'], deadline)
    return _inactive(_observe(deadline, require_fresh=True, recovery=recovery)[0])
