#!/bin/bash
# Run ONLY in the disposable container created by the CI installer job.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || { echo 'Disposable Docker container required'; exit 1; }
[[ -d /tmp/candidate-writable && -d /tmp/baseline-writable ]] || exit 1
export PATH=/mock-bin:$PATH
mkdir -p /mock-bin /etc/cgp-letsencrypt /etc/systemd/system
install -d -m 700 /var/lib/cgp-letsencrypt
# Every candidate/baseline Python process inherits an offline transport guard.
# Even a swallowed accidental probe/send attempt must leave a failing marker.
mkdir -p /tmp/cgp-installer-guards
cat >/tmp/cgp-installer-guards/sitecustomize.py <<'OFFLINE_GUARD'
from pathlib import Path
import socket
import sys

_attempt_marker = Path('/tmp/cgp-installer-network-attempted')

def refused(*args, **kwargs):
    _attempt_marker.write_text('Unexpected installer network operation\n')
    raise AssertionError('Installer must not initiate network operations')

def block_worker(frame, event, arg):
    # The worker deliberately discards ambient PYTHONPATH. Refuse its parent
    # entrypoint before it can start a child that would lack these test guards.
    if (event == 'call' and frame.f_code.co_name == 'execute'
            and frame.f_globals.get('__name__') == 'cgp_cert_manager.monitor_worker'):
        refused()

socket.create_connection = refused
socket.getaddrinfo = refused
socket.socket.connect = refused
socket.socket.connect_ex = refused
sys.setprofile(block_worker)
OFFLINE_GUARD
export PYTHONPATH=/tmp/cgp-installer-guards
cat >/mock-bin/systemctl <<'SH'
#!/bin/bash
set -eu
echo "$*" >> /tmp/systemctl.log
case "$1" in
  is-active)
    case "$*" in
      *cgp-letsencrypt.service*) test -f /tmp/service-active ;;
      *cgp-letsencrypt.timer*) test -f /tmp/timer-active ;;
      *cgp-monitor.service*) test -f /tmp/monitor-service-active ;;
      *cgp-monitor.timer*) test -f /tmp/monitor-timer-active ;;
      *) exit 1 ;;
    esac ;;
  list-unit-files)
    if [[ -f /etc/systemd/system/$2 ]]; then
      printf '%s disabled\n' "$2"
    fi ;;
  stop|start|restart)
    case "$2" in
      cgp-letsencrypt.timer) marker=/tmp/timer-active ;;
      cgp-monitor.timer) marker=/tmp/monitor-timer-active ;;
      *) echo "Unexpected service activation: $*" >&2; exit 2 ;;
    esac
    if [[ $1 == stop ]]; then rm -f "$marker"; else touch "$marker"; fi ;;
  daemon-reload)
    if [[ -f /tmp/fail-reload-once ]]; then
      rm /tmp/fail-reload-once
      exit 1
    fi ;;
  *) echo "Unexpected systemctl command: $*" >&2; exit 2 ;;
esac
SH
chmod 755 /mock-bin/systemctl
# Do not touch production paths outside this container.
config=/etc/cgp-letsencrypt/config.json
app=/opt/cgp-certificate-manager
launcher=/usr/local/sbin/cgp-letsencrypt
certbot_launcher=/usr/local/sbin/cgp-certbot
monitor_launcher=/usr/local/sbin/cgp-monitor
monitor_config=/etc/cgp-monitor/config.json
monitor_state=/var/lib/cgp-monitor
monitor_evidence=$monitor_state/state.json
drop=/etc/systemd/system/cgp-letsencrypt.timer.d/90-cgp-manager.conf
source_version() {
    python3 -c 'import runpy,sys; print(runpy.run_path(sys.argv[1])["__version__"])' "$1/cgp_cert_manager/__init__.py"
}
candidate_version=$(source_version /tmp/candidate-writable)
baseline_version=$(source_version /tmp/baseline-writable)
journal=/var/lib/cgp-letsencrypt/transactions/example.com.json
assert_pending_journal() {
    # An application upgrade must preserve unresolved recovery data verbatim.
    cmp "$journal" /tmp/pending.expected
    test "$(stat -c %a "$journal")" = 600
    test "$(stat -c %u "$journal")" = 0
    test "$(stat -c %a "$(dirname "$journal")")" = 700
    test "$(stat -c %u "$(dirname "$journal")")" = 0
    assert_audit_archives
    cmp "$dns_receipt" /tmp/dns-receipt.expected
    test "$(stat -c %a "$dns_receipt")" = 600
    test "$(stat -c %a "$(dirname "$dns_receipt")")" = 700
    assert_monitor_data
    test ! -e /tmp/cgp-installer-network-attempted
}
assert_monitor_data() {
    if [[ ! -f /tmp/monitor-config.expected ]]; then
        test ! -e "$monitor_config"
        return
    fi
    python3 - "$monitor_config" "$monitor_evidence" "${audit_unsafe_path:-}" <<'MONITOR_PRESERVATION'
from pathlib import Path
import stat
import sys

config, evidence, fault = sys.argv[1:]
for name, expected in ((config, '/tmp/monitor-config.expected'), (evidence, '/tmp/monitor-state.expected')):
    path = Path(name)
    assert path.read_bytes() == Path(expected).read_bytes(), 'Monitor evidence changed'
    if name != fault:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
state = Path(evidence).parent
if str(state) != fault:
    info = state.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
lock = state / 'run.lock'
if str(lock) != fault:
    info = lock.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
MONITOR_PRESERVATION
}
assert_monitor_cli() {
    python3 - "$app" "$monitor_launcher" "$monitor_state" <<'MONITOR_ENTRYPOINT'
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import io
from pathlib import Path
import runpy
import socket
import smtplib
import sys
from unittest.mock import patch

application, launcher, state = (Path(value) for value in sys.argv[1:])
sys.path.insert(0, str(application))
from cgp_cert_manager import __version__, core, monitor_config, storage

def snapshot():
    return {str(path): (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for root in (core.STATE, state) for path in root.rglob('*') if path.is_file()}

before = snapshot()
with ExitStack() as stack:
    forbidden = [stack.enter_context(patch.object(module, name, side_effect=AssertionError('Read-only entrypoint')))
                 for module, name in ((socket, 'create_connection'), (smtplib, 'SMTP'),
                                      (smtplib, 'SMTP_SSL'), (storage, 'operation_lock'),
                                      (storage, 'atomic_json'), (monitor_config, 'load'))]
    for action in ('--help', '--version'):
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(launcher), action]), redirect_stdout(output), redirect_stderr(io.StringIO()):
            try:
                runpy.run_path(str(launcher), run_name='__main__')
            except SystemExit as exited:
                assert exited.code == 0, action
            else:
                raise AssertionError('Launcher did not return its exit status')
        if action == '--version':
            assert __version__ in output.getvalue()
        else:
            assert '--run' in output.getvalue() and '--send' in output.getvalue()
    for call in forbidden:
        call.assert_not_called()
assert snapshot() == before, 'Monitor help/version changed private state'
MONITOR_ENTRYPOINT
    test "$(stat -c %a "$monitor_launcher")" = 750
    test "$(stat -c %a "$monitor_state")" = 700
    test "$(stat -c %a "$monitor_state/run.lock")" = 600
    test -f /etc/systemd/system/cgp-monitor.service
    test -f /etc/systemd/system/cgp-monitor.timer
    grep -Fxq 'ExecStart=/usr/local/sbin/cgp-monitor --run' /etc/systemd/system/cgp-monitor.service
    grep -Fxq 'ProtectSystem=strict' /etc/systemd/system/cgp-monitor.service
    grep -Fxq 'ReadWritePaths=/var/lib/cgp-monitor' /etc/systemd/system/cgp-monitor.service
    grep -Fxq 'OnUnitInactiveSec=5min' /etc/systemd/system/cgp-monitor.timer
    test ! -e /tmp/cgp-installer-network-attempted
}
assert_audit_archives() {
    python3 - /tmp/cgp-resolution-expected/manifest.json "${audit_unsafe_path:-}" <<'AUDIT_CHECK'
import json
from pathlib import Path
import stat
import sys

manifest = json.loads(Path(sys.argv[1]).read_text())
intentional_fault = sys.argv[2]
for entry in manifest['files']:
    path = Path(entry['path'])
    assert path.read_bytes() == Path(entry['expected']).read_bytes(), str(path)
    if str(path) != intentional_fault:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
for value in manifest['directories']:
    if value != intentional_fault:
        info = Path(value).lstat()
        assert stat.S_ISDIR(info.st_mode)
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
missing = Path(manifest['incomplete']) / 'completion.json'
assert not missing.exists() and not missing.is_symlink()
AUDIT_CHECK
}
write_config() {
    cat >"$config" <<'JSON'
{"schema_version":2,"email":"admin@example.com","communigate":{"url":"http://127.0.0.1:8100/CLI/","username":"dummy","password":"dummy"},"cloudflare_credentials":"/etc/cgp-letsencrypt/cloudflare.ini","domains":[],"schedule":{"hour":7,"random_delay":300}}
JSON
    chmod 600 "$config"
}
must_fail() {
    if "$@"; then echo "Expected failure: $*" >&2; exit 1; fi
}
assert_monitoring_cli() {
    local before_log metrics_dir
    before_log=$(sha256sum /tmp/systemctl.log)
    metrics_dir=$(mktemp -d /tmp/cgp-monitoring-export-XXXXXXXX)
    chmod 755 "$metrics_dir"
    # Execute the installed launcher with its real native interpreter/imports.
    # The absent inventory/state and intentionally retained recovery fixtures
    # must produce partial observations, never trigger discovery or repairs.
    python3 - "$app" "$launcher" "$metrics_dir" <<'MONITORING_CHECK'
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import runpy
import smtplib
import socket
import stat
import subprocess
import sys
from unittest.mock import Mock, patch

application, launcher, destination = (Path(value) for value in sys.argv[1:])
sys.path.insert(0, str(application))
from cgp_cert_manager import cli, core, deployment, dnsauth, resolution, storage
assert Path(cli.__file__).resolve().parent == application / 'cgp_cert_manager'

def private_snapshot():
    captured = {}
    for root in (core.CONFIG.parent, core.STATE):
        for path in (root, *sorted(root.rglob('*'))):
            info = path.lstat()
            content = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None
            captured[str(path)] = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                                   info.st_size, info.st_mtime_ns, info.st_ctime_ns, content)
    return captured

def invoke(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(sys, 'argv', [str(launcher), *args]), redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            runpy.run_path(str(launcher), run_name='__main__')
        except SystemExit as result:
            code = result.code
        else:
            raise AssertionError('Installed launcher did not return an exit code')
    return code, stdout.getvalue(), stderr.getvalue()

assert not (core.STATE / 'domains.json').exists()
assert not (core.STATE / 'state.json').exists()
before = private_snapshot()
guards = []
with ExitStack() as stack:
    targets = [(module, name) for module in (core, cli)
               for name in ('cli', 'cf', 'zones', 'discover', 'token', 'run', 'atomic', 'issue', 'deploy')]
    targets += [(cli, 'notify'), (cli, 'history'), (storage, 'operation_lock'),
                (storage, 'atomic_json'), (storage, 'ensure_private_directory'),
                (dnsauth, 'cleanup_pending'), (deployment, 'recover_pending'),
                (resolution, 'acknowledge'), (socket, 'socket'),
                (subprocess, 'run'), (subprocess, 'Popen'), (smtplib, 'SMTP')]
    for module, name in targets:
        guard = Mock(side_effect=AssertionError('Installed monitoring attempted a forbidden side effect'))
        stack.enter_context(patch.object(module, name, guard))
        guards.append(guard)
    code, observed, error = invoke('--monitoring', '--json')
    assert code == 1 and error == '', (code, error)
    snapshot = json.loads(observed)
    assert set(snapshot) == {'schema', 'generated_at', 'complete', 'sources', 'pending', 'domains'}
    assert snapshot['schema'] == 1 and snapshot['complete'] is False and snapshot['domains'] == []
    source_names = {'config', 'inventory', 'state', 'transactions', 'resolutions', 'dns_challenges', 'lock'}
    assert set(snapshot['sources']) == source_names
    for source in snapshot['sources'].values():
        assert set(source) <= {'status', 'mtime'}
        assert source['status'] in ('ok', 'missing', 'error', 'busy')
    assert snapshot['sources']['config']['status'] == 'ok'
    assert snapshot['sources']['lock']['status'] == 'ok'
    assert snapshot['sources']['inventory']['status'] == 'missing'
    assert snapshot['sources']['state']['status'] == 'missing'
    assert set(snapshot['pending']) == {'transactions', 'resolutions', 'dns_challenges'}
    for kind in snapshot['pending']:
        # The legacy-shaped journal and foreign DNS identity may be invalid for
        # observation, but must never be silently counted as a healthy zero.
        if snapshot['sources'][kind]['status'] == 'ok':
            assert snapshot['pending'][kind] == 1, (kind, snapshot['pending'][kind])
        else:
            assert snapshot['sources'][kind]['status'] == 'error'
            assert snapshot['pending'][kind] is None
    code, metrics, error = invoke('--metrics')
    assert code == 1 and error == '', (code, error)
    assert 'cgp_manager_collection_success 0\n' in metrics and metrics.endswith('\n')
    code, discovery, error = invoke('--zabbix-discovery', '--json')
    assert code == 1 and discovery == ''
    assert error == 'Monitoring snapshot incomplete; Zabbix discovery not emitted\n'
    public_file = destination / 'cgp.prom'
    code, published_stdout, error = invoke('--metrics', '--metrics-file', str(public_file))
    assert code == 1 and published_stdout == '' and error == '', (code, error)
    assert stat.S_IMODE(public_file.stat().st_mode) == 0o644
    published = public_file.read_text()
    assert 'cgp_manager_collection_success 0\n' in published and published.endswith('\n')
    for text in (observed, metrics, published):
        for private in ('PrivateSecureKey', 'SecureCertificate', 'CAChain', 'dummy',
                        'b2xkLWtleQ==', 'bmV3LWtleQ==', 'A' * 43,
                        '/etc/cgp-letsencrypt/cloudflare.ini', 'Synthetic installer preservation test'):
            assert private not in text, 'Monitoring disclosed private source data'
    for guard in guards:
        guard.assert_not_called()
assert private_snapshot() == before, 'Installed monitoring mutated configuration or recovery data'
assert not (core.STATE / 'domains.json').exists()
assert not (core.STATE / 'state.json').exists()
MONITORING_CHECK
    test "$(sha256sum /tmp/systemctl.log)" = "$before_log"
    assert_pending_journal
}
write_config
echo 'dns_cloudflare_api_token = dummy' >/etc/cgp-letsencrypt/cloudflare.ini
chmod 600 /etc/cgp-letsencrypt/cloudflare.ini
cp "$config" /tmp/config.expected
# Synthetic values only. Keep this journal present throughout clean install,
# application rollback, blocked upgrades and successful upgrade. No recovery
# command is run by the installer and these bytes must not be migrated.
install -d -m 700 "$(dirname "$journal")"
cat >"$journal" <<'JSON'
{"schema":2,"domain":"example.com","phase":"applying","previous":{"PrivateSecureKey":"[b2xkLWtleQ==]","SecureCertificate":"[b2xkLWNlcnQ=]","CAChain":"[Y2E=]","CertificateType":"YES"},"intended":{"PrivateSecureKey":"[bmV3LWtleQ==]","SecureCertificate":"[bmV3LWNlcnQ=]","CAChain":"[Y2E=]","CertificateType":"YES"},"endpoints":[{"host":"127.0.0.1","port":443,"sni":"new.example.com"}],"previous_endpoints":[{"host":"127.0.0.1","port":443,"sni":"old.example.com"}],"config_identity":"installer-test-fixture"}
JSON
chmod 600 "$journal"
dns_receipt=/var/lib/cgp-letsencrypt/dns-challenges/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.json
install -d -m 700 "$(dirname "$dns_receipt")"
cat >"$dns_receipt" <<'DNS_RECEIPT'
{"schema":1,"identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attempt":"dddddddddddddddddddddddddddddddd","owner":"cgp-certificate-manager:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","credentials":"/etc/cgp-letsencrypt/cloudflare.ini","zone":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"_acme-challenge.example.com","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","record":null,"phase":"intent"}
DNS_RECEIPT
chmod 600 "$dns_receipt"
cp "$dns_receipt" /tmp/dns-receipt.expected
cp "$journal" /tmp/pending.expected
# Create real-format synthetic audit evidence with a fake local CGP readback.
# Keep one incomplete authorization after pending was removed: the installer
# must preserve it without converting it into an acknowledged completion.
python3 - /tmp/candidate-writable /var/lib/cgp-letsencrypt /tmp/cgp-resolution-expected <<'AUDIT_FIXTURES'
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])
from cgp_cert_manager import core, recovery, resolution, storage
from cgp_cert_manager.transactions import Journal

core.STATE = Path(sys.argv[2])
expected = Path(sys.argv[3])
storage.ensure_private_directory(expected)
cfg = {'communigate': {'url': 'http://127.0.0.1:8100/CLI/'}}
identity = recovery.server_identity(cfg, 'a' * 32)
previous = {'PrivateSecureKey': '[b2xkLWtleQ==]', 'SecureCertificate': '[b2xkLWNlcnQ=]',
            'CAChain': '[Y2E=]', 'CertificateType': 'NO'}
intended = dict(previous, SecureCertificate='[bmV3LWNlcnQ=]', CertificateType='YES')
manifest = {'files': [], 'directories': [str(core.STATE / 'resolutions')]}
with storage.operation_lock(core.STATE), \
        patch.object(core, 'current', return_value=previous), \
        patch.object(core, 'update', side_effect=AssertionError('No CGP writes in audit fixture')), \
        patch.object(recovery, 'verify_snapshot', side_effect=AssertionError('No TLS proof in audit fixture')), \
        patch.object(recovery, 'server_identity', return_value=identity):
    for kind in ('completed', 'incomplete'):
        domain = kind + '.example.com'
        Journal(core.STATE / 'transactions').prepare(
            domain, previous, intended, [{'port': 443, 'sni': domain}], identity)
        token = resolution.preview(cfg, domain)['confirmation_token']
        resolution.acknowledge(cfg, domain, token, 'Synthetic installer preservation test')
        bundle = core.STATE / 'resolutions' / token
        if kind == 'incomplete':
            # Fixture for death after pending unlink but before completion.
            (bundle / 'completion.json').unlink()
        manifest[kind] = str(bundle)
        manifest['directories'].append(str(bundle))
        for path in sorted(bundle.glob('*.json')):
            copy = expected / (kind + '-' + path.name)
            storage.atomic_text(copy, storage.read_text(path))
            manifest['files'].append({'path': str(path), 'expected': str(copy)})
storage.atomic_json(expected / 'manifest.json', manifest)
AUDIT_FIXTURES

echo '=== clean install ==='
bash /tmp/candidate-writable/install.sh --non-interactive
test -x "$launcher"
test -x "$certbot_launcher"
test -x "$monitor_launcher"
test "$(stat -c %a "$certbot_launcher")" = 750
"$certbot_launcher" --version
python3 - "$app" <<'PLUGIN_DISCOVERY'
import importlib.metadata
import sys
sys.path.insert(0, sys.argv[1])
from certbot._internal.plugins.disco import PluginsRegistry
from cgp_cert_manager import __version__, certbot_runner, core, storage
assert 'cgp-dns' in PluginsRegistry.find_all()
assert importlib.metadata.version('cgp-certbot-dns') == __version__
# Exercise the installed interpreter's actual procfs/descriptor contract without
# starting Certbot or touching the pending provider/CGP recovery fixtures.
with storage.operation_lock(core.STATE) as lock:
    certbot_runner._check_lock(lock.fileno())
PLUGIN_DISCOVERY
test "$("$launcher" --version)" = "$candidate_version"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.expected
grep -q '07,19:00:00' "$drop"
test "$(stat -c %a "$launcher")" = 750
test "$(stat -c %a "$config")" = 600
test "$(stat -c %a /var/lib/cgp-letsencrypt)" = 700
test ! -f /tmp/timer-active
test ! -f /tmp/monitor-timer-active
! grep -Eq '^(enable|start|restart) cgp-monitor\.' /tmp/systemctl.log
assert_pending_journal
assert_monitoring_cli
assert_monitor_cli

echo '=== clean installation failure restores absent application ==='
rm -rf "$app" "$launcher" "$certbot_launcher" "$monitor_launcher" "$drop" /etc/systemd/system/cgp-letsencrypt.{service,timer} /etc/systemd/system/cgp-monitor.{service,timer}
touch /tmp/fail-reload-once
must_fail bash /tmp/candidate-writable/install.sh --non-interactive
test ! -e "$app"
test ! -e "$launcher"
test ! -e "$certbot_launcher"
test ! -e "$monitor_launcher"
test ! -e /etc/systemd/system/cgp-monitor.service
test ! -e /etc/systemd/system/cgp-monitor.timer
test ! -e "$drop"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.expected
assert_pending_journal

echo "=== install actual baseline $baseline_version ==="
bash /tmp/baseline-writable/install.sh
test "$("$launcher" --version)" = "$baseline_version"
test ! -e "$certbot_launcher"
test ! -e "$monitor_launcher"
assert_pending_journal
touch "$app/cgp_cert_manager/stale.py"
echo 'persistent-state' >/var/lib/cgp-letsencrypt/sentinel
chmod 600 /var/lib/cgp-letsencrypt/sentinel
touch /tmp/timer-active
cp "$config" /tmp/config.before-upgrade

echo '=== upgrade failure restores baseline and active timer ==='
touch /tmp/fail-reload-once
must_fail bash /tmp/candidate-writable/install.sh --upgrade
test "$("$launcher" --version)" = "$baseline_version"
test -f "$app/cgp_cert_manager/stale.py"
test ! -e "$certbot_launcher"
test ! -e "$monitor_launcher"
test ! -e /etc/systemd/system/cgp-monitor.service
test ! -e /etc/systemd/system/cgp-monitor.timer
test -f /tmp/timer-active
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.before-upgrade
assert_pending_journal

echo '=== monitor operation also excludes application upgrade ==='
before_monitor_log=$(sha256sum /tmp/systemctl.log)
(
  flock -n 9
  must_fail bash /tmp/candidate-writable/install.sh --upgrade
) 9>>"$monitor_state/run.lock"
test "$(sha256sum /tmp/systemctl.log)" = "$before_monitor_log"
test -f /tmp/timer-active
test "$("$launcher" --version)" = "$baseline_version"
assert_pending_journal
touch /tmp/monitor-service-active
must_fail bash /tmp/candidate-writable/install.sh --upgrade
rm /tmp/monitor-service-active
test -f /tmp/timer-active
test "$("$launcher" --version)" = "$baseline_version"
assert_pending_journal

echo '=== running operation rejects upgrade without stopping timer ==='
(
  flock -n 9
  must_fail bash /tmp/candidate-writable/install.sh --upgrade
) 9>>/var/lib/cgp-letsencrypt/run.lock
test -f /tmp/timer-active
test "$("$launcher" --version)" = "$baseline_version"
assert_pending_journal
touch /tmp/service-active
must_fail bash /tmp/candidate-writable/install.sh --upgrade
rm /tmp/service-active
test -f /tmp/timer-active
assert_pending_journal

echo '=== successful upgrade ==='
bash /tmp/candidate-writable/install.sh --upgrade
test "$("$launcher" --version)" = "$candidate_version"
test -x "$certbot_launcher"
"$certbot_launcher" --version
test ! -e "$app/cgp_cert_manager/stale.py"
test ! -f /tmp/timer-active
test ! -f /tmp/monitor-timer-active
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.before-upgrade
grep -q persistent-state /var/lib/cgp-letsencrypt/sentinel
grep -q '07,19:00:00' "$drop"
grep -q 'dummy' /etc/cgp-letsencrypt/cloudflare.ini
assert_pending_journal
assert_monitoring_cli
assert_monitor_cli

echo '=== existing monitor configuration and state survive upgrade rollback ==='
install -d -m 700 /etc/cgp-monitor
cat >"$monitor_config" <<'MONITOR_CONFIG'
{"schema":1,"enabled":false,"endpoints":[],"notifications":{"enabled":false,"channels":[]}}
MONITOR_CONFIG
printf '%s\n' '{"private":"retained monitor observation and delivery evidence"}' >"$monitor_evidence"
chmod 600 "$monitor_config" "$monitor_evidence"
cp "$monitor_config" /tmp/monitor-config.expected
cp "$monitor_evidence" /tmp/monitor-state.expected
for file in "$monitor_launcher" /etc/systemd/system/cgp-monitor.service /etc/systemd/system/cgp-monitor.timer; do
    printf '\n# prior monitor installation fixture\n' >>"$file"
    cp -a "$file" "/tmp/$(basename "$file").prior"
done
touch /tmp/timer-active /tmp/monitor-timer-active /tmp/fail-reload-once
must_fail bash /tmp/candidate-writable/install.sh --upgrade
for file in "$monitor_launcher" /etc/systemd/system/cgp-monitor.service /etc/systemd/system/cgp-monitor.timer; do
    cmp "$file" "/tmp/$(basename "$file").prior"
done
test -f /tmp/timer-active
test -f /tmp/monitor-timer-active
test "$("$launcher" --version)" = "$candidate_version"
assert_pending_journal
assert_monitor_cli

echo '=== successful monitor upgrade leaves both timers stopped ==='
bash /tmp/candidate-writable/install.sh --upgrade
test ! -f /tmp/timer-active
test ! -f /tmp/monitor-timer-active
cmp "$monitor_launcher" /tmp/candidate-writable/monitor-launcher
cmp /etc/systemd/system/cgp-monitor.service /tmp/candidate-writable/systemd/cgp-monitor.service
cmp /etc/systemd/system/cgp-monitor.timer /tmp/candidate-writable/systemd/cgp-monitor.timer
assert_pending_journal
assert_monitor_cli

echo '=== invalid monitor configuration refuses before changing either timer ==='
printf '%s\n' '{"schema":1,"enabled":true,"endpoints":[],"notifications":{"enabled":false,"channels":[]}}' >"$monitor_config"
before_monitor_log=$(sha256sum /tmp/systemctl.log)
before_monitor_app=$(tar -C "$app" -cf - . | sha256sum)
touch /tmp/timer-active /tmp/monitor-timer-active
must_fail bash /tmp/candidate-writable/install.sh --upgrade
test "$(sha256sum /tmp/systemctl.log)" = "$before_monitor_log"
test "$(tar -C "$app" -cf - . | sha256sum)" = "$before_monitor_app"
test -f /tmp/timer-active
test -f /tmp/monitor-timer-active
cp /tmp/monitor-config.expected "$monitor_config"
assert_pending_journal

echo '=== invalid schedule rejected before modifying files ==='
cp "$config" /tmp/valid-config
python3 -c 'import json; p="/etc/cgp-letsencrypt/config.json"; c=json.load(open(p)); c["schedule"]["hour"]=24; json.dump(c,open(p,"w"))'
touch /tmp/timer-active
must_fail bash /tmp/candidate-writable/install.sh --upgrade
test -f /tmp/timer-active
test "$("$launcher" --version)" = "$candidate_version"
cp /tmp/valid-config "$config"
assert_pending_journal

echo '=== invalid DNS options rejected before modifying files ==='
cp "$config" /tmp/valid-dns-config
python3 -c 'import json; p="/etc/cgp-letsencrypt/config.json"; c=json.load(open(p)); c["dns_propagation"]={"mode":"adaptive","timeout_seconds":False}; json.dump(c,open(p,"w"))'
touch /tmp/timer-active
before_dns_log=$(sha256sum /tmp/systemctl.log)
before_dns_app=$(tar -C "$app" -cf - . | sha256sum)
must_fail bash /tmp/candidate-writable/install.sh --upgrade
test "$(sha256sum /tmp/systemctl.log)" = "$before_dns_log"
test "$(tar -C "$app" -cf - . | sha256sum)" = "$before_dns_app"
test -f /tmp/timer-active
cp /tmp/valid-dns-config "$config"
assert_pending_journal

echo '=== unsafe private paths are refused before installer mutations ==='
assert_preflight_refused() {
    local before_log before_app before_backups
    before_log=$(sha256sum /tmp/systemctl.log)
    before_app=$(tar -C "$app" -cf - . | sha256sum)
    before_backups=$(find /root -maxdepth 1 -type d -name 'cgp-manager-backup-*' | sort)
    must_fail bash /tmp/candidate-writable/install.sh --upgrade
    test "$(sha256sum /tmp/systemctl.log)" = "$before_log"
    test "$(tar -C "$app" -cf - . | sha256sum)" = "$before_app"
    test "$(find /root -maxdepth 1 -type d -name 'cgp-manager-backup-*' | sort)" = "$before_backups"
    test -f /tmp/timer-active
    test -f /tmp/monitor-timer-active
    assert_pending_journal
}
path_contents() {
    if [[ -d $1 ]]; then
        tar -C "$1" -cf - . | sha256sum
    else
        sha256sum <"$1"
    fi
}
exercise_unsafe_path() {
    local path=$1 safe_mode=$2 unsafe_mode=$3 before target
    # Audit content must remain unchanged even while this one path's metadata
    # is intentionally unsafe; the caller verifies that the fault is retained.
    local audit_unsafe_path=$path
    chmod "$unsafe_mode" "$path"
    before=$(path_contents "$path")
    assert_preflight_refused
    test "$(stat -c %a "$path")" = "$unsafe_mode"
    test "$(path_contents "$path")" = "$before"
    chmod "$safe_mode" "$path"

    target=$(mktemp -d /tmp/cgp-permission-target-XXXXXXXX)
    rmdir "$target"
    mv "$path" "$target"
    ln -s "$target" "$path"
    before=$(path_contents "$target")
    assert_preflight_refused
    test -L "$path"
    test "$(path_contents "$target")" = "$before"
    rm "$path"
    mv "$target" "$path"

    chown 65534:65534 "$path"
    before=$(path_contents "$path")
    assert_preflight_refused
    test "$(stat -c %u "$path")" = 65534
    test "$(path_contents "$path")" = "$before"
    chown 0:0 "$path"
}
install -d -m 700 /var/lib/cgp-letsencrypt/backups /var/lib/cgp-letsencrypt/backups/example.com
backup_fixture=/var/lib/cgp-letsencrypt/backups/example.com/synthetic.json
printf '%s\n' '{"synthetic":"private backup"}' >"$backup_fixture"
chmod 600 "$backup_fixture"
exercise_unsafe_path "$config" 600 644
exercise_unsafe_path /etc/cgp-letsencrypt/cloudflare.ini 600 644
exercise_unsafe_path /var/lib/cgp-letsencrypt 700 755
exercise_unsafe_path /var/lib/cgp-letsencrypt/run.lock 600 644
exercise_unsafe_path /var/lib/cgp-letsencrypt/backups 700 755
exercise_unsafe_path "$backup_fixture" 600 644
audit_fixture=$(python3 -c 'import json; print(json.load(open("/tmp/cgp-resolution-expected/manifest.json"))["completed"] + "/authorization.json")')
exercise_unsafe_path /var/lib/cgp-letsencrypt/resolutions 700 755
exercise_unsafe_path "$audit_fixture" 600 644
exercise_unsafe_path "$monitor_config" 600 644
exercise_unsafe_path "$monitor_state" 700 755
exercise_unsafe_path "$monitor_state/run.lock" 600 644
exercise_unsafe_path "$monitor_evidence" 600 644
assert_audit_archives
assert_monitor_data
test ! -e /tmp/cgp-installer-network-attempted

echo 'Installer integration scenarios passed.'
