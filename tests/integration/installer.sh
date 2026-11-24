#!/bin/bash
# Run ONLY in the disposable container created by the CI installer job.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || { echo 'Disposable Docker container required'; exit 1; }
[[ -d /tmp/candidate-writable && -d /tmp/baseline-writable ]] || exit 1
export PATH=/mock-bin:$PATH
mkdir -p /mock-bin /etc/cgp-letsencrypt /etc/systemd/system
install -d -m 700 /var/lib/cgp-letsencrypt
cat >/mock-bin/systemctl <<'SH'
#!/bin/bash
set -eu
echo "$*" >> /tmp/systemctl.log
case "$1" in
  is-active)
    case "$*" in
      *cgp-letsencrypt.service*) test -f /tmp/service-active ;;
      *cgp-letsencrypt.timer*) test -f /tmp/timer-active ;;
      *) exit 1 ;;
    esac ;;
  list-unit-files)
    if [[ -f /etc/systemd/system/cgp-letsencrypt.timer ]]; then
      echo 'cgp-letsencrypt.timer enabled'
    fi ;;
  stop) rm -f /tmp/timer-active ;;
  start|restart) touch /tmp/timer-active ;;
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
cp "$journal" /tmp/pending.expected

echo '=== clean install ==='
bash /tmp/candidate-writable/install.sh --non-interactive
test -x "$launcher"
test "$("$launcher" --version)" = "$candidate_version"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.expected
grep -q '07,19:00:00' "$drop"
test "$(stat -c %a "$launcher")" = 750
test "$(stat -c %a "$config")" = 600
test "$(stat -c %a /var/lib/cgp-letsencrypt)" = 700
test ! -f /tmp/timer-active
assert_pending_journal

echo '=== clean installation failure restores absent application ==='
rm -rf "$app" "$launcher" "$drop" /etc/systemd/system/cgp-letsencrypt.{service,timer}
touch /tmp/fail-reload-once
must_fail bash /tmp/candidate-writable/install.sh --non-interactive
test ! -e "$app"
test ! -e "$launcher"
test ! -e "$drop"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.expected
assert_pending_journal

echo "=== install actual baseline $baseline_version ==="
bash /tmp/baseline-writable/install.sh
test "$("$launcher" --version)" = "$baseline_version"
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
test -f /tmp/timer-active
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.before-upgrade
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
test ! -e "$app/cgp_cert_manager/stale.py"
test ! -f /tmp/timer-active
python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == json.load(open(sys.argv[2]))' "$config" /tmp/config.before-upgrade
grep -q persistent-state /var/lib/cgp-letsencrypt/sentinel
grep -q '07,19:00:00' "$drop"
grep -q 'dummy' /etc/cgp-letsencrypt/cloudflare.ini
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

echo 'Installer integration scenarios passed.'
