#!/bin/bash
# Run ONLY in the disposable container created by the CI installer job.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || { echo 'Disposable Docker container required'; exit 1; }
[[ -d /candidate && -d /baseline ]] || exit 1
export PATH=/mock-bin:$PATH
mkdir -p /mock-bin /etc/cgp-letsencrypt /etc/systemd/system /var/lib/cgp-letsencrypt
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

echo '=== clean install ==='
bash /candidate/install.sh --non-interactive
test -x "$launcher"
test "$("$launcher" --version)" = 2.1.0rc1
cmp "$config" /tmp/config.expected
grep -q '07,19:00:00' "$drop"
test "$(stat -c %a "$launcher")" = 750
test "$(stat -c %a "$config")" = 600
test "$(stat -c %a /var/lib/cgp-letsencrypt)" = 700
test ! -f /tmp/timer-active

echo '=== clean installation failure restores absent application ==='
rm -rf "$app" "$launcher" "$drop" /etc/systemd/system/cgp-letsencrypt.{service,timer}
touch /tmp/fail-reload-once
must_fail bash /candidate/install.sh --non-interactive
test ! -e "$app"
test ! -e "$launcher"
test ! -e "$drop"
cmp "$config" /tmp/config.expected

echo '=== install actual baseline 2.0.1 ==='
bash /baseline/install.sh
test "$("$launcher" --version)" = 2.0.1
touch "$app/cgp_cert_manager/stale.py"
echo 'persistent-state' >/var/lib/cgp-letsencrypt/sentinel
touch /tmp/timer-active
cp "$config" /tmp/config.before-upgrade

echo '=== upgrade failure restores baseline and active timer ==='
touch /tmp/fail-reload-once
must_fail bash /candidate/install.sh --upgrade
test "$("$launcher" --version)" = 2.0.1
test -f "$app/cgp_cert_manager/stale.py"
test -f /tmp/timer-active
cmp "$config" /tmp/config.before-upgrade

echo '=== running operation rejects upgrade without stopping timer ==='
(
  flock -n 9
  must_fail bash /candidate/install.sh --upgrade
) 9>>/var/lib/cgp-letsencrypt/run.lock
test -f /tmp/timer-active
test "$("$launcher" --version)" = 2.0.1
touch /tmp/service-active
must_fail bash /candidate/install.sh --upgrade
rm /tmp/service-active
test -f /tmp/timer-active

echo '=== successful upgrade ==='
bash /candidate/install.sh --upgrade
test "$("$launcher" --version)" = 2.1.0rc1
test ! -e "$app/cgp_cert_manager/stale.py"
test ! -f /tmp/timer-active
cmp "$config" /tmp/config.before-upgrade
grep -q persistent-state /var/lib/cgp-letsencrypt/sentinel
grep -q '07,19:00:00' "$drop"
grep -q 'dummy' /etc/cgp-letsencrypt/cloudflare.ini

echo '=== invalid schedule rejected before modifying files ==='
cp "$config" /tmp/valid-config
python3 -c 'import json; p="/etc/cgp-letsencrypt/config.json"; c=json.load(open(p)); c["schedule"]["hour"]=24; json.dump(c,open(p,"w"))'
touch /tmp/timer-active
must_fail bash /candidate/install.sh --upgrade
test -f /tmp/timer-active
test "$("$launcher" --version)" = 2.1.0rc1
cp /tmp/valid-config "$config"

echo 'Installer integration scenarios passed.'
