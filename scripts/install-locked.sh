#!/bin/bash
# Internal payload. The parent Python process and inherited descriptors retain
# both secure operation locks until installation/rollback finishes.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
[[ $# == 2 ]] || { echo 'Both installer lock descriptors required'; exit 2; }
python3 -m cgp_cert_manager.installer --check-lock "$1" "$2"
umask 077
app=/opt/cgp-certificate-manager
conf=/etc/cgp-letsencrypt/config.json
bin=/usr/local/sbin/cgp-letsencrypt
certbot_bin=/usr/local/sbin/cgp-certbot
monitor_bin=/usr/local/sbin/cgp-monitor
units=/etc/systemd/system
dropin=$units/cgp-letsencrypt.timer.d/90-cgp-manager.conf
if systemctl is-active --quiet cgp-letsencrypt.service; then echo 'Service running; retry after completion'; exit 1; fi
if systemctl is-active --quiet cgp-monitor.service; then echo 'Monitor service running; retry after completion'; exit 1; fi
# Validate migration and schedule before stopping the timer or modifying files.
python3 -c 'from cgp_cert_manager.core import CONFIG,load; from cgp_cert_manager.cli import migrate; from cgp_cert_manager.schedule import render; cfg=migrate(load(CONFIG)); render(cfg.get("schedule",{}))'
# The inherited-lock checker has validated DNS options and native dependencies.
b=$(mktemp -d /root/cgp-manager-backup-XXXXXXXX)
installed_files=("$bin" "$certbot_bin" "$monitor_bin" "$conf" "$units/cgp-letsencrypt.service" "$units/cgp-letsencrypt.timer" "$dropin" "$units/cgp-monitor.service" "$units/cgp-monitor.timer")
for f in "${installed_files[@]}"; do
    if [[ -e $f ]]; then cp -a "$f" "$b/"; fi
done
if [[ -d $app ]]; then cp -a "$app" "$b/opt"; fi
timer_active=0
if systemctl is-active --quiet cgp-letsencrypt.timer; then timer_active=1; fi
monitor_timer_active=0
if systemctl is-active --quiet cgp-monitor.timer; then monitor_timer_active=1; fi
changed=0
success=0
restore_file() {
    local dest=$1 source="$b/$(basename "$1")"
    if [[ -e $source ]]; then
        mkdir -p "$(dirname "$dest")" && cp -a --remove-destination "$source" "$dest"
    else
        rm -f "$dest"
    fi
}
recover() {
    local rc=$? failed=0
    trap - EXIT HUP INT TERM
    if [[ $success == 1 ]]; then return; fi
    set +e
    if [[ $changed == 1 ]]; then
        rm -rf "$app" || failed=1
        if [[ -d $b/opt ]]; then cp -a "$b/opt" "$app" || failed=1; fi
        for f in "${installed_files[@]}"; do
            restore_file "$f" || failed=1
        done
        systemctl daemon-reload || failed=1
    fi
    # Do not restart an old timer until restoration has succeeded.
    if [[ $timer_active == 1 && $failed == 0 ]]; then
        systemctl start cgp-letsencrypt.timer || failed=1
    fi
    if [[ $monitor_timer_active == 1 && $failed == 0 ]]; then
        systemctl start cgp-monitor.timer || failed=1
    fi
    if [[ $failed == 0 ]]; then
        echo "Installation failed; previous application files restored if changed. Backup: $b" >&2
    else
        echo "CRITICAL: installation recovery incomplete. Backup: $b" >&2
    fi
    exit "$rc"
}
trap recover EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
if systemctl list-unit-files cgp-letsencrypt.timer --no-legend | grep -q '^cgp-letsencrypt.timer'; then
    systemctl stop cgp-letsencrypt.timer
fi
if systemctl list-unit-files cgp-monitor.timer --no-legend | grep -q '^cgp-monitor.timer'; then
    systemctl stop cgp-monitor.timer
fi
if systemctl is-active --quiet cgp-letsencrypt.service; then echo 'Service running; retry after completion'; exit 1; fi
if systemctl is-active --quiet cgp-monitor.service; then echo 'Monitor service running; retry after completion'; exit 1; fi
changed=1
install -d -m 755 "$app"
# Replace the package so stale files from older releases cannot be imported.
rm -rf "$app/cgp_cert_manager"
rm -rf "$app"/cgp_certbot_dns-*.dist-info
cp -a cgp_cert_manager "$app/"
cp -a cgp_certbot_dns-*.dist-info "$app/"
install -m 750 launcher "$bin"
install -m 750 certbot-launcher "$certbot_bin"
install -m 750 monitor-launcher "$monitor_bin"
install -m 644 systemd/* "$units/"
# Run under the existing lock, avoiding nested CLI flock acquisition.
(cd "$app" && /usr/bin/python3 -c 'from cgp_cert_manager.core import CONFIG,load,atomic; from cgp_cert_manager.cli import migrate; atomic(CONFIG,migrate(load(CONFIG)))')
systemctl daemon-reload
(cd "$app" && /usr/bin/python3 -c 'from cgp_cert_manager.schedule import apply; apply()')
"$bin" --version
"$monitor_bin" --version
success=1
echo "Backup: $b"
echo 'Timer left stopped. Run --doctor, --plan and --verify, then systemctl enable --now cgp-letsencrypt.timer'
echo 'Monitor timer left stopped. Configure cgp-monitor and check --check-config and --probe before explicitly enabling cgp-monitor.timer. Notifications require --run --send.'
