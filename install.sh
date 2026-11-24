#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
mode=${1:---auto}
case "$mode" in
  --auto|--tui|--non-interactive|--upgrade) ;;
  *) echo "Usage: $0 [--tui|--non-interactive|--upgrade]"; exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
if [[ "$mode" == --auto && ! -f /etc/cgp-letsencrypt/config.json && -t 0 && -t 1 ]]; then
    mode=--tui
fi
if [[ "$mode" == --tui ]]; then
    command -v whiptail >/dev/null || { echo 'Install whiptail: apt install whiptail'; exit 1; }
    if python3 -m cgp_cert_manager.tui --setup; then
        :
    else
        rc=$?
        if [[ $rc -eq 3 || $rc -eq 130 ]]; then
            echo 'Installation cancelled; no application files or systemd units changed.'
            exit 0
        fi
        exit "$rc"
    fi
fi
test -f /etc/cgp-letsencrypt/config.json || { echo 'Create configuration or run install.sh --tui'; exit 1; }
[[ $(pwd -P) != /opt/cgp-certificate-manager ]] || { echo "Extract into /tmp first"; exit 1; }
umask 077
b=/root/cgp-manager-backup-$(date +%Y%m%d-%H%M%S)
mkdir -p "$b"
for f in /usr/local/sbin/cgp-letsencrypt /etc/cgp-letsencrypt/config.json /etc/systemd/system/cgp-letsencrypt.{service,timer}; do [[ ! -e $f ]] || cp -a "$f" "$b/"; done
if [[ -d /opt/cgp-certificate-manager ]]; then cp -a /opt/cgp-certificate-manager "$b/opt"; fi
systemctl stop cgp-letsencrypt.timer || true
if systemctl is-active --quiet cgp-letsencrypt.service; then echo 'Service running; retry after completion'; exit 1; fi
install -d -m 755 /opt/cgp-certificate-manager
cp -a cgp_cert_manager /opt/cgp-certificate-manager/
install -m 750 launcher /usr/local/sbin/cgp-letsencrypt
install -d -m 700 /var/lib/cgp-letsencrypt
/usr/local/sbin/cgp-letsencrypt --migrate
install -m 644 systemd/* /etc/systemd/system/
systemctl daemon-reload
/usr/local/sbin/cgp-letsencrypt --apply-schedule
echo "Backup: $b"
echo 'Timer left stopped. Run --doctor, --plan and --verify, then systemctl enable --now cgp-letsencrypt.timer'
