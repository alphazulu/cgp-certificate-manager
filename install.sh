#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
test -f /etc/cgp-letsencrypt/config.json
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
echo "Backup: $b"
echo 'Timer left stopped. Run --doctor, --plan and --verify, then systemctl enable --now cgp-letsencrypt.timer'
