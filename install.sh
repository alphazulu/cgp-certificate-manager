#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $EUID == 0 ]] || { echo 'Run as root'; exit 1; }
[[ $(pwd -P) != /opt/cgp-certificate-manager ]] || { echo "Extract into /tmp first"; exit 1; }
export PYTHONDONTWRITEBYTECODE=1
# Refuse a pending application update before the wizard or any installer writes.
python3 -B - <<'UPDATE_GUARD'
import sys
from cgp_cert_manager.update_gate import PendingUpdateError, require_idle
try:
    require_idle()
except PendingUpdateError as error:
    print('Installation refused: ' + str(error), file=sys.stderr)
    sys.exit(1)
UPDATE_GUARD
python3 -m compileall -q cgp_cert_manager
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
# Validate storage and retain a secure operation lock across the shell payload.
exec python3 -m cgp_cert_manager.installer
