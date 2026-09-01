#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Execute como root/sudo." >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT=/opt/bots-central/current

[[ -L "$CURRENT" ]] || { echo "Instalação não preparada: $CURRENT ausente." >&2; exit 1; }

REPO_ROOT="$CURRENT" bash "$ROOT/preflight.sh"

grep -q 'usuario@gmail.com' /etc/bots-central/gmail-config.py 2>/dev/null && {
  echo "gmail-config.py ainda contém a conta de exemplo usuario@gmail.com." >&2
  exit 1
}

for env_file in /etc/bots-central/bots-central.env /etc/bots-central/studies.env; do
  chmod 0600 "$env_file"
done

/opt/bots-central/venvs/gmail/bin/python -m compileall -q   "$CURRENT/Ativos/gmail-telegram" "$CURRENT/Ativos/shared_core"
/opt/bots-central/venvs/studies/bin/python -m compileall -q   "$CURRENT/Ativos/estudos" "$CURRENT/Ativos/shared_core"

systemctl enable bots-central.service bots-central-studies.service
systemctl restart bots-central.service bots-central-studies.service
sleep 3

failed=0
for unit in bots-central.service bots-central-studies.service; do
  if systemctl is-active --quiet "$unit"; then
    echo "OK   $unit ativo"
  else
    echo "FAIL $unit não iniciou" >&2
    journalctl -u "$unit" -n 60 --no-pager >&2 || true
    failed=1
  fi
done
exit "$failed"
