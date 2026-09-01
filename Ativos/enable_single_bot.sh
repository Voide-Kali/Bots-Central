#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./enable_single_bot.sh [SERVICE]
# Example: sudo ./enable_single_bot.sh gmail-telegram-bot.service

KEEP="${1:-gmail-telegram-bot.service}"
TO_DISABLE=(
  estudos-bot.service
  lembrete-bot.service
  kali-bunker-pc-agent.service
)

echo "Manter ativo: $KEEP"

for s in "${TO_DISABLE[@]}"; do
  if [ "$s" != "$KEEP" ]; then
    echo "Parando e desabilitando: $s"
    systemctl stop "$s" || true
    systemctl disable "$s" || true
  fi
done

echo "Recarregando systemd e habilitando/iniciando: $KEEP"
systemctl daemon-reload
systemctl enable --now "$KEEP"

echo "Status do serviço $KEEP:"
systemctl status "$KEEP" --no-pager || true

echo "Últimas 200 linhas do journal do serviço $KEEP:"
journalctl -u "$KEEP" -n 200 --no-pager || true

echo "Concluído. Se quiser reverter, execute: systemctl enable --now <SERVICE> para restaurar outro serviço."
