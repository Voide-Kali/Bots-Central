#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo bash enable_all_bots.sh
# Habilita e inicia todos os serviços de bots conhecidos

SERVICES=(
  gmail-telegram-bot.service
  estudos-bot.service
  lembrete-bot.service
  kali-bunker-pc-agent.service
)

echo "Recarregando systemd..."
systemctl daemon-reload

for s in "${SERVICES[@]}"; do
  echo "Habilitando e iniciando: $s"
  systemctl enable --now "$s" || true
done

echo
echo "Serviços ativos (filtrando por nome):"
systemctl list-units --type=service --state=running | egrep -i 'gmail|estudos|lembrete|kali-bunker|pc-agent' || true

echo
echo "Journals recentes do gmail-telegram-bot.service:"
journalctl -u gmail-telegram-bot.service -n 100 --no-pager || true

echo
echo "Concluído."
