#!/usr/bin/env bash
set -euo pipefail

declare -A units=(
  [gmail]="gmail-telegram-bot.service"
  [estudos]="estudos-bot.service"
  [lembrete]="lembrete-bot.service"
  [kali-legado]="kali-bunker-telegram.service"
)

usage() {
  cat <<'EOF'
Uso:
  gerenciar.sh status
  gerenciar.sh BOT ligar|parar|reiniciar|ativar|desativar|logs

Bots: gmail, estudos, lembrete, kali-legado

"ativar" habilita no boot e inicia agora.
"desativar" para agora e desabilita no boot.
EOF
}

if [[ ${1:-} == "status" ]]; then
  exec "$(dirname "$0")/verificar.sh"
fi

bot="${1:-}"
action="${2:-}"
unit="${units[$bot]:-}"
if [[ -z "$unit" || -z "$action" ]]; then
  usage
  exit 2
fi

starts_service=false
case "$action" in
  ligar|start|reiniciar|restart|ativar|enable) starts_service=true ;;
esac

if [[ "$bot" == "lembrete" && "$starts_service" == true ]]; then
  if ! grep -Eq '^LEMBRETE_TELEGRAM_TOKEN=.+$' /home/voide/Projetos/lembrete-bot/.env 2>/dev/null; then
    printf 'Lembrete não iniciado: configure um token exclusivo em Projetos/lembrete-bot/.env.\n' >&2
    exit 3
  fi
fi

if [[ "$starts_service" == true && "$bot" == "gmail" ]]; then
  if systemctl --user is-active --quiet kali-bunker-telegram.service || \
     systemctl --user is-enabled --quiet kali-bunker-telegram.service; then
    printf 'Operação recusada: desative kali-legado antes de ligar o Gmail central.\n' >&2
    exit 4
  fi
fi

if [[ "$starts_service" == true && "$bot" == "kali-legado" ]]; then
  if systemctl --user is-active --quiet gmail-telegram-bot.service || \
     systemctl --user is-enabled --quiet gmail-telegram-bot.service; then
    printf 'Operação recusada: Gmail central e Kali legado usam o mesmo token.\n' >&2
    exit 4
  fi
fi

case "$action" in
  ligar|start)
    systemctl --user start "$unit"
    ;;
  parar|stop)
    systemctl --user stop "$unit"
    ;;
  reiniciar|restart)
    systemctl --user restart "$unit"
    ;;
  ativar|enable)
    systemctl --user enable --now "$unit"
    ;;
  desativar|disable)
    systemctl --user disable --now "$unit"
    ;;
  logs)
    lines="${3:-80}"
    if ! [[ "$lines" =~ ^[0-9]+$ ]] || (( lines < 1 || lines > 500 )); then
      printf 'Quantidade de linhas deve estar entre 1 e 500.\n' >&2
      exit 2
    fi
    exec journalctl --user -u "$unit" -n "$lines" --no-pager
    ;;
  status)
    exec systemctl --user status "$unit" --no-pager
    ;;
  *)
    usage
    exit 2
    ;;
esac

systemctl --user is-active "$unit" || true
