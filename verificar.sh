#!/usr/bin/env bash
set -u

declare -A paths=(
  [gmail-telegram]="/home/voide/Projetos/gmail-telegram-bot"
  [estudos]="/home/voide/Projetos/estudos-bot"
  [lembrete]="/home/voide/Projetos/lembrete-bot"
  [kali-legado]="/home/voide/Kali-Bunker-main"
)

declare -A services=(
  [gmail-telegram]="gmail-telegram-bot.service"
  [estudos]="estudos-bot.service"
  [lembrete]="lembrete-bot.service"
  [kali-legado]="kali-bunker-telegram.service"
)

declare -A env_files=(
  [gmail-telegram]="/home/voide/Kali-Bunker-main/.env"
  [estudos]="/home/voide/Projetos/estudos-bot/.env"
  [lembrete]="/home/voide/Projetos/lembrete-bot/.env"
  [kali-legado]="/home/voide/Kali-Bunker-main/.env"
)

declare -A token_keys=(
  [gmail-telegram]="TELEGRAM_BOT_TOKEN"
  [estudos]="TELEGRAM_TOKEN"
  [lembrete]="LEMBRETE_TELEGRAM_TOKEN"
  [kali-legado]="TELEGRAM_BOT_TOKEN"
)

printf '%-18s %-9s %-11s %-14s %s\n' "BOT" "ARQUIVOS" "CONFIG" "SERVIÇO" "AUTOSTART"

for bot in gmail-telegram estudos lembrete kali-legado; do
  if [[ -d "${paths[$bot]}" ]]; then
    files="OK"
  else
    files="FALHA"
  fi

  if grep -Eq "^${token_keys[$bot]}=.+$" "${env_files[$bot]}" 2>/dev/null; then
    config="OK"
  else
    config="SEM TOKEN"
  fi

  service="${services[$bot]}"
  if systemctl --user is-active --quiet "$service" 2>/dev/null; then
    state="ATIVO"
  else
    state="$(systemctl --user is-active "$service" 2>/dev/null || true)"
    case "$state" in
      inactive) state="INATIVO" ;;
      failed) state="FALHA" ;;
      activating) state="INICIANDO" ;;
      deactivating) state="PARANDO" ;;
      "") state="INDISPONÍVEL" ;;
    esac
  fi

  enabled="$(systemctl --user is-enabled "$service" 2>/dev/null || true)"
  case "$enabled" in
    enabled) enabled="SIM" ;;
    disabled) enabled="NÃO" ;;
    "") enabled="INDISP." ;;
  esac

  printf '%-18s %-9s %-11s %-14s %s\n' "$bot" "$files" "$config" "$state" "$enabled"
done
