#!/bin/bash

set -a
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
elif [[ -f "/home/voide/.env" ]]; then
  # shellcheck disable=SC1091
  source "/home/voide/.env"
elif [[ -f "$HOME/.config/kali-bunker/.env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.config/kali-bunker/.env"
fi

set +a

require_pushover() {
  if [[ -z "${PUSHOVER_TOKEN:-}" || -z "${PUSHOVER_USER:-}" ]]; then
    echo "PUSHOVER_TOKEN/PUSHOVER_USER nao configurados. Crie um .env baseado em .env.example." >&2
    exit 1
  fi
}

require_provider() {
  local provider="${ALERT_PROVIDER:-telegram}"
  case "$provider" in
    telegram|pushover) ;;
    *)
      echo "ALERT_PROVIDER invalido: $provider. Use telegram ou pushover." >&2
      exit 1
      ;;
  esac
}

require_alert() {
  require_provider
  local provider="${ALERT_PROVIDER:-telegram}"
  if [[ "$provider" == "pushover" ]]; then
    require_pushover
    return
  fi

  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    echo "TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID nao configurados. Crie um .env baseado em .env.example." >&2
    exit 1
  fi
}

send_alert() {
  local title="$1"
  local message="$2"
  local attachment="${3:-}"
  local provider="${ALERT_PROVIDER:-telegram}"

  if [[ "$provider" == "pushover" ]]; then
    if [[ -n "$attachment" && -f "$attachment" ]]; then
      curl --fail --silent --show-error \
        --form-string "token=$PUSHOVER_TOKEN" \
        --form-string "user=$PUSHOVER_USER" \
        --form-string "title=$title" \
        --form-string "message=$message" \
        -F "attachment=@$attachment" \
        https://api.pushover.net/1/messages.json > /dev/null
    else
      curl --fail --silent --show-error \
      --form-string "token=$PUSHOVER_TOKEN" \
      --form-string "user=$PUSHOVER_USER" \
      --form-string "title=$title" \
      --form-string "message=$message" \
      https://api.pushover.net/1/messages.json > /dev/null
    fi
    return
  fi

  if [[ -n "$attachment" && -f "$attachment" ]]; then
    curl --fail --silent --show-error \
      -F "chat_id=$TELEGRAM_CHAT_ID" \
      -F "caption=$title

$message" \
      -F "photo=@$attachment" \
      "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto" > /dev/null
  else
    curl --fail --silent --show-error \
      --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" \
      --data-urlencode "text=$title

$message" \
      "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" > /dev/null
  fi
}
