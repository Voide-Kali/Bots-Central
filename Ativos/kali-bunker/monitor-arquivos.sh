#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bunker-env.sh"

require_alert

PASTA_PROTEGIDA="${PROTECTED_DIR:-$HOME/Documentos}"
ULTIMO_ALERTA=0

if [[ ! -d "$PASTA_PROTEGIDA" ]]; then
    echo "Pasta protegida nao encontrada: $PASTA_PROTEGIDA" >&2
    exit 1
fi

inotifywait -m -r -e access -e open "$PASTA_PROTEGIDA" --format '%f' | while read FILE
do
    if [[ "$FILE" != .* ]]; then
        AGORA=$(date +%s)
        # Só envia mensagem se passou 5 segundos desde a última
        if (( AGORA - ULTIMO_ALERTA > 5 )); then
            send_alert "ARQUIVO ACESSADO!" "O arquivo $FILE foi aberto em Documentos."
            ULTIMO_ALERTA=$AGORA
        fi
    fi
done
