#!/bin/bash

USER_KEY="u2qzmnz761dxbrs3b3y14i143j7v61"
API_TOKEN="agjsv1wivgccbqmvmjwb69d6hf4k1j"
PASTA_PROTEGIDA="/home/voide/Documentos"
ULTIMO_ALERTA=0

inotifywait -m -r -e access -e open "$PASTA_PROTEGIDA" --format '%f' | while read FILE
do
    if [[ "$FILE" != .* ]]; then
        AGORA=$(date +%s)
        # Só envia mensagem se passou 5 segundos desde a última
        if (( AGORA - ULTIMO_ALERTA > 5 )); then
            curl -s \
                --form-string "token=$API_TOKEN" \
                --form-string "user=$USER_KEY" \
                --form-string "title=🕵️ ARQUIVO ACESSADO!" \
                --form-string "message=O arquivo $FILE foi aberto em Documentos." \
                --form-string "priority=1" \
                --form-string "sound=magic" \
                https://api.pushover.net/1/messages.json > /dev/null
            ULTIMO_ALERTA=$AGORA
        fi
    fi
done
