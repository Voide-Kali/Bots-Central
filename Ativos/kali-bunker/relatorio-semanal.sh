#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bunker-env.sh"

require_alert

# Coleta de dados
MEM=$(free -m | awk "/Mem:/ { print \$3 }")
DISK=$(df -h / | awk "NR==2 { print \$5 }")
CPU=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk "{print 100 - \$1}")
TEMP=$(sensors 2>/dev/null | grep "Package id 0" | awk "{print \$4}")

MESSAGE="STATUS DO KALI:
- RAM em uso: ${MEM}MB
- Disco: ${DISK} ocupado
- CPU: ${CPU}%
- Temp: ${TEMP}"

send_alert "RELATORIO DE SAUDE" "$MESSAGE"
