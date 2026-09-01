#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bunker-env.sh"

require_alert

# Executa limpeza
apt-get clean
apt-get autoremove -y

DISK=$(df -h / | awk "NR==2 { print \$4 }")

send_alert "LIMPEZA CONCLUIDA" "O cache do sistema foi limpo. Espaco livre: $DISK"
