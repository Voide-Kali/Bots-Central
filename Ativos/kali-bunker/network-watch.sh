#!/bin/bash
# Detecta mudança de rede sem confiar automaticamente em novos dispositivos.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bunker-env.sh"

require_alert

KNOWN_MACS="${KNOWN_MACS_FILE:-$HOME/macs_conhecidos.txt}"
WIFI_IFACE="${WIFI_INTERFACE:-wlan0}"
ARP_SCAN_BIN="${ARP_SCAN_BIN:-/usr/sbin/arp-scan}"
NETWORK_WATCH_INTERVAL="${NETWORK_WATCH_INTERVAL:-30}"
NETWORK_LEARN_DELAY="${NETWORK_LEARN_DELAY:-10}"
NETWORK_AUTO_LEARN="${NETWORK_AUTO_LEARN:-0}"
STATE_ROOT="${RUNTIME_DIRECTORY:-${KALI_BUNKER_STATE_DIR:-/run/kali-bunker}}"
REDE_ATUAL_FILE="$STATE_ROOT/network-current"
LOG_TAG="network-watch"
KNOWN_MACS_OWNER="$(stat -c '%u:%g' "$(dirname "$KNOWN_MACS")" 2>/dev/null || true)"

if [[ ! "$NETWORK_WATCH_INTERVAL" =~ ^[0-9]+$ || "$NETWORK_WATCH_INTERVAL" -lt 5 ]]; then
    echo "NETWORK_WATCH_INTERVAL deve ser um inteiro >= 5." >&2
    exit 1
fi

if [[ ! "$NETWORK_LEARN_DELAY" =~ ^[0-9]+$ ]]; then
    echo "NETWORK_LEARN_DELAY deve ser um inteiro." >&2
    exit 1
fi

case "$NETWORK_AUTO_LEARN" in
    0|1) ;;
    *)
        echo "NETWORK_AUTO_LEARN deve ser 0 ou 1." >&2
        exit 1
        ;;
esac

if [[ ! -x "$ARP_SCAN_BIN" ]]; then
    echo "arp-scan nao encontrado ou sem permissao de execucao: $ARP_SCAN_BIN" >&2
    exit 1
fi

mkdir -p "$STATE_ROOT" "$(dirname "$KNOWN_MACS")"
chmod 700 "$STATE_ROOT"
if [[ -L "$KNOWN_MACS" ]]; then
    echo "Arquivo de MACs conhecidos nao pode ser link simbolico: $KNOWN_MACS" >&2
    exit 1
fi
if [[ ! -e "$KNOWN_MACS" ]]; then
    install -m 0600 /dev/null "$KNOWN_MACS"
fi
if [[ -n "$KNOWN_MACS_OWNER" ]]; then
    chown "$KNOWN_MACS_OWNER" "$KNOWN_MACS" 2>/dev/null || true
fi
chmod 600 "$KNOWN_MACS"

get_ssid() {
    local ssid
    ssid=$(iwgetid "$WIFI_IFACE" -r 2>/dev/null || true)
    if [[ -z "$ssid" ]] && command -v nmcli >/dev/null 2>&1; then
        ssid=$(nmcli -t -f ACTIVE,SSID dev wifi 2>/dev/null | awk -F: '$1 == "yes" {print $2; exit}' || true)
    fi
    printf '%s\n' "$ssid"
}

get_gateway() {
    ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}' || true
}

aprender_rede() {
    local ssid="$1"
    local scan_output
    local temp_known
    temp_known="$(mktemp "$(dirname "$KNOWN_MACS")/.macs-conhecidos.XXXXXX")"
    echo "[$LOG_TAG] Aprendendo dispositivos da rede: $ssid"
    sleep "$NETWORK_LEARN_DELAY"
    if ! scan_output="$("$ARP_SCAN_BIN" --interface="$WIFI_IFACE" --localnet --ignoredups 2>/dev/null)"; then
        echo "[$LOG_TAG] Falha ao executar arp-scan." >&2
        rm -f "$temp_known"
        return 1
    fi

    awk '/^[0-9]/ {print toupper($2)}' <<< "$scan_output" > "$temp_known"
    mv "$temp_known" "$KNOWN_MACS"
    if [[ -n "$KNOWN_MACS_OWNER" ]]; then
        chown "$KNOWN_MACS_OWNER" "$KNOWN_MACS" 2>/dev/null || true
    fi
    chmod 600 "$KNOWN_MACS"
    local total
    total=$(wc -l < "$KNOWN_MACS")
    echo "[$LOG_TAG] $total dispositivos salvos como conhecidos."
    send_alert "🌐 REDE ALTERADA" "Conectado em: $ssid
$total dispositivos aprendidos como conhecidos." || true
    if ! systemctl restart monitor-wifi; then
        echo "[$LOG_TAG] Nao foi possivel reiniciar monitor-wifi." >&2
    fi
}

salvar_rede_atual() {
    local rede_id="$1"
    local temp_state
    temp_state="$(mktemp "$STATE_ROOT/.network-current.XXXXXX")"
    printf '%s\n' "$rede_id" > "$temp_state"
    chmod 600 "$temp_state"
    mv -fT "$temp_state" "$REDE_ATUAL_FILE"
}

echo "[$LOG_TAG] Iniciado. Monitorando mudanças de rede..."
REDE_ANTERIOR=""

if [[ -f "$REDE_ATUAL_FILE" && ! -L "$REDE_ATUAL_FILE" ]]; then
    IFS= read -r REDE_ANTERIOR < "$REDE_ATUAL_FILE" || true
fi

while true; do
    SSID=$(get_ssid)
    GATEWAY=$(get_gateway)
    REDE_ID="${SSID}__${GATEWAY}"

    if [[ -z "$SSID" ]]; then
        echo "[$LOG_TAG] Sem rede WiFi conectada..."
        sleep 15
        continue
    fi

    if [[ "$REDE_ID" != "$REDE_ANTERIOR" ]]; then
        echo "[$LOG_TAG] Mudança detectada: '$REDE_ANTERIOR' → '$REDE_ID'"
        salvar_rede_atual "$REDE_ID"
        if [[ "$NETWORK_AUTO_LEARN" == "1" ]]; then
            aprender_rede "$SSID"
        else
            send_alert "🌐 REDE ALTERADA" "Conectado em: $SSID
Gateway: ${GATEWAY:-desconhecido}

Novos dispositivos NAO foram marcados como confiaveis. Use 'sudo kb network learn' localmente para aprovar a rede." || true
        fi
        REDE_ANTERIOR="$REDE_ID"
    else
        echo "[$LOG_TAG] Rede atual: $SSID (sem mudança)"
    fi

    sleep "$NETWORK_WATCH_INTERVAL"
done
