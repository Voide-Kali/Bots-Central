#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_OWNER="$(stat -c '%U' "$PROJECT_DIR")"
TARGET_USER="${KALI_BUNKER_USER:-${SUDO_USER:-$PROJECT_OWNER}}"
RUNTIME_DIR="${KALI_BUNKER_RUNTIME_DIR:-/opt/kali-bunker}"
SYSTEM_CONFIG="${KALI_BUNKER_SYSTEM_CONFIG:-/etc/kali-bunker/kali-bunker.env}"
SYSTEMD_INSTALL_DIR="/etc/systemd/system"
ENABLE_TELEGRAM="${KALI_BUNKER_ENABLE_TELEGRAM:-0}"

log() {
  printf '[kali-bunker] %s\n' "$*"
}

fail() {
  printf '[kali-bunker] ERRO: %s\n' "$*" >&2
  exit 1
}

if [[ $EUID -ne 0 ]]; then
  fail "execute com sudo: sudo ./install.sh"
fi

case "$ENABLE_TELEGRAM" in
  0|1) ;;
  *) fail "KALI_BUNKER_ENABLE_TELEGRAM deve ser 0 ou 1" ;;
esac

[[ "$RUNTIME_DIR" == /* && "$RUNTIME_DIR" != "/" ]] || \
  fail "KALI_BUNKER_RUNTIME_DIR deve ser um caminho absoluto dedicado"
RUNTIME_PARENT="$(dirname -- "$RUNTIME_DIR")"
RUNTIME_BASENAME="$(basename -- "$RUNTIME_DIR")"
[[ "$RUNTIME_PARENT" != "/" ]] || fail "use um subdiretorio dedicado para o runtime"
[[ "$RUNTIME_BASENAME" != "." && "$RUNTIME_BASENAME" != ".." ]] || \
  fail "nome do runtime invalido"

passwd_entry="$(getent passwd "$TARGET_USER" 2>/dev/null || true)"
[[ -n "$passwd_entry" ]] || fail "usuario alvo invalido: $TARGET_USER"
IFS=: read -r _ _ _ _ _ TARGET_HOME _ <<< "$passwd_entry"
TARGET_GROUP="$(id -gn "$TARGET_USER" 2>/dev/null || true)"
[[ -n "$TARGET_HOME" && -n "$TARGET_GROUP" ]] || fail "nao foi possivel resolver home/grupo de $TARGET_USER"

if [[ -r "$PROJECT_DIR/.env" ]]; then
  CONFIG_SOURCE="$PROJECT_DIR/.env"
elif [[ -r "$TARGET_HOME/.config/kali-bunker/.env" ]]; then
  CONFIG_SOURCE="$TARGET_HOME/.config/kali-bunker/.env"
else
  fail "configure .env antes de instalar (use .env.example como base)"
fi

runtime_python_files=(
  action_policy.py
  bluetooth_alarm.py
  bunker_audit.py
  bunker_config.py
  bunker_health.py
  bunkerctl.py
  dashboard.py
  health_monitor.py
  monitor-auth.py
  monitor-recursos.py
  monitor-wifi.py
  notifica_boot.py
  notifica_shutdown.py
  notifier.py
  remote_control.py
  runtime_integrity.py
  state_utils.py
  telegram_control.py
  voice_vault.py
)
runtime_shell_files=(
  bunker-env.sh
  limpeza-semanal.sh
  monitor-arquivos.sh
  network-watch.sh
  relatorio-semanal.sh
  kb
  bunker-menu
)

for required_file in "${runtime_python_files[@]}" "${runtime_shell_files[@]}" requirements.txt install_support.py; do
  [[ -f "$PROJECT_DIR/$required_file" ]] || fail "arquivo obrigatorio ausente: $required_file"
done

config_flags="$(
  python3 "$PROJECT_DIR/install_support.py" \
    check-config "$CONFIG_SOURCE" "$TARGET_HOME"
)"
read -r alert_ok iphone_ok protected_dir_ok telegram_polling_ok <<< "$config_flags"

[[ "$alert_ok" == "1" ]] || fail "credenciais do provedor de alertas incompletas no .env"
if [[ "$ENABLE_TELEGRAM" == "1" && "$telegram_polling_ok" != "1" ]]; then
  fail "polling Telegram solicitado sem token e chat autorizado"
fi

log "Origem: $PROJECT_DIR"
log "Usuario operacional: $TARGET_USER"
log "Runtime protegido: $RUNTIME_DIR"

packages=()
for spec in \
  python3:python3 \
  nmap:nmap \
  arp-scan:arp-scan \
  iptables:iptables \
  ip:iproute2 \
  curl:curl \
  inotifywait:inotify-tools \
  bluetoothctl:bluez \
  fswebcam:fswebcam \
  v4l2-ctl:v4l-utils; do
  command_name="${spec%%:*}"
  package_name="${spec#*:}"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    packages+=("$package_name")
  fi
done

if ! python3 -m venv --help >/dev/null 2>&1; then
  packages+=(python3-venv)
fi

if ((${#packages[@]})); then
  command -v apt-get >/dev/null 2>&1 || fail "dependencias ausentes e apt-get indisponivel: ${packages[*]}"
  log "Instalando dependencias do sistema: ${packages[*]}"
  apt-get update
  apt-get install -y "${packages[@]}"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 nao foi instalado"
python3 -m venv --help >/dev/null 2>&1 || fail "modulo venv indisponivel"

log "Preparando runtime root-owned em area temporaria"
install -d -o root -g root -m 0755 "$RUNTIME_PARENT"
runtime_stage="$(mktemp -d "$RUNTIME_PARENT/.${RUNTIME_BASENAME}.stage.XXXXXX")"
unit_stage="$(mktemp -d /tmp/kali-bunker-units.XXXXXX)"
chmod 0755 "$runtime_stage"

cleanup_stage() {
  if [[ -n "${runtime_stage:-}" && -d "$runtime_stage" ]]; then
    rm -r -- "$runtime_stage"
  fi
  if [[ -n "${unit_stage:-}" && -d "$unit_stage" ]]; then
    rm -r -- "$unit_stage"
  fi
}
trap cleanup_stage EXIT

for runtime_file in "${runtime_python_files[@]}" "${runtime_shell_files[@]}"; do
  install -o root -g root -m 0755 "$PROJECT_DIR/$runtime_file" "$runtime_stage/$runtime_file"
done
install -o root -g root -m 0644 "$PROJECT_DIR/requirements.txt" "$runtime_stage/requirements.txt"

python3 -m venv "$runtime_stage/.venv"
"$runtime_stage/.venv/bin/python" -m pip install \
  --disable-pip-version-check \
  --requirement "$runtime_stage/requirements.txt"
# O pkexec pode aplicar umask 0077. O runtime continua root-owned e sem escrita
# para outros usuarios, mas os servicos operacionais precisam atravessar o
# venv e ler suas bibliotecas.
chmod -R u=rwX,go=rX "$runtime_stage/.venv"
RUNTIME_PYTHON="$RUNTIME_DIR/.venv/bin/python"

log "Renderizando unidades systemd"
systemd_files=()
for source_unit in "$PROJECT_DIR"/systemd/*.service "$PROJECT_DIR"/systemd/*.timer; do
  unit_name="$(basename "$source_unit")"
  systemd_files+=("$unit_name")
  python3 "$PROJECT_DIR/install_support.py" render-unit \
    "$source_unit" "$unit_stage/$unit_name" \
    --user "$TARGET_USER" \
    --group "$TARGET_GROUP" \
    --home "$TARGET_HOME" \
    --runtime "$RUNTIME_DIR" \
    --python "$RUNTIME_PYTHON" \
    --config "$SYSTEM_CONFIG"
done
chmod 0644 "$unit_stage"/*

log "Protegendo configuracao do sistema"
install -d -o root -g root -m 0755 "$(dirname "$SYSTEM_CONFIG")"
install -o root -g root -m 0600 "$CONFIG_SOURCE" "$SYSTEM_CONFIG"

USER_CONFIG="$TARGET_HOME/.config/kali-bunker/.env"
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 0700 "$(dirname "$USER_CONFIG")"
if [[ "$(readlink -f -- "$CONFIG_SOURCE")" != "$(readlink -m -- "$USER_CONFIG")" ]]; then
  install -o "$TARGET_USER" -g "$TARGET_GROUP" -m 0600 "$CONFIG_SOURCE" "$USER_CONFIG"
else
  chown "$TARGET_USER:$TARGET_GROUP" "$USER_CONFIG"
  chmod 0600 "$USER_CONFIG"
fi

log "Preparando estado local"
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 0700 \
  "$TARGET_HOME/.local/state/kali-bunker"

log "Instalando unidades systemd renderizadas"
install -o root -g root -m 0644 "$unit_stage"/* "$SYSTEMD_INSTALL_DIR/"

log "Gerando manifesto SHA-256 sem incluir segredos ou ambiente virtual"
manifest_command=(
  python3 "$PROJECT_DIR/install_support.py" write-manifest
  --runtime-source "$runtime_stage"
  --runtime-install "$RUNTIME_DIR"
  --systemd-source "$SYSTEMD_INSTALL_DIR"
  --systemd-install "$SYSTEMD_INSTALL_DIR"
  --output "$runtime_stage/runtime-manifest.json"
)
for runtime_file in "${runtime_python_files[@]}" "${runtime_shell_files[@]}" requirements.txt; do
  manifest_command+=(--runtime-file "$runtime_file")
done
for unit_name in "${systemd_files[@]}"; do
  manifest_command+=(--systemd-file "$unit_name")
done
"${manifest_command[@]}"

log "Promovendo runtime preparado"
runtime_previous="$RUNTIME_PARENT/.${RUNTIME_BASENAME}.previous"
if [[ -e "$runtime_previous" || -L "$runtime_previous" ]]; then
  rm -rf -- "$runtime_previous"
fi
had_previous=0
if [[ -e "$RUNTIME_DIR" || -L "$RUNTIME_DIR" ]]; then
  [[ -d "$RUNTIME_DIR" && ! -L "$RUNTIME_DIR" ]] || \
    fail "runtime existente deve ser um diretorio real: $RUNTIME_DIR"
  mv -T -- "$RUNTIME_DIR" "$runtime_previous"
  had_previous=1
fi
if ! mv -T -- "$runtime_stage" "$RUNTIME_DIR"; then
  if [[ "$had_previous" == "1" && ! -e "$RUNTIME_DIR" ]]; then
    mv -T -- "$runtime_previous" "$RUNTIME_DIR"
  fi
  fail "nao foi possivel promover o runtime preparado"
fi
runtime_stage=""

"$RUNTIME_PYTHON" "$RUNTIME_DIR/runtime_integrity.py"
if [[ "$had_previous" == "1" ]]; then
  log "Runtime anterior preservado para rollback em $runtime_previous"
fi

cleanup_stage
unit_stage=""
trap - EXIT

log "Instalando comandos operacionais"
ln -sfnT "$RUNTIME_DIR/kb" /usr/local/bin/kb
ln -sfnT "$RUNTIME_DIR/kb" /usr/local/bin/bunkerctl
ln -sfnT "$RUNTIME_DIR/bunker-menu" /usr/local/bin/bunker-menu
cat > /usr/local/bin/bunker-dashboard <<EOF
#!/bin/sh
export KALI_BUNKER_USER="$TARGET_USER"
export KALI_BUNKER_HOME="$TARGET_HOME"
exec "$RUNTIME_PYTHON" "$RUNTIME_DIR/dashboard.py" "\$@"
EOF
chmod 0755 /usr/local/bin/bunker-dashboard

# Muitos desktops priorizam ~/bin no PATH. Atualize somente links (ou caminhos
# ausentes), sem sobrescrever um comando regular criado pelo usuário.
install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 0755 "$TARGET_HOME/bin"
for command_name in kb bunkerctl bunker-menu; do
  user_command="$TARGET_HOME/bin/$command_name"
  if [[ ! -e "$user_command" || -L "$user_command" ]]; then
    ln -sfnT "/usr/local/bin/$command_name" "$user_command"
    chown -h "$TARGET_USER:$TARGET_GROUP" "$user_command"
  else
    log "Mantendo comando regular existente: $user_command"
  fi
done

user_unit_in_use() {
  local unit="$1"
  [[ -L "$TARGET_HOME/.config/systemd/user/default.target.wants/$unit" ]] && return 0
  systemctl --user --machine="${TARGET_USER}@" is-active --quiet "$unit" >/dev/null 2>&1
}

if [[ "$ENABLE_TELEGRAM" == "1" ]]; then
  for conflicting_unit in gmail-telegram-bot.service kali-bunker-telegram.service; do
    if user_unit_in_use "$conflicting_unit"; then
      fail "desative a unit de usuario $conflicting_unit antes de habilitar o polling de sistema"
    fi
  done
fi

log "Recarregando systemd"
systemctl daemon-reload

main_units=(
  monitor-auth.service
  monitor-recursos.service
  monitor-wifi.service
  network-watch.service
  kali-bunker-health.service
  limpeza-semanal.timer
  relatorio-semanal.timer
)

if [[ "$iphone_ok" == "1" ]]; then
  main_units+=(bt-alarm.service)
else
  systemctl disable --now bt-alarm.service >/dev/null 2>&1 || true
  log "Bluetooth nao habilitado: IPHONE_MAC esta vazio"
fi

if [[ "$protected_dir_ok" == "1" ]]; then
  main_units+=(monitor-arquivos.service)
else
  systemctl disable --now monitor-arquivos.service >/dev/null 2>&1 || true
  log "Monitor de arquivos nao habilitado: PROTECTED_DIR nao existe"
fi

log "Habilitando modulos validados"
systemctl enable "${main_units[@]}"
systemctl reset-failed "${main_units[@]}" >/dev/null 2>&1 || true
systemctl restart "${main_units[@]}"
systemctl enable notifica-boot.service
systemctl enable --now notifica-shutdown.service

if [[ "$ENABLE_TELEGRAM" == "1" ]]; then
  systemctl enable --now kali-bunker-telegram.service
else
  systemctl disable --now kali-bunker-telegram.service >/dev/null 2>&1 || true
  log "Polling Telegram legado desabilitado; alertas de saida continuam ativos"
fi

log "Instalacao concluida"
printf '\nComandos recomendados:\n'
printf '  kb install-check\n'
printf '  kb doctor\n'
printf '  kb overview\n'
