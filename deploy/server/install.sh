#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Execute como root/sudo." >&2; exit 1; }

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED_SHA="${EXPECTED_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
APP_ROOT=/opt/bots-central
RELEASE_DIR="$APP_ROOT/releases/$EXPECTED_SHA"
CURRENT_LINK="$APP_ROOT/current"
VENV_ROOT="$APP_ROOT/venvs"
ETC_ROOT=/etc/bots-central
STATE_ROOT=/var/lib/bots-central
SERVICE_USER=bots-central

git -C "$REPO_ROOT" cat-file -e "$EXPECTED_SHA^{commit}"
git -C "$REPO_ROOT" archive "$EXPECTED_SHA" >/dev/null

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$STATE_ROOT" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0755 "$APP_ROOT" "$APP_ROOT/releases" "$VENV_ROOT"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$ETC_ROOT" "$ETC_ROOT/credentials"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$STATE_ROOT" "$STATE_ROOT/pc-artifacts"

if [[ ! -d "$RELEASE_DIR" ]]; then
  tmp="$(mktemp -d "$APP_ROOT/releases/.tmp.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$REPO_ROOT" archive "$EXPECTED_SHA" | tar -x -C "$tmp"
  printf '%s\n' "$EXPECTED_SHA" > "$tmp/.deploy-sha"
  mv "$tmp" "$RELEASE_DIR"
  trap - EXIT
fi

# mktemp cria o diretório temporário com modo 0700. Após o mv, a release
# preserva esse modo e o usuário de serviço não consegue atravessá-la.
# Código versionado não contém secrets; permita leitura/travessia do serviço.
find "$RELEASE_DIR" -type d -exec chmod 0755 {} +
find "$RELEASE_DIR" -type f -exec chmod a+r {} +

for spec in   "$ETC_ROOT/gmail-config.py:$RELEASE_DIR/Ativos/gmail-telegram/config.example.py"   "$ETC_ROOT/studies-config.py:$RELEASE_DIR/Ativos/estudos/config.example.py"; do
  target="${spec%%:*}"; source="${spec#*:}"
  if [[ ! -e "$target" ]]; then
    cp "$source" "$target"
    chown "$SERVICE_USER:$SERVICE_USER" "$target"
    chmod 0600 "$target"
  fi
done

ln -sfn "$ETC_ROOT/gmail-config.py" "$RELEASE_DIR/Ativos/gmail-telegram/config.py"
ln -sfn "$ETC_ROOT/credentials" "$RELEASE_DIR/Ativos/gmail-telegram/credentials"
ln -sfn "$STATE_ROOT/gmail_bot.db" "$RELEASE_DIR/Ativos/gmail-telegram/gmail_bot.db"
rm -f "$RELEASE_DIR/Ativos/estudos/config.py"\ninstall -o root -g root -m 0644 "$ETC_ROOT/studies-config.py" "$RELEASE_DIR/Ativos/estudos/config.py"

if [[ ! -f "$ETC_ROOT/bots-central.env" ]]; then
  cp "$SCRIPT_DIR/bots-central.env.example" "$ETC_ROOT/bots-central.env"
  chown "$SERVICE_USER:$SERVICE_USER" "$ETC_ROOT/bots-central.env"
  chmod 0600 "$ETC_ROOT/bots-central.env"
  echo "Criado $ETC_ROOT/bots-central.env. Preencha antes de ativar." >&2
fi
if [[ ! -f "$ETC_ROOT/studies.env" ]]; then
  cp "$SCRIPT_DIR/studies.env.example" "$ETC_ROOT/studies.env"
  chown "$SERVICE_USER:$SERVICE_USER" "$ETC_ROOT/studies.env"
  chmod 0600 "$ETC_ROOT/studies.env"
  echo "Criado $ETC_ROOT/studies.env. Preencha antes de ativar." >&2
fi

python3 -m venv "$VENV_ROOT/gmail"
"$VENV_ROOT/gmail/bin/python" -m pip install --disable-pip-version-check -q --upgrade pip
"$VENV_ROOT/gmail/bin/pip" install --disable-pip-version-check -q -r "$RELEASE_DIR/Ativos/gmail-telegram/requirements.txt"

python3 -m venv "$VENV_ROOT/studies"
"$VENV_ROOT/studies/bin/python" -m pip install --disable-pip-version-check -q --upgrade pip
"$VENV_ROOT/studies/bin/pip" install --disable-pip-version-check -q -r "$RELEASE_DIR/Ativos/estudos/requirements.txt"

ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"
chown -R root:root "$RELEASE_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_ROOT" "$ETC_ROOT"

install -m 0644 "$SCRIPT_DIR/bots-central.service" /etc/systemd/system/bots-central.service
install -m 0644 "$SCRIPT_DIR/bots-central-studies.service" /etc/systemd/system/bots-central-studies.service
systemctl daemon-reload

echo "Instalação preparada em $RELEASE_DIR"
echo "Current -> $EXPECTED_SHA"
echo "Preencha /etc/bots-central/*.env e configs persistentes; depois rode activate.sh"
