#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Execute como root/sudo." >&2; exit 1; }
[[ $# -eq 1 ]] || { echo "Uso: $0 <sha-release>" >&2; exit 2; }

release="/opt/bots-central/releases/$1"
[[ -d "$release" && -f "$release/.deploy-sha" ]] || {
  echo "Release não encontrada: $release" >&2
  exit 1
}

ln -sfn "$release" /opt/bots-central/current
systemctl restart bots-central.service bots-central-studies.service
sleep 3
systemctl --no-pager --full status bots-central.service bots-central-studies.service || true

for unit in bots-central.service bots-central-studies.service; do
  systemctl is-active --quiet "$unit" || {
    echo "FAIL $unit não ficou ativo após rollback" >&2
    exit 1
  }
done

echo "Rollback ativo: $1"
