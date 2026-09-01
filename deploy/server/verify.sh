#!/usr/bin/env bash
set -euo pipefail

units=(bots-central.service bots-central-studies.service)
failed=0

if [[ -L /opt/bots-central/current ]]; then
  target="$(readlink -f /opt/bots-central/current)"
  sha="$(cat "$target/.deploy-sha" 2>/dev/null || true)"
  echo "Deploy: ${sha:-desconhecido}"
  echo "Release: $target"
else
  echo "FAIL /opt/bots-central/current ausente" >&2
  failed=1
fi

for unit in "${units[@]}"; do
  active="$(systemctl is-active "$unit" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  restarts="$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)"
  printf '%-28s active=%-10s enabled=%-10s restarts=%s\n' "$unit" "$active" "$enabled" "${restarts:-?}"
  [[ "$active" == active && "$enabled" == enabled ]] || failed=1
done

if command -v tailscale >/dev/null 2>&1; then
  tailscale status --self 2>/dev/null || echo "WARN tailscale sem status"
fi

echo
echo "Erros recentes:"
for unit in "${units[@]}"; do
  echo "--- $unit"
  journalctl -u "$unit" --since '-10 min' --no-pager 2>/dev/null |
    grep -Ei 'traceback|critical|permission denied|database is locked|conflict|oauth|error|failed' |
    tail -n 20 || true
done

exit "$failed"
