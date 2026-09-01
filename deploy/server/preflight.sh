#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
EXPECTED_SHA="${EXPECTED_SHA:-}"
errors=0
warnings=0

ok(){ printf 'OK   %s\n' "$*"; }
warn(){ printf 'WARN %s\n' "$*" >&2; warnings=$((warnings+1)); }
fail(){ printf 'FAIL %s\n' "$*" >&2; errors=$((errors+1)); }

for cmd in git python3 systemctl; do
  command -v "$cmd" >/dev/null 2>&1 && ok "$cmd disponível" || fail "$cmd ausente"
done

if command -v tailscale >/dev/null 2>&1; then
  ok "tailscale disponível"
else
  warn "tailscale não instalado ou fora do PATH"
fi

if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  ok "git HEAD $sha"
  if [[ -n "$EXPECTED_SHA" && "$sha" != "$EXPECTED_SHA" ]]; then
    fail "HEAD difere de EXPECTED_SHA=$EXPECTED_SHA"
  fi
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
    warn "working tree possui alterações; o instalador usa git archive do SHA e não copiará mudanças locais"
  fi
else
  fail "REPO_ROOT não é um repositório Git: $REPO_ROOT"
fi

python3 - <<'PY' || exit_code=$?
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ é necessário")
print("OK   Python", sys.version.split()[0])
PY
if [[ "${exit_code:-0}" != 0 ]]; then fail "Python incompatível"; fi

free_kb="$(df -Pk /opt 2>/dev/null | awk 'NR==2{print $4}' || true)"
if [[ "$free_kb" =~ ^[0-9]+$ ]] && (( free_kb < 1048576 )); then
  warn "menos de 1 GiB livre em /opt"
fi

for unit in bots-central.service bots-central-studies.service gmail-telegram-bot.service estudos-bot.service kali-bunker-telegram.service; do
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "$unit"; then
    warn "serviço existente detectado: $unit"
  fi
done

env_value() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  grep -m1 "^$key=" "$file" 2>/dev/null | cut -d= -f2- || true
}

central_env=/etc/bots-central/bots-central.env
studies_env=/etc/bots-central/studies.env
if [[ -f "$central_env" ]]; then
  [[ "$(stat -c '%a' "$central_env" 2>/dev/null || true)" == "600" ]] || warn "$central_env deveria estar com modo 600"
  [[ -n "$(env_value "$central_env" TELEGRAM_TOKEN)" ]] || fail "TELEGRAM_TOKEN ausente no ambiente central"
  [[ -n "$(env_value "$central_env" TELEGRAM_CHAT_ID)" ]] || fail "TELEGRAM_CHAT_ID ausente no ambiente central"
fi
if [[ -f "$studies_env" ]]; then
  [[ "$(stat -c '%a' "$studies_env" 2>/dev/null || true)" == "600" ]] || warn "$studies_env deveria estar com modo 600"
  [[ -n "$(env_value "$studies_env" TELEGRAM_TOKEN)" ]] || fail "TELEGRAM_TOKEN ausente no ambiente Estudos"
fi

central_token="$(env_value "$central_env" TELEGRAM_TOKEN)"
studies_token="$(env_value "$studies_env" TELEGRAM_TOKEN)"
if [[ -n "$central_token" && -n "$studies_token" && "$central_token" == "$studies_token" ]]; then
  fail "Central e Estudos usam o mesmo TELEGRAM_TOKEN; dois long-pollers não podem compartilhar o mesmo bot"
fi

printf '\nResumo: %d erro(s), %d aviso(s).\n' "$errors" "$warnings"
(( errors == 0 ))
