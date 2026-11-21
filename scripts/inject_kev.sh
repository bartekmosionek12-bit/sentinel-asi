#!/usr/bin/env bash
# Scenariusz zero-day na prezentacji: syntetyczny wpis KEV dla podatności z feedów demo.
#
#   ./scripts/inject_kev.sh               # domyślnie CVE-2021-23017 (nginx na proxy-01)
#   ./scripts/inject_kev.sh CVE-2022-24735
#
# Tylko DEMO_MODE=true. Wpis przechodzi tą samą ścieżką co prawdziwy feed KEV: dopasowanie,
# ocena ryzyka, powiadomienia i raport „zero-day” w skrzynce raportów, bez modelu językowego.
# W dzienniku audytu jest oznaczony jako syntetyczny.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env 2>/dev/null; then
  echo "inject_kev działa tylko przy DEMO_MODE=true w pliku .env." >&2
  exit 1
fi
CVE_ID=${1:-CVE-2021-23017}
docker compose exec -T worker-feeds python -m app.cli inject-kev "$CVE_ID"
