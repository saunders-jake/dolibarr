#!/usr/bin/env bash
# Wrapper: set env vars then run PHP PoC.
#
# Required env:
#   DOLI_INSTANCE_UNIQUE_ID   from conf.php ($dolibarr_main_instance_unique_id)
#   DOLI_FILE                   relative path under ticket storage
# Optional:
#   DOLI_BASE_URL               e.g. https://example.org/htdocs
#   DOLI_ENTITY                 default 1

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PHP="${PHP:-php}"
ID="${DOLI_INSTANCE_UNIQUE_ID:-}"
FILE="${DOLI_FILE:-}"
BASE="${DOLI_BASE_URL:-}"
ENTITY="${DOLI_ENTITY:-1}"

if [[ -z "$ID" || -z "$FILE" ]]; then
  echo "Set DOLI_INSTANCE_UNIQUE_ID and DOLI_FILE" >&2
  exit 1
fi

ARGS=(--instance-id "$ID" --file "$FILE" --entity "$ENTITY")
if [[ -n "$BASE" ]]; then
  ARGS+=(--base-url "$BASE")
fi

exec "$PHP" "$ROOT/dev/security-poc/poc_public_ticket_document.php" "${ARGS[@]}"
