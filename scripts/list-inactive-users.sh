#!/usr/bin/env bash
# lista usuarios sem login nos ultimos N dias (padrao: 90)
# uso: ./list-inactive-users.sh [dias]

set -euo pipefail

WORKSPACE_URL="${DATABRICKS_HOST:-}"
TOKEN="${DATABRICKS_TOKEN:-}"
DAYS_INACTIVE="${1:-90}"

if [[ -z "$WORKSPACE_URL" || -z "$TOKEN" ]]; then
  echo "Erro: DATABRICKS_HOST e DATABRICKS_TOKEN sao obrigatorios" >&2
  exit 1
fi

echo "Buscando usuarios inativos ha mais de ${DAYS_INACTIVE} dias..."

curl -sf -H "Authorization: Bearer $TOKEN" \
  "${WORKSPACE_URL}/api/2.0/preview/scim/v2/Users" | \
  python3 - <<'PYEOF'
import sys, json
from datetime import datetime, timedelta
import os

days = int(os.environ.get("DAYS_INACTIVE", "90"))
cutoff = datetime.utcnow() - timedelta(days=days)

data = json.load(sys.stdin)
users = data.get("Resources", [])
inactive = []

for u in users:
    last = u.get("lastLoginDate", "")
    name = u.get("displayName", u.get("userName", "unknown"))
    if not last or datetime.fromisoformat(last[:19]) < cutoff:
        inactive.append({"name": name, "last_login": last or "nunca"})

if not inactive:
    print("Nenhum usuario inativo encontrado.")
else:
    print(f"Encontrados {len(inactive)} usuario(s) inativo(s):")
    for u in inactive:
        print(f"  - {u['name']} | ultimo login: {u['last_login']}")
PYEOF
