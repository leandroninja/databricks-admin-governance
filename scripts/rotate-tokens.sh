#!/usr/bin/env bash
# Rotação automática de tokens Databricks — executar semanalmente via job agendado
# Identifica tokens prestes a expirar, revoga e notifica responsáveis
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ROTATION_LOG="/var/log/databricks-governance/token-rotation-$(date +%Y%m%d).log"
DAYS_BEFORE_EXPIRY="${DAYS_BEFORE_EXPIRY:-7}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$1] ${*:2}" | tee -a "$ROTATION_LOG"; }

log "INFO" "=== ROTAÇÃO DE TOKENS ==="
log "INFO" "Verificando tokens que expiram em $DAYS_BEFORE_EXPIRY dias..."

: "${DATABRICKS_HOST:?DATABRICKS_HOST não definido}"
: "${DATABRICKS_TOKEN:?DATABRICKS_TOKEN não definido}"

# Identificar tokens prestes a expirar
TOKENS_REPORT=$(python3 - <<PYTHON
import sys, json
sys.path.insert(0, "$PROJECT_ROOT")

from src.admin.service_principal_manager import ServicePrincipalManager

mgr = ServicePrincipalManager()
expiring = mgr.rotate_expiring_tokens(days_before_expiry=int("$DAYS_BEFORE_EXPIRY"))

# Separar: tokens sem expiração (violação crítica) e tokens expirando
no_expiry = [t for t in expiring if "SEM_EXPIRAÇÃO" in str(t.get("expires_at", ""))]
expiring_soon = [t for t in expiring if "SEM_EXPIRAÇÃO" not in str(t.get("expires_at", ""))]

print(json.dumps({
    "no_expiry_count": len(no_expiry),
    "expiring_soon_count": len(expiring_soon),
    "no_expiry": no_expiry,
    "expiring_soon": expiring_soon
}))
PYTHON
)

NO_EXPIRY_COUNT=$(echo "$TOKENS_REPORT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['no_expiry_count'])")
EXPIRING_COUNT=$(echo "$TOKENS_REPORT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['expiring_soon_count'])")

log "INFO" "Tokens sem expiração (violação): $NO_EXPIRY_COUNT"
log "INFO" "Tokens expirando em $DAYS_BEFORE_EXPIRY dias: $EXPIRING_COUNT"

# Tokens sem expiração são violação crítica — notificar e revogar
if [[ "$NO_EXPIRY_COUNT" -gt 0 ]]; then
  log "CRITICAL" "VIOLAÇÃO DE POLÍTICA: $NO_EXPIRY_COUNT tokens sem data de expiração!"
  log "CRITICAL" "Tokens revogados automaticamente. Responsáveis notificados."

  # Notificação de emergência
  if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    curl -s -X POST "$SLACK_WEBHOOK_URL" \
      -H 'Content-Type: application/json' \
      -d "{\"text\":\":rotating_light: *VIOLAÇÃO DE POLÍTICA DATABRICKS* — $NO_EXPIRY_COUNT tokens sem expiração detectados e revogados. Verificar imediatamente.\"}" \
      >/dev/null
  fi
fi

# Notificar donos de tokens que expiram em breve
if [[ "$EXPIRING_COUNT" -gt 0 ]]; then
  log "WARN" "$EXPIRING_COUNT tokens expirando em breve — notificando responsáveis"

  echo "$TOKENS_REPORT" | python3 - <<PYTHON
import sys, json

data = json.load(sys.stdin)
for token in data.get("expiring_soon", []):
    print(f"  → Token '{token.get('comment', 'sem comentário')}' "
          f"criado por {token.get('created_by', 'desconhecido')} "
          f"— expira em {token.get('expires_at', 'N/A')}")
PYTHON

  log "INFO" "Para renovar: use src/admin/service_principal_manager.py generate_oauth_token()"
fi

log "INFO" "Gerando relatório de service principals..."
python3 - <<PYTHON
import sys, json
sys.path.insert(0, "$PROJECT_ROOT")

from src.admin.service_principal_manager import ServicePrincipalManager

mgr = ServicePrincipalManager()
sps = mgr.list_service_principals_with_tokens()

print(f"Total service principals: {len(sps)}")
for sp in sps:
    status = "ATIVO" if sp["active"] else "INATIVO"
    print(f"  [{status}] {sp['display_name']} — {sp['active_tokens']} tokens ativos")
PYTHON

log "INFO" "=== ROTAÇÃO CONCLUÍDA ==="
log "INFO" "Log salvo em: $ROTATION_LOG"
