#!/usr/bin/env bash
# Offboarding de usuário: revoga todos os acessos e desativa conta no Databricks
# Uso: ./scripts/offboard-user.sh --email user@empresa.com --reason "Desligamento voluntário"
# IMPORTANTE: Execute imediatamente no dia do desligamento — prazo máximo 1h após saída
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/databricks-governance/offboarding-$(date +%Y%m%d).log"

log() {
  local level="$1"; shift
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$level] $*" | tee -a "$LOG_FILE"
}

usage() {
  cat <<EOF
Uso: $0 --email EMAIL --reason MOTIVO [--ticket TICKET_ID]

Parâmetros obrigatórios:
  --email     E-mail do usuário a ser desativado
  --reason    Motivo do offboarding (ex: "Desligamento voluntário", "Fim de contrato")

Parâmetros opcionais:
  --ticket    ID do ticket ITSM
  --dry-run   Simula sem aplicar alterações

ATENÇÃO: Este script:
  1. Remove o usuário de TODOS os grupos Databricks
  2. Revoga TODOS os tokens pessoais e de serviço
  3. Desativa a conta (NÃO deleta — preserva histórico de auditoria)
  4. Registra em log de conformidade

EOF
  exit 1
}

EMAIL=""
REASON=""
TICKET=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)   EMAIL="$2";   shift 2 ;;
    --reason)  REASON="$2";  shift 2 ;;
    --ticket)  TICKET="$2";  shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage ;;
    *) log "ERROR" "Argumento desconhecido: $1"; usage ;;
  esac
done

[[ -z "$EMAIL" || -z "$REASON" ]] && { log "ERROR" "E-mail e motivo são obrigatórios."; usage; }

mkdir -p "$(dirname "$LOG_FILE")"
log "WARN" "=== INÍCIO DO OFFBOARDING ==="
log "WARN" "Usuário: $EMAIL | Motivo: $REASON | Ticket: ${TICKET:-N/A}"
log "WARN" "Executado por: $(az account show --query user.name -o tsv 2>/dev/null || echo 'system')"

: "${DATABRICKS_HOST:?DATABRICKS_HOST não definido}"
: "${DATABRICKS_TOKEN:?DATABRICKS_TOKEN não definido}"

if $DRY_RUN; then
  log "INFO" "[DRY RUN] Seria executado offboarding para: $EMAIL"
  log "INFO" "[DRY RUN] Grupos seriam removidos, tokens revogados, conta desativada."
  exit 0
fi

# Confirmação interativa (exceto em CI/CD)
if [[ -t 0 ]]; then
  read -rp "⚠️  Confirmar offboarding de $EMAIL? (sim/não): " confirm
  [[ "$confirm" != "sim" ]] && { log "INFO" "Offboarding cancelado pelo operador."; exit 0; }
fi

log "INFO" "Executando offboarding..."

python3 - <<PYTHON
import sys
sys.path.insert(0, "$PROJECT_ROOT")

from src.admin.user_provisioning import UserProvisioner

provisioner = UserProvisioner()
provisioner.offboard_user(email="$EMAIL", reason="$REASON")
print("Offboarding concluído: conta desativada, grupos removidos, tokens revogados.")
PYTHON

# Verificar se Azure AD precisa ser atualizado também
log "INFO" "Verificando Azure AD..."
az ad user update --id "$EMAIL" --account-enabled false 2>/dev/null && \
  log "INFO" "Conta desabilitada no Azure AD." || \
  log "WARN" "Não foi possível desabilitar no Azure AD — verificar manualmente."

log "WARN" "=== OFFBOARDING CONCLUÍDO ==="
log "WARN" "Conta $EMAIL desativada. Histórico de auditoria preservado."
log "WARN" "Ticket: ${TICKET:-N/A}"

# Criar entrada de auditoria imutável
echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"OFFBOARD\",\"email\":\"$EMAIL\",\"reason\":\"$REASON\",\"ticket\":\"${TICKET:-}\",\"executor\":\"$(az account show --query user.name -o tsv 2>/dev/null || echo 'system')\"}" \
  >> "/var/log/databricks-governance/audit-trail.jsonl"
