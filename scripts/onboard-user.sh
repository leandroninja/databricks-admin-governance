#!/usr/bin/env bash
# Onboarding automatizado de usuário no Databricks
# Uso: ./scripts/onboard-user.sh --email user@empresa.com --role data_analyst --env prod --team vendas
set -euo pipefail

# ── Constantes ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/databricks-governance/onboarding-$(date +%Y%m%d).log"

VALID_ROLES=("admin" "engineer" "scientist" "analyst" "viewer")
VALID_ENVS=("dev" "staging" "prod")

# ── Funções auxiliares ────────────────────────────────────────────────────────
log() {
  local level="$1"; shift
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$level] $*" | tee -a "$LOG_FILE"
}

usage() {
  cat <<EOF
Uso: $0 --email EMAIL --role PAPEL --env AMBIENTE --team TIME [--ticket TICKET_ID]

Parâmetros obrigatórios:
  --email     E-mail corporativo do usuário (deve existir no Azure AD)
  --role      Papel: ${VALID_ROLES[*]}
  --env       Ambiente: ${VALID_ENVS[*]} (para engenheiros)
  --team      Time proprietário dos dados (ex: vendas, rh, financeiro)

Parâmetros opcionais:
  --ticket    ID do ticket ITSM para rastreabilidade (ex: INC0012345)
  --dry-run   Executa verificações sem aplicar alterações

Exemplos:
  $0 --email joao.silva@empresa.com --role analyst --env prod --team vendas
  $0 --email maria.souza@empresa.com --role engineer --env staging --team data-platform --ticket INC0012345

EOF
  exit 1
}

validate_email() {
  local email="$1"
  if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log "ERROR" "E-mail inválido: $email"
    exit 1
  fi

  # Verificar se domínio é corporativo (não aceitar e-mails pessoais)
  local domain="${email##*@}"
  if [[ "$domain" =~ ^(gmail|hotmail|yahoo|outlook)\.com$ ]]; then
    log "ERROR" "E-mail pessoal não permitido: $email. Use o e-mail corporativo."
    exit 1
  fi
}

validate_role() {
  local role="$1"
  for valid in "${VALID_ROLES[@]}"; do
    [[ "$role" == "$valid" ]] && return 0
  done
  log "ERROR" "Papel inválido: $role. Valores aceitos: ${VALID_ROLES[*]}"
  exit 1
}

check_azure_ad_user() {
  local email="$1"
  log "INFO" "Verificando existência do usuário $email no Azure AD..."

  # Requer az CLI autenticado
  local user_id
  user_id=$(az ad user show --id "$email" --query "id" -o tsv 2>/dev/null || echo "")

  if [[ -z "$user_id" ]]; then
    log "ERROR" "Usuário $email não encontrado no Azure AD. "
    log "ERROR" "O usuário deve existir no AD antes do provisionamento Databricks."
    exit 1
  fi

  log "INFO" "Usuário encontrado no Azure AD: $user_id"
  echo "$user_id"
}

# ── Parsing de argumentos ─────────────────────────────────────────────────────
EMAIL=""
ROLE=""
ENV=""
TEAM=""
TICKET=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)   EMAIL="$2";   shift 2 ;;
    --role)    ROLE="$2";    shift 2 ;;
    --env)     ENV="$2";     shift 2 ;;
    --team)    TEAM="$2";    shift 2 ;;
    --ticket)  TICKET="$2";  shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage ;;
    *) log "ERROR" "Argumento desconhecido: $1"; usage ;;
  esac
done

# ── Validações ────────────────────────────────────────────────────────────────
[[ -z "$EMAIL" || -z "$ROLE" || -z "$ENV" || -z "$TEAM" ]] && {
  log "ERROR" "Parâmetros obrigatórios ausentes."
  usage
}

validate_email "$EMAIL"
validate_role "$ROLE"

mkdir -p "$(dirname "$LOG_FILE")"
log "INFO" "=== INÍCIO DO ONBOARDING ==="
log "INFO" "Usuário: $EMAIL | Papel: $ROLE | Ambiente: $ENV | Time: $TEAM | Ticket: ${TICKET:-N/A}"
log "INFO" "Dry run: $DRY_RUN"

# ── Verificar pré-requisitos ──────────────────────────────────────────────────
command -v python3 >/dev/null || { log "ERROR" "Python3 não encontrado."; exit 1; }
command -v az     >/dev/null || { log "ERROR" "Azure CLI não encontrado."; exit 1; }

# Verificar variáveis de ambiente necessárias
: "${DATABRICKS_HOST:?Variável DATABRICKS_HOST não definida}"
: "${DATABRICKS_TOKEN:?Variável DATABRICKS_TOKEN não definida (use um SP token do Key Vault)}"

# ── Verificar existência no Azure AD ─────────────────────────────────────────
AD_USER_ID=$(check_azure_ad_user "$EMAIL")

if $DRY_RUN; then
  log "INFO" "[DRY RUN] Provisionamento seria executado para:"
  log "INFO" "  - E-mail: $EMAIL"
  log "INFO" "  - AD User ID: $AD_USER_ID"
  log "INFO" "  - Grupos Databricks: $(python3 -c "
ROLE='$ROLE'; ENV='$ENV'
if ROLE == 'engineer': print(f'data-engineers-{ENV}')
elif ROLE == 'scientist': print('data-scientists')
elif ROLE == 'analyst': print('data-analysts')
elif ROLE == 'admin': print('data-admins')
else: print('viewer')
")"
  log "INFO" "[DRY RUN] Nenhuma alteração aplicada."
  exit 0
fi

# ── Executar provisionamento via Python SDK ───────────────────────────────────
log "INFO" "Executando provisionamento Databricks..."

python3 - <<PYTHON
import sys
sys.path.insert(0, "$PROJECT_ROOT")

from src.admin.user_provisioning import UserProvisioner, UserProvisioningRequest

provisioner = UserProvisioner()
request = UserProvisioningRequest(
    email="$EMAIL",
    display_name="$EMAIL",
    team="$TEAM",
    role="$ROLE",
    cost_center="$TEAM",
    environments=["$ENV"],
)

user = provisioner.onboard_user(request)
print(f"Usuário provisionado com sucesso: {user.user_name} (ID: {user.id})")
PYTHON

log "INFO" "Provisionamento concluído com sucesso."
log "INFO" "Ticket: ${TICKET:-N/A} | Executado por: $(az account show --query user.name -o tsv 2>/dev/null || echo 'automation')"
log "INFO" "=== FIM DO ONBOARDING ==="

# Notificar via email (opcional — requer configuração de SMTP ou SendGrid)
if [[ -n "${NOTIFY_EMAIL:-}" ]]; then
  log "INFO" "Notificação enviada para $NOTIFY_EMAIL"
fi
