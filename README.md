# Databricks Admin & Governance Platform

Plataforma completa de administração, governança e segurança para Databricks com Unity Catalog. Demonstra boas práticas de controle de acesso, proteção de dados PII, auditoria automatizada e conformidade LGPD em ambientes multi-workspace Azure.

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Azure Active Directory                           │
│              (fonte da verdade de identidade)                       │
└──────────────────────┬──────────────────────────────────────────────┘
                       │ SCIM sync automático
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Databricks Account Console                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │               Unity Catalog Metastore                       │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │   │
│  │  │ prod     │  │ staging  │  │   dev    │  │ sandbox  │   │   │
│  │  │ ├vendas  │  │          │  │          │  │          │   │   │
│  │  │ ├financ. │  │ (dados   │  │ (dados   │  │ (livre   │   │   │
│  │  │ ├rh(PII) │  │  anon.)  │  │  sintét.)│  │  experi.)│   │   │
│  │  │ └security│  │          │  │          │  │          │   │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│         │ Row Filters        │ Column Masks        │ Audit Logs    │
└─────────┼────────────────────┼─────────────────────┼───────────────┘
          ▼                    ▼                     ▼
   Apenas seus dados     PII mascarado por      system.access.audit
   (filtro por time)     padrão (LGPD)         → alertas automáticos
```

## Funcionalidades Implementadas

### Identidade e Autenticação
| Funcionalidade | Implementação |
|---------------|---------------|
| Provisionamento via SCIM | Azure AD → Databricks (sincronização automática) |
| Autenticação sem PAT | OAuth M2M via Service Principal para automações |
| MFA obrigatório | Configurado via `workspace_conf` no Terraform |
| Rotação automática de tokens | `scripts/rotate-tokens.sh` — executa semanalmente |
| Offboarding imediato | `scripts/offboard-user.sh` — revoga todos os acessos |

### Controle de Acesso (Unity Catalog)
| Funcionalidade | Implementação |
|---------------|---------------|
| Grants baseados em grupos | `src/unity_catalog/grant_manager.py` |
| Matriz de entitlements | `policies/iam/entitlement-matrix.yaml` |
| Hierarquia de grupos | `policies/iam/group-hierarchy.yaml` |
| Revisão automática de acessos | `.github/workflows/access-audit.yml` |
| Detecção de over-provisioning | `src/admin/access_auditor.py` |

### Proteção de Dados PII (LGPD)
| Funcionalidade | Implementação |
|---------------|---------------|
| Column Masking (9 tipos PII) | `src/unity_catalog/column_mask_manager.py` |
| Row-Level Security | `src/unity_catalog/row_filter_manager.py` |
| Classificação de dados | `policies/unity-catalog/data-classification.yaml` |
| Funções SQL de mascaramento | CPF, CNPJ, Email, Telefone, Nome, Data Nasc., Cartão, Salário, Endereço |
| Bypass controlado | Grupo `pii-access` com aprovação do DPO |

### Auditoria e Conformidade
| Funcionalidade | Implementação |
|---------------|---------------|
| Análise de audit logs | `src/security/audit_log_analyzer.py` |
| Score de conformidade | `src/security/compliance_reporter.py` |
| 7 categorias de alertas | Mass download, after-hours, PII não autorizado, alterações manuais |
| Issues automáticas | GitHub Actions cria issue para falhas críticas |
| Relatório JSON completo | Exportado como artefato do workflow |

### Governança de Clusters
| Funcionalidade | Implementação |
|---------------|---------------|
| 4 políticas por papel | `terraform/workspace/cluster-policies.tf` |
| Auditoria de compliance | `src/cluster/cluster_policy_manager.py` |
| Encerramento de violadores | `terminate_non_compliant_clusters()` |
| Rastreamento por time | Tag obrigatória `Team` em todos os clusters |

## Estrutura do Projeto

```
databricks-admin-governance/
├── terraform/
│   ├── main.tf                          # Providers + módulos
│   ├── variables.tf
│   ├── unity-catalog/
│   │   ├── main.tf                      # Metastore, catálogos, schemas, grants
│   │   └── external-locations.tf        # ADLS Bronze/Silver/Gold
│   ├── workspace/
│   │   ├── main.tf                      # Grupos, usuários, SPs, secrets
│   │   └── cluster-policies.tf          # 4 políticas por papel
│   └── network/
│       └── main.tf                      # IP access lists, SQL Warehouses
├── src/
│   ├── admin/
│   │   ├── user_provisioning.py         # Onboarding/offboarding automatizado
│   │   ├── service_principal_manager.py # Ciclo de vida de SPs + tokens OAuth
│   │   └── access_auditor.py            # Snapshot de acessos + over-provisioning
│   ├── unity_catalog/
│   │   ├── grant_manager.py             # Grants com auditoria completa
│   │   ├── row_filter_manager.py        # Row-Level Security via Unity Catalog
│   │   └── column_mask_manager.py       # 9 funções de mascaramento PII
│   ├── security/
│   │   ├── audit_log_analyzer.py        # 7 análises de comportamento suspeito
│   │   └── compliance_reporter.py       # Score de conformidade + relatório JSON
│   ├── cluster/
│   │   └── cluster_policy_manager.py    # Auditoria e correção de clusters
│   └── utils/
│       └── databricks_client.py         # Fábrica de clientes SDK
├── policies/
│   ├── cluster-policies/                # JSONs de política por papel
│   ├── unity-catalog/                   # Taxonomia de classificação de dados
│   └── iam/                             # Matriz de entitlements + hierarquia
├── scripts/
│   ├── onboard-user.sh                  # Provisionamento com validação Azure AD
│   ├── offboard-user.sh                 # Revogação imediata de acessos
│   └── rotate-tokens.sh                 # Rotação automática de tokens
├── tests/unit/                          # 50+ testes com mocks do SDK
├── docs/
│   └── access-control-model.md          # Modelo completo de controle de acesso
└── .github/workflows/
    ├── terraform-plan.yml               # CI com tfsec + Checkov + plan no PR
    └── access-audit.yml                 # Auditoria semanal automatizada
```

## Pré-requisitos

| Requisito | Versão | Finalidade |
|-----------|--------|-----------|
| Python | ≥ 3.11 | Scripts de administração |
| Databricks SDK | ≥ 0.24 | API do workspace e conta |
| Terraform | ≥ 1.6 | Infraestrutura como código |
| Azure CLI | qualquer | Autenticação OIDC |
| Databricks Premium | — | Unity Catalog obrigatório |

## Início Rápido

```bash
# 1. Instalar dependências Python
pip install -r requirements.txt

# 2. Autenticar (usar Azure Managed Identity em produção)
export DATABRICKS_HOST="https://adb-xxxx.azuredatabricks.net"
export DATABRICKS_TOKEN="<token-do-key-vault>"

# 3. Provisionar infraestrutura via Terraform
cd terraform
terraform init && terraform plan

# 4. Onboarding de usuário
./scripts/onboard-user.sh \
  --email novo.analista@empresa.com \
  --role analyst \
  --env prod \
  --team vendas \
  --ticket INC0012345

# 5. Aplicar mascaramento PII
python3 -c "
from src.unity_catalog.column_mask_manager import ColumnMaskManager, ColumnMaskPolicy, PIIType
mgr = ColumnMaskManager()
mgr.create_all_mask_functions('prod')
mgr.apply_column_mask(ColumnMaskPolicy(
    catalog='prod', schema='rh', table='funcionarios',
    column='cpf', pii_type=PIIType.CPF
))
"

# 6. Executar relatório de conformidade
python3 -c "
from src.security.compliance_reporter import ComplianceReporter
report = ComplianceReporter().generate_report('prod', output_path='compliance.json')
print(f'Score: {report.compliance_score}%')
"

# 7. Executar testes
pytest tests/ -v --cov=src --cov-report=html
```

## Segurança — Decisões de Design

### Por que SINGLE_USER mode?
Clusters em `SINGLE_USER` garantem isolamento de processo e dados: um usuário não pode ver os dados em memória de outro. `USER_ISOLATION` é usado apenas em jobs compartilhados onde o custo de múltiplos clusters é proibitivo.

### Por que OAuth M2M em vez de PATs para SPs?
Personal Access Tokens são segredos estáticos com risco de vazamento. OAuth M2M usa fluxo de credenciais de cliente (client credentials) com tokens de curta duração que expiram automaticamente, reduzindo a janela de risco.

### Por que grupos em vez de usuários individuais?
Grants individuais não escalam e criam risco de over-provisioning acidental. Com grupos, o acesso é controlado pela adição/remoção do usuário ao grupo, criando um modelo auditável e reversível.

### Por que Column Masks em vez de views?
Views precisam ser mantidas manualmente e duplicam a lógica. Column Masks no Unity Catalog são aplicadas transparentemente na engine, funcionam em todas as interfaces (SQL, Python, BI tools) e são auditadas automaticamente.

## Certificações Demonstradas

Este projeto aplica conhecimentos de:
- **AZ-400** — DevSecOps: pipelines CI/CD com verificações de segurança IaC (tfsec, Checkov)
- **AZ-305** — Azure Architecture: Managed Identity, Key Vault, ADLS Gen2, Private Endpoints
- **Databricks** — Unity Catalog, cluster policies, audit logs, Delta Lake
- **Intel FinOps** — Políticas de cluster para controle de custo, tags obrigatórias, auto-termination
- **Linux Foundation** — Práticas open source: IaC versionado, testes unitários, documentação

---

**Autor:** Leandro Oliveira Moraes  
**GitHub:** [leandroninja](https://github.com/leandroninja)
