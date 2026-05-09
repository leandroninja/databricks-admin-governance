# Modelo de Controle de Acesso — Databricks Platform

## Visão Geral

Este documento descreve o modelo de controle de acesso implementado na plataforma Databricks,
cobrindo identidade, autenticação, autorização no Unity Catalog e proteção de dados PII.

## Arquitetura de Identidade

```
Azure Active Directory (fonte da verdade)
         │
         │ SCIM sync (a cada 60 min)
         ▼
Databricks Account Console
         │
         ├── Unity Catalog Metastore (brasiliouth)
         │       ├── Catálogo: prod
         │       │       ├── Schema: vendas    ──► Row Filter: por time
         │       │       ├── Schema: financeiro ──► Row Filter: por centro de custo
         │       │       ├── Schema: rh        ──► Acesso restrito ao grupo rh-data-owners
         │       │       └── Schema: security  ──► Funções de mascaramento PII
         │       ├── Catálogo: staging
         │       ├── Catálogo: dev
         │       └── Catálogo: sandbox
         │
         └── Workspace: dbw-dataplatform-prod
                 ├── Grupos → Políticas de Cluster
                 ├── SQL Warehouses
                 └── Secrets (backed by Azure Key Vault)
```

## Hierarquia de Grupos

```
data-admins (ALL_PRIVILEGES em todos os catálogos)
├── data-engineers-prod   (USE_CATALOG, CREATE_TABLE, MODIFY em prod)
├── data-engineers-staging (ALL_PRIVILEGES em staging)
├── data-engineers-dev    (ALL_PRIVILEGES em dev)
├── data-scientists       (SELECT, CREATE_TABLE em dev/staging; feature_store em prod)
├── data-analysts         (USE_CATALOG, USE_SCHEMA, SELECT em prod — via SQL Warehouse)
├── vendas-data-owners    (MODIFY em prod.vendas)
├── financeiro-data-owners (MODIFY em prod.financeiro)
├── rh-data-owners        (SELECT em prod.rh — com mascaramento de PII)
└── pii-access            (bypass de column masks para dados PII)
```

## Fluxo de Autorização

```
Usuário faz query em prod.rh.funcionarios
         │
         ├─► Unity Catalog verifica: usuário tem USE_CATALOG em prod?
         │       └── Não → PERMISSION_DENIED
         │
         ├─► Unity Catalog verifica: usuário tem USE_SCHEMA em prod.rh?
         │       └── Não → PERMISSION_DENIED
         │
         ├─► Unity Catalog verifica: usuário tem SELECT em prod.rh.funcionarios?
         │       └── Não → PERMISSION_DENIED
         │
         ├─► Row Filter aplicado: IS_ACCOUNT_GROUP_MEMBER('rh-data-owners')
         │       └── False → linhas filtradas (usuário vê apenas seus dados)
         │
         └─► Column Mask aplicado em cada coluna PII:
                 cpf    → IS_ACCOUNT_GROUP_MEMBER('pii-access')? cpf : '***.***.*XX-**'
                 email  → IS_ACCOUNT_GROUP_MEMBER('pii-access')? email : '***@empresa.com'
                 salario → IS_ACCOUNT_GROUP_MEMBER('pii-access')? salario : NULL
```

## Regras de Ouro de Segurança

| Regra | Descrição |
|-------|-----------|
| **Grupos, nunca indivíduos** | Todos os grants são concedidos a grupos. Usuários individuais nunca recebem permissões diretamente. |
| **Menor privilégio** | Cada papel tem o mínimo necessário. Analistas não têm MODIFY; engenheiros de dev não têm acesso a prod. |
| **Tokens com expiração** | Todos os PATs têm prazo máximo de 90 dias. SPs usam OAuth M2M com 30 dias. |
| **IaC obrigatório** | Mudanças de permissão via Terraform. Alterações manuais via console geram alerta de auditoria. |
| **PII mascarado por padrão** | Column masks aplicados na criação da tabela. `pii-access` concedido apenas com aprovação do DPO. |
| **Service principals para automação** | Pipelines usam SPs, nunca PATs de usuários humanos. |
| **Modo SINGLE_USER** | Clusters em modo SINGLE_USER ou USER_ISOLATION — sem acesso compartilhado não auditado. |
| **Auditoria completa** | `system.access.audit` monitorado automaticamente. Alertas criados para comportamentos anômalos. |

## Processo de Concessão de Acesso

```
Solicitante abre ticket ITSM
         │
         ├── Aprovação do gestor direto
         │
         ├── (Para PII) Aprovação adicional do DPO
         │
         └── Admin executa onboard-user.sh --email ... --role ... --ticket INC-XXXXX
                 │
                 ├── Verifica existência no Azure AD
                 ├── Cria usuário no workspace (se novo)
                 ├── Adiciona ao grupo Unity Catalog correto
                 └── Registra evento no log de auditoria imutável
```

## Revisão Periódica de Acessos

| Frequência | Escopo | Responsável |
|------------|--------|-------------|
| Semanal | Tokens expirando, alertas de segurança | Automatizado (GitHub Actions) |
| Mensal | Usuários no grupo `pii-access`, usuários admin | DPO + CISO |
| Trimestral | Todos os engenheiros de produção | Engineering Manager |
| Semestral | Todos os usuários ativos | Data Platform Team |
| Anual | Políticas de cluster, roles e entitlements | Arquiteto de Dados + CISO |

## Conformidade LGPD

Os dados pessoais tratados na plataforma seguem a **Lei 13.709/2018 (LGPD)**:

- **Minimização de dados**: Column masks reduzem exposição de PII por padrão
- **Rastreabilidade**: `system.access.audit` registra todos os acessos com identidade do usuário
- **Direito de exclusão**: Processo documentado em `docs/runbooks/data-deletion.md`
- **Base legal**: Cada tabela PII tem a tag `lgpd_basis` obrigatória
- **DPO**: Aprovação do Data Protection Officer para qualquer acesso a `sensitive_pii`
- **ROPA**: Registro de Atividades de Processamento mantido externamente e referenciado nas tags
