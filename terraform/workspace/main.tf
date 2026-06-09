terraform {
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "~> 1.38"
    }
  }
}

# ── Grupos de workspace — nunca conceder acesso a usuários individuais ────────

# Administradores da plataforma Databricks
resource "databricks_group" "data_admins" {
  display_name             = "data-admins"
  allow_cluster_create     = true
  allow_instance_pool_create = true
  workspace_access         = true
  databricks_sql_access    = true
}

# Engenheiros de dados por ambiente
resource "databricks_group" "data_engineers" {
  for_each = toset(["dev", "staging", "prod"])

  display_name          = "data-engineers-${each.value}"
  allow_cluster_create  = true
  workspace_access      = true
  databricks_sql_access = true
}

# Cientistas de dados
resource "databricks_group" "data_scientists" {
  display_name          = "data-scientists"
  allow_cluster_create  = true
  workspace_access      = true
  databricks_sql_access = true
}

# Analistas de dados — sem criação de cluster, apenas SQL e notebooks
resource "databricks_group" "data_analysts" {
  display_name          = "data-analysts"
  allow_cluster_create  = false
  workspace_access      = true
  databricks_sql_access = true
}

# Proprietários de dados por domínio
resource "databricks_group" "domain_owners" {
  for_each     = toset(var.data_domains)
  display_name = "${each.value}-data-owners"
  workspace_access      = true
  databricks_sql_access = true
}

# Grupo com acesso a dados PII — requer aprovação extra
resource "databricks_group" "pii_access" {
  display_name     = "pii-access"
  workspace_access = true
}

# ── Usuários: criados via SCIM do Azure AD na prática, aqui para referência ───
resource "databricks_user" "admins" {
  for_each  = { for u in var.admin_users : u.email => u }
  user_name = each.value.email
  display_name = each.value.display_name
  workspace_access = true

  # Evitar deleção acidental — apenas desativar
  force_delete_repos  = false
  force_delete_home_dir = false
}

# ── Membros dos grupos ─────────────────────────────────────────────────────────
resource "databricks_group_member" "admin_members" {
  for_each  = { for u in var.admin_users : u.email => u }
  group_id  = databricks_group.data_admins.id
  member_id = databricks_user.admins[each.key].id
}

# ── Service Principals para automações e pipelines ────────────────────────────
resource "databricks_service_principal" "pipelines" {
  for_each     = var.service_principals
  display_name = each.value.display_name

  # Service principals nunca têm admin global — princípio de menor privilégio
  allow_cluster_create     = false
  workspace_access         = true
  databricks_sql_access    = false
  allow_instance_pool_create = false
}

# SP de ingestão: membro do grupo de engenheiros-prod
resource "databricks_group_member" "sp_ingestion_engineer" {
  for_each  = { for k, v in var.service_principals : k => v if contains(v.groups, "data-engineers-prod") }
  group_id  = databricks_group.data_engineers["prod"].id
  member_id = databricks_service_principal.pipelines[each.key].id
}

# ── Secrets: armazenados no Key Vault, não como PAT no Databricks ─────────────
resource "databricks_secret_scope" "keyvault" {
  name = "keyvault-secrets"

  keyvault_metadata {
    resource_id = var.key_vault_resource_id
    dns_name    = var.key_vault_dns_name
  }
}

# Escopo para configurações de pipelines
resource "databricks_secret_scope" "pipeline_config" {
  name                     = "pipeline-config"
  initial_manage_principal = "data-admins"
}

# ── Permissões nos escopos de secrets ─────────────────────────────────────────
resource "databricks_secret_acl" "pipeline_config_engineers" {
  scope      = databricks_secret_scope.pipeline_config.name
  principal  = databricks_group.data_engineers["prod"].display_name
  permission = "READ"
}

resource "databricks_secret_acl" "pipeline_config_admins" {
  scope      = databricks_secret_scope.pipeline_config.name
  principal  = databricks_group.data_admins.display_name
  permission = "MANAGE"
}

# ── Configurações globais do workspace ────────────────────────────────────────
resource "databricks_workspace_conf" "security_settings" {
  custom_config = {
    # Desabilitar acesso legado à tabela hive_metastore — forçar Unity Catalog
    "enableHiveMetastore"                    = "false"
    # Requerer clusters com Unity Catalog habilitado
    "enforceClusterComplianceForAllWorkloads" = "true"
    # Bloquear download de dados de result sets do SQL Warehouse
    "enableResultSetDownload"                = "false"
    # Desabilitar exportação de notebooks com dados sensíveis
    "enableNotebookExport"                   = "false"
    # Requerer autenticação multi-fator
    "enableMFA"                              = "true"
  }
}
