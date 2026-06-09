terraform {
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "~> 1.38"
      configuration_aliases = [databricks.account, databricks.workspace]
    }
  }
}

# ── Metastore Unity Catalog — região Brasil ───────────────────────────────────
resource "databricks_metastore" "main" {
  provider      = databricks.account
  name          = var.metastore_name
  storage_root  = var.metastore_storage_adls
  region        = "brazilsouth"
  owner         = "unity-catalog-admins"

  # Forçar Unity Catalog como modelo de segurança padrão
  force_destroy = false
}

# ── Associar workspace ao metastore ──────────────────────────────────────────
resource "databricks_metastore_assignment" "workspace" {
  provider             = databricks.account
  metastore_id         = databricks_metastore.main.id
  workspace_id         = var.workspace_id
  default_catalog_name = "sandbox"
}

# ── Configuração do metastore: herança de permissões e delta sharing ──────────
resource "databricks_metastore_data_access" "managed_identity" {
  provider     = databricks.account
  metastore_id = databricks_metastore.main.id
  name         = "mi-databricks-metastore"
  is_default   = true

  azure_managed_identity {
    # Managed Identity do workspace tem acesso ao ADLS do metastore
    access_connector_id = var.access_connector_id
  }
}

# ── Catálogos por ambiente (dev / staging / prod) ─────────────────────────────
resource "databricks_catalog" "env" {
  provider     = databricks.workspace
  for_each     = toset(var.environments)

  name         = each.value
  metastore_id = databricks_metastore.main.id
  comment      = "Catálogo do ambiente ${each.value} — acesso controlado por grupos Unity Catalog"

  properties = {
    environment = each.value
    managed_by  = "terraform"
  }
}

# ── Catálogo sandbox — área de experimentação isolada ─────────────────────────
resource "databricks_catalog" "sandbox" {
  provider     = databricks.workspace
  name         = "sandbox"
  metastore_id = databricks_metastore.main.id
  comment      = "Área de experimentação — dados não sensíveis, sem promoção para produção"
}

# ── Schemas por domínio de dados dentro de cada catálogo ─────────────────────
resource "databricks_schema" "domains" {
  provider   = databricks.workspace
  for_each   = { for pair in local.catalog_domain_pairs : "${pair.env}_${pair.domain}" => pair }

  catalog_name = databricks_catalog.env[each.value.env].name
  name         = each.value.domain
  comment      = "Domínio ${each.value.domain} no ambiente ${each.value.env}"

  properties = {
    domain      = each.value.domain
    environment = each.value.env
    data_owner  = "${each.value.domain}-data-owners"
  }
}

locals {
  catalog_domain_pairs = flatten([
    for env in var.environments : [
      for domain in var.data_domains : {
        env    = env
        domain = domain
      }
    ]
  ])
}

# ── Grants por catálogo: grupo de admins tem ALL PRIVILEGES ──────────────────
resource "databricks_grants" "catalog_admin" {
  provider = databricks.workspace
  for_each = toset(var.environments)

  catalog = databricks_catalog.env[each.value].name

  grant {
    principal  = "data-admins"
    privileges = ["ALL_PRIVILEGES"]
  }

  # Engenheiros de dados: podem criar objetos no catálogo
  grant {
    principal  = "data-engineers-${each.value}"
    privileges = ["USE_CATALOG", "CREATE_SCHEMA", "CREATE_TABLE", "CREATE_FUNCTION", "CREATE_VOLUME"]
  }

  # Cientistas de dados: leitura e criação em sandbox/dev
  dynamic "grant" {
    for_each = each.value != "prod" ? [1] : []
    content {
      principal  = "data-scientists"
      privileges = ["USE_CATALOG", "CREATE_SCHEMA", "CREATE_TABLE"]
    }
  }

  # Analistas: apenas leitura no catálogo prod
  dynamic "grant" {
    for_each = each.value == "prod" ? [1] : []
    content {
      principal  = "data-analysts"
      privileges = ["USE_CATALOG"]
    }
  }
}

# ── Grants por schema: herança de permissões do catálogo + permissões específicas
resource "databricks_grants" "schema_prod_vendas" {
  provider = databricks.workspace

  schema = "${databricks_catalog.env["prod"].name}.vendas"

  grant {
    principal  = "data-engineers-prod"
    privileges = ["ALL_PRIVILEGES"]
  }

  grant {
    principal  = "data-analysts"
    privileges = ["USE_SCHEMA", "SELECT"]
  }

  grant {
    principal  = "vendas-data-owners"
    privileges = ["USE_SCHEMA", "SELECT", "MODIFY", "CREATE_TABLE"]
  }
}

resource "databricks_grants" "schema_prod_rh" {
  provider = databricks.workspace
  # Schema RH tem dados PII — acesso extremamente restrito
  schema = "${databricks_catalog.env["prod"].name}.rh"

  grant {
    principal  = "data-engineers-prod"
    privileges = ["USE_SCHEMA", "CREATE_TABLE", "MODIFY"]
  }

  # Apenas o grupo rh-data-owners pode SELECT em dados de RH
  grant {
    principal  = "rh-data-owners"
    privileges = ["USE_SCHEMA", "SELECT"]
  }
}

# ── Sistema de tags para classificação de dados ───────────────────────────────
resource "databricks_system_schema" "access" {
  provider = databricks.workspace
  schema   = "access"
}

resource "databricks_system_schema" "lineage" {
  provider = databricks.workspace
  schema   = "lineage"
}
