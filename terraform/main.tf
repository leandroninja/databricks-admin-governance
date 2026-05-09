terraform {
  required_version = ">= 1.6.0"

  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "~> 1.38"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }

  # Estado remoto no Azure Blob com autenticação AAD — sem chaves de acesso
  backend "azurerm" {
    resource_group_name  = "rg-databricks-governance-state"
    storage_account_name = "stdbgov001tfstate"
    container_name       = "tfstate"
    key                  = "databricks-governance.tfstate"
    use_azuread_auth     = true
  }
}

# ── Provider workspace: autenticação via Azure AD sem PAT hardcoded ──────────
provider "databricks" {
  alias                       = "workspace"
  host                        = var.databricks_workspace_url
  azure_workspace_resource_id = var.azure_workspace_resource_id
  # Usa Azure Managed Identity ou az CLI automaticamente
}

# ── Provider conta: Unity Catalog e administração global ─────────────────────
provider "databricks" {
  alias      = "account"
  host       = "https://accounts.azuredatabricks.net"
  account_id = var.databricks_account_id
  # Requer papel Account Admin no Databricks Account Console
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

# ── Módulos principais ────────────────────────────────────────────────────────

module "unity_catalog" {
  source = "./unity-catalog"
  providers = {
    databricks.account   = databricks.account
    databricks.workspace = databricks.workspace
  }

  metastore_name          = var.metastore_name
  metastore_storage_adls  = var.metastore_storage_adls
  azure_tenant_id         = var.azure_tenant_id
  workspace_id            = var.databricks_workspace_id
  environments            = var.environments
  data_domains            = var.data_domains
  tags                    = var.tags
}

module "workspace_admin" {
  source = "./workspace"
  providers = {
    databricks = databricks.workspace
  }

  groups          = var.groups
  service_principals = var.service_principals
  entitlements    = var.entitlements
  tags            = var.tags
}

module "network_security" {
  source = "./network"
  providers = {
    databricks = databricks.workspace
  }

  allowed_ip_ranges     = var.allowed_ip_ranges
  workspace_url         = var.databricks_workspace_url
}
