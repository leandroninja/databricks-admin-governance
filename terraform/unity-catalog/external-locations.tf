# ── Credencial de armazenamento: Managed Identity do Access Connector ─────────
resource "databricks_storage_credential" "adls_managed_identity" {
  provider = databricks.workspace
  name     = "sc-adls-managed-identity"
  comment  = "Credencial principal via Azure Managed Identity — sem chaves de acesso"

  azure_managed_identity {
    access_connector_id = var.access_connector_id
  }
}

# ── External Location: camada Bronze (dados brutos) ───────────────────────────
resource "databricks_external_location" "bronze" {
  provider        = databricks.workspace
  name            = "el-datalake-bronze"
  url             = "abfss://bronze@${var.adls_account_name}.dfs.core.windows.net"
  credential_name = databricks_storage_credential.adls_managed_identity.name
  comment         = "Dados brutos ingeridos — zona de aterrissagem, read-only para analistas"

  skip_validation = false
}

# ── External Location: camada Silver (dados limpos) ───────────────────────────
resource "databricks_external_location" "silver" {
  provider        = databricks.workspace
  name            = "el-datalake-silver"
  url             = "abfss://silver@${var.adls_account_name}.dfs.core.windows.net"
  credential_name = databricks_storage_credential.adls_managed_identity.name
  comment         = "Dados tratados e validados — zona de confiança"
}

# ── External Location: camada Gold (dados prontos para negócio) ───────────────
resource "databricks_external_location" "gold" {
  provider        = databricks.workspace
  name            = "el-datalake-gold"
  url             = "abfss://gold@${var.adls_account_name}.dfs.core.windows.net"
  credential_name = databricks_storage_credential.adls_managed_identity.name
  comment         = "Dados aggregados para consumo BI e APIs — acesso controlado por domínio"
}

# ── External Location: checkpoints de streaming ───────────────────────────────
resource "databricks_external_location" "checkpoints" {
  provider        = databricks.workspace
  name            = "el-streaming-checkpoints"
  url             = "abfss://checkpoints@${var.adls_account_name}.dfs.core.windows.net"
  credential_name = databricks_storage_credential.adls_managed_identity.name
  comment         = "Checkpoints de jobs Structured Streaming — acesso apenas para service principals"
}

# ── Grants nas external locations ─────────────────────────────────────────────
resource "databricks_grants" "bronze_location" {
  provider          = databricks.workspace
  external_location = databricks_external_location.bronze.id

  grant {
    principal  = "data-admins"
    privileges = ["ALL_PRIVILEGES"]
  }

  # Engenheiros leem e escrevem Bronze durante ingestão
  grant {
    principal  = "data-engineers-prod"
    privileges = ["READ_FILES", "WRITE_FILES", "CREATE_EXTERNAL_TABLE"]
  }

  # Service principals de ingestão têm acesso completo à Bronze
  grant {
    principal  = "sp-ingestion-pipeline"
    privileges = ["READ_FILES", "WRITE_FILES", "CREATE_EXTERNAL_TABLE"]
  }
}

resource "databricks_grants" "gold_location" {
  provider          = databricks.workspace
  external_location = databricks_external_location.gold.id

  grant {
    principal  = "data-admins"
    privileges = ["ALL_PRIVILEGES"]
  }

  grant {
    principal  = "data-engineers-prod"
    privileges = ["READ_FILES", "WRITE_FILES", "CREATE_EXTERNAL_TABLE"]
  }

  # Analistas: apenas leitura na Gold
  grant {
    principal  = "data-analysts"
    privileges = ["READ_FILES"]
  }
}

resource "databricks_grants" "checkpoints_location" {
  provider          = databricks.workspace
  external_location = databricks_external_location.checkpoints.id

  # Checkpoints acessíveis apenas por service principals e admins
  grant {
    principal  = "sp-streaming-pipeline"
    privileges = ["ALL_PRIVILEGES"]
  }

  grant {
    principal  = "data-admins"
    privileges = ["ALL_PRIVILEGES"]
  }
}

# ── Grants na credencial de armazenamento ─────────────────────────────────────
resource "databricks_grants" "storage_credential" {
  provider           = databricks.workspace
  storage_credential = databricks_storage_credential.adls_managed_identity.name

  grant {
    principal  = "data-admins"
    privileges = ["ALL_PRIVILEGES"]
  }
}
