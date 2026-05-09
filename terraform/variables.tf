variable "databricks_workspace_url" {
  description = "URL do workspace Databricks (ex: https://adb-xxxx.azuredatabricks.net)"
  type        = string
}

variable "azure_workspace_resource_id" {
  description = "Resource ID do workspace Databricks no Azure"
  type        = string
}

variable "databricks_account_id" {
  description = "ID da conta Databricks para Unity Catalog e administração global"
  type        = string
  sensitive   = true
}

variable "databricks_workspace_id" {
  description = "ID numérico do workspace para associação ao metastore"
  type        = string
}

variable "metastore_name" {
  description = "Nome do metastore Unity Catalog"
  type        = string
  default     = "metastore-brasil-southeast"
}

variable "metastore_storage_adls" {
  description = "URI do Azure Data Lake Storage Gen2 para armazenamento do metastore"
  type        = string
}

variable "azure_tenant_id" {
  description = "ID do tenant Azure Active Directory"
  type        = string
  sensitive   = true
}

variable "environments" {
  description = "Ambientes para criação de catálogos Unity Catalog"
  type        = list(string)
  default     = ["dev", "staging", "prod"]
}

variable "data_domains" {
  description = "Domínios de dados para organização dos schemas"
  type        = list(string)
  default     = ["vendas", "financeiro", "rh", "marketing", "operacoes", "shared"]
}

variable "groups" {
  description = "Grupos a serem criados no workspace com seus membros e papéis"
  type = map(object({
    display_name    = string
    entitlement     = string
    member_emails   = list(string)
    workspace_access = bool
  }))
}

variable "service_principals" {
  description = "Service principals para pipelines e automações (sem PAT pessoal)"
  type = map(object({
    display_name  = string
    catalogs      = list(string)
    role          = string
  }))
  default = {}
}

variable "entitlements" {
  description = "Mapa de entitlements disponíveis por nível de acesso"
  type = map(list(string))
  default = {
    admin    = ["workspace-access", "databricks-sql-access", "allow-cluster-create", "allow-instance-pool-create"]
    engineer = ["workspace-access", "databricks-sql-access", "allow-cluster-create"]
    analyst  = ["workspace-access", "databricks-sql-access"]
    viewer   = ["workspace-access"]
  }
}

variable "allowed_ip_ranges" {
  description = "Faixas de IP autorizadas a acessar o workspace (CIDR)"
  type        = list(string)
  default     = []
}

variable "daily_cost_alert_threshold_usd" {
  description = "Limite diário de custo em USD para alerta"
  type        = number
  default     = 500
}

variable "tags" {
  description = "Tags padrão aplicadas a todos os recursos"
  type        = map(string)
  default = {
    ManagedBy   = "terraform"
    Project     = "databricks-governance"
    Environment = "prod"
    CostCenter  = "platform-engineering"
  }
}
