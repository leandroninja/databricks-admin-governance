# ── Lista de IPs permitidos — bloqueia acessos externos não autorizados ───────
resource "databricks_ip_access_list" "corporate_network" {
  label        = "Rede Corporativa — Acesso Permitido"
  list_type    = "ALLOW"
  ip_addresses = var.allowed_ip_ranges
  enabled      = true
}

resource "databricks_ip_access_list" "vpn_brazil" {
  label        = "VPN Brasil — Escritórios"
  list_type    = "ALLOW"
  ip_addresses = var.vpn_ip_ranges
  enabled      = true
}

# Bloquear explicitamente faixas conhecidas de saída de proxies e TOR
resource "databricks_ip_access_list" "block_known_threats" {
  label        = "Blocklist — Saídas Suspeitas"
  list_type    = "BLOCK"
  ip_addresses = var.blocked_ip_ranges
  enabled      = true
}

# ── Configuração global de acesso: habilitar restrição por IP ─────────────────
resource "databricks_workspace_conf" "ip_restriction" {
  custom_config = {
    "enableIpAccessLists" = "true"
  }
}

# ── SQL Warehouse compartilhado para analistas ────────────────────────────────
resource "databricks_sql_endpoint" "shared_analytics" {
  name             = "wh-analytics-compartilhado"
  cluster_size     = "Small"
  min_num_clusters = 1
  max_num_clusters = 3
  auto_stop_mins   = 15

  # Serverless reduz cold start e elimina gerenciamento de infraestrutura
  enable_serverless_compute = true

  # Canal estável — sem versões preview em produção
  channel {
    name = "CHANNEL_NAME_CURRENT"
  }

  tags {
    custom_tags {
      key   = "Team"
      value = "analytics"
    }
    custom_tags {
      key   = "ManagedBy"
      value = "terraform"
    }
  }
}

# ── SQL Warehouse de engenharia para jobs e pipelines ─────────────────────────
resource "databricks_sql_endpoint" "engineering" {
  name             = "wh-engineering-pipeline"
  cluster_size     = "Medium"
  min_num_clusters = 0
  max_num_clusters = 2
  auto_stop_mins   = 10
  enable_serverless_compute = true

  channel {
    name = "CHANNEL_NAME_CURRENT"
  }
}

# ── Permissões nos warehouses ─────────────────────────────────────────────────
resource "databricks_permissions" "warehouse_analytics" {
  sql_endpoint_id = databricks_sql_endpoint.shared_analytics.id

  access_control {
    group_name       = "data-analysts"
    permission_level = "CAN_USE"
  }

  access_control {
    group_name       = "data-scientists"
    permission_level = "CAN_USE"
  }

  access_control {
    group_name       = "data-admins"
    permission_level = "CAN_MANAGE"
  }
}

resource "databricks_permissions" "warehouse_engineering" {
  sql_endpoint_id = databricks_sql_endpoint.engineering.id

  access_control {
    group_name       = "data-engineers-prod"
    permission_level = "CAN_USE"
  }

  access_control {
    group_name       = "data-admins"
    permission_level = "CAN_MANAGE"
  }
}

# ── Token de administrador: curta duração, gerado via Terraform ───────────────
# Em produção, usar OAuth M2M — tokens de serviço sem expiração são proibidos
resource "databricks_token" "terraform_automation" {
  comment          = "Token temporário para automação Terraform — renovar mensalmente"
  lifetime_seconds = 2592000 # 30 dias
}

# Salvar token no Key Vault — nunca em variáveis de ambiente ou código
resource "azurerm_key_vault_secret" "terraform_token" {
  name         = "databricks-terraform-token"
  value        = databricks_token.terraform_automation.token_value
  key_vault_id = var.key_vault_id

  content_type    = "databricks-pat"
  expiration_date = timeadd(timestamp(), "720h") # 30 dias
}
