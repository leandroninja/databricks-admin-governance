# ── Política de cluster: Engenharia de Dados ─────────────────────────────────
# Balanceia custo e performance: Spot para dev, On-Demand para prod
resource "databricks_cluster_policy" "data_engineering" {
  name = "Política — Engenharia de Dados"

  definition = jsonencode({
    # Limitar tipos de instância para controle de custo
    "node_type_id" = {
      type        = "allowlist"
      values      = ["Standard_DS3_v2", "Standard_DS4_v2", "Standard_DS5_v2", "Standard_D8ds_v4"]
      defaultValue = "Standard_DS3_v2"
    }
    # Encerramento automático obrigatório — 60 minutos de inatividade
    "autotermination_minutes" = {
      type         = "fixed"
      value        = 60
      hidden       = false
    }
    # Mínimo 1 worker — sem clusters single-node para DEps
    "num_workers" = {
      type         = "range"
      minValue     = 1
      maxValue     = 10
      defaultValue = 2
    }
    # Autoscaling habilitado por padrão
    "autoscale.min_workers" = {
      type         = "range"
      minValue     = 1
      maxValue     = 5
      defaultValue = 1
    }
    "autoscale.max_workers" = {
      type         = "range"
      minValue     = 2
      maxValue     = 10
      defaultValue = 4
    }
    # Databricks Runtime LTS obrigatório
    "spark_version" = {
      type        = "allowlist"
      values      = ["14.3.x-scala2.12", "14.3.x-cpu-ml-scala2.12", "15.4.x-scala2.12"]
      defaultValue = "14.3.x-scala2.12"
    }
    # Modo single user — isolamento de segurança, sem compartilhamento de cluster
    "data_security_mode" = {
      type  = "fixed"
      value = "SINGLE_USER"
    }
    # Photon habilitado para performance
    "runtime_engine" = {
      type         = "fixed"
      value        = "PHOTON"
    }
    # Tags obrigatórias para rastreamento de custo
    "custom_tags.Team" = {
      type  = "fixed"
      value = "data-engineering"
    }
    "custom_tags.ManagedBy" = {
      type  = "fixed"
      value = "cluster-policy"
    }
  })
}

# ── Política de cluster: Ciência de Dados ─────────────────────────────────────
resource "databricks_cluster_policy" "data_science" {
  name = "Política — Ciência de Dados"

  definition = jsonencode({
    "node_type_id" = {
      type        = "allowlist"
      # Instâncias com GPU para treinamento ML
      values      = ["Standard_NC6s_v3", "Standard_NC12s_v3", "Standard_DS3_v2", "Standard_DS4_v2"]
      defaultValue = "Standard_DS3_v2"
    }
    "autotermination_minutes" = {
      type         = "range"
      minValue     = 30
      maxValue     = 180
      defaultValue = 90
    }
    "spark_version" = {
      type        = "allowlist"
      # Runtimes ML para bibliotecas de machine learning pré-instaladas
      values      = ["14.3.x-cpu-ml-scala2.12", "14.3.x-gpu-ml-scala2.12", "15.4.x-cpu-ml-scala2.12"]
      defaultValue = "14.3.x-cpu-ml-scala2.12"
    }
    "data_security_mode" = {
      type  = "fixed"
      value = "SINGLE_USER"
    }
    # Spot instances para reduzir custo de experimentos ML
    "azure_attributes.availability" = {
      type  = "fixed"
      value = "SPOT_WITH_FALLBACK_AZURE"
    }
    "custom_tags.Team" = {
      type  = "fixed"
      value = "data-science"
    }
    "custom_tags.CostCenter" = {
      type    = "regex"
      pattern = "ML-[A-Z]+-[0-9]{4}"
    }
  })
}

# ── Política de cluster: SQL Analytics (analistas) ────────────────────────────
resource "databricks_cluster_policy" "analytics" {
  name = "Política — Analytics (somente leitura)"

  definition = jsonencode({
    "node_type_id" = {
      type         = "allowlist"
      values       = ["Standard_DS2_v2", "Standard_DS3_v2"]
      defaultValue = "Standard_DS2_v2"
    }
    "autotermination_minutes" = {
      type  = "fixed"
      value = 30
    }
    "num_workers" = {
      type         = "fixed"
      value        = 1
    }
    "spark_version" = {
      type         = "allowlist"
      values       = ["14.3.x-scala2.12", "15.4.x-scala2.12"]
      defaultValue = "14.3.x-scala2.12"
    }
    "data_security_mode" = {
      type  = "fixed"
      value = "SINGLE_USER"
    }
    "custom_tags.Team" = {
      type  = "fixed"
      value = "analytics"
    }
  })
}

# ── Política de cluster: Jobs compartilhados (pipelines) ─────────────────────
resource "databricks_cluster_policy" "shared_jobs" {
  name = "Política — Jobs Compartilhados"

  definition = jsonencode({
    "node_type_id" = {
      type        = "allowlist"
      values      = ["Standard_DS3_v2", "Standard_DS4_v2", "Standard_DS5_v2", "Standard_D16ds_v4"]
      defaultValue = "Standard_DS4_v2"
    }
    "autotermination_minutes" = {
      type  = "fixed"
      value = 20
    }
    # Jobs clusters: sem autoscaling para custo previsível
    "num_workers" = {
      type         = "range"
      minValue     = 2
      maxValue     = 20
      defaultValue = 4
    }
    "spark_version" = {
      type         = "allowlist"
      values       = ["14.3.x-scala2.12", "15.4.x-scala2.12"]
      defaultValue = "14.3.x-scala2.12"
    }
    # Modo compartilhado para jobs que usam Unity Catalog
    "data_security_mode" = {
      type  = "fixed"
      value = "USER_ISOLATION"
    }
    "runtime_engine" = {
      type  = "fixed"
      value = "PHOTON"
    }
    "custom_tags.ManagedBy" = {
      type  = "fixed"
      value = "workflow-jobs"
    }
  })
}

# ── Permissões nas políticas ───────────────────────────────────────────────────
resource "databricks_permissions" "policy_data_engineering" {
  cluster_policy_id = databricks_cluster_policy.data_engineering.id

  access_control {
    group_name       = "data-engineers-dev"
    permission_level = "CAN_USE"
  }
  access_control {
    group_name       = "data-engineers-staging"
    permission_level = "CAN_USE"
  }
  access_control {
    group_name       = "data-engineers-prod"
    permission_level = "CAN_USE"
  }
}

resource "databricks_permissions" "policy_data_science" {
  cluster_policy_id = databricks_cluster_policy.data_science.id

  access_control {
    group_name       = "data-scientists"
    permission_level = "CAN_USE"
  }
}

resource "databricks_permissions" "policy_analytics" {
  cluster_policy_id = databricks_cluster_policy.analytics.id

  access_control {
    group_name       = "data-analysts"
    permission_level = "CAN_USE"
  }
}
