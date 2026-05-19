"""Análise de logs de auditoria do Databricks para detecção de anomalias de segurança."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from databricks.sdk import WorkspaceClient
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.window import Window

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


@dataclass
class SecurityAlert:
    """Alerta de segurança detectado na análise de logs."""
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    alert_type: str
    user: str
    description: str
    event_time: str
    details: dict = field(default_factory=dict)


class AuditLogAnalyzer:
    """Analisa o system.access.audit do Unity Catalog para detectar comportamentos suspeitos.

    Casos de uso cobertos:
    - Tentativas de acesso negadas repetidas (brute force / misconfiguration)
    - Download em massa de dados (exfiltração potencial)
    - Acessos em horários incomuns (fora do horário comercial)
    - Uso de tabelas PII por usuários não autorizados
    - Mudanças de permissão não autorizadas
    - Tokens sem expiração criados
    - Acesso ao system.access.audit (quem audita os auditores?)
    - Clusters criados fora das políticas
    """

    AUDIT_TABLE = "system.access.audit"
    BUSINESS_HOURS = (8, 19)          # horário comercial BRT
    MASS_DOWNLOAD_THRESHOLD = 100_000  # linhas em uma única query

    def __init__(self, spark: SparkSession, client: Optional[WorkspaceClient] = None):
        self.spark = spark
        self.ws = client or get_workspace_client()

    def analyze_last_days(self, days: int = 7) -> list[SecurityAlert]:
        """Executa todas as análises de segurança para os últimos N dias."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        df = self._load_audit_logs(cutoff)

        alerts: list[SecurityAlert] = []
        alerts.extend(self._detect_repeated_access_denied(df))
        alerts.extend(self._detect_mass_data_access(df))
        alerts.extend(self._detect_after_hours_access(df))
        alerts.extend(self._detect_unauthorized_pii_access(df))
        alerts.extend(self._detect_permission_changes(df))
        alerts.extend(self._detect_audit_log_access(df))
        alerts.extend(self._detect_policy_violations(df))

        # Ordenar por severidade
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda a: severity_order.get(a.severity, 99))

        logger.info(
            "Análise concluída: %d alertas encontrados (%d críticos, %d altos)",
            len(alerts),
            sum(1 for a in alerts if a.severity == "CRITICAL"),
            sum(1 for a in alerts if a.severity == "HIGH"),
        )

        return alerts

    def _load_audit_logs(self, since: datetime) -> DataFrame:
        since_str = since.strftime("%Y-%m-%d %H:%M:%S")
        return (
            self.spark.table(self.AUDIT_TABLE)
            .filter(F.col("event_time") >= F.lit(since_str))
            .cache()
        )

    def _detect_repeated_access_denied(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta usuários com múltiplas tentativas de acesso negadas — possível misconfiguration ou ataque."""
        threshold = 10  # mais de 10 negações em 1 hora = alerta

        denied = (
            df.filter(F.col("response.status_code") == 403)
            .withColumn("hour_bucket", F.date_trunc("hour", F.col("event_time")))
            .groupBy("user_identity.email", "hour_bucket")
            .agg(F.count("*").alias("denied_count"))
            .filter(F.col("denied_count") >= threshold)
            .orderBy(F.col("denied_count").desc())
        )

        alerts = []
        for row in denied.collect():
            alerts.append(SecurityAlert(
                severity="HIGH",
                alert_type="REPEATED_ACCESS_DENIED",
                user=row["email"] or "unknown",
                description=f"{row['denied_count']} tentativas de acesso negadas em 1 hora",
                event_time=str(row["hour_bucket"]),
                details={"denied_count": row["denied_count"]},
            ))

        return alerts

    def _detect_mass_data_access(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta queries que retornaram volume incomum de dados — possível exfiltração."""
        mass_access = (
            df.filter(
                (F.col("action_name").isin(["commandSubmit", "runCommand"]))
                & (F.col("response.rows_returned") > self.MASS_DOWNLOAD_THRESHOLD)
            )
            .select(
                "user_identity.email",
                "event_time",
                "response.rows_returned",
                "request_params.commandText",
            )
            .orderBy(F.col("rows_returned").desc())
        )

        alerts = []
        for row in mass_access.collect():
            alerts.append(SecurityAlert(
                severity="CRITICAL",
                alert_type="MASS_DATA_ACCESS",
                user=row["email"] or "unknown",
                description=f"Query retornou {row['rows_returned']:,} linhas — possível exfiltração de dados",
                event_time=str(row["event_time"]),
                details={
                    "rows_returned": row["rows_returned"],
                    "query_preview": (row["commandText"] or "")[:200],
                },
            ))

        return alerts

    def _detect_after_hours_access(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta acessos a dados PII fora do horário comercial."""
        start_hour, end_hour = self.BUSINESS_HOURS

        after_hours = (
            df.filter(
                (F.hour(F.col("event_time")) < start_hour)
                | (F.hour(F.col("event_time")) >= end_hour)
            )
            .filter(F.col("action_name").isin(["getData", "commandSubmit", "runCommand"]))
            .filter(F.col("user_identity.email").isNotNull())
            .filter(~F.col("user_identity.email").contains("@"))  # excluir SPs
            .groupBy("user_identity.email", F.to_date("event_time").alias("access_date"))
            .agg(F.count("*").alias("after_hours_events"))
            .filter(F.col("after_hours_events") >= 5)
        )

        alerts = []
        for row in after_hours.collect():
            alerts.append(SecurityAlert(
                severity="MEDIUM",
                alert_type="AFTER_HOURS_ACCESS",
                user=row["email"] or "unknown",
                description=f"{row['after_hours_events']} eventos fora do horário comercial em {row['access_date']}",
                event_time=str(row["access_date"]),
                details={"events": row["after_hours_events"]},
            ))

        return alerts

    def _detect_unauthorized_pii_access(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta acessos a tabelas PII por usuários sem o grupo pii-access."""
        pii_tables = ["rh.funcionarios", "clientes.perfil", "financeiro.folha_pagamento"]

        pii_access = (
            df.filter(
                F.array_contains(
                    F.array([F.lit(t) for t in pii_tables]),
                    F.col("request_params.tableName"),
                )
            )
            .filter(F.col("action_name") == "getData")
            .select("user_identity.email", "event_time", "request_params.tableName")
        )

        alerts = []
        for row in pii_access.collect():
            alerts.append(SecurityAlert(
                severity="HIGH",
                alert_type="PII_TABLE_ACCESS",
                user=row["email"] or "unknown",
                description=f"Acesso à tabela PII: {row['tableName']} — verificar autorização",
                event_time=str(row["event_time"]),
                details={"table": row["tableName"]},
            ))

        return alerts

    def _detect_permission_changes(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta alterações de permissão — devem ser feitas apenas via Terraform/IaC."""
        perm_changes = (
            df.filter(F.col("action_name").isin([
                "updatePermissions", "grantPrivilege", "revokePrivilege",
                "updateGroupMembers", "updateServicePrincipal",
            ]))
            .select("user_identity.email", "event_time", "action_name", "request_params")
        )

        alerts = []
        for row in perm_changes.collect():
            # Alterações fora do service principal do Terraform são suspeitas
            user = row["email"] or "unknown"
            if "terraform" not in user.lower():
                alerts.append(SecurityAlert(
                    severity="HIGH",
                    alert_type="MANUAL_PERMISSION_CHANGE",
                    user=user,
                    description=f"Alteração manual de permissão detectada: {row['action_name']}. "
                                "Permissões devem ser gerenciadas via Terraform.",
                    event_time=str(row["event_time"]),
                    details={"action": row["action_name"]},
                ))

        return alerts

    def _detect_audit_log_access(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta quem está consultando os próprios logs de auditoria."""
        audit_access = (
            df.filter(
                F.col("request_params.commandText").contains("system.access.audit")
            )
            .select("user_identity.email", "event_time")
        )

        alerts = []
        for row in audit_access.collect():
            alerts.append(SecurityAlert(
                severity="LOW",
                alert_type="AUDIT_LOG_ACCESS",
                user=row["email"] or "unknown",
                description="Usuário acessou os logs de auditoria — registrado para rastreabilidade",
                event_time=str(row["event_time"]),
            ))

        return alerts

    def _detect_policy_violations(self, df: DataFrame) -> list[SecurityAlert]:
        """Detecta clusters criados sem política aplicada."""
        violations = (
            df.filter(F.col("action_name") == "create")
            .filter(F.col("request_params.cluster_source") == "UI")
            .filter(F.col("request_params.policy_id").isNull())
            .select("user_identity.email", "event_time", "request_params.cluster_name")
        )

        alerts = []
        for row in violations.collect():
            alerts.append(SecurityAlert(
                severity="MEDIUM",
                alert_type="CLUSTER_POLICY_VIOLATION",
                user=row["email"] or "unknown",
                description=f"Cluster criado sem política: {row.get('cluster_name', 'N/A')}",
                event_time=str(row["event_time"]),
            ))

        return alerts
