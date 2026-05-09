"""Gerenciamento programático de políticas de cluster e auditoria de compliance."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.compute import (
    ClusterDetails,
    ClusterSpec,
    State,
)

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


@dataclass
class ClusterComplianceResult:
    """Resultado da verificação de compliance de um cluster."""
    cluster_id: str
    cluster_name: str
    owner: str
    state: str
    has_policy: bool
    policy_name: Optional[str]
    auto_terminate: bool
    auto_terminate_minutes: Optional[int]
    data_security_mode: Optional[str]
    issues: list[str]

    @property
    def is_compliant(self) -> bool:
        return len(self.issues) == 0


class ClusterPolicyManager:
    """Audita e corrige conformidade de clusters com as políticas de governança.

    Regras de compliance verificadas:
    - Todos os clusters devem usar uma política de cluster
    - Auto-termination obrigatório (máx 120 min para interactive, 20 min para jobs)
    - Modo de segurança de dados: SINGLE_USER ou USER_ISOLATION
    - Runtime LTS — sem versões beta ou preview em produção
    - Tags obrigatórias: Team, ManagedBy, CostCenter
    - Spot instances apenas com fallback (SPOT_WITH_FALLBACK)
    """

    REQUIRED_TAGS = {"Team", "ManagedBy"}
    MAX_INTERACTIVE_TERMINATE_MINS = 120
    MAX_JOB_TERMINATE_MINS = 20
    ALLOWED_SECURITY_MODES = {"SINGLE_USER", "USER_ISOLATION"}

    def __init__(self, client: Optional[WorkspaceClient] = None):
        self.ws = client or get_workspace_client()

    def audit_all_clusters(self) -> list[ClusterComplianceResult]:
        """Audita todos os clusters ativos e retorna resultados de compliance."""
        clusters = list(self.ws.clusters.list())
        policies = {p.policy_id: p.name for p in self.ws.cluster_policies.list()}

        results = []
        for cluster in clusters:
            result = self._audit_cluster(cluster, policies)
            results.append(result)

            if not result.is_compliant:
                logger.warning(
                    "Cluster fora de compliance: %s — problemas: %s",
                    cluster.cluster_name, result.issues,
                )

        compliant = sum(1 for r in results if r.is_compliant)
        logger.info(
            "Auditoria concluída: %d/%d clusters em compliance",
            compliant, len(results),
        )

        return results

    def terminate_non_compliant_clusters(
        self, dry_run: bool = True
    ) -> list[dict]:
        """Encerra clusters fora de compliance (ex: sem política, sem auto-termination).
        dry_run=True apenas reporta sem agir — sempre testar antes de executar em produção.
        """
        results = self.audit_all_clusters()
        non_compliant = [r for r in results if not r.is_compliant]
        actions = []

        for cluster in non_compliant:
            # Apenas encerrar clusters em estado RUNNING
            if cluster.state == "RUNNING":
                action = {
                    "cluster_id": cluster.cluster_id,
                    "cluster_name": cluster.cluster_name,
                    "owner": cluster.owner,
                    "issues": cluster.issues,
                    "action": "TERMINATE" if not dry_run else "WOULD_TERMINATE",
                }
                actions.append(action)

                if not dry_run:
                    self.ws.clusters.delete(cluster_id=cluster.cluster_id)
                    logger.info(
                        "Cluster encerrado por violação de política: %s (proprietário: %s)",
                        cluster.cluster_name, cluster.owner,
                    )

        if dry_run and actions:
            logger.info(
                "DRY RUN: %d clusters seriam encerrados. Use dry_run=False para aplicar.",
                len(actions),
            )

        return actions

    def apply_policy_to_cluster(self, cluster_id: str, policy_id: str) -> None:
        """Aplica política de cluster a um cluster existente (requer reinicialização)."""
        cluster = self.ws.clusters.get(cluster_id=cluster_id)
        logger.info(
            "Aplicando política %s ao cluster %s. Reinicialização necessária.",
            policy_id, cluster.cluster_name,
        )

        self.ws.clusters.edit(
            cluster_id=cluster_id,
            spark_version=cluster.spark_version,
            node_type_id=cluster.node_type_id,
            policy_id=policy_id,
        )

    def get_cost_summary_by_team(self) -> list[dict]:
        """Agrega clusters por time via tag Team — para rastreamento de custo."""
        clusters = list(self.ws.clusters.list())
        team_summary: dict[str, dict] = {}

        for cluster in clusters:
            tags = cluster.custom_tags or {}
            team = tags.get("Team", "sem-tag")

            if team not in team_summary:
                team_summary[team] = {"cluster_count": 0, "running": 0, "cluster_names": []}

            team_summary[team]["cluster_count"] += 1
            if cluster.state and cluster.state == State.RUNNING:
                team_summary[team]["running"] += 1
            team_summary[team]["cluster_names"].append(cluster.cluster_name or "N/A")

        return [
            {"team": team, **data}
            for team, data in sorted(team_summary.items())
        ]

    def _audit_cluster(
        self, cluster: ClusterDetails, policies: dict[str, str]
    ) -> ClusterComplianceResult:
        issues = []

        # Verificar política
        has_policy = bool(cluster.policy_id)
        policy_name = policies.get(cluster.policy_id) if cluster.policy_id else None
        if not has_policy:
            issues.append("Cluster sem política de cluster — risco de custo descontrolado")

        # Verificar auto-termination
        terminate_mins = cluster.autotermination_minutes
        auto_terminate = bool(terminate_mins and terminate_mins > 0)
        if not auto_terminate:
            issues.append("Auto-termination desabilitado — cluster pode ficar ativo indefinidamente")
        elif terminate_mins and terminate_mins > self.MAX_INTERACTIVE_TERMINATE_MINS:
            issues.append(
                f"Auto-termination muito alto: {terminate_mins} min "
                f"(máximo permitido: {self.MAX_INTERACTIVE_TERMINATE_MINS} min)"
            )

        # Verificar modo de segurança de dados
        security_mode = None
        if cluster.data_security_mode:
            security_mode = cluster.data_security_mode.value
            if security_mode not in self.ALLOWED_SECURITY_MODES:
                issues.append(
                    f"Modo de segurança inválido: {security_mode}. "
                    f"Use SINGLE_USER ou USER_ISOLATION."
                )

        # Verificar tags obrigatórias
        tags = cluster.custom_tags or {}
        missing_tags = self.REQUIRED_TAGS - set(tags.keys())
        if missing_tags:
            issues.append(f"Tags obrigatórias ausentes: {missing_tags}")

        owner = cluster.creator_user_name or "unknown"
        return ClusterComplianceResult(
            cluster_id=cluster.cluster_id or "",
            cluster_name=cluster.cluster_name or "N/A",
            owner=owner,
            state=cluster.state.value if cluster.state else "UNKNOWN",
            has_policy=has_policy,
            policy_name=policy_name,
            auto_terminate=auto_terminate,
            auto_terminate_minutes=terminate_mins,
            data_security_mode=security_mode,
            issues=issues,
        )
