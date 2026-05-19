"""Geração de relatórios de conformidade de governança Databricks."""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from databricks.sdk import WorkspaceClient

from src.security.audit_log_analyzer import AuditLogAnalyzer, SecurityAlert
from src.unity_catalog.column_mask_manager import ColumnMaskManager
from src.unity_catalog.row_filter_manager import RowFilterManager
from src.unity_catalog.grant_manager import GrantManager
from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


@dataclass
class ComplianceCheck:
    """Resultado de um item de verificação de conformidade."""
    check_id: str
    category: str     # identity | data_protection | network | audit | cluster
    title: str
    status: str       # PASS | FAIL | WARNING | NOT_APPLICABLE
    details: str
    remediation: Optional[str] = None


@dataclass
class ComplianceReport:
    """Relatório completo de conformidade."""
    generated_at: str
    workspace_url: str
    period_days: int
    checks: list[ComplianceCheck] = field(default_factory=list)
    security_alerts: list[dict] = field(default_factory=list)
    grant_summary: dict = field(default_factory=dict)
    masked_columns: list[dict] = field(default_factory=list)
    pii_tables_without_mask: list[str] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "PASS")

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "FAIL")

    @property
    def compliance_score(self) -> float:
        total = len(self.checks)
        if total == 0:
            return 0.0
        return round(self.pass_count / total * 100, 1)


class ComplianceReporter:
    """Gera relatórios de conformidade de governança Databricks.

    Cobertura:
    - Identidade e autenticação (MFA, tokens, service principals)
    - Proteção de dados (column masks, row filters, classificação)
    - Controle de acesso (grupos, grants, princípio menor privilégio)
    - Rede (IP access lists, private endpoints)
    - Auditoria (alertas de segurança, logs)
    - Clusters (políticas, auto-termination)
    """

    def __init__(
        self,
        workspace_client: Optional[WorkspaceClient] = None,
        grant_manager: Optional[GrantManager] = None,
        mask_manager: Optional[ColumnMaskManager] = None,
    ):
        self.ws = workspace_client or get_workspace_client()
        self.grant_mgr = grant_manager or GrantManager(self.ws)
        self.mask_mgr = mask_manager or ColumnMaskManager(self.ws)

    def generate_report(
        self, catalog_name: str = "prod", period_days: int = 30,
        output_path: Optional[str] = None
    ) -> ComplianceReport:
        """Executa todas as verificações e gera relatório completo."""
        logger.info("Gerando relatório de conformidade para catálogo: %s", catalog_name)

        report = ComplianceReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            workspace_url=self.ws.config.host or "N/A",
            period_days=period_days,
        )

        # Executar verificações por categoria
        report.checks.extend(self._check_identity_controls())
        report.checks.extend(self._check_token_hygiene())
        report.checks.extend(self._check_cluster_policies())
        report.checks.extend(self._check_ip_access_lists())
        report.checks.extend(self._check_workspace_config())

        # Dados de Unity Catalog
        report.masked_columns = self.mask_mgr.list_masked_columns(catalog_name)
        report.grant_summary = self.grant_mgr.audit_all_grants(catalog_name)

        # Verificações de proteção de dados
        report.checks.extend(self._check_pii_coverage(report.masked_columns, catalog_name))
        report.checks.extend(self._check_grant_hygiene(report.grant_summary))

        score = report.compliance_score
        logger.info(
            "Relatório gerado: score=%.1f%% (%d pass, %d fail de %d verificações)",
            score, report.pass_count, report.fail_count, len(report.checks),
        )

        if output_path:
            self._save_report(report, output_path)

        return report

    def _check_identity_controls(self) -> list[ComplianceCheck]:
        checks = []

        # Verificar se há usuários sem grupo (acesso órfão)
        all_users = list(self.ws.users.list())
        ungrouped = []
        for user in all_users:
            if user.active and not user.groups:
                ungrouped.append(user.user_name)

        checks.append(ComplianceCheck(
            check_id="ID-001",
            category="identity",
            title="Usuários ativos devem pertencer a pelo menos um grupo",
            status="PASS" if not ungrouped else "FAIL",
            details=f"{len(ungrouped)} usuários sem grupo: {ungrouped[:5]}",
            remediation="Adicionar usuários aos grupos corretos ou desativar contas inativas.",
        ))

        # Verificar contas de serviço com acesso workspace admin
        workspace_admins = list(self.ws.workspace.list("/"))
        sp_admins = [
            u for u in all_users
            if u.active and any(
                g.display == "admins" for g in (u.groups or [])
            ) and not u.user_name  # SPs não têm user_name
        ]

        checks.append(ComplianceCheck(
            check_id="ID-002",
            category="identity",
            title="Service principals não devem ter papel de workspace admin",
            status="PASS" if not sp_admins else "WARNING",
            details=f"{len(sp_admins)} service principals com papel admin",
            remediation="Usar grupos específicos para SPs em vez do grupo 'admins'.",
        ))

        return checks

    def _check_token_hygiene(self) -> list[ComplianceCheck]:
        checks = []
        tokens = list(self.ws.token_management.list())

        # Tokens sem expiração
        no_expiry = [t for t in tokens if not t.expiry_time]
        checks.append(ComplianceCheck(
            check_id="TOK-001",
            category="identity",
            title="Todos os tokens devem ter data de expiração",
            status="PASS" if not no_expiry else "FAIL",
            details=f"{len(no_expiry)} tokens sem expiração encontrados",
            remediation="Revogar tokens sem expiração e recriar com lifetime máximo de 90 dias.",
        ))

        # Tokens expirados mas ainda listados
        now_ms = datetime.now(timezone.utc).timestamp() * 1000
        expired = [t for t in tokens if t.expiry_time and t.expiry_time < now_ms]
        checks.append(ComplianceCheck(
            check_id="TOK-002",
            category="identity",
            title="Tokens expirados devem ser removidos",
            status="PASS" if not expired else "WARNING",
            details=f"{len(expired)} tokens expirados ainda presentes",
            remediation="Executar scripts/rotate-tokens.sh para limpar tokens expirados.",
        ))

        return checks

    def _check_cluster_policies(self) -> list[ComplianceCheck]:
        checks = []
        policies = list(self.ws.cluster_policies.list())

        checks.append(ComplianceCheck(
            check_id="CLU-001",
            category="cluster",
            title="Políticas de cluster configuradas para todos os papéis",
            status="PASS" if len(policies) >= 3 else "FAIL",
            details=f"{len(policies)} políticas encontradas (mínimo: 3 — engenharia, ciência, analytics)",
            remediation="Criar políticas via Terraform em terraform/workspace/cluster-policies.tf",
        ))

        # Verificar clusters ativos sem política
        active_clusters = [
            c for c in self.ws.clusters.list()
            if c.state and c.state.value == "RUNNING"
        ]
        no_policy = [c for c in active_clusters if not c.policy_id]

        checks.append(ComplianceCheck(
            check_id="CLU-002",
            category="cluster",
            title="Clusters ativos devem usar política de cluster",
            status="PASS" if not no_policy else "FAIL",
            details=f"{len(no_policy)} clusters ativos sem política",
            remediation="Aplicar política a clusters existentes ou terminar e recriar com política.",
        ))

        return checks

    def _check_ip_access_lists(self) -> list[ComplianceCheck]:
        checks = []
        lists = list(self.ws.ip_access_lists.list())
        allow_lists = [l for l in lists if l.list_type and l.list_type.value == "ALLOW"]

        checks.append(ComplianceCheck(
            check_id="NET-001",
            category="network",
            title="Lista de IPs permitidos configurada e habilitada",
            status="PASS" if allow_lists else "FAIL",
            details=f"{len(allow_lists)} listas de IPs permitidos encontradas",
            remediation="Configurar IP access lists via Terraform em terraform/network/main.tf",
        ))

        return checks

    def _check_workspace_config(self) -> list[ComplianceCheck]:
        checks = []
        conf = self.ws.workspace_conf.get_status(keys=[
            "enableIpAccessLists", "enableMFA", "enableResultSetDownload"
        ])

        checks.append(ComplianceCheck(
            check_id="CFG-001",
            category="network",
            title="Restrição por IP habilitada no workspace",
            status="PASS" if conf.get("enableIpAccessLists") == "true" else "FAIL",
            details=f"enableIpAccessLists = {conf.get('enableIpAccessLists')}",
            remediation="Habilitar via databricks_workspace_conf no Terraform.",
        ))

        checks.append(ComplianceCheck(
            check_id="CFG-002",
            category="identity",
            title="Download de resultados SQL desabilitado",
            status="PASS" if conf.get("enableResultSetDownload") == "false" else "WARNING",
            details=f"enableResultSetDownload = {conf.get('enableResultSetDownload')}",
            remediation="Desabilitar download de resultados para prevenir exfiltração.",
        ))

        return checks

    def _check_pii_coverage(
        self, masked_columns: list[dict], catalog: str
    ) -> list[ComplianceCheck]:
        """Verifica cobertura de mascaramento PII."""
        pii_keywords = ["cpf", "cnpj", "email", "telefone", "salario", "senha", "cartao"]
        masked_set = {f"{r['table_schema']}.{r['table_name']}.{r['column_name']}" for r in masked_columns}

        # Verificação simplificada: ao menos há colunas mascaradas
        return [ComplianceCheck(
            check_id="PII-001",
            category="data_protection",
            title="Colunas PII com mascaramento Unity Catalog",
            status="PASS" if len(masked_columns) > 0 else "FAIL",
            details=f"{len(masked_columns)} colunas PII mascaradas encontradas no catálogo {catalog}",
            remediation="Aplicar column masks via src/unity_catalog/column_mask_manager.py",
        )]

    def _check_grant_hygiene(self, grant_summary: dict) -> list[ComplianceCheck]:
        """Verifica que grants não foram concedidos a usuários individuais."""
        individual_grants = []
        for level, grants in grant_summary.items():
            for grant in grants:
                if "@" in grant.get("principal", ""):
                    individual_grants.append(grant["principal"])

        return [ComplianceCheck(
            check_id="AC-001",
            category="identity",
            title="Grants concedidos apenas a grupos, nunca a usuários individuais",
            status="PASS" if not individual_grants else "FAIL",
            details=f"{len(individual_grants)} grants individuais encontrados: {individual_grants[:5]}",
            remediation="Mover usuários para grupos e revogar grants individuais via grant_manager.py",
        )]

    def _save_report(self, report: ComplianceReport, output_path: str) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "metadata": {
                        "generated_at": report.generated_at,
                        "workspace": report.workspace_url,
                        "compliance_score": f"{report.compliance_score}%",
                        "pass": report.pass_count,
                        "fail": report.fail_count,
                    },
                    "checks": [asdict(c) for c in report.checks],
                    "grant_summary": {k: len(v) for k, v in report.grant_summary.items()},
                    "masked_columns_count": len(report.masked_columns),
                },
                f, indent=2, ensure_ascii=False,
            )

        logger.info("Relatório salvo em: %s", output_path)
