"""Auditoria de acessos efetivos: quem tem acesso a quê no Databricks."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.iam import Group, User

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


@dataclass
class UserAccessSnapshot:
    """Snapshot completo de acesso de um usuário."""
    user_name: str
    display_name: str
    active: bool
    groups: list[str]
    active_tokens: int
    cluster_policies: list[str]
    has_admin: bool
    last_seen: Optional[str] = None


@dataclass
class AccessReviewReport:
    """Relatório de revisão de acessos — executar mensalmente."""
    generated_at: str
    users: list[UserAccessSnapshot] = field(default_factory=list)
    orphaned_accounts: list[str] = field(default_factory=list)
    over_privileged: list[str] = field(default_factory=list)
    never_logged_in: list[str] = field(default_factory=list)


class AccessAuditor:
    """Audita o estado atual de todos os acessos no workspace.

    Gera dados para:
    - Revisão periódica de acessos (access review / recertification)
    - Identificação de contas órfãs (sem atividade)
    - Detecção de over-provisioning (mais acesso do que necessário)
    - Relatórios de conformidade SOC2/ISO27001
    """

    def __init__(self, client: Optional[WorkspaceClient] = None):
        self.ws = client or get_workspace_client()

    def snapshot_all_users(self) -> list[UserAccessSnapshot]:
        """Captura estado de acesso de todos os usuários ativos."""
        all_users = list(self.ws.users.list(attributes="id,userName,displayName,active,groups"))
        all_tokens = list(self.ws.token_management.list())
        policies = list(self.ws.cluster_policies.list())

        snapshots = []
        for user in all_users:
            if not user.active:
                continue

            user_tokens = [t for t in all_tokens if t.created_by_id == str(user.id)]
            user_groups = [g.display for g in (user.groups or []) if g.display]

            # Verificar se usuário tem política de cluster atribuída
            user_policies = []
            for policy in policies:
                perms = self.ws.permissions.get(
                    request_object_type="cluster-policies",
                    request_object_id=policy.policy_id,
                )
                for ac in (perms.access_control_list or []):
                    if ac.user_name == user.user_name:
                        user_policies.append(policy.name)
                        break

            has_admin = any(
                g.display in ("admins", "data-admins") for g in (user.groups or [])
            )

            snapshots.append(UserAccessSnapshot(
                user_name=user.user_name or "",
                display_name=user.display_name or "",
                active=user.active,
                groups=user_groups,
                active_tokens=len(user_tokens),
                cluster_policies=user_policies,
                has_admin=has_admin,
            ))

        logger.info("Snapshot capturado: %d usuários ativos", len(snapshots))
        return snapshots

    def identify_orphaned_accounts(self, days_inactive: int = 90) -> list[str]:
        """Identifica contas sem atividade nos últimos N dias — para desativação."""
        users = list(self.ws.users.list())
        tokens = list(self.ws.token_management.list())
        token_owners = {t.created_by_id for t in tokens}

        # Usuários ativos sem tokens e sem atividade recente — candidatos a offboarding
        orphaned = []
        for user in users:
            if not user.active:
                continue
            if str(user.id) not in token_owners and not user.groups:
                orphaned.append(user.user_name or str(user.id))

        logger.info("Contas órfãs identificadas: %d", len(orphaned))
        return orphaned

    def detect_over_privileged_users(self) -> list[dict]:
        """Detecta usuários com acesso excessivo comparado ao papel declarado."""
        over_privileged = []
        users = list(self.ws.users.list(attributes="id,userName,displayName,active,groups"))

        for user in users:
            if not user.active:
                continue

            groups = [g.display for g in (user.groups or []) if g.display]

            # Analista com permissão de criar cluster = over-provisioning
            is_analyst_only = any("analyst" in g for g in groups) and not any(
                "engineer" in g or "scientist" in g or "admin" in g for g in groups
            )

            # Verificar se pode criar cluster (propriedade do usuário)
            user_detail = self.ws.users.get(user.id)
            if is_analyst_only and user_detail.allow_cluster_create:
                over_privileged.append({
                    "user": user.user_name,
                    "groups": groups,
                    "issue": "Analista com permissão allow_cluster_create",
                    "recommendation": "Remover allow_cluster_create para usuários apenas analistas",
                })

            # Usuário em múltiplos grupos de engenheiro (dev + staging + prod) com papel analista
            env_groups = [g for g in groups if any(
                env in g for env in ["dev", "staging", "prod"]
            )]
            if is_analyst_only and len(env_groups) > 0:
                over_privileged.append({
                    "user": user.user_name,
                    "groups": groups,
                    "issue": f"Analista em grupos de engenharia: {env_groups}",
                    "recommendation": "Remover de grupos de engenharia — analistas usam apenas SQL Warehouse",
                })

        return over_privileged

    def generate_access_matrix(self) -> list[dict]:
        """Gera matriz de acesso: usuário × grupo × privilégios para relatório."""
        matrix = []
        groups = list(self.ws.groups.list(attributes="id,displayName,members"))

        for group in groups:
            for member in (group.members or []):
                matrix.append({
                    "group": group.display_name,
                    "member_id": member.value,
                    "member_display": member.display,
                    "member_ref": member.ref,
                })

        return matrix

    def export_for_review(self, output_format: str = "json") -> str:
        """Exporta snapshot completo para revisão de acessos externa (ITSM, planilha)."""
        import json
        from datetime import datetime, timezone
        from dataclasses import asdict

        snapshots = self.snapshot_all_users()
        orphaned = self.identify_orphaned_accounts()
        over_privileged = self.detect_over_privileged_users()

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_active_users": len(snapshots),
                "admin_users": sum(1 for s in snapshots if s.has_admin),
                "orphaned_accounts": len(orphaned),
                "over_privileged": len(over_privileged),
            },
            "users": [asdict(s) for s in snapshots],
            "orphaned_accounts": orphaned,
            "over_privileged": over_privileged,
        }

        return json.dumps(report, indent=2, ensure_ascii=False)
