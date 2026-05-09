"""Provisionamento e desativação de usuários no Databricks via SCIM API."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from databricks.sdk import WorkspaceClient, AccountClient
from databricks.sdk.service.iam import (
    ComplexValue,
    Group,
    PatchOp,
    PatchRequestOperation,
    User,
)

from src.utils.databricks_client import get_workspace_client, get_account_client

logger = logging.getLogger(__name__)


@dataclass
class UserProvisioningRequest:
    """Solicitação de criação de usuário com todos os atributos necessários."""
    email: str
    display_name: str
    team: str
    role: str  # admin | engineer | scientist | analyst | viewer
    cost_center: str
    manager_email: Optional[str] = None
    environments: list[str] = field(default_factory=lambda: ["dev"])
    expiry_date: Optional[str] = None  # ISO 8601 — para acessos temporários


# Mapeamento de papel para grupos Unity Catalog
ROLE_TO_GROUPS: dict[str, list[str]] = {
    "admin":     ["data-admins"],
    "engineer":  [],  # grupos por ambiente adicionados dinamicamente
    "scientist": ["data-scientists"],
    "analyst":   ["data-analysts"],
    "viewer":    [],
}


class UserProvisioner:
    """Orquestra criação, atualização e revogação de acessos de usuários."""

    def __init__(self, workspace_client: Optional[WorkspaceClient] = None,
                 account_client: Optional[AccountClient] = None):
        self.ws = workspace_client or get_workspace_client()
        self.ac = account_client or get_account_client()

    def onboard_user(self, request: UserProvisioningRequest) -> User:
        """Cria usuário e adiciona aos grupos corretos conforme papel e ambientes."""
        logger.info("Iniciando provisionamento de %s (papel: %s)", request.email, request.role)

        # Verificar se usuário já existe para evitar duplicatas
        existing = self._find_user(request.email)
        if existing:
            logger.warning("Usuário %s já existe. Atualizando grupos.", request.email)
            return self._update_user_groups(existing, request)

        # Criar usuário via SCIM
        user = self.ws.users.create(
            user_name=request.email,
            display_name=request.display_name,
            active=True,
            emails=[ComplexValue(value=request.email, primary=True)],
        )
        logger.info("Usuário criado: %s (ID: %s)", user.user_name, user.id)

        # Adicionar aos grupos conforme papel
        self._assign_groups(user, request)

        # Registrar no log de auditoria interno
        self._log_provisioning_event(
            action="ONBOARD",
            user_email=request.email,
            role=request.role,
            environments=request.environments,
            performed_by=self._get_current_user(),
        )

        return user

    def offboard_user(self, email: str, reason: str = "Desligamento") -> None:
        """Remove todos os acessos do usuário e desativa a conta.
        Não deleta o usuário — preserva histórico de auditoria.
        """
        logger.info("Iniciando offboarding de %s. Motivo: %s", email, reason)

        user = self._find_user(email)
        if not user:
            raise ValueError(f"Usuário {email} não encontrado no workspace.")

        # Remover de todos os grupos antes de desativar
        groups = list(self.ws.groups.list(filter=f"members co \"{user.id}\""))
        for group in groups:
            self._remove_from_group(user.id, group)
            logger.info("Removido do grupo: %s", group.display_name)

        # Revogar todos os tokens pessoais
        self._revoke_all_tokens(user.id)

        # Desativar conta — não deletar para preservar auditoria
        self.ws.users.update(
            id=user.id,
            user_name=email,
            active=False,
        )
        logger.info("Conta desativada: %s", email)

        self._log_provisioning_event(
            action="OFFBOARD",
            user_email=email,
            role="revoked",
            environments=[],
            performed_by=self._get_current_user(),
            details={"reason": reason},
        )

    def grant_temporary_access(
        self, email: str, group: str, duration_days: int, justification: str
    ) -> None:
        """Concede acesso temporário a um grupo com data de expiração."""
        user = self._find_user(email)
        if not user:
            raise ValueError(f"Usuário {email} não encontrado.")

        target_group = self._find_group(group)
        if not target_group:
            raise ValueError(f"Grupo {group} não encontrado.")

        self._add_to_group(user.id, target_group)

        expiry = datetime.now(timezone.utc).replace(microsecond=0)
        logger.info(
            "Acesso temporário concedido: %s → %s por %d dias. Justificativa: %s",
            email, group, duration_days, justification,
        )

        self._log_provisioning_event(
            action="TEMP_ACCESS",
            user_email=email,
            role=group,
            environments=[],
            performed_by=self._get_current_user(),
            details={
                "group": group,
                "duration_days": duration_days,
                "justification": justification,
                "expires_at": expiry.isoformat(),
            },
        )

    def _assign_groups(self, user: User, request: UserProvisioningRequest) -> None:
        base_groups = ROLE_TO_GROUPS.get(request.role, [])

        # Engenheiros recebem grupos por ambiente
        if request.role == "engineer":
            base_groups = [f"data-engineers-{env}" for env in request.environments]

        for group_name in base_groups:
            group = self._find_group(group_name)
            if group:
                self._add_to_group(user.id, group)
                logger.info("Usuário %s adicionado ao grupo: %s", user.user_name, group_name)
            else:
                logger.warning("Grupo %s não encontrado — ignorando.", group_name)

    def _update_user_groups(self, user: User, request: UserProvisioningRequest) -> User:
        self._assign_groups(user, request)
        return user

    def _find_user(self, email: str) -> Optional[User]:
        users = list(self.ws.users.list(filter=f"userName eq \"{email}\""))
        return users[0] if users else None

    def _find_group(self, display_name: str) -> Optional[Group]:
        groups = list(self.ws.groups.list(filter=f"displayName eq \"{display_name}\""))
        return groups[0] if groups else None

    def _add_to_group(self, user_id: str, group: Group) -> None:
        self.ws.groups.patch(
            id=group.id,
            operations=[
                PatchRequestOperation(
                    op=PatchOp.ADD,
                    path="members",
                    value=[{"value": user_id}],
                )
            ],
        )

    def _remove_from_group(self, user_id: str, group: Group) -> None:
        self.ws.groups.patch(
            id=group.id,
            operations=[
                PatchRequestOperation(
                    op=PatchOp.REMOVE,
                    path=f"members[value eq \"{user_id}\"]",
                )
            ],
        )

    def _revoke_all_tokens(self, user_id: str) -> None:
        tokens = list(self.ws.token_management.list(created_by_id=user_id))
        for token in tokens:
            self.ws.token_management.delete(token_id=token.token_id)
            logger.info("Token revogado: %s", token.comment)

    def _get_current_user(self) -> str:
        return self.ws.current_user.me().user_name or "automation"

    def _log_provisioning_event(self, action: str, user_email: str,
                                role: str, environments: list[str],
                                performed_by: str, details: dict = None) -> None:
        logger.info(
            "AUDITORIA | ação=%s | usuário=%s | papel=%s | ambientes=%s | executado_por=%s | detalhes=%s",
            action, user_email, role, environments, performed_by, details or {},
        )
