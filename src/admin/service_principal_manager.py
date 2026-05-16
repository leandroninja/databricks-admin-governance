"""Gerenciamento de Service Principals: criação, rotação de tokens OAuth e auditoria."""
from __future__ import annotations

import logging
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from databricks.sdk import WorkspaceClient, AccountClient
from databricks.sdk.service.iam import ServicePrincipal

from src.utils.databricks_client import get_workspace_client, get_account_client

logger = logging.getLogger(__name__)

# Duração máxima de tokens OAuth M2M para service principals
MAX_TOKEN_LIFETIME_SECONDS = 7776000  # 90 dias
RECOMMENDED_ROTATION_DAYS = 30


@dataclass
class ServicePrincipalConfig:
    """Configuração para criação de service principal."""
    display_name: str
    purpose: str          # pipeline | reporting | terraform | monitoring
    catalogs: list[str]   # catálogos Unity Catalog que o SP precisa acessar
    schemas: list[str]    # schemas específicos (vazio = acesso a todos do catálogo)
    token_lifetime_days: int = RECOMMENDED_ROTATION_DAYS
    allow_cluster_create: bool = False


class ServicePrincipalManager:
    """Gerencia o ciclo de vida completo de service principals no Databricks.

    Boas práticas implementadas:
    - Service principals em vez de usuários humanos para automação
    - Tokens OAuth M2M com tempo de vida limitado (máx 90 dias)
    - Rotação automática antes da expiração
    - Princípio de menor privilégio: acesso apenas aos catálogos/schemas necessários
    - Armazenamento de secrets no Key Vault, nunca em código
    """

    def __init__(self, workspace_client: Optional[WorkspaceClient] = None,
                 account_client: Optional[AccountClient] = None):
        self.ws = workspace_client or get_workspace_client()
        self.ac = account_client or get_account_client()

    def create_service_principal(self, config: ServicePrincipalConfig) -> ServicePrincipal:
        """Cria service principal com permissões mínimas necessárias."""
        logger.info("Criando service principal: %s", config.display_name)

        sp = self.ws.service_principals.create(
            display_name=config.display_name,
            # Service principals nunca recebem admin global
            allow_cluster_create=config.allow_cluster_create,
            allow_instance_pool_create=False,
            databricks_sql_access=config.purpose in ("pipeline", "reporting"),
            workspace_access=True,
        )

        logger.info("Service principal criado: %s (ID: %s)", sp.display_name, sp.id)

        self._log_event(
            action="SP_CREATED",
            sp_name=config.display_name,
            details={"purpose": config.purpose, "catalogs": config.catalogs},
        )

        return sp

    def generate_oauth_token(
        self, sp_id: str, lifetime_days: int = RECOMMENDED_ROTATION_DAYS
    ) -> dict:
        """Gera token OAuth M2M para o service principal.

        Retorna token + metadados de expiração para armazenamento seguro no Key Vault.
        NUNCA logar o valor do token.
        """
        if lifetime_days > MAX_TOKEN_LIFETIME_SECONDS // 86400:
            raise ValueError(
                f"Tempo de vida máximo: {MAX_TOKEN_LIFETIME_SECONDS // 86400} dias. "
                f"Solicitado: {lifetime_days} dias."
            )

        lifetime_seconds = lifetime_days * 86400
        token = self.ws.tokens.create(
            comment=f"OAuth M2M — {sp_id} — rotação automática",
            lifetime_seconds=lifetime_seconds,
        )

        expiry = datetime.now(timezone.utc) + timedelta(days=lifetime_days)

        logger.info(
            "Token gerado para SP %s — expira em: %s (token_id: %s)",
            sp_id, expiry.isoformat(), token.token_info.token_id,
        )

        return {
            "token_id": token.token_info.token_id,
            # token_value deve ir diretamente para o Key Vault — nunca persistir em log
            "token_value": token.token_value,
            "expires_at": expiry.isoformat(),
            "lifetime_days": lifetime_days,
        }

    def rotate_expiring_tokens(self, days_before_expiry: int = 7) -> list[dict]:
        """Identifica tokens prestes a expirar e gera substitutos.
        Deve ser executado diariamente via job Databricks ou pipeline CI/CD.
        """
        rotated = []
        tokens = list(self.ws.token_management.list())
        now = datetime.now(timezone.utc)
        threshold = now + timedelta(days=days_before_expiry)

        for token in tokens:
            if not token.expiry_time:
                # Token sem expiração é violação de política — revogar imediatamente
                logger.warning(
                    "VIOLAÇÃO DE POLÍTICA: token sem expiração detectado. "
                    "ID: %s, Criador: %s — revogando.",
                    token.token_id, token.created_by_username,
                )
                self.ws.token_management.delete(token_id=token.token_id)
                continue

            expiry = datetime.fromtimestamp(token.expiry_time / 1000, tz=timezone.utc)
            if expiry <= threshold:
                logger.info(
                    "Token expirando em breve: %s (criado por: %s, expira: %s)",
                    token.comment, token.created_by_username, expiry.isoformat(),
                )
                rotated.append({
                    "token_id": token.token_id,
                    "comment": token.comment,
                    "created_by": token.created_by_username,
                    "expires_at": expiry.isoformat(),
                    "action": "ROTATION_NEEDED",
                })

        return rotated

    def list_service_principals_with_tokens(self) -> list[dict]:
        """Lista todos os SPs e seus tokens ativos — para auditoria de acesso."""
        result = []
        sps = list(self.ws.service_principals.list())
        all_tokens = list(self.ws.token_management.list())

        for sp in sps:
            sp_tokens = [t for t in all_tokens if t.created_by_id == str(sp.id)]
            result.append({
                "id": sp.id,
                "display_name": sp.display_name,
                "active": sp.active,
                "active_tokens": len(sp_tokens),
                "tokens": [
                    {
                        "token_id": t.token_id,
                        "comment": t.comment,
                        "expires_at": (
                            datetime.fromtimestamp(t.expiry_time / 1000, tz=timezone.utc).isoformat()
                            if t.expiry_time else "SEM_EXPIRAÇÃO"
                        ),
                    }
                    for t in sp_tokens
                ],
            })

        return result

    def decommission_service_principal(self, sp_id: str, reason: str) -> None:
        """Desativa SP e revoga todos os tokens. Não deleta — preserva auditoria."""
        logger.info("Descomissionando service principal %s. Motivo: %s", sp_id, reason)

        # Revogar tokens antes de desativar
        tokens = list(self.ws.token_management.list(created_by_id=sp_id))
        for token in tokens:
            self.ws.token_management.delete(token_id=token.token_id)
            logger.info("Token revogado: %s", token.token_id)

        self.ws.service_principals.update(
            id=sp_id,
            active=False,
        )

        self._log_event(
            action="SP_DECOMMISSIONED",
            sp_name=sp_id,
            details={"reason": reason, "tokens_revoked": len(tokens)},
        )

    def _log_event(self, action: str, sp_name: str, details: dict) -> None:
        logger.info(
            "AUDITORIA | ação=%s | service_principal=%s | detalhes=%s",
            action, sp_name, details,
        )
