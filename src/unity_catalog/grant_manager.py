"""Gerenciamento fino de grants no Unity Catalog com auditoria completa."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import (
    PermissionsChange,
    Privilege,
    SecurableType,
)

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


class DataRole(str, Enum):
    """Papéis padronizados mapeados para conjuntos de privilégios Unity Catalog."""
    DATA_OWNER      = "data_owner"
    DATA_ENGINEER   = "data_engineer"
    DATA_SCIENTIST  = "data_scientist"
    DATA_ANALYST    = "data_analyst"
    VIEWER          = "viewer"
    PIPELINE_SP     = "pipeline_sp"


# Matriz de privilégios por papel — jamais conceder ALL_PRIVILEGES a usuários finais
ROLE_PRIVILEGES: dict[DataRole, list[Privilege]] = {
    DataRole.DATA_OWNER: [
        Privilege.ALL_PRIVILEGES,
    ],
    DataRole.DATA_ENGINEER: [
        Privilege.USE_CATALOG,
        Privilege.USE_SCHEMA,
        Privilege.CREATE_TABLE,
        Privilege.CREATE_FUNCTION,
        Privilege.CREATE_VOLUME,
        Privilege.SELECT,
        Privilege.MODIFY,
    ],
    DataRole.DATA_SCIENTIST: [
        Privilege.USE_CATALOG,
        Privilege.USE_SCHEMA,
        Privilege.SELECT,
        Privilege.CREATE_TABLE,  # para tabelas de feature store e experimentos
    ],
    DataRole.DATA_ANALYST: [
        Privilege.USE_CATALOG,
        Privilege.USE_SCHEMA,
        Privilege.SELECT,
    ],
    DataRole.VIEWER: [
        Privilege.USE_CATALOG,
        Privilege.USE_SCHEMA,
        Privilege.SELECT,
    ],
    DataRole.PIPELINE_SP: [
        Privilege.USE_CATALOG,
        Privilege.USE_SCHEMA,
        Privilege.SELECT,
        Privilege.MODIFY,
        Privilege.CREATE_TABLE,
        Privilege.REFRESH,
    ],
}


@dataclass
class GrantRequest:
    """Solicitação de grant com contexto para auditoria."""
    principal: str          # grupo Unity Catalog (nunca usuário individual)
    role: DataRole
    securable_type: str     # catalog | schema | table | function | volume
    securable_name: str     # ex: prod.vendas.transacoes
    justification: str
    requested_by: str
    ticket_id: Optional[str] = None  # ID do ticket ITSM para rastreabilidade


class GrantManager:
    """Controla concessão e revogação de privileges Unity Catalog.

    Princípios aplicados:
    - Grants apenas para grupos, nunca para usuários individuais
    - Todos os grants registrados com justificativa e rastreabilidade
    - Revisão de acessos suportada por listagem de grants efetivos
    - Separação de funções: analistas não podem modificar dados de produção
    """

    def __init__(self, client: Optional[WorkspaceClient] = None):
        self.ws = client or get_workspace_client()

    def grant(self, request: GrantRequest) -> None:
        """Concede privileges ao principal conforme papel padronizado."""
        self._validate_request(request)

        privileges = ROLE_PRIVILEGES[request.role]
        securable_type = self._resolve_securable_type(request.securable_type)

        changes = [
            PermissionsChange(
                add=privileges,
                principal=request.principal,
            )
        ]

        self.ws.grants.update(
            securable_type=securable_type,
            full_name=request.securable_name,
            changes=changes,
        )

        logger.info(
            "GRANT concedido | principal=%s | papel=%s | objeto=%s/%s | ticket=%s | justificativa=%s",
            request.principal,
            request.role.value,
            request.securable_type,
            request.securable_name,
            request.ticket_id,
            request.justification,
        )

    def revoke(self, principal: str, securable_type: str,
               securable_name: str, justification: str,
               revoked_by: str) -> None:
        """Revoga todos os privileges de um principal em um objeto."""
        st = self._resolve_securable_type(securable_type)

        current = self.ws.grants.get(securable_type=st, full_name=securable_name)
        if not current.privilege_assignments:
            logger.info("Nenhum grant encontrado para %s em %s", principal, securable_name)
            return

        principal_grants = [
            pa for pa in current.privilege_assignments
            if pa.principal == principal
        ]

        if not principal_grants:
            logger.info("Principal %s não tem grants em %s", principal, securable_name)
            return

        privileges_to_remove = principal_grants[0].privileges

        changes = [
            PermissionsChange(
                remove=privileges_to_remove,
                principal=principal,
            )
        ]

        self.ws.grants.update(
            securable_type=st,
            full_name=securable_name,
            changes=changes,
        )

        logger.info(
            "GRANT revogado | principal=%s | objeto=%s/%s | privileges=%s | revogado_por=%s | motivo=%s",
            principal, securable_type, securable_name,
            [p.value for p in privileges_to_remove],
            revoked_by, justification,
        )

    def list_grants(self, securable_type: str, securable_name: str) -> list[dict]:
        """Lista todos os grants efetivos em um objeto para revisão de acesso."""
        st = self._resolve_securable_type(securable_type)
        result = self.ws.grants.get(securable_type=st, full_name=securable_name)

        grants = []
        if result.privilege_assignments:
            for pa in result.privilege_assignments:
                grants.append({
                    "principal": pa.principal,
                    "privileges": [p.value for p in (pa.privileges or [])],
                    "securable_type": securable_type,
                    "securable_name": securable_name,
                })

        return grants

    def audit_all_grants(self, catalog_name: str) -> dict[str, list[dict]]:
        """Auditoria completa de grants em um catálogo — usado em revisões periódicas."""
        report: dict[str, list[dict]] = {
            "catalog": self.list_grants("catalog", catalog_name),
            "schemas": [],
            "tables": [],
        }

        schemas = list(self.ws.schemas.list(catalog_name=catalog_name))
        for schema in schemas:
            schema_full = f"{catalog_name}.{schema.name}"
            schema_grants = self.list_grants("schema", schema_full)
            if schema_grants:
                report["schemas"].extend(schema_grants)

            tables = list(self.ws.tables.list(
                catalog_name=catalog_name, schema_name=schema.name
            ))
            for table in tables:
                table_grants = self.list_grants("table", table.full_name)
                if table_grants:
                    report["tables"].extend(table_grants)

        total = sum(len(v) for v in report.values())
        logger.info("Auditoria concluída para catálogo %s: %d grants encontrados", catalog_name, total)
        return report

    def _validate_request(self, request: GrantRequest) -> None:
        # Proibir grants diretos a usuários individuais — apenas grupos
        if "@" in request.principal:
            raise ValueError(
                f"Grants individuais não são permitidos. "
                f"Adicione '{request.principal}' a um grupo Unity Catalog."
            )

        if not request.justification or len(request.justification) < 10:
            raise ValueError("Justificativa obrigatória com mínimo de 10 caracteres.")

    def _resolve_securable_type(self, securable_type: str) -> SecurableType:
        mapping = {
            "catalog":           SecurableType.CATALOG,
            "schema":            SecurableType.SCHEMA,
            "table":             SecurableType.TABLE,
            "function":          SecurableType.FUNCTION,
            "volume":            SecurableType.VOLUME,
            "external_location": SecurableType.EXTERNAL_LOCATION,
            "storage_credential": SecurableType.STORAGE_CREDENTIAL,
        }
        st = mapping.get(securable_type.lower())
        if not st:
            raise ValueError(f"Tipo de objeto não suportado: {securable_type}")
        return st
