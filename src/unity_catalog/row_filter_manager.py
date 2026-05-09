"""Segurança em nível de linha (Row-Level Security) via Unity Catalog row filters."""
from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass
from typing import Optional

from databricks.sdk import WorkspaceClient

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


@dataclass
class RowFilterPolicy:
    """Política de RLS para uma tabela."""
    catalog: str
    schema: str
    table: str
    filter_function_name: str    # função SQL que implementa a regra
    filter_column: str           # coluna passada para a função de filtro
    description: str


class RowFilterManager:
    """Gerencia Row-Level Security (RLS) via Unity Catalog Row Filters.

    Implementação:
    - Funções SQL criadas no schema `security` do catálogo correspondente
    - Funções verificam membership de grupo via IS_ACCOUNT_GROUP_MEMBER()
    - Grupo 'data-admins' sempre tem acesso irrestrito (bypass)
    - Aplicadas via ALTER TABLE ... SET ROW FILTER
    """

    SECURITY_SCHEMA = "security"
    ADMIN_BYPASS_GROUP = "data-admins"

    def __init__(self, client: Optional[WorkspaceClient] = None):
        self.ws = client or get_workspace_client()

    def create_team_row_filter(self, catalog: str, team_column: str) -> str:
        """Cria função de filtro que restringe linhas por time do usuário.
        Retorna o nome completo da função criada.
        """
        function_name = f"{catalog}.{self.SECURITY_SCHEMA}.filter_by_team"

        # Garantir que o schema de segurança existe
        self._ensure_security_schema(catalog)

        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {function_name}(team_col STRING)
            RETURN
              IS_ACCOUNT_GROUP_MEMBER('{self.ADMIN_BYPASS_GROUP}')
              OR IS_ACCOUNT_GROUP_MEMBER(team_col)
              OR IS_ACCOUNT_GROUP_MEMBER(CONCAT(team_col, '-data-owners'))
        """).strip()

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

        logger.info("Row filter criado: %s (coluna de time: %s)", function_name, team_column)
        return function_name

    def create_environment_row_filter(self, catalog: str) -> str:
        """Cria filtro que permite ver apenas dados do próprio ambiente.
        Útil para tabelas multi-ambiente compartilhadas.
        """
        function_name = f"{catalog}.{self.SECURITY_SCHEMA}.filter_by_environment"
        self._ensure_security_schema(catalog)

        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {function_name}(env_col STRING)
            RETURN
              IS_ACCOUNT_GROUP_MEMBER('{self.ADMIN_BYPASS_GROUP}')
              OR (
                (IS_ACCOUNT_GROUP_MEMBER('data-engineers-prod') AND env_col = 'prod')
                OR (IS_ACCOUNT_GROUP_MEMBER('data-engineers-staging') AND env_col = 'staging')
                OR (IS_ACCOUNT_GROUP_MEMBER('data-engineers-dev') AND env_col IN ('dev', 'staging', 'prod'))
              )
        """).strip()

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

        logger.info("Row filter de ambiente criado: %s", function_name)
        return function_name

    def create_cost_center_row_filter(self, catalog: str) -> str:
        """Cria filtro que restringe linhas pelo centro de custo do usuário.
        Usado em tabelas financeiras onde cada time vê apenas seus dados.
        """
        function_name = f"{catalog}.{self.SECURITY_SCHEMA}.filter_by_cost_center"
        self._ensure_security_schema(catalog)

        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {function_name}(cost_center_col STRING)
            RETURN
              IS_ACCOUNT_GROUP_MEMBER('{self.ADMIN_BYPASS_GROUP}')
              OR IS_ACCOUNT_GROUP_MEMBER('financeiro-data-owners')
              OR IS_ACCOUNT_GROUP_MEMBER(CONCAT('cc-', cost_center_col))
        """).strip()

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

        logger.info("Row filter de centro de custo criado: %s", function_name)
        return function_name

    def apply_row_filter(self, policy: RowFilterPolicy) -> None:
        """Aplica função de row filter a uma tabela via ALTER TABLE."""
        full_table = f"{policy.catalog}.{policy.schema}.{policy.table}"

        sql = textwrap.dedent(f"""
            ALTER TABLE {full_table}
            SET ROW FILTER {policy.filter_function_name} ON ({policy.filter_column})
        """).strip()

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=policy.catalog,
        )

        logger.info(
            "Row filter aplicado: tabela=%s, função=%s, coluna=%s",
            full_table, policy.filter_function_name, policy.filter_column,
        )

    def remove_row_filter(self, catalog: str, schema: str, table: str) -> None:
        """Remove row filter de uma tabela."""
        full_table = f"{catalog}.{schema}.{table}"

        sql = f"ALTER TABLE {full_table} DROP ROW FILTER"

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

        logger.info("Row filter removido da tabela: %s", full_table)

    def list_tables_with_row_filters(self, catalog: str, schema: str) -> list[dict]:
        """Lista tabelas com row filters aplicados — para auditoria."""
        sql = textwrap.dedent(f"""
            SELECT
                table_catalog,
                table_schema,
                table_name,
                row_filter_function_name,
                row_filter_input_columns
            FROM {catalog}.information_schema.tables
            WHERE table_catalog = '{catalog}'
              AND table_schema   = '{schema}'
              AND row_filter_function_name IS NOT NULL
            ORDER BY table_name
        """).strip()

        result = self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

        rows = []
        if result.result and result.result.data_array:
            cols = [c.name for c in result.manifest.schema.columns]
            for row in result.result.data_array:
                rows.append(dict(zip(cols, row)))

        return rows

    def _ensure_security_schema(self, catalog: str) -> None:
        sql = f"CREATE SCHEMA IF NOT EXISTS {catalog}.{self.SECURITY_SCHEMA}"
        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

    def _get_warehouse_id(self) -> str:
        warehouses = list(self.ws.warehouses.list())
        if not warehouses:
            raise RuntimeError("Nenhum SQL Warehouse disponível para execução de SQL.")
        # Preferir warehouse de engenharia para operações administrativas
        for wh in warehouses:
            if "engineering" in (wh.name or "").lower():
                return wh.id
        return warehouses[0].id
