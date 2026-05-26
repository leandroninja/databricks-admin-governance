"""Mascaramento de colunas PII via Unity Catalog Column Masks."""
from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from databricks.sdk import WorkspaceClient

from src.utils.databricks_client import get_workspace_client

logger = logging.getLogger(__name__)


class PIIType(str, Enum):
    """Tipos de dados PII com estratégias de mascaramento específicas."""
    CPF             = "cpf"
    CNPJ            = "cnpj"
    EMAIL           = "email"
    TELEFONE        = "telefone"
    NOME_COMPLETO   = "nome_completo"
    DATA_NASCIMENTO = "data_nascimento"
    CARTAO_CREDITO  = "cartao_credito"
    SENHA_HASH      = "senha_hash"
    SALARIO         = "salario"
    ENDERECO        = "endereco"


@dataclass
class ColumnMaskPolicy:
    """Configuração de mascaramento para uma coluna."""
    catalog: str
    schema: str
    table: str
    column: str
    pii_type: PIIType
    groups_with_full_access: list[str] = field(
        default_factory=lambda: ["data-admins", "pii-access"]
    )


class ColumnMaskManager:
    """Gerencia Column Masking para dados PII via Unity Catalog.

    Estratégias por tipo de dado:
    - CPF: exibe apenas últimos 3 dígitos → ***.***.*XX-**
    - Email: exibe domínio, oculta usuário → ***@empresa.com
    - Cartão: exibe apenas últimos 4 dígitos → ****-****-****-1234
    - Salário: retorna NULL para não autorizados (mais seguro que valor genérico)
    - Nome: exibe apenas primeiro nome
    - Data nascimento: exibe apenas ano

    Grupos 'data-admins' e 'pii-access' sempre veem dados reais.
    """

    SECURITY_SCHEMA = "security"
    ADMIN_GROUP = "data-admins"
    PII_ACCESS_GROUP = "pii-access"

    def __init__(self, client: Optional[WorkspaceClient] = None):
        self.ws = client or get_workspace_client()

    def create_all_mask_functions(self, catalog: str) -> dict[PIIType, str]:
        """Cria todas as funções de mascaramento PII no schema security."""
        self._ensure_security_schema(catalog)
        created: dict[PIIType, str] = {}

        creators = {
            PIIType.CPF:             self._create_cpf_mask,
            PIIType.CNPJ:            self._create_cnpj_mask,
            PIIType.EMAIL:           self._create_email_mask,
            PIIType.TELEFONE:        self._create_telefone_mask,
            PIIType.NOME_COMPLETO:   self._create_nome_mask,
            PIIType.DATA_NASCIMENTO: self._create_data_nasc_mask,
            PIIType.CARTAO_CREDITO:  self._create_cartao_mask,
            PIIType.SALARIO:         self._create_salario_mask,
            PIIType.ENDERECO:        self._create_endereco_mask,
        }

        for pii_type, creator in creators.items():
            function_name = creator(catalog)
            created[pii_type] = function_name
            logger.info("Função de mascaramento criada: %s → %s", pii_type.value, function_name)

        return created

    def apply_column_mask(self, policy: ColumnMaskPolicy) -> None:
        """Aplica máscara a uma coluna via ALTER TABLE ... ALTER COLUMN."""
        full_table = f"{policy.catalog}.{policy.schema}.{policy.table}"

        # Mapear tipo PII para nome da função
        function_map = {
            PIIType.CPF:             f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_cpf",
            PIIType.CNPJ:            f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_cnpj",
            PIIType.EMAIL:           f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_email",
            PIIType.TELEFONE:        f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_telefone",
            PIIType.NOME_COMPLETO:   f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_nome_completo",
            PIIType.DATA_NASCIMENTO: f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_data_nascimento",
            PIIType.CARTAO_CREDITO:  f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_cartao_credito",
            PIIType.SALARIO:         f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_salario",
            PIIType.ENDERECO:        f"{policy.catalog}.{self.SECURITY_SCHEMA}.mask_endereco",
        }

        function_name = function_map[policy.pii_type]

        sql = textwrap.dedent(f"""
            ALTER TABLE {full_table}
            ALTER COLUMN {policy.column}
            SET MASK {function_name}
        """).strip()

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=policy.catalog,
        )

        logger.info(
            "Column mask aplicado: tabela=%s, coluna=%s, tipo_pii=%s, função=%s",
            full_table, policy.column, policy.pii_type.value, function_name,
        )

    def remove_column_mask(self, catalog: str, schema: str, table: str, column: str) -> None:
        """Remove máscara de uma coluna."""
        full_table = f"{catalog}.{schema}.{table}"
        sql = f"ALTER TABLE {full_table} ALTER COLUMN {column} DROP MASK"

        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )
        logger.info("Column mask removido: tabela=%s, coluna=%s", full_table, column)

    def list_masked_columns(self, catalog: str) -> list[dict]:
        """Lista todas as colunas com mascaramento ativo — para auditoria de PII."""
        sql = textwrap.dedent(f"""
            SELECT
                c.table_catalog,
                c.table_schema,
                c.table_name,
                c.column_name,
                c.data_type,
                c.mask_function_name
            FROM {catalog}.information_schema.columns c
            WHERE c.table_catalog = '{catalog}'
              AND c.mask_function_name IS NOT NULL
            ORDER BY c.table_schema, c.table_name, c.column_name
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

    # ── Funções SQL de mascaramento ────────────────────────────────────────────

    def _auth_check(self) -> str:
        """Expressão SQL de verificação de autorização PII."""
        return (
            f"IS_ACCOUNT_GROUP_MEMBER('{self.ADMIN_GROUP}') "
            f"OR IS_ACCOUNT_GROUP_MEMBER('{self.PII_ACCESS_GROUP}')"
        )

    def _create_cpf_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_cpf"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(cpf STRING)
            RETURN CASE
              WHEN {auth} THEN cpf
              ELSE CONCAT('***.***.', SUBSTRING(cpf, 8, 3), '-**')
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_cnpj_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_cnpj"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(cnpj STRING)
            RETURN CASE
              WHEN {auth} THEN cnpj
              ELSE CONCAT('**.***/****-', RIGHT(cnpj, 2))
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_email_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_email"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(email STRING)
            RETURN CASE
              WHEN {auth} THEN email
              ELSE CONCAT('***@', SPLIT_PART(email, '@', 2))
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_telefone_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_telefone"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(tel STRING)
            RETURN CASE
              WHEN {auth} THEN tel
              ELSE CONCAT('(**) *****-', RIGHT(REGEXP_REPLACE(tel, '[^0-9]', ''), 4))
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_nome_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_nome_completo"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(nome STRING)
            RETURN CASE
              WHEN {auth} THEN nome
              ELSE CONCAT(SPLIT_PART(nome, ' ', 1), ' ***')
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_data_nasc_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_data_nascimento"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(dt DATE)
            RETURN CASE
              WHEN {auth} THEN dt
              ELSE CAST(CONCAT(YEAR(dt), '-01-01') AS DATE)
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_cartao_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_cartao_credito"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(cartao STRING)
            RETURN CASE
              WHEN {auth} THEN cartao
              ELSE CONCAT('****-****-****-', RIGHT(REGEXP_REPLACE(cartao, '[^0-9]', ''), 4))
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_salario_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_salario"
        auth = self._auth_check()
        # Salário: retorna NULL em vez de valor falso — sem inferência possível
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(salario DECIMAL(15,2))
            RETURN CASE
              WHEN {auth} THEN salario
              ELSE CAST(NULL AS DECIMAL(15,2))
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _create_endereco_mask(self, catalog: str) -> str:
        fn = f"{catalog}.{self.SECURITY_SCHEMA}.mask_endereco"
        auth = self._auth_check()
        sql = textwrap.dedent(f"""
            CREATE OR REPLACE FUNCTION {fn}(endereco STRING)
            RETURN CASE
              WHEN {auth} THEN endereco
              ELSE '*** (endereço ocultado)'
            END
        """).strip()
        self._execute(sql, catalog)
        return fn

    def _execute(self, sql: str, catalog: str) -> None:
        self.ws.statement_execution.execute(
            warehouse_id=self._get_warehouse_id(),
            statement=sql,
            catalog=catalog,
        )

    def _ensure_security_schema(self, catalog: str) -> None:
        self._execute(f"CREATE SCHEMA IF NOT EXISTS {catalog}.{self.SECURITY_SCHEMA}", catalog)

    def _get_warehouse_id(self) -> str:
        warehouses = list(self.ws.warehouses.list())
        if not warehouses:
            raise RuntimeError("Nenhum SQL Warehouse disponível.")
        for wh in warehouses:
            if "engineering" in (wh.name or "").lower():
                return wh.id
        return warehouses[0].id
