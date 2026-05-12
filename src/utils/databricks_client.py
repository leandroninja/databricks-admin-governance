"""Fábrica de clientes Databricks SDK com autenticação segura."""
from __future__ import annotations

import os
import logging
from functools import lru_cache
from typing import Optional

from databricks.sdk import WorkspaceClient, AccountClient
from databricks.sdk.config import Config

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def get_workspace_client(
    host: Optional[str] = None,
    profile: Optional[str] = None,
    cluster_id: Optional[str] = None,
) -> WorkspaceClient:
    """Retorna cliente do workspace com autenticação em cascata:
    1. Azure Managed Identity (produção)
    2. Variáveis de ambiente DATABRICKS_HOST + DATABRICKS_TOKEN
    3. Profile do ~/.databrickscfg (desenvolvimento local)
    """
    kwargs: dict = {}

    if host:
        kwargs["host"] = host
    if profile:
        kwargs["profile"] = profile
    if cluster_id:
        kwargs["cluster_id"] = cluster_id

    client = WorkspaceClient(**kwargs)

    # Validar conectividade na inicialização para falhar rapidamente
    try:
        me = client.current_user.me()
        logger.info("Workspace client autenticado como: %s", me.user_name)
    except Exception as exc:
        raise RuntimeError(f"Falha ao autenticar no workspace Databricks: {exc}") from exc

    return client


@lru_cache(maxsize=4)
def get_account_client(
    account_id: Optional[str] = None,
    host: str = "https://accounts.azuredatabricks.net",
) -> AccountClient:
    """Retorna cliente da conta Databricks para operações de Unity Catalog e SCIM.
    Requer papel Account Admin — use com parcimônia.
    """
    kwargs: dict = {"host": host}

    if account_id:
        kwargs["account_id"] = account_id
    elif env_id := os.getenv("DATABRICKS_ACCOUNT_ID"):
        kwargs["account_id"] = env_id

    client = AccountClient(**kwargs)
    logger.info("Account client inicializado para conta: %s", kwargs.get("account_id"))
    return client


def get_client_for_environment(environment: str) -> WorkspaceClient:
    """Retorna cliente para o workspace correspondente ao ambiente (dev/staging/prod).
    Lê configuração de DATABRICKS_HOST_<ENV> e DATABRICKS_TOKEN_<ENV>.
    """
    env_upper = environment.upper()
    host = os.environ.get(f"DATABRICKS_HOST_{env_upper}")
    token = os.environ.get(f"DATABRICKS_TOKEN_{env_upper}")

    if not host:
        raise ValueError(
            f"Variável DATABRICKS_HOST_{env_upper} não definida. "
            "Configure o ambiente antes de executar."
        )

    config = Config(host=host, token=token) if token else Config(host=host)
    return WorkspaceClient(config=config)
