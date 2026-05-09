"""Testes unitários do GrantManager com mocks do Databricks SDK."""
import pytest
from unittest.mock import MagicMock, patch, call
from databricks.sdk.service.catalog import (
    PermissionsChange,
    Privilege,
    PrivilegeAssignment,
    SchemaPermissions,
    SecurableType,
)

from src.unity_catalog.grant_manager import GrantManager, GrantRequest, DataRole


@pytest.fixture
def mock_ws():
    """Workspace client mockado para isolamento de testes."""
    ws = MagicMock()
    ws.current_user.me.return_value = MagicMock(user_name="test@empresa.com")
    return ws


@pytest.fixture
def grant_manager(mock_ws):
    return GrantManager(client=mock_ws)


class TestGrantRequest:
    """Testes de validação da solicitação de grant."""

    def test_rejeita_grant_para_usuario_individual(self, grant_manager):
        """Grant direto a usuário individual deve ser rejeitado — apenas grupos."""
        request = GrantRequest(
            principal="joao.silva@empresa.com",  # usuário individual!
            role=DataRole.DATA_ANALYST,
            securable_type="schema",
            securable_name="prod.vendas",
            justification="Acesso para análise de vendas Q4",
            requested_by="gestor@empresa.com",
        )

        with pytest.raises(ValueError, match="Grants individuais não são permitidos"):
            grant_manager.grant(request)

    def test_rejeita_justificativa_vazia(self, grant_manager):
        """Justificativa vazia ou muito curta deve ser rejeitada."""
        request = GrantRequest(
            principal="data-analysts",
            role=DataRole.DATA_ANALYST,
            securable_type="schema",
            securable_name="prod.vendas",
            justification="",  # vazia!
            requested_by="gestor@empresa.com",
        )

        with pytest.raises(ValueError, match="Justificativa obrigatória"):
            grant_manager.grant(request)

    def test_rejeita_justificativa_curta(self, grant_manager):
        request = GrantRequest(
            principal="data-analysts",
            role=DataRole.DATA_ANALYST,
            securable_type="schema",
            securable_name="prod.vendas",
            justification="curta",  # menos de 10 chars
            requested_by="gestor@empresa.com",
        )

        with pytest.raises(ValueError, match="Justificativa obrigatória"):
            grant_manager.grant(request)


class TestGrantPrivileges:
    """Testes de concessão de privileges."""

    def test_grant_analista_recebe_privilegios_corretos(self, grant_manager, mock_ws):
        """Analista deve receber USE_CATALOG + USE_SCHEMA + SELECT."""
        request = GrantRequest(
            principal="data-analysts",
            role=DataRole.DATA_ANALYST,
            securable_type="schema",
            securable_name="prod.vendas",
            justification="Acesso para análise de vendas do Q4 2024",
            requested_by="gestor@empresa.com",
            ticket_id="INC0012345",
        )

        grant_manager.grant(request)

        mock_ws.grants.update.assert_called_once()
        call_args = mock_ws.grants.update.call_args

        assert call_args.kwargs["securable_type"] == SecurableType.SCHEMA
        assert call_args.kwargs["full_name"] == "prod.vendas"

        changes = call_args.kwargs["changes"]
        assert len(changes) == 1
        assert changes[0].principal == "data-analysts"
        assert Privilege.SELECT in changes[0].add
        assert Privilege.USE_CATALOG in changes[0].add
        assert Privilege.USE_SCHEMA in changes[0].add
        # Analista NÃO deve ter MODIFY
        assert Privilege.MODIFY not in changes[0].add

    def test_grant_engenheiro_inclui_create_e_modify(self, grant_manager, mock_ws):
        """Engenheiro deve ter CREATE_TABLE e MODIFY além de SELECT."""
        request = GrantRequest(
            principal="data-engineers-prod",
            role=DataRole.DATA_ENGINEER,
            securable_type="catalog",
            securable_name="prod",
            justification="Acesso de engenharia para manutenção do pipeline de vendas",
            requested_by="tech.lead@empresa.com",
        )

        grant_manager.grant(request)

        changes = mock_ws.grants.update.call_args.kwargs["changes"]
        privileges = changes[0].add
        assert Privilege.CREATE_TABLE in privileges
        assert Privilege.MODIFY in privileges
        assert Privilege.CREATE_FUNCTION in privileges

    def test_grant_data_owner_tem_all_privileges(self, grant_manager, mock_ws):
        """Data owner deve receber ALL_PRIVILEGES no schema."""
        request = GrantRequest(
            principal="vendas-data-owners",
            role=DataRole.DATA_OWNER,
            securable_type="schema",
            securable_name="prod.vendas",
            justification="Proprietário do domínio vendas com controle total",
            requested_by="diretor.vendas@empresa.com",
        )

        grant_manager.grant(request)

        changes = mock_ws.grants.update.call_args.kwargs["changes"]
        assert Privilege.ALL_PRIVILEGES in changes[0].add

    def test_grant_pipeline_sp_tem_refresh(self, grant_manager, mock_ws):
        """Service principal de pipeline deve ter REFRESH para streaming."""
        request = GrantRequest(
            principal="sp-ingestion-pipeline",
            role=DataRole.PIPELINE_SP,
            securable_type="table",
            securable_name="prod.vendas.transacoes",
            justification="SP de ingestão precisa de REFRESH para tabelas de streaming",
            requested_by="tech.lead@empresa.com",
        )

        grant_manager.grant(request)

        changes = mock_ws.grants.update.call_args.kwargs["changes"]
        assert Privilege.REFRESH in changes[0].add

    def test_tipo_objeto_invalido_gera_erro(self, grant_manager):
        """Tipo de objeto inválido deve lançar ValueError."""
        request = GrantRequest(
            principal="data-analysts",
            role=DataRole.DATA_ANALYST,
            securable_type="recurso_inexistente",
            securable_name="prod.vendas",
            justification="Testando tipo inválido de objeto",
            requested_by="admin@empresa.com",
        )

        with pytest.raises(ValueError, match="Tipo de objeto não suportado"):
            grant_manager.grant(request)


class TestRevokeGrants:
    """Testes de revogação de privileges."""

    def test_revoke_remove_privileges_existentes(self, grant_manager, mock_ws):
        """Revogação deve remover os privileges do principal."""
        mock_ws.grants.get.return_value = MagicMock(
            privilege_assignments=[
                PrivilegeAssignment(
                    principal="data-analysts",
                    privileges=[Privilege.SELECT, Privilege.USE_SCHEMA, Privilege.USE_CATALOG],
                )
            ]
        )

        grant_manager.revoke(
            principal="data-analysts",
            securable_type="schema",
            securable_name="prod.vendas",
            justification="Usuário mudou de time — acesso não mais necessário",
            revoked_by="admin@empresa.com",
        )

        mock_ws.grants.update.assert_called_once()
        call_args = mock_ws.grants.update.call_args.kwargs
        assert call_args["changes"][0].principal == "data-analysts"

    def test_revoke_sem_grants_existentes_nao_falha(self, grant_manager, mock_ws):
        """Revogar de objeto sem grants não deve lançar exceção."""
        mock_ws.grants.get.return_value = MagicMock(privilege_assignments=[])

        grant_manager.revoke(
            principal="data-analysts",
            securable_type="schema",
            securable_name="prod.vendas",
            justification="Limpeza preventiva de acessos",
            revoked_by="admin@empresa.com",
        )

        mock_ws.grants.update.assert_not_called()


class TestListGrants:
    """Testes de listagem de grants para auditoria."""

    def test_list_grants_retorna_formato_correto(self, grant_manager, mock_ws):
        """Listagem de grants deve retornar dicionários com principal e privileges."""
        mock_ws.grants.get.return_value = MagicMock(
            privilege_assignments=[
                PrivilegeAssignment(
                    principal="data-analysts",
                    privileges=[Privilege.SELECT],
                ),
                PrivilegeAssignment(
                    principal="data-engineers-prod",
                    privileges=[Privilege.SELECT, Privilege.MODIFY],
                ),
            ]
        )

        grants = grant_manager.list_grants("schema", "prod.vendas")

        assert len(grants) == 2
        principals = [g["principal"] for g in grants]
        assert "data-analysts" in principals
        assert "data-engineers-prod" in principals

    def test_list_grants_objeto_sem_grants_retorna_lista_vazia(self, grant_manager, mock_ws):
        mock_ws.grants.get.return_value = MagicMock(privilege_assignments=None)

        grants = grant_manager.list_grants("schema", "prod.vazio")
        assert grants == []


class TestSecurableTypeMapping:
    """Testes do mapeamento de tipos de objetos."""

    @pytest.mark.parametrize("input_type,expected", [
        ("catalog",   SecurableType.CATALOG),
        ("schema",    SecurableType.SCHEMA),
        ("table",     SecurableType.TABLE),
        ("function",  SecurableType.FUNCTION),
        ("volume",    SecurableType.VOLUME),
        ("CATALOG",   SecurableType.CATALOG),  # case insensitive
        ("TABLE",     SecurableType.TABLE),
    ])
    def test_resolve_securable_type(self, grant_manager, input_type, expected):
        result = grant_manager._resolve_securable_type(input_type)
        assert result == expected
