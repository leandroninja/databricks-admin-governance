"""Testes unitários do UserProvisioner — fluxos de onboarding e offboarding."""
import pytest
from unittest.mock import MagicMock, patch, call
from databricks.sdk.service.iam import ComplexValue, Group, User

from src.admin.user_provisioning import (
    UserProvisioner,
    UserProvisioningRequest,
    ROLE_TO_GROUPS,
)


@pytest.fixture
def mock_ws():
    ws = MagicMock()
    ws.current_user.me.return_value = MagicMock(user_name="admin@empresa.com")
    return ws


@pytest.fixture
def provisioner(mock_ws):
    return UserProvisioner(workspace_client=mock_ws, account_client=MagicMock())


def make_user(email: str, user_id: str = "123", active: bool = True) -> User:
    return User(
        id=user_id,
        user_name=email,
        display_name=email.split("@")[0].replace(".", " ").title(),
        active=active,
    )


def make_group(name: str, group_id: str = "456") -> Group:
    return Group(id=group_id, display_name=name)


class TestOnboardUser:
    """Testes do fluxo de provisionamento."""

    def test_cria_usuario_novo_com_sucesso(self, provisioner, mock_ws):
        """Novo usuário deve ser criado e adicionado ao grupo correto."""
        mock_ws.users.list.return_value = []  # usuário não existe
        created_user = make_user("joao@empresa.com", "999")
        mock_ws.users.create.return_value = created_user
        mock_ws.groups.list.return_value = [make_group("data-analysts")]

        request = UserProvisioningRequest(
            email="joao@empresa.com",
            display_name="João Silva",
            team="vendas",
            role="analyst",
            cost_center="VENDAS-2024",
        )

        user = provisioner.onboard_user(request)

        assert user.user_name == "joao@empresa.com"
        mock_ws.users.create.assert_called_once()
        # Deve adicionar ao grupo data-analysts
        mock_ws.groups.patch.assert_called()

    def test_usuario_existente_nao_duplica(self, provisioner, mock_ws):
        """Usuário já existente deve ter grupos atualizados sem criar novo."""
        existing_user = make_user("existente@empresa.com", "100")
        mock_ws.users.list.return_value = [existing_user]
        mock_ws.groups.list.return_value = [make_group("data-analysts")]

        request = UserProvisioningRequest(
            email="existente@empresa.com",
            display_name="Usuário Existente",
            team="financeiro",
            role="analyst",
            cost_center="FIN-2024",
        )

        provisioner.onboard_user(request)

        # NÃO deve criar usuário duplicado
        mock_ws.users.create.assert_not_called()

    def test_engenheiro_recebe_grupo_por_ambiente(self, provisioner, mock_ws):
        """Engenheiro de dados deve ser adicionado ao grupo do ambiente correto."""
        mock_ws.users.list.return_value = []
        mock_ws.users.create.return_value = make_user("eng@empresa.com", "200")

        prod_group = make_group("data-engineers-prod", "300")
        mock_ws.groups.list.side_effect = lambda filter=None: (
            [prod_group] if "data-engineers-prod" in (filter or "") else []
        )

        request = UserProvisioningRequest(
            email="eng@empresa.com",
            display_name="Engenheiro Prod",
            team="data-platform",
            role="engineer",
            cost_center="DE-PLATFORM-2024",
            environments=["prod"],
        )

        provisioner.onboard_user(request)

        # Deve ter buscado o grupo data-engineers-prod
        filter_calls = [
            str(c) for c in mock_ws.groups.list.call_args_list
        ]
        assert any("data-engineers-prod" in call for call in filter_calls)

    def test_admin_recebe_grupo_data_admins(self, provisioner, mock_ws):
        """Admin deve ser adicionado ao grupo data-admins."""
        mock_ws.users.list.return_value = []
        mock_ws.users.create.return_value = make_user("admin@empresa.com", "10")
        admin_group = make_group("data-admins", "1")
        mock_ws.groups.list.return_value = [admin_group]

        request = UserProvisioningRequest(
            email="admin@empresa.com",
            display_name="Admin User",
            team="platform",
            role="admin",
            cost_center="PLATFORM-2024",
        )

        provisioner.onboard_user(request)

        # Deve ter adicionado ao data-admins
        assert mock_ws.groups.patch.called

    def test_grupo_inexistente_nao_falha(self, provisioner, mock_ws):
        """Grupo não encontrado deve ser ignorado com warning — sem erro fatal."""
        mock_ws.users.list.return_value = []
        mock_ws.users.create.return_value = make_user("novo@empresa.com", "500")
        mock_ws.groups.list.return_value = []  # nenhum grupo encontrado

        request = UserProvisioningRequest(
            email="novo@empresa.com",
            display_name="Novo User",
            team="ops",
            role="analyst",
            cost_center="OPS-2024",
        )

        # Não deve lançar exceção
        user = provisioner.onboard_user(request)
        assert user is not None


class TestOffboardUser:
    """Testes do fluxo de desativação."""

    def test_offboard_remove_grupos_e_tokens(self, provisioner, mock_ws):
        """Offboarding deve remover grupos, revogar tokens e desativar conta."""
        user = make_user("saindo@empresa.com", "777")
        mock_ws.users.list.return_value = [user]

        groups = [make_group("data-analysts", "456"), make_group("vendas-data-owners", "789")]
        mock_ws.groups.list.return_value = groups

        token1 = MagicMock(token_id="tok1", comment="Token pessoal")
        token2 = MagicMock(token_id="tok2", comment="Token pipeline")
        mock_ws.token_management.list.return_value = [token1, token2]

        provisioner.offboard_user("saindo@empresa.com", reason="Desligamento voluntário")

        # Deve ter removido dos grupos
        assert mock_ws.groups.patch.call_count == len(groups)

        # Deve ter revogado todos os tokens
        assert mock_ws.token_management.delete.call_count == 2
        mock_ws.token_management.delete.assert_any_call(token_id="tok1")
        mock_ws.token_management.delete.assert_any_call(token_id="tok2")

        # Deve ter desativado a conta
        mock_ws.users.update.assert_called_once()
        update_args = mock_ws.users.update.call_args.kwargs
        assert update_args["active"] is False

    def test_offboard_usuario_inexistente_gera_erro(self, provisioner, mock_ws):
        """Tentar fazer offboard de usuário inexistente deve lançar ValueError."""
        mock_ws.users.list.return_value = []

        with pytest.raises(ValueError, match="não encontrado no workspace"):
            provisioner.offboard_user("inexistente@empresa.com", reason="Teste")

    def test_offboard_sem_tokens_nao_falha(self, provisioner, mock_ws):
        """Usuário sem tokens deve ter offboard realizado normalmente."""
        user = make_user("semtoken@empresa.com", "888")
        mock_ws.users.list.return_value = [user]
        mock_ws.groups.list.return_value = []
        mock_ws.token_management.list.return_value = []

        provisioner.offboard_user("semtoken@empresa.com", reason="Teste sem tokens")

        # Conta ainda deve ser desativada
        mock_ws.users.update.assert_called_once()


class TestTemporaryAccess:
    """Testes de acesso temporário."""

    def test_acesso_temporario_adiciona_ao_grupo(self, provisioner, mock_ws):
        """Acesso temporário deve adicionar usuário ao grupo alvo."""
        user = make_user("temp@empresa.com", "999")
        mock_ws.users.list.return_value = [user]
        pii_group = make_group("pii-access", "100")
        mock_ws.groups.list.side_effect = lambda filter=None: [pii_group]

        provisioner.grant_temporary_access(
            email="temp@empresa.com",
            group="pii-access",
            duration_days=30,
            justification="Acesso pontual para auditoria LGPD — aprovado pelo DPO",
        )

        mock_ws.groups.patch.assert_called_once()

    def test_acesso_temporario_usuario_inexistente(self, provisioner, mock_ws):
        """Usuário inexistente deve lançar ValueError."""
        mock_ws.users.list.return_value = []

        with pytest.raises(ValueError, match="não encontrado"):
            provisioner.grant_temporary_access(
                email="fantasma@empresa.com",
                group="pii-access",
                duration_days=30,
                justification="Acesso que não deveria ser concedido",
            )


class TestRoleToGroupsMapping:
    """Testes do mapeamento papel → grupos."""

    def test_analista_mapeado_para_data_analysts(self):
        assert "data-analysts" in ROLE_TO_GROUPS["analyst"]

    def test_cientistaem_data_scientists(self):
        assert "data-scientists" in ROLE_TO_GROUPS["scientist"]

    def test_admin_em_data_admins(self):
        assert "data-admins" in ROLE_TO_GROUPS["admin"]

    def test_engenheiro_mapeamento_vazio_para_grupos_por_ambiente(self):
        # Engenheiro não tem grupos fixos — grupos por ambiente são adicionados dinamicamente
        assert ROLE_TO_GROUPS["engineer"] == []
