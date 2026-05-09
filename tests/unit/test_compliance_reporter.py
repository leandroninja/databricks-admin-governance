"""Testes unitários do ComplianceReporter — verificações de conformidade."""
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from src.security.compliance_reporter import (
    ComplianceReporter,
    ComplianceCheck,
    ComplianceReport,
)


@pytest.fixture
def mock_ws():
    ws = MagicMock()
    ws.config.host = "https://adb-test.azuredatabricks.net"
    ws.workspace_conf.get_status.return_value = {
        "enableIpAccessLists": "true",
        "enableMFA": "true",
        "enableResultSetDownload": "false",
    }
    return ws


@pytest.fixture
def mock_grant_manager():
    gm = MagicMock()
    gm.audit_all_grants.return_value = {
        "catalog": [],
        "schemas": [],
        "tables": [],
    }
    return gm


@pytest.fixture
def mock_mask_manager():
    mm = MagicMock()
    mm.list_masked_columns.return_value = [
        {"table_schema": "rh", "table_name": "funcionarios", "column_name": "cpf"},
        {"table_schema": "clientes", "table_name": "perfil", "column_name": "email"},
    ]
    return mm


@pytest.fixture
def reporter(mock_ws, mock_grant_manager, mock_mask_manager):
    return ComplianceReporter(
        workspace_client=mock_ws,
        grant_manager=mock_grant_manager,
        mask_manager=mock_mask_manager,
    )


class TestComplianceScore:
    """Testes de cálculo do score de conformidade."""

    def test_score_100_sem_falhas(self):
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            workspace_url="https://test.azuredatabricks.net",
            period_days=30,
            checks=[
                ComplianceCheck("ID-001", "identity", "Check A", "PASS", "OK"),
                ComplianceCheck("ID-002", "identity", "Check B", "PASS", "OK"),
                ComplianceCheck("NET-001", "network", "Check C", "PASS", "OK"),
            ]
        )
        assert report.compliance_score == 100.0

    def test_score_0_com_todas_falhas(self):
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            workspace_url="https://test.azuredatabricks.net",
            period_days=30,
            checks=[
                ComplianceCheck("ID-001", "identity", "Check A", "FAIL", "Falhou"),
                ComplianceCheck("ID-002", "identity", "Check B", "FAIL", "Falhou"),
            ]
        )
        assert report.compliance_score == 0.0

    def test_score_50_com_metade_passando(self):
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            workspace_url="https://test.azuredatabricks.net",
            period_days=30,
            checks=[
                ComplianceCheck("ID-001", "identity", "Pass", "PASS", "OK"),
                ComplianceCheck("ID-002", "identity", "Fail", "FAIL", "Erro"),
            ]
        )
        assert report.compliance_score == 50.0

    def test_score_zero_sem_checks(self):
        report = ComplianceReport(
            generated_at="2024-01-01T00:00:00Z",
            workspace_url="https://test",
            period_days=30,
        )
        assert report.compliance_score == 0.0


class TestTokenHygieneChecks:
    """Testes das verificações de tokens."""

    def test_falha_quando_existem_tokens_sem_expiracao(self, reporter, mock_ws):
        """Tokens sem expiração devem gerar check FAIL."""
        mock_ws.token_management.list.return_value = [
            MagicMock(token_id="t1", expiry_time=None, comment="Token sem expiração"),
        ]
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [MagicMock(), MagicMock(), MagicMock()]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        tok_check = next((c for c in report.checks if c.check_id == "TOK-001"), None)
        assert tok_check is not None
        assert tok_check.status == "FAIL"
        assert "sem expiração" in tok_check.details

    def test_pass_quando_todos_tokens_tem_expiracao(self, reporter, mock_ws):
        """Todos os tokens com expiração devem gerar check PASS."""
        now_ms = datetime.now(timezone.utc).timestamp() * 1000
        future_ms = now_ms + 86400 * 1000 * 30  # 30 dias no futuro

        mock_ws.token_management.list.return_value = [
            MagicMock(token_id="t1", expiry_time=int(future_ms), comment="Token válido"),
        ]
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        tok_check = next((c for c in report.checks if c.check_id == "TOK-001"), None)
        assert tok_check is not None
        assert tok_check.status == "PASS"


class TestClusterPolicyChecks:
    """Testes das verificações de políticas de cluster."""

    def test_falha_quando_menos_de_3_politicas(self, reporter, mock_ws):
        mock_ws.token_management.list.return_value = []
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock()  # apenas 2 políticas — mínimo é 3
        ]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        clu_check = next((c for c in report.checks if c.check_id == "CLU-001"), None)
        assert clu_check is not None
        assert clu_check.status == "FAIL"

    def test_falha_quando_cluster_ativo_sem_politica(self, reporter, mock_ws):
        mock_ws.token_management.list.return_value = []
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]

        cluster_sem_politica = MagicMock()
        cluster_sem_politica.state.value = "RUNNING"
        cluster_sem_politica.policy_id = None  # sem política!
        mock_ws.clusters.list.return_value = [cluster_sem_politica]
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        clu_check = next((c for c in report.checks if c.check_id == "CLU-002"), None)
        assert clu_check is not None
        assert clu_check.status == "FAIL"


class TestIPAccessChecks:
    """Testes das verificações de IP access list."""

    def test_falha_quando_sem_ip_access_list(self, reporter, mock_ws):
        mock_ws.token_management.list.return_value = []
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = []  # sem listas!

        report = reporter.generate_report(catalog_name="prod")

        net_check = next((c for c in report.checks if c.check_id == "NET-001"), None)
        assert net_check is not None
        assert net_check.status == "FAIL"


class TestPIICoverageChecks:
    """Testes das verificações de cobertura PII."""

    def test_pass_quando_existem_colunas_mascaradas(self, reporter, mock_ws, mock_mask_manager):
        mock_ws.token_management.list.return_value = []
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        pii_check = next((c for c in report.checks if c.check_id == "PII-001"), None)
        assert pii_check is not None
        assert pii_check.status == "PASS"
        assert "2" in pii_check.details  # 2 colunas mascaradas

    def test_falha_quando_sem_colunas_mascaradas(self, reporter, mock_ws, mock_mask_manager):
        mock_mask_manager.list_masked_columns.return_value = []  # sem máscaras!

        mock_ws.token_management.list.return_value = []
        mock_ws.users.list.return_value = []
        mock_ws.cluster_policies.list.return_value = [
            MagicMock(), MagicMock(), MagicMock()
        ]
        mock_ws.clusters.list.return_value = []
        mock_ws.ip_access_lists.list.return_value = [
            MagicMock(list_type=MagicMock(value="ALLOW"))
        ]

        report = reporter.generate_report(catalog_name="prod")

        pii_check = next((c for c in report.checks if c.check_id == "PII-001"), None)
        assert pii_check.status == "FAIL"
