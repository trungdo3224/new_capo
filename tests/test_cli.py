"""CLI integration tests for C.A.P.O 4 core verbs."""

import pytest
from typer.testing import CliRunner

from capo.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _setup_test_env(isolated_capo):
    """Ensure every test uses isolated capo environment."""
    yield


class TestGlobalCli:
    """Test global flags and help output."""

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "C.A.P.O v" in result.output

    def test_help_lists_core_verbs(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for cmd in ("target", "scan", "add", "state"):
            assert cmd in result.output


class TestTargetCli:
    """Test 'capo target' command."""

    def test_target_set_and_positional(self):
        res1 = runner.invoke(app, ["target", "set", "10.10.10.20"])
        assert res1.exit_code == 0
        assert "10.10.10.20" in res1.output

        res2 = runner.invoke(app, ["target", "10.10.10.21"])
        assert res2.exit_code == 0
        assert "10.10.10.21" in res2.output


class TestAddCli:
    """Test 'capo add' subcommands."""

    @pytest.fixture(autouse=True)
    def _set_active_target(self):
        runner.invoke(app, ["target", "set", "10.10.10.30"])

    def test_add_fingerprint_info(self):
        res1 = runner.invoke(app, ["add", "os", "Windows Server 2022"])
        assert res1.exit_code == 0

        res2 = runner.invoke(app, ["add", "os-build", "20348"])
        assert res2.exit_code == 0

        res3 = runner.invoke(app, ["add", "arch", "x64"])
        assert res3.exit_code == 0

        res4 = runner.invoke(app, ["add", "domain", "htb.local", "--dc"])
        assert res4.exit_code == 0

        res5 = runner.invoke(app, ["add", "hostname", "DC01"])
        assert res5.exit_code == 0

    def test_add_services_and_loot(self):
        res1 = runner.invoke(app, ["add", "port", "80", "http", "Apache"])
        assert res1.exit_code == 0

        res2 = runner.invoke(app, ["add", "user", "svc_backup"])
        assert res2.exit_code == 0

        res3 = runner.invoke(app, ["add", "cred", "admin", "P@ss123", "--admin"])
        assert res3.exit_code == 0

        res4 = runner.invoke(app, ["add", "flag", "user_txt", "flag12345"])
        assert res4.exit_code == 0

        res5 = runner.invoke(app, ["add", "note", "Test note text"])
        assert res5.exit_code == 0


class TestStateAndScanCli:
    """Test 'capo state' HUD and 'capo scan'."""

    def test_state_hud(self):
        runner.invoke(app, ["target", "set", "10.10.10.40"])
        runner.invoke(app, ["add", "os", "Ubuntu 22.04"])
        runner.invoke(app, ["add", "port", "22", "ssh", "OpenSSH 8.9"])

        res = runner.invoke(app, ["state"])
        assert res.exit_code == 0
        assert "10.10.10.40" in res.output
        assert "22" in res.output

    def test_scan_dry_run(self):
        runner.invoke(app, ["target", "set", "10.10.10.50"])
        res = runner.invoke(app, ["scan", "quick", "--dry-run"])
        assert res.exit_code == 0

