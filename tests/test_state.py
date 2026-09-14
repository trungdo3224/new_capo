"""Unit tests for StateManager (Schema v5)."""

import pytest

from capo.errors import TargetError
from capo.state import CURRENT_SCHEMA_VERSION, StateManager


class TestSetTarget:
    """Test target validation and workspace creation."""

    def test_valid_ipv4(self, isolated_capo):
        sm = StateManager()
        ws = sm.set_target("10.10.10.1")
        assert sm.target == "10.10.10.1"
        assert ws.exists()
        assert (ws / "state.json").exists()

    def test_valid_hostname(self, isolated_capo):
        sm = StateManager()
        ws = sm.set_target("target.local")
        assert sm.target == "target.local"
        assert ws.exists()

    def test_invalid_target_raises(self, isolated_capo):
        sm = StateManager()
        with pytest.raises(TargetError):
            sm.set_target("bad;target")


class TestSchemaV5Entities:
    """Test Schema v5 specific fields and setters."""

    def test_schema_version(self, sm):
        assert sm.state.get("schema_version") == CURRENT_SCHEMA_VERSION

    def test_os_and_build_setters(self, sm):
        sm.set_os("Windows Server 2022")
        sm.set_os_build("20348")
        sm.set_arch("x64")
        assert sm.get("os") == "Windows Server 2022"
        assert sm.get("os_build") == "20348"
        assert sm.get("arch") == "x64"

    def test_domain_and_dc_setter(self, sm):
        sm.set_domain("corp.local", is_dc=True)
        assert "corp.local" in sm.get("domains")
        info = sm.get("domain_info")
        assert info["domain_name"] == "corp.local"
        assert info["is_domain_joined"] is True
        assert info["is_dc"] is True

    def test_flag_normalization(self, sm):
        sm.set_flag("user.txt", "flag_hash_user")
        sm.set_flag("proof", "flag_hash_root")
        flags = sm.get("flags")
        assert flags["user_txt"] == "flag_hash_user"
        assert flags["proof_txt"] == "flag_hash_root"


class TestPortAndServiceManagement:
    """Test port tracking and service aggregation."""

    def test_add_port_and_retrieve(self, sm):
        sm.add_port(80, "tcp", "http", "Apache 2.4.52", "open")
        ports = sm.get("ports", [])
        assert len(ports) == 1
        assert ports[0]["port"] == 80
        assert ports[0]["service"] == "http"

    def test_add_port_dedup(self, sm):
        sm.add_port(80, "tcp", "http", "Apache 2.4.52")
        sm.add_port(80, "tcp", "http", "Apache 2.4.52 updated")
        ports = sm.get("ports", [])
        assert len(ports) == 1
        assert ports[0]["version"] == "Apache 2.4.52 updated"


class TestIdentityAndLoot:
    """Test users, credentials, and hashes."""

    def test_add_user_and_dedup(self, sm):
        sm.add_user("admin")
        sm.add_user("admin")
        sm.add_user("svc_backup")
        users = sm.get("users", [])
        assert users == ["admin", "svc_backup"]

    def test_add_credential(self, sm):
        sm.add_credential("admin", "P@ssword123", is_admin=True)
        creds = sm.get("credentials", [])
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
        assert creds[0]["password"] == "P@ssword123"
        assert creds[0]["is_admin"] is True

    def test_add_hash(self, sm):
        sm.add_hash("aad3b435b51404ee", username="admin")
        hashes = sm.get("hashes", [])
        assert len(hashes) == 1
        assert hashes[0]["hash"] == "aad3b435b51404ee"
        assert hashes[0]["username"] == "admin"


class TestVariablesAndNotes:
    """Test dynamic variable injection and notes."""

    def test_get_var_injection(self, sm):
        sm.set_os("Linux")
        sm.set_os_build("5.15.0")
        sm.set_arch("x86_64")
        sm.set_hostname("kali")
        sm.add_user("alice")

        assert sm.get_var("IP") == "10.10.10.1"
        assert sm.get_var("OS") == "Linux"
        assert sm.get_var("OS_BUILD") == "5.15.0"
        assert sm.get_var("ARCH") == "x86_64"
        assert sm.get_var("HOSTNAME") == "kali"
        assert sm.get_var("USER") == "alice"

    def test_add_note(self, sm):
        sm.add_note("Discovered LFI at /index.php?page=")
        notes = sm.get("notes", [])
        assert len(notes) == 1
        assert "LFI" in notes[0]["note"]

