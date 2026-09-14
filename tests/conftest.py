"""Shared test fixtures for C.A.P.O test suite."""

import pytest

import capo.config
from capo.state import StateManager


@pytest.fixture
def isolated_capo(tmp_path, monkeypatch):
    """Isolate tests from user's ~/.capo environment."""
    monkeypatch.setattr(capo.config, "CAPO_HOME", tmp_path)
    monkeypatch.setattr(capo.config, "WORKSPACES_DIR", tmp_path / "workspaces")
    (tmp_path / "workspaces").mkdir(parents=True, exist_ok=True)

    from capo.state import state_manager
    state_manager._target = None
    state_manager._workspace = None
    state_manager._state = {}
    return tmp_path


@pytest.fixture
def sm(isolated_capo):
    """Return a fresh StateManager instance bound to target 10.10.10.1."""
    manager = StateManager()
    manager.set_target("10.10.10.1")
    return manager

