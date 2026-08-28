from __future__ import annotations

from pathlib import Path

import pytest

from wazuh_orchestrator.discovery import discover_from_compose, discover_installation
from wazuh_orchestrator.models import DiscoveryError


FIXTURES = Path(__file__).parent / "fixtures"


class NoDocker:
    def available(self): return False
    def compose_available(self): return False
    def inspect(self): return {}


def test_docker_absent(tmp_path):
    state = discover_installation(tmp_path, NoDocker())
    assert state.mode == "unknown"
    assert state.docker_available is False


def test_single_node():
    state = discover_from_compose(FIXTURES / "compose_single_node.yml")
    assert state.mode == "single-node"
    assert state.master == "wazuh.manager"
    assert state.workers == ()


def test_multi_node():
    state = discover_from_compose(FIXTURES / "compose_multi_node.yml")
    assert state.mode == "multi-node"
    assert state.master == "wazuh-manager01.local"
    assert state.workers == ("wazuh-manager02.local",)


def test_master_unique():
    state = discover_from_compose(FIXTURES / "compose_multi_node.yml")
    assert state.master and state.master not in state.workers


def test_multiple_master_error(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text("services:\n  wazuh-manager01.local: {}\n  wazuh-manager01.backup: {}\n", encoding="utf-8")
    with pytest.raises(DiscoveryError):
        discover_from_compose(p)


def test_malformed_compose_rejected(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text("services: [", encoding="utf-8")
    with pytest.raises(DiscoveryError, match="Malformed Compose"):
        discover_from_compose(p)


def test_compose_root_must_be_mapping(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text("- services", encoding="utf-8")
    with pytest.raises(DiscoveryError, match="root must be a mapping"):
        discover_from_compose(p)


def test_worker_absent_single_node_supported():
    state = discover_from_compose(FIXTURES / "compose_single_node.yml")
    assert state.worker_count == 0


def test_nginx_absent_marks_drift(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text("services:\n  wazuh-manager01.local: {}\n  wazuh-manager02.local: {}\n", encoding="utf-8")
    state = discover_from_compose(p)
    assert state.nginx is None
    assert state.config_drift is True


def test_config_drift_for_multinode_without_nginx(tmp_path):
    p = tmp_path / "docker-compose.yml"
    p.write_text("services:\n  wazuh-manager01.local: {}\n  wazuh-manager02.local: {}\n", encoding="utf-8")
    assert discover_from_compose(p).config_drift is True
