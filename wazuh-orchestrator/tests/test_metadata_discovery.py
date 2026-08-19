from __future__ import annotations

from pathlib import Path

import pytest

from wazuh_orchestrator.discovery import discover_from_compose, load_deployment_metadata
from wazuh_orchestrator.models import DiscoveryError


def metadata(tmp_path: Path, stack: Path, mode="multi-node", baseline=1) -> Path:
    p = tmp_path / "deployment.yaml"
    p.write_text(f"""
schema_version: 1

deployment:
  mode: {mode}
  stack_directory: {stack}
  compose_file: docker-compose.yml
  compose_project_name: null

managers:
  prefix: wazuh-manager
  number_width: 2
  internal_dns_suffix: local
  master_index: 1

baseline:
  workers: {baseline}

indexers:
  prefix: wazuh-indexer
  number_width: 2

dashboard:
  count: 1
  scalable: false
""", encoding="utf-8")
    return p


def compose(tmp_path: Path) -> Path:
    p = tmp_path / "docker-compose.yml"
    p.write_text("""services:
  wazuh-manager01.local: {}
  wazuh-manager02.local: {}
  wazuh-dashboard01.local: {}
  wazuh-indexer01.local: {}
  nginx: {}
networks:
  default: {}
""", encoding="utf-8")
    return p


def test_metadata_load_valid(tmp_path):
    stack = tmp_path / "stack"
    path = metadata(tmp_path, stack)
    loaded = load_deployment_metadata(path)
    assert loaded is not None
    assert loaded.baseline_workers == 1
    assert loaded.naming.manager_prefix == "wazuh-manager"


def test_metadata_rejects_dashboard_scaling(tmp_path):
    stack = tmp_path / "stack"
    path = metadata(tmp_path, stack)
    text = path.read_text(encoding="utf-8").replace("scalable: false", "scalable: true")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(DiscoveryError):
        load_deployment_metadata(path)


def test_discovery_uses_metadata_policy(tmp_path):
    c = compose(tmp_path)
    md = load_deployment_metadata(metadata(tmp_path, tmp_path))
    state = discover_from_compose(c, md)
    assert state.naming_policy is not None
    assert state.master == "wazuh-manager01.local"
    assert state.workers == ("wazuh-manager02.local",)


def test_metadata_drift_when_baseline_missing(tmp_path):
    c = compose(tmp_path)
    md = load_deployment_metadata(metadata(tmp_path, tmp_path, baseline=2))
    state = discover_from_compose(c, md)
    assert state.config_drift is True
