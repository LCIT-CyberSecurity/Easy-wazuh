from __future__ import annotations

from pathlib import Path

import pytest

from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import ConfigurationError


def write_cfg(tmp_path, text):
    path = tmp_path / "orchestrator.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_yaml(tmp_path):
    cfg = load_config(write_cfg(tmp_path, "workers:\n  baseline: 1\n  max: 3\n"))
    assert cfg.workers.baseline == 1
    assert cfg.workers.max == 3


def test_invalid_yaml_root(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "- nope\n"))


def test_malformed_yaml_rejected(tmp_path):
    with pytest.raises(ConfigurationError, match="Malformed configuration"):
        load_config(write_cfg(tmp_path, "workers: ["))


def test_baseline_greater_than_max_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "workers:\n  baseline: 4\n  max: 3\n"))


def test_percentage_invalid_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "host:\n  cpu_block_percent: 101\n"))


def test_baseline_negative_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "workers:\n  baseline: -1\n"))


def test_sample_count_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "analysis:\n  sample_count: 0\n"))


def test_max_delta_must_be_one(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "scaling:\n  max_delta_per_operation: 2\n"))


def test_logging_level_valid(tmp_path):
    cfg = load_config(write_cfg(tmp_path, "logging:\n  level: DEBUG\n"))
    assert cfg.logging.level == "DEBUG"


def test_logging_level_invalid_refused(tmp_path):
    with pytest.raises(ConfigurationError):
        load_config(write_cfg(tmp_path, "logging:\n  level: TRACE\n"))


def test_wazuh_api_url_must_be_https(tmp_path):
    with pytest.raises(ConfigurationError, match="HTTPS"):
        load_config(write_cfg(tmp_path, "runtime:\n  wazuh_api_url: http://wazuh:55000\n"))


def test_wazuh_api_timeout_positive(tmp_path):
    with pytest.raises(ConfigurationError, match="wazuh_api_timeout"):
        load_config(write_cfg(tmp_path, "runtime:\n  wazuh_api_timeout_seconds: 0\n"))



def test_metrics_provider_invalid_refused(tmp_path):
    with pytest.raises(ConfigurationError, match="metrics_provider"):
        load_config(write_cfg(tmp_path, "runtime:\n  metrics_provider: docker\n"))


def test_indexer_api_url_must_be_https(tmp_path):
    with pytest.raises(ConfigurationError, match="indexer_api_url"):
        load_config(write_cfg(tmp_path, "runtime:\n  indexer_api_url: http://indexer:9200\n"))


def test_nginx_health_url_must_be_http_url(tmp_path):
    with pytest.raises(ConfigurationError, match="nginx_health_url"):
        load_config(write_cfg(tmp_path, "runtime:\n  nginx_health_url: file:///tmp/status\n"))


def test_container_compose_example_is_read_only_and_unprivileged():
    import yaml

    data = yaml.safe_load((Path(__file__).resolve().parents[1] / "docker-compose.yml.example").read_text(encoding="utf-8"))
    service = data["services"]["wazuh-orchestrator"]

    assert service["user"] == "10001:10001"
    assert service["read_only"] is True
    assert "ALL" in service["cap_drop"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["command"][:2] == ["--config", "/app/config/orchestrator.yaml"]
    assert all("/var/run/docker.sock" not in volume for volume in service["volumes"])
    assert all(volume.endswith(":ro") for volume in service["volumes"])
