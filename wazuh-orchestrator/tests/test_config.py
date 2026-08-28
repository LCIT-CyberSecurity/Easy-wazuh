from __future__ import annotations

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
