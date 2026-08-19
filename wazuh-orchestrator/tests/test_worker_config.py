from __future__ import annotations

import pytest

from wazuh_orchestrator.backends.compose import derive_worker_config
from wazuh_orchestrator.models import ScalingError


def test_worker03_receives_unique_node_name(tmp_path):
    template = tmp_path / "worker02.conf"
    target = tmp_path / "worker03.conf"
    template.write_text("<cluster><node_name>worker02</node_name><node>wazuh-manager01.local</node><key>SECRET</key></cluster>", encoding="utf-8")
    derive_worker_config(template, target, "worker03", "wazuh-manager01.local")
    text = target.read_text(encoding="utf-8")
    assert "<node_name>worker03</node_name>" in text
    assert "<key>SECRET</key>" in text
    assert template.read_text(encoding="utf-8").count("worker02") == 1


def test_duplicate_missing_node_name_rejected(tmp_path):
    template = tmp_path / "bad.conf"
    template.write_text("<cluster><key>SECRET</key></cluster>", encoding="utf-8")
    with pytest.raises(ScalingError):
        derive_worker_config(template, tmp_path / "out.conf", "worker03", "master")
