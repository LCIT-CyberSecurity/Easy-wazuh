from __future__ import annotations

import subprocess
import pytest

from wazuh_orchestrator.backends.compose import ComposeBackend, NginxConfigManager, validate_service_name
from wazuh_orchestrator.models import ClusterState, ScalingError


def cluster():
    return ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local",), ("i",), "d", "nginx", None, None, "default")


def test_generation_override(tmp_path):
    out = tmp_path / "docker-compose.orchestrator.yml"
    b = ComposeBackend(tmp_path / "base.yml", out, tmp_path)
    b.generate_override(cluster(), "wazuh-manager03.local")
    assert "wazuh-manager03.local" in out.read_text(encoding="utf-8")


def test_worker_unique():
    b = ComposeBackend(__file__, __file__, __file__)
    assert b.next_worker_name(cluster()) == "wazuh-manager03.local"


def test_names_uniques_and_validated():
    with pytest.raises(ScalingError):
        validate_service_name("../bad")


def test_chemins_corrects(tmp_path):
    b = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path)
    assert str(b.compose_command("config")[3]).endswith("base.yml")


def test_commande_compose_shell_false(tmp_path):
    calls = []
    def runner(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args[0], 0)
    b = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path, runner=runner)
    b.run_compose("config")
    assert calls[0]["shell"] is False


def test_timeout_prevu(tmp_path):
    calls = []
    def runner(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args[0], 0)
    ComposeBackend(tmp_path / "b", tmp_path / "o", tmp_path, timeout=7, runner=runner).run_compose("ps")
    assert calls[0]["timeout"] == 7


def test_nginx_pool_correct(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    assert "wazuh-manager03.local:1514" in NginxConfigManager(p).render_with_worker("wazuh-manager03.local")


def test_worker_added_once(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_managers {\n    server wazuh-manager03.local:1514;\n}\n", encoding="utf-8")
    rendered = NginxConfigManager(p).render_with_worker("wazuh-manager03.local")
    assert rendered.count("wazuh-manager03.local") == 1


def test_nginx_validation_ok(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    NginxConfigManager(p, validator=lambda path: True).apply_worker("wazuh-manager03.local", tmp_path / "backup")
    assert "wazuh-manager03.local" in p.read_text(encoding="utf-8")


def test_nginx_validation_ko_restore(tmp_path):
    p = tmp_path / "nginx.conf"
    original = "upstream wazuh_managers {\n}\n"
    p.write_text(original, encoding="utf-8")
    with pytest.raises(ScalingError):
        NginxConfigManager(p, validator=lambda path: False).apply_worker("wazuh-manager03.local", tmp_path / "backup")
    assert p.read_text(encoding="utf-8") == original
