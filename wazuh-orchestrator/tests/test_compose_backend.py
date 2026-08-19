from __future__ import annotations

import subprocess
import pytest

from wazuh_orchestrator.backends.compose import ComposeBackend, NginxConfigManager, validate_service_name
from wazuh_orchestrator.models import ClusterState, NamingPolicy, ScalingError


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
    cmd = b.compose_command("config")
    assert "--project-directory" in cmd
    assert str(cmd[cmd.index("-f") + 1]).endswith("base.yml")


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


def test_monotonic_next_worker_with_policy_gap():
    policy = NamingPolicy(manager_prefix="wazuh-manager", manager_number_width=2, manager_internal_dns_suffix="local")
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager04.local"), ("i",), "d", "nginx", None, None, "default", naming_policy=policy)
    b = ComposeBackend(__file__, __file__, __file__)
    assert b.next_worker_name(c) == "wazuh-manager05.local"


def test_removed_worker_cannot_resurrect_from_desired_state(tmp_path):
    out = tmp_path / "docker-compose.orchestrator.yml"
    b = ComposeBackend(tmp_path / "base.yml", out, tmp_path)
    b.generate_override(cluster(), "wazuh-manager03.local")
    assert "wazuh-manager03.local" in out.read_text(encoding="utf-8")
    b.generate_override(cluster(), "wazuh-manager04.local")
    text = out.read_text(encoding="utf-8")
    assert "wazuh-manager04.local" in text
    assert "wazuh-manager03.local" not in text


def test_scale_down_removes_worker_from_desired_state_preserves_volume(tmp_path):
    out = tmp_path / "docker-compose.orchestrator.yml"
    b = ComposeBackend(tmp_path / "base.yml", out, tmp_path)
    b.generate_override(cluster(), "wazuh-manager03.local")
    b.remove_from_override("wazuh-manager03.local")
    text = out.read_text(encoding="utf-8")
    assert "wazuh-manager03.local:" not in text
    assert "volumes:" in text


def test_nginx_does_not_add_worker_to_enrollment_backend(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_enrollment {\n    server wazuh-manager01.local:1515;\n}\nupstream wazuh_agent_traffic {\n    server wazuh-manager02.local:1514;\n}\n", encoding="utf-8")
    rendered = NginxConfigManager(p).render_with_worker("wazuh-manager03.local")
    enrollment = rendered.split("upstream wazuh_agent_traffic", 1)[0]
    assert "wazuh-manager03.local" not in enrollment
    assert "server wazuh-manager03.local:1514;" in rendered


def test_nginx_missing_agent_upstream_fails_closed(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_enrollment {\n    server wazuh-manager01.local:1515;\n}\n", encoding="utf-8")
    with pytest.raises(ScalingError, match="agent-traffic"):
        NginxConfigManager(p).render_with_worker("wazuh-manager03.local")
