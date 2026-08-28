from __future__ import annotations

import subprocess

import pytest
import yaml

from wazuh_orchestrator.backends.compose import ComposeBackend, NginxConfigManager, validate_service_name
from wazuh_orchestrator.models import ClusterState, NamingPolicy, ScalingError


def cluster():
    return ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local",), ("wazuh-indexer01.local",), "d", "nginx", None, None, "default")


def write_base_compose(root):
    path = root / "base.yml"
    path.write_text("""services:
  wazuh-manager02.local:
    image: wazuh/wazuh-manager:4.14.5
    restart: unless-stopped
    hostname: wazuh-manager02.local
    environment:
      CUSTOM_KEEP: yes
    volumes:
      - wazuh-manager02_local_etc:/var/ossec/etc
      - wazuh-manager02_local_logs:/var/ossec/logs
      - ./config/wazuh_cluster/wazuh_worker.conf:/wazuh-config-mount/etc/ossec.conf:ro
volumes:
  wazuh-manager02_local_etc:
  wazuh-manager02_local_logs:
""", encoding="utf-8")
    return path


def write_worker_template(root):
    path = root / "config" / "wazuh_cluster" / "wazuh_worker.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<cluster><node_name>wazuh-manager02.local</node_name><node>wazuh-manager01.local</node><key>SECRET</key></cluster>", encoding="utf-8")
    return path


def test_generation_override(tmp_path):
    write_worker_template(tmp_path)
    base = write_base_compose(tmp_path)
    original_base = base.read_text(encoding="utf-8")
    out = tmp_path / "docker-compose.orchestrator.yml"
    b = ComposeBackend(base, out, tmp_path)
    b.generate_override(cluster(), "wazuh-manager03.local")
    rendered = out.read_text(encoding="utf-8")
    assert "wazuh-manager03.local" in rendered
    assert "worker-configs/wazuh-manager03.local.conf" in rendered
    worker_config = tmp_path / "worker-configs" / "wazuh-manager03.local.conf"
    assert "<node_name>wazuh-manager03.local</node_name>" in worker_config.read_text(encoding="utf-8")
    assert "<key>SECRET</key>" in worker_config.read_text(encoding="utf-8")
    assert "restart: unless-stopped" in rendered
    assert "CUSTOM_KEEP" in rendered
    assert "wazuh-manager02.local:" not in rendered
    assert base.read_text(encoding="utf-8") == original_base


def test_generation_override_uses_cluster_network_and_indexer(tmp_path):
    write_worker_template(tmp_path)
    base = write_base_compose(tmp_path)
    out = tmp_path / "docker-compose.orchestrator.yml"
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local",), ("wazuh-indexer01.local",), "d", "nginx", None, None, "easywazuh")
    ComposeBackend(base, out, tmp_path).generate_override(c, "wazuh-manager03.local")
    rendered = out.read_text(encoding="utf-8")
    generated = yaml.safe_load(rendered)
    service = generated["services"]["wazuh-manager03.local"]
    assert service["networks"] == ["easywazuh"]
    assert service["environment"]["INDEXER_URL"] == "https://wazuh-indexer01.local:9200"


def test_missing_worker_template_blocks_override(tmp_path):
    b = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path)
    with pytest.raises(ScalingError, match="Baseline Wazuh worker config"):
        b.generate_override(cluster(), "wazuh-manager03.local")


def test_malformed_base_compose_blocks_override(tmp_path):
    write_worker_template(tmp_path)
    base = tmp_path / "base.yml"
    base.write_text("services: [", encoding="utf-8")
    b = ComposeBackend(base, tmp_path / "generated.yml", tmp_path)
    with pytest.raises(ScalingError, match="Malformed Compose"):
        b.generate_override(cluster(), "wazuh-manager03.local")


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


def test_worker_health_accepts_compose_json_array(tmp_path):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='[{"Service":"wazuh-manager03.local","Health":"healthy"}]')

    backend = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path, runner=runner)
    backend.wait_for_worker_health("wazuh-manager03.local")
    assert calls[0][-4:] == ["ps", "--format", "json", "wazuh-manager03.local"]


def test_worker_health_accepts_compose_json_lines_status(tmp_path):
    def runner(command, **kwargs):
        stdout = '{"Service":"other","State":"running"}\n{"Service":"wazuh-manager03.local","Status":"running (healthy)"}'
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    backend = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path, runner=runner)
    backend.wait_for_worker_health("wazuh-manager03.local")


def test_worker_health_timeout_fails_closed(tmp_path):
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout='[{"Service":"wazuh-manager03.local","Health":"starting"}]')

    backend = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path, timeout=0, runner=runner)
    with pytest.raises(ScalingError, match="starting"):
        backend.wait_for_worker_health("wazuh-manager03.local")


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
    write_worker_template(tmp_path)
    out = tmp_path / "docker-compose.orchestrator.yml"
    b = ComposeBackend(tmp_path / "base.yml", out, tmp_path)
    b.generate_override(cluster(), "wazuh-manager03.local")
    assert "wazuh-manager03.local" in out.read_text(encoding="utf-8")
    b.generate_override(cluster(), "wazuh-manager04.local")
    text = out.read_text(encoding="utf-8")
    assert "wazuh-manager04.local" in text
    assert "wazuh-manager03.local" not in text


def test_scale_down_removes_worker_from_desired_state_preserves_volume(tmp_path):
    write_worker_template(tmp_path)
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


def test_nginx_reload_failure_restores_previous_config(tmp_path):
    p = tmp_path / "nginx.conf"
    original = "upstream wazuh_managers {\n}\n"
    p.write_text(original, encoding="utf-8")

    def fail_reload():
        raise RuntimeError("reload failed")

    with pytest.raises(ScalingError, match="reload failed"):
        NginxConfigManager(p, validator=lambda path: True, reloader=fail_reload).apply_worker("wazuh-manager03.local", tmp_path / "backup")
    assert p.read_text(encoding="utf-8") == original


def test_compose_backend_validates_and_reloads_nginx_service(tmp_path):
    commands = []

    def runner(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    backend = ComposeBackend(tmp_path / "base.yml", tmp_path / "generated.yml", tmp_path, runner=runner)
    assert backend.validate_nginx_config("nginx") is True
    assert backend.reload_nginx("nginx") is True
    assert commands[0][-5:] == ["exec", "-T", "nginx", "nginx", "-t"]
    assert commands[1][-6:] == ["exec", "-T", "nginx", "nginx", "-s", "reload"]
