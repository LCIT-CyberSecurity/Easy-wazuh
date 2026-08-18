from __future__ import annotations

import json

import pytest

from wazuh_orchestrator.backends.compose import NginxConfigManager
from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, ScalingError, WorkerMetrics
from wazuh_orchestrator.scaler import build_plan, scale


class Backend:
    def __init__(self, fail_up=False):
        self.commands = []
        self.generated = []
        self.fail_up = fail_up

    def next_worker_name(self, cluster):
        return "wazuh-manager04.local"

    def generate_override(self, cluster, worker):
        self.generated.append(worker)

    def run_compose(self, *args):
        self.commands.append(args)
        if self.fail_up and args[:2] == ("up", "-d"):
            raise ScalingError("Docker start failure")


def cfg():
    return load_config()


def snapshot(count=3):
    workers = tuple(
        WorkerMetrics(
            f"wazuh-manager{i:02d}.local",
            80,
            20,
            1,
            1,
            managed_by_orchestrator=i > 2,
            baseline_worker=i == 2,
        )
        for i in range(2, 2 + count)
    )
    cluster = ClusterState("multi-node", "wazuh-manager01.local", tuple(w.name for w in workers), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    return AnalysisInput(cluster, HostMetrics(4, 35, 35, 1024, 0, 10, 1, 80, "/"), workers, IndexerState(("i",), True, 20, 20, 80))


def test_scale_up_success_writes_audit(tmp_path):
    backend = Backend()
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    plan = scale(snapshot(3), cfg(), 4, backend, NginxConfigManager(nginx_conf), tmp_path)
    assert plan.action == "scale_up"
    assert ("up", "-d", "wazuh-manager04.local") in backend.commands
    audit = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert '"result": "success"' in audit


def test_docker_start_failure_records_failed_audit(tmp_path):
    with pytest.raises(ScalingError):
        scale(snapshot(3), cfg(), 4, Backend(fail_up=True), None, tmp_path)
    assert '"result": "failed"' in (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")


def test_nginx_failure_rolls_back_new_worker(tmp_path):
    backend = Backend()
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    with pytest.raises(ScalingError):
        scale(snapshot(3), cfg(), 4, backend, NginxConfigManager(nginx_conf, validator=lambda path: False), tmp_path)
    assert ("stop", "wazuh-manager04.local") in backend.commands
    assert ("rm", "-f", "wazuh-manager04.local") in backend.commands


def test_scale_down_drain_before_stop(tmp_path):
    events = []
    class OrderedBackend(Backend):
        def run_compose(self, *args):
            events.append(args[0])
            super().run_compose(*args)
    scale(snapshot(3), cfg(), 2, OrderedBackend(), None, tmp_path, sleep=lambda seconds: events.append("drain"))
    assert events == ["drain", "stop", "rm"]


def test_scale_down_rm_never_uses_volume_flag(tmp_path):
    backend = Backend()
    scale(snapshot(3), cfg(), 2, backend, None, tmp_path, sleep=lambda seconds: None)
    assert all("-v" not in cmd for cmd in backend.commands)


def test_master_never_selected_for_scale_down():
    plan = build_plan(snapshot(3), cfg(), 2)
    assert plan.worker_to_remove != "wazuh-manager01.local"


def test_double_generation_uses_next_unique_worker():
    plan = build_plan(snapshot(3), cfg(), 4, Backend())
    assert plan.worker_to_create == "wazuh-manager04.local"


def test_nginx_remove_worker(tmp_path):
    p = tmp_path / "nginx.conf"
    p.write_text("upstream wazuh_managers {\n    server wazuh-manager03.local:1514;\n}\n", encoding="utf-8")
    NginxConfigManager(p).remove_worker("wazuh-manager03.local", tmp_path / "backup")
    assert "wazuh-manager03.local" not in p.read_text(encoding="utf-8")


def test_secret_absent_from_audit(tmp_path):
    from wazuh_orchestrator.logging_setup import write_audit
    write_audit(tmp_path, {"action": "x", "password": "SecretPassword", "token": "abc"})
    data = json.loads((tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8"))
    assert data["password"] == "REDACTED"
    assert data["token"] == "REDACTED"


def test_healthcheck_failure_path_is_reported(tmp_path):
    backend = Backend()
    class FailingNginx:
        def apply_worker(self, worker, backup_dir):
            raise ScalingError("healthcheck failure")
    with pytest.raises(ScalingError, match="healthcheck failure"):
        scale(snapshot(3), cfg(), 4, backend, FailingNginx(), tmp_path)


def test_cluster_join_failure_path_is_reported(tmp_path):
    backend = Backend()
    class FailingNginx:
        def apply_worker(self, worker, backup_dir):
            raise ScalingError("cluster join failure")
    with pytest.raises(ScalingError, match="cluster join failure"):
        scale(snapshot(3), cfg(), 4, backend, FailingNginx(), tmp_path)


def test_lock_file_created_for_scale(tmp_path):
    scale(snapshot(3), cfg(), 2, Backend(), None, tmp_path, sleep=lambda seconds: None)
    assert (tmp_path / "generated" / "scale.lock").exists()
