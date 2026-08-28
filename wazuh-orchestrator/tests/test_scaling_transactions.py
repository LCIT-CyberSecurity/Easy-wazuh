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

    def validate_effective_config(self):
        self.run_compose("config")

    def start_worker(self, worker):
        self.run_compose("up", "-d", worker)

    def wait_for_worker_health(self, worker):
        self.commands.append(("health", worker))

class ClusterValidator:
    def __init__(self, fail_join=False, fail_final=False):
        self.events = []
        self.fail_join = fail_join
        self.fail_final = fail_final

    def verify_cluster_join(self, worker):
        self.events.append(("join", worker))
        if self.fail_join:
            raise ScalingError("cluster join failure")

    def final_validate_cluster(self):
        self.events.append(("validate",))
        if self.fail_final:
            raise ScalingError("final cluster validation failure")


class DesiredStateBackend(Backend):
    def __init__(self):
        super().__init__()
        self.backup = "previous"
        self.restored = None
        self.cleaned_configs = []

    def backup_desired_state(self, backup_dir):
        return self.backup

    def restore_desired_state(self, backup):
        self.restored = backup

    def cleanup_worker_config(self, worker):
        self.cleaned_configs.append(worker)


class CertificatePreparer:
    def __init__(self, fail_prepare=False):
        self.prepared = []
        self.cleaned = []
        self.fail_prepare = fail_prepare

    def prepare_worker(self, node_name, transaction_id):
        self.prepared.append((node_name, transaction_id))
        if self.fail_prepare:
            raise ScalingError("certificate failure")
        return {"status": "ready", "transaction_id": f"cert-{transaction_id}"}

    def cleanup_worker(self, transaction_id):
        self.cleaned.append(transaction_id)


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
    certs = CertificatePreparer()
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    plan = scale(snapshot(3), cfg(), 4, backend, NginxConfigManager(nginx_conf), tmp_path, certificate_preparer=certs, cluster_validator=ClusterValidator())
    assert plan.action == "scale_up"
    assert ("up", "-d", "wazuh-manager04.local") in backend.commands
    assert certs.prepared[0][0] == "wazuh-manager04.local"
    audit = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert '"result": "success"' in audit


def test_docker_start_failure_records_failed_audit(tmp_path):
    certs = CertificatePreparer()
    with pytest.raises(ScalingError):
        scale(snapshot(3), cfg(), 4, Backend(fail_up=True), None, tmp_path, certificate_preparer=certs, cluster_validator=ClusterValidator())
    assert len(certs.cleaned) == 1
    assert '"result": "failed"' in (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")


def test_nginx_failure_rolls_back_new_worker(tmp_path):
    backend = Backend()
    certs = CertificatePreparer()
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    with pytest.raises(ScalingError):
        scale(snapshot(3), cfg(), 4, backend, NginxConfigManager(nginx_conf, validator=lambda path: False), tmp_path, certificate_preparer=certs, cluster_validator=ClusterValidator())
    assert ("stop", "wazuh-manager04.local") in backend.commands
    assert ("rm", "-f", "wazuh-manager04.local") in backend.commands
    assert len(certs.cleaned) == 1


def test_scale_down_drain_before_stop(tmp_path):
    events = []
    class OrderedBackend(Backend):
        def run_compose(self, *args):
            events.append(args[0])
            super().run_compose(*args)
    scale(snapshot(3), cfg(), 2, OrderedBackend(), None, tmp_path, sleep=lambda seconds: events.append("drain"), cluster_validator=ClusterValidator())
    assert events == ["drain", "stop", "rm", "config"]


def test_scale_down_cleans_generated_worker_config(tmp_path):
    backend = DesiredStateBackend()
    scale(snapshot(3), cfg(), 2, backend, None, tmp_path, sleep=lambda seconds: None, cluster_validator=ClusterValidator())
    assert backend.cleaned_configs == ["wazuh-manager04.local"]


def test_scale_down_rm_never_uses_volume_flag(tmp_path):
    backend = Backend()
    scale(snapshot(3), cfg(), 2, backend, None, tmp_path, sleep=lambda seconds: None, cluster_validator=ClusterValidator())
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
        scale(snapshot(3), cfg(), 4, backend, FailingNginx(), tmp_path, certificate_preparer=CertificatePreparer(), cluster_validator=ClusterValidator())


def test_cluster_join_failure_path_is_reported(tmp_path):
    backend = Backend()
    with pytest.raises(ScalingError, match="cluster join failure"):
        scale(snapshot(3), cfg(), 4, backend, None, tmp_path, certificate_preparer=CertificatePreparer(), cluster_validator=ClusterValidator(fail_join=True))
    assert ("stop", "wazuh-manager04.local") in backend.commands
    assert ("rm", "-f", "wazuh-manager04.local") in backend.commands


def test_nginx_entry_removed_when_later_validation_fails(tmp_path):
    backend = Backend()
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    with pytest.raises(ScalingError, match="final cluster validation failure"):
        scale(snapshot(3), cfg(), 4, backend, NginxConfigManager(nginx_conf), tmp_path, certificate_preparer=CertificatePreparer(), cluster_validator=ClusterValidator(fail_final=True))
    assert "wazuh-manager04.local" not in nginx_conf.read_text(encoding="utf-8")


def test_nginx_rollback_reload_failure_keeps_original_config(tmp_path):
    backend = Backend()
    nginx_conf = tmp_path / "nginx.conf"
    original = "upstream wazuh_managers {\n    server wazuh-manager02.local:1514;\n}\n"
    nginx_conf.write_text(original, encoding="utf-8")
    reloads = []

    def fail_second_reload():
        reloads.append("reload")
        if len(reloads) == 2:
            raise RuntimeError("reload failed")

    with pytest.raises(ScalingError, match="NGINX rollback failed"):
        scale(
            snapshot(3),
            cfg(),
            4,
            backend,
            NginxConfigManager(nginx_conf, reloader=fail_second_reload),
            tmp_path,
            certificate_preparer=CertificatePreparer(),
            cluster_validator=ClusterValidator(fail_final=True),
        )
    assert nginx_conf.read_text(encoding="utf-8") == original


def test_final_cluster_validation_failure_path_is_reported(tmp_path):
    backend = Backend()
    with pytest.raises(ScalingError, match="final cluster validation failure"):
        scale(snapshot(3), cfg(), 4, backend, None, tmp_path, certificate_preparer=CertificatePreparer(), cluster_validator=ClusterValidator(fail_final=True))
    assert ("stop", "wazuh-manager04.local") in backend.commands
    assert ("rm", "-f", "wazuh-manager04.local") in backend.commands


def test_rollback_restores_desired_state_and_worker_config(tmp_path):
    backend = DesiredStateBackend()
    with pytest.raises(ScalingError, match="cluster join failure"):
        scale(snapshot(3), cfg(), 4, backend, None, tmp_path, certificate_preparer=CertificatePreparer(), cluster_validator=ClusterValidator(fail_join=True))
    assert backend.restored == "previous"
    assert backend.cleaned_configs == ["wazuh-manager04.local"]


def test_missing_cluster_validator_fails_closed_after_worker_health(tmp_path):
    backend = Backend()
    with pytest.raises(ScalingError, match="INTEGRATION_VALIDATION_REQUIRED"):
        scale(snapshot(3), cfg(), 4, backend, None, tmp_path, certificate_preparer=CertificatePreparer())
    assert ("stop", "wazuh-manager04.local") in backend.commands
    assert ("rm", "-f", "wazuh-manager04.local") in backend.commands


def test_certificate_failure_blocks_before_compose(tmp_path):
    backend = Backend()
    with pytest.raises(ScalingError, match="certificate failure"):
        scale(snapshot(3), cfg(), 4, backend, None, tmp_path, certificate_preparer=CertificatePreparer(fail_prepare=True))
    assert backend.commands == []


def test_lock_file_created_for_scale(tmp_path):
    scale(snapshot(3), cfg(), 2, Backend(), None, tmp_path, sleep=lambda seconds: None, cluster_validator=ClusterValidator())
    assert (tmp_path / "generated" / "scale.lock").exists()


def test_busy_lock_reports_scaling_locked(monkeypatch, tmp_path):
    from wazuh_orchestrator import scaler

    def busy_lock(lock, flags):
        raise BlockingIOError("busy")

    monkeypatch.setattr(scaler.fcntl, "flock", busy_lock)
    with pytest.raises(ScalingError, match="SCALING_LOCKED"):
        scale(snapshot(3), cfg(), 2, Backend(), None, tmp_path, sleep=lambda seconds: None, cluster_validator=ClusterValidator())
