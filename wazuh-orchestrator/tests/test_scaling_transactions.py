from __future__ import annotations

import pytest

from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, DashboardState, HostMetrics, IndexerState, NginxState, ScalingError, WorkerMetrics
from wazuh_orchestrator.scaler import scale


def cfg():
    return load_config()


class Backend:
    def __init__(self):
        self.commands = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.commands.append((name, args, kwargs))
        return record


def snapshot():
    cluster = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    workers = (
        WorkerMetrics("wazuh-manager02.local", events_received=1000, queue_usage_percent=90, discarded_count=1, dropped_count=1, health="healthy", samples_with_pressure=3, baseline_worker=True),
        WorkerMetrics("wazuh-manager03.local", events_received=1000, queue_usage_percent=90, discarded_count=1, dropped_count=1, health="healthy", samples_with_pressure=3, managed_by_orchestrator=True),
    )
    return AnalysisInput(
        cluster,
        HostMetrics(None, None, None, None, None, None, None, None, None),
        workers,
        IndexerState(("i",), True, health_status="green", rejected_operations=0, fs_free_percent=80),
        DashboardState("d", True),
        NginxState("nginx", True, True, advanced_metrics_available=False),
    )


def test_scale_execution_disabled_before_backend_calls(tmp_path):
    backend = Backend()
    with pytest.raises(ScalingError, match="disabled in Wazuh Orchestrator V1"):
        scale(snapshot(), cfg(), 3, backend, None, tmp_path)
    assert backend.commands == []


def test_scale_execution_disabled_before_sleep_or_validators(tmp_path):
    backend = Backend()
    slept = []

    class Validator:
        def final_validate_cluster(self):
            raise AssertionError("validator must not run in V1")

    with pytest.raises(ScalingError, match="read-only diagnostics"):
        scale(snapshot(), cfg(), 1, backend, None, tmp_path, sleep=lambda seconds: slept.append(seconds), cluster_validator=Validator())

    assert slept == []
    assert not (tmp_path / "generated" / "scale.lock").exists()


def test_scale_execution_disabled_before_certificate_preparation(tmp_path):
    backend = Backend()

    class Certificates:
        def prepare_worker(self, worker, transaction_id):
            raise AssertionError("certificates must not be prepared in V1")

    with pytest.raises(ScalingError, match="disabled"):
        scale(snapshot(), cfg(), 3, backend, None, tmp_path, certificate_preparer=Certificates())

    assert backend.commands == []
