from __future__ import annotations

import pytest

from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, SafetyError, WorkerMetrics
from wazuh_orchestrator.scaler import build_plan


def cfg():
    return load_config()


def snapshot(cluster=None, workers=None, host=None):
    cluster = cluster or ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    workers = workers or (WorkerMetrics("wazuh-manager02.local", 80, 20, 1, 1, baseline_worker=True), WorkerMetrics("wazuh-manager03.local", 78, 20, 1, 1, managed_by_orchestrator=True))
    return AnalysisInput(cluster, host or HostMetrics(4, 40, 40, 1024, 0, 10, 1, 80, "/"), workers, IndexerState(("i",), True, 20, 20, 80))


def test_target_under_baseline_refused():
    with pytest.raises(SafetyError):
        build_plan(snapshot(), cfg(), 0)


def test_target_over_max_refused():
    with pytest.raises(SafetyError):
        build_plan(snapshot(), cfg(), 7)


def test_delta_over_one_refused():
    with pytest.raises(SafetyError):
        build_plan(snapshot(), cfg(), 4)


def test_single_node_scaling_refused():
    s = snapshot(cluster=ClusterState("single-node", "wazuh.manager", (), (), None, None, None, None, None))
    with pytest.raises(SafetyError):
        build_plan(s, cfg(), 1)


def test_low_confidence_scaling_refused():
    s = snapshot(host=HostMetrics(4, None, 40, 1024, 0, 10, 1, 80, "/"))
    with pytest.raises(SafetyError):
        build_plan(s, cfg(), 3)


def test_host_reserve_insuffisante_refused():
    s = snapshot(host=HostMetrics(4, 84, 40, 1024, 0, 10, 1, 80, "/"))
    with pytest.raises(SafetyError):
        build_plan(s, cfg(), 3)


def test_projected_reserve_insuffisante_refused():
    s = snapshot(workers=(WorkerMetrics("w1", 60, 60, 1, 1), WorkerMetrics("w2", 60, 60, 1, 1)), host=HostMetrics(4, 70, 70, 1024, 0, 10, 1, 80, "/"))
    with pytest.raises(SafetyError):
        build_plan(s, cfg(), 3)


def test_healthy_cluster_scale_up_refused_without_recommendation():
    workers = (WorkerMetrics("w1", 20, 20), WorkerMetrics("w2", 20, 20))
    with pytest.raises(SafetyError, match="does not recommend"):
        build_plan(snapshot(workers=workers), cfg(), 3)


def test_plan_scale_down_3_to_2():
    c = ClusterState("multi-node", "m", ("w1", "w2", "w3"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    ws = (WorkerMetrics("w1", 20, 20, baseline_worker=True), WorkerMetrics("w2", 20, 20, managed_by_orchestrator=True), WorkerMetrics("w3", 20, 20, managed_by_orchestrator=True))
    plan = build_plan(snapshot(c, ws), cfg(), 2)
    assert plan.action == "scale_down"
    assert plan.worker_to_remove == "w3"


def test_baseline_worker_never_removed():
    c = ClusterState("multi-node", "m", ("w1", "w2"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    ws = (WorkerMetrics("w1", 20, 20, baseline_worker=True), WorkerMetrics("w2", 20, 20, baseline_worker=True))
    with pytest.raises(SafetyError):
        build_plan(snapshot(c, ws), cfg(), 1)


def test_idempotent_target_already_reached():
    plan = build_plan(snapshot(), cfg(), 2)
    assert plan.action == "none"
