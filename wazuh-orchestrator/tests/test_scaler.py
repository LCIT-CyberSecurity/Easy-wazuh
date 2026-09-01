from __future__ import annotations

import pytest

from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, DashboardState, HostMetrics, IndexerState, NginxState, SafetyError, WorkerMetrics
from wazuh_orchestrator.scaler import build_plan


def cfg():
    return load_config()


def pressure_worker(name, baseline=False, managed=False):
    return WorkerMetrics(
        name,
        queue_size=100,
        queue_delta=10,
        events_received=1000,
        events_processed=990,
        queue_usage_percent=90,
        discarded_count=1,
        dropped_count=1,
        connected_agents=50,
        cluster_sync_status="synced",
        health="healthy",
        baseline_worker=baseline,
        managed_by_orchestrator=managed,
        samples_with_pressure=3,
    )


def snapshot(cluster=None, workers=None, host=None, dashboard=None):
    cluster = cluster or ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    workers = workers or (pressure_worker("wazuh-manager02.local", baseline=True), pressure_worker("wazuh-manager03.local", managed=True))
    return AnalysisInput(
        cluster,
        host or HostMetrics(None, None, None, None, None, None, None, None, None),
        workers,
        IndexerState(("i",), True, disk_free_percent=80, health_status="green", rejected_operations=0, fs_free_percent=80),
        dashboard or DashboardState("d", True),
        NginxState("nginx", True, True, advanced_metrics_available=False),
    )


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


def test_plan_reports_host_capacity_unknown_without_blocking_read_only_plan():
    plan = build_plan(snapshot(), cfg(), 3)
    assert plan.action == "scale_up"
    assert plan.projection.reason == "HOST_CAPACITY_UNKNOWN"


def test_plan_reports_risks_when_analysis_does_not_recommend_scale():
    workers = (WorkerMetrics("w1", events_received=100, queue_usage_percent=5, health="healthy"), WorkerMetrics("w2", events_received=100, queue_usage_percent=5, health="healthy"))
    plan = build_plan(snapshot(workers=workers), cfg(), 3)
    assert plan.action == "scale_up"
    assert plan.risks


def test_plan_without_backend_uses_current_worker_count_for_fallback_name():
    plan = build_plan(snapshot(), cfg(), 3)
    assert plan.worker_to_create == "wazuh-manager03.local"


def test_plan_scale_down_3_to_2():
    c = ClusterState("multi-node", "m", ("w1", "w2", "w3"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    ws = (WorkerMetrics("w1", baseline_worker=True), WorkerMetrics("w2", managed_by_orchestrator=True), WorkerMetrics("w3", managed_by_orchestrator=True))
    plan = build_plan(snapshot(c, ws), cfg(), 2)
    assert plan.action == "scale_down"
    assert plan.worker_to_remove == "w3"


def test_baseline_worker_never_removed():
    c = ClusterState("multi-node", "m", ("w1", "w2"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    ws = (WorkerMetrics("w1", baseline_worker=True), WorkerMetrics("w2", baseline_worker=True))
    with pytest.raises(SafetyError):
        build_plan(snapshot(c, ws), cfg(), 1)


def test_idempotent_target_already_reached():
    plan = build_plan(snapshot(), cfg(), 2)
    assert plan.action == "none"


def test_incomplete_transaction_scaling_refused():
    c = ClusterState("multi-node", "m", ("w1", "w2"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True, details={"incomplete_transaction": True})
    with pytest.raises(SafetyError, match="INCOMPLETE_TRANSACTION"):
        build_plan(snapshot(c), cfg(), 3)


def test_dashboard_pressure_is_a_read_only_plan_risk():
    s = snapshot(dashboard=DashboardState("d", True, 90, 20, 0))
    plan = build_plan(s, cfg(), 3)
    assert plan.risks
    assert any("Dashboard" in risk for risk in plan.risks)
