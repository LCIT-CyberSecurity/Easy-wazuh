from __future__ import annotations

from wazuh_orchestrator.analyzer import analyze
from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, WorkerMetrics


def cfg():
    return load_config()


def cluster(workers=2, healthy=True, nginx=True, mode="multi-node"):
    names = tuple(f"wazuh-manager{i:02d}.local" for i in range(2, 2 + workers))
    return ClusterState(mode, "wazuh-manager01.local", names, ("wazuh-indexer01.local",), "wazuh-dashboard01.local", "nginx" if nginx else None, None, None, "default", cluster_healthy=healthy, nginx_healthy=True if nginx else None)


def host(cpu=45, mem=45, iowait=3, disk=68):
    return HostMetrics(4, cpu, mem, 1024, 0, 20, iowait, disk, "/")


def workers(cpu=30, mem=30, q=0, count=2, restarts=0):
    return tuple(WorkerMetrics(f"w{i}", cpu, mem, 10, q, restart_count=restarts) for i in range(count))


def snap(**kw):
    c = kw.pop("cluster", cluster())
    return AnalysisInput(c, kw.pop("host", host()), kw.pop("workers", workers(count=c.worker_count)), kw.pop("indexer", IndexerState(("i",), True, 20, 20, 70)))


def test_healthy():
    assert "HEALTHY" in analyze(snap(), cfg()).diagnostics


def test_worker_pressure_host_libre():
    r = analyze(snap(workers=workers(cpu=85, mem=10, q=5)), cfg())
    assert "WORKER_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers == 3


def test_workers_charges_host_sature_host_pressure_prioritaire():
    r = analyze(snap(host=host(cpu=93, mem=90), workers=workers(cpu=88, mem=88, q=5)), cfg())
    assert "HOST_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_host_sature_workers_faibles_pas_de_scale():
    r = analyze(snap(host=host(cpu=92), workers=workers(cpu=25, mem=30)), cfg())
    assert "HOST_PRESSURE" in r.diagnostics
    assert "WORKER_PRESSURE" not in r.diagnostics


def test_worker_imbalance():
    r = analyze(snap(workers=(WorkerMetrics("w1", 90, 40), WorkerMetrics("w2", 20, 30))), cfg())
    assert "WORKER_IMBALANCE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_indexer_pressure():
    r = analyze(snap(indexer=IndexerState(("i",), False, 90, 90, 8)), cfg())
    assert "INDEXER_PRESSURE" in r.diagnostics


def test_cluster_degraded():
    r = analyze(snap(cluster=cluster(healthy=False)), cfg())
    assert "CLUSTER_DEGRADED" in r.diagnostics


def test_insufficient_metrics():
    r = analyze(snap(host=host(cpu=None), workers=workers()), cfg())
    assert "INSUFFICIENT_METRICS" in r.diagnostics
    assert r.confidence == "LOW"


def test_max_workers_reached():
    r = analyze(snap(cluster=cluster(workers=6), workers=workers(count=6, cpu=80, mem=80, q=1)), cfg())
    assert "MAX_WORKERS_REACHED" in r.diagnostics


def test_restart_loop_not_auto_plus_one():
    r = analyze(snap(workers=workers(cpu=30, mem=30, restarts=4)), cfg())
    assert r.recommended_next_workers is None


def test_restart_loop_plus_cpu_not_enough_for_scale():
    r = analyze(snap(workers=workers(cpu=85, mem=20, q=0, restarts=4)), cfg())
    assert "WORKER_PRESSURE" not in r.diagnostics
    assert r.recommended_next_workers is None

from wazuh_orchestrator.models import DashboardState


def test_dashboard_pressure_detected_without_scaling():
    base = snap()
    r = analyze(AnalysisInput(base.cluster, base.host, base.workers, base.indexer, DashboardState("wazuh-dashboard01.local", True, 90, 20, 0)), cfg())
    assert "DASHBOARD_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers is None
    assert "Dashboard" in r.recommendation


def test_dashboard_missing_detected():
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local",), ("i",), None, "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True)
    r = analyze(snap(cluster=c, workers=workers(count=1)), cfg())
    assert "DASHBOARD_PRESSURE" in r.diagnostics


def test_single_node_is_unsupported_for_worker_scaling():
    c = cluster(mode="single-node")
    r = analyze(snap(cluster=c, workers=()), cfg())
    assert "UNSUPPORTED_DEPLOYMENT_MODE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_post_scale_stabilizing_blocks_second_recommendation():
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True, details={"post_scale_stabilizing": True})
    r = analyze(snap(cluster=c, workers=workers(cpu=90, mem=90, q=3)), cfg())
    assert "POST_SCALE_STABILIZING" in r.diagnostics
    assert r.recommended_next_workers is None


def test_incomplete_transaction_blocks_recommendation():
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True, details={"incomplete_transaction": True})
    r = analyze(snap(cluster=c, workers=workers(cpu=90, mem=90, q=3)), cfg())
    assert "INCOMPLETE_TRANSACTION" in r.diagnostics
    assert r.recommended_next_workers is None
