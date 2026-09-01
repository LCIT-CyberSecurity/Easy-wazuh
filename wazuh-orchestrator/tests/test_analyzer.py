from __future__ import annotations

from wazuh_orchestrator.analyzer import analyze
from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.models import AnalysisInput, ClusterState, DashboardState, HostMetrics, IndexerState, NginxState, WorkerMetrics


def cfg():
    return load_config()


def cluster(workers=2, healthy=True, nginx=True, mode="multi-node"):
    names = tuple(f"wazuh-manager{i:02d}.local" for i in range(2, 2 + workers))
    return ClusterState(mode, "wazuh-manager01.local", names, ("wazuh-indexer01.local",), "wazuh-dashboard01.local", "nginx" if nginx else None, None, None, "default", cluster_healthy=healthy, nginx_healthy=True if nginx else None)


def host(cpu=45, mem=45, iowait=3, disk=68):
    return HostMetrics(4, cpu, mem, 1024, 0, 20, iowait, disk, "/")


def workers(count=2, queue_usage=5, queue_delta=0, discarded=0, dropped=0, eps=10, samples=0, agents=50, health="healthy", cpu=None, mem=None):
    return tuple(
        WorkerMetrics(
            name=f"w{i}",
            cpu_percent=cpu,
            memory_percent=mem,
            queue_size=10 + queue_delta,
            queue_delta=queue_delta,
            eps=eps,
            events_received=1000,
            events_processed=990,
            queue_usage_percent=queue_usage,
            queue_capacity=131072,
            discarded_count=discarded,
            dropped_count=dropped,
            connected_agents=agents,
            cluster_sync_status="synced",
            health=health,
            samples_with_pressure=samples,
        )
        for i in range(count)
    )


def snap(**kw):
    c = kw.pop("cluster", cluster())
    return AnalysisInput(
        c,
        kw.pop("host", host()),
        kw.pop("workers", workers(count=c.worker_count)),
        kw.pop("indexer", IndexerState(("i",), True, disk_free_percent=70, health_status="green", node_count=3, unassigned_shards=0, pending_tasks=0, rejected_operations=0, fs_free_percent=70, heap_used_percent=30)),
        kw.pop("dashboard", DashboardState(c.dashboard, True)),
        kw.pop("nginx", NginxState(c.nginx, True, True, advanced_metrics_available=False)),
    )


def test_healthy():
    r = analyze(snap(), cfg())
    assert r.status == "OK"
    assert "HEALTHY" in r.diagnostics


def test_moderate_pressure_is_watch_not_scale():
    r = analyze(snap(workers=workers(queue_usage=75, queue_delta=5, samples=1)), cfg())
    assert r.status == "WATCH"
    assert "WORKER_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_persistent_manager_saturation_recommends_one_worker_even_with_host_unknown():
    r = analyze(snap(host=HostMetrics(None, None, None, None, None, None, None, None, None), workers=workers(queue_usage=90, queue_delta=10, discarded=2, dropped=1, samples=3)), cfg())
    assert r.status == "SCALE_RECOMMENDED"
    assert "HOST_CAPACITY_UNKNOWN" in r.diagnostics
    assert r.recommended_next_workers == 3
    assert r.host_capacity_status == "HOST_CAPACITY_UNKNOWN"


def test_workers_charges_host_sature_host_pressure_prioritaire():
    r = analyze(snap(host=host(cpu=93, mem=90), workers=workers(queue_usage=90, queue_delta=5, discarded=1, samples=3)), cfg())
    assert "HOST_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_host_sature_workers_faibles_pas_de_scale():
    r = analyze(snap(host=host(cpu=92), workers=workers(queue_usage=5)), cfg())
    assert "HOST_PRESSURE" in r.diagnostics
    assert "WORKER_PRESSURE" not in r.diagnostics


def test_worker_imbalance():
    r = analyze(snap(workers=(workers(count=1, agents=100)[0], workers(count=1, agents=10)[0])), cfg())
    assert "WORKER_IMBALANCE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_indexer_pressure():
    r = analyze(snap(indexer=IndexerState(("i",), False, disk_free_percent=8, health_status="red", unassigned_shards=2, rejected_operations=5, fs_free_percent=8)), cfg())
    assert r.status == "INDEXER_PRESSURE"
    assert "INDEXER_PRESSURE" in r.diagnostics
    assert r.recommended_next_workers is None


def test_cluster_degraded():
    r = analyze(snap(cluster=cluster(healthy=False)), cfg())
    assert "CLUSTER_DEGRADED" in r.diagnostics
    assert r.status == "UNKNOWN"


def test_insufficient_metrics():
    empty = tuple(WorkerMetrics(f"w{i}") for i in range(2))
    r = analyze(snap(host=host(cpu=None), workers=empty), cfg())
    assert "INSUFFICIENT_METRICS" in r.diagnostics
    assert r.confidence == "LOW"


def test_max_workers_reached():
    r = analyze(snap(cluster=cluster(workers=6), workers=workers(count=6, queue_usage=90, discarded=1, samples=3)), cfg())
    assert "MAX_WORKERS_REACHED" in r.diagnostics
    assert r.recommended_next_workers is None


def test_restart_loop_not_auto_plus_one():
    r = analyze(snap(workers=workers(queue_usage=5)), cfg())
    assert r.recommended_next_workers is None


def test_single_cpu_signal_not_enough_for_scale():
    r = analyze(snap(workers=workers(queue_usage=5, cpu=90)), cfg())
    assert r.status == "WATCH"
    assert r.recommended_next_workers is None


def test_dashboard_pressure_detected_without_scaling():
    base = snap()
    r = analyze(AnalysisInput(base.cluster, base.host, base.workers, base.indexer, DashboardState("wazuh-dashboard01.local", True, 90, 20, 0), base.nginx), cfg())
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
    r = analyze(snap(cluster=c, workers=workers(queue_usage=90, dropped=1, samples=3)), cfg())
    assert "POST_SCALE_STABILIZING" in r.diagnostics
    assert r.recommended_next_workers is None


def test_incomplete_transaction_blocks_recommendation():
    c = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", None, None, "default", cluster_healthy=True, nginx_healthy=True, details={"incomplete_transaction": True})
    r = analyze(snap(cluster=c, workers=workers(queue_usage=90, dropped=1, samples=3)), cfg())
    assert "INCOMPLETE_TRANSACTION" in r.diagnostics
    assert r.recommended_next_workers is None


def test_nginx_ko_is_explicit():
    r = analyze(snap(nginx=NginxState("nginx", reachable=False, healthy=False, advanced_metrics_available=False)), cfg())
    assert "NGINX_DEGRADED" in r.diagnostics
    assert r.status == "UNKNOWN"


def test_nginx_advanced_metrics_unavailable_is_partial_not_failure():
    r = analyze(snap(nginx=NginxState("nginx", reachable=True, healthy=True, advanced_metrics_available=False)), cfg())
    assert "NGINX_METRICS_UNAVAILABLE" in r.diagnostics
    assert r.status == "OK"
