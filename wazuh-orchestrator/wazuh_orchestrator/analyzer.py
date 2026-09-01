"""Capacity analysis and read-only recommendations."""

from __future__ import annotations

from statistics import median

from .models import AnalysisInput, AnalysisResult, HostCapacityProjection, OrchestratorConfig, WorkerMetrics

DIAGNOSTICS = {
    "HEALTHY",
    "OK",
    "WATCH",
    "UNKNOWN",
    "WORKER_PRESSURE",
    "MANAGER_PRESSURE",
    "HOST_PRESSURE",
    "WORKER_IMBALANCE",
    "INDEXER_PRESSURE",
    "DASHBOARD_PRESSURE",
    "CLUSTER_DEGRADED",
    "NGINX_DEGRADED",
    "NGINX_METRICS_UNAVAILABLE",
    "CONFIG_DRIFT",
    "INSUFFICIENT_METRICS",
    "MAX_WORKERS_REACHED",
    "UNSUPPORTED_DEPLOYMENT_MODE",
    "UNSUPPORTED_WAZUH_LAYOUT",
    "POST_SCALE_STABILIZING",
    "INCOMPLETE_TRANSACTION",
    "CERTIFICATE_SAFETY_FAILURE",
    "NAMING_COLLISION",
    "NAMING_POLICY_AMBIGUOUS",
    "HOST_CAPACITY_UNKNOWN",
}


def analyze(snapshot: AnalysisInput, cfg: OrchestratorConfig) -> AnalysisResult:
    """Diagnose Wazuh pressure without requiring Docker or host metrics."""
    diagnostics: list[str] = []
    explanations: list[str] = []
    current = snapshot.cluster.worker_count
    projection = can_host_accept_worker(snapshot.host, snapshot.workers, cfg)
    host_capacity_status = projection.reason if projection.reason == "HOST_CAPACITY_UNKNOWN" else ("HOST_CAPACITY_OK" if projection.can_accept else "HOST_CAPACITY_LIMITED")

    _topology_diagnostics(snapshot, diagnostics, explanations)
    _platform_diagnostics(snapshot, cfg, diagnostics, explanations)

    manager_signals = _worker_pressure_signals(snapshot.workers, cfg)
    indexer_signals = _indexer_pressure_signals(snapshot)
    persistent = _persistent_manager_pressure(snapshot.workers, cfg)
    confidence = _confidence(snapshot, manager_signals, indexer_signals)

    if indexer_signals:
        diagnostics.append("INDEXER_PRESSURE")
        explanations.append("Indexer pressure detected: " + ", ".join(indexer_signals) + ".")
    if _dashboard_pressure(snapshot):
        diagnostics.append("DASHBOARD_PRESSURE")
        explanations.append("Dashboard pressure detected; V1 monitors it but never creates another Dashboard.")
    if _host_pressure(snapshot.host, cfg):
        diagnostics.append("HOST_PRESSURE")
        explanations.append("Host CPU, memory, I/O wait or disk safety threshold is exceeded.")
    elif host_capacity_status == "HOST_CAPACITY_UNKNOWN":
        diagnostics.append("HOST_CAPACITY_UNKNOWN")
        explanations.append("Host CPU/RAM/IO capacity is unknown; verify host resources before deploying another worker on this host.")
    if _worker_imbalance(snapshot.workers, cfg):
        diagnostics.append("WORKER_IMBALANCE")
        explanations.append("Worker agent distribution is imbalanced; inspect NGINX and agent assignment.")
    if _metrics_insufficient(snapshot):
        diagnostics.append("INSUFFICIENT_METRICS")
        explanations.append("Some Wazuh metrics are missing; unknown values are not considered healthy.")
    if current >= cfg.workers.max:
        diagnostics.append("MAX_WORKERS_REACHED")
        explanations.append("Configured maximum worker count has been reached.")

    status = _status(diagnostics, manager_signals, indexer_signals, persistent, cfg)
    next_workers = None
    estimated = None
    if status == "SCALE_RECOMMENDED":
        estimated = min(current + 1, cfg.workers.max)
        next_workers = estimated
        diagnostics.extend(("MANAGER_PRESSURE", "WORKER_PRESSURE"))
        explanations.append("Persistent Wazuh manager pressure is detected; add one worker, then re-evaluate after stabilization.")
        if host_capacity_status == "HOST_CAPACITY_UNKNOWN":
            explanations.append("The recommendation does not prove that the current host has enough CPU/RAM/IO for the new worker.")
    elif status == "WATCH":
        diagnostics.append("WATCH")
        if manager_signals:
            diagnostics.extend(("MANAGER_PRESSURE", "WORKER_PRESSURE"))
            explanations.append("Manager pressure signals are present but not persistent or concordant enough for scale-out: " + ", ".join(manager_signals) + ".")
    elif status == "OK":
        diagnostics.extend(("OK", "HEALTHY"))
        explanations.append("No significant Wazuh manager or indexer saturation signal was detected.")
    elif status == "UNKNOWN":
        diagnostics.append("UNKNOWN")
        explanations.append("Analysis is incomplete because required Wazuh runtime data is unavailable or ambiguous.")

    return AnalysisResult(
        diagnostics=tuple(dict.fromkeys(diagnostics)),
        recommendation=_recommendation(status, current, next_workers, host_capacity_status),
        current_workers=current,
        estimated_target_workers=estimated,
        recommended_next_workers=next_workers,
        confidence=confidence,
        explanations=tuple(dict.fromkeys(explanations)),
        projection=projection,
        pressure_signals=tuple(manager_signals + indexer_signals),
        status=status,
        host_capacity_status=host_capacity_status,
    )


def can_host_accept_worker(host, workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> HostCapacityProjection:
    if host.cpu_percent is None or host.memory_percent is None or host.disk_free_percent is None:
        return HostCapacityProjection(False, None, None, None, None, "HOST_CAPACITY_UNKNOWN")
    if host.cpu_percent >= cfg.host.cpu_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host CPU block threshold reached")
    if host.memory_percent >= cfg.host.memory_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host memory block threshold reached")
    if host.iowait_percent is not None and host.iowait_percent >= cfg.host.iowait_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host I/O wait block threshold reached")
    if host.disk_free_percent < cfg.host.disk_free_min_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host disk free threshold reached")
    if not workers or any(w.cpu_percent is None or w.memory_percent is None for w in workers):
        return HostCapacityProjection(False, None, None, None, None, "HOST_CAPACITY_UNKNOWN")
    estimated_cpu_cost = min(median([w.cpu_percent for w in workers if w.cpu_percent is not None]), host.cpu_percent / len(workers))
    estimated_mem_cost = min(median([w.memory_percent for w in workers if w.memory_percent is not None]), host.memory_percent / len(workers))
    projected_cpu = host.cpu_percent + estimated_cpu_cost * cfg.capacity.new_worker_safety_factor
    projected_mem = host.memory_percent + estimated_mem_cost * cfg.capacity.new_worker_safety_factor
    cpu_reserve = 100 - projected_cpu
    mem_reserve = 100 - projected_mem
    ok = cpu_reserve >= cfg.host.reserve_cpu_percent_after_scale and mem_reserve >= cfg.host.reserve_memory_percent_after_scale
    reason = "host capacity accepted" if ok else "projected reserve after adding worker is insufficient"
    return HostCapacityProjection(ok, projected_cpu, projected_mem, cpu_reserve, mem_reserve, reason)


def _topology_diagnostics(snapshot: AnalysisInput, diagnostics: list[str], explanations: list[str]) -> None:
    if snapshot.cluster.mode not in {"single-node", "multi-node"}:
        diagnostics.append("UNSUPPORTED_DEPLOYMENT_MODE")
        explanations.append("Deployment mode is not recognized as Easy-Wazuh.")
    elif snapshot.cluster.mode == "single-node":
        diagnostics.append("UNSUPPORTED_DEPLOYMENT_MODE")
        explanations.append("Worker horizontal scaling requires Easy-Wazuh multi-node deployment.")
    if snapshot.cluster.details.get("unsupported_layout"):
        diagnostics.append("UNSUPPORTED_WAZUH_LAYOUT")
        explanations.append("Wazuh layout is not safe to interpret automatically.")
    if snapshot.cluster.config_drift:
        diagnostics.append("CONFIG_DRIFT")
        explanations.append("Compose or frontend configuration drift was detected.")


def _platform_diagnostics(snapshot: AnalysisInput, cfg: OrchestratorConfig, diagnostics: list[str], explanations: list[str]) -> None:
    if snapshot.cluster.details.get("incomplete_transaction"):
        diagnostics.append("INCOMPLETE_TRANSACTION")
        explanations.append("A previous scaling transaction is incomplete and must be reconciled.")
    if snapshot.cluster.details.get("post_scale_stabilizing"):
        diagnostics.append("POST_SCALE_STABILIZING")
        explanations.append("Recent scaling is still in the stabilization window.")
    if snapshot.cluster.cluster_healthy is False:
        diagnostics.append("CLUSTER_DEGRADED")
        explanations.append("Wazuh cluster health is degraded.")
    elif snapshot.cluster.cluster_healthy is None:
        diagnostics.append("UNKNOWN")
        explanations.append("Wazuh cluster health is unknown.")
    if snapshot.cluster.nginx and snapshot.nginx.healthy is False:
        diagnostics.append("NGINX_DEGRADED")
        explanations.append("NGINX health check failed.")
    elif snapshot.cluster.nginx and snapshot.nginx.healthy is None and cfg.runtime.nginx_health_url:
        diagnostics.append("NGINX_DEGRADED")
        explanations.append("NGINX health check did not return a known state.")
    if snapshot.cluster.nginx and snapshot.nginx.advanced_metrics_available is False:
        diagnostics.append("NGINX_METRICS_UNAVAILABLE")
        explanations.append("NGINX advanced metrics are unavailable; simple health is still usable.")


def _worker_pressure_signals(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> list[str]:
    signals: list[str] = []
    queue_usages = [w.queue_usage_percent for w in workers if w.queue_usage_percent is not None]
    queue_deltas = [w.queue_delta for w in workers if w.queue_delta is not None]
    discarded = [w.discarded_count for w in workers if w.discarded_count is not None]
    dropped = [w.dropped_count for w in workers if w.dropped_count is not None]
    eps_values = [w.eps for w in workers if w.eps is not None]
    agent_counts = [w.connected_agents if w.connected_agents is not None else w.agent_count for w in workers if (w.connected_agents is not None or w.agent_count is not None)]
    cpus = [w.cpu_percent for w in workers if w.cpu_percent is not None]
    mems = [w.memory_percent for w in workers if w.memory_percent is not None]

    if queue_usages and median(queue_usages) >= cfg.workers.warning_utilization_percent:
        signals.append("queue_usage")
    if queue_deltas and sum(1 for q in queue_deltas if q > 0) >= max(1, len(queue_deltas) // 2):
        signals.append("queue_growth")
    if discarded and any(value > 0 for value in discarded):
        signals.append("discarded")
    if dropped and any(value > 0 for value in dropped):
        signals.append("dropped")
    if eps_values and queue_usages and median(queue_usages) >= cfg.workers.warning_utilization_percent:
        signals.append("eps_under_queue_pressure")
    if len(agent_counts) >= 2 and max(agent_counts) - median(agent_counts) >= cfg.analysis.worker_imbalance_percent:
        signals.append("agent_imbalance")
    if cpus and median(cpus) >= cfg.workers.warning_utilization_percent:
        signals.append("cpu_optional")
    if mems and median(mems) >= cfg.workers.warning_utilization_percent:
        signals.append("memory_optional")
    for worker in workers:
        if worker.health not in (None, "healthy", "active", "connected", "ready"):
            signals.append("worker_unhealthy")
            break
        if worker.cluster_sync_status and worker.cluster_sync_status.lower() not in {"synced", "synchronized", "ok", "healthy", "active"}:
            signals.append("cluster_sync")
            break
    return list(dict.fromkeys(signals))


def _persistent_manager_pressure(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> bool:
    if not cfg.analysis.require_multiple_signals:
        return True
    pressure_samples = [w.samples_with_pressure for w in workers if w.samples_with_pressure > 0]
    return bool(pressure_samples and max(pressure_samples) >= 2)


def _indexer_pressure_signals(snapshot: AnalysisInput) -> list[str]:
    idx = snapshot.indexer
    signals: list[str] = []
    if idx.unavailable:
        signals.append("indexer_api_unavailable")
    if idx.health_status and idx.health_status.lower() == "red":
        signals.append("cluster_red")
    elif idx.healthy is False:
        signals.append("cluster_degraded")
    if idx.unassigned_shards is not None and idx.unassigned_shards > 0:
        signals.append("unassigned_shards")
    if idx.pending_tasks is not None and idx.pending_tasks > 0:
        signals.append("pending_tasks")
    if idx.rejected_operations is not None and idx.rejected_operations > 0:
        signals.append("rejected_operations")
    disk_free = idx.fs_free_percent if idx.fs_free_percent is not None else idx.disk_free_percent
    if disk_free is not None and disk_free < 15:
        signals.append("low_storage")
    if idx.heap_used_percent is not None and idx.heap_used_percent >= 85:
        signals.append("jvm_heap")
    if idx.cpu_percent is not None and idx.cpu_percent >= 85:
        signals.append("cpu_optional")
    if idx.memory_percent is not None and idx.memory_percent >= 85:
        signals.append("memory_optional")
    return signals


def _host_pressure(host, cfg: OrchestratorConfig) -> bool:
    return any((
        host.cpu_percent is not None and host.cpu_percent >= cfg.host.cpu_block_percent,
        host.memory_percent is not None and host.memory_percent >= cfg.host.memory_block_percent,
        host.iowait_percent is not None and host.iowait_percent >= cfg.host.iowait_block_percent,
        host.disk_free_percent is not None and host.disk_free_percent < cfg.host.disk_free_min_percent,
    ))


def _worker_imbalance(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> bool:
    counts = [w.connected_agents if w.connected_agents is not None else w.agent_count for w in workers if (w.connected_agents is not None or w.agent_count is not None)]
    if len(counts) >= 2:
        return max(counts) - median(counts) >= cfg.analysis.worker_imbalance_percent
    cpus = [w.cpu_percent for w in workers if w.cpu_percent is not None]
    return len(cpus) >= 2 and max(cpus) - median(cpus) >= cfg.analysis.worker_imbalance_percent


def _dashboard_pressure(snapshot: AnalysisInput) -> bool:
    dashboard = snapshot.dashboard
    if snapshot.cluster.dashboard is None or dashboard.healthy is False:
        return True
    if dashboard.restart_count is not None and dashboard.restart_count >= 3:
        return True
    return any(v is not None and v >= 85 for v in (dashboard.cpu_percent, dashboard.memory_percent))


def _metrics_insufficient(snapshot: AnalysisInput) -> bool:
    if not snapshot.workers:
        return True
    for worker in snapshot.workers:
        observed = (worker.events_received, worker.queue_usage_percent, worker.queue_size, worker.discarded_count, worker.dropped_count, worker.health)
        if all(value is None for value in observed):
            return True
    return False


def _confidence(snapshot: AnalysisInput, manager_signals: list[str], indexer_signals: list[str]) -> str:
    if _metrics_insufficient(snapshot) or snapshot.cluster.cluster_healthy is None:
        return "LOW"
    if indexer_signals or len(manager_signals) >= 2:
        return "HIGH"
    if manager_signals or snapshot.indexer.healthy is None or snapshot.nginx.healthy is None:
        return "MEDIUM"
    return "HIGH"


def _status(diagnostics: list[str], manager_signals: list[str], indexer_signals: list[str], persistent: bool, cfg: OrchestratorConfig) -> str:
    hard_unknown = {"UNSUPPORTED_DEPLOYMENT_MODE", "UNSUPPORTED_WAZUH_LAYOUT", "CLUSTER_DEGRADED", "NGINX_DEGRADED", "POST_SCALE_STABILIZING", "INCOMPLETE_TRANSACTION", "CONFIG_DRIFT"}
    if hard_unknown.intersection(diagnostics):
        return "UNKNOWN"
    if indexer_signals:
        return "INDEXER_PRESSURE"
    if "DASHBOARD_PRESSURE" in diagnostics:
        return "UNKNOWN"
    if "HOST_PRESSURE" in diagnostics:
        return "WATCH" if manager_signals else "UNKNOWN"
    if "MAX_WORKERS_REACHED" in diagnostics:
        return "WATCH" if manager_signals else "OK"
    if len(manager_signals) >= cfg.analysis.minimum_pressure_signals and persistent:
        return "SCALE_RECOMMENDED"
    if manager_signals:
        return "WATCH"
    if "INSUFFICIENT_METRICS" in diagnostics or "UNKNOWN" in diagnostics:
        return "UNKNOWN"
    return "OK"


def _recommendation(status: str, current: int, next_workers: int | None, host_capacity_status: str) -> str:
    if status == "SCALE_RECOMMENDED" and next_workers is not None:
        extra = " HOST_CAPACITY_UNKNOWN: verify CPU/RAM/IO before deploying on the same host." if host_capacity_status == "HOST_CAPACITY_UNKNOWN" else ""
        return f"SCALE_RECOMMENDED. Recommended next step: {current} -> {next_workers}. Add one worker, then re-evaluate.{extra}"
    if status == "INDEXER_PRESSURE":
        return "INDEXER_PRESSURE. Do not add a Wazuh manager worker as the default fix; review indexer storage, shards, JVM heap and rejected operations."
    if status == "WATCH":
        return "WATCH. Pressure is present but not persistent or conclusive enough for immediate worker scale-out."
    if status == "UNKNOWN":
        return "UNKNOWN. Analysis is incomplete; missing data is not treated as healthy. Review Wazuh, Dashboard and NGINX diagnostics."
    return "OK. No worker scaling recommended."
