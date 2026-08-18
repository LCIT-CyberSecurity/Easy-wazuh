"""Capacity analysis and safety gates."""

from __future__ import annotations

from math import ceil
from statistics import median

from .models import AnalysisInput, AnalysisResult, HostCapacityProjection, OrchestratorConfig, WorkerMetrics

DIAGNOSTICS = {
    "HEALTHY",
    "WORKER_PRESSURE",
    "HOST_PRESSURE",
    "WORKER_IMBALANCE",
    "INDEXER_PRESSURE",
    "CLUSTER_DEGRADED",
    "NGINX_DEGRADED",
    "CONFIG_DRIFT",
    "INSUFFICIENT_METRICS",
    "MAX_WORKERS_REACHED",
    "HOST_CAPACITY_UNKNOWN",
}


def analyze(snapshot: AnalysisInput, cfg: OrchestratorConfig) -> AnalysisResult:
    diagnostics: list[str] = []
    explanations: list[str] = []
    signals = _worker_pressure_signals(snapshot.workers, cfg)
    confidence = _confidence(snapshot)
    current = snapshot.cluster.worker_count
    projection = can_host_accept_worker(snapshot.host, snapshot.workers, cfg)

    if snapshot.cluster.config_drift:
        diagnostics.append("CONFIG_DRIFT")
        explanations.append("Compose or frontend configuration drift was detected.")
    if snapshot.cluster.cluster_healthy is False:
        diagnostics.append("CLUSTER_DEGRADED")
        explanations.append("Wazuh cluster health is degraded or ambiguous.")
    if snapshot.cluster.nginx and snapshot.cluster.nginx_healthy is False:
        diagnostics.append("NGINX_DEGRADED")
        explanations.append("NGINX/load balancer health is degraded.")
    if snapshot.indexer.healthy is False or _indexer_pressure(snapshot):
        diagnostics.append("INDEXER_PRESSURE")
        explanations.append("Indexer pressure detected; worker scaling is not recommended.")
    if _host_pressure(snapshot.host, cfg):
        diagnostics.append("HOST_PRESSURE")
        explanations.append("Host CPU, memory, I/O wait or disk safety threshold is exceeded.")
    if _worker_imbalance(snapshot.workers, cfg):
        diagnostics.append("WORKER_IMBALANCE")
        explanations.append("Worker load distribution is imbalanced; inspect NGINX and agent distribution.")
    if confidence == "LOW":
        diagnostics.append("INSUFFICIENT_METRICS")
        explanations.append("Critical metrics are missing or inconsistent.")
    if current >= cfg.workers.max:
        diagnostics.append("MAX_WORKERS_REACHED")
        explanations.append("Configured maximum worker count has been reached.")

    worker_pressure = len(signals) >= cfg.analysis.minimum_pressure_signals
    can_recommend = (
        worker_pressure
        and "HOST_PRESSURE" not in diagnostics
        and "WORKER_IMBALANCE" not in diagnostics
        and "INDEXER_PRESSURE" not in diagnostics
        and "CLUSTER_DEGRADED" not in diagnostics
        and "NGINX_DEGRADED" not in diagnostics
        and "INSUFFICIENT_METRICS" not in diagnostics
        and "MAX_WORKERS_REACHED" not in diagnostics
        and projection.can_accept
    )
    estimated = _estimate_target_workers(snapshot.workers, cfg) if worker_pressure else None
    next_workers = min(current + 1, cfg.workers.max, estimated or current) if can_recommend else None
    if worker_pressure and "HOST_PRESSURE" not in diagnostics and "WORKER_IMBALANCE" not in diagnostics:
        diagnostics.append("WORKER_PRESSURE")
        explanations.append(f"Worker pressure signals: {', '.join(signals)}.")
    if not diagnostics:
        diagnostics.append("HEALTHY")
        explanations.append("No scaling pressure detected.")
    if not projection.can_accept and worker_pressure:
        explanations.append(f"Scaling blocked by host safety gate: {projection.reason}.")

    recommendation = _recommendation(diagnostics, current, estimated, next_workers)
    return AnalysisResult(
        diagnostics=tuple(dict.fromkeys(diagnostics)),
        recommendation=recommendation,
        current_workers=current,
        estimated_target_workers=estimated,
        recommended_next_workers=next_workers,
        confidence=confidence,
        explanations=tuple(explanations),
        projection=projection,
        pressure_signals=tuple(signals),
    )


def can_host_accept_worker(host, workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> HostCapacityProjection:
    required = (host.cpu_percent, host.memory_percent, host.disk_free_percent)
    if cfg.safety.require_complete_host_metrics and any(v is None for v in required):
        return HostCapacityProjection(False, None, None, None, None, "HOST_CAPACITY_UNKNOWN")
    if host.cpu_percent is not None and host.cpu_percent >= cfg.host.cpu_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host CPU block threshold reached")
    if host.memory_percent is not None and host.memory_percent >= cfg.host.memory_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host memory block threshold reached")
    if host.iowait_percent is not None and host.iowait_percent >= cfg.host.iowait_block_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host I/O wait block threshold reached")
    if host.disk_free_percent is not None and host.disk_free_percent < cfg.host.disk_free_min_percent:
        return HostCapacityProjection(False, host.cpu_percent, host.memory_percent, None, None, "host disk free threshold reached")
    if not workers or host.cpu_percent is None or host.memory_percent is None:
        return HostCapacityProjection(False, None, None, None, None, "HOST_CAPACITY_UNKNOWN")
    if any(w.cpu_percent is None or w.memory_percent is None for w in workers):
        return HostCapacityProjection(False, None, None, None, None, "HOST_CAPACITY_UNKNOWN")
    estimated_cpu_cost = host.cpu_percent / len(workers)
    estimated_mem_cost = host.memory_percent / len(workers)
    projected_cpu = host.cpu_percent + estimated_cpu_cost * cfg.capacity.new_worker_safety_factor
    projected_mem = host.memory_percent + estimated_mem_cost * cfg.capacity.new_worker_safety_factor
    cpu_reserve = 100 - projected_cpu
    mem_reserve = 100 - projected_mem
    ok = cpu_reserve >= cfg.host.reserve_cpu_percent_after_scale and mem_reserve >= cfg.host.reserve_memory_percent_after_scale
    reason = "host capacity accepted" if ok else "projected reserve after adding worker is insufficient"
    return HostCapacityProjection(ok, projected_cpu, projected_mem, cpu_reserve, mem_reserve, reason)


def _worker_pressure_signals(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> list[str]:
    signals: list[str] = []
    cpus = [w.cpu_percent for w in workers if w.cpu_percent is not None]
    mems = [w.memory_percent for w in workers if w.memory_percent is not None]
    queues = [w.queue_delta for w in workers if w.queue_delta is not None]
    restarts = [w.restart_count for w in workers if w.restart_count is not None]
    if cpus and median(cpus) >= cfg.workers.warning_utilization_percent:
        signals.append("cpu")
    if mems and median(mems) >= cfg.workers.warning_utilization_percent:
        signals.append("memory")
    if queues and sum(1 for q in queues if q > 0) >= max(1, len(queues) // 2):
        signals.append("queue_growth")
    if restarts and max(restarts) >= 3:
        signals.append("restart_loop")
    return signals


def _host_pressure(host, cfg: OrchestratorConfig) -> bool:
    return any(
        (
            host.cpu_percent is not None and host.cpu_percent >= cfg.host.cpu_block_percent,
            host.memory_percent is not None and host.memory_percent >= cfg.host.memory_block_percent,
            host.iowait_percent is not None and host.iowait_percent >= cfg.host.iowait_block_percent,
            host.disk_free_percent is not None and host.disk_free_percent < cfg.host.disk_free_min_percent,
        )
    )


def _worker_imbalance(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> bool:
    cpus = [w.cpu_percent for w in workers if w.cpu_percent is not None]
    if len(cpus) < 2:
        return False
    return max(cpus) - median(cpus) >= cfg.analysis.worker_imbalance_percent


def _indexer_pressure(snapshot: AnalysisInput) -> bool:
    idx = snapshot.indexer
    return any(v is not None and v >= 85 for v in (idx.cpu_percent, idx.memory_percent)) or (idx.disk_free_percent is not None and idx.disk_free_percent < 15)


def _confidence(snapshot: AnalysisInput) -> str:
    if snapshot.cluster.cluster_healthy is None or not snapshot.workers:
        return "LOW"
    critical_missing = snapshot.host.cpu_percent is None or snapshot.host.memory_percent is None
    if critical_missing:
        return "LOW"
    secondary_missing = any(v is None for v in (snapshot.host.iowait_percent, snapshot.host.disk_free_percent))
    worker_missing = any(w.cpu_percent is None or w.memory_percent is None for w in snapshot.workers)
    return "MEDIUM" if secondary_missing or worker_missing else "HIGH"


def _estimate_target_workers(workers: tuple[WorkerMetrics, ...], cfg: OrchestratorConfig) -> int | None:
    cpus = [w.cpu_percent for w in workers if w.cpu_percent is not None]
    if not cpus:
        return None
    return max(len(workers), ceil(len(workers) * median(cpus) / cfg.workers.target_utilization_percent))


def _recommendation(diagnostics: list[str], current: int, estimated: int | None, next_workers: int | None) -> str:
    if next_workers is not None:
        return f"Estimated target: {estimated}. Recommended next step: {current} -> {next_workers}."
    if "HOST_PRESSURE" in diagnostics:
        return "SCALING BLOCKED. Host pressure has priority; do not add workers."
    if "INDEXER_PRESSURE" in diagnostics:
        return "Worker scaling not recommended. Review Wazuh indexer capacity."
    if "WORKER_IMBALANCE" in diagnostics:
        return "Worker scaling not recommended until load balancer and agent distribution are reviewed."
    return "No worker scaling recommended."
