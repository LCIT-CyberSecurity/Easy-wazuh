"""Scaling validation and transaction orchestration."""

from __future__ import annotations

import fcntl
from pathlib import Path
from typing import Callable

from .analyzer import analyze, can_host_accept_worker
from .backends.compose import ComposeBackend, NginxConfigManager, timestamped_backup_dir
from .logging_setup import write_audit
from .models import AnalysisInput, AnalysisResult, OrchestratorConfig, SafetyError, ScalingError, ScalingPlan


def build_plan(snapshot: AnalysisInput, cfg: OrchestratorConfig, target_workers: int, backend: ComposeBackend | None = None) -> ScalingPlan:
    """Build a dry-run scaling plan after enforcing V1 safety limits.

    This function does not modify infrastructure. It is intentionally safe to use
    from the CLI `plan` command and from tests without Docker.
    """
    _validate_limits(snapshot, cfg, target_workers)
    current = snapshot.cluster.worker_count
    if target_workers == current:
        return ScalingPlan(current, target_workers, "none", (), no_change_reason="Desired worker count already reached. No change required.")
    result = analyze(snapshot, cfg)
    if target_workers > current:
        _validate_scale_up(snapshot, cfg, result)
        worker = backend.next_worker_name(snapshot.cluster) if backend else f"wazuh-manager{target_workers + 1:02d}.local"
        files = (Path("wazuh-orchestrator/generated/docker-compose.orchestrator.yml"),)
        return ScalingPlan(current, target_workers, "scale_up", files, worker_to_create=worker, nginx_changes=(f"add {worker} to NGINX pool",), safety_checks=("host capacity", "cluster health", "nginx health"), projection=result.projection)
    removable = _select_removable_worker(snapshot, cfg)
    return ScalingPlan(
        current,
        target_workers,
        "scale_down",
        (),
        worker_to_remove=removable,
        nginx_changes=(f"remove {removable} from NGINX pool",),
        risks=("Existing agent connections to this worker may reconnect to another worker.",),
        preconditions=("target worker must be orchestrator-managed",),
    )


def scale(snapshot: AnalysisInput, cfg: OrchestratorConfig, target_workers: int, backend: ComposeBackend, nginx: NginxConfigManager | None, root: Path, *, sleep: Callable[[int], None] | None = None) -> ScalingPlan:
    """Execute an already-confirmed scaling transaction.

    The CLI owns human confirmation. This function owns locking, backups, backend
    calls, rollback attempts and audit records. Tests inject fake backends so no
    Docker daemon is required locally.
    """
    plan = build_plan(snapshot, cfg, target_workers, backend)
    if plan.action == "none":
        return plan
    lock_path = root / "generated" / "scale.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            backup_dir = timestamped_backup_dir(root)
            if plan.action == "scale_up" and plan.worker_to_create:
                backend.generate_override(snapshot.cluster, plan.worker_to_create)
                backend.run_compose("up", "-d", plan.worker_to_create)
                try:
                    if nginx:
                        nginx.apply_worker(plan.worker_to_create, backup_dir)
                except Exception:
                    backend.run_compose("stop", plan.worker_to_create)
                    backend.run_compose("rm", "-f", plan.worker_to_create)
                    raise
            elif plan.action == "scale_down" and plan.worker_to_remove:
                if nginx:
                    nginx.remove_worker(plan.worker_to_remove, backup_dir)
                if sleep:
                    sleep(cfg.scale_down.drain_seconds)
                backend.run_compose("stop", plan.worker_to_remove)
                backend.run_compose("rm", "-f", plan.worker_to_remove)
            write_audit(root, {"action": plan.action, "workers_before": plan.current_workers, "workers_after": plan.target_workers, "result": "success"})
            return plan
        except Exception as exc:
            write_audit(root, {"action": plan.action, "workers_before": plan.current_workers, "workers_after": plan.target_workers, "result": "failed"})
            if isinstance(exc, (SafetyError, ScalingError)):
                raise
            raise ScalingError(str(exc)) from exc


def _validate_limits(snapshot: AnalysisInput, cfg: OrchestratorConfig, target_workers: int) -> None:
    current = snapshot.cluster.worker_count
    if target_workers < cfg.workers.baseline:
        raise SafetyError("target workers is below Easy-Wazuh baseline.")
    if target_workers > cfg.workers.max:
        raise SafetyError("target workers exceeds configured maximum.")
    if abs(target_workers - current) > cfg.scaling.max_delta_per_operation:
        raise SafetyError("V1 permits only one worker change per operation.")
    if cfg.safety.require_multi_node_for_scaling and snapshot.cluster.mode != "multi-node":
        raise SafetyError("Worker horizontal scaling requires a Wazuh multi-node topology. Current deployment: single-node.")


def _validate_scale_up(snapshot: AnalysisInput, cfg: OrchestratorConfig, result: AnalysisResult) -> None:
    if not cfg.scaling.allow_scale_up:
        raise SafetyError("scale-up is disabled by configuration.")
    if result.confidence == "LOW":
        raise SafetyError("LOW confidence analysis blocks scaling.")
    if cfg.safety.require_cluster_healthy and snapshot.cluster.cluster_healthy is not True:
        raise SafetyError("CLUSTER_DEGRADED. Scaling blocked.")
    if cfg.safety.require_nginx_healthy and snapshot.cluster.nginx and snapshot.cluster.nginx_healthy is not True:
        raise SafetyError("NGINX_DEGRADED. Scaling blocked.")
    projection = can_host_accept_worker(snapshot.host, snapshot.workers, cfg)
    if not projection.can_accept:
        raise SafetyError(f"SCALING BLOCKED: {projection.reason}")
    if result.recommended_next_workers != snapshot.cluster.worker_count + 1:
        raise SafetyError("Scale-up is blocked because analysis does not recommend adding a worker.")


def _select_removable_worker(snapshot: AnalysisInput, cfg: OrchestratorConfig) -> str:
    if not cfg.scaling.allow_scale_down:
        raise SafetyError("scale-down is disabled by configuration.")
    for worker in reversed(snapshot.workers):
        if worker.managed_by_orchestrator and not worker.baseline_worker:
            return worker.name
    raise SafetyError("No orchestrator-managed non-baseline worker can be removed.")
