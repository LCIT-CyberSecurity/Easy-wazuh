"""Scaling validation and transaction orchestration."""

from __future__ import annotations

import fcntl
from pathlib import Path
from typing import Callable, Protocol

from .analyzer import analyze, can_host_accept_worker
from .backends.compose import ComposeBackend, NginxConfigManager, timestamped_backup_dir
from .certificates import CertificatePreparer, IntegrationRequiredCertificatePreparer
from .logging_setup import write_audit
from .models import AnalysisInput, AnalysisResult, OrchestratorConfig, SafetyError, ScalingError, ScalingPlan
from .transactions import TransactionStore


class ClusterValidator(Protocol):
    def verify_cluster_join(self, worker_name: str) -> None:
        ...

    def final_validate_cluster(self) -> None:
        ...


class IntegrationRequiredClusterValidator:
    def verify_cluster_join(self, worker_name: str) -> None:
        raise ScalingError("INTEGRATION_VALIDATION_REQUIRED: Wazuh API cluster join validation is required before scale-up execution.")

    def final_validate_cluster(self) -> None:
        raise ScalingError("INTEGRATION_VALIDATION_REQUIRED: Wazuh API final cluster validation is required before completing scaling.")


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
        worker = backend.next_worker_name(snapshot.cluster) if backend else f"wazuh-manager{current + 1:02d}.local"
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


def scale(
    snapshot: AnalysisInput,
    cfg: OrchestratorConfig,
    target_workers: int,
    backend: ComposeBackend,
    nginx: NginxConfigManager | None,
    root: Path,
    *,
    sleep: Callable[[int], None] | None = None,
    certificate_preparer: CertificatePreparer | None = None,
    cluster_validator: ClusterValidator | None = None,
) -> ScalingPlan:
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
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ScalingError("SCALING_LOCKED. Another scaling operation is already running.") from exc
        try:
            store = TransactionStore(root)
            if store.incomplete():
                raise ScalingError("INCOMPLETE_TRANSACTION. Scaling blocked until reconciliation is complete.")
            worker = plan.worker_to_create or plan.worker_to_remove
            manifest = store.create(plan.action, worker)
            backup_dir = timestamped_backup_dir(root)
            desired_state_backup = backend.backup_desired_state(backup_dir) if hasattr(backend, "backup_desired_state") else None
            if plan.action == "scale_up" and plan.worker_to_create:
                certs = certificate_preparer or IntegrationRequiredCertificatePreparer()
                cluster_checks = cluster_validator or IntegrationRequiredClusterValidator()
                certificate_transaction_id: str | None = None
                try:
                    certificate_result = certs.prepare_worker(plan.worker_to_create, manifest.transaction_id)
                    certificate_transaction_id = str(certificate_result.get("transaction_id") or manifest.transaction_id)
                    manifest = store.advance(manifest, "CERTIFICATE_READY", certificate_ready=True)
                    backend.generate_override(snapshot.cluster, plan.worker_to_create)
                    backend.validate_effective_config()
                    manifest = store.advance(manifest, "COMPOSE_READY", compose_updated=True)
                    backend.start_worker(plan.worker_to_create)
                    manifest = store.advance(manifest, "WORKER_STARTED", container_started=True)
                    backend.wait_for_worker_health(plan.worker_to_create)
                    manifest = store.advance(manifest, "WORKER_HEALTHY", worker_healthy=True)
                    cluster_checks.verify_cluster_join(plan.worker_to_create)
                    manifest = store.advance(manifest, "CLUSTER_JOINED", cluster_joined=True)
                    if nginx:
                        nginx.apply_worker(plan.worker_to_create, backup_dir)
                        manifest = store.advance(manifest, "NGINX_UPDATED", nginx_updated=True)
                    cluster_checks.final_validate_cluster()
                    manifest = store.advance(manifest, "VALIDATED", validated=True)
                except Exception as exc:
                    manifest = store.advance(manifest, "ROLLBACK")
                    if manifest.flags.get("nginx_updated") and nginx:
                        try:
                            if hasattr(nginx, "restore_backup"):
                                nginx.restore_backup(backup_dir)
                            else:
                                nginx.remove_worker(plan.worker_to_create, backup_dir)
                        except Exception as nginx_cleanup_exc:
                            raise ScalingError(f"{exc}; NGINX rollback failed: {nginx_cleanup_exc}") from exc
                    if manifest.flags.get("container_started"):
                        backend.run_compose("stop", plan.worker_to_create)
                        backend.run_compose("rm", "-f", plan.worker_to_create)
                    if hasattr(backend, "restore_desired_state"):
                        backend.restore_desired_state(desired_state_backup)
                    if hasattr(backend, "cleanup_worker_config"):
                        backend.cleanup_worker_config(plan.worker_to_create)
                    if certificate_transaction_id:
                        try:
                            certs.cleanup_worker(certificate_transaction_id)
                        except Exception as cleanup_exc:
                            raise ScalingError(f"{exc}; certificate cleanup failed: {cleanup_exc}") from exc
                    raise
            elif plan.action == "scale_down" and plan.worker_to_remove:
                cluster_checks = cluster_validator or IntegrationRequiredClusterValidator()
                if nginx:
                    nginx.remove_worker(plan.worker_to_remove, backup_dir)
                    manifest = store.advance(manifest, "NGINX_UPDATED", nginx_updated=True)
                if sleep:
                    sleep(cfg.scale_down.drain_seconds)
                backend.run_compose("stop", plan.worker_to_remove)
                backend.run_compose("rm", "-f", plan.worker_to_remove)
                if hasattr(backend, "remove_from_override"):
                    backend.remove_from_override(plan.worker_to_remove)
                if hasattr(backend, "cleanup_worker_config"):
                    backend.cleanup_worker_config(plan.worker_to_remove)
                backend.validate_effective_config()
                manifest = store.advance(manifest, "COMPOSE_READY", compose_updated=True)
                cluster_checks.final_validate_cluster()
                manifest = store.advance(manifest, "VALIDATED", validated=True)
            store.advance(manifest, "SUCCESS")
            write_audit(root, {"action": plan.action, "workers_before": plan.current_workers, "workers_after": plan.target_workers, "result": "success"})
            return plan
        except Exception as exc:
            try:
                if "manifest" in locals():
                    TransactionStore(root).advance(manifest, "FAILED")
            finally:
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
        raise SafetyError("UNSUPPORTED_DEPLOYMENT_MODE. Worker horizontal scaling requires an Easy-Wazuh multi-node topology.")
    if snapshot.cluster.details.get("unsupported_layout"):
        raise SafetyError("UNSUPPORTED_WAZUH_LAYOUT. Scaling blocked.")
    if snapshot.cluster.details.get("incomplete_transaction"):
        raise SafetyError("INCOMPLETE_TRANSACTION. Scaling blocked until reconciliation is complete.")


def _validate_scale_up(snapshot: AnalysisInput, cfg: OrchestratorConfig, result: AnalysisResult) -> None:
    if not cfg.scaling.allow_scale_up:
        raise SafetyError("scale-up is disabled by configuration.")
    if result.confidence == "LOW":
        raise SafetyError("LOW confidence analysis blocks scaling.")
    blocked = {"UNSUPPORTED_DEPLOYMENT_MODE", "UNSUPPORTED_WAZUH_LAYOUT", "POST_SCALE_STABILIZING", "INCOMPLETE_TRANSACTION", "DASHBOARD_PRESSURE"}
    hit = blocked.intersection(result.diagnostics)
    if hit:
        raise SafetyError(f"{sorted(hit)[0]}. Scaling blocked.")
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
