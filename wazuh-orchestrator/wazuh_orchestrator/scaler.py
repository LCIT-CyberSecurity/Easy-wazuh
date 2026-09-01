"""Scaling validation and transaction orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Protocol

from .analyzer import analyze
from .backends.compose import ComposeBackend, NginxConfigManager
from .certificates import CertificatePreparer
from .models import AnalysisInput, OrchestratorConfig, SafetyError, ScalingError, ScalingPlan


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
        worker = backend.next_worker_name(snapshot.cluster) if backend else f"wazuh-manager{current + 1:02d}.local"
        files = (Path("wazuh-orchestrator/generated/docker-compose.orchestrator.yml"),)
        risks = tuple(result.explanations) if result.status != "SCALE_RECOMMENDED" else ()
        return ScalingPlan(current, target_workers, "scale_up", files, worker_to_create=worker, nginx_changes=(f"add {worker} to NGINX pool",), safety_checks=("read-only analysis", "cluster health", "nginx health", "host capacity review"), risks=risks, projection=result.projection)
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
    """Scaling execution is intentionally disabled in V1."""
    raise ScalingError("Scaling execution is disabled in Wazuh Orchestrator V1. Use analyze/plan as read-only diagnostics only.")


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


def _select_removable_worker(snapshot: AnalysisInput, cfg: OrchestratorConfig) -> str:
    if not cfg.scaling.allow_scale_down:
        raise SafetyError("scale-down is disabled by configuration.")
    for worker in reversed(snapshot.workers):
        if worker.managed_by_orchestrator and not worker.baseline_worker:
            return worker.name
    raise SafetyError("No orchestrator-managed non-baseline worker can be removed.")
