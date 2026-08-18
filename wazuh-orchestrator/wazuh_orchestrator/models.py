"""Typed domain models for the Easy-Wazuh orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

UNKNOWN: None = None

Confidence = Literal["HIGH", "MEDIUM", "LOW"]
TopologyMode = Literal["unknown", "single-node", "multi-node"]


class ConfigurationError(Exception):
    """Invalid orchestrator configuration."""


class DiscoveryError(Exception):
    """Easy-Wazuh environment discovery failed."""


class MetricsError(Exception):
    """Metric collection failed."""


class WazuhAPIError(Exception):
    """Wazuh API access failed."""


class SafetyError(Exception):
    """A safety gate blocked a scaling operation."""


class ScalingError(Exception):
    """A scaling transaction failed."""


@dataclass(frozen=True)
class WorkerSettings:
    baseline: int = 1
    max: int = 6
    target_utilization_percent: float = 55
    warning_utilization_percent: float = 70
    critical_utilization_percent: float = 85


@dataclass(frozen=True)
class AnalysisSettings:
    sample_interval_seconds: int = 10
    sample_count: int = 6
    require_multiple_signals: bool = True
    minimum_pressure_signals: int = 2
    worker_imbalance_percent: float = 35


@dataclass(frozen=True)
class ScalingSettings:
    max_delta_per_operation: int = 1
    allow_scale_up: bool = True
    allow_scale_down: bool = True


@dataclass(frozen=True)
class CapacitySettings:
    new_worker_safety_factor: float = 1.30


@dataclass(frozen=True)
class HostSettings:
    cpu_warning_percent: float = 70
    cpu_block_percent: float = 85
    memory_warning_percent: float = 75
    memory_block_percent: float = 85
    iowait_block_percent: float = 15
    disk_free_min_percent: float = 15
    reserve_cpu_percent_after_scale: float = 25
    reserve_memory_percent_after_scale: float = 25


@dataclass(frozen=True)
class SafetySettings:
    require_multi_node_for_scaling: bool = True
    require_cluster_healthy: bool = True
    require_nginx_healthy: bool = True
    require_complete_host_metrics: bool = True
    backup_before_change: bool = True


@dataclass(frozen=True)
class ScaleDownSettings:
    drain_seconds: int = 60


@dataclass(frozen=True)
class RuntimeSettings:
    easy_wazuh_root: Path = Path("/opt/wazuh/wazuh-docker")
    orchestrator_root: Path = Path("wazuh-orchestrator")
    compose_timeout_seconds: int = 120
    wazuh_api_url: str | None = None
    wazuh_api_username: str | None = None
    wazuh_api_password: str | None = None
    wazuh_api_verify_tls: bool = True
    wazuh_api_timeout_seconds: int = 10


@dataclass(frozen=True)
class OrchestratorConfig:
    workers: WorkerSettings = field(default_factory=WorkerSettings)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)
    scaling: ScalingSettings = field(default_factory=ScalingSettings)
    capacity: CapacitySettings = field(default_factory=CapacitySettings)
    host: HostSettings = field(default_factory=HostSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    scale_down: ScaleDownSettings = field(default_factory=ScaleDownSettings)
    runtime: RuntimeSettings = field(default_factory=RuntimeSettings)


@dataclass(frozen=True)
class HostMetrics:
    vcpu: int | None
    cpu_percent: float | None
    memory_percent: float | None
    memory_available_bytes: int | None
    swap_percent: float | None
    load_average_normalized: float | None
    iowait_percent: float | None
    disk_free_percent: float | None
    filesystem: str | None


@dataclass(frozen=True)
class ContainerMetrics:
    name: str
    running: bool
    health: str | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    restart_count: int | None = None
    uptime_seconds: int | None = None


@dataclass(frozen=True)
class WorkerMetrics:
    name: str
    cpu_percent: float | None
    memory_percent: float | None = None
    queue_size: int | None = None
    queue_delta: int | None = None
    eps: float | None = None
    agent_count: int | None = None
    restart_count: int | None = None
    managed_by_orchestrator: bool = False
    baseline_worker: bool = False


@dataclass(frozen=True)
class IndexerState:
    names: tuple[str, ...] = ()
    healthy: bool | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_free_percent: float | None = None


@dataclass(frozen=True)
class ClusterState:
    mode: TopologyMode
    master: str | None
    workers: tuple[str, ...]
    indexers: tuple[str, ...]
    dashboard: str | None
    nginx: str | None
    compose_file: Path | None
    compose_project_directory: Path | None
    compose_network: str | None
    version: str | None = None
    cluster_healthy: bool | None = None
    nginx_healthy: bool | None = None
    config_drift: bool = False
    docker_available: bool = False
    compose_available: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def worker_count(self) -> int:
        return len(self.workers)


@dataclass(frozen=True)
class AnalysisInput:
    cluster: ClusterState
    host: HostMetrics
    workers: tuple[WorkerMetrics, ...]
    indexer: IndexerState = field(default_factory=IndexerState)


@dataclass(frozen=True)
class HostCapacityProjection:
    can_accept: bool
    projected_cpu_percent: float | None
    projected_memory_percent: float | None
    cpu_reserve_percent: float | None
    memory_reserve_percent: float | None
    reason: str


@dataclass(frozen=True)
class AnalysisResult:
    diagnostics: tuple[str, ...]
    recommendation: str
    current_workers: int
    estimated_target_workers: int | None
    recommended_next_workers: int | None
    confidence: Confidence
    explanations: tuple[str, ...]
    projection: HostCapacityProjection | None = None
    pressure_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScalingPlan:
    current_workers: int
    target_workers: int
    action: Literal["none", "scale_up", "scale_down"]
    files_to_generate: tuple[Path, ...]
    worker_to_create: str | None = None
    worker_to_remove: str | None = None
    nginx_changes: tuple[str, ...] = ()
    safety_checks: tuple[str, ...] = ()
    risks: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    projection: HostCapacityProjection | None = None
    no_change_reason: str | None = None
