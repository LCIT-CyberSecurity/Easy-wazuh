"""Easy-Wazuh topology and deployment metadata discovery."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Protocol

import yaml

from .models import ClusterState, DeploymentMetadata, DiscoveryError, NamingError, NamingPolicy
from .naming import infer_legacy_policy, parse_node_name

DEFAULT_METADATA_PATH = Path("/opt/wazuh/easy-wazuh/deployment.yaml")


class DockerDiscoveryClient(Protocol):
    def available(self) -> bool:
        ...

    def compose_available(self) -> bool:
        ...

    def inspect(self) -> dict[str, Any]:
        ...


class LocalDockerDiscovery:
    def available(self) -> bool:
        return shutil.which("docker") is not None

    def compose_available(self) -> bool:
        return self.available()

    def inspect(self) -> dict[str, Any]:
        raise DiscoveryError("Docker runtime not detected.\nNo running Easy-Wazuh installation can be inspected on this host.")


def load_deployment_metadata(path: Path) -> DeploymentMetadata | None:
    """Load and strictly validate persisted Easy-Wazuh deployment identity."""
    if not path.exists():
        return None
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise DiscoveryError(f"Malformed deployment metadata: {path}") from exc
    if not isinstance(raw, dict):
        raise DiscoveryError("Deployment metadata root must be a mapping.")
    if raw.get("schema_version") != 1:
        raise DiscoveryError("Unsupported deployment metadata schema_version.")
    deployment = _mapping(raw, "deployment")
    managers = _mapping(raw, "managers")
    baseline = _mapping(raw, "baseline")
    indexers = _mapping(raw, "indexers")
    dashboard = _mapping(raw, "dashboard")
    naming = NamingPolicy(
        manager_prefix=_required_str(managers, "prefix"),
        manager_number_width=_required_int(managers, "number_width"),
        manager_internal_dns_suffix=managers.get("internal_dns_suffix"),
        manager_master_index=_required_int(managers, "master_index"),
        indexer_prefix=_required_str(indexers, "prefix"),
        indexer_number_width=_required_int(indexers, "number_width"),
    )
    metadata = DeploymentMetadata(
        schema_version=1,
        mode=_required_str(deployment, "mode"),
        stack_directory=Path(_required_str(deployment, "stack_directory")),
        compose_file=_required_str(deployment, "compose_file"),
        compose_project_name=deployment.get("compose_project_name"),
        naming=naming,
        baseline_workers=_required_int(baseline, "workers"),
        dashboard_count=_required_int(dashboard, "count"),
        dashboard_scalable=bool(dashboard.get("scalable", False)),
    )
    validate_deployment_metadata(metadata)
    return metadata


def validate_deployment_metadata(metadata: DeploymentMetadata) -> None:
    """Validate immutable deployment identity values before using them."""
    if metadata.mode not in {"single-node", "multi-node"}:
        raise DiscoveryError("Unsupported deployment metadata mode.")
    if metadata.baseline_workers < 0:
        raise DiscoveryError("Deployment metadata baseline workers must be >= 0.")
    if metadata.dashboard_count != 1 or metadata.dashboard_scalable:
        raise DiscoveryError("V1 supports exactly one non-scalable Dashboard.")
    if metadata.naming.manager_number_width < 1 or metadata.naming.indexer_number_width < 1:
        raise DiscoveryError("Invalid deployment metadata number width.")
    if metadata.naming.manager_master_index < 1:
        raise DiscoveryError("Invalid deployment metadata master index.")


def discover_installation(
    root: Path = Path("/opt/wazuh/wazuh-docker"),
    docker_client: DockerDiscoveryClient | None = None,
    metadata_path: Path | None = None,
) -> ClusterState:
    """Discover Easy-Wazuh from metadata, files and optional Docker adapters."""
    docker_client = docker_client or LocalDockerDiscovery()
    metadata = load_deployment_metadata(metadata_path or DEFAULT_METADATA_PATH)
    file_state = discover_from_files(root, metadata)
    docker_available = docker_client.available()
    compose_available = docker_client.compose_available()
    if file_state.mode == "unknown" and metadata is not None:
        candidate = metadata.stack_directory / metadata.compose_file
        if candidate.exists():
            file_state = discover_from_compose(candidate, metadata)
    if file_state.mode == "unknown" and not docker_available:
        return ClusterState(
            mode="unknown",
            master=None,
            workers=(),
            indexers=(),
            dashboard=None,
            nginx=None,
            compose_file=None,
            compose_project_directory=None,
            compose_network=None,
            deployment_metadata=metadata,
            naming_policy=metadata.naming if metadata else None,
            docker_available=False,
            compose_available=compose_available,
        )
    return ClusterState(**{**file_state.__dict__, "docker_available": docker_available, "compose_available": compose_available})


def discover_from_files(root: Path, metadata: DeploymentMetadata | None = None) -> ClusterState:
    """Discover generated Easy-Wazuh compose stacks under the install root."""
    single = root / "single-node" / "docker-compose.yml"
    multi = root / "multi-node" / "docker-compose.yml"
    if metadata is not None:
        candidate = metadata.stack_directory / metadata.compose_file
        if candidate.exists():
            return discover_from_compose(candidate, metadata)
    if multi.exists():
        return _discover_compose(multi, "multi-node", metadata)
    if single.exists():
        return _discover_compose(single, "single-node", metadata)
    return ClusterState(
        mode="unknown",
        master=None,
        workers=(),
        indexers=(),
        dashboard=None,
        nginx=None,
        compose_file=None,
        compose_project_directory=None,
        compose_network=None,
        deployment_metadata=metadata,
        naming_policy=metadata.naming if metadata else None,
    )


def discover_from_compose(compose_file: Path, metadata: DeploymentMetadata | None = None) -> ClusterState:
    """Parse one Compose file into a ClusterState for tests and offline checks."""
    data = _load_compose(compose_file)
    services = data.get("services", {})
    mode = metadata.mode if metadata else ("multi-node" if isinstance(services, dict) and ("nginx" in services or any("manager02" in name for name in services)) else "single-node")
    return _discover_compose_data(compose_file, mode, data, metadata)


def _discover_compose(compose_file: Path, mode: str, metadata: DeploymentMetadata | None) -> ClusterState:
    data = _load_compose(compose_file)
    return _discover_compose_data(compose_file, mode, data, metadata)


def _load_compose(compose_file: Path) -> dict[str, object]:
    try:
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise DiscoveryError(f"Malformed Compose file: {compose_file}") from exc
    if not isinstance(data, dict):
        raise DiscoveryError("Compose root must be a mapping.")
    return data


def _discover_compose_data(compose_file: Path, mode: str, data: dict[str, object], metadata: DeploymentMetadata | None) -> ClusterState:
    services = data.get("services", {})
    if not isinstance(services, dict):
        raise DiscoveryError("Compose services must be a mapping.")
    names = tuple(services)
    indexers = tuple(n for n in names if "indexer" in n)
    managers = tuple(n for n in names if "manager" in n or n in ("wazuh.master", "wazuh.worker"))
    dashboard = next((n for n in names if "dashboard" in n), None)
    nginx = next((n for n in names if n == "nginx" or "nginx" in n), None)
    masters = _master_names(managers, metadata.naming if metadata else None)
    if len(masters) > 1:
        raise DiscoveryError("Multiple Wazuh master services detected.")
    if mode == "single-node":
        master = managers[0] if managers else None
        workers = ()
    else:
        master = masters[0] if masters else None
        workers = tuple(n for n in managers if n not in masters)
    if mode == "multi-node" and master is None:
        raise DiscoveryError("No Wazuh master service detected.")
    policy = metadata.naming if metadata else _legacy_policy_or_none(master, workers, indexers)
    config_drift = _config_drift(mode, nginx, dashboard, metadata, compose_file, master, workers, indexers)
    network = next(iter((data.get("networks") or {"default": {}}).keys()), "default")
    return ClusterState(
        mode=mode,  # type: ignore[arg-type]
        master=master,
        workers=workers,
        indexers=indexers,
        dashboard=dashboard,
        nginx=nginx,
        compose_file=compose_file,
        compose_project_directory=compose_file.parent,
        compose_network=network,
        deployment_metadata=metadata,
        naming_policy=policy,
        cluster_healthy=None,
        nginx_healthy=None if nginx else False,
        config_drift=config_drift,
        details={"legacy_policy_discovered": metadata is None and policy is not None},
    )


def _master_names(managers: tuple[str, ...], policy: NamingPolicy | None = None) -> tuple[str, ...]:
    if policy is not None:
        expected_host = f"{policy.manager_prefix}{policy.manager_master_index:0{policy.manager_number_width}d}"
        expected = f"{expected_host}.{policy.manager_internal_dns_suffix}" if policy.manager_internal_dns_suffix else expected_host
        return tuple(n for n in managers if n == expected)
    return tuple(n for n in managers if n.endswith("manager01") or "manager01." in n or n.endswith("master") or ".master" in n)


def _config_drift(mode: str, nginx: str | None, dashboard: str | None, metadata: DeploymentMetadata | None, compose_file: Path, master: str | None, workers: tuple[str, ...], indexers: tuple[str, ...]) -> bool:
    if mode == "multi-node" and nginx is None:
        return True
    if metadata is None:
        return False
    if metadata.mode != mode:
        return True
    if metadata.stack_directory.resolve() != compose_file.parent.resolve():
        return True
    if metadata.dashboard_count != (1 if dashboard else 0):
        return True
    if len(workers) < metadata.baseline_workers:
        return True
    try:
        expected_master_index = parse_node_name(master or "").index
    except NamingError:
        return True
    return expected_master_index != metadata.naming.manager_master_index


def _legacy_policy_or_none(master: str | None, workers: tuple[str, ...], indexers: tuple[str, ...]) -> NamingPolicy | None:
    try:
        return infer_legacy_policy(master, workers, indexers)
    except NamingError:
        return None


def _mapping(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise DiscoveryError(f"Deployment metadata section {key} must be a mapping.")
    return value


def _required_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise DiscoveryError(f"Deployment metadata key {key} must be a non-empty string.")
    return value


def _required_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise DiscoveryError(f"Deployment metadata key {key} must be an integer.")
    return value
