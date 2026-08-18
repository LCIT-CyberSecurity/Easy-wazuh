"""Easy-Wazuh topology discovery without requiring Docker during tests."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Protocol

import yaml

from .models import ClusterState, DiscoveryError


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


def discover_installation(root: Path = Path("/opt/wazuh/wazuh-docker"), docker_client: DockerDiscoveryClient | None = None) -> ClusterState:
    """Discover Easy-Wazuh topology from files and an optional Docker adapter.

    Local development can pass a fake Docker client. When no files and no Docker
    runtime are present, the caller receives an explicit unknown state instead
    of a traceback.
    """
    docker_client = docker_client or LocalDockerDiscovery()
    file_state = discover_from_files(root)
    docker_available = docker_client.available()
    compose_available = docker_client.compose_available()
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
            docker_available=False,
            compose_available=compose_available,
        )
    return ClusterState(
        **{**file_state.__dict__, "docker_available": docker_available, "compose_available": compose_available}
    )


def discover_from_files(root: Path) -> ClusterState:
    """Discover the generated Easy-Wazuh compose stack under /opt/wazuh.

    Multi-node is preferred when both layouts exist because only multi-node
    supports horizontal worker scaling in V1.
    """
    single = root / "single-node" / "docker-compose.yml"
    multi = root / "multi-node" / "docker-compose.yml"
    if multi.exists():
        return _discover_compose(multi, "multi-node")
    if single.exists():
        return _discover_compose(single, "single-node")
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
    )


def discover_from_compose(compose_file: Path) -> ClusterState:
    """Parse one Compose file into a ClusterState for tests and offline checks."""
    data = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    services = data.get("services", {})
    mode = "multi-node" if isinstance(services, dict) and ("nginx" in services or any("manager02" in name for name in services)) else "single-node"
    return _discover_compose_data(compose_file, mode, data)


def _discover_compose(compose_file: Path, mode: str) -> ClusterState:
    data = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    return _discover_compose_data(compose_file, mode, data)


def _discover_compose_data(compose_file: Path, mode: str, data: dict[str, object]) -> ClusterState:
    services = data.get("services", {})
    if not isinstance(services, dict):
        raise DiscoveryError("Compose services must be a mapping.")
    names = tuple(services)
    indexers = tuple(n for n in names if "indexer" in n)
    managers = tuple(n for n in names if "manager" in n or n in ("wazuh.master", "wazuh.worker"))
    dashboard = next((n for n in names if "dashboard" in n), None)
    nginx = next((n for n in names if n == "nginx" or "nginx" in n), None)
    masters = _master_names(managers)
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
    config_drift = mode == "multi-node" and nginx is None
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
        cluster_healthy=None,
        nginx_healthy=None if nginx else False,
        config_drift=config_drift,
    )


def _master_names(managers: tuple[str, ...]) -> tuple[str, ...]:
    explicit = tuple(n for n in managers if n.endswith("manager01") or "manager01." in n or n.endswith("master") or ".master" in n)
    return explicit
