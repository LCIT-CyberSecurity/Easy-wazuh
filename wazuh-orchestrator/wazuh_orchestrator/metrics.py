"""Host and Docker metric collection with mockable boundaries."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol

import psutil

from .models import ContainerMetrics, HostMetrics, MetricsError


class DockerRuntime(Protocol):
    def list_containers(self) -> list[Any]:
        ...


def collect_host_metrics(install_path: Path = Path("/opt/wazuh")) -> HostMetrics:
    """Collect host capacity metrics without inventing unavailable values.

    Linux-only signals such as I/O wait are returned as None when unavailable,
    which the analyzer treats as UNKNOWN rather than zero.
    """
    try:
        vcpu = psutil.cpu_count() or None
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        load_avg = _load_average_normalized(vcpu)
        iowait = _iowait_percent()
        disk = psutil.disk_usage(str(_existing_parent(install_path)))
        return HostMetrics(
            vcpu=vcpu,
            cpu_percent=cpu,
            memory_percent=mem.percent,
            memory_available_bytes=mem.available,
            swap_percent=swap.percent,
            load_average_normalized=load_avg,
            iowait_percent=iowait,
            disk_free_percent=100 - disk.percent,
            filesystem=str(_existing_parent(install_path)),
        )
    except OSError as exc:
        raise MetricsError(f"Unable to collect host metrics: {exc}") from exc


def _existing_parent(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def _load_average_normalized(vcpu: int | None) -> float | None:
    if not hasattr(os, "getloadavg") or not vcpu:
        return None
    return os.getloadavg()[0] / vcpu * 100


def _iowait_percent() -> float | None:
    times = psutil.cpu_times_percent(interval=None)
    return float(times.iowait) if hasattr(times, "iowait") else None


class DockerMetricsCollector:
    """Collect container metrics from an injected Docker client."""

    def __init__(self, docker_runtime: DockerRuntime):
        self._docker = docker_runtime

    def collect(self) -> tuple[ContainerMetrics, ...]:
        """Convert injected Docker container objects into typed metrics."""
        metrics: list[ContainerMetrics] = []
        for container in self._docker.list_containers():
            attrs = getattr(container, "attrs", {}) or {}
            state = attrs.get("State", {})
            metrics.append(
                ContainerMetrics(
                    name=getattr(container, "name", attrs.get("Name", "")).lstrip("/"),
                    running=state.get("Status") == "running",
                    health=(state.get("Health") or {}).get("Status"),
                    cpu_percent=_optional_float(attrs.get("cpu_percent")),
                    memory_percent=_optional_float(attrs.get("memory_percent")),
                    restart_count=attrs.get("RestartCount"),
                    uptime_seconds=attrs.get("uptime_seconds"),
                )
            )
        return tuple(metrics)


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)
