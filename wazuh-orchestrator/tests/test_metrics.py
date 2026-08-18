from __future__ import annotations

from collections import namedtuple

from wazuh_orchestrator.metrics import DockerMetricsCollector, _iowait_percent
from wazuh_orchestrator.models import HostMetrics


def host(cpu=20, mem=30, iowait=1, disk=80):
    return HostMetrics(4, cpu, mem, 1024, 0, 20, iowait, disk, "/")


def test_host_saine():
    h = host()
    assert h.cpu_percent < 70 and h.disk_free_percent > 15


def test_cpu_eleve():
    assert host(cpu=90).cpu_percent == 90


def test_ram_eleve():
    assert host(mem=90).memory_percent == 90


def test_iowait_eleve():
    assert host(iowait=20).iowait_percent == 20


def test_disk_faible():
    assert host(disk=5).disk_free_percent == 5


def test_metrique_absente_unknown():
    assert host(cpu=None).cpu_percent is None


def test_docker_metrics_from_mock():
    C = namedtuple("C", "name attrs")
    runtime = type("R", (), {"list_containers": lambda self: [C("wazuh", {"State": {"Status": "running", "Health": {"Status": "healthy"}}, "RestartCount": 1})]})()
    metrics = DockerMetricsCollector(runtime).collect()
    assert metrics[0].running is True
    assert metrics[0].health == "healthy"
