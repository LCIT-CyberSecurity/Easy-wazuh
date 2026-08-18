from __future__ import annotations

import importlib.util
from pathlib import Path

from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, WorkerMetrics


CLI_PATH = Path(__file__).resolve().parents[1] / "wazuh-orchestrator.py"


def load_cli():
    spec = importlib.util.spec_from_file_location("wazuh_orchestrator_cli", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def snapshot():
    cluster = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", Path("base.yml"), Path("."), "default", cluster_healthy=True, nginx_healthy=True)
    workers = (WorkerMetrics("w1", 80, 20, 1, 1), WorkerMetrics("w2", 78, 20, 1, 1))
    return AnalysisInput(cluster, HostMetrics(4, 35, 35, 1024, 0, 10, 1, 80, "/"), workers, IndexerState(("i",), True, 20, 20, 80))


def test_cli_status(monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["status"]) == 0
    assert "Workers          2" in capsys.readouterr().out


def test_cli_analyze_json(monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["analyze", "--json"]) == 0
    assert "WORKER_PRESSURE" in capsys.readouterr().out


def test_cli_plan(monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["plan", "--workers", "3"]) == 0
    assert "Action:          scale_up" in capsys.readouterr().out
