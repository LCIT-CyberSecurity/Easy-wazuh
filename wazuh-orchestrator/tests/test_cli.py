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


def test_cli_debug_overrides_configured_log_level(monkeypatch):
    cli = load_cli()
    levels = []
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "configure_logging", lambda root, level: levels.append(level))
    assert cli.main(["--debug", "status"]) == 0
    assert levels == ["DEBUG"]


class Backend:
    def __init__(self):
        self.commands = []

    def next_worker_name(self, cluster):
        return "wazuh-manager04.local"

    def generate_override(self, cluster, worker):
        self.commands.append(("generate", worker))

    def run_compose(self, *args):
        self.commands.append(args)


def test_cli_scale_cancelled_without_exact_confirmation(monkeypatch, capsys):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert cli.main(["scale", "--workers", "3"]) == 1
    assert backend.commands == []
    assert "Scaling cancelled." in capsys.readouterr().out


def test_cli_scale_requires_no_yes_flag(monkeypatch):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["scale", "--workers", "3", "--" + "yes"]) == 2


def test_cli_scale_runs_after_exact_confirmation(monkeypatch):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setattr("builtins.input", lambda prompt: "SCALE")
    assert cli.main(["scale", "--workers", "3"]) == 0
    assert ("up", "-d", "wazuh-manager04.local") in backend.commands
