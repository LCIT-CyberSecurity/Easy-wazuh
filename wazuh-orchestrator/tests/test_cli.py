from __future__ import annotations

import importlib.util
from pathlib import Path

from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, NginxState, WorkerMetrics


CLI_PATH = Path(__file__).resolve().parents[1] / "wazuh-orchestrator.py"


def load_cli(*, isolate_transactions=True):
    spec = importlib.util.spec_from_file_location("wazuh_orchestrator_cli", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    if isolate_transactions:
        module._with_transaction_details = lambda snapshot, root, cfg: snapshot
    return module


def snapshot():
    cluster = ClusterState("multi-node", "wazuh-manager01.local", ("wazuh-manager02.local", "wazuh-manager03.local"), ("i",), "d", "nginx", Path("base.yml"), Path("."), "default", cluster_healthy=True, nginx_healthy=True)
    workers = (WorkerMetrics("w1", 80, 20, 1, 1), WorkerMetrics("w2", 78, 20, 1, 1))
    return AnalysisInput(cluster, HostMetrics(4, 35, 35, 1024, 0, 10, 1, 80, "/"), workers, IndexerState(("i",), True, 20, 20, 80))


def test_cli_status(monkeypatch, capsys):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "Workers          2" in out
    assert "Stack directory" in out
    assert "Compose file" in out
    assert "Compose project" in out


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


def test_transaction_details_expose_incomplete_transaction(tmp_path):
    cli = load_cli(isolate_transactions=False)
    cfg = cli.load_config()
    cli.TransactionStore(tmp_path).create("scale_up", "wazuh-manager04.local")

    enriched = cli._with_transaction_details(snapshot(), tmp_path, cfg)
    result = cli.analyze(enriched, cfg)

    assert enriched.cluster.details["incomplete_transaction"] is True
    assert "INCOMPLETE_TRANSACTION" in result.diagnostics


def test_transaction_details_expose_recent_scale_stabilization(tmp_path):
    cli = load_cli(isolate_transactions=False)
    cfg = cli.load_config()
    store = cli.TransactionStore(tmp_path)
    manifest = store.create("scale_up", "wazuh-manager04.local")
    store.advance(manifest, "SUCCESS")

    enriched = cli._with_transaction_details(snapshot(), tmp_path, cfg)
    result = cli.analyze(enriched, cfg)

    assert enriched.cluster.details["post_scale_stabilizing"] is True
    assert "POST_SCALE_STABILIZING" in result.diagnostics


def test_runtime_root_uses_configured_absolute_path(tmp_path):
    cli = load_cli()
    cfg = cli.load_config()
    cfg = cfg.__class__(**{
        **cfg.__dict__,
        "runtime": cfg.runtime.__class__(**{**cfg.runtime.__dict__, "orchestrator_root": tmp_path}),
    })

    assert cli._runtime_root(cfg) == tmp_path


def test_runtime_root_default_is_script_directory():
    cli = load_cli()
    assert cli._runtime_root(cli.load_config()) == CLI_PATH.parent


class Backend:
    def __init__(self):
        self.commands = []

    def next_worker_name(self, cluster):
        return "wazuh-manager04.local"

    def generate_override(self, cluster, worker):
        self.commands.append(("generate", worker))

    def run_compose(self, *args):
        self.commands.append(args)

    def validate_effective_config(self):
        self.run_compose("config")

    def start_worker(self, worker):
        self.run_compose("up", "-d", worker)

    def wait_for_worker_health(self, worker):
        self.commands.append(("health", worker))

    def validate_nginx_config(self, service="nginx"):
        self.commands.append(("nginx-test", service))
        return True

    def reload_nginx(self, service="nginx"):
        self.commands.append(("nginx-reload", service))
        return True


def test_cli_scale_is_monitoring_only(monkeypatch, capsys):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)

    assert cli.main(["scale", "--workers", "3"]) == 2

    captured = capsys.readouterr()
    assert "Action:          scale_up" in captured.out
    assert "Scaling execution is disabled in Wazuh Orchestrator V1" in captured.err
    assert backend.commands == []


def test_cli_scale_does_not_prompt_for_confirmation(monkeypatch):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)

    def fail_input(prompt):
        raise AssertionError("scale must not prompt in beta monitoring mode")

    monkeypatch.setattr("builtins.input", fail_input)

    assert cli.main(["scale", "--workers", "3"]) == 2
    assert backend.commands == []


def test_cli_scale_does_not_call_live_scaling_dependencies(monkeypatch):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)

    assert not hasattr(cli, "scale")
    assert not hasattr(cli, "_nginx_manager")
    assert not hasattr(cli, "_certificate_preparer")
    assert cli.main(["scale", "--workers", "3"]) == 2
    assert backend.commands == []


def test_cli_scale_requires_no_yes_flag(monkeypatch):
    cli = load_cli()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    assert cli.main(["scale", "--workers", "3", "--" + "yes"]) == 2


def test_cli_analyze_duration_collects_multiple_snapshots(monkeypatch, capsys):
    cli = load_cli()
    calls = []
    samples = [snapshot(), snapshot(), snapshot()]

    def fake_snapshot(cfg, previous=None, elapsed_seconds=None):
        calls.append((previous, elapsed_seconds))
        return samples[min(len(calls) - 1, len(samples) - 1)]

    monkeypatch.setattr(cli, "_snapshot", fake_snapshot)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(cli.time, "monotonic", iter([0, 10, 10, 20]).__next__)

    assert cli.main(["analyze", "--duration", "30", "--json"]) == 0

    assert len(calls) == 3
    assert calls[0] == (None, None)
    assert calls[1][0] is samples[0]
    assert calls[1][1] == 10
    assert calls[2][0] is samples[1]
    assert calls[2][1] == 10
    assert "status" in capsys.readouterr().out


class FakeWazuhClient:
    def get_cluster_state(self):
        return {"data": {"enabled": "yes", "running": "yes"}}

    def get_nodes(self):
        return {
            "data": {
                "affected_items": [
                    {"name": "wazuh-manager02.local", "status": "active", "agents": 50, "sync_status": "synced"},
                    {"name": "wazuh-manager03.local", "status": "active", "agents": 55, "sync_status": "synced"},
                ]
            }
        }

    def get_node_daemon_stats(self, node_id):
        return {
            "data": {
                "affected_items": [
                    {
                        "name": "wazuh-remoted",
                        "metrics": {
                            "messages": {"received_breakdown": {"event": 1400, "discarded": 2}},
                            "queues": {"received": {"size": 131072, "usage": 92}},
                            "dropped_count": 1,
                        },
                    },
                    {"name": "wazuh-analysisd", "metrics": {"events_processed": 1390}},
                ]
            }
        }


class FakeIndexerClient:
    def cluster_health(self):
        return {"status": "green", "number_of_nodes": 3, "active_shards": 12, "unassigned_shards": 0, "number_of_pending_tasks": 0}

    def cluster_stats(self):
        return {"indices": {"indexing": {"index_total": 2400}}}

    def nodes_stats(self):
        return {
            "nodes": {
                "n1": {
                    "thread_pool": {"write": {"rejected": 0}},
                    "fs": {"total": {"available_in_bytes": 800, "total_in_bytes": 1000}},
                    "jvm": {"mem": {"heap_used_percent": 35}},
                }
            }
        }

    def pending_tasks(self):
        return {"tasks": []}


class FakeNginxClient:
    def __init__(self, *args, **kwargs):
        pass

    def collect(self, name=None):
        return NginxState(name=name, reachable=True, healthy=True, active_connections=3, requests=42, advanced_metrics_available=True)


def test_snapshot_collects_api_clients_then_analyzer_recommends(monkeypatch):
    cli = load_cli()
    cluster = ClusterState(
        "multi-node",
        "wazuh-manager01.local",
        ("wazuh-manager02.local", "wazuh-manager03.local"),
        ("wazuh-indexer01.local",),
        "wazuh-dashboard01.local",
        "nginx",
        None,
        None,
        "default",
    )
    monkeypatch.setattr(cli, "discover_installation", lambda *args, **kwargs: cluster)
    monkeypatch.setattr(cli, "_wazuh_api_client", lambda cfg: FakeWazuhClient())
    monkeypatch.setattr(cli, "_indexer_api_client", lambda cfg: FakeIndexerClient())
    monkeypatch.setattr(cli, "NginxHealthClient", FakeNginxClient)
    cfg = cli.load_config()
    cfg = cfg.__class__(**{
        **cfg.__dict__,
        "runtime": cfg.runtime.__class__(**{
            **cfg.runtime.__dict__,
            "wazuh_api_url": "https://wazuh:55000",
            "wazuh_api_username": "readonly",
            "wazuh_api_password": "secret",
            "indexer_api_url": "https://indexer:9200",
            "nginx_health_url": "http://nginx/health",
        }),
    })

    first = cli._snapshot(cfg)
    second = cli._snapshot(cfg, first, 10)
    merged = cli._merge_samples([first, second], cfg)
    result = cli.analyze(merged, cfg)

    assert second.cluster.cluster_healthy is True
    assert second.workers[0].events_received == 1400
    assert second.workers[0].eps == 0
    assert second.indexer.health_status == "green"
    assert second.nginx.healthy is True
    assert merged.workers[0].samples_with_pressure == 2
    assert result.status == "SCALE_RECOMMENDED"
    assert result.recommended_next_workers == 3
    assert result.host_capacity_status == "HOST_CAPACITY_UNKNOWN"
