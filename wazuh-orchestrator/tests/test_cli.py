from __future__ import annotations

import importlib.util
from pathlib import Path

from wazuh_orchestrator.models import AnalysisInput, ClusterState, HostMetrics, IndexerState, WorkerMetrics


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


class ClusterValidator:
    def verify_cluster_join(self, worker):
        return None

    def final_validate_cluster(self):
        return None


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


def test_cli_scale_up_fails_closed_without_validated_certificates(monkeypatch, capsys):
    cli = load_cli()
    backend = Backend()
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snapshot())
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)
    monkeypatch.setattr(cli, "_cluster_validator", lambda cfg: ClusterValidator())
    monkeypatch.setattr(cli, "_nginx_manager", lambda snapshot, backend: None)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setattr("builtins.input", lambda prompt: "SCALE")
    assert cli.main(["scale", "--workers", "3"]) == 2
    captured = capsys.readouterr()
    assert "CERTIFICATE_SAFETY_FAILURE" in captured.err
    assert backend.commands == []


def test_cli_scale_requires_wazuh_api_configuration_after_certificates(monkeypatch, tmp_path, capsys):
    cli = load_cli()
    backend = Backend()
    certs = tmp_path / "config" / "wazuh_indexer_ssl_certs"
    certs.mkdir(parents=True)
    nginx_conf = tmp_path / "config" / "nginx" / "nginx.conf"
    nginx_conf.parent.mkdir(parents=True)
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    for name in ("root-ca.pem", "wazuh-manager04.local.pem", "wazuh-manager04.local-key.pem"):
        (certs / name).write_text("CERT", encoding="utf-8")
    snap = snapshot()
    snap = AnalysisInput(snap.cluster.__class__(**{**snap.cluster.__dict__, "compose_project_directory": tmp_path}), snap.host, snap.workers, snap.indexer, snap.dashboard)
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snap)
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setattr("builtins.input", lambda prompt: "SCALE")
    assert cli.main(["scale", "--workers", "3"]) == 2
    assert "Wazuh API configuration is required" in capsys.readouterr().err
    assert ("up", "-d", "wazuh-manager04.local") not in backend.commands


def test_cli_scale_uses_configured_cluster_validator(monkeypatch, tmp_path):
    cli = load_cli()
    backend = Backend()
    certs = tmp_path / "config" / "wazuh_indexer_ssl_certs"
    certs.mkdir(parents=True)
    nginx_conf = tmp_path / "config" / "nginx" / "nginx.conf"
    nginx_conf.parent.mkdir(parents=True)
    nginx_conf.write_text("upstream wazuh_managers {\n}\n", encoding="utf-8")
    for name in ("root-ca.pem", "wazuh-manager04.local.pem", "wazuh-manager04.local-key.pem"):
        (certs / name).write_text("CERT", encoding="utf-8")
    snap = snapshot()
    snap = AnalysisInput(snap.cluster.__class__(**{**snap.cluster.__dict__, "compose_project_directory": tmp_path}), snap.host, snap.workers, snap.indexer, snap.dashboard)
    monkeypatch.setattr(cli, "_snapshot", lambda cfg: snap)
    monkeypatch.setattr(cli, "_backend", lambda snapshot, root, cfg: backend)
    monkeypatch.setattr(cli, "_cluster_validator", lambda cfg: ClusterValidator())
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setattr("builtins.input", lambda prompt: "SCALE")
    assert cli.main(["scale", "--workers", "3"]) == 0
    assert ("up", "-d", "wazuh-manager04.local") in backend.commands
