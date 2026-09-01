#!/usr/bin/env python3
"""CLI entry point for Easy-Wazuh Orchestrator."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from wazuh_orchestrator.analyzer import analyze
from wazuh_orchestrator.backends.compose import ComposeBackend
from wazuh_orchestrator.config import load_config
from wazuh_orchestrator.discovery import discover_installation
from wazuh_orchestrator.indexer_api import IndexerAPIClient, collect_indexer_state, unavailable_indexer_state
from wazuh_orchestrator.logging_setup import configure_logging
from wazuh_orchestrator.metrics import collect_host_metrics
from wazuh_orchestrator.models import AnalysisInput, ConfigurationError, DiscoveryError, DashboardState, HostMetrics, IndexerState, NginxState, SafetyError, ScalingError, WazuhAPIError, WorkerMetrics
from wazuh_orchestrator.nginx import NginxHealthClient, unknown_nginx_state
from wazuh_orchestrator.scaler import build_plan
from wazuh_orchestrator.transactions import TransactionStore
from wazuh_orchestrator.wazuh_api import WazuhAPIClient, cluster_status_healthy, collect_worker_metrics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Easy-Wazuh Orchestrator")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--debug", action="store_true", help="Force DEBUG logging for this run.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")
        if name == "analyze":
            p.add_argument("--duration", type=int)
    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--workers", type=int, required=True)
    p_scale = sub.add_parser("scale")
    p_scale.add_argument("--workers", type=int, required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        cfg = load_config(args.config)
        root = _runtime_root(cfg)
        configure_logging(root, "DEBUG" if args.debug else cfg.logging.level)
        if args.command == "analyze":
            if args.duration:
                cfg = _duration_config(cfg, args.duration)
            snapshot = _with_transaction_details(_analysis_snapshot(cfg, args.duration), root, cfg)
            transaction_state = TransactionStore(root).reconcile_read_only()
            result = analyze(snapshot, cfg)
            return _print_analysis(snapshot, cfg, result, args.json)
        snapshot = _with_transaction_details(_snapshot(cfg), root, cfg)
        transaction_state = TransactionStore(root).reconcile_read_only()
        if args.command == "status":
            return _status(snapshot, cfg, args.json, transaction_state)
        if args.command in ("plan", "scale"):
            backend = _backend(snapshot, root, cfg)
            plan = build_plan(snapshot, cfg, args.workers, backend)
            print_plan(plan)
            if args.command == "scale":
                print("Scaling execution is disabled in Wazuh Orchestrator V1. Use analyze/plan as read-only diagnostics only.", file=sys.stderr)
                return 2
            return 0
    except (ConfigurationError, DiscoveryError, SafetyError, ScalingError, WazuhAPIError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 1


def _snapshot(cfg, previous: AnalysisInput | None = None, elapsed_seconds: float | None = None) -> AnalysisInput:
    cluster = discover_installation(cfg.runtime.easy_wazuh_root, metadata_path=cfg.runtime.deployment_metadata_path)
    cluster = _with_wazuh_cluster_health(cluster, cfg)
    host = _host_metrics(cfg)
    workers = _worker_metrics(cluster, cfg, previous, elapsed_seconds)
    indexer = _indexer_state(cluster, cfg, previous.indexer if previous else None, elapsed_seconds)
    nginx = _nginx_state(cluster, cfg)
    cluster = cluster.__class__(**{**cluster.__dict__, "nginx_healthy": nginx.healthy})
    return AnalysisInput(cluster=cluster, host=host, workers=workers, indexer=indexer, dashboard=DashboardState(name=cluster.dashboard), nginx=nginx)


def _analysis_snapshot(cfg, duration: int | None = None) -> AnalysisInput:
    samples = max(1, cfg.analysis.sample_count)
    if duration is None or samples == 1:
        return _snapshot(cfg)
    interval = max(1, cfg.analysis.sample_interval_seconds)
    previous = _snapshot(cfg)
    collected = [previous]
    for _ in range(1, samples):
        started = time.monotonic()
        time.sleep(interval)
        elapsed = time.monotonic() - started
        previous = _snapshot(cfg, previous, elapsed)
        collected.append(previous)
    return _merge_samples(collected, cfg)


def _merge_samples(samples: list[AnalysisInput], cfg=None) -> AnalysisInput:
    latest = samples[-1]
    pressure_threshold = cfg.workers.warning_utilization_percent if cfg is not None else 70
    enriched = []
    for worker in latest.workers:
        pressure_count = 0
        previous_queue = None
        latest_delta = worker.queue_delta
        for sample in samples:
            current = next((w for w in sample.workers if w.name == worker.name), None)
            if current is None:
                continue
            queue_pressure = current.queue_usage_percent is not None and current.queue_usage_percent >= pressure_threshold
            loss_pressure = (current.discarded_count is not None and current.discarded_count > 0) or (current.dropped_count is not None and current.dropped_count > 0)
            if queue_pressure or loss_pressure:
                pressure_count += 1
            if previous_queue is not None and current.queue_size is not None:
                latest_delta = current.queue_size - previous_queue
            if current.queue_size is not None:
                previous_queue = current.queue_size
        enriched.append(worker.__class__(**{**worker.__dict__, "queue_delta": latest_delta, "samples_with_pressure": pressure_count}))
    return AnalysisInput(latest.cluster, latest.host, tuple(enriched), latest.indexer, latest.dashboard, latest.nginx)


def _with_wazuh_cluster_health(cluster, cfg):
    if not cfg.runtime.wazuh_api_url:
        return cluster
    try:
        client = _wazuh_api_client(cfg)
        healthy = cluster_status_healthy(client.get_cluster_state())
    except (ConfigurationError, WazuhAPIError):
        healthy = None
    return cluster.__class__(**{**cluster.__dict__, "cluster_healthy": healthy})


def _host_metrics(cfg) -> HostMetrics:
    if cfg.runtime.metrics_provider == "local":
        return collect_host_metrics(cfg.runtime.easy_wazuh_root.parent)
    return HostMetrics(None, None, None, None, None, None, None, None, None)


def _worker_metrics(cluster, cfg, previous: AnalysisInput | None, elapsed_seconds: float | None) -> tuple[WorkerMetrics, ...]:
    fallback = tuple(WorkerMetrics(name=w, baseline_worker=i < cfg.workers.baseline) for i, w in enumerate(cluster.workers))
    if not cfg.runtime.wazuh_api_url:
        return fallback
    try:
        collected = collect_worker_metrics(_wazuh_api_client(cfg), cluster.workers, previous.workers if previous else (), elapsed_seconds)
    except (ConfigurationError, WazuhAPIError):
        return fallback
    return tuple(worker.__class__(**{**worker.__dict__, "baseline_worker": i < cfg.workers.baseline}) for i, worker in enumerate(collected))


def _indexer_state(cluster, cfg, previous: IndexerState | None, elapsed_seconds: float | None) -> IndexerState:
    if not cfg.runtime.indexer_api_url:
        return IndexerState(names=cluster.indexers, healthy=None)
    try:
        client = _indexer_api_client(cfg)
        return collect_indexer_state(client, cluster.indexers, previous, elapsed_seconds)
    except (ConfigurationError, WazuhAPIError):
        return unavailable_indexer_state(cluster.indexers)


def _nginx_state(cluster, cfg) -> NginxState:
    if not cluster.nginx:
        return unknown_nginx_state(None)
    if not cfg.runtime.nginx_health_url and not cfg.runtime.nginx_stub_status_url:
        return unknown_nginx_state(cluster.nginx)
    return NginxHealthClient(
        cfg.runtime.nginx_health_url,
        cfg.runtime.nginx_stub_status_url,
        verify_tls=cfg.runtime.nginx_verify_tls,
        timeout=cfg.runtime.nginx_timeout_seconds,
    ).collect(cluster.nginx)


def _with_transaction_details(snapshot: AnalysisInput, root: Path, cfg) -> AnalysisInput:
    store = TransactionStore(root)
    state = store.reconcile_read_only()
    post_scale_stabilizing = bool(
        store.recent_success("scale_up", cfg.scaling.stabilization_seconds)
        or store.recent_success("scale_down", cfg.scaling.stabilization_seconds)
    )
    details = {
        **snapshot.cluster.details,
        "incomplete_transaction": bool(state.get("incomplete_transaction")),
        "post_scale_stabilizing": post_scale_stabilizing,
    }
    cluster = snapshot.cluster.__class__(**{**snapshot.cluster.__dict__, "details": details})
    return AnalysisInput(cluster, snapshot.host, snapshot.workers, snapshot.indexer, snapshot.dashboard, snapshot.nginx)


def _wazuh_api_client(cfg) -> WazuhAPIClient:
    missing = [
        name
        for name, value in (
            ("runtime.wazuh_api_url", cfg.runtime.wazuh_api_url),
            ("runtime.wazuh_api_username", cfg.runtime.wazuh_api_username),
            ("runtime.wazuh_api_password", cfg.runtime.wazuh_api_password),
        )
        if not value
    ]
    if missing:
        raise ConfigurationError("Wazuh API configuration is required for manager diagnostics: " + ", ".join(missing))
    return WazuhAPIClient(
        cfg.runtime.wazuh_api_url,
        cfg.runtime.wazuh_api_username,
        cfg.runtime.wazuh_api_password,
        verify_tls=cfg.runtime.wazuh_api_verify_tls,
        timeout=cfg.runtime.wazuh_api_timeout_seconds,
    )


def _indexer_api_client(cfg) -> IndexerAPIClient:
    if not cfg.runtime.indexer_api_url:
        raise ConfigurationError("runtime.indexer_api_url is required for Wazuh Indexer collection.")
    return IndexerAPIClient(
        cfg.runtime.indexer_api_url,
        cfg.runtime.indexer_api_username,
        cfg.runtime.indexer_api_password,
        verify_tls=cfg.runtime.indexer_api_verify_tls,
        timeout=cfg.runtime.indexer_api_timeout_seconds,
    )


def _duration_config(cfg, duration: int):
    interval = max(1, cfg.analysis.sample_interval_seconds)
    sample_count = max(2, duration // interval) if duration > 0 else 1
    return cfg.__class__(**{**cfg.__dict__, "analysis": cfg.analysis.__class__(**{**cfg.analysis.__dict__, "sample_count": sample_count})})


def _runtime_root(cfg) -> Path:
    root = cfg.runtime.orchestrator_root
    if root == Path("wazuh-orchestrator") and not root.is_absolute():
        return Path(__file__).resolve().parent
    return root if root.is_absolute() else Path.cwd() / root


def _backend(snapshot: AnalysisInput, root: Path, cfg) -> ComposeBackend:
    if not snapshot.cluster.compose_file or not snapshot.cluster.compose_project_directory:
        raise DiscoveryError("No Easy-Wazuh Compose file discovered.")
    return ComposeBackend(snapshot.cluster.compose_file, root / "generated" / "docker-compose.orchestrator.yml", snapshot.cluster.compose_project_directory, cfg.runtime.compose_timeout_seconds)


def _status(snapshot: AnalysisInput, cfg, as_json: bool, transaction_state=None) -> int:
    transaction_state = transaction_state or {}
    if as_json:
        print(json.dumps(_jsonable({"cluster": asdict(snapshot.cluster), "host": asdict(snapshot.host), "baseline": cfg.workers.baseline, "max": cfg.workers.max, "transaction_state": transaction_state}), sort_keys=True))
        return 0
    print("Easy-Wazuh Orchestrator")
    print("=======================")
    print(f"Deployment       {snapshot.cluster.mode}")
    print(f"Stack directory  {snapshot.cluster.compose_project_directory or 'UNKNOWN'}")
    print(f"Compose file     {snapshot.cluster.compose_file or 'UNKNOWN'}")
    print(f"Compose project  {snapshot.cluster.deployment_metadata.compose_project_name if snapshot.cluster.deployment_metadata else 'UNKNOWN'}")
    print(f"Version          {snapshot.cluster.version or 'UNKNOWN'}")
    print(f"Master           {snapshot.cluster.master or 'UNKNOWN'}")
    print(f"Workers          {snapshot.cluster.worker_count}")
    print(f"Baseline         {cfg.workers.baseline}")
    print(f"Max workers      {cfg.workers.max}")
    print(f"Indexers         {len(snapshot.cluster.indexers)}")
    print(f"Dashboard        {snapshot.cluster.dashboard or 'UNKNOWN'}")
    print(f"NGINX            {snapshot.cluster.nginx or 'not detected'}")
    print(f"Cluster health   {_fmt(snapshot.cluster.cluster_healthy)}")
    print(f"NGINX health     {_fmt(snapshot.nginx.healthy)}")
    print(f"Indexer health   {snapshot.indexer.health_status or _fmt(snapshot.indexer.healthy)}")
    if snapshot.cluster.naming_policy:
        print(f"Naming prefix    {snapshot.cluster.naming_policy.manager_prefix}")
        print(f"Naming width     {snapshot.cluster.naming_policy.manager_number_width}")
    print(f"Transaction      {'INCOMPLETE' if transaction_state.get('incomplete_transaction') else 'clean'}")
    print(f"Host CPU         {_pct(snapshot.host.cpu_percent)}")
    print(f"Host RAM         {_pct(snapshot.host.memory_percent)}")
    return 0


def _print_analysis(snapshot: AnalysisInput, cfg, result, as_json: bool) -> int:
    if as_json:
        print(json.dumps(_jsonable(asdict(result)), sort_keys=True))
        return 0
    print("Easy-Wazuh Orchestrator\n=======================\n")
    print("Topology\n--------")
    print(f"Mode             {snapshot.cluster.mode}")
    print(f"Master           {snapshot.cluster.master or 'UNKNOWN'}")
    print(f"Workers          {snapshot.cluster.worker_count}")
    print(f"Baseline         {cfg.workers.baseline}")
    print(f"Max workers      {cfg.workers.max}\n")
    print("Host\n----")
    print(f"CPU              {_pct(snapshot.host.cpu_percent)}")
    print(f"RAM              {_pct(snapshot.host.memory_percent)}")
    print(f"I/O wait         {_pct(snapshot.host.iowait_percent)}")
    print(f"Disk free        {_pct(snapshot.host.disk_free_percent)}\n")
    print("Runtime\n-------")
    print(f"Indexer health   {snapshot.indexer.health_status or _fmt(snapshot.indexer.healthy)}")
    print(f"NGINX health     {_fmt(snapshot.nginx.healthy)}")
    print(f"NGINX metrics    {_fmt(snapshot.nginx.advanced_metrics_available)}\n")
    print("Diagnosis\n---------")
    print("\n".join(result.diagnostics))
    print("\nRecommendation\n--------------")
    print(result.recommendation)
    print(f"\nStatus           {result.status}")
    print(f"Confidence       {result.confidence}")
    print(f"Host capacity   {result.host_capacity_status}")
    return 0


def print_plan(plan) -> None:
    if plan.no_change_reason:
        print(plan.no_change_reason)
        return
    print(f"Current workers: {plan.current_workers}")
    print(f"Target workers:  {plan.target_workers}")
    print(f"Action:          {plan.action}")
    for path in plan.files_to_generate:
        print(f"Would generate:  {path}")
    if plan.worker_to_create:
        print(f"Would create:    {plan.worker_to_create}")
    if plan.worker_to_remove:
        print(f"Would remove:    {plan.worker_to_remove}")
    for change in plan.nginx_changes:
        print(f"Would update:    {change}")
    for risk in plan.risks:
        print(f"Risk:            {risk}")


def _pct(value) -> str:
    return "UNKNOWN" if value is None else f"{value:.0f} %"


def _fmt(value) -> str:
    return "UNKNOWN" if value is None else str(value)


def _jsonable(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
