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
from wazuh_orchestrator.logging_setup import configure_logging
from wazuh_orchestrator.metrics import collect_host_metrics
from wazuh_orchestrator.models import AnalysisInput, ConfigurationError, DiscoveryError, HostMetrics, IndexerState, SafetyError, ScalingError, WorkerMetrics
from wazuh_orchestrator.scaler import build_plan, scale


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
    p_scale.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        root = Path(__file__).resolve().parent
        configure_logging(root, "DEBUG" if args.debug else cfg.logging.level)
        snapshot = _snapshot(cfg)
        if args.command == "status":
            return _status(snapshot, cfg, args.json)
        if args.command == "analyze":
            if args.duration:
                cfg = _duration_config(cfg, args.duration)
            result = analyze(snapshot, cfg)
            return _print_analysis(snapshot, cfg, result, args.json)
        if args.command in ("plan", "scale"):
            backend = _backend(snapshot, root, cfg)
            plan = build_plan(snapshot, cfg, args.workers, backend)
            if args.command == "scale":
                plan = scale(snapshot, cfg, args.workers, backend, None, root, yes=args.yes, sleep=time.sleep)
            print_plan(plan)
            return 0
    except (ConfigurationError, DiscoveryError, SafetyError, ScalingError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 1


def _snapshot(cfg) -> AnalysisInput:
    cluster = discover_installation(cfg.runtime.easy_wazuh_root)
    if cluster.mode == "unknown" and not cluster.docker_available:
        raise DiscoveryError("Docker runtime not detected.\nNo running Easy-Wazuh installation can be inspected on this host.")
    host = collect_host_metrics(cfg.runtime.easy_wazuh_root.parent)
    workers = tuple(WorkerMetrics(name=w, cpu_percent=None, memory_percent=None, baseline_worker=i < cfg.workers.baseline) for i, w in enumerate(cluster.workers))
    return AnalysisInput(cluster=cluster, host=host, workers=workers, indexer=IndexerState(names=cluster.indexers, healthy=cluster.cluster_healthy))


def _duration_config(cfg, duration: int):
    sample_count = max(1, duration // max(1, cfg.analysis.sample_interval_seconds))
    return cfg.__class__(**{**cfg.__dict__, "analysis": cfg.analysis.__class__(**{**cfg.analysis.__dict__, "sample_count": sample_count})})


def _backend(snapshot: AnalysisInput, root: Path, cfg) -> ComposeBackend:
    if not snapshot.cluster.compose_file or not snapshot.cluster.compose_project_directory:
        raise DiscoveryError("No Easy-Wazuh Compose file discovered.")
    return ComposeBackend(snapshot.cluster.compose_file, root / "generated" / "docker-compose.orchestrator.yml", snapshot.cluster.compose_project_directory, cfg.runtime.compose_timeout_seconds)


def _status(snapshot: AnalysisInput, cfg, as_json: bool) -> int:
    if as_json:
        print(json.dumps(_jsonable({"cluster": asdict(snapshot.cluster), "host": asdict(snapshot.host), "baseline": cfg.workers.baseline, "max": cfg.workers.max}), sort_keys=True))
        return 0
    print("Easy-Wazuh Orchestrator")
    print("=======================")
    print(f"Deployment       {snapshot.cluster.mode}")
    print(f"Version          {snapshot.cluster.version or 'UNKNOWN'}")
    print(f"Master           {snapshot.cluster.master or 'UNKNOWN'}")
    print(f"Workers          {snapshot.cluster.worker_count}")
    print(f"Baseline         {cfg.workers.baseline}")
    print(f"Max workers      {cfg.workers.max}")
    print(f"Indexers         {len(snapshot.cluster.indexers)}")
    print(f"Dashboard        {snapshot.cluster.dashboard or 'UNKNOWN'}")
    print(f"NGINX            {snapshot.cluster.nginx or 'not detected'}")
    print(f"Cluster health   {_fmt(snapshot.cluster.cluster_healthy)}")
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
    print("Diagnosis\n---------")
    print("\n".join(result.diagnostics))
    print("\nRecommendation\n--------------")
    print(result.recommendation)
    print(f"\nConfidence       {result.confidence}")
    return 0


def print_plan(plan) -> None:
    if plan.no_change_reason:
        print(plan.no_change_reason)
        return
    print(f"Current workers: {plan.current_workers}")
    print(f"Target workers:  {plan.target_workers}")
    print(f"Action:          {plan.action}")
    for path in plan.files_to_generate:
        print(f"Generate:        {path}")
    if plan.worker_to_create:
        print(f"Create worker:   {plan.worker_to_create}")
    if plan.worker_to_remove:
        print(f"Remove worker:   {plan.worker_to_remove}")
    for change in plan.nginx_changes:
        print(f"NGINX:           {change}")
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
