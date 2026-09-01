"""Configuration loading and validation."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from typing import Any, get_type_hints
from urllib.parse import urlparse

import yaml

from .models import (
    AnalysisSettings,
    CapacitySettings,
    ConfigurationError,
    HostSettings,
    LoggingSettings,
    OrchestratorConfig,
    RuntimeSettings,
    SafetySettings,
    ScaleDownSettings,
    ScalingSettings,
    WorkerSettings,
)


DEFAULT_CONFIG = OrchestratorConfig()


def load_config(path: Path | None = None) -> OrchestratorConfig:
    """Load YAML config, using built-in defaults when no path is supplied."""
    data: dict[str, Any] = {}
    if path is not None:
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Malformed configuration file: {path}") from exc
        if raw is None:
            data = {}
        elif isinstance(raw, dict):
            data = raw
        else:
            raise ConfigurationError("Configuration root must be a mapping.")
    cfg = OrchestratorConfig(
        workers=_section(WorkerSettings, data.get("workers", {})),
        analysis=_section(AnalysisSettings, data.get("analysis", {})),
        scaling=_section(ScalingSettings, data.get("scaling", {})),
        capacity=_section(CapacitySettings, data.get("capacity", {})),
        host=_section(HostSettings, data.get("host", {})),
        safety=_section(SafetySettings, data.get("safety", {})),
        scale_down=_section(ScaleDownSettings, data.get("scale_down", {})),
        logging=_section(LoggingSettings, data.get("logging", {})),
        runtime=_runtime(data.get("runtime", {})),
    )
    validate_config(cfg)
    return cfg


def _section(model: type[Any], data: Any) -> Any:
    if not isinstance(data, dict):
        raise ConfigurationError(f"{model.__name__} must be a mapping.")
    allowed = {f.name for f in fields(model)}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigurationError(f"Unknown configuration keys for {model.__name__}: {', '.join(unknown)}")
    return model(**data)


def _runtime(data: Any) -> RuntimeSettings:
    if not isinstance(data, dict):
        raise ConfigurationError("RuntimeSettings must be a mapping.")
    allowed = {f.name for f in fields(RuntimeSettings)}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigurationError(f"Unknown configuration keys for RuntimeSettings: {', '.join(unknown)}")
    converted = dict(data)
    for key in ("easy_wazuh_root", "orchestrator_root", "deployment_metadata_path"):
        if key in converted:
            converted[key] = Path(converted[key])
    return RuntimeSettings(**converted)


def validate_config(cfg: OrchestratorConfig) -> None:
    if cfg.workers.baseline < 0:
        raise ConfigurationError("workers.baseline must be >= 0.")
    if cfg.workers.max < cfg.workers.baseline:
        raise ConfigurationError("workers.max must be >= workers.baseline.")
    if cfg.analysis.sample_count < 1:
        raise ConfigurationError("analysis.sample_count must be >= 1.")
    if cfg.analysis.sample_interval_seconds < 0:
        raise ConfigurationError("analysis.sample_interval_seconds must be >= 0.")
    if cfg.scaling.max_delta_per_operation != 1:
        raise ConfigurationError("scaling.max_delta_per_operation must be exactly 1 in V1.")
    if cfg.capacity.new_worker_safety_factor < 1:
        raise ConfigurationError("capacity.new_worker_safety_factor must be >= 1.")
    if cfg.scaling.stabilization_seconds < 0:
        raise ConfigurationError("scaling.stabilization_seconds must be >= 0.")
    if cfg.scale_down.drain_seconds < 0:
        raise ConfigurationError("scale_down.drain_seconds must be >= 0.")
    if cfg.runtime.wazuh_api_timeout_seconds < 1:
        raise ConfigurationError("runtime.wazuh_api_timeout_seconds must be >= 1.")
    if cfg.runtime.indexer_api_timeout_seconds < 1:
        raise ConfigurationError("runtime.indexer_api_timeout_seconds must be >= 1.")
    if cfg.runtime.nginx_timeout_seconds < 1:
        raise ConfigurationError("runtime.nginx_timeout_seconds must be >= 1.")
    if cfg.runtime.metrics_provider not in {"none", "local"}:
        raise ConfigurationError("runtime.metrics_provider must be one of: none, local.")
    if cfg.runtime.wazuh_api_url:
        parsed = urlparse(cfg.runtime.wazuh_api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ConfigurationError("runtime.wazuh_api_url must be an HTTPS URL.")
    if cfg.runtime.indexer_api_url:
        parsed = urlparse(cfg.runtime.indexer_api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ConfigurationError("runtime.indexer_api_url must be an HTTPS URL.")
    for url_name, url_value in (("runtime.nginx_health_url", cfg.runtime.nginx_health_url), ("runtime.nginx_stub_status_url", cfg.runtime.nginx_stub_status_url)):
        if url_value:
            parsed = urlparse(url_value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ConfigurationError(f"{url_name} must be an HTTP or HTTPS URL.")
    if cfg.logging.level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigurationError("logging.level must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.")
    _validate_percentages(cfg)


def _validate_percentages(cfg: OrchestratorConfig) -> None:
    percentage_paths = (
        "workers.target_utilization_percent",
        "workers.warning_utilization_percent",
        "workers.critical_utilization_percent",
        "analysis.worker_imbalance_percent",
        "host.cpu_warning_percent",
        "host.cpu_block_percent",
        "host.memory_warning_percent",
        "host.memory_block_percent",
        "host.iowait_block_percent",
        "host.disk_free_min_percent",
        "host.reserve_cpu_percent_after_scale",
        "host.reserve_memory_percent_after_scale",
    )
    for path in percentage_paths:
        value: Any = cfg
        for part in path.split("."):
            value = getattr(value, part)
        if value < 0 or value > 100:
            raise ConfigurationError(f"{path} must be between 0 and 100.")
