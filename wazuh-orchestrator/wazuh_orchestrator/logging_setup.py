"""Logging and audit helpers."""

from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tempfile import NamedTemporaryFile
from datetime import datetime, timezone

SECRET_KEYS = ("password", "token", "secret", "key", "credential")


def configure_logging(root: Path, level: str = "INFO") -> None:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        log_dir = root / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(log_dir / "wazuh-orchestrator.log", maxBytes=1_000_000, backupCount=3)
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logging.basicConfig(level=getattr(logging, level.upper()), handlers=[handler], force=True)


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {k: ("REDACTED" if any(s in k.lower() for s in SECRET_KEYS) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def write_audit(root: Path, event: dict[str, object]) -> None:
    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **redact(event)}
    with (log_dir / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    tmp_path.chmod(mode)
    tmp_path.replace(path)
