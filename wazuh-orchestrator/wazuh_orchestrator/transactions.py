"""Transaction manifests for conservative scale crash detection."""

from __future__ import annotations

import json
import uuid
import yaml
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .logging_setup import atomic_write, redact
from .models import ScalingError

Phase = Literal[
    "PLANNED",
    "CERTIFICATE_READY",
    "CONFIG_READY",
    "COMPOSE_READY",
    "WORKER_STARTED",
    "WORKER_HEALTHY",
    "CLUSTER_JOINED",
    "NGINX_UPDATED",
    "VALIDATED",
    "SUCCESS",
    "ROLLBACK",
    "FAILED",
]

TERMINAL = {"SUCCESS", "FAILED", "ROLLBACK"}


@dataclass(frozen=True)
class TransactionManifest:
    """Secret-free manifest describing one scale operation and current phase."""

    transaction_id: str
    operation: str
    worker: str | None
    phase: Phase
    status: str
    created_at: str
    updated_at: str
    created_artifacts: tuple[str, ...] = ()
    flags: dict[str, bool] = field(default_factory=dict)


class TransactionStore:
    """Read and write transaction manifests under generated/transactions."""

    def __init__(self, root: Path):
        self.directory = root / "generated" / "transactions"

    def create(self, operation: str, worker: str | None) -> TransactionManifest:
        now = _now()
        manifest = TransactionManifest(str(uuid.uuid4()), operation, worker, "PLANNED", "INCOMPLETE", now, now)
        self.save(manifest)
        return manifest

    def advance(self, manifest: TransactionManifest, phase: Phase, **flags: bool) -> TransactionManifest:
        status = "SUCCESS" if phase == "SUCCESS" else "FAILED" if phase == "FAILED" else "INCOMPLETE"
        updated = TransactionManifest(
            manifest.transaction_id,
            manifest.operation,
            manifest.worker,
            phase,
            status,
            manifest.created_at,
            _now(),
            manifest.created_artifacts,
            {**manifest.flags, **flags},
        )
        self.save(updated)
        return updated

    def save(self, manifest: TransactionManifest) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{manifest.transaction_id}.json"
        payload = redact(asdict(manifest))
        atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=0o600)
        return path

    def incomplete(self) -> tuple[TransactionManifest, ...]:
        if not self.directory.exists():
            return ()
        manifests = []
        for path in sorted(self.directory.glob("*.json")):
            manifests.append(self.load(path))
        return tuple(m for m in manifests if m.phase not in TERMINAL and m.status != "SUCCESS")


    def recent_success(self, operation: str, within_seconds: int) -> tuple[TransactionManifest, ...]:
        """Return successful transactions updated within the stabilization window."""
        if within_seconds <= 0 or not self.directory.exists():
            return ()
        now = datetime.now(timezone.utc)
        matches = []
        for path in sorted(self.directory.glob("*.json")):
            manifest = self.load(path)
            if manifest.operation != operation or manifest.status != "SUCCESS" or manifest.phase != "SUCCESS":
                continue
            try:
                updated = datetime.fromisoformat(manifest.updated_at.replace("Z", "+00:00"))
            except ValueError:
                continue
            if (now - updated).total_seconds() <= within_seconds:
                matches.append(manifest)
        return tuple(matches)

    def load(self, path: Path) -> TransactionManifest:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return TransactionManifest(
                transaction_id=str(raw["transaction_id"]),
                operation=str(raw["operation"]),
                worker=raw.get("worker"),
                phase=raw["phase"],
                status=str(raw["status"]),
                created_at=str(raw["created_at"]),
                updated_at=str(raw["updated_at"]),
                created_artifacts=tuple(raw.get("created_artifacts", ())),
                flags=dict(raw.get("flags", {})),
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ScalingError(f"Malformed transaction manifest: {path}") from exc

    def reconcile_read_only(
        self,
        *,
        desired_compose: Path | None = None,
        docker_workers: tuple[str, ...] = (),
        cluster_workers: tuple[str, ...] = (),
        nginx_config: Path | None = None,
        cert_dir: Path | None = None,
    ) -> dict[str, object]:
        """Compare incomplete transactions with observable state without changing it."""
        incomplete = self.incomplete()
        observations = []
        desired_workers = _desired_compose_workers(desired_compose) if desired_compose else set()
        nginx_workers = _nginx_workers(nginx_config) if nginx_config else set()
        cert_workers = _cert_workers(cert_dir) if cert_dir else set()
        for manifest in incomplete:
            worker = manifest.worker
            observations.append(
                {
                    "transaction_id": manifest.transaction_id,
                    "phase": manifest.phase,
                    "worker": worker,
                    "in_desired_compose": worker in desired_workers if worker else False,
                    "in_docker": worker in docker_workers if worker else False,
                    "in_wazuh_cluster": worker in cluster_workers if worker else False,
                    "in_nginx": worker in nginx_workers if worker else False,
                    "has_certificate_artifacts": worker in cert_workers if worker else False,
                }
            )
        return {
            "incomplete_transaction": bool(incomplete),
            "transaction_ids": [m.transaction_id for m in incomplete],
            "manual_intervention_required": bool(incomplete),
            "observations": observations,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _desired_compose_workers(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ScalingError(f"Malformed desired Compose override: {path}") from exc
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return set()
    return {str(name) for name in services if "manager" in str(name)}


def _nginx_workers(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    workers = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("server ") or ":1514" not in stripped:
            continue
        workers.add(stripped.split()[1].split(":", 1)[0])
    return workers


def _cert_workers(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    workers = set()
    for cert in path.glob("*.pem"):
        name = cert.name
        if name == "root-ca.pem" or name.endswith("-key.pem"):
            continue
        key = cert.with_name(cert.stem + "-key.pem")
        if key.exists():
            workers.add(cert.stem)
    return workers
