"""Transaction manifests for conservative scale crash detection."""

from __future__ import annotations

import json
import uuid
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

    def reconcile_read_only(self) -> dict[str, object]:
        """Return enough state for an admin to decide manual recovery."""
        incomplete = self.incomplete()
        return {
            "incomplete_transaction": bool(incomplete),
            "transaction_ids": [m.transaction_id for m in incomplete],
            "manual_intervention_required": bool(incomplete),
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
