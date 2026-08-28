"""Certificate preparation integration points for worker scaling."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Protocol

from .logging_setup import atomic_write
from .models import ScalingError

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
SAFE_TRANSACTION_ID = re.compile(r"^cert-[A-Za-z0-9_.-]+$")


class CertificatePreparer(Protocol):
    """Prepare and validate worker certificates for one scale transaction."""

    def prepare_worker(self, node_name: str, transaction_id: str) -> dict[str, object]:
        ...

    def cleanup_worker(self, transaction_id: str) -> None:
        ...


class IntegrationRequiredCertificatePreparer:
    """Fail closed until incremental Wazuh certificate generation is validated."""

    def prepare_worker(self, node_name: str, transaction_id: str) -> dict[str, object]:
        raise ScalingError(
            "INTEGRATION_VALIDATION_REQUIRED: worker certificate preparation must be validated on a real Easy-Wazuh/Wazuh Docker host before scale-up execution."
        )

    def cleanup_worker(self, transaction_id: str) -> None:
        return None


class PreprovisionedCertificatePreparer:
    """Accept a worker only when its certificate artifacts already exist."""

    def __init__(self, cert_dir: Path, root: Path):
        self.cert_dir = cert_dir
        self.transactions = root / "generated" / "certificate-transactions"

    def prepare_worker(self, node_name: str, transaction_id: str) -> dict[str, object]:
        _validate_node_name(node_name)
        certificate_transaction_id = f"cert-{transaction_id}"
        before = self._fingerprints()
        existing = self._artifact_names()
        missing = [name for name in self._required_artifacts(node_name) if name not in existing]
        if missing:
            raise ScalingError("CERTIFICATE_SAFETY_FAILURE: missing worker certificate artifacts: " + ", ".join(missing))
        self._write_manifest(certificate_transaction_id, node_name, (), before, before, "ready")
        return {
            "status": "ready",
            "node_name": node_name,
            "certificate_ready": True,
            "transaction_id": certificate_transaction_id,
            "created_artifacts": [],
        }

    def cleanup_worker(self, transaction_id: str) -> None:
        manifest_path = self._manifest_path(transaction_id)
        if not manifest_path.exists():
            raise ScalingError("certificate transaction not found")
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScalingError("malformed certificate transaction manifest") from exc
        for artifact in raw.get("created_artifacts", []):
            path = Path(str(artifact))
            if path.exists() and self.cert_dir in path.parents:
                path.unlink()

    def _required_artifacts(self, node_name: str) -> tuple[str, ...]:
        return ("root-ca.pem", f"{node_name}.pem", f"{node_name}-key.pem")

    def _fingerprints(self) -> dict[str, str]:
        if not self.cert_dir.exists():
            return {}
        return {
            path.name: fingerprint(path)
            for path in sorted(self.cert_dir.iterdir())
            if path.is_file() and path.suffix == ".pem" and not path.name.endswith("-key.pem")
        }

    def _artifact_names(self) -> set[str]:
        if not self.cert_dir.exists():
            return set()
        return {path.name for path in self.cert_dir.iterdir() if path.is_file()}

    def _manifest_path(self, transaction_id: str) -> Path:
        if not SAFE_TRANSACTION_ID.fullmatch(transaction_id) or ".." in transaction_id:
            raise ScalingError("invalid certificate transaction id")
        return self.transactions / f"{transaction_id}.json"

    def _write_manifest(
        self,
        transaction_id: str,
        node_name: str,
        created_artifacts: tuple[str, ...],
        before: dict[str, str],
        after: dict[str, str],
        status: str,
    ) -> None:
        payload = {
            "transaction_id": transaction_id,
            "node_name": node_name,
            "status": status,
            "created_artifacts": list(created_artifacts),
            "fingerprints_before": before,
            "fingerprints_after": after,
        }
        atomic_write(self._manifest_path(transaction_id), json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=0o600)


def fingerprint(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_node_name(node_name: str) -> None:
    if not SAFE_NAME.fullmatch(node_name) or ".." in node_name:
        raise ScalingError(f"Unsafe certificate node name: {node_name}")
