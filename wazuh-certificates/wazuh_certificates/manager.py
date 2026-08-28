"""Minimal certificate artifact validation and transaction tracking."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile


class CertificateSafetyError(Exception):
    """Certificate operation would be unsafe or is not validated for V1."""


SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
SAFE_TRANSACTION_ID = re.compile(r"^cert-[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class CertificateTransaction:
    transaction_id: str
    node_name: str
    created_artifacts: tuple[str, ...]


class CertificateManager:
    """Protect existing Wazuh CA/certs and trace worker cert preparation."""

    def __init__(self, cert_dir: Path, root: Path):
        self.cert_dir = cert_dir
        self.root = root
        self.transactions = root / "generated" / "certificate-transactions"

    def status(self) -> dict[str, object]:
        ca = self.cert_dir / "root-ca.pem"
        return {"status": "ready" if ca.exists() else "missing_ca", "ca_fingerprint": fingerprint(ca) if ca.exists() else None}

    def validate(self) -> dict[str, object]:
        ca = self.cert_dir / "root-ca.pem"
        if not ca.exists():
            raise CertificateSafetyError("CERTIFICATE_SAFETY_FAILURE: existing Wazuh CA not found")
        return {"status": "valid", "ca_fingerprint": fingerprint(ca)}

    def prepare_worker(self, node_name: str) -> dict[str, object]:
        _validate_node_name(node_name)
        before = self._fingerprints()
        existing = self._artifact_names()
        if "root-ca.pem" not in existing:
            raise CertificateSafetyError("CERTIFICATE_SAFETY_FAILURE: existing Wazuh CA not found")
        tx = CertificateTransaction(f"cert-{uuid.uuid4()}", node_name, ())
        if all(name in existing for name in self._required_artifacts(node_name)):
            self._write_manifest(tx, before, before, "ready")
            return {
                "status": "ready",
                "node_name": node_name,
                "certificate_ready": True,
                "transaction_id": tx.transaction_id,
                "created_artifacts": [],
            }
        self._write_manifest(tx, before, before, "INTEGRATION_VALIDATION_REQUIRED")
        return {
            "status": "INTEGRATION_VALIDATION_REQUIRED",
            "node_name": node_name,
            "certificate_ready": False,
            "transaction_id": tx.transaction_id,
            "created_artifacts": [],
        }

    def cleanup_worker(self, transaction_id: str) -> dict[str, object]:
        manifest = self._manifest_path(transaction_id)
        if not manifest.exists():
            raise CertificateSafetyError("certificate transaction not found")
        try:
            raw = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CertificateSafetyError("malformed certificate transaction manifest") from exc
        removed = []
        for artifact in raw.get("created_artifacts", []):
            path = Path(artifact)
            if path.exists() and self.cert_dir in path.parents:
                path.unlink()
                removed.append(str(path))
        return {"status": "cleaned", "transaction_id": transaction_id, "removed_artifacts": removed}

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

    def _required_artifacts(self, node_name: str) -> tuple[str, ...]:
        return ("root-ca.pem", f"{node_name}.pem", f"{node_name}-key.pem")

    def _manifest_path(self, transaction_id: str) -> Path:
        if not SAFE_TRANSACTION_ID.fullmatch(transaction_id) or ".." in transaction_id:
            raise CertificateSafetyError("invalid certificate transaction id")
        return self.transactions / f"{transaction_id}.json"

    def _write_manifest(self, tx: CertificateTransaction, before: dict[str, str], after: dict[str, str], status: str) -> None:
        self.transactions.mkdir(parents=True, exist_ok=True)
        payload = {
            "transaction_id": tx.transaction_id,
            "node_name": tx.node_name,
            "status": status,
            "created_artifacts": list(tx.created_artifacts),
            "fingerprints_before": before,
            "fingerprints_after": after,
        }
        atomic_write(self._manifest_path(tx.transaction_id), json.dumps(payload, indent=2, sort_keys=True) + "\n")


def fingerprint(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    tmp_path.chmod(0o600)
    tmp_path.replace(path)


def _validate_node_name(node_name: str) -> None:
    if not SAFE_NAME.fullmatch(node_name) or ".." in node_name:
        raise CertificateSafetyError(f"Unsafe certificate node name: {node_name}")
