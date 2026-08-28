from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

CERT_ROOT = Path(__file__).resolve().parents[2] / "wazuh-certificates"
sys.path.insert(0, str(CERT_ROOT))

from wazuh_certificates.manager import CertificateManager, CertificateSafetyError, fingerprint


def cert_dir(tmp_path):
    p = tmp_path / "certs"
    p.mkdir()
    (p / "root-ca.pem").write_text("CA", encoding="utf-8")
    (p / "wazuh-manager02.local.pem").write_text("EXISTING", encoding="utf-8")
    (p / "wazuh-dashboard01.local.pem").write_text("DASHBOARD", encoding="utf-8")
    return p


def test_ca_fingerprint_before_after_unchanged(tmp_path):
    certs = cert_dir(tmp_path)
    manager = CertificateManager(certs, tmp_path)
    before = fingerprint(certs / "root-ca.pem")
    result = manager.prepare_worker("wazuh-manager03.local")
    after = fingerprint(certs / "root-ca.pem")
    assert before == after
    assert result["status"] == "INTEGRATION_VALIDATION_REQUIRED"


def test_preprovisioned_worker_certificate_ready(tmp_path):
    certs = cert_dir(tmp_path)
    (certs / "wazuh-manager03.local.pem").write_text("CERT", encoding="utf-8")
    (certs / "wazuh-manager03.local-key.pem").write_text("PRIVATE KEY", encoding="utf-8")
    manager = CertificateManager(certs, tmp_path)
    result = manager.prepare_worker("wazuh-manager03.local")
    assert result["status"] == "ready"
    assert result["certificate_ready"] is True


def test_existing_certs_not_overwritten(tmp_path):
    certs = cert_dir(tmp_path)
    manager = CertificateManager(certs, tmp_path)
    before = (certs / "wazuh-manager02.local.pem").read_text(encoding="utf-8")
    manager.prepare_worker("wazuh-manager03.local")
    assert (certs / "wazuh-manager02.local.pem").read_text(encoding="utf-8") == before


def test_dashboard_cert_not_modified(tmp_path):
    certs = cert_dir(tmp_path)
    manager = CertificateManager(certs, tmp_path)
    before = fingerprint(certs / "wazuh-dashboard01.local.pem")
    manager.prepare_worker("wazuh-manager03.local")
    assert fingerprint(certs / "wazuh-dashboard01.local.pem") == before


def test_missing_ca_blocks_prepare(tmp_path):
    certs = tmp_path / "certs"
    certs.mkdir()
    with pytest.raises(CertificateSafetyError):
        CertificateManager(certs, tmp_path).prepare_worker("wazuh-manager03.local")


def test_cleanup_by_transaction_id_only(tmp_path):
    certs = cert_dir(tmp_path)
    manager = CertificateManager(certs, tmp_path)
    result = manager.prepare_worker("wazuh-manager03.local")
    assert manager.cleanup_worker(result["transaction_id"])["removed_artifacts"] == []
    with pytest.raises(CertificateSafetyError):
        manager.cleanup_worker("manager03")


def test_unsafe_worker_name_rejected(tmp_path):
    certs = cert_dir(tmp_path)
    with pytest.raises(CertificateSafetyError):
        CertificateManager(certs, tmp_path).prepare_worker("../wazuh-manager03.local")


def test_cleanup_rejects_malformed_manifest(tmp_path):
    certs = cert_dir(tmp_path)
    tx_dir = tmp_path / "generated" / "certificate-transactions"
    tx_dir.mkdir(parents=True)
    (tx_dir / "cert-bad.json").write_text("{bad", encoding="utf-8")

    with pytest.raises(CertificateSafetyError, match="malformed certificate transaction manifest"):
        CertificateManager(certs, tmp_path).cleanup_worker("cert-bad")


def test_certificate_manifest_has_no_secret(tmp_path):
    certs = cert_dir(tmp_path)
    manager = CertificateManager(certs, tmp_path)
    result = manager.prepare_worker("wazuh-manager03.local")
    manifest = tmp_path / "generated" / "certificate-transactions" / f"{result['transaction_id']}.json"
    raw = manifest.read_text(encoding="utf-8")
    assert "SecretPassword" not in raw
    assert "PRIVATE KEY" not in raw
    assert "-key.pem" not in raw
