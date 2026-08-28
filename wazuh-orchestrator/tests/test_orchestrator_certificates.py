from __future__ import annotations

import json

import pytest

from wazuh_orchestrator.certificates import PreprovisionedCertificatePreparer, fingerprint
from wazuh_orchestrator.models import ScalingError


def cert_dir(tmp_path):
    p = tmp_path / "certs"
    p.mkdir()
    (p / "root-ca.pem").write_text("CA", encoding="utf-8")
    (p / "wazuh-manager02.local.pem").write_text("EXISTING", encoding="utf-8")
    (p / "wazuh-dashboard01.local.pem").write_text("DASHBOARD", encoding="utf-8")
    return p


def test_preprovisioned_worker_certificates_allow_prepare(tmp_path):
    certs = cert_dir(tmp_path)
    (certs / "wazuh-manager03.local.pem").write_text("CERT", encoding="utf-8")
    (certs / "wazuh-manager03.local-key.pem").write_text("KEY", encoding="utf-8")
    before_ca = fingerprint(certs / "root-ca.pem")
    result = PreprovisionedCertificatePreparer(certs, tmp_path).prepare_worker("wazuh-manager03.local", "tx-1")
    assert result["certificate_ready"] is True
    assert result["transaction_id"] == "cert-tx-1"
    assert fingerprint(certs / "root-ca.pem") == before_ca


def test_missing_worker_key_blocks_prepare(tmp_path):
    certs = cert_dir(tmp_path)
    (certs / "wazuh-manager03.local.pem").write_text("CERT", encoding="utf-8")
    with pytest.raises(ScalingError, match="wazuh-manager03.local-key.pem"):
        PreprovisionedCertificatePreparer(certs, tmp_path).prepare_worker("wazuh-manager03.local", "tx-1")


def test_preprovisioned_manifest_has_no_secret_material(tmp_path):
    certs = cert_dir(tmp_path)
    (certs / "wazuh-manager03.local.pem").write_text("CERT", encoding="utf-8")
    (certs / "wazuh-manager03.local-key.pem").write_text("PRIVATE KEY", encoding="utf-8")
    result = PreprovisionedCertificatePreparer(certs, tmp_path).prepare_worker("wazuh-manager03.local", "tx-1")
    manifest = tmp_path / "generated" / "certificate-transactions" / f"{result['transaction_id']}.json"
    raw = manifest.read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in raw
    assert "-key.pem" not in raw
    assert json.loads(raw)["created_artifacts"] == []


def test_preprovisioned_cleanup_rejects_name_heuristics(tmp_path):
    certs = cert_dir(tmp_path)
    with pytest.raises(ScalingError):
        PreprovisionedCertificatePreparer(certs, tmp_path).cleanup_worker("manager03")


def test_preprovisioned_cleanup_rejects_malformed_manifest(tmp_path):
    certs = cert_dir(tmp_path)
    tx_dir = tmp_path / "generated" / "certificate-transactions"
    tx_dir.mkdir(parents=True)
    (tx_dir / "cert-bad.json").write_text("{bad", encoding="utf-8")

    with pytest.raises(ScalingError, match="malformed certificate transaction manifest"):
        PreprovisionedCertificatePreparer(certs, tmp_path).cleanup_worker("cert-bad")
