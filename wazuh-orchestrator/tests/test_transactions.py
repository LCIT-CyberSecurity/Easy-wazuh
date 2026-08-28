from __future__ import annotations

import json

import pytest

from wazuh_orchestrator.models import ScalingError
from wazuh_orchestrator.transactions import TransactionStore


def test_transaction_manifest_lifecycle(tmp_path):
    store = TransactionStore(tmp_path)
    tx = store.create("scale_up", "wazuh-manager03.local")
    assert store.incomplete()[0].transaction_id == tx.transaction_id
    tx = store.advance(tx, "WORKER_STARTED", container_started=True)
    assert tx.flags["container_started"] is True
    store.advance(tx, "SUCCESS")
    assert store.incomplete() == ()


def test_incomplete_reconciliation_is_read_only(tmp_path):
    store = TransactionStore(tmp_path)
    tx = store.create("scale_up", "wazuh-manager03.local")
    state = store.reconcile_read_only()
    assert state["incomplete_transaction"] is True
    assert tx.transaction_id in state["transaction_ids"]


def test_transaction_manifest_has_no_plain_secret(tmp_path):
    store = TransactionStore(tmp_path)
    tx = store.create("scale_up", "wazuh-manager03.local")
    store.save(tx)
    content = next((tmp_path / "generated" / "transactions").glob("*.json")).read_text(encoding="utf-8")
    assert "SecretPassword" not in content
    assert "private" not in content.lower()


def test_malformed_transaction_rejected(tmp_path):
    path = tmp_path / "generated" / "transactions" / "bad.json"
    path.parent.mkdir(parents=True)
    path.write_text("{bad", encoding="utf-8")
    with pytest.raises(ScalingError):
        TransactionStore(tmp_path).incomplete()


def test_reconciliation_compares_observable_state(tmp_path):
    store = TransactionStore(tmp_path)
    tx = store.create("scale_up", "wazuh-manager03.local")
    tx = store.advance(tx, "WORKER_STARTED", container_started=True)
    compose = tmp_path / "generated" / "docker-compose.orchestrator.yml"
    compose.write_text("services:\n  wazuh-manager03.local:\n    image: wazuh/wazuh-manager\n", encoding="utf-8")
    nginx = tmp_path / "nginx.conf"
    nginx.write_text("upstream wazuh_managers {\n    server wazuh-manager03.local:1514;\n}\n", encoding="utf-8")
    certs = tmp_path / "certs"
    certs.mkdir()
    (certs / "wazuh-manager03.local.pem").write_text("CERT", encoding="utf-8")
    (certs / "wazuh-manager03.local-key.pem").write_text("KEY", encoding="utf-8")

    state = store.reconcile_read_only(
        desired_compose=compose,
        docker_workers=("wazuh-manager03.local",),
        cluster_workers=("wazuh-manager03.local",),
        nginx_config=nginx,
        cert_dir=certs,
    )

    assert state["manual_intervention_required"] is True
    obs = state["observations"][0]
    assert obs["transaction_id"] == tx.transaction_id
    assert obs["in_desired_compose"] is True
    assert obs["in_docker"] is True
    assert obs["in_wazuh_cluster"] is True
    assert obs["in_nginx"] is True
    assert obs["has_certificate_artifacts"] is True


def test_reconciliation_rejects_malformed_desired_compose(tmp_path):
    store = TransactionStore(tmp_path)
    store.create("scale_up", "wazuh-manager03.local")
    compose = tmp_path / "bad.yml"
    compose.write_text("services: [", encoding="utf-8")
    with pytest.raises(ScalingError, match="Malformed desired Compose"):
        store.reconcile_read_only(desired_compose=compose)
