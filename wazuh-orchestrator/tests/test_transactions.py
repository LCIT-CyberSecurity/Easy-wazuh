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
