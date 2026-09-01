from __future__ import annotations

import requests
import pytest

from wazuh_orchestrator.indexer_api import IndexerAPIClient, collect_indexer_state
from wazuh_orchestrator.models import IndexerState, WazuhAPIError


class Response:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        if self._payload == "bad":
            raise ValueError
        return self._payload


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def nodes_stats(rejected=0, free=900, total=1000, heap=30):
    return {
        "nodes": {
            "node-a": {
                "thread_pool": {"write": {"rejected": rejected}},
                "fs": {"total": {"available_in_bytes": free, "total_in_bytes": total}},
                "jvm": {"mem": {"heap_used_percent": heap}},
            }
        }
    }


def test_collect_indexer_state_healthy():
    session = Session([
        Response(200, {"status": "green", "number_of_nodes": 3, "active_shards": 12, "unassigned_shards": 0, "number_of_pending_tasks": 0}),
        Response(200, {"indices": {"indexing": {"index_total": 1000}}}),
        Response(200, nodes_stats()),
        Response(200, {"tasks": []}),
    ])
    state = collect_indexer_state(IndexerAPIClient("https://indexer:9200", "u", "p", session=session), ("i1",))

    assert state.healthy is True
    assert state.health_status == "green"
    assert state.node_count == 3
    assert state.rejected_operations == 0
    assert state.fs_free_percent == 90
    assert all(call[1]["allow_redirects"] is False for call in session.calls)


def test_collect_indexer_state_pressure_and_indexing_rate():
    session = Session([
        Response(200, {"status": "red", "number_of_nodes": 2, "active_shards": 10, "unassigned_shards": 3, "number_of_pending_tasks": 4}),
        Response(200, {"indices": {"indexing": {"index_total": 1300}}}),
        Response(200, nodes_stats(rejected=5, free=50, total=1000, heap=91)),
        Response(200, {"tasks": [{"x": 1}]}),
    ])
    state = collect_indexer_state(IndexerAPIClient("https://indexer:9200", session=session), ("i1",), IndexerState(indexing_total=1000), 10)

    assert state.healthy is False
    assert state.indexing_rate == 30
    assert state.rejected_operations == 5
    assert state.fs_free_percent == 5
    assert state.heap_used_percent == 91


def test_indexer_timeout_is_safe_error():
    with pytest.raises(WazuhAPIError):
        IndexerAPIClient("https://indexer:9200", session=Session([requests.Timeout()])).cluster_health()
