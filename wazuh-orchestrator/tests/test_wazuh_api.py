from __future__ import annotations

import requests
import pytest

from wazuh_orchestrator.wazuh_api import WazuhAPIClient, WazuhClusterValidator, cluster_status_healthy
from wazuh_orchestrator.models import WazuhAPIError


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


def client(responses):
    return WazuhAPIClient("https://wazuh:55000", "u", "p", session=Session(responses))


def test_api_saine():
    c = client([Response(200, {"data": {"token": "t"}}), Response(200, {"data": {"enabled": "yes"}})])
    assert c.get_cluster_state()["data"]["enabled"] == "yes"


def test_api_requests_do_not_follow_redirects():
    session = Session([Response(200, {"data": {"token": "t"}}), Response(200, {"data": {"enabled": "yes"}})])
    c = WazuhAPIClient("https://wazuh:55000", "u", "p", session=session)
    c.get_cluster_state()

    assert all(call[1]["allow_redirects"] is False for call in session.calls)


def test_timeout():
    with pytest.raises(WazuhAPIError):
        client([requests.Timeout()]).authenticate()


def test_auth_failure():
    with pytest.raises(WazuhAPIError):
        client([Response(401, {})]).authenticate()


def test_reponse_partielle():
    with pytest.raises(WazuhAPIError):
        client([Response(200, {"data": {}})]).authenticate()


def test_cluster_degraded_response_is_returned():
    c = client([Response(200, {"data": {"token": "t"}}), Response(200, {"data": {"running": "no"}})])
    assert c.get_cluster_state()["data"]["running"] == "no"


def test_cluster_validator_accepts_joined_worker():
    c = client([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"affected_items": [{"name": "wazuh-manager03.local", "status": "active"}]}}),
    ])
    WazuhClusterValidator(c).verify_cluster_join("wazuh-manager03.local")


def test_cluster_validator_rejects_missing_worker():
    c = client([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"affected_items": []}}),
    ])
    with pytest.raises(WazuhAPIError, match="not reported"):
        WazuhClusterValidator(c).verify_cluster_join("wazuh-manager03.local")


def test_cluster_validator_rejects_degraded_final_state():
    c = client([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"enabled": "yes", "running": "no"}}),
    ])
    with pytest.raises(WazuhAPIError, match="not running"):
        WazuhClusterValidator(c).final_validate_cluster()


def test_cluster_status_healthy_handles_malformed_payload():
    assert cluster_status_healthy({"data": []}) is False


def daemon_stats(events=1000, queue_usage=10, discarded=0, dropped=0):
    return {
        "data": {
            "affected_items": [
                {
                    "name": "wazuh-remoted",
                    "metrics": {
                        "messages": {
                            "received_breakdown": {"event": events, "discarded": discarded},
                            "sent_breakdown": {"discarded": 0},
                        },
                        "queues": {"received": {"size": 131072, "usage": queue_usage}},
                        "dropped_count": dropped,
                    },
                },
                {"name": "wazuh-analysisd", "metrics": {"events_processed": events - discarded}},
            ]
        }
    }


def test_collect_worker_metrics_uses_cluster_daemon_stats_endpoint():
    session = Session([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"affected_items": [{"name": "wazuh-manager02.local", "status": "active", "agents": 42, "sync_status": "synced"}]}}),
        Response(200, daemon_stats(events=1200, queue_usage=80, discarded=2)),
    ])
    c = WazuhAPIClient("https://wazuh:55000", "u", "p", session=session)
    from wazuh_orchestrator.wazuh_api import collect_worker_metrics

    metrics = collect_worker_metrics(c, ("wazuh-manager02.local",))

    assert metrics[0].events_received == 1200
    assert metrics[0].queue_usage_percent == 80
    assert metrics[0].discarded_count == 2
    assert metrics[0].connected_agents == 42
    assert any("/cluster/wazuh-manager02.local/daemons/stats" in call[0][0] for call in session.calls)


def test_collect_worker_metrics_eps_requires_valid_delta():
    from wazuh_orchestrator.wazuh_api import collect_worker_metrics
    from wazuh_orchestrator.models import WorkerMetrics

    c = client([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"affected_items": []}}),
        Response(200, daemon_stats(events=1300)),
    ])
    metrics = collect_worker_metrics(c, ("wazuh-manager02.local",), (WorkerMetrics("wazuh-manager02.local", events_received=1000),), 10)
    assert metrics[0].eps == 30


def test_collect_worker_metrics_counter_reset_returns_unknown_eps():
    from wazuh_orchestrator.wazuh_api import collect_worker_metrics
    from wazuh_orchestrator.models import WorkerMetrics

    c = client([
        Response(200, {"data": {"token": "t"}}),
        Response(200, {"data": {"affected_items": []}}),
        Response(200, daemon_stats(events=100)),
    ])
    metrics = collect_worker_metrics(c, ("wazuh-manager02.local",), (WorkerMetrics("wazuh-manager02.local", events_received=1000),), 10)
    assert metrics[0].eps is None
