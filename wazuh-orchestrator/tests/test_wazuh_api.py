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
