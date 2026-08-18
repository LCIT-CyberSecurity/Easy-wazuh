from __future__ import annotations

import requests
import pytest

from wazuh_orchestrator.wazuh_api import WazuhAPIClient
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
    def get(self, *args, **kwargs):
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(responses):
    return WazuhAPIClient("https://wazuh:55000", "u", "p", session=Session(responses))


def test_api_saine():
    c = client([Response(200, {"data": {"token": "t"}}), Response(200, {"data": {"enabled": "yes"}})])
    assert c.get_cluster_state()["data"]["enabled"] == "yes"


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
