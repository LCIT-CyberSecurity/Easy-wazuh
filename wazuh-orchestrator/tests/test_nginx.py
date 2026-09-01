from __future__ import annotations

import requests

from wazuh_orchestrator.nginx import NginxHealthClient, parse_stub_status


class Response:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


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


def test_nginx_health_simple_without_stub_status():
    session = Session([Response(200)])
    state = NginxHealthClient("http://nginx/health", session=session).collect("nginx")

    assert state.reachable is True
    assert state.healthy is True
    assert state.advanced_metrics_available is False
    assert session.calls[0][1]["allow_redirects"] is False


def test_nginx_ko_is_explicit():
    state = NginxHealthClient("http://nginx/health", session=Session([requests.Timeout()])).collect("nginx")

    assert state.reachable is False
    assert state.healthy is False
    assert "timed out" in state.error


def test_stub_status_parsed_when_available():
    text = """Active connections: 3
server accepts handled requests
 10 10 42
Reading: 0 Writing: 1 Waiting: 2
"""
    assert parse_stub_status(text) == (3, 42)
    session = Session([Response(200), Response(200, text)])
    state = NginxHealthClient("http://nginx/health", "http://nginx/stub_status", session=session).collect("nginx")

    assert state.advanced_metrics_available is True
    assert state.active_connections == 3
    assert state.requests == 42


def test_stub_status_unavailable_keeps_simple_health():
    session = Session([Response(200), Response(404)])
    state = NginxHealthClient("http://nginx/health", "http://nginx/stub_status", session=session).collect("nginx")

    assert state.healthy is True
    assert state.advanced_metrics_available is False
