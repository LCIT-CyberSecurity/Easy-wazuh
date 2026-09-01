"""Read-only NGINX health checks."""

from __future__ import annotations

import re

import requests

from .models import NginxState


class NginxHealthClient:
    def __init__(self, health_url: str | None, stub_status_url: str | None = None, *, verify_tls: bool = True, timeout: int = 5, session: requests.Session | None = None):
        self.health_url = health_url
        self.stub_status_url = stub_status_url
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()

    def collect(self, name: str | None = None) -> NginxState:
        reachable = None
        healthy = None
        error = None
        if self.health_url:
            try:
                response = self.session.get(self.health_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)
                reachable = True
                healthy = 200 <= response.status_code < 400
            except requests.Timeout:
                reachable = False
                healthy = False
                error = "NGINX health check timed out."
            except requests.RequestException:
                reachable = False
                healthy = False
                error = "NGINX health check failed."

        active = None
        requests_count = None
        advanced = None
        if self.stub_status_url:
            try:
                response = self.session.get(self.stub_status_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)
                if 200 <= response.status_code < 400:
                    advanced = True
                    active, requests_count = parse_stub_status(response.text)
                else:
                    advanced = False
            except (requests.Timeout, requests.RequestException):
                advanced = False
        elif self.health_url:
            advanced = False

        return NginxState(
            name=name,
            reachable=reachable,
            healthy=healthy,
            active_connections=active,
            requests=requests_count,
            advanced_metrics_available=advanced,
            error=error,
        )


def parse_stub_status(text: str) -> tuple[int | None, int | None]:
    active = None
    requests_count = None
    active_match = re.search(r"Active connections:\s*([0-9]+)", text)
    if active_match:
        active = int(active_match.group(1))
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for index, line in enumerate(lines):
        if line.startswith("server accepts handled requests") and index + 1 < len(lines):
            parts = lines[index + 1].split()
            if len(parts) >= 3 and parts[2].isdigit():
                requests_count = int(parts[2])
            break
    return active, requests_count


def unknown_nginx_state(name: str | None) -> NginxState:
    return NginxState(name=name, reachable=None, healthy=None, advanced_metrics_available=None)
