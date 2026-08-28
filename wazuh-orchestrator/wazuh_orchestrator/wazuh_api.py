"""Small Wazuh API wrapper with safe error handling."""

from __future__ import annotations

from typing import Any

import requests

from .models import WazuhAPIError


class WazuhAPIClient:
    def __init__(self, base_url: str, username: str, password: str, *, verify_tls: bool = True, timeout: int = 10, session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()
        self._token: str | None = None

    def authenticate(self) -> str:
        try:
            response = self.session.get(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise WazuhAPIError("Wazuh API authentication timed out.") from exc
        except requests.RequestException as exc:
            raise WazuhAPIError("Wazuh API authentication failed.") from exc
        if response.status_code in (401, 403):
            raise WazuhAPIError("Wazuh API authentication rejected credentials.")
        if response.status_code >= 400:
            raise WazuhAPIError(f"Wazuh API authentication returned HTTP {response.status_code}.")
        payload = _json(response)
        token = payload.get("data", {}).get("token") if isinstance(payload.get("data"), dict) else None
        if not token:
            raise WazuhAPIError("Wazuh API authentication response did not contain a token.")
        self._token = str(token)
        return self._token

    def get_cluster_state(self) -> dict[str, Any]:
        return self._get("/cluster/status")

    def get_nodes(self) -> dict[str, Any]:
        return self._get("/cluster/nodes")

    def get_stats(self) -> dict[str, Any]:
        return self._get("/manager/stats")

    def _get(self, path: str) -> dict[str, Any]:
        token = self._token or self.authenticate()
        try:
            response = self.session.get(
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise WazuhAPIError(f"Wazuh API request timed out: {path}") from exc
        except requests.RequestException as exc:
            raise WazuhAPIError(f"Wazuh API request failed: {path}") from exc
        if response.status_code >= 400:
            raise WazuhAPIError(f"Wazuh API request returned HTTP {response.status_code}: {path}")
        return _json(response)


def _json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise WazuhAPIError("Wazuh API returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise WazuhAPIError("Wazuh API returned an unexpected response shape.")
    return payload


class WazuhClusterValidator:
    """Validate Wazuh cluster state through the existing Wazuh API client."""

    def __init__(self, client: WazuhAPIClient):
        self.client = client

    def verify_cluster_join(self, worker_name: str) -> None:
        node = _find_cluster_node(self.client.get_nodes(), worker_name)
        if node is None:
            raise WazuhAPIError(f"Wazuh cluster join validation failed: {worker_name} was not reported by the Wazuh API.")
        status = str(node.get("status") or node.get("Status") or "").lower()
        if status and status not in {"active", "connected", "ready"}:
            raise WazuhAPIError(f"Wazuh cluster join validation failed for {worker_name}: {status}")

    def final_validate_cluster(self) -> None:
        if not cluster_status_healthy(self.client.get_cluster_state()):
            raise WazuhAPIError("Wazuh cluster validation failed: cluster is not running.")


def cluster_status_healthy(payload: dict[str, Any]) -> bool:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return False
    enabled = str(data.get("enabled") or data.get("cluster_enabled") or "yes").lower()
    running = str(data.get("running") or data.get("cluster_running") or "yes").lower()
    return enabled not in {"no", "false", "disabled", "0"} and running not in {"no", "false", "disabled", "0"}


def _find_cluster_node(payload: dict[str, Any], worker_name: str) -> dict[str, Any] | None:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return None
    items = data.get("affected_items") or data.get("items") or data.get("nodes")
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("node_name") or item.get("Name") or "")
        if name == worker_name:
            return item
    return None
