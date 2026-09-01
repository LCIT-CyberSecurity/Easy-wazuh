"""Small Wazuh API wrapper with safe error handling."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from .models import WazuhAPIError, WorkerMetrics


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

    def get_node_daemon_stats(self, node_id: str) -> dict[str, Any]:
        safe_node = quote(node_id, safe="")
        return self._get(f"/cluster/{safe_node}/daemons/stats")

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


def collect_worker_metrics(client: WazuhAPIClient, worker_names: tuple[str, ...], previous: tuple[WorkerMetrics, ...] = (), elapsed_seconds: float | None = None) -> tuple[WorkerMetrics, ...]:
    nodes_payload = _safe_api_call(client.get_nodes)
    previous_by_name = {worker.name: worker for worker in previous}
    workers: list[WorkerMetrics] = []
    for name in worker_names:
        node = _find_cluster_node(nodes_payload, name) if nodes_payload else None
        daemon_payload = _safe_api_call(lambda node_id=name: client.get_node_daemon_stats(node_id))
        metrics = _metrics_from_daemon_stats(daemon_payload or {})
        prev = previous_by_name.get(name)
        eps = _counter_rate(metrics.get("events_received"), prev.events_received if prev else None, elapsed_seconds)
        health = _node_health(node, daemon_payload)
        connected = _int(_first_present(node or {}, ("agents", "agent_count", "connected_agents", "agents_count")))
        workers.append(
            WorkerMetrics(
                name=name,
                eps=eps,
                events_received=metrics.get("events_received"),
                events_processed=metrics.get("events_processed"),
                queue_size=metrics.get("queue_size"),
                queue_usage_percent=metrics.get("queue_usage_percent"),
                queue_capacity=metrics.get("queue_capacity"),
                discarded_count=metrics.get("discarded_count"),
                dropped_count=metrics.get("dropped_count"),
                agent_count=connected,
                connected_agents=connected,
                cluster_sync_status=_cluster_sync_status(node),
                health=health,
            )
        )
    return tuple(workers)


def _safe_api_call(func):
    try:
        return func()
    except WazuhAPIError:
        return None


def _metrics_from_daemon_stats(payload: dict[str, Any]) -> dict[str, int | float | None]:
    items = _affected_items(payload)
    remoted = _daemon_item(items, "wazuh-remoted") or {}
    analysisd = _daemon_item(items, "wazuh-analysisd") or {}
    remoted_metrics = remoted.get("metrics") if isinstance(remoted.get("metrics"), dict) else {}
    analysisd_metrics = analysisd.get("metrics") if isinstance(analysisd.get("metrics"), dict) else {}

    received_breakdown = _dict_path(remoted_metrics, ("messages", "received_breakdown"))
    sent_breakdown = _dict_path(remoted_metrics, ("messages", "sent_breakdown"))
    received_queue = _dict_path(remoted_metrics, ("queues", "received"))
    analysis_queue = _first_dict_path(analysisd_metrics, (("queues", "events"), ("queues", "analysis"), ("queue",)))

    events_received = _sum_known(
        _int(received_breakdown.get("event")),
        _int(received_breakdown.get("events")),
        _recursive_int(remoted_metrics, ("evt_count", "events_received", "received_events")),
    )
    events_processed = _sum_known(
        _recursive_int(analysisd_metrics, ("events_processed", "processed_events", "total_events_decoded", "events_decoded")),
    )
    discarded = _sum_known(_int(received_breakdown.get("discarded")), _int(sent_breakdown.get("discarded")), _recursive_int(remoted_metrics, ("discarded_count",)))
    dropped = _sum_known(_recursive_int(remoted_metrics, ("dropped", "dropped_count", "rejected", "rejected_count")), _recursive_int(analysisd_metrics, ("dropped", "dropped_count", "rejected", "rejected_count")))
    queue_capacity = _int(received_queue.get("size")) or _int(analysis_queue.get("size"))
    queue_usage = _float(received_queue.get("usage"))
    queue_size = _int(received_queue.get("current")) or _int(received_queue.get("queue_size")) or _int(analysis_queue.get("usage")) or _int(analysis_queue.get("current"))

    return {
        "events_received": events_received,
        "events_processed": events_processed,
        "queue_size": queue_size,
        "queue_usage_percent": queue_usage if queue_usage is not None and 0 <= queue_usage <= 100 else None,
        "queue_capacity": queue_capacity,
        "discarded_count": discarded,
        "dropped_count": dropped,
    }


def _affected_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    data = payload.get("data") if isinstance(payload, dict) else None
    items = data.get("affected_items") if isinstance(data, dict) else None
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _daemon_item(items: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for item in items:
        if item.get("name") == name:
            return item
    return None


def _node_health(node: dict[str, Any] | None, daemon_payload: dict[str, Any] | None) -> str | None:
    if node is None and daemon_payload is None:
        return None
    status = str(_first_present(node or {}, ("status", "Status", "health")) or "").lower()
    if status in {"active", "connected", "ready", "healthy"}:
        return "healthy"
    if status:
        return status
    return "healthy" if daemon_payload else None


def _cluster_sync_status(node: dict[str, Any] | None) -> str | None:
    if not node:
        return None
    value = _first_present(node, ("sync_status", "synchronization", "sync"))
    if isinstance(value, dict):
        value = _first_present(value, ("status", "integrity", "agent-info", "agent_info"))
    return str(value) if value not in (None, "") else None


def _first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _dict_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return {}
        value = value.get(key)
    return value if isinstance(value, dict) else {}


def _first_dict_path(data: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> dict[str, Any]:
    for path in paths:
        value = _dict_path(data, path)
        if value:
            return value
    return {}


def _recursive_int(data: Any, keys: tuple[str, ...]) -> int | None:
    if isinstance(data, dict):
        for key in keys:
            value = _int(data.get(key))
            if value is not None:
                return value
        for value in data.values():
            found = _recursive_int(value, keys)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _recursive_int(value, keys)
            if found is not None:
                return found
    return None


def _sum_known(*values: int | None) -> int | None:
    known = [value for value in values if value is not None]
    return sum(known) if known else None


def _counter_rate(current: int | None, previous: int | None, elapsed_seconds: float | None) -> float | None:
    if current is None or previous is None or elapsed_seconds is None or elapsed_seconds <= 0:
        return None
    if current < previous:
        return None
    return (current - previous) / elapsed_seconds


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
