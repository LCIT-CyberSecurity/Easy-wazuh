"""Read-only Wazuh Indexer API collection."""

from __future__ import annotations

from typing import Any

import requests

from .models import IndexerState, WazuhAPIError


class IndexerAPIClient:
    def __init__(self, base_url: str, username: str | None = None, password: str | None = None, *, verify_tls: bool = True, timeout: int = 10, session: requests.Session | None = None):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = session or requests.Session()

    def cluster_health(self) -> dict[str, Any]:
        return self._get("/_cluster/health")

    def cluster_stats(self) -> dict[str, Any]:
        return self._get("/_cluster/stats")

    def nodes_stats(self) -> dict[str, Any]:
        return self._get("/_nodes/stats/jvm,fs,thread_pool,indices")

    def pending_tasks(self) -> dict[str, Any]:
        return self._get("/_cluster/pending_tasks")

    def _get(self, path: str) -> dict[str, Any]:
        try:
            response = self.session.get(
                f"{self.base_url}{path}",
                auth=(self.username, self.password) if self.username or self.password else None,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise WazuhAPIError(f"Wazuh Indexer API request timed out: {path}") from exc
        except requests.RequestException as exc:
            raise WazuhAPIError(f"Wazuh Indexer API request failed: {path}") from exc
        if response.status_code in (401, 403):
            raise WazuhAPIError("Wazuh Indexer API rejected credentials.")
        if response.status_code >= 400:
            raise WazuhAPIError(f"Wazuh Indexer API request returned HTTP {response.status_code}: {path}")
        return _json(response)


def collect_indexer_state(client: IndexerAPIClient, names: tuple[str, ...] = (), previous: IndexerState | None = None, elapsed_seconds: float | None = None) -> IndexerState:
    try:
        health = client.cluster_health()
        stats = client.cluster_stats()
        nodes = client.nodes_stats()
        pending = client.pending_tasks()
    except WazuhAPIError:
        raise

    status = _str(health.get("status") or stats.get("status"))
    node_count = _int(health.get("number_of_nodes")) or _nested_int(stats, ("_nodes", "total"))
    active_shards = _int(health.get("active_shards")) or _nested_int(stats, ("indices", "shards", "total"))
    unassigned_shards = _int(health.get("unassigned_shards"))
    pending_tasks = _int(health.get("number_of_pending_tasks"))
    if pending_tasks is None:
        tasks = pending.get("tasks")
        pending_tasks = len(tasks) if isinstance(tasks, list) else None

    indexing_total = _nested_int(stats, ("indices", "indexing", "index_total"))
    rejected = _sum_thread_pool_rejections(nodes)
    fs_free_percent = _fs_free_percent(nodes)
    heap = _max_nested_percent(nodes, ("nodes",), "jvm", "mem", "heap_used_percent")
    indexing_rate = _rate(indexing_total, previous.indexing_total if previous else None, elapsed_seconds)
    healthy = None if status is None else status.lower() in {"green", "yellow"}
    return IndexerState(
        names=names,
        healthy=healthy,
        disk_free_percent=fs_free_percent,
        health_status=status,
        node_count=node_count,
        active_shards=active_shards,
        unassigned_shards=unassigned_shards,
        pending_tasks=pending_tasks,
        indexing_total=indexing_total,
        indexing_rate=indexing_rate,
        rejected_operations=rejected,
        fs_free_percent=fs_free_percent,
        heap_used_percent=heap,
    )


def unavailable_indexer_state(names: tuple[str, ...]) -> IndexerState:
    return IndexerState(names=names, healthy=None, unavailable=True)


def _json(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise WazuhAPIError("Wazuh Indexer API returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise WazuhAPIError("Wazuh Indexer API returned an unexpected response shape.")
    return payload


def _nested_int(data: dict[str, Any], path: tuple[str, ...]) -> int | None:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return _int(value)


def _sum_thread_pool_rejections(nodes: dict[str, Any]) -> int | None:
    node_map = nodes.get("nodes")
    if not isinstance(node_map, dict):
        return None
    total = 0
    seen = False
    for node in node_map.values():
        pools = node.get("thread_pool") if isinstance(node, dict) else None
        if not isinstance(pools, dict):
            continue
        for name in ("write", "index", "bulk", "search"):
            rejected = _nested_int(pools, (name, "rejected"))
            if rejected is not None:
                total += rejected
                seen = True
    return total if seen else None


def _fs_free_percent(nodes: dict[str, Any]) -> float | None:
    node_map = nodes.get("nodes")
    if not isinstance(node_map, dict):
        return None
    total_bytes = 0
    available_bytes = 0
    for node in node_map.values():
        fs_total = _nested_int(node, ("fs", "total", "total_in_bytes")) if isinstance(node, dict) else None
        fs_available = _nested_int(node, ("fs", "total", "available_in_bytes")) if isinstance(node, dict) else None
        if fs_total is None or fs_available is None or fs_total <= 0:
            continue
        total_bytes += fs_total
        available_bytes += fs_available
    if total_bytes <= 0:
        return None
    return available_bytes / total_bytes * 100


def _max_nested_percent(data: dict[str, Any], root_path: tuple[str, ...], *leaf: str) -> float | None:
    value: Any = data
    for key in root_path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    if not isinstance(value, dict):
        return None
    vals = []
    for item in value.values():
        raw: Any = item
        for key in leaf:
            if not isinstance(raw, dict):
                raw = None
                break
            raw = raw.get(key)
        num = _float(raw)
        if num is not None:
            vals.append(num)
    return max(vals) if vals else None


def _rate(current: int | None, previous: int | None, elapsed_seconds: float | None) -> float | None:
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


def _str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None
