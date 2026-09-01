# Architecture

`easy-wazuh-bootstrap.sh` performs the initial Easy-Wazuh installation only: initial topology, Wazuh configuration, certificates, NGINX configuration, naming and deployment metadata. It is not a resize tool.

`wazuh-orchestrator` V1 is a post-install read-only diagnostic tool for Easy-Wazuh multi-node deployments. It keeps the existing flow:

```text
discovery -> snapshot -> analyzer -> plan/recommendation
```

Discovery reads deployment metadata and Compose files when available. It does not claim Docker runtime state when Docker Engine is not queried. Runtime observations are collected from Wazuh API, Wazuh Indexer API and NGINX HTTP health checks.

Core modules:

- `discovery.py`: deployment metadata, Compose topology and conservative legacy discovery.
- `wazuh_api.py`: Wazuh API authentication, cluster status and per-node daemon stats using `/cluster/{node_id}/daemons/stats`.
- `indexer_api.py`: read-only Indexer health, cluster stats, node stats, shard/task/reject/storage/JVM signals.
- `nginx.py`: read-only HTTP health and optional `stub_status` parsing.
- `metrics.py`: optional non-privileged local host metrics only when configured.
- `analyzer.py`: OK/WATCH/SCALE_RECOMMENDED/UNKNOWN/INDEXER_PRESSURE recommendation logic.
- `scaler.py`: read-only plan building; live `scale()` execution is disabled in V1.
- `transactions.py`: secret-free transaction manifests and read-only reconciliation for previous/future operations.
- `backends/compose.py`: desired-state and NGINX mutation helpers kept for future validation, but not called by the V1 CLI scale path.

V1 differentiates two questions. First, Wazuh manager pressure is evaluated through queues, queue growth, dropped/discarded events, EPS when valid counter deltas exist, agent distribution, node health and cluster synchronization. Second, host capacity is evaluated only when non-privileged host metrics are explicitly available. Unknown host capacity does not hide manager pressure; it is reported as `HOST_CAPACITY_UNKNOWN`.

Indexer pressure is a separate outcome. Indexer rejects, red health, unassigned shards, pending tasks, low storage and high JVM heap produce `INDEXER_PRESSURE`; the orchestrator must not recommend a manager worker as the default fix for those symptoms.

V1 recommends only one progressive step: current workers -> current workers + 1, then re-analysis after stabilization. It does not calculate arbitrary final worker counts.

Easy-Wazuh metadata is expected at `/opt/wazuh/easy-wazuh/deployment.yaml`. It records the installed identity and must not be silently rewritten. The baseline remains one master, one worker, three indexers, one dashboard and one NGINX service.
