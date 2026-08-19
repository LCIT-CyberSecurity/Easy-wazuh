# Architecture

`easy-wazuh-bootstrap.sh` performs the initial Easy-Wazuh installation only: initial topology, Wazuh configuration, certificates, NGINX configuration, naming and deployment metadata. It is not a resize tool.

`wazuh-orchestrator` is a post-install manual tool for Easy-Wazuh multi-node deployments. V1 scales only Wazuh Manager workers. The Wazuh Manager master is fixed, Indexers are monitored only, and exactly one Dashboard is supported and monitored only.

Core modules:

- `discovery.py`: deployment metadata, Compose topology and conservative legacy discovery.
- `naming.py`: prefix, padding, FQDN suffix, monotonic worker numbering and collision validation.
- `metrics.py` / `wazuh_api.py`: host/container/Wazuh signal collection behind mockable interfaces.
- `analyzer.py`: diagnostics, confidence, capacity recommendation and host safety projection.
- `scaler.py`: preconditions, lock, transaction workflow and rollback coordination.
- `transactions.py`: secret-free transaction manifests and read-only reconciliation.
- `backends/compose.py`: Compose command construction, desired-state override and targeted NGINX updates.

Easy-Wazuh metadata is expected at `/opt/wazuh/easy-wazuh/deployment.yaml`. It records the installed identity and must not be silently rewritten. Drift blocks scaling.

The Compose override is desired state, not history. A removed worker must disappear from `generated/docker-compose.orchestrator.yml` so a future Compose operation cannot resurrect it.

Dashboard browser certificate customization is manual/admin-managed and outside V1. Worker scaling must not modify Dashboard TLS, Dashboard FQDN or Dashboard instance count.

`INTEGRATION_VALIDATION_REQUIRED`: real worker certificate generation, Docker health, Wazuh cluster join and NGINX validation require the future Docker/Wazuh integration host.
