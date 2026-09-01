# Security

The orchestrator follows least privilege for V1:

- no `/var/run/docker.sock` mount
- no Docker group membership requirement
- no root requirement for normal operation
- no `docker stats` dependency
- no autoscaling, daemon or cron
- no live worker creation/removal from CLI or Python `scale()`
- no `--force` and no `--yes`
- no secrets in transaction manifests or audit logs
- no redirects followed on API calls
- HTTP timeouts on Wazuh API, Wazuh Indexer API and NGINX checks
- HTTPS-only URLs for Wazuh API and Wazuh Indexer API configuration

Unknown is not healthy. Missing API fields, null values, timeouts, unavailable nodes and incomplete JSON are represented as unknown or degraded data and must not be converted to a healthy state.

Wazuh API credentials and Wazuh Indexer credentials should use read-only accounts where Wazuh permits it. The code must not log passwords, bearer tokens, Authorization headers, private keys or generated cluster secrets.

The Dockerfile runs the application as an unprivileged user. Containerized operation should mount only the configuration/secrets needed for read-only API access and, optionally, deployment metadata/Compose files for declared topology discovery.

When host CPU/RAM/IO metrics are unavailable, manager pressure can still produce `SCALE_RECOMMENDED`, but the result includes `HOST_CAPACITY_UNKNOWN`. This prevents a false claim that another worker on the same host will solve the issue.

Future integrations with Prometheus, Zabbix or Centreon are out of scope for V1. They should be added through a minimal metrics provider abstraction without weakening the default `none` behavior.
