# Security

The orchestrator follows fail-closed behavior:

- no autoscaling in V1
- no `--force` escape hatch
- no `shell=True` for Compose commands
- no Docker daemon required for tests
- no database or network service
- baseline workers are protected
- existing volumes are never deleted by V1 code
- secrets are redacted before audit logging
- low-confidence analysis blocks scaling
- host pressure and indexer pressure block worker scale-up

Mounting `/var/run/docker.sock` into a future containerized orchestrator gives the container very high privilege over the Docker host. Treat it as equivalent to administrative control of the host.

`INTEGRATION_VALIDATION_REQUIRED`: real NGINX validation, Wazuh cluster join, Docker health checks and certificate generation must be tested on the integration machine.
