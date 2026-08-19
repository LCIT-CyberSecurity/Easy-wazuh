# Security

The orchestrator follows fail-closed behavior: unknown topology, ambiguous naming, config drift, low confidence, host pressure, indexer pressure, Dashboard pressure, degraded cluster, degraded NGINX and incomplete transactions all block worker scale-up.

Protections implemented in V1:

- no autoscaling, daemon or cron
- no `--force` and no `--yes`
- one worker delta per operation
- baseline and max worker enforcement
- no `shell=True` for Compose commands
- no Docker daemon required for tests
- no volume deletion during scale-down
- lock with `fcntl.flock`
- secret redaction for audit logs
- transaction manifests without secrets
- certificate helper does not regenerate, overwrite or delete CA/baseline certs
- cleanup uses transaction manifests, never name heuristics

Mounting `/var/run/docker.sock` into a future containerized run gives high privilege over the Docker host. Treat it as administrative access.

Dashboard certificate customization is outside V1. The orchestrator does not replace Dashboard private keys or Dashboard TLS paths.
