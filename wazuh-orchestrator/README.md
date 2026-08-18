# Easy-Wazuh Orchestrator

V1 provides manual, controlled analysis and worker scaling preparation for Easy-Wazuh multi-node deployments.

It does not perform automatic scaling. The administrator must run:

```bash
python3 wazuh-orchestrator.py analyze
python3 wazuh-orchestrator.py plan --workers 3
python3 wazuh-orchestrator.py scale --workers 3 --yes
```

Use `--debug` to force DEBUG logs for one run. Other log levels are configured
in YAML:

```yaml
logging:
  level: INFO
```

Development and unit tests require no Docker daemon and no Wazuh installation. Real Docker, Wazuh API, certificate, NGINX and cluster-join validation is intentionally deferred to the integration checklist in `docs/integration-testing.md`.

The thresholds in `config/orchestrator.yaml.example` are Easy-Wazuh safety guardrails, not official Wazuh sizing recommendations.
