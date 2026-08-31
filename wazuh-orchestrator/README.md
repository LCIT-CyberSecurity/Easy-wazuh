# Easy-Wazuh Orchestrator

Beta manual monitoring tool for Easy-Wazuh multi-node deployments. It analyzes capacity and builds read-only worker scaling plans, but it does not modify the live deployment.

Supported in V1:

- Easy-Wazuh multi-node deployments recognized from `deployment.yaml` or conservative legacy discovery
- exactly one Wazuh Manager master
- N Wazuh Manager workers, monitored against baseline and max
- exactly one Wazuh Dashboard, monitored only
- Wazuh Indexers monitored only
- existing Easy-Wazuh NGINX/load balancer only

Not supported in V1:

- autoscaling
- live worker scaling from the CLI
- single-node orchestration or migration to multi-node
- multi-host orchestration
- Dashboard horizontal scaling
- Indexer scaling
- Dashboard certificate customization

## CLI

```bash
python3 wazuh-orchestrator.py status
python3 wazuh-orchestrator.py analyze
python3 wazuh-orchestrator.py analyze --duration 120
python3 wazuh-orchestrator.py plan --workers 3
# Disabled in beta monitoring mode:
# python3 wazuh-orchestrator.py scale --workers 3
```

`status` and `analyze` support `--json`. Use global `--debug` to force DEBUG logs for one run; otherwise configure `logging.level` in YAML.

`plan` is the manual read-only check for a possible worker count change. In beta monitoring mode, `scale` is intentionally disabled: it prints the same plan context, exits with an error, and does not prompt for confirmation or modify Docker, NGINX, certificates, transactions, or live infrastructure.

## Configuration

Copy `config/orchestrator.yaml.example` and adjust thresholds. Defaults are Easy-Wazuh conservative guardrails, not official universal Wazuh sizing recommendations.

The bootstrap persists deployment identity at `/opt/wazuh/easy-wazuh/deployment.yaml`. The orchestrator reads and validates this file, then compares it with actual Compose state. Important drift blocks scaling. Wazuh API credentials are used only for cluster health and join validation and are never printed in CLI output or audit logs.

## Local Development

Development and unit tests require no Docker daemon, no Wazuh installation, no root and no Internet. Docker, Wazuh API, NGINX and certificate behavior are mocked or represented by synthetic fixtures.

```bash
python3 -m pytest
python3 -m compileall wazuh-orchestrator/
python3 -m compileall wazuh-certificates/
bash -n easy-wazuh-bootstrap.sh
bash -n wazuh-orchestrator-installer.sh
git diff --check
```

Use the existing project virtualenv when the system Python has no pytest installed.

## Safety

The orchestrator fails closed. In beta monitoring mode, the CLI does not add or remove workers at all; it only reports status, analysis and read-only plans. The lower-level scaling transaction code remains guarded by topology, naming, metrics, host capacity, cluster health, NGINX health, certificates and transaction state checks for future validation.

Real Docker/Wazuh/NGINX/certificate behavior still requires validation on a prepared integration host; see `docs/integration-testing.md`. Do not claim host-level high availability for a single Docker host deployment.
