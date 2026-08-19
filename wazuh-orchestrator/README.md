# Easy-Wazuh Orchestrator

Manual V1 orchestrator for Easy-Wazuh multi-node deployments. It analyzes capacity and prepares controlled horizontal scaling of Wazuh Manager workers only.

Supported in V1:

- Easy-Wazuh multi-node deployments recognized from `deployment.yaml` or conservative legacy discovery
- exactly one Wazuh Manager master
- N Wazuh Manager workers, bounded by baseline and max
- exactly one Wazuh Dashboard, monitored only
- Wazuh Indexers monitored only
- existing Easy-Wazuh NGINX/load balancer only

Not supported in V1:

- autoscaling
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
python3 wazuh-orchestrator.py scale --workers 3
```

`status` and `analyze` support `--json`. Use global `--debug` to force DEBUG logs for one run; otherwise configure `logging.level` in YAML.

`scale` is manual and interactive. It prints the plan and requires typing `SCALE`. There is no `--yes` and no `--force` in V1.

## Configuration

Copy `config/orchestrator.yaml.example` and adjust thresholds. Defaults are Easy-Wazuh conservative guardrails, not official universal Wazuh sizing recommendations.

The bootstrap persists deployment identity at `/opt/wazuh/easy-wazuh/deployment.yaml`. The orchestrator reads and validates this file, then compares it with actual Compose state. Important drift blocks scaling.

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

The orchestrator fails closed. It does not add a worker when topology, naming, metrics, host capacity, cluster health, NGINX health, certificates or transaction state are uncertain.

Real Docker/Wazuh deployment validation remains required; see `docs/integration-testing.md`.
