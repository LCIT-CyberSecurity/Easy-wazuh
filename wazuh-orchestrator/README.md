# Easy-Wazuh Orchestrator

Read-only diagnostic and sizing recommendation tool for Easy-Wazuh multi-node deployments. It observes Wazuh, Wazuh Indexer and NGINX, detects manager/indexer pressure, and may recommend adding one Wazuh Manager worker. It does not modify the live deployment in V1.

Supported in V1:

- Easy-Wazuh multi-node deployments recognized from `deployment.yaml` or conservative legacy discovery
- exactly one Wazuh Manager master
- N Wazuh Manager workers, monitored against baseline and max
- exactly one Wazuh Dashboard, monitored only
- Wazuh Indexers monitored through read-only Indexer APIs
- existing Easy-Wazuh NGINX/load balancer health checked over HTTP
- container execution without root and without `/var/run/docker.sock`
- operation without Docker Engine privileges or Docker CPU/RAM container metrics

Not supported in V1:

- autoscaling
- live worker scaling from the CLI or Python API
- single-node orchestration or migration to multi-node
- multi-host orchestration
- Dashboard horizontal scaling
- Indexer scaling
- Dashboard certificate customization
- privileged Docker socket access
- host CPU/RAM/IO providers such as Prometheus, Zabbix or Centreon

## CLI

```bash
python3 wazuh-orchestrator.py status
python3 wazuh-orchestrator.py analyze
python3 wazuh-orchestrator.py analyze --duration 120
python3 wazuh-orchestrator.py plan --workers 3
# Disabled in V1:
# python3 wazuh-orchestrator.py scale --workers 3
```

`status` and `analyze` support `--json`. Use global `--debug` to force DEBUG logs for one run; otherwise configure `logging.level` in YAML.

`analyze --duration` performs repeated metric collection across the requested duration and computes rates such as EPS only when two valid counter samples are available. `plan` is a read-only planning aid for a possible worker count change. In V1, `scale` is intentionally disabled: it exits with an error before backend, Docker, NGINX, certificate, transaction or lock operations can run.

## Configuration

Copy `config/orchestrator.yaml.example` and adjust thresholds. Defaults are Easy-Wazuh conservative guardrails, not official universal Wazuh sizing recommendations.

The bootstrap persists deployment identity at `/opt/wazuh/easy-wazuh/deployment.yaml`. The orchestrator reads and validates this file, then compares it with declared Compose state when files are available. Runtime health comes from Wazuh API, Wazuh Indexer API and NGINX HTTP checks, not from Docker Engine access. API credentials should be read-only where Wazuh allows it and are never printed in CLI output or audit logs.

## Local Development

Development and unit tests require no Docker daemon, no Wazuh installation, no root and no Internet. Wazuh API, Wazuh Indexer API, NGINX and certificate behavior are mocked or represented by synthetic fixtures.

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

The orchestrator treats missing data as unknown, not healthy. In V1, the CLI and Python `scale()` path do not add or remove workers at all; they only report status, analysis and read-only plans. A manager scale-out recommendation means add one worker and re-evaluate after stabilization, not that scaling will certainly fix the issue.

When host CPU/RAM/IO metrics are not available, the orchestrator can detect Wazuh-side pressure but cannot prove that the current host has enough capacity for another worker. Verify host resources before deploying the worker on the same node. Future providers such as Prometheus, Zabbix or Centreon are intentionally out of scope for V1.

Dashboard certificate customization is outside V1. The orchestrator does not replace Dashboard private keys or Dashboard TLS paths.
