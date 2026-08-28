"""Docker Compose backend primitives, all mockable and shell-free."""

from __future__ import annotations

import json
from copy import deepcopy
import re
import shutil
import subprocess
import time
from pathlib import Path

import yaml

from ..logging_setup import atomic_write
from ..models import ClusterState, NamingError, ScalingError
from ..naming import next_worker_name as policy_next_worker_name, validate_unique_identity

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


def validate_service_name(name: str) -> None:
    """Reject service names that could lead to path or command injection."""
    if not SAFE_NAME.fullmatch(name) or ".." in name:
        raise ScalingError(f"Unsafe service name: {name}")


class ComposeBackend:
    def __init__(self, compose_file: Path, override_file: Path, project_directory: Path, timeout: int = 120, runner=subprocess.run):
        self.compose_file = compose_file
        self.override_file = override_file
        self.project_directory = project_directory
        self.timeout = timeout
        self.runner = runner

    def next_worker_name(self, cluster: ClusterState) -> str:
        """Return the monotonic next worker name from deployment policy."""
        existing = set(cluster.workers) | ({cluster.master} if cluster.master else set())
        policy = cluster.naming_policy
        if policy is not None:
            try:
                candidate = policy_next_worker_name(policy, tuple(existing))
                validate_unique_identity(candidate, existing)
                return candidate
            except NamingError as exc:
                raise ScalingError(str(exc)) from exc
        suffix = _suffix(cluster.master or "wazuh-manager01.local")
        indices = []
        for name in existing:
            match = re.search(r"manager([0-9]+)", name)
            if match:
                indices.append(int(match.group(1)))
        candidate = f"wazuh-manager{(max(indices) if indices else 1) + 1:02d}{suffix}"
        validate_service_name(candidate)
        return candidate

    def prepare_worker_config(self, cluster: ClusterState, worker_name: str) -> Path:
        """Create a worker-specific Wazuh config derived from the baseline worker."""
        validate_service_name(worker_name)
        template = self.project_directory / "config" / "wazuh_cluster" / "wazuh_worker.conf"
        if not template.exists():
            raise ScalingError(f"Baseline Wazuh worker config not found: {template}")
        target = self.override_file.parent / "worker-configs" / f"{worker_name}.conf"
        return derive_worker_config(template, target, worker_name, cluster.master or "wazuh-manager01.local")

    def generate_override(self, cluster: ClusterState, worker_name: str) -> Path:
        """Write the orchestrator Compose override for one additional worker.

        INTEGRATION_VALIDATION_REQUIRED: certificate and volume details must be
        confirmed on a real Easy-Wazuh Docker host before production use.
        """
        validate_service_name(worker_name)
        master = cluster.master or "wazuh-manager01.local"
        network = cluster.compose_network or "default"
        config_path = self.prepare_worker_config(cluster, worker_name)
        indexer = cluster.indexers[0] if cluster.indexers else "wazuh-indexer01.local"
        baseline_worker = cluster.workers[-1] if cluster.workers else None
        service = self._worker_service_template(cluster)
        if baseline_worker:
            service = _replace_string_values(service, baseline_worker, worker_name)
        service["hostname"] = worker_name
        service.pop("container_name", None)
        service["networks"] = _worker_networks(service.get("networks"), network)
        environment = _environment_mapping(service.get("environment"))
        environment.update({
            "INDEXER_URL": f"https://{indexer}:9200",
            "WAZUH_CLUSTER_MASTER": master,
            "WAZUH_NODE_NAME": worker_name,
        })
        service["environment"] = environment
        service["volumes"] = _worker_volumes(service.get("volumes"), worker_name, config_path)
        data = {
            "services": {worker_name: service},
            "volumes": _worker_named_volumes(worker_name),
        }
        atomic_write(self.override_file, yaml.safe_dump(data, sort_keys=False), mode=0o600)
        return self.override_file

    def _worker_service_template(self, cluster: ClusterState) -> dict[str, object]:
        """Clone the baseline worker service when available instead of hardcoding a full template."""
        if cluster.workers and self.compose_file.exists():
            try:
                data = yaml.safe_load(self.compose_file.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise ScalingError(f"Malformed Compose file: {self.compose_file}") from exc
            services = data.get("services") if isinstance(data, dict) else None
            baseline = cluster.workers[-1]
            if isinstance(services, dict) and isinstance(services.get(baseline), dict):
                return deepcopy(services[baseline])
        return {
            "image": "wazuh/wazuh-manager:${WAZUH_VERSION:-4.14.5}",
        }

    def remove_from_override(self, worker_name: str) -> Path:
        """Remove a worker from current desired-state override without deleting volumes."""
        validate_service_name(worker_name)
        if not self.override_file.exists():
            return self.override_file
        data = yaml.safe_load(self.override_file.read_text(encoding="utf-8")) or {}
        services = data.get("services") if isinstance(data, dict) else None
        if isinstance(services, dict):
            services.pop(worker_name, None)
        # V1 intentionally preserves volumes for removed workers.
        atomic_write(self.override_file, yaml.safe_dump(data, sort_keys=False), mode=0o600)
        return self.override_file

    def backup_desired_state(self, backup_dir: Path) -> Path | None:
        """Back up orchestrator desired-state override before changing it."""
        backup_dir.mkdir(parents=True, exist_ok=True)
        if not self.override_file.exists():
            return None
        backup = backup_dir / self.override_file.name
        shutil.copy2(self.override_file, backup)
        return backup

    def restore_desired_state(self, backup: Path | None) -> None:
        """Restore or remove generated desired-state override during rollback."""
        if backup is None:
            if self.override_file.exists():
                self.override_file.unlink()
            return
        shutil.copy2(backup, self.override_file)

    def cleanup_worker_config(self, worker_name: str) -> None:
        """Remove only the generated config file for the target worker."""
        validate_service_name(worker_name)
        path = self.override_file.parent / "worker-configs" / f"{worker_name}.conf"
        if path.exists():
            path.unlink()

    def validate_effective_config(self) -> None:
        """Validate the effective Compose model through the command builder."""
        self.run_compose("config")

    def start_worker(self, worker_name: str) -> None:
        """Start only the target worker service."""
        validate_service_name(worker_name)
        self.run_compose("up", "-d", worker_name)

    def validate_nginx_config(self, nginx_service: str = "nginx") -> bool:
        """Validate NGINX config inside the existing Easy-Wazuh NGINX service."""
        validate_service_name(nginx_service)
        self.run_compose("exec", "-T", nginx_service, "nginx", "-t")
        return True

    def reload_nginx(self, nginx_service: str = "nginx") -> bool:
        """Reload the existing Easy-Wazuh NGINX service."""
        validate_service_name(nginx_service)
        self.run_compose("exec", "-T", nginx_service, "nginx", "-s", "reload")
        return True

    def wait_for_worker_health(self, worker_name: str) -> None:
        """Poll Compose until the target worker reports healthy."""
        validate_service_name(worker_name)
        deadline = time.monotonic() + self.timeout
        last_state = "unknown"
        while True:
            process = self.run_compose("ps", "--format", "json", worker_name)
            state = _compose_health_state(process.stdout, worker_name)
            if state == "healthy":
                return
            last_state = state
            if time.monotonic() >= deadline:
                raise ScalingError(f"Docker health check failed for {worker_name}: {last_state}")
            time.sleep(2)

    def compose_command(self, *args: str) -> list[str]:
        """Build a shell-free docker compose command with base and override files."""
        return ["docker", "compose", "--project-directory", str(self.project_directory), "-f", str(self.compose_file), "-f", str(self.override_file), *args]

    def run_compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Execute Compose through an injectable runner; never uses shell=True."""
        return self.runner(
            self.compose_command(*args),
            cwd=self.project_directory,
            shell=False,
            timeout=self.timeout,
            check=True,
            text=True,
            capture_output=True,
        )


class NginxConfigManager:
    def __init__(self, config_path: Path, validator=None, reloader=None):
        self.config_path = config_path
        self.validator = validator or (lambda path: True)
        self.reloader = reloader or (lambda: True)

    def render_with_worker(self, worker: str) -> str:
        """Return NGINX config content with one agent-traffic worker added once."""
        validate_service_name(worker)
        content = self.config_path.read_text(encoding="utf-8") if self.config_path.exists() else "upstream wazuh_managers {\n}\n"
        line = f"    server {worker}:1514;"
        if line in content:
            return content
        lines = content.splitlines()
        upstream_index = _agent_traffic_upstream_index(lines)
        if upstream_index is None:
            raise ScalingError("NGINX agent-traffic upstream not found.")
        lines.insert(upstream_index + 1, line)
        return "\n".join(lines) + "\n"

    def apply_worker(self, worker: str, backup_dir: Path) -> None:
        """Backup, atomically apply and validate an NGINX worker addition."""
        self._apply_content(self.render_with_worker(worker), backup_dir)

    def remove_worker(self, worker: str, backup_dir: Path) -> None:
        """Backup, atomically apply and validate an NGINX worker removal."""
        validate_service_name(worker)
        content = self.config_path.read_text(encoding="utf-8") if self.config_path.exists() else ""
        lines = [line for line in content.splitlines() if f"server {worker}:1514;" not in line]
        self._apply_content("\n".join(lines) + ("\n" if lines else ""), backup_dir)

    def restore_backup(self, backup_dir: Path) -> None:
        """Restore the config saved before an NGINX update and reload it."""
        backup = backup_dir / self.config_path.name
        if not backup.exists():
            raise ScalingError("NGINX rollback failed; backup configuration not found.")
        shutil.copy2(backup, self.config_path)
        if not self.validator(self.config_path):
            raise ScalingError("NGINX rollback failed; restored configuration did not validate.")
        try:
            self.reloader()
        except Exception as exc:
            raise ScalingError("NGINX rollback failed; restored configuration could not be reloaded.") from exc

    def _apply_content(self, candidate: str, backup_dir: Path) -> None:
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / self.config_path.name
        if self.config_path.exists():
            shutil.copy2(self.config_path, backup)
        atomic_write(self.config_path, candidate, mode=0o600)
        if not self.validator(self.config_path):
            if backup.exists():
                shutil.copy2(backup, self.config_path)
            raise ScalingError("NGINX validation failed; previous configuration restored.")
        try:
            self.reloader()
        except Exception as exc:
            if backup.exists():
                shutil.copy2(backup, self.config_path)
            raise ScalingError("NGINX reload failed; previous configuration restored.") from exc


def derive_worker_config(template_path: Path, target_path: Path, node_name: str, master_name: str) -> Path:
    """Clone a baseline worker config and patch only worker-specific fields.

    The cluster key is preserved by copying the template content and never being
    logged or inspected beyond equality-preserving text replacement.
    """
    validate_service_name(node_name)
    content = template_path.read_text(encoding="utf-8")
    patched = _replace_xml_value(content, "node_name", node_name)
    patched = _replace_xml_value(patched, "node", master_name, first_only=True)
    atomic_write(target_path, patched, mode=0o600)
    return target_path


def _replace_xml_value(content: str, tag: str, value: str, *, first_only: bool = False) -> str:
    pattern = re.compile(rf"(<{tag}>)(.*?)(</{tag}>)", re.DOTALL)
    count = 1 if first_only else 0
    if not pattern.search(content):
        raise ScalingError(f"Wazuh config tag not found: {tag}")
    return pattern.sub(lambda match: f"{match.group(1)}{value}{match.group(3)}", content, count=count)


def _agent_traffic_upstream_index(lines: list[str]) -> int | None:
    candidates: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = re.match(r"\s*upstream\s+([^\s{]+)\s*{", line)
        if match:
            candidates.append((index, match.group(1).lower()))
    for index, name in candidates:
        if "enroll" in name:
            continue
        if "agent" in name or "manager" in name or name == "wazuh_managers":
            return index
    return None


def _replace_string_values(value: object, old: str, new: str) -> object:
    if isinstance(value, str):
        return value.replace(old, new).replace(old.replace('.', '_'), new.replace('.', '_'))
    if isinstance(value, list):
        return [_replace_string_values(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _replace_string_values(item, old, new) for key, item in value.items()}
    return value


def _environment_mapping(value: object) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    env: dict[str, str] = {}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and "=" in item:
                key, raw = item.split("=", 1)
                env[key] = raw
    return env


def _worker_volumes(value: object, worker_name: str, config_path: Path) -> list[str]:
    volumes = [str(item) for item in value] if isinstance(value, list) else []
    config_mount = f"{config_path.resolve()}:/wazuh-config-mount/etc/ossec.conf:ro"
    volumes = [item for item in volumes if "/wazuh-config-mount/etc/ossec.conf" not in item]
    volumes.append(config_mount)
    names = {item.split(":", 1)[0] for item in volumes}
    for volume in _worker_named_volumes(worker_name):
        if volume not in names:
            volumes.append(f"{volume}:/var/ossec/{volume.rsplit('_', 1)[-1]}")
    return volumes


def _worker_networks(value: object, network: str) -> object:
    if isinstance(value, dict):
        if network in value:
            return value
        if len(value) == 1:
            return {network: next(iter(value.values()))}
        return {network: None, **value}
    if isinstance(value, list):
        networks = [str(item) for item in value]
        if network in networks:
            return networks
        if len(networks) == 1 and networks[0] == "default":
            return [network]
        return [network, *networks]
    return [network]


def _worker_named_volumes(worker_name: str) -> dict[str, None]:
    safe = worker_name.replace('.', '_')
    return {f"{safe}_etc": None, f"{safe}_logs": None}


def _suffix(master: str) -> str:
    parts = master.split(".", 1)
    return f".{parts[1]}" if len(parts) == 2 else ".local"


def _compose_health_state(stdout: str | None, worker_name: str) -> str:
    if not stdout:
        return "missing"
    rows = _compose_ps_rows(stdout)
    if not rows:
        return "missing"
    for row in rows:
        if not isinstance(row, dict):
            continue
        names = {str(row.get(key, "")) for key in ("Name", "Service", "Names")}
        if worker_name not in names:
            continue
        health = str(row.get("Health") or "").strip().lower()
        if health:
            return health
        state = str(row.get("State") or row.get("Status") or "").strip().lower()
        if "healthy" in state:
            return "healthy"
        if state:
            return state
    return "missing"


def _compose_ps_rows(stdout: str) -> list[object]:
    text = stdout.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                return []
        return rows
    if isinstance(payload, list):
        return payload
    return [payload]


def timestamped_backup_dir(root: Path) -> Path:
    return root / "backups" / time.strftime("%Y%m%d-%H%M%S")
