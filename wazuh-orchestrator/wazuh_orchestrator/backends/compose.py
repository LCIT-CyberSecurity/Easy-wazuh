"""Docker Compose backend primitives, all mockable and shell-free."""

from __future__ import annotations

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

    def generate_override(self, cluster: ClusterState, worker_name: str) -> Path:
        """Write the orchestrator Compose override for one additional worker.

        INTEGRATION_VALIDATION_REQUIRED: certificate and volume details must be
        confirmed on a real Easy-Wazuh Docker host before production use.
        """
        validate_service_name(worker_name)
        master = cluster.master or "wazuh-manager01.local"
        data = {
            "services": {
                worker_name: {
                    "image": "wazuh/wazuh-manager:${WAZUH_VERSION:-4.14.5}",
                    "hostname": worker_name,
                    "volumes": [
                        f"{worker_name.replace('.', '_')}_etc:/var/ossec/etc",
                        f"{worker_name.replace('.', '_')}_logs:/var/ossec/logs",
                        "../config/wazuh_cluster/wazuh_worker.conf:/wazuh-config-mount/etc/ossec.conf:ro",
                    ],
                    "environment": {
                        "INDEXER_URL": "https://wazuh-indexer01.local:9200",
                        "WAZUH_CLUSTER_MASTER": master,
                        "WAZUH_NODE_NAME": worker_name,
                    },
                    "networks": ["default"],
                }
            },
            "volumes": {
                f"{worker_name.replace('.', '_')}_etc": None,
                f"{worker_name.replace('.', '_')}_logs": None,
            },
        }
        atomic_write(self.override_file, yaml.safe_dump(data, sort_keys=False), mode=0o600)
        return self.override_file


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
        self.reloader()


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


def _suffix(master: str) -> str:
    parts = master.split(".", 1)
    return f".{parts[1]}" if len(parts) == 2 else ".local"


def timestamped_backup_dir(root: Path) -> Path:
    return root / "backups" / time.strftime("%Y%m%d-%H%M%S")
