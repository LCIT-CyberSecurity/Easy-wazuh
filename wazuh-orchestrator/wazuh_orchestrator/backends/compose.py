"""Docker Compose backend primitives, all mockable and shell-free."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

import yaml

from ..logging_setup import atomic_write
from ..models import ClusterState, ScalingError

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
        """Return the first unused worker name matching Easy-Wazuh conventions."""
        suffix = _suffix(cluster.master or "wazuh-manager01.local")
        existing = set(cluster.workers) | ({cluster.master} if cluster.master else set())
        index = 2
        while True:
            candidate = f"wazuh-manager{index:02d}{suffix}"
            if candidate not in existing:
                validate_service_name(candidate)
                return candidate
            index += 1

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

    def compose_command(self, *args: str) -> list[str]:
        """Build a shell-free docker compose command with base and override files."""
        return ["docker", "compose", "-f", str(self.compose_file), "-f", str(self.override_file), *args]

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
        """Return NGINX config content with one worker added once."""
        validate_service_name(worker)
        content = self.config_path.read_text(encoding="utf-8") if self.config_path.exists() else "upstream wazuh_managers {\n}\n"
        line = f"    server {worker}:1514;"
        if line in content:
            return content
        return content.replace("upstream wazuh_managers {\n", f"upstream wazuh_managers {{\n{line}\n")

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


def _suffix(master: str) -> str:
    parts = master.split(".", 1)
    return f".{parts[1]}" if len(parts) == 2 else ".local"


def timestamped_backup_dir(root: Path) -> Path:
    return root / "backups" / time.strftime("%Y%m%d-%H%M%S")
