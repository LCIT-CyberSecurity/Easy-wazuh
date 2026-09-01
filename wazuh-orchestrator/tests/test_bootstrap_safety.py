from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "easy-wazuh-bootstrap.sh"


def bootstrap_text() -> str:
    return BOOTSTRAP.read_text(encoding="utf-8")


def test_fresh_install_does_not_remove_container_runtime_packages():
    text = bootstrap_text()

    assert "apt remove" not in text
    assert "apt purge" not in text
    assert "autoremove" not in text
    assert "docker rm" not in text
    assert "docker volume rm" not in text
    assert "rm -rf" not in text


def test_fresh_install_blocks_existing_container_runtimes():
    text = bootstrap_text()

    assert "guard_fresh_install_against_existing_container_runtime" in text
    assert "docker.io docker-ce docker-ce-cli" in text
    assert "podman podman-docker" in text
    assert "containerd containerd.io" in text
    assert "kubelet kubectl kubeadm k3s microk8s" in text
    assert "The selected fresh install mode will not remove or replace existing" in text


def test_bootstrap_does_not_modify_dns_or_hosts_files():
    text = bootstrap_text()

    assert "/etc/hosts" not in text
    assert "resolv.conf" not in text


def test_bootstrap_checks_host_resources_before_package_work():
    text = bootstrap_text()

    assert "check_host_resources" in text
    assert 'EASY_WAZUH_MIN_VCPU="${EASY_WAZUH_MIN_VCPU:-4}"' in text
    assert 'EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE="${EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE:-8}"' in text
    assert 'EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE="${EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE:-16}"' in text
    assert 'EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE="${EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE:-50}"' in text
    assert 'EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE="${EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE:-100}"' in text
    assert "EASY_WAZUH_SKIP_RESOURCE_CHECK=yes" in text
    assert text.index('check_host_resources "$WAZUH_DIR"') < text.index("apt update")
