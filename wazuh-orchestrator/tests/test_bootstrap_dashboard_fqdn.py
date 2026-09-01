from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "easy-wazuh-bootstrap.sh"


def bootstrap_functions() -> str:
    text = BOOTSTRAP.read_text(encoding="utf-8")
    start = text.index("is_valid_ipv4()")
    end = text.index("prompt_component_hostname()")
    return text[start:end]


def run_bash(script: str) -> str:
    result = subprocess.run(
        ["bash", "-c", bootstrap_functions() + "\n" + script],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    return result.stdout.strip()


def test_default_dashboard_fqdn_uses_wazuh_home_lan():
    assert run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX="home.lan"; default_dashboard_fqdn "VM-Openvas.home.lan"') == "wazuh.home.lan"


def test_default_dashboard_fqdn_uses_internal_suffix_when_selected():
    assert run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX="sec.lan"; default_dashboard_fqdn "VM-Openvas.home.lan"') == "wazuh.sec.lan"


def test_default_dashboard_fqdn_falls_back_to_host_domain():
    assert run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX=""; default_dashboard_fqdn "VM-Openvas.home.lan"') == "wazuh.home.lan"


def test_default_dashboard_fqdn_uses_public_suffix_override():
    assert run_bash('WAZUH_PUBLIC_DNS_SUFFIX="sec.lan"; WAZUH_INTERNAL_DNS_SUFFIX="internal.lan"; default_dashboard_fqdn "VM-Openvas.home.lan"') == "wazuh.sec.lan"


def test_default_dashboard_fqdn_does_not_use_detected_hostname():
    assert run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX="sec.lan"; default_dashboard_fqdn "VM-Openvas.home.lan"') != "VM-Openvas.home.lan"


def test_public_fqdn_override_preserves_admin_value():
    output = run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX="sec.lan"; WAZUH_PUBLIC_FQDN="siem.example.internal"; prompt_public_endpoint "VM-Openvas.home.lan" "192.168.1.28"; printf "%s" "$PUBLIC_ENDPOINT"')

    assert output == "siem.example.internal"

def test_public_prompt_continues_when_default_fqdn_does_not_resolve():
    output = run_bash('WAZUH_PUBLIC_DNS_SUFFIX=""; WAZUH_INTERNAL_DNS_SUFFIX="not-resolving.invalid"; WAZUH_PUBLIC_FQDN=""; prompt_public_endpoint "VM-Openvas.home.lan" "192.168.1.28" <<< ""; printf "%s" "$PUBLIC_ENDPOINT"')

    assert output == "wazuh.not-resolving.invalid"
