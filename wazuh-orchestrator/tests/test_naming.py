from __future__ import annotations

import pytest

from wazuh_orchestrator.models import NamingError, NamingPolicy
from wazuh_orchestrator.naming import format_node_name, infer_legacy_policy, next_worker_name, parse_node_name, validate_unique_identity


def test_padding_preserved():
    assert format_node_name("wazuh-manager", 3, 2, "local") == "wazuh-manager03.local"


def test_custom_prefix_and_fqdn_suffix():
    policy = NamingPolicy(manager_prefix="soc-manager", manager_number_width=2, manager_internal_dns_suffix="example.internal")
    assert next_worker_name(policy, ("soc-manager01.example.internal", "soc-manager02.example.internal")) == "soc-manager03.example.internal"


def test_monotonic_index_does_not_reuse_gap():
    policy = NamingPolicy(manager_prefix="wazuh-manager", manager_number_width=2, manager_internal_dns_suffix="local")
    assert next_worker_name(policy, ("wazuh-manager01.local", "wazuh-manager02.local", "wazuh-manager04.local")) == "wazuh-manager05.local"


def test_invalid_hostname_refused():
    with pytest.raises(NamingError):
        parse_node_name("bad/name01.local")


def test_collision_refused():
    with pytest.raises(NamingError, match="NAMING_COLLISION"):
        validate_unique_identity("wazuh-manager03.local", {"wazuh-manager03.local"})


def test_legacy_policy_discovered():
    policy = infer_legacy_policy("wazuh-manager01.local", ("wazuh-manager02.local",), ("wazuh-indexer01.local",))
    assert policy.manager_prefix == "wazuh-manager"
    assert policy.manager_number_width == 2
    assert policy.manager_internal_dns_suffix == "local"


def test_ambiguous_legacy_naming_refused():
    with pytest.raises(NamingError):
        infer_legacy_policy("wazuh-manager01.local", ("soc-worker02.local",), ())
