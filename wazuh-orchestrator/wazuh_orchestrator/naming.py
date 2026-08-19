"""Naming policy parsing, validation and legacy inference for Easy-Wazuh."""

from __future__ import annotations

import re
from dataclasses import dataclass
from statistics import mode

from .models import NamingError, NamingPolicy

DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62})$")
FORBIDDEN = re.compile(r"[\s/\\;$`|&<>]|\.\.")


@dataclass(frozen=True)
class ParsedNodeName:
    """Parsed numbered node name with optional internal DNS suffix."""

    prefix: str
    index: int
    number_width: int
    suffix: str | None


def validate_prefix(prefix: str) -> None:
    """Validate a deployment prefix used to format manager or indexer names."""
    if not prefix or FORBIDDEN.search(prefix):
        raise NamingError("invalid prefix")
    for label in prefix.split("-"):
        if not label:
            raise NamingError("invalid prefix")
    if not SERVICE_NAME.fullmatch(prefix):
        raise NamingError("invalid prefix")


def validate_hostname(name: str) -> None:
    """Validate a Docker hostname or service/FQDN used by Wazuh nodes."""
    if not name or FORBIDDEN.search(name) or len(name) > 253:
        raise NamingError("invalid hostname")
    labels = name.split(".")
    if any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise NamingError("invalid hostname")


def validate_compose_service_name(name: str) -> None:
    """Validate a Compose service name without allowing path or shell tricks."""
    if not name or FORBIDDEN.search(name) or not SERVICE_NAME.fullmatch(name):
        raise NamingError("invalid compose service name")
    validate_hostname(name.replace("_", "-"))


def parse_node_name(name: str) -> ParsedNodeName:
    """Parse names such as wazuh-manager02.local into prefix, index and suffix."""
    validate_hostname(name)
    host, _, suffix = name.partition(".")
    match = re.match(r"^(?P<prefix>.+?)(?P<number>[0-9]+)$", host)
    if not match:
        raise NamingError("node name does not end with a numeric index")
    prefix = match.group("prefix")
    number = match.group("number")
    validate_prefix(prefix)
    return ParsedNodeName(prefix, int(number), len(number), suffix or None)


def format_node_name(prefix: str, index: int, width: int, suffix: str | None = None) -> str:
    """Format a node name while preserving padding and optional DNS suffix."""
    validate_prefix(prefix)
    if index < 0 or width < 1:
        raise NamingError("invalid numbering")
    host = f"{prefix}{index:0{width}d}"
    name = f"{host}.{suffix}" if suffix else host
    validate_hostname(name)
    return name


def next_worker_name(policy: NamingPolicy, existing_names: tuple[str, ...]) -> str:
    """Return the monotonic next worker name using max(existing_indices) + 1."""
    indices = []
    for name in existing_names:
        parsed = parse_node_name(name)
        if parsed.prefix != policy.manager_prefix:
            continue
        if parsed.suffix != policy.manager_internal_dns_suffix:
            continue
        indices.append(parsed.index)
    if not indices:
        raise NamingError("NAMING_POLICY_AMBIGUOUS")
    return format_node_name(
        policy.manager_prefix,
        max(indices) + 1,
        policy.manager_number_width,
        policy.manager_internal_dns_suffix,
    )


def infer_legacy_policy(master: str | None, workers: tuple[str, ...], indexers: tuple[str, ...] = ()) -> NamingPolicy:
    """Infer legacy naming only when all known manager names share one pattern."""
    names = tuple(n for n in ((master,) if master else ()) + workers if n)
    if not master or not workers:
        raise NamingError("NAMING_POLICY_AMBIGUOUS")
    parsed = [parse_node_name(name) for name in names]
    prefixes = {p.prefix for p in parsed}
    suffixes = {p.suffix for p in parsed}
    widths = {p.number_width for p in parsed}
    if len(prefixes) != 1 or len(suffixes) != 1 or len(widths) != 1:
        raise NamingError("NAMING_POLICY_AMBIGUOUS")
    master_index = parse_node_name(master).index
    indexer_prefix = "wazuh-indexer"
    indexer_width = next(iter(widths))
    if indexers:
        iparsed = [parse_node_name(name) for name in indexers]
        iprefixes = {p.prefix for p in iparsed}
        iwidths = {p.number_width for p in iparsed}
        if len(iprefixes) == 1:
            indexer_prefix = next(iter(iprefixes))
        if len(iwidths) == 1:
            indexer_width = next(iter(iwidths))
    return NamingPolicy(
        manager_prefix=next(iter(prefixes)),
        manager_number_width=next(iter(widths)),
        manager_internal_dns_suffix=next(iter(suffixes)),
        manager_master_index=master_index,
        indexer_prefix=indexer_prefix,
        indexer_number_width=indexer_width,
    )


def validate_unique_identity(candidate: str, existing: set[str]) -> None:
    """Reject a worker identity collision across service, hostname and node names."""
    validate_hostname(candidate)
    validate_compose_service_name(candidate)
    if candidate in existing:
        raise NamingError("NAMING_COLLISION")
