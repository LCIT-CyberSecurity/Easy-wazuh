#!/bin/bash

set -Eeuo pipefail

echo "=================================================="
echo " Wazuh Docker installation script"
echo "=================================================="
echo ""
echo "Scope:"
echo "  This installer deploys a Wazuh Docker stack on one Docker host/VM"
echo "  for PoC/lab use."
echo "  The stack uses three separate Wazuh component images and containers:"
echo "  manager, indexer, and dashboard."
echo "  The installer can deploy the official single-node stack or a multi-node"
echo "  stack using numbered FQDN component names."
echo "  This installer is not intended for production deployments."
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Example: sudo ./easy-wazuh-bootstrap.sh"
  exit 1
fi

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.5}"
WAZUH_PUBLIC_FQDN="${WAZUH_PUBLIC_FQDN:-}"
WAZUH_PUBLIC_DNS_SUFFIX="${WAZUH_PUBLIC_DNS_SUFFIX:-}"
WAZUH_PORTS=(443 1514 1515 514 55000 9200)
WAZUH_INDEXER_NODE="wazuh.indexer"
WAZUH_MANAGER_NODE="wazuh.manager"
WAZUH_DASHBOARD_NODE="wazuh.dashboard"
WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE"
WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE"
WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE"
WAZUH_INTERNAL_DNS_SUFFIX="${WAZUH_INTERNAL_DNS_SUFFIX:-}"
WAZUH_INDEXER_HOSTNAME="${WAZUH_INDEXER_HOSTNAME:-}"
WAZUH_MANAGER_HOSTNAME="${WAZUH_MANAGER_HOSTNAME:-}"
WAZUH_DASHBOARD_HOSTNAME="${WAZUH_DASHBOARD_HOSTNAME:-}"
EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME="${EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME:-}"
EASY_WAZUH_SKIP_RESOURCE_CHECK="${EASY_WAZUH_SKIP_RESOURCE_CHECK:-no}"
EASY_WAZUH_MIN_VCPU="${EASY_WAZUH_MIN_VCPU:-2}"
EASY_WAZUH_RECOMMENDED_VCPU="${EASY_WAZUH_RECOMMENDED_VCPU:-4}"
EASY_WAZUH_MIN_MEMORY_GB="${EASY_WAZUH_MIN_MEMORY_GB:-}"
EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE="${EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE:-8}"
EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE="${EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE:-16}"
EASY_WAZUH_MIN_DISK_FREE_GB="${EASY_WAZUH_MIN_DISK_FREE_GB:-}"
EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE="${EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE:-50}"
EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE="${EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE:-100}"
DEPLOYMENT_TOPOLOGY=""
DEPLOYMENT_TOPOLOGY_LABEL=""
DEPLOYMENT_STACK_MODE=""
DEPLOYMENT_STACK_LABEL=""
STACK_SUBDIR=""
USE_FIXED_CONTAINER_NAMES="no"
WAZUH_WORKER_NODE=""
WAZUH_INDEXER_NODES=()
WAZUH_MANAGER_NODES=()
WAZUH_DASHBOARD_NODES=()
WAZUH_FRONTEND_NODES=()
WAZUH_CERT_NODES=()
WAZUH_COMPOSE_SERVICES=()

# Keep version input narrow so it cannot be interpreted as a Git option.
if [[ ! "$WAZUH_VERSION" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "Error: invalid WAZUH_VERSION value: $WAZUH_VERSION"
  echo "Expected format example: v4.14.5"
  exit 1
fi

if [ -n "$EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME" ]; then
  case "$EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME" in
    yes|no)
      ;;
    *)
      echo "Error: invalid EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME value: $EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME"
      echo "Expected value: yes or no"
      exit 1
      ;;
  esac
fi

case "$EASY_WAZUH_SKIP_RESOURCE_CHECK" in
  yes|no)
    ;;
  *)
    echo "Error: invalid EASY_WAZUH_SKIP_RESOURCE_CHECK value: $EASY_WAZUH_SKIP_RESOURCE_CHECK"
    echo "Expected value: yes or no"
    exit 1
    ;;
esac

for RESOURCE_SETTING in EASY_WAZUH_MIN_VCPU EASY_WAZUH_RECOMMENDED_VCPU EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE; do
  RESOURCE_VALUE="${!RESOURCE_SETTING}"
  if [[ ! "$RESOURCE_VALUE" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: invalid $RESOURCE_SETTING value: $RESOURCE_VALUE"
    echo "Expected a positive integer."
    exit 1
  fi
done

for OPTIONAL_RESOURCE_SETTING in EASY_WAZUH_MIN_MEMORY_GB EASY_WAZUH_MIN_DISK_FREE_GB; do
  OPTIONAL_RESOURCE_VALUE="${!OPTIONAL_RESOURCE_SETTING}"
  if [ -n "$OPTIONAL_RESOURCE_VALUE" ] && [[ ! "$OPTIONAL_RESOURCE_VALUE" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: invalid $OPTIONAL_RESOURCE_SETTING value: $OPTIONAL_RESOURCE_VALUE"
    echo "Expected a positive integer."
    exit 1
  fi
done

# Keep public names narrow because they are written into TLS certificate
# configuration and later shown to users as connection endpoints.
is_valid_ipv4() {
  local VALUE="$1"
  local OCTET
  local -a OCTETS

  if [[ ! "$VALUE" =~ ^([0-9]{1,3}[.]){3}[0-9]{1,3}$ ]]; then
    return 1
  fi

  IFS='.' read -r -a OCTETS <<< "$VALUE"
  for OCTET in "${OCTETS[@]}"; do
    if [ "$OCTET" -gt 255 ]; then
      return 1
    fi
  done

  return 0
}

is_valid_fqdn() {
  local VALUE="$1"
  local LABEL
  local -a LABELS

  if [ "${#VALUE}" -gt 253 ]; then
    return 1
  fi

  if [[ ! "$VALUE" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
    return 1
  fi

  if [[ "$VALUE" != *.* ]]; then
    return 1
  fi

  IFS='.' read -r -a LABELS <<< "$VALUE"
  for LABEL in "${LABELS[@]}"; do
    if [ -z "$LABEL" ] || [ "${#LABEL}" -gt 63 ]; then
      return 1
    fi

    if [[ ! "$LABEL" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
      return 1
    fi
  done

  return 0
}

is_valid_dns_suffix() {
  local VALUE="$1"

  is_valid_fqdn "host.$VALUE"
}

is_valid_dns_label() {
  local VALUE="$1"

  if [ "${#VALUE}" -gt 63 ]; then
    return 1
  fi

  [[ "$VALUE" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]
}

is_valid_public_endpoint() {
  local VALUE="$1"

  is_valid_fqdn "$VALUE" || is_valid_ipv4 "$VALUE"
}

resolve_first_ipv4() {
  local NAME="$1"

  getent ahostsv4 "$NAME" 2>/dev/null | awk '{print $1; exit}'
}

host_dns_suffix() {
  local DETECTED_FQDN="$1"

  if [[ "$DETECTED_FQDN" == *.* ]]; then
    echo "${DETECTED_FQDN#*.}"
  else
    echo "local"
  fi
}

default_dashboard_fqdn() {
  local DETECTED_FQDN="$1"
  local DNS_SUFFIX

  DNS_SUFFIX="${WAZUH_PUBLIC_DNS_SUFFIX:-${WAZUH_INTERNAL_DNS_SUFFIX:-$(host_dns_suffix "$DETECTED_FQDN")}}"

  if is_valid_dns_suffix "$DNS_SUFFIX"; then
    echo "wazuh.$DNS_SUFFIX"
    return 0
  fi

  echo ""
}

server_fqdn_with_suffix() {
  local DETECTED_NAME="$1"
  local DNS_SUFFIX="$2"

  if is_valid_fqdn "$DETECTED_NAME" || is_valid_ipv4 "$DETECTED_NAME"; then
    echo "$DETECTED_NAME"
    return 0
  fi

  if is_valid_dns_label "$DETECTED_NAME" && is_valid_dns_suffix "$DNS_SUFFIX"; then
    echo "$DETECTED_NAME.$DNS_SUFFIX"
    return 0
  fi

  echo "$DETECTED_NAME"
}

set_named_component_dns_names() {
  local DNS_SUFFIX="$1"

  WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE.$DNS_SUFFIX"
  WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE.$DNS_SUFFIX"
  WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE.$DNS_SUFFIX"
}

set_multi_node_fqdn_names() {
  local DNS_SUFFIX="$1"

  WAZUH_INDEXER_NODE="wazuh-indexer01.$DNS_SUFFIX"
  WAZUH_MANAGER_NODE="wazuh-manager01.$DNS_SUFFIX"
  WAZUH_DASHBOARD_NODE="wazuh-dashboard01.$DNS_SUFFIX"
  WAZUH_WORKER_NODE="wazuh-manager02.$DNS_SUFFIX"
  WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE"
  WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE"
  WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE"
  WAZUH_INDEXER_NODES=("wazuh-indexer01.$DNS_SUFFIX" "wazuh-indexer02.$DNS_SUFFIX" "wazuh-indexer03.$DNS_SUFFIX")
  WAZUH_MANAGER_NODES=("wazuh-manager01.$DNS_SUFFIX" "wazuh-manager02.$DNS_SUFFIX")
  WAZUH_DASHBOARD_NODES=("wazuh-dashboard01.$DNS_SUFFIX")
  WAZUH_FRONTEND_NODES=("nginx")
  WAZUH_CERT_NODES=("${WAZUH_INDEXER_NODES[@]}" "${WAZUH_MANAGER_NODES[@]}" "${WAZUH_DASHBOARD_NODES[@]}")
  WAZUH_COMPOSE_SERVICES=("${WAZUH_INDEXER_NODES[@]}" "${WAZUH_MANAGER_NODES[@]}" "${WAZUH_DASHBOARD_NODES[@]}" "nginx")
}

set_named_component_hostnames() {
  if [ "$1" = "$2" ] || [ "$1" = "$3" ] || [ "$2" = "$3" ]; then
    echo "Error: component hostnames must be unique."
    exit 1
  fi

  WAZUH_INDEXER_NODE="$1"
  WAZUH_MANAGER_NODE="$2"
  WAZUH_DASHBOARD_NODE="$3"
  set_named_component_dns_names "${WAZUH_INTERNAL_DNS_SUFFIX:-local}"
}

prompt_public_endpoint() {
  local DETECTED_FQDN="$1"
  local DETECTED_IP="$2"
  local DEFAULT_ENDPOINT
  local DEFAULT_FQDN
  local DEFAULT_FQDN_IP
  local ENTERED_ENDPOINT

  DEFAULT_FQDN="$(default_dashboard_fqdn "$DETECTED_FQDN")"
  DEFAULT_ENDPOINT="$DEFAULT_FQDN"

  if [ -n "$DEFAULT_FQDN" ] && ! is_valid_ipv4 "$DEFAULT_FQDN" && command -v getent >/dev/null 2>&1; then
    DEFAULT_FQDN_IP="$(resolve_first_ipv4 "$DEFAULT_FQDN" || true)"
    if [ -n "$DEFAULT_FQDN_IP" ] && [ -n "$DETECTED_IP" ] && [ "$DEFAULT_FQDN_IP" != "$DETECTED_IP" ]; then
      echo "Warning: default dashboard FQDN $DEFAULT_FQDN resolves to $DEFAULT_FQDN_IP,"
      echo "but this VM IP appears to be $DETECTED_IP."
      echo "Keeping $DEFAULT_FQDN as the default dashboard URL host."
      echo "Use $DETECTED_IP manually only if DNS is not ready for this test."
    fi
  fi

  if ! is_valid_public_endpoint "$DEFAULT_ENDPOINT"; then
    DEFAULT_ENDPOINT="$DETECTED_IP"
  fi

  while true; do
    if [ -n "$WAZUH_PUBLIC_FQDN" ]; then
      ENTERED_ENDPOINT="$WAZUH_PUBLIC_FQDN"
    else
      read -r -p "Dashboard FQDN or IP clients will use [$DEFAULT_ENDPOINT]: " ENTERED_ENDPOINT
      if [ -z "$ENTERED_ENDPOINT" ]; then
        ENTERED_ENDPOINT="$DEFAULT_ENDPOINT"
      fi
    fi

    if is_valid_public_endpoint "$ENTERED_ENDPOINT"; then
      PUBLIC_ENDPOINT="$ENTERED_ENDPOINT"
      return 0
    fi

    echo "Invalid dashboard FQDN or IP: $ENTERED_ENDPOINT"
    echo "Use a valid FQDN such as wazuh.example.com, or an IPv4 address."

    if [ -n "$WAZUH_PUBLIC_FQDN" ]; then
      exit 1
    fi
  done
}

prompt_component_hostname() {
  local ROLE="$1"
  local DEFAULT_HOSTNAME="$2"
  local ENTERED_HOSTNAME

  while true; do
    read -r -p "$ROLE hostname [$DEFAULT_HOSTNAME]: " ENTERED_HOSTNAME
    if [ -z "$ENTERED_HOSTNAME" ]; then
      ENTERED_HOSTNAME="$DEFAULT_HOSTNAME"
    fi

    if is_valid_dns_label "$ENTERED_HOSTNAME"; then
      COMPONENT_HOSTNAME="$ENTERED_HOSTNAME"
      return 0
    fi

    echo "Invalid hostname: $ENTERED_HOSTNAME"
    echo "Use a DNS label such as wazuh-indexer01, without dots or underscores."
  done
}

configure_named_component_hostnames() {
  local CUSTOMIZE_HOSTNAMES
  local INDEXER_HOSTNAME
  local MANAGER_HOSTNAME
  local DASHBOARD_HOSTNAME

  if [ "$USE_FIXED_CONTAINER_NAMES" != "yes" ]; then
    return 0
  fi

  INDEXER_HOSTNAME="${WAZUH_INDEXER_HOSTNAME:-$WAZUH_INDEXER_NODE}"
  MANAGER_HOSTNAME="${WAZUH_MANAGER_HOSTNAME:-$WAZUH_MANAGER_NODE}"
  DASHBOARD_HOSTNAME="${WAZUH_DASHBOARD_HOSTNAME:-$WAZUH_DASHBOARD_NODE}"

  if [ -n "$WAZUH_INDEXER_HOSTNAME" ] || [ -n "$WAZUH_MANAGER_HOSTNAME" ] || [ -n "$WAZUH_DASHBOARD_HOSTNAME" ]; then
    if ! is_valid_dns_label "$INDEXER_HOSTNAME" || ! is_valid_dns_label "$MANAGER_HOSTNAME" || ! is_valid_dns_label "$DASHBOARD_HOSTNAME"; then
      echo "Error: invalid WAZUH_*_HOSTNAME value."
      echo "Hostnames must be DNS labels without dots or underscores."
      exit 1
    fi

    set_named_component_hostnames "$INDEXER_HOSTNAME" "$MANAGER_HOSTNAME" "$DASHBOARD_HOSTNAME"
    return 0
  fi

  read -r -p "Customize component hostnames? [y/N]: " CUSTOMIZE_HOSTNAMES

  case "$CUSTOMIZE_HOSTNAMES" in
    y|Y|yes|YES)
      prompt_component_hostname "Indexer" "$WAZUH_INDEXER_NODE"
      INDEXER_HOSTNAME="$COMPONENT_HOSTNAME"
      prompt_component_hostname "Manager" "$WAZUH_MANAGER_NODE"
      MANAGER_HOSTNAME="$COMPONENT_HOSTNAME"
      prompt_component_hostname "Dashboard" "$WAZUH_DASHBOARD_NODE"
      DASHBOARD_HOSTNAME="$COMPONENT_HOSTNAME"
      set_named_component_hostnames "$INDEXER_HOSTNAME" "$MANAGER_HOSTNAME" "$DASHBOARD_HOSTNAME"
      ;;
    *)
      set_named_component_hostnames "$WAZUH_INDEXER_NODE" "$WAZUH_MANAGER_NODE" "$WAZUH_DASHBOARD_NODE"
      ;;
  esac
}

prompt_internal_dns_suffix() {
  local DETECTED_FQDN="$1"
  local DEFAULT_SUFFIX
  local ENTERED_SUFFIX

  if [ "$USE_FIXED_CONTAINER_NAMES" != "yes" ] && [ "$DEPLOYMENT_STACK_MODE" != "multi-node" ]; then
    return 0
  fi

  DEFAULT_SUFFIX="$(host_dns_suffix "$DETECTED_FQDN")"
  if ! is_valid_dns_suffix "$DEFAULT_SUFFIX"; then
    DEFAULT_SUFFIX="local"
  fi

  while true; do
    if [ -n "$WAZUH_INTERNAL_DNS_SUFFIX" ]; then
      ENTERED_SUFFIX="$WAZUH_INTERNAL_DNS_SUFFIX"
    else
      read -r -p "Internal TLS DNS suffix for Docker components [$DEFAULT_SUFFIX]: " ENTERED_SUFFIX
      if [ -z "$ENTERED_SUFFIX" ]; then
        ENTERED_SUFFIX="$DEFAULT_SUFFIX"
      fi
    fi

    if is_valid_dns_suffix "$ENTERED_SUFFIX"; then
      WAZUH_INTERNAL_DNS_SUFFIX="$ENTERED_SUFFIX"
      if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
        set_multi_node_fqdn_names "$WAZUH_INTERNAL_DNS_SUFFIX"
      else
        set_named_component_dns_names "$WAZUH_INTERNAL_DNS_SUFFIX"
      fi
      return 0
    fi

    echo "Invalid DNS suffix: $ENTERED_SUFFIX"
    echo "Use a DNS suffix such as local, lab.example, or customer.example."

    if [ -n "$WAZUH_INTERNAL_DNS_SUFFIX" ]; then
      exit 1
    fi
  done
}

prompt_local_agent_fim_realtime() {
  local ENABLE_FIM

  if [ -n "$EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME" ]; then
    return 0
  fi

  echo "Optional local File Integrity Monitoring (FIM):"
  echo "  File Integrity Monitoring watches selected files and directories for"
  echo "  creation, modification, and deletion events."
  echo "  Enabling realtime FIM on this Docker host changes only a local Wazuh"
  echo "  agent installed at /var/ossec, if one exists."
  echo "  The installer will back up /var/ossec/etc/ossec.conf, configure realtime"
  echo "  monitoring for /etc, /usr/bin, and /usr/sbin, then restart wazuh-agent."
  echo "  This can increase event volume. Leave disabled unless the client approves"
  echo "  realtime integrity monitoring on this host."
  echo ""

  read -r -p "Enable local File Integrity Monitoring (FIM) realtime on this host? [y/N]: " ENABLE_FIM

  case "$ENABLE_FIM" in
    y|Y|yes|YES)
      EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME="yes"
      ;;
    *)
      EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME="no"
      ;;
  esac
}

select_deployment_stack_mode() {
  echo "Wazuh Docker deployment mode:"
  echo "  1) single-node - lab/small PoC on one Docker host"
  echo "  2) multi-node - recommended default for scalable Wazuh Docker deployments"
  echo ""

  while true; do
    read -r -p "Choose Wazuh deployment mode [1/2, default 2]: " DEPLOYMENT_STACK_MODE

    case "$DEPLOYMENT_STACK_MODE" in
      1)
        DEPLOYMENT_STACK_MODE="single-node"
        DEPLOYMENT_STACK_LABEL="Single-node"
        STACK_SUBDIR="single-node"
        WAZUH_INDEXER_NODE="wazuh.indexer"
        WAZUH_MANAGER_NODE="wazuh.manager"
        WAZUH_DASHBOARD_NODE="wazuh.dashboard"
        WAZUH_WORKER_NODE=""
        WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE"
        WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE"
        WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE"
        WAZUH_INDEXER_NODES=("wazuh.indexer")
        WAZUH_MANAGER_NODES=("wazuh.manager")
        WAZUH_DASHBOARD_NODES=("wazuh.dashboard")
        WAZUH_FRONTEND_NODES=()
        WAZUH_CERT_NODES=("wazuh.indexer" "wazuh.manager" "wazuh.dashboard")
        WAZUH_COMPOSE_SERVICES=("wazuh.indexer" "wazuh.manager" "wazuh.dashboard")
        USE_FIXED_CONTAINER_NAMES="no"
        break
        ;;
      2|"")
        DEPLOYMENT_STACK_MODE="multi-node"
        DEPLOYMENT_STACK_LABEL="Multi-node"
        STACK_SUBDIR="multi-node"
        WAZUH_INDEXER_NODE="wazuh-indexer01"
        WAZUH_MANAGER_NODE="wazuh-manager01"
        WAZUH_DASHBOARD_NODE="wazuh-dashboard01"
        WAZUH_WORKER_NODE="wazuh-manager02"
        WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE"
        WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE"
        WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE"
        WAZUH_INDEXER_NODES=("wazuh-indexer01" "wazuh-indexer02" "wazuh-indexer03")
        WAZUH_MANAGER_NODES=("wazuh-manager01" "wazuh-manager02")
        WAZUH_DASHBOARD_NODES=("wazuh-dashboard01")
        WAZUH_FRONTEND_NODES=("nginx")
        WAZUH_CERT_NODES=("wazuh-indexer01" "wazuh-indexer02" "wazuh-indexer03" "wazuh-manager01" "wazuh-manager02" "wazuh-dashboard01")
        WAZUH_COMPOSE_SERVICES=("wazuh-indexer01" "wazuh-indexer02" "wazuh-indexer03" "wazuh-manager01" "wazuh-manager02" "wazuh-dashboard01" "nginx")
        USE_FIXED_CONTAINER_NAMES="no"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done
}

select_deployment_topology() {
  DEPLOYMENT_TOPOLOGY="official"
  if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    DEPLOYMENT_TOPOLOGY_LABEL="Named multi-node component names"
  else
    DEPLOYMENT_TOPOLOGY_LABEL="Official Wazuh Docker names"
  fi

  echo "Wazuh Docker topology:"
  echo "  $DEPLOYMENT_STACK_LABEL - $DEPLOYMENT_TOPOLOGY_LABEL"
  if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    echo "  The official Wazuh Docker multi-node stack is rewritten with clearer"
    echo "  numbered FQDN component names after host FQDN detection."
  else
    echo "  The official Wazuh Docker single-node service names are kept."
  fi
  echo ""
  echo "Wazuh services:"
  printf '  Indexers:  %s\n' "${WAZUH_INDEXER_NODES[*]}"
  printf '  Managers:  %s\n' "${WAZUH_MANAGER_NODES[*]}"
  printf '  Dashboard: %s\n' "${WAZUH_DASHBOARD_NODES[*]}"
  if [ "${#WAZUH_FRONTEND_NODES[@]}" -gt 0 ]; then
    printf '  Frontend:  %s\n' "${WAZUH_FRONTEND_NODES[*]}"
  fi
  echo ""
}

check_public_endpoint_resolution() {
  local ENDPOINT="$1"
  local SERVER_IP="$2"
  local RESOLVED_IP

  if is_valid_ipv4 "$ENDPOINT"; then
    return 0
  fi

  if ! command -v getent >/dev/null 2>&1; then
    echo "Warning: getent command was not found. DNS resolution cannot be checked."
    return 0
  fi

  RESOLVED_IP="$(resolve_first_ipv4 "$ENDPOINT" || true)"

  if [ -z "$RESOLVED_IP" ]; then
    echo "Warning: $ENDPOINT does not currently resolve to an IPv4 address."
    echo "Clients must resolve this FQDN to the Wazuh VM before deployment testing."
    return 0
  fi

  if [ -n "$SERVER_IP" ] && [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
    echo "Warning: $ENDPOINT resolves to $RESOLVED_IP, but this VM IP appears to be $SERVER_IP."
    echo "Update DNS or confirm the detected VM IP before testing client access."
    return 0
  fi

  echo "Dashboard FQDN DNS check: $ENDPOINT resolves to $RESOLVED_IP"
}

print_wazuh_connection_summary() {
  echo "Wazuh connection summary:"
  echo "  Dashboard URL:        https://$PUBLIC_ENDPOINT"
  echo "  Detected server FQDN: $SERVER_FQDN"
  echo "  Detected server IP:   $SERVER_IP"
  echo "  Agent events TCP:     $PUBLIC_ENDPOINT:1514"
  echo "  Agent enrollment TCP: $PUBLIC_ENDPOINT:1515"
  echo "  Syslog UDP:           $PUBLIC_ENDPOINT:514"
  echo "  Manager API HTTPS:    https://$PUBLIC_ENDPOINT:55000"
  echo "  Indexer API HTTPS:    https://$PUBLIC_ENDPOINT:9200"
  echo "  Access depends on DNS, routing, and firewall rules."
  echo "  Do not expose 55000 or 9200 to untrusted networks."
  echo ""
  echo "Internal Docker component names:"
  echo "  Indexers:  ${WAZUH_INDEXER_NODES[*]}"
  echo "  Managers:  ${WAZUH_MANAGER_NODES[*]}"
  echo "  Dashboard: ${WAZUH_DASHBOARD_NODES[*]}"
  if [ "${#WAZUH_FRONTEND_NODES[@]}" -gt 0 ]; then
    echo "  Frontend:  ${WAZUH_FRONTEND_NODES[*]}"
  fi
  echo "Internal TLS DNS names:"
  echo "  Indexer primary:   $WAZUH_INDEXER_DNS"
  echo "  Manager primary:   $WAZUH_MANAGER_DNS"
  echo "  Dashboard primary: $WAZUH_DASHBOARD_DNS"
}

write_wazuh_certificate_config() {
  local CERT_CONFIG_FILE="$1"
  local DASHBOARD_ENDPOINT="$2"

  if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    cat > "$CERT_CONFIG_FILE" <<EOF
nodes:
  # Wazuh indexer server nodes
  indexer:
    - name: ${WAZUH_INDEXER_NODES[0]}
      ip: ${WAZUH_INDEXER_NODES[0]}
    - name: ${WAZUH_INDEXER_NODES[1]}
      ip: ${WAZUH_INDEXER_NODES[1]}
    - name: ${WAZUH_INDEXER_NODES[2]}
      ip: ${WAZUH_INDEXER_NODES[2]}

  # Wazuh server nodes
  server:
    - name: ${WAZUH_MANAGER_NODES[0]}
      ip: ${WAZUH_MANAGER_NODES[0]}
      node_type: master
    - name: ${WAZUH_MANAGER_NODES[1]}
      ip: ${WAZUH_MANAGER_NODES[1]}
      node_type: worker

  # Wazuh dashboard node
  dashboard:
    - name: ${WAZUH_DASHBOARD_NODES[0]}
      ip: ${WAZUH_DASHBOARD_NODES[0]}
EOF
    return 0
  fi

  cat > "$CERT_CONFIG_FILE" <<EOF
nodes:
  # Internal Docker service name used by Wazuh manager and dashboard.
  indexer:
    - name: $WAZUH_INDEXER_NODE
      ip: $WAZUH_INDEXER_DNS

  # Internal Docker service name used by Filebeat/API integrations.
  server:
    - name: $WAZUH_MANAGER_NODE
      ip: $WAZUH_MANAGER_DNS

  # Dashboard host used by browsers. This keeps the dashboard certificate
  # aligned with each client's FQDN while preserving the expected file names.
  dashboard:
    - name: $WAZUH_DASHBOARD_NODE
      ip: $WAZUH_DASHBOARD_DNS
EOF
}

cert_dir_has_files() {
  local CERT_DIR="$1"
  local FILE

  if [ ! -d "$CERT_DIR" ]; then
    return 1
  fi

  for FILE in "$CERT_DIR"/*; do
    if [ -f "$FILE" ]; then
      return 0
    fi
  done

  return 1
}

certificates_match_selected_topology() {
  local CERT_DIR="$1"
  local CERT_NODE

  if [ ! -f "$CERT_DIR/root-ca.pem" ]; then
    return 1
  fi

  for CERT_NODE in "${WAZUH_CERT_NODES[@]}"; do
    if [ ! -f "$CERT_DIR/$CERT_NODE.pem" ]; then
      return 1
    fi
  done

  return 0
}

expected_certificate_metadata() {
  echo "indexer=$WAZUH_INDEXER_NODE;indexer_dns=$WAZUH_INDEXER_DNS;manager=$WAZUH_MANAGER_NODE;manager_dns=$WAZUH_MANAGER_DNS;dashboard=$WAZUH_DASHBOARD_NODE;dashboard_dns=$WAZUH_DASHBOARD_DNS;endpoint=$PUBLIC_ENDPOINT"
}

certificate_metadata_matches() {
  local METADATA_FILE="$1"
  local CURRENT_METADATA

  if [ ! -f "$METADATA_FILE" ]; then
    return 1
  fi

  CURRENT_METADATA="$(sed -n '1p' "$METADATA_FILE")"
  [ "$CURRENT_METADATA" = "$(expected_certificate_metadata)" ]
}

write_certificate_metadata() {
  local METADATA_FILE="$1"

  expected_certificate_metadata > "$METADATA_FILE"
}

rewrite_indexer_tls_endpoint_in_file() {
  local FILE="$1"

  if [ ! -f "$FILE" ]; then
    return 0
  fi

  sed -i \
    -e "s#https://$WAZUH_INDEXER_NODE:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
    -e "s#- $WAZUH_INDEXER_NODE:9200#- $WAZUH_INDEXER_DNS:9200#g" \
    -e "s#=$WAZUH_INDEXER_NODE:9200#=$WAZUH_INDEXER_DNS:9200#g" \
    -e "s#https://wazuh[.]indexer:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
    -e "s#- wazuh[.]indexer:9200#- $WAZUH_INDEXER_DNS:9200#g" \
    -e "s#=wazuh[.]indexer:9200#=$WAZUH_INDEXER_DNS:9200#g" \
    "$FILE"
}

rewrite_wazuh_node_names() {
  local FILE
  local INDEXER_CONFIG_SOURCE="$STACK_DIR/config/wazuh_indexer/wazuh.indexer.yml"
  local INDEXER_CONFIG_TARGET="$STACK_DIR/config/wazuh_indexer/$WAZUH_INDEXER_NODE.yml"

  for FILE in \
    "$COMPOSE_FILE" \
    "$INDEXER_CONFIG_SOURCE" \
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml" \
    "$STACK_DIR/config/wazuh_dashboard/wazuh.yml"; do
    if [ ! -f "$FILE" ]; then
      echo "Error: expected Wazuh configuration file was not found:"
      echo "$FILE"
      exit 1
    fi

    sed -i \
      -e "s/wazuh[.]indexer/$WAZUH_INDEXER_NODE/g" \
      -e "s/wazuh[.]manager/$WAZUH_MANAGER_NODE/g" \
      -e "s/wazuh[.]dashboard/$WAZUH_DASHBOARD_NODE/g" \
      "$FILE"
  done

  # Filebeat, the manager indexer connector, and dashboard indexer clients
  # must use the same DNS name as the indexer certificate SAN. Using only the
  # Docker service name can resolve correctly but fail TLS verification with:
  # "certificate is valid for <fqdn>, not <service>".
  for FILE in \
    "$COMPOSE_FILE" \
    "$STACK_DIR/config/wazuh_cluster/filebeat.yml" \
    "$STACK_DIR/config/wazuh_cluster/wazuh_manager.conf" \
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml"; do
    rewrite_indexer_tls_endpoint_in_file "$FILE"
  done

  if [ "$INDEXER_CONFIG_SOURCE" != "$INDEXER_CONFIG_TARGET" ]; then
    if [ -d "$INDEXER_CONFIG_TARGET" ]; then
      echo "Error: $INDEXER_CONFIG_TARGET exists as a directory."
      echo "This usually happens after Docker tried to bind-mount a missing file."
      echo "Move the generated Wazuh Docker directory away before rerunning the installer."
      exit 1
    fi

    if [ -e "$INDEXER_CONFIG_TARGET" ]; then
      echo "Error: $INDEXER_CONFIG_TARGET already exists."
      echo "Move the generated Wazuh Docker directory away before rerunning the installer."
      exit 1
    fi

    mv "$INDEXER_CONFIG_SOURCE" "$INDEXER_CONFIG_TARGET"
  fi
}

rename_file_if_exists() {
  local SOURCE="$1"
  local TARGET="$2"

  if [ ! -e "$SOURCE" ]; then
    return 0
  fi

  if [ "$SOURCE" = "$TARGET" ]; then
    return 0
  fi

  if [ -e "$TARGET" ]; then
    echo "Error: target file already exists:"
    echo "$TARGET"
    exit 1
  fi

  mv "$SOURCE" "$TARGET"
}

rewrite_multi_node_names() {
  local FILE
  local -a FILES

  FILES=(
    "$COMPOSE_FILE"
    "$STACK_DIR/config/certs.yml"
    "$STACK_DIR/config/nginx/nginx.conf"
    "$STACK_DIR/config/wazuh_cluster/wazuh_manager.conf"
    "$STACK_DIR/config/wazuh_cluster/wazuh_worker.conf"
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml"
    "$STACK_DIR/config/wazuh_dashboard/wazuh.yml"
    "$STACK_DIR/config/wazuh_indexer/wazuh1.indexer.yml"
    "$STACK_DIR/config/wazuh_indexer/wazuh2.indexer.yml"
    "$STACK_DIR/config/wazuh_indexer/wazuh3.indexer.yml"
  )

  for FILE in "${FILES[@]}"; do
    if [ ! -f "$FILE" ]; then
      echo "Error: expected Wazuh multi-node configuration file was not found:"
      echo "$FILE"
      exit 1
    fi

    sed -i \
      -e "s/wazuh1[.]indexer/${WAZUH_INDEXER_NODES[0]}/g" \
      -e "s/wazuh2[.]indexer/${WAZUH_INDEXER_NODES[1]}/g" \
      -e "s/wazuh3[.]indexer/${WAZUH_INDEXER_NODES[2]}/g" \
      -e "s/wazuh[.]master/${WAZUH_MANAGER_NODES[0]}/g" \
      -e "s/wazuh[.]worker/${WAZUH_MANAGER_NODES[1]}/g" \
      -e "s/wazuh[.]dashboard/${WAZUH_DASHBOARD_NODES[0]}/g" \
      "$FILE"
  done

  rename_file_if_exists \
    "$STACK_DIR/config/wazuh_indexer/wazuh1.indexer.yml" \
    "$STACK_DIR/config/wazuh_indexer/${WAZUH_INDEXER_NODES[0]}.yml"
  rename_file_if_exists \
    "$STACK_DIR/config/wazuh_indexer/wazuh2.indexer.yml" \
    "$STACK_DIR/config/wazuh_indexer/${WAZUH_INDEXER_NODES[1]}.yml"
  rename_file_if_exists \
    "$STACK_DIR/config/wazuh_indexer/wazuh3.indexer.yml" \
    "$STACK_DIR/config/wazuh_indexer/${WAZUH_INDEXER_NODES[2]}.yml"
}

assert_named_component_indexer_tls_target() {
  local FILE
  local BAD_MATCHES=""

  for FILE in \
    "$COMPOSE_FILE" \
    "$STACK_DIR/config/wazuh_cluster/filebeat.yml" \
    "$STACK_DIR/config/wazuh_cluster/wazuh_manager.conf" \
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml"; do
    if [ ! -f "$FILE" ]; then
      continue
    fi

    if grep -Eq "(https://|=|- )($WAZUH_INDEXER_NODE|wazuh[.]indexer):9200" "$FILE"; then
      BAD_MATCHES="$BAD_MATCHES $FILE"
    fi
  done

  if [ -n "$BAD_MATCHES" ]; then
    echo "Error: indexer TLS endpoints were not rewritten to $WAZUH_INDEXER_DNS."
    echo "Files with unsafe indexer endpoints:$BAD_MATCHES"
    exit 1
  fi
}

ensure_compose_network_aliases() {
  local SERVICE="$1"
  local DNS_ALIAS="$2"

  if grep -Eq "^[[:space:]]+-[[:space:]]+$DNS_ALIAS$" "$COMPOSE_FILE"; then
    return 0
  fi

  sed -i "/^[[:space:]]\\{2\\}${SERVICE}:/a\\    networks:\\n      default:\\n        aliases:\\n          - $DNS_ALIAS" "$COMPOSE_FILE"
}

ensure_named_component_network_aliases() {
  ensure_compose_network_aliases "$WAZUH_INDEXER_NODE" "$WAZUH_INDEXER_DNS"
  ensure_compose_network_aliases "$WAZUH_MANAGER_NODE" "$WAZUH_MANAGER_DNS"
  ensure_compose_network_aliases "$WAZUH_DASHBOARD_NODE" "$WAZUH_DASHBOARD_DNS"
}

ensure_compose_container_name() {
  local SERVICE="$1"

  if grep -Eq "^[[:space:]]+container_name:[[:space:]]+$SERVICE$" "$COMPOSE_FILE"; then
    return 0
  fi

  sed -i "/^[[:space:]]\\{2\\}${SERVICE}:/a\\    container_name: $SERVICE" "$COMPOSE_FILE"
}

ensure_compose_container_names() {
  ensure_compose_container_name "$WAZUH_INDEXER_NODE"
  ensure_compose_container_name "$WAZUH_MANAGER_NODE"
  ensure_compose_container_name "$WAZUH_DASHBOARD_NODE"
}

assert_single_node_compose_services() {
  local COMPOSE_FILE="$1"
  local MISSING_SERVICES=""
  local SERVICE

  for SERVICE in "${WAZUH_COMPOSE_SERVICES[@]}"; do
    if ! grep -Eq "^[[:space:]]{2}${SERVICE}:" "$COMPOSE_FILE"; then
      MISSING_SERVICES="$MISSING_SERVICES $SERVICE"
    fi
  done

  if [ -n "$MISSING_SERVICES" ]; then
    echo "Error: the expected Wazuh Docker $STACK_SUBDIR stack was not found."
    echo "Missing services:$MISSING_SERVICES"
    echo "Compose file: $COMPOSE_FILE"
    exit 1
  fi
}

assert_single_node_container_names() {
  local MISSING_CONTAINERS=""
  local SERVICE

  for SERVICE in "$WAZUH_INDEXER_NODE" "$WAZUH_MANAGER_NODE" "$WAZUH_DASHBOARD_NODE"; do
    if ! grep -Eq "^[[:space:]]+container_name:[[:space:]]+$SERVICE$" "$COMPOSE_FILE"; then
      MISSING_CONTAINERS="$MISSING_CONTAINERS $SERVICE"
    fi
  done

  if [ -n "$MISSING_CONTAINERS" ]; then
    echo "Error: expected fixed Docker container names were not configured."
    echo "Missing container names:$MISSING_CONTAINERS"
    echo "Compose file: $COMPOSE_FILE"
    exit 1
  fi
}


write_deployment_metadata() {
  local METADATA_DIR="$WAZUH_DIR/easy-wazuh"
  local METADATA_FILE="$METADATA_DIR/deployment.yaml"
  local TMP_FILE
  local BASELINE_WORKERS=0
  local MANAGER_PREFIX="wazuh-manager"
  local MANAGER_WIDTH=2
  local MANAGER_SUFFIX="null"
  local INDEXER_PREFIX="wazuh-indexer"
  local INDEXER_WIDTH=2

  if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    BASELINE_WORKERS=$((${#WAZUH_MANAGER_NODES[@]} - 1))
    if [[ "${WAZUH_MANAGER_NODES[0]}" =~ ^(.+[^0-9])([0-9]+)([.](.+))?$ ]]; then
      MANAGER_PREFIX="${BASH_REMATCH[1]}"
      MANAGER_WIDTH="${#BASH_REMATCH[2]}"
      if [ -n "${BASH_REMATCH[4]:-}" ]; then
        MANAGER_SUFFIX="${BASH_REMATCH[4]}"
      fi
    fi
    if [[ "${WAZUH_INDEXER_NODES[0]}" =~ ^(.+[^0-9])([0-9]+)([.].+)?$ ]]; then
      INDEXER_PREFIX="${BASH_REMATCH[1]}"
      INDEXER_WIDTH="${#BASH_REMATCH[2]}"
    fi
  fi

  mkdir -p "$METADATA_DIR"
  chmod 700 "$METADATA_DIR"
  TMP_FILE="$(mktemp "$METADATA_DIR/deployment.yaml.tmp.XXXXXX")"
  cat > "$TMP_FILE" <<EOF
schema_version: 1

deployment:
  mode: $DEPLOYMENT_STACK_MODE
  stack_directory: $STACK_DIR
  compose_file: docker-compose.yml
  compose_project_name: null

managers:
  prefix: $MANAGER_PREFIX
  number_width: $MANAGER_WIDTH
  internal_dns_suffix: $MANAGER_SUFFIX
  master_index: 1

baseline:
  workers: $BASELINE_WORKERS

indexers:
  prefix: $INDEXER_PREFIX
  number_width: $INDEXER_WIDTH

dashboard:
  count: ${#WAZUH_DASHBOARD_NODES[@]}
  scalable: false
EOF
  chmod 600 "$TMP_FILE"

  if [ -f "$METADATA_FILE" ] && ! cmp -s "$TMP_FILE" "$METADATA_FILE"; then
    echo "Error: Easy-Wazuh deployment metadata already exists and differs:"
    echo "  $METADATA_FILE"
    echo "Refusing to overwrite deployment identity silently."
    rm -f "$TMP_FILE"
    exit 1
  fi

  mv "$TMP_FILE" "$METADATA_FILE"
  echo "Deployment metadata: $METADATA_FILE"
}

# Docker detection helpers are used before making package changes.
docker_is_available() {
  command -v docker >/dev/null 2>&1
}

docker_daemon_is_available() {
  docker_is_available && docker info >/dev/null 2>&1
}

package_is_installed() {
  local PACKAGE="$1"

  dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -q "install ok installed"
}

systemd_unit_is_active() {
  local UNIT="$1"

  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$UNIT"
}

runtime_command_exists() {
  local COMMAND="$1"

  command -v "$COMMAND" >/dev/null 2>&1
}

count_docker_containers() {
  if docker_daemon_is_available; then
    docker ps -aq 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

count_running_docker_containers() {
  if docker_daemon_is_available; then
    docker ps -q 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

count_docker_images() {
  if docker_daemon_is_available; then
    docker images -q 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

# Print a non-destructive inventory of the current Docker host.
print_existing_docker_summary() {
  if docker_is_available; then
    echo "Existing Docker command detected:"
    docker --version || true
  else
    echo "No Docker command detected."
    return 0
  fi

  if docker_daemon_is_available; then
    echo "Docker daemon is reachable."
    echo "Running containers: $(count_running_docker_containers)"
    echo "Total containers:   $(count_docker_containers)"
    echo "Local images:       $(count_docker_images)"
  else
    echo "Docker daemon is not reachable or not running."
  fi
}

# Refuse the fresh install path if container runtimes or workloads already exist.
guard_fresh_install_against_existing_container_runtime() {
  local TOTAL_CONTAINERS="0"
  local RUNNING_CONTAINERS="0"
  local TOTAL_IMAGES="0"
  local CONFLICTS=()
  local PKG
  local CMD
  local UNIT

  for PKG in docker.io docker-ce docker-ce-cli docker-compose docker-compose-plugin podman podman-docker containerd containerd.io runc cri-o cri-o-runc kubelet kubectl kubeadm k3s microk8s; do
    if package_is_installed "$PKG"; then
      CONFLICTS+=("installed package: $PKG")
    fi
  done

  for CMD in docker podman nerdctl ctr crictl kubectl kubelet kubeadm k3s microk8s; do
    if runtime_command_exists "$CMD"; then
      CONFLICTS+=("available command: $CMD")
    fi
  done

  for UNIT in docker docker.socket containerd podman podman.socket crio kubelet k3s snap.microk8s.daemon-containerd snap.microk8s.daemon-kubelite; do
    if systemd_unit_is_active "$UNIT"; then
      CONFLICTS+=("active service: $UNIT")
    fi
  done

  if docker_is_available; then
    echo ""
    echo "Safety check: Docker already appears to be installed on this machine."
    print_existing_docker_summary
    echo ""

    if docker_daemon_is_available; then
      TOTAL_CONTAINERS="$(count_docker_containers)"
      RUNNING_CONTAINERS="$(count_running_docker_containers)"
      TOTAL_IMAGES="$(count_docker_images)"

      if [ "$TOTAL_CONTAINERS" -gt 0 ]; then
        CONFLICTS+=("Docker containers present: $TOTAL_CONTAINERS")
      fi
      if [ "$TOTAL_IMAGES" -gt 0 ]; then
        CONFLICTS+=("Docker images present: $TOTAL_IMAGES")
      fi
    fi
  fi

  if [ "${#CONFLICTS[@]}" -gt 0 ]; then
    echo "Error: this does not look like a fresh Debian container host."
    echo "The selected fresh install mode will not remove or replace existing"
    echo "Docker, Kubernetes, Podman, containerd or CRI components."
    echo ""
    echo "Detected container runtime conflicts:"
    printf '  - %s\n' "${CONFLICTS[@]}"
    echo ""
    echo "Use installation mode 2 to keep the current Docker environment, or prepare"
    echo "a clean host before using fresh install mode."
    echo ""
    if docker_daemon_is_available && [ "$RUNNING_CONTAINERS" -gt 0 ]; then
      echo "Currently running Docker containers:"
      docker ps --format '  {{.Names}}	{{.Image}}	{{.Status}}'
      echo ""
    fi
    exit 1
  fi
}

# Stop before Compose starts Wazuh if another workload already owns a port.
check_wazuh_port_availability() {
  local PORT
  local BUSY_PORTS=""
  local WAZUH_CONTAINERS=""

  if ! command -v ss >/dev/null 2>&1; then
    echo "Warning: ss command was not found. Port availability cannot be checked."
    return 0
  fi

  for PORT in "${WAZUH_PORTS[@]}"; do
    if ss -H -ltnu "( sport = :$PORT )" 2>/dev/null | grep -q .; then
      BUSY_PORTS="$BUSY_PORTS $PORT"
    fi
  done

  if [ -n "$BUSY_PORTS" ]; then
    echo "Error: the following ports required by Wazuh are already in use:$BUSY_PORTS"
    echo ""
    echo "Wazuh default ports:"
    echo "  443    dashboard HTTPS"
    echo "  1514   agent events TCP"
    echo "  1515   agent enrollment TCP"
    echo "  514    syslog UDP"
    echo "  55000  Wazuh server API HTTPS"
    echo "  9200   Wazuh indexer API HTTPS"
    echo ""
    echo "Current listeners on required ports:"
    ss -H -ltnup 2>/dev/null | awk '$5 ~ /:(443|1514|1515|514|55000|9200)$/ {print "  " $0}' || true
    echo ""

    if docker_daemon_is_available; then
      WAZUH_CONTAINERS="$(docker ps -a --filter "name=wazuh" --format '  {{.Names}}	{{.Image}}	{{.Status}}' || true)"
      if [ -n "$WAZUH_CONTAINERS" ]; then
        echo "Wazuh-related containers found:"
        echo "$WAZUH_CONTAINERS"
        echo ""
        echo "For a lab reset, stop the installer and review Wazuh-related containers,"
        echo "volumes and /opt/wazuh manually before any destructive cleanup."
        echo "Do not remove data on a client environment unless data loss is approved."
        echo ""
      fi
    fi

    echo "The installer stops here to avoid breaking existing services or containers."
    exit 1
  fi
}

detect_vcpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return 0
  fi

  getconf _NPROCESSORS_ONLN 2>/dev/null || echo "0"
}

detect_memory_total_gb() {
  awk '/^MemTotal:/ {print int(($2 + 1048576 - 1) / 1048576)}' /proc/meminfo 2>/dev/null || echo "0"
}

existing_parent_path() {
  local TARGET="$1"

  while [ ! -e "$TARGET" ] && [ "$TARGET" != "/" ]; do
    TARGET="$(dirname "$TARGET")"
  done

  echo "$TARGET"
}

detect_disk_free_gb() {
  local TARGET

  TARGET="$(existing_parent_path "$1")"
  df -Pk "$TARGET" 2>/dev/null | awk 'NR == 2 {print int(($4 + 1048576 - 1) / 1048576)}' || echo "0"
}

check_host_resources() {
  local INSTALL_PATH="$1"
  local VCPU
  local MEMORY_GB
  local DISK_FREE_GB
  local REQUIRED_MEMORY_GB
  local REQUIRED_DISK_FREE_GB
  local FAILURES=()

  if [ "$EASY_WAZUH_SKIP_RESOURCE_CHECK" = "yes" ]; then
    echo "Warning: host resource preflight was skipped by EASY_WAZUH_SKIP_RESOURCE_CHECK=yes."
    echo "Only use this override for lab troubleshooting."
    return 0
  fi

  VCPU="$(detect_vcpu_count)"
  MEMORY_GB="$(detect_memory_total_gb)"
  DISK_FREE_GB="$(detect_disk_free_gb "$INSTALL_PATH")"

  if [ -n "$EASY_WAZUH_MIN_MEMORY_GB" ]; then
    REQUIRED_MEMORY_GB="$EASY_WAZUH_MIN_MEMORY_GB"
  elif [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    REQUIRED_MEMORY_GB="$EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE"
  else
    REQUIRED_MEMORY_GB="$EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE"
  fi

  if [ -n "$EASY_WAZUH_MIN_DISK_FREE_GB" ]; then
    REQUIRED_DISK_FREE_GB="$EASY_WAZUH_MIN_DISK_FREE_GB"
  elif [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    REQUIRED_DISK_FREE_GB="$EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE"
  else
    REQUIRED_DISK_FREE_GB="$EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE"
  fi

  VCPU="${VCPU:-0}"
  MEMORY_GB="${MEMORY_GB:-0}"
  DISK_FREE_GB="${DISK_FREE_GB:-0}"

  echo "Host resource preflight:"
  echo "  vCPU:             $VCPU detected, minimum $EASY_WAZUH_MIN_VCPU, recommended $EASY_WAZUH_RECOMMENDED_VCPU"
  echo "  RAM:              ${MEMORY_GB} GB detected, minimum ${REQUIRED_MEMORY_GB} GB"
  echo "  Free disk space:  ${DISK_FREE_GB} GB available for $INSTALL_PATH, minimum ${REQUIRED_DISK_FREE_GB} GB"
  echo ""

  if [ "$VCPU" -lt "$EASY_WAZUH_MIN_VCPU" ]; then
    FAILURES+=("vCPU $VCPU < $EASY_WAZUH_MIN_VCPU")
  elif [ "$VCPU" -lt "$EASY_WAZUH_RECOMMENDED_VCPU" ]; then
    echo "Warning: vCPU $VCPU is below the recommended $EASY_WAZUH_RECOMMENDED_VCPU vCPU for Wazuh Docker."
    echo "The installer will continue, but startup and indexing can be slow on this host."
    echo ""
  fi
  if [ "$MEMORY_GB" -lt "$REQUIRED_MEMORY_GB" ]; then
    FAILURES+=("RAM ${MEMORY_GB} GB < ${REQUIRED_MEMORY_GB} GB")
  fi
  if [ "$DISK_FREE_GB" -lt "$REQUIRED_DISK_FREE_GB" ]; then
    FAILURES+=("free disk ${DISK_FREE_GB} GB < ${REQUIRED_DISK_FREE_GB} GB")
  fi

  if [ "${#FAILURES[@]}" -gt 0 ]; then
    echo "Error: this host is below the minimum resource requirements for this Wazuh PoC deployment."
    printf '  - %s\n' "${FAILURES[@]}"
    echo ""
    echo "Increase the VM resources before installing Wazuh, or rerun with"
    echo "EASY_WAZUH_SKIP_RESOURCE_CHECK=yes only for lab troubleshooting."
    exit 1
  fi
}

# Warn instead of silently colliding with a previous Wazuh deployment.
check_existing_wazuh_containers() {
  local MATCHES

  if ! docker_daemon_is_available; then
    return 0
  fi

  MATCHES="$(docker ps -a --filter "name=wazuh" --format '  {{.Names}}	{{.Image}}	{{.Status}}' || true)"

  if [ -n "$MATCHES" ]; then
    echo "Warning: existing containers with 'wazuh' in their name were found:"
    echo "$MATCHES"
    echo ""
    read -r -p "Continue anyway? [y/N]: " CONFIRM_EXISTING_WAZUH

    case "$CONFIRM_EXISTING_WAZUH" in
      y|Y|yes|YES)
        echo "Continuing with existing Wazuh-related containers present."
        ;;
      *)
        echo "Installation cancelled by user."
        exit 0
        ;;
    esac
    echo ""
  fi
}

guard_wazuh_repo_clean() {
  local REPO_DIR="$1"
  local REPO_STATUS

  REPO_STATUS="$(git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" status --porcelain)"

  if [ -n "$REPO_STATUS" ]; then
    echo "Error: existing Wazuh Docker repository has local changes:"
    echo "$REPO_DIR"
    echo ""
    echo "$REPO_STATUS"
    echo ""
    echo "Move the repository away or review these changes before rerunning the installer."
    echo "This prevents mixing topology rewrites or local edits with a new deployment."
    exit 1
  fi
}

echo "Installation mode:"
echo "  1) Fresh Debian installation - install Docker and prerequisites"
echo "  2) Existing Docker environment - keep current Docker installation"
echo ""

while true; do
  read -r -p "Choose installation mode [1/2]: " INSTALL_MODE

  case "$INSTALL_MODE" in
    1)
      INSTALL_DOCKER="yes"
      INSTALL_MODE_LABEL="Fresh Debian installation"
      break
      ;;
    2)
      INSTALL_DOCKER="no"
      INSTALL_MODE_LABEL="Existing Docker environment"
      break
      ;;
    *)
      echo "Please enter 1 or 2."
      ;;
  esac
done

echo ""
echo "Selected mode: $INSTALL_MODE_LABEL"
echo "Wazuh version: $WAZUH_VERSION"
echo "Deployment: one Docker host/VM PoC/lab only, not production"
echo ""

select_deployment_stack_mode

select_deployment_topology

configure_named_component_hostnames

prompt_local_agent_fim_realtime

echo ""
echo "Selected topology: $DEPLOYMENT_TOPOLOGY_LABEL"
echo "Selected deployment mode: $DEPLOYMENT_STACK_LABEL"
echo "Docker service/container naming:"
echo "  Indexers:  ${WAZUH_INDEXER_NODES[*]}"
echo "  Managers:  ${WAZUH_MANAGER_NODES[*]}"
echo "  Dashboard: ${WAZUH_DASHBOARD_NODES[*]}"
if [ "${#WAZUH_FRONTEND_NODES[@]}" -gt 0 ]; then
  echo "  Frontend:  ${WAZUH_FRONTEND_NODES[*]}"
fi
if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ] || [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
  echo "Internal TLS DNS suffix will be requested after host FQDN detection."
fi
echo "Local File Integrity Monitoring (FIM) realtime: $EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME"
echo ""

read -r -p "Continue with this installation mode and topology? [y/N]: " CONFIRM_INSTALL

case "$CONFIRM_INSTALL" in
  y|Y|yes|YES)
    echo "Continuing installation."
    ;;
  *)
    echo "Installation cancelled by user."
    exit 0
    ;;
esac

echo ""

echo "[1/11] Detecting server FQDN and IP address..."

SERVER_FQDN="$(hostname -f 2>/dev/null || hostname)"
SERVER_IP="$(hostname -I | awk '{print $1}')"
SERVER_DNS_SUFFIX=""

if [ -z "$SERVER_FQDN" ]; then
  SERVER_FQDN="$SERVER_IP"
fi

echo "Detected hostname: $SERVER_FQDN"
echo "Detected IP:   $SERVER_IP"
echo "Mode:          $INSTALL_MODE_LABEL"
echo "Stack:         $DEPLOYMENT_STACK_LABEL"
echo "Topology:      $DEPLOYMENT_TOPOLOGY_LABEL"
echo ""

prompt_internal_dns_suffix "$SERVER_FQDN"

SERVER_DNS_SUFFIX="${WAZUH_INTERNAL_DNS_SUFFIX:-$(host_dns_suffix "$SERVER_FQDN")}"
if ! is_valid_dns_suffix "$SERVER_DNS_SUFFIX"; then
  SERVER_DNS_SUFFIX="local"
fi
SERVER_FQDN="$(server_fqdn_with_suffix "$SERVER_FQDN" "$SERVER_DNS_SUFFIX")"
echo "Detected server FQDN: $SERVER_FQDN"
echo ""

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ] || [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
  echo "Internal TLS DNS suffix: $WAZUH_INTERNAL_DNS_SUFFIX"
  echo "Internal TLS DNS names:"
  if [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
    echo "  Indexers:  ${WAZUH_INDEXER_NODES[*]}"
    echo "  Managers:  ${WAZUH_MANAGER_NODES[*]}"
    echo "  Dashboard: ${WAZUH_DASHBOARD_NODES[*]}"
  else
    echo "  Indexer:   $WAZUH_INDEXER_DNS"
    echo "  Manager:   $WAZUH_MANAGER_DNS"
    echo "  Dashboard: $WAZUH_DASHBOARD_DNS"
  fi
  echo ""
fi

prompt_public_endpoint "$SERVER_FQDN" "$SERVER_IP"

echo "Dashboard URL for clients: https://$PUBLIC_ENDPOINT"
check_public_endpoint_resolution "$PUBLIC_ENDPOINT" "$SERVER_IP"
echo ""
print_wazuh_connection_summary
echo ""

WAZUH_DIR="/opt/wazuh"

echo "[2/12] Checking host resources..."

check_host_resources "$WAZUH_DIR"

echo "Host resources meet the configured minimums."
echo ""

if [ "$INSTALL_DOCKER" = "yes" ]; then
  guard_fresh_install_against_existing_container_runtime
fi

echo "[3/12] Updating package list and installing prerequisites..."

apt update
apt install -y ca-certificates curl git gnupg

echo "Prerequisites installed."
echo ""

if [ "$INSTALL_DOCKER" = "yes" ]; then
  echo "[4/12] Verifying fresh install container runtime preflight..."

  guard_fresh_install_against_existing_container_runtime

  echo "No existing container runtime conflicts detected."
  echo ""

  echo "[5/12] Installing Docker repository key..."

  install -m 0755 -d /etc/apt/keyrings
  rm -f /etc/apt/keyrings/docker.gpg

  curl -fsSL https://download.docker.com/linux/debian/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "Docker key installed."
  echo ""

  echo "[6/12] Adding Docker APT repository..."

  DEBIAN_CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"

  if [ -z "$DEBIAN_CODENAME" ]; then
    echo "Error: Debian VERSION_CODENAME could not be detected."
    exit 1
  fi

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $DEBIAN_CODENAME stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt update

  echo "Docker repository added."
  echo ""

  echo "[7/12] Installing Docker Engine and Docker Compose plugin..."

  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  systemctl enable --now docker

  echo "Docker installed and started."
  echo ""
else
  echo "[4/12] Checking existing Docker environment..."

  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker command was not found."
    echo "Choose mode 1 to install Docker, or install Docker before running this script."
    exit 1
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "Error: Docker Compose plugin was not found."
    echo "Install the Docker Compose plugin, or choose mode 1 on a fresh Debian host."
    exit 1
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet docker || systemctl start docker
  fi

  if ! docker_daemon_is_available; then
    echo "Error: Docker daemon is not reachable."
    exit 1
  fi

  echo "Existing Docker environment detected."
  echo ""
fi

docker --version
docker compose version
echo ""

echo "Docker safety summary:"
print_existing_docker_summary
echo ""

check_existing_wazuh_containers
check_wazuh_port_availability

echo "[8/12] Configuring Wazuh indexer kernel requirement..."

sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuh.conf

echo "vm.max_map_count configured."
echo ""

echo "[9/12] Preparing Wazuh installation directory..."

REPO_DIR="$WAZUH_DIR/wazuh-docker"
STACK_DIR="$REPO_DIR/$STACK_SUBDIR"
COMPOSE_FILE="$STACK_DIR/docker-compose.yml"

mkdir -p "$WAZUH_DIR"

if [ -d "$REPO_DIR/.git" ]; then
  echo "Existing Wazuh Docker repository found. Updating it..."
  guard_wazuh_repo_clean "$REPO_DIR"
  git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" fetch --tags origin
  git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" checkout "$WAZUH_VERSION"
elif [ -e "$REPO_DIR" ]; then
  echo "Error: $REPO_DIR already exists but is not a Git repository."
  echo "Move it away or remove it before running this installer again."
  exit 1
else
  git clone https://github.com/wazuh/wazuh-docker.git -b "$WAZUH_VERSION" "$REPO_DIR"
fi

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Error: Wazuh $STACK_SUBDIR Docker Compose file was not found:"
  echo "$COMPOSE_FILE"
  exit 1
fi

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  rewrite_wazuh_node_names
  ensure_named_component_network_aliases
  ensure_compose_container_names
  assert_named_component_indexer_tls_target
elif [ "$DEPLOYMENT_STACK_MODE" = "multi-node" ]; then
  rewrite_multi_node_names
fi

assert_single_node_compose_services "$COMPOSE_FILE"

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  assert_single_node_container_names
fi

echo "Wazuh directory: $WAZUH_DIR"
echo "Compose file:    $COMPOSE_FILE"
echo "Deployment mode: $DEPLOYMENT_STACK_LABEL"
echo "Docker component names:"
echo "  Indexers:  ${WAZUH_INDEXER_NODES[*]}"
echo "  Managers:  ${WAZUH_MANAGER_NODES[*]}"
echo "  Dashboard: ${WAZUH_DASHBOARD_NODES[*]}"
if [ "${#WAZUH_FRONTEND_NODES[@]}" -gt 0 ]; then
  echo "  Frontend:  ${WAZUH_FRONTEND_NODES[*]}"
fi
echo "Internal TLS DNS names:"
echo "  Indexer primary:   $WAZUH_INDEXER_DNS"
echo "  Manager primary:   $WAZUH_MANAGER_DNS"
echo "  Dashboard primary: $WAZUH_DASHBOARD_DNS"
if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  echo "Fixed container names: enabled"
else
  echo "Fixed container names: disabled, Docker Compose will generate container names"
fi
echo ""

write_deployment_metadata
echo ""

echo "[10/12] Generating Wazuh self-signed certificates..."

cd "$STACK_DIR"

CERT_DIR="$STACK_DIR/config/wazuh_indexer_ssl_certs"
CERT_CONFIG_FILE="$STACK_DIR/config/certs.yml"
CERT_METADATA_FILE="$CERT_DIR/.easy-wazuh-cert-endpoint"

write_wazuh_certificate_config "$CERT_CONFIG_FILE" "$PUBLIC_ENDPOINT"

if certificates_match_selected_topology "$CERT_DIR"; then
  if certificate_metadata_matches "$CERT_METADATA_FILE"; then
    echo "Existing Wazuh certificates found. Keeping them."
  else
    echo "Error: existing Wazuh certificates do not match the selected endpoint metadata."
    echo "Certificate directory: $CERT_DIR"
    echo "Expected metadata:"
    echo "  $(expected_certificate_metadata)"
    echo ""
    echo "Move the existing certificate directory away before changing topology or dashboard host."
    exit 1
  fi
elif cert_dir_has_files "$CERT_DIR"; then
  echo "Error: existing Wazuh certificate files do not match the selected topology."
  echo "Certificate directory: $CERT_DIR"
  echo "Expected certificate files:"
  for CERT_NODE in "${WAZUH_CERT_NODES[@]}"; do
    echo "  $CERT_NODE.pem"
  done
  echo ""
  echo "Move the existing certificate directory away before changing topology."
  exit 1
else
  docker compose -f generate-indexer-certs.yml run --rm -T --interactive=false generator
  write_certificate_metadata "$CERT_METADATA_FILE"
fi

echo "Certificates ready."
echo ""

echo "[11/12] Final confirmation before starting Wazuh containers..."

echo ""
echo "The next step will pull Wazuh Docker images, generate/use local volumes,"
echo "and start the Wazuh $STACK_SUBDIR stack from:"
echo "  $COMPOSE_FILE"
echo ""
read -r -p "Start Wazuh containers now? [y/N]: " CONFIRM_START

case "$CONFIRM_START" in
  y|Y|yes|YES)
    echo "Starting Wazuh containers."
    ;;
  *)
    echo "Wazuh containers were not started."
    echo ""
    echo "You can start them later with:"
    echo "  sudo docker compose -f $COMPOSE_FILE pull"
    echo "  sudo docker compose -f $COMPOSE_FILE up -d"
    exit 0
    ;;
esac

echo ""

echo "[12/12] Starting Wazuh containers..."

docker compose -f "$COMPOSE_FILE" pull
docker compose -f "$COMPOSE_FILE" up -d

echo ""
echo "Waiting for Wazuh containers to become ready..."

wait_for_service() {
  local SERVICE_NAME="$1"
  local CONTAINER_ID
  local STATUS
  local ATTEMPT=1
  local MAX_ATTEMPTS=80
  local SLEEP_SECONDS=15

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    CONTAINER_ID="$(docker compose -f "$COMPOSE_FILE" ps -q "$SERVICE_NAME" || true)"

    if [ -n "$CONTAINER_ID" ]; then
      STATUS="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER_ID" 2>/dev/null || echo "unknown")"
    else
      STATUS="not found"
    fi

    echo "$SERVICE_NAME status: $STATUS - attempt $ATTEMPT/$MAX_ATTEMPTS"

    if [ "$STATUS" = "healthy" ] || [ "$STATUS" = "running" ]; then
      echo "$SERVICE_NAME is ready."
      return 0
    fi

    if [ "$ATTEMPT" -eq "$MAX_ATTEMPTS" ]; then
      echo ""
      echo "Error: $SERVICE_NAME did not become ready in time."
      echo ""
      echo "Last logs from $SERVICE_NAME:"
      docker compose -f "$COMPOSE_FILE" logs --tail=100 "$SERVICE_NAME"
      echo ""
      echo "Current container status:"
      docker compose -f "$COMPOSE_FILE" ps
      exit 1
    fi

    sleep "$SLEEP_SECONDS"
    ATTEMPT=$((ATTEMPT + 1))
  done
}

wait_for_manager_runtime() {
  local MANAGER_CONTAINER
  local ATTEMPT=1
  local MAX_ATTEMPTS=80
  local SLEEP_SECONDS=5

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    MANAGER_CONTAINER="$(manager_container_id)"

    if [ -n "$MANAGER_CONTAINER" ] && \
      docker exec "$MANAGER_CONTAINER" test -f /etc/filebeat/filebeat.yml >/dev/null 2>&1 && \
      docker exec "$MANAGER_CONTAINER" test -f /var/ossec/etc/ossec.conf >/dev/null 2>&1; then
      echo "$WAZUH_MANAGER_NODE runtime is ready."
      return 0
    fi

    echo "$WAZUH_MANAGER_NODE runtime not ready yet - attempt $ATTEMPT/$MAX_ATTEMPTS"

    if [ "$ATTEMPT" -eq "$MAX_ATTEMPTS" ]; then
      echo ""
      echo "Error: $WAZUH_MANAGER_NODE runtime did not become ready in time."
      echo ""
      docker compose -f "$COMPOSE_FILE" logs --tail=150 "$WAZUH_MANAGER_NODE"
      exit 1
    fi

    sleep "$SLEEP_SECONDS"
    ATTEMPT=$((ATTEMPT + 1))
  done
}

wait_for_indexer_api() {
  local ATTEMPT=1
  local MAX_ATTEMPTS=80
  local SLEEP_SECONDS=5

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    if curl -fsSk -u admin:SecretPassword "https://localhost:9200" >/dev/null 2>&1; then
      echo "$WAZUH_INDEXER_NODE API is ready."
      return 0
    fi

    echo "$WAZUH_INDEXER_NODE API not ready yet - attempt $ATTEMPT/$MAX_ATTEMPTS"

    if [ "$ATTEMPT" -eq "$MAX_ATTEMPTS" ]; then
      echo ""
      echo "Error: $WAZUH_INDEXER_NODE API did not become ready in time."
      echo ""
      docker compose -f "$COMPOSE_FILE" logs --tail=150 "$WAZUH_INDEXER_NODE"
      exit 1
    fi

    sleep "$SLEEP_SECONDS"
    ATTEMPT=$((ATTEMPT + 1))
  done
}

validate_named_component_indexer_flow() {
  local MANAGER_CONTAINER="$WAZUH_MANAGER_NODE"
  local INDEXER_ENDPOINT="https://$WAZUH_INDEXER_DNS:9200"
  local LOG_CHECK

  if [ "$USE_FIXED_CONTAINER_NAMES" != "yes" ]; then
    return 0
  fi

  echo ""
  echo "Validating named component DNS and TLS indexer flow..."

  echo "Checking manager DNS resolution for $WAZUH_INDEXER_DNS..."
  docker exec "$MANAGER_CONTAINER" getent hosts "$WAZUH_INDEXER_DNS" >/dev/null

  echo "Checking manager ossec.conf indexer endpoint..."
  docker exec "$MANAGER_CONTAINER" grep -q "$INDEXER_ENDPOINT" /var/ossec/etc/ossec.conf

  echo "Checking Filebeat configuration..."
  docker exec "$MANAGER_CONTAINER" filebeat test config >/dev/null

  echo "Checking Filebeat TLS output..."
  docker exec "$MANAGER_CONTAINER" filebeat test output | tee /tmp/easy-wazuh-filebeat-output.log
  if ! grep -q "handshake.*OK" /tmp/easy-wazuh-filebeat-output.log; then
    echo "Error: Filebeat TLS handshake validation did not report OK."
    exit 1
  fi

  echo "Checking recent manager logs for certificate errors..."
  LOG_CHECK="$(docker logs --tail=300 "$MANAGER_CONTAINER" 2>&1 | grep -E "bad_certificate|certificate is valid for|x509:" || true)"
  if [ -n "$LOG_CHECK" ]; then
    echo "Error: manager logs still contain indexer certificate errors:"
    echo "$LOG_CHECK"
    exit 1
  fi

  echo "Checking indexer API from the Docker host..."
  if ! curl -fsSk -u admin:SecretPassword "https://localhost:9200" >/dev/null; then
    echo "Error: Wazuh indexer API did not respond on https://localhost:9200."
    exit 1
  fi

  echo "Current Wazuh indexer indices, if any:"
  curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-*?v" || true

  echo "Named component indexer DNS/TLS flow is valid."
}

manager_container_id() {
  docker compose -f "$COMPOSE_FILE" ps -q "$WAZUH_MANAGER_NODE"
}

ensure_running_filebeat_tls_endpoint() {
  local MANAGER_CONTAINER

  if [ "$USE_FIXED_CONTAINER_NAMES" != "yes" ]; then
    return 0
  fi

  MANAGER_CONTAINER="$(manager_container_id)"

  if [ -z "$MANAGER_CONTAINER" ]; then
    echo "Error: Wazuh manager container was not found."
    docker compose -f "$COMPOSE_FILE" ps
    exit 1
  fi

  echo ""
  echo "Checking active Filebeat indexer TLS endpoint..."

  if docker exec "$MANAGER_CONTAINER" grep -q "https://$WAZUH_INDEXER_DNS:9200" /etc/filebeat/filebeat.yml; then
    echo "Active Filebeat configuration already uses $WAZUH_INDEXER_DNS."
    return 0
  fi

  if docker exec "$MANAGER_CONTAINER" grep -Eq "https://($WAZUH_INDEXER_NODE|wazuh[.]indexer):9200" /etc/filebeat/filebeat.yml; then
    echo "Updating Compose and active Filebeat configuration to use $WAZUH_INDEXER_DNS..."
    rewrite_indexer_tls_endpoint_in_file "$COMPOSE_FILE"

    docker exec "$MANAGER_CONTAINER" sed -i \
      -e "s#https://$WAZUH_INDEXER_NODE:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
      -e "s#https://wazuh[.]indexer:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
      /etc/filebeat/filebeat.yml

    echo "Recreating Wazuh manager so Filebeat keeps the corrected endpoint..."
    docker compose -f "$COMPOSE_FILE" up -d --force-recreate "$WAZUH_MANAGER_NODE"
    wait_for_service "$WAZUH_MANAGER_NODE"
    wait_for_manager_runtime
    return 0
  fi

  echo "Error: active Filebeat configuration does not contain the expected indexer endpoint."
  docker exec "$MANAGER_CONTAINER" grep -n "hosts:" -A5 /etc/filebeat/filebeat.yml || true
  exit 1
}

wazuh_alerts_template_exists() {
  curl -fsSk -u admin:SecretPassword "https://localhost:9200/_template/wazuh" 2>/dev/null | grep -q "wazuh-alerts" || \
    curl -fsSk -u admin:SecretPassword "https://localhost:9200/_index_template/wazuh" 2>/dev/null | grep -q "wazuh-alerts"
}

wait_for_wazuh_alerts_template() {
  local ATTEMPT=1
  local MAX_ATTEMPTS=24
  local SLEEP_SECONDS=5

  while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    if wazuh_alerts_template_exists; then
      echo "Wazuh alerts index template is present."
      return 0
    fi

    echo "Waiting for Wazuh alerts index template - attempt $ATTEMPT/$MAX_ATTEMPTS"
    sleep "$SLEEP_SECONDS"
    ATTEMPT=$((ATTEMPT + 1))
  done

  echo "Error: Wazuh alerts index template was not found in the indexer."
  echo "The dashboard will show: No template found for wazuh-alerts-*."
  echo ""
  echo "Recent manager logs:"
  docker compose -f "$COMPOSE_FILE" logs --tail=150 "$WAZUH_MANAGER_NODE"
  exit 1
}

validate_filebeat_indexing_setup() {
  local MANAGER_CONTAINER

  MANAGER_CONTAINER="$(manager_container_id)"

  if [ -z "$MANAGER_CONTAINER" ]; then
    echo "Error: Wazuh manager container was not found."
    docker compose -f "$COMPOSE_FILE" ps
    exit 1
  fi

  echo ""
  echo "Validating Filebeat indexer output and Wazuh alert template..."

  echo "Checking Filebeat configuration..."
  docker exec "$MANAGER_CONTAINER" filebeat test config >/dev/null

  echo "Checking Filebeat TLS output..."
  docker exec "$MANAGER_CONTAINER" filebeat test output | tee /tmp/easy-wazuh-filebeat-output.log
  if ! grep -q "handshake.*OK" /tmp/easy-wazuh-filebeat-output.log; then
    echo "Error: Filebeat TLS handshake validation did not report OK."
    exit 1
  fi

  echo "Uploading Wazuh Filebeat ingest pipelines..."
  docker exec "$MANAGER_CONTAINER" filebeat setup --pipelines

  echo "Uploading Wazuh alerts index template..."
  docker exec "$MANAGER_CONTAINER" filebeat setup --index-management -E output.logstash.enabled=false

  wait_for_wazuh_alerts_template

  echo "Current Wazuh alert indices, if any:"
  curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-alerts-*?v" || true
  echo ""
  echo "If this is a fresh deployment with no enrolled agents yet, the template is ready"
  echo "and the first wazuh-alerts-* index will be created when alerts are produced."
}

configure_local_agent_fim_realtime() {
  local AGENT_CONF="/var/ossec/etc/ossec.conf"
  local BACKUP_FILE

  if [ "$EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME" != "yes" ]; then
    return 0
  fi

  echo ""
  echo "Configuring local Wazuh agent FIM realtime monitoring..."

  if [ ! -f "$AGENT_CONF" ]; then
    echo "Warning: local Wazuh agent configuration was not found:"
    echo "  $AGENT_CONF"
    echo "Skipping local agent FIM realtime configuration."
    return 0
  fi

  BACKUP_FILE="$AGENT_CONF.easy-wazuh-fim.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$AGENT_CONF" "$BACKUP_FILE"
  echo "Local agent config backup: $BACKUP_FILE"

  sed -i '/<directories realtime="yes">\/etc<\/directories>/d' "$AGENT_CONF"

  if grep -q '<directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>' "$AGENT_CONF"; then
    echo "Local agent FIM realtime directories are already configured."
  elif grep -q '<directories>/etc,/usr/bin,/usr/sbin</directories>' "$AGENT_CONF"; then
    sed -i \
      's#<directories>/etc,/usr/bin,/usr/sbin</directories>#<directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>#' \
      "$AGENT_CONF"
  else
    sed -i '/<syscheck>/a\    <directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>' "$AGENT_CONF"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
    systemctl restart wazuh-agent
  elif [ -x /var/ossec/bin/wazuh-control ]; then
    /var/ossec/bin/wazuh-control restart
  else
    echo "Warning: local Wazuh agent restart command was not found."
    echo "Restart the local agent manually for FIM realtime to take effect."
    return 0
  fi

  echo "Local Wazuh agent FIM realtime configuration applied."
  echo "Monitored realtime paths: /etc, /usr/bin, /usr/sbin"
}

for SERVICE in "${WAZUH_COMPOSE_SERVICES[@]}"; do
  wait_for_service "$SERVICE"
done
wait_for_indexer_api
wait_for_manager_runtime

ensure_running_filebeat_tls_endpoint
validate_named_component_indexer_flow
validate_filebeat_indexing_setup
configure_local_agent_fim_realtime

echo ""
echo "Current container status:"
docker compose -f "$COMPOSE_FILE" ps
echo ""

echo "=================================================="
echo " Installation completed"
echo "=================================================="
echo ""
echo "Wazuh dashboard should be available at:"
echo ""
echo "  https://$PUBLIC_ENDPOINT"
echo ""
echo "Detected server identity:"
echo "  Dashboard URL:   https://$PUBLIC_ENDPOINT"
echo "  FQDN:            $SERVER_FQDN"
echo "  IP:              $SERVER_IP"
echo ""
print_wazuh_connection_summary
echo ""
echo "Deployed topology:"
echo "  Mode:      $DEPLOYMENT_STACK_LABEL"
echo "  Naming:    $DEPLOYMENT_TOPOLOGY_LABEL"
echo "  Indexers:  ${WAZUH_INDEXER_NODES[*]}"
echo "  Managers:  ${WAZUH_MANAGER_NODES[*]}"
echo "  Dashboard: ${WAZUH_DASHBOARD_NODES[*]}"
if [ "${#WAZUH_FRONTEND_NODES[@]}" -gt 0 ]; then
  echo "  Frontend:  ${WAZUH_FRONTEND_NODES[*]}"
fi
echo ""
echo "Port information:"
echo "  HTTPS uses the standard port 443, so no port needs to be added"
echo "  to the URL unless you changed the Docker Compose port mapping."
echo ""

if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "$PUBLIC_ENDPOINT" ]; then
  echo "Alternative URL using the server IP:"
  echo ""
  echo "  https://$SERVER_IP"
  echo ""
fi

if is_valid_fqdn "$SERVER_FQDN" && [ "$SERVER_FQDN" != "$PUBLIC_ENDPOINT" ]; then
  echo "Alternative URL using the detected FQDN:"
  echo ""
  echo "  https://$SERVER_FQDN"
  echo ""
fi

echo "Default dashboard credentials:"
echo ""
echo "  Username: admin"
echo "  Password: SecretPassword"
echo ""
echo "Important:"
echo "  These are initial Wazuh Docker dashboard credentials only."
echo "  Change the dashboard password and review all default Wazuh Docker"
echo "  credentials before connecting real endpoints or exposing the service."
echo "  Follow the official Wazuh password change procedure because the stack"
echo "  also includes internal service credentials."
echo ""
echo "Certificate warning:"
echo "  If your browser displays a certificate warning, this is expected with"
echo "  the self-signed certificates generated for this PoC $STACK_SUBDIR stack."
echo "  Before using this deployment with real endpoints or exposing it to users,"
echo "  replace the self-signed certificates with official certificates trusted"
echo "  by the client organization or by a recognized certificate authority."
echo "  Review the official Wazuh certificate documentation before replacing"
echo "  certificates."
echo ""
echo "Required next steps before client use:"
echo "  1. Change the default Wazuh passwords using the official Wazuh procedure."
echo "  2. Replace self-signed certificates with trusted official certificates."
echo "  3. Restrict exposed ports to approved admin, agent, API, and syslog networks."
echo ""
echo "Useful commands:"
echo ""
echo "  Check containers:"
echo "    docker compose -f $COMPOSE_FILE ps"
echo ""
echo "  Follow logs:"
echo "    docker compose -f $COMPOSE_FILE logs -f"
echo ""
echo "  Follow dashboard logs:"
echo "    docker compose -f $COMPOSE_FILE logs -f $WAZUH_DASHBOARD_NODE"
echo ""
echo "  Restart Wazuh:"
echo "    docker compose -f $COMPOSE_FILE up -d"
echo ""
echo "  Stop Wazuh:"
echo "    docker compose -f $COMPOSE_FILE down"
echo ""
