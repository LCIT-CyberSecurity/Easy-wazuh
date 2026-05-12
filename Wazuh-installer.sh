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
echo "  The installer can keep the official Wazuh Docker service names, or rename"
echo "  the three component containers for clearer lab deployments."
echo "  This installer is not intended for production deployments."
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Example: sudo ./Wazuh-installer.sh"
  exit 1
fi

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.5}"
WAZUH_PUBLIC_FQDN="${WAZUH_PUBLIC_FQDN:-}"
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
DEPLOYMENT_TOPOLOGY=""
DEPLOYMENT_TOPOLOGY_LABEL=""
USE_FIXED_CONTAINER_NAMES="no"

# Keep version input narrow so it cannot be interpreted as a Git option.
if [[ ! "$WAZUH_VERSION" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "Error: invalid WAZUH_VERSION value: $WAZUH_VERSION"
  echo "Expected format example: v4.14.5"
  exit 1
fi

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

set_named_component_dns_names() {
  local DNS_SUFFIX="$1"

  WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE.$DNS_SUFFIX"
  WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE.$DNS_SUFFIX"
  WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE.$DNS_SUFFIX"
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
  local ENTERED_ENDPOINT

  DEFAULT_ENDPOINT="$DETECTED_FQDN"
  if ! is_valid_public_endpoint "$DEFAULT_ENDPOINT"; then
    DEFAULT_ENDPOINT="$DETECTED_IP"
  fi

  while true; do
    if [ -n "$WAZUH_PUBLIC_FQDN" ]; then
      ENTERED_ENDPOINT="$WAZUH_PUBLIC_FQDN"
    else
      read -r -p "Public FQDN or IP clients will use [$DEFAULT_ENDPOINT]: " ENTERED_ENDPOINT
      if [ -z "$ENTERED_ENDPOINT" ]; then
        ENTERED_ENDPOINT="$DEFAULT_ENDPOINT"
      fi
    fi

    if is_valid_public_endpoint "$ENTERED_ENDPOINT"; then
      PUBLIC_ENDPOINT="$ENTERED_ENDPOINT"
      return 0
    fi

    echo "Invalid public endpoint: $ENTERED_ENDPOINT"
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

  if [ "$USE_FIXED_CONTAINER_NAMES" != "yes" ]; then
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
      set_named_component_dns_names "$WAZUH_INTERNAL_DNS_SUFFIX"
      return 0
    fi

    echo "Invalid DNS suffix: $ENTERED_SUFFIX"
    echo "Use a DNS suffix such as local, lab.example, or customer.example."

    if [ -n "$WAZUH_INTERNAL_DNS_SUFFIX" ]; then
      exit 1
    fi
  done
}

select_deployment_topology() {
  echo "Wazuh Docker topology:"
  echo "  1) Official Wazuh Docker names - default service/container names"
  echo "  2) Three named components - manager, indexer, dashboard as separate containers/images"
  echo ""

  while true; do
    read -r -p "Choose Wazuh topology [1/2]: " DEPLOYMENT_TOPOLOGY

    case "$DEPLOYMENT_TOPOLOGY" in
      1)
        DEPLOYMENT_TOPOLOGY_LABEL="Official Wazuh Docker names"
        WAZUH_INDEXER_NODE="wazuh.indexer"
        WAZUH_MANAGER_NODE="wazuh.manager"
        WAZUH_DASHBOARD_NODE="wazuh.dashboard"
        WAZUH_INDEXER_DNS="$WAZUH_INDEXER_NODE"
        WAZUH_MANAGER_DNS="$WAZUH_MANAGER_NODE"
        WAZUH_DASHBOARD_DNS="$WAZUH_DASHBOARD_NODE"
        USE_FIXED_CONTAINER_NAMES="no"
        break
        ;;
      2)
        DEPLOYMENT_TOPOLOGY_LABEL="Three named components"
        WAZUH_INDEXER_NODE="wazuh-indexer01"
        WAZUH_MANAGER_NODE="wazuh-manager01"
        WAZUH_DASHBOARD_NODE="wazuh-dashboard01"
        set_named_component_dns_names "local"
        USE_FIXED_CONTAINER_NAMES="yes"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done
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

  RESOLVED_IP="$(resolve_first_ipv4 "$ENDPOINT")"

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

  echo "Public endpoint DNS check: $ENDPOINT resolves to $RESOLVED_IP"
}

print_wazuh_connection_summary() {
  echo "Wazuh connection summary:"
  echo "  Dashboard URL:        https://$PUBLIC_ENDPOINT"
  echo "  Agent events TCP:     $PUBLIC_ENDPOINT:1514"
  echo "  Agent enrollment TCP: $PUBLIC_ENDPOINT:1515"
  echo "  Syslog UDP:           $PUBLIC_ENDPOINT:514"
  echo "  Manager API HTTPS:    https://$PUBLIC_ENDPOINT:55000"
  echo "  Indexer API HTTPS:    https://$PUBLIC_ENDPOINT:9200"
  echo "  Access depends on DNS, routing, and firewall rules."
  echo "  Do not expose 55000 or 9200 to untrusted networks."
  echo ""
  echo "Internal Docker component names:"
  echo "  Indexer:   $WAZUH_INDEXER_NODE"
  echo "  Manager:   $WAZUH_MANAGER_NODE"
  echo "  Dashboard: $WAZUH_DASHBOARD_NODE"
  echo "Internal TLS DNS names:"
  echo "  Indexer:   $WAZUH_INDEXER_DNS"
  echo "  Manager:   $WAZUH_MANAGER_DNS"
  echo "  Dashboard: $WAZUH_DASHBOARD_DNS"
}

write_wazuh_certificate_config() {
  local CERT_CONFIG_FILE="$1"
  local DASHBOARD_ENDPOINT="$2"

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

  # Public endpoint used by browsers. This keeps the dashboard certificate
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

  [ -f "$CERT_DIR/root-ca.pem" ] && \
    [ -f "$CERT_DIR/$WAZUH_INDEXER_NODE.pem" ] && \
    [ -f "$CERT_DIR/$WAZUH_MANAGER_NODE.pem" ] && \
    [ -f "$CERT_DIR/$WAZUH_DASHBOARD_NODE.pem" ]
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
  sed -i \
    -e "s#https://$WAZUH_INDEXER_NODE:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
    -e "s#https://wazuh[.]indexer:9200#https://$WAZUH_INDEXER_DNS:9200#g" \
    "$COMPOSE_FILE" \
    "$STACK_DIR/config/wazuh_cluster/wazuh_manager.conf" \
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml"

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

assert_named_component_indexer_tls_target() {
  local FILE
  local BAD_MATCHES=""

  for FILE in \
    "$COMPOSE_FILE" \
    "$STACK_DIR/config/wazuh_cluster/wazuh_manager.conf" \
    "$STACK_DIR/config/wazuh_dashboard/opensearch_dashboards.yml"; do
    if grep -Eq "https://($WAZUH_INDEXER_NODE|wazuh[.]indexer):9200" "$FILE"; then
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

  for SERVICE in "$WAZUH_INDEXER_NODE" "$WAZUH_MANAGER_NODE" "$WAZUH_DASHBOARD_NODE"; do
    if ! grep -Eq "^[[:space:]]{2}${SERVICE}:" "$COMPOSE_FILE"; then
      MISSING_SERVICES="$MISSING_SERVICES $SERVICE"
    fi
  done

  if [ -n "$MISSING_SERVICES" ]; then
    echo "Error: the expected three-service Wazuh Docker stack was not found."
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

# Docker detection helpers are used before making package changes.
docker_is_available() {
  command -v docker >/dev/null 2>&1
}

docker_daemon_is_available() {
  docker_is_available && docker info >/dev/null 2>&1
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

# Refuse the fresh install path if Docker already contains workloads.
guard_fresh_install_against_existing_docker() {
  local TOTAL_CONTAINERS
  local RUNNING_CONTAINERS
  local TOTAL_IMAGES

  if ! docker_is_available; then
    return 0
  fi

  echo ""
  echo "Safety check: Docker already appears to be installed on this machine."
  print_existing_docker_summary
  echo ""

  if docker_daemon_is_available; then
    TOTAL_CONTAINERS="$(count_docker_containers)"
    RUNNING_CONTAINERS="$(count_running_docker_containers)"
    TOTAL_IMAGES="$(count_docker_images)"

    if [ "$TOTAL_CONTAINERS" -gt 0 ] || [ "$TOTAL_IMAGES" -gt 0 ]; then
      echo "Error: this does not look like a fresh Debian Docker host."
      echo "The selected mode could modify the Docker installation while existing"
      echo "containers or images are present."
      echo ""
      echo "Use installation mode 2 to keep the current Docker environment."
      echo ""
      if [ "$RUNNING_CONTAINERS" -gt 0 ]; then
        echo "Currently running containers:"
        docker ps --format '  {{.Names}}	{{.Image}}	{{.Status}}'
        echo ""
      fi
      exit 1
    fi
  fi
}

# Stop before Compose starts Wazuh if another workload already owns a port.
check_wazuh_port_availability() {
  local PORT
  local BUSY_PORTS=""

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
    echo "The installer stops here to avoid breaking existing services or containers."
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

  REPO_STATUS="$(git -C "$REPO_DIR" status --porcelain)"

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

select_deployment_topology

configure_named_component_hostnames

echo ""
echo "Selected topology: $DEPLOYMENT_TOPOLOGY_LABEL"
echo "Docker service/container naming:"
echo "  Indexer:   $WAZUH_INDEXER_NODE"
echo "  Manager:   $WAZUH_MANAGER_NODE"
echo "  Dashboard: $WAZUH_DASHBOARD_NODE"
if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  echo "Internal TLS DNS suffix will be requested after host FQDN detection."
fi
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

if [ -z "$SERVER_FQDN" ]; then
  SERVER_FQDN="$SERVER_IP"
fi

echo "Detected FQDN: $SERVER_FQDN"
echo "Detected IP:   $SERVER_IP"
echo "Mode:          $INSTALL_MODE_LABEL"
echo "Topology:      $DEPLOYMENT_TOPOLOGY_LABEL"
echo ""

prompt_internal_dns_suffix "$SERVER_FQDN"

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  echo "Internal TLS DNS suffix: $WAZUH_INTERNAL_DNS_SUFFIX"
  echo "Internal TLS DNS names:"
  echo "  Indexer:   $WAZUH_INDEXER_DNS"
  echo "  Manager:   $WAZUH_MANAGER_DNS"
  echo "  Dashboard: $WAZUH_DASHBOARD_DNS"
  echo ""
fi

prompt_public_endpoint "$SERVER_FQDN" "$SERVER_IP"

echo "Public endpoint for clients: $PUBLIC_ENDPOINT"
check_public_endpoint_resolution "$PUBLIC_ENDPOINT" "$SERVER_IP"
echo ""
print_wazuh_connection_summary
echo ""

if [ "$INSTALL_DOCKER" = "yes" ]; then
  guard_fresh_install_against_existing_docker
fi

echo "[2/11] Updating package list and installing prerequisites..."

apt update
apt install -y ca-certificates curl git gnupg

echo "Prerequisites installed."
echo ""

if [ "$INSTALL_DOCKER" = "yes" ]; then
  echo "[3/11] Removing conflicting Docker packages if present..."

  for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    apt remove -y "$pkg" || true
  done

  echo "Conflicting packages removed or not present."
  echo ""

  echo "[4/11] Installing Docker repository key..."

  install -m 0755 -d /etc/apt/keyrings
  rm -f /etc/apt/keyrings/docker.gpg

  curl -fsSL https://download.docker.com/linux/debian/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "Docker key installed."
  echo ""

  echo "[5/11] Adding Docker APT repository..."

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

  echo "[6/11] Installing Docker Engine and Docker Compose plugin..."

  apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  systemctl enable --now docker

  echo "Docker installed and started."
  echo ""
else
  echo "[3/11] Checking existing Docker environment..."

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

echo "[7/11] Configuring Wazuh indexer kernel requirement..."

sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuh.conf

echo "vm.max_map_count configured."
echo ""

echo "[8/11] Preparing Wazuh installation directory..."

WAZUH_DIR="/opt/wazuh"
REPO_DIR="$WAZUH_DIR/wazuh-docker"
STACK_DIR="$REPO_DIR/single-node"
COMPOSE_FILE="$STACK_DIR/docker-compose.yml"

mkdir -p "$WAZUH_DIR"

if [ -d "$REPO_DIR/.git" ]; then
  echo "Existing Wazuh Docker repository found. Updating it..."
  guard_wazuh_repo_clean "$REPO_DIR"
  git -C "$REPO_DIR" fetch --tags origin
  git -C "$REPO_DIR" checkout "$WAZUH_VERSION"
elif [ -e "$REPO_DIR" ]; then
  echo "Error: $REPO_DIR already exists but is not a Git repository."
  echo "Move it away or remove it before running this installer again."
  exit 1
else
  git clone https://github.com/wazuh/wazuh-docker.git -b "$WAZUH_VERSION" "$REPO_DIR"
fi

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Error: Wazuh single-node Docker Compose file was not found:"
  echo "$COMPOSE_FILE"
  exit 1
fi

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  rewrite_wazuh_node_names
  ensure_named_component_network_aliases
  ensure_compose_container_names
  assert_named_component_indexer_tls_target
fi

assert_single_node_compose_services "$COMPOSE_FILE"

if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  assert_single_node_container_names
fi

echo "Wazuh directory: $WAZUH_DIR"
echo "Compose file:    $COMPOSE_FILE"
echo "Docker component names:"
echo "  $WAZUH_INDEXER_NODE"
echo "  $WAZUH_MANAGER_NODE"
echo "  $WAZUH_DASHBOARD_NODE"
echo "Internal TLS DNS names:"
echo "  $WAZUH_INDEXER_DNS"
echo "  $WAZUH_MANAGER_DNS"
echo "  $WAZUH_DASHBOARD_DNS"
if [ "$USE_FIXED_CONTAINER_NAMES" = "yes" ]; then
  echo "Fixed container names: enabled"
else
  echo "Fixed container names: disabled, Docker Compose will generate container names"
fi
echo ""

echo "[9/11] Generating Wazuh self-signed certificates..."

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
    echo "Move the existing certificate directory away before changing topology or public endpoint."
    exit 1
  fi
elif cert_dir_has_files "$CERT_DIR"; then
  echo "Error: existing Wazuh certificate files do not match the selected topology."
  echo "Certificate directory: $CERT_DIR"
  echo "Expected certificate files:"
  echo "  $WAZUH_INDEXER_NODE.pem"
  echo "  $WAZUH_MANAGER_NODE.pem"
  echo "  $WAZUH_DASHBOARD_NODE.pem"
  echo ""
  echo "Move the existing certificate directory away before changing topology."
  exit 1
else
  docker compose -f generate-indexer-certs.yml run --rm generator
  write_certificate_metadata "$CERT_METADATA_FILE"
fi

echo "Certificates ready."
echo ""

echo "[10/11] Final confirmation before starting Wazuh containers..."

echo ""
echo "The next step will pull Wazuh Docker images, generate/use local volumes,"
echo "and start the Wazuh single-node stack from:"
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

echo "[11/11] Starting Wazuh containers..."

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

  echo "Checking recent manager logs for indexer TLS/connectivity errors..."
  LOG_CHECK="$(docker logs --tail=300 "$MANAGER_CONTAINER" 2>&1 | grep -E "No available server|bad_certificate|IndexerConnector initialization failed|certificate is valid for" || true)"
  if [ -n "$LOG_CHECK" ]; then
    echo "Error: manager logs still contain indexer connectivity or TLS errors:"
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

wait_for_service "$WAZUH_INDEXER_NODE"
wait_for_service "$WAZUH_MANAGER_NODE"
wait_for_service "$WAZUH_DASHBOARD_NODE"

validate_named_component_indexer_flow

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
print_wazuh_connection_summary
echo ""
echo "Deployed topology:"
echo "  $DEPLOYMENT_TOPOLOGY_LABEL"
echo "  Indexer:   $WAZUH_INDEXER_NODE"
echo "  Manager:   $WAZUH_MANAGER_NODE"
echo "  Dashboard: $WAZUH_DASHBOARD_NODE"
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
echo "  the self-signed certificates generated for this PoC single-node stack."
echo "  For any environment beyond a PoC, review the official Wazuh certificate"
echo "  documentation and use certificates trusted by your organization."
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
