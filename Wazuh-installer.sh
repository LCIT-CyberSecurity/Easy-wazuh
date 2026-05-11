#!/bin/bash

set -Eeuo pipefail

echo "=================================================="
echo " Wazuh Docker installation script"
echo "=================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Example: sudo ./Wazuh-installer.sh"
  exit 1
fi

WAZUH_VERSION="${WAZUH_VERSION:-v4.14.5}"
WAZUH_PORTS=(443 1514 1515 514 55000 9200)

# Keep version input narrow so it cannot be interpreted as a Git option.
if [[ ! "$WAZUH_VERSION" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  echo "Error: invalid WAZUH_VERSION value: $WAZUH_VERSION"
  echo "Expected format example: v4.14.5"
  exit 1
fi

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
echo ""

read -r -p "Continue with this installation mode? [y/N]: " CONFIRM_INSTALL

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

echo "Wazuh directory: $WAZUH_DIR"
echo "Compose file:    $COMPOSE_FILE"
echo ""

echo "[9/11] Generating Wazuh self-signed certificates..."

cd "$STACK_DIR"

CERT_DIR="$STACK_DIR/config/wazuh_indexer_ssl_certs"

if [ -f "$CERT_DIR/root-ca.pem" ] && [ -f "$CERT_DIR/wazuh.dashboard.pem" ]; then
  echo "Existing Wazuh certificates found. Keeping them."
else
  docker compose -f generate-indexer-certs.yml run --rm generator
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

wait_for_service "wazuh.indexer"
wait_for_service "wazuh.manager"
wait_for_service "wazuh.dashboard"

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
echo "  https://$SERVER_FQDN"
echo ""
echo "Port information:"
echo "  HTTPS uses the standard port 443, so no port needs to be added"
echo "  to the URL unless you changed the Docker Compose port mapping."
echo ""

if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "$SERVER_FQDN" ]; then
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
echo "  Change all default Wazuh passwords after the first login."
echo "  The default passwords are defined in the Wazuh Docker Compose"
echo "  configuration and related internal user files."
echo ""
echo "Certificate warning:"
echo "  If your browser displays a certificate warning, this is expected"
echo "  when Wazuh uses its default self-signed HTTPS certificate."
echo "  For a warning-free browser experience, install a TLS certificate"
echo "  issued by a certificate authority trusted by browsers."
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
echo "    docker compose -f $COMPOSE_FILE logs -f wazuh.dashboard"
echo ""
echo "  Restart Wazuh:"
echo "    docker compose -f $COMPOSE_FILE up -d"
echo ""
echo "  Stop Wazuh:"
echo "    docker compose -f $COMPOSE_FILE down"
echo ""
