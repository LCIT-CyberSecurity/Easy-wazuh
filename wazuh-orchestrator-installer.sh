#!/bin/bash

set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCH_DIR="$PROJECT_DIR/wazuh-orchestrator"

is_debian_supported() {
  [ -r /etc/os-release ] || return 1
  . /etc/os-release
  [ "${ID:-}" = "debian" ] && { [ "${VERSION_ID:-}" = "12" ] || [ "${VERSION_ID:-}" = "13" ]; }
}

has_docker() {
  command -v docker >/dev/null 2>&1
}

has_compose() {
  has_docker && docker compose version >/dev/null 2>&1
}

install_native() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 was not detected."
    exit 1
  fi
  python3 -m venv "$ORCH_DIR/.venv"
  "$ORCH_DIR/.venv/bin/pip" install -r "$ORCH_DIR/requirements.txt"
  echo "Native installation complete."
  echo ""
  echo "Typical manual workflow:"
  echo "  1. Inspect current deployment:"
  echo "     $ORCH_DIR/.venv/bin/python $ORCH_DIR/wazuh-orchestrator.py status"
  echo "  2. Analyze capacity:"
  echo "     $ORCH_DIR/.venv/bin/python $ORCH_DIR/wazuh-orchestrator.py analyze"
  echo "  3. Prepare a dry-run plan:"
  echo "     $ORCH_DIR/.venv/bin/python $ORCH_DIR/wazuh-orchestrator.py plan --workers <target>"
  echo "  4. Apply manually outside the orchestrator if the recommendation is accepted."
  echo ""
  echo "The V1 scale command is disabled and cannot change the stack."
  echo "Use --debug only for troubleshooting."
}

print_container_note() {
  echo "Container mode is read-only in V1 and must not mount /var/run/docker.sock."
  echo "Configure Wazuh API, Wazuh Indexer API and NGINX health URLs instead."
}

main() {
  if ! is_debian_supported; then
    echo "Error: supported platforms are Debian 12 and Debian 13."
    exit 1
  fi

  if [ ! -d "$ORCH_DIR" ]; then
    echo "Error: orchestrator project directory was not found: $ORCH_DIR"
    exit 1
  fi

  if has_docker && has_compose; then
    echo "Wazuh Orchestrator installation"
    echo ""
    echo "1) Docker container"
    echo "2) Native Python"
    echo "3) Exit"
    read -r -p "Choose installation mode [1/2/3]: " choice
    case "$choice" in
      1)
        print_container_note
        echo "Dockerfile is ready. Build is intentionally not run by this installer."
        ;;
      2) install_native ;;
      *) exit 0 ;;
    esac
  else
    echo "Docker was not detected."
    echo ""
    echo "1) Native Python"
    echo "2) Exit"
    read -r -p "Choose installation mode [1/2]: " choice
    case "$choice" in
      1) install_native ;;
      *) exit 0 ;;
    esac
  fi
}

main "$@"
