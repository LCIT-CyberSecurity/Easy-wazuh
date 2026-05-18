#!/bin/bash

set -Eeuo pipefail

BACKUP_ROOT="${BACKUP_ROOT:-/opt/easy-wazuh-backups}"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/backup-$TIMESTAMP"
WAZUH_DIR="${WAZUH_DIR:-/opt/wazuh}"
STACK_DIR="$WAZUH_DIR/wazuh-docker/single-node"
LOCAL_AGENT_CONF="${LOCAL_AGENT_CONF:-/var/ossec/etc/ossec.conf}"

echo "=================================================="
echo " Easy-wazuh configuration backup"
echo "=================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Example: sudo ./Backup_Wazuh-Config.sh"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

copy_if_exists() {
  local SOURCE="$1"
  local TARGET="$2"

  if [ -e "$SOURCE" ]; then
    mkdir -p "$(dirname "$TARGET")"
    cp -a "$SOURCE" "$TARGET"
    echo "Saved: $SOURCE"
  else
    echo "Skipped, not found: $SOURCE"
  fi
}

echo "Backup directory:"
echo "  $BACKUP_DIR"
echo ""

echo "Saving Wazuh Docker configuration..."
copy_if_exists "$STACK_DIR/docker-compose.yml" "$BACKUP_DIR/wazuh-docker-single-node/docker-compose.yml"
copy_if_exists "$STACK_DIR/config" "$BACKUP_DIR/wazuh-docker-single-node/config"
echo ""

echo "Saving local Wazuh agent configuration, if present..."
copy_if_exists "$LOCAL_AGENT_CONF" "$BACKUP_DIR/local-agent/ossec.conf"
echo ""

if [ -d "$WAZUH_DIR" ]; then
  echo "Creating compressed metadata/config archive..."
  tar -C "$(dirname "$WAZUH_DIR")" \
    -czf "$BACKUP_DIR/opt-wazuh-config-and-metadata.tar.gz" \
    --exclude='wazuh/wazuh-docker/.git' \
    --exclude='*.log' \
    "$(basename "$WAZUH_DIR")"
  echo "Saved: $BACKUP_DIR/opt-wazuh-config-and-metadata.tar.gz"
else
  echo "Skipped archive, not found: $WAZUH_DIR"
fi

echo ""
echo "Backup content:"
find "$BACKUP_DIR" -maxdepth 4 -type f -printf '  %p\n' | sort

echo ""
echo "=================================================="
echo " Backup completed"
echo "=================================================="
echo "Backup directory:"
echo "  $BACKUP_DIR"
