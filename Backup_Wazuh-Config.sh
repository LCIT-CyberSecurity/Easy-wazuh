#!/bin/bash

set -Eeuo pipefail
umask 077

BACKUP_ROOT="${BACKUP_ROOT:-/opt/easy-wazuh-backups}"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/backup-$TIMESTAMP"
WAZUH_DIR="${WAZUH_DIR:-/opt/wazuh}"
STACK_TYPE="${STACK_TYPE:-${WAZUH_STACK_TYPE:-}}"
STACK_DIR="${STACK_DIR:-}"
LOCAL_AGENT_CONF="${LOCAL_AGENT_CONF:-/var/ossec/etc/ossec.conf}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
ACTION="${ACTION:-}"
BACKUP_CLIENT_DATA="${BACKUP_CLIENT_DATA:-}"
RESTORE_DIR="${RESTORE_DIR:-}"
RESTORE_CLIENT_DATA="${RESTORE_CLIENT_DATA:-}"

echo "=================================================="
echo " Easy-wazuh backup"
echo "=================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "Error: this script must be run as root."
  echo "Example: sudo ./Backup_Wazuh-Config.sh"
  exit 1
fi

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

ensure_private_directory() {
  local DIRECTORY="$1"

  install -d -m 700 "$DIRECTORY"
}

validate_tar_archive_paths() {
  local ARCHIVE="$1"
  local ENTRY

  if ! tar -tzf "$ARCHIVE" >/dev/null; then
    echo "Error: invalid or unreadable tar archive:"
    echo "  $ARCHIVE"
    exit 1
  fi

  while IFS= read -r ENTRY; do
    case "$ENTRY" in
      ""|/*|..|../*|*/..|*/../*)
        echo "Error: unsafe path found in tar archive:"
        echo "  $ENTRY"
        echo "Archive rejected: $ARCHIVE"
        exit 1
        ;;
    esac
  done < <(tar -tzf "$ARCHIVE")
}

restore_if_exists() {
  local SOURCE="$1"
  local TARGET="$2"

  if [ -e "$SOURCE" ]; then
    mkdir -p "$(dirname "$TARGET")"
    cp -a "$SOURCE" "$TARGET"
    echo "Restored: $TARGET"
  else
    echo "Skipped, not found in backup: $SOURCE"
  fi
}

docker_is_available() {
  command -v docker >/dev/null 2>&1
}

docker_daemon_is_available() {
  docker_is_available && docker info >/dev/null 2>&1
}

set_stack_type() {
  local SELECTED_STACK_TYPE="$1"

  case "$SELECTED_STACK_TYPE" in
    single-node|multi-node)
      STACK_TYPE="$SELECTED_STACK_TYPE"
      ;;
    *)
      echo "Error: invalid stack type: $SELECTED_STACK_TYPE"
      echo "Expected value: single-node or multi-node"
      exit 1
      ;;
  esac

  STACK_DIR="$WAZUH_DIR/wazuh-docker/$STACK_TYPE"

  if [ -z "$COMPOSE_PROJECT_NAME" ]; then
    COMPOSE_PROJECT_NAME="$(basename "$STACK_DIR")"
  fi
}

select_stack_type() {
  local SELECTED_STACK

  if [ -n "$STACK_TYPE" ]; then
    set_stack_type "$STACK_TYPE"
    return 0
  fi

  echo "Wazuh Docker stack type:"
  echo "  1) single-node"
  echo "  2) multi-node"
  echo ""

  while true; do
    read -r -p "Choose stack type [1/2]: " SELECTED_STACK

    case "$SELECTED_STACK" in
      1|"")
        set_stack_type "single-node"
        break
        ;;
      2)
        set_stack_type "multi-node"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done

  echo ""
}

confirm_or_exit() {
  local PROMPT="$1"
  local ANSWER

  read -r -p "$PROMPT [y/N]: " ANSWER

  case "$ANSWER" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      echo "Cancelled."
      exit 0
      ;;
  esac
}

select_action() {
  local SELECTED_ACTION

  if [ -n "$ACTION" ]; then
    case "$ACTION" in
      backup|restore)
        return 0
        ;;
      *)
        echo "Error: invalid ACTION value: $ACTION"
        echo "Expected value: backup or restore"
        exit 1
        ;;
    esac
  fi

  echo "Action:"
  echo "  1) Backup Wazuh"
  echo "  2) Restore Wazuh"
  echo ""

  while true; do
    read -r -p "Choose action [1/2]: " SELECTED_ACTION

    case "$SELECTED_ACTION" in
      1|"")
        ACTION="backup"
        break
        ;;
      2)
        ACTION="restore"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done

  echo ""
}

select_backup_scope() {
  local BACKUP_SCOPE

  if [ -n "$BACKUP_CLIENT_DATA" ]; then
    case "$BACKUP_CLIENT_DATA" in
      yes|no)
        return 0
        ;;
      *)
        echo "Error: invalid BACKUP_CLIENT_DATA value: $BACKUP_CLIENT_DATA"
        echo "Expected value: yes or no"
        exit 1
        ;;
    esac
  fi

  echo "Backup scope:"
  echo "  1) Wazuh configuration only - no client/runtime data"
  echo "  2) Wazuh configuration and client/runtime data from Docker volumes"
  echo ""
  echo "########################################################################"
  echo "# WARNING: if you choose option 1, client data will NOT be backed up. #"
  echo "########################################################################"
  echo ""

  while true; do
    read -r -p "Choose backup scope [1/2]: " BACKUP_SCOPE

    case "$BACKUP_SCOPE" in
      1|"")
        BACKUP_CLIENT_DATA="no"
        break
        ;;
      2)
        BACKUP_CLIENT_DATA="yes"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done

  echo ""
}

select_restore_scope() {
  local RESTORE_SCOPE

  if [ -n "$RESTORE_CLIENT_DATA" ]; then
    case "$RESTORE_CLIENT_DATA" in
      yes|no)
        return 0
        ;;
      *)
        echo "Error: invalid RESTORE_CLIENT_DATA value: $RESTORE_CLIENT_DATA"
        echo "Expected value: yes or no"
        exit 1
        ;;
    esac
  fi

  echo "Restore scope:"
  echo "  1) Restore Wazuh configuration only - no client/runtime data"
  echo "  2) Restore Wazuh configuration and client/runtime data from Docker volumes"
  echo ""
  echo "##########################################################################"
  echo "# WARNING: option 2 overwrites current Docker volume client/runtime data. #"
  echo "##########################################################################"
  echo ""

  while true; do
    read -r -p "Choose restore scope [1/2]: " RESTORE_SCOPE

    case "$RESTORE_SCOPE" in
      1|"")
        RESTORE_CLIENT_DATA="no"
        break
        ;;
      2)
        RESTORE_CLIENT_DATA="yes"
        break
        ;;
      *)
        echo "Please enter 1 or 2."
        ;;
    esac
  done

  echo ""
}

select_restore_dir() {
  local SELECTED_DIR

  if [ -n "$RESTORE_DIR" ]; then
    if [ ! -d "$RESTORE_DIR" ]; then
      echo "Error: restore directory not found: $RESTORE_DIR"
      exit 1
    fi
    return 0
  fi

  echo "Available backups:"
  if [ -d "$BACKUP_ROOT" ]; then
    find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -name 'backup-*' -printf '  %p\n' | sort
  else
    echo "  No backup root found: $BACKUP_ROOT"
  fi
  echo ""

  while true; do
    read -r -p "Backup directory to restore: " SELECTED_DIR

    if [ -d "$SELECTED_DIR" ]; then
      RESTORE_DIR="$SELECTED_DIR"
      break
    fi

    echo "Directory not found: $SELECTED_DIR"
  done

  echo ""
}

restore_stack_backup_dir() {
  local CANDIDATE="$RESTORE_DIR/wazuh-docker-$STACK_TYPE"

  if [ -d "$CANDIDATE" ]; then
    echo "$CANDIDATE"
    return 0
  fi

  # Backward-compatible path for older single-node backups.
  if [ "$STACK_TYPE" = "single-node" ] && [ -d "$RESTORE_DIR/wazuh-docker-single-node" ]; then
    echo "$RESTORE_DIR/wazuh-docker-single-node"
    return 0
  fi

  echo "$CANDIDATE"
}

infer_stack_type_from_restore_dir() {
  local METADATA_FILE="$RESTORE_DIR/easy-wazuh-backup-metadata.env"

  if [ -n "$STACK_TYPE" ]; then
    set_stack_type "$STACK_TYPE"
    return 0
  fi

  if [ -f "$METADATA_FILE" ]; then
    STACK_TYPE="$(sed -n 's/^STACK_TYPE=//p' "$METADATA_FILE" | sed -n '1p')"
    if [ -n "$STACK_TYPE" ]; then
      set_stack_type "$STACK_TYPE"
      return 0
    fi
  fi

  if [ -d "$RESTORE_DIR/wazuh-docker-single-node" ] && [ ! -d "$RESTORE_DIR/wazuh-docker-multi-node" ]; then
    set_stack_type "single-node"
    return 0
  fi

  if [ -d "$RESTORE_DIR/wazuh-docker-multi-node" ] && [ ! -d "$RESTORE_DIR/wazuh-docker-single-node" ]; then
    set_stack_type "multi-node"
    return 0
  fi

  select_stack_type
}

print_config_only_warning() {
  echo "=================================================="
  echo " BIG WARNING - CONFIGURATION BACKUP ONLY"
  echo "=================================================="
  echo "You selected configuration-only backup."
  echo "Client data will NOT be backed up."
  echo ""
  echo "This script intentionally does NOT back up client/runtime data."
  echo ""
  echo "It saves Wazuh configuration files and local metadata only."
  echo "It does NOT save Docker volumes such as:"
  echo "  wazuh-indexer-data, wazuh_logs, wazuh_queue, wazuh_etc,"
  echo "  filebeat_etc, filebeat_var, dashboard volumes, or alert indices."
  echo ""
  echo "Client alerts, indexed events, runtime state, and other data stored in"
  echo "Docker volumes are excluded on purpose."
  echo ""
  echo "Do NOT run 'docker compose down -v' unless you intentionally want to delete"
  echo "those Docker volumes."
  echo "=================================================="
  echo ""
}

print_config_only_restore_warning() {
  echo "=================================================="
  echo " BIG WARNING - CONFIGURATION RESTORE ONLY"
  echo "=================================================="
  echo "You selected configuration-only restore."
  echo "Client data will NOT be restored."
  echo ""
  echo "Only Wazuh Docker configuration files and the local agent configuration,"
  echo "if present in the backup, will be copied back."
  echo "=================================================="
  echo ""
}

print_client_data_warning() {
  echo "=================================================="
  echo " BIG WARNING - CLIENT/RUNTIME DATA BACKUP ENABLED"
  echo "=================================================="
  echo "This backup will include Wazuh Docker volumes that can contain client data:"
  echo "  alerts, indexed events, manager state, Filebeat state, dashboard data,"
  echo "  queues, and runtime logs."
  echo ""
  echo "For the most consistent data backup, stop the Wazuh containers before"
  echo "running this script. Backing up live containers can capture changing data"
  echo "mid-write."
  echo "=================================================="
  echo ""
}

print_client_data_restore_warning() {
  echo "=================================================="
  echo " BIG WARNING - CLIENT/RUNTIME DATA RESTORE ENABLED"
  echo "=================================================="
  echo "This restore will overwrite Wazuh Docker volumes when matching volume"
  echo "archives exist in the selected backup."
  echo ""
  echo "This can replace current alerts, indexed events, manager state, Filebeat"
  echo "state, dashboard data, queues, and runtime logs."
  echo ""
  echo "Stop Wazuh containers before restoring client/runtime data."
  echo "=================================================="
  echo ""
}

docker_compose_declared_volumes() {
  docker compose -f "$STACK_DIR/docker-compose.yml" config --volumes
}

docker_volume_name_for_compose_volume() {
  local LOGICAL_VOLUME="$1"
  local VOLUME_NAME

  VOLUME_NAME="$(docker volume ls \
    --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" \
    --filter "label=com.docker.compose.volume=$LOGICAL_VOLUME" \
    --format '{{.Name}}' | sed -n '1p')"

  if [ -n "$VOLUME_NAME" ]; then
    echo "$VOLUME_NAME"
  else
    echo "${COMPOSE_PROJECT_NAME}_${LOGICAL_VOLUME}"
  fi
}

backup_docker_volume() {
  local LOGICAL_VOLUME="$1"
  local VOLUME_NAME
  local MOUNTPOINT
  local TARGET

  VOLUME_NAME="$(docker_volume_name_for_compose_volume "$LOGICAL_VOLUME")"

  if ! docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
    echo "Skipped, Docker volume not found: $LOGICAL_VOLUME ($VOLUME_NAME)"
    return 0
  fi

  MOUNTPOINT="$(docker volume inspect "$VOLUME_NAME" --format '{{.Mountpoint}}')"
  TARGET="$BACKUP_DIR/docker-volumes/$LOGICAL_VOLUME.tar.gz"

  if [ -z "$MOUNTPOINT" ] || [ ! -d "$MOUNTPOINT" ]; then
    echo "Skipped, Docker volume mountpoint not found: $LOGICAL_VOLUME ($VOLUME_NAME)"
    return 0
  fi

  ensure_private_directory "$(dirname "$TARGET")"
  tar --warning=no-file-changed -C "$MOUNTPOINT" -czf "$TARGET" .
  echo "Saved Docker volume: $LOGICAL_VOLUME ($VOLUME_NAME)"
}

backup_wazuh_docker_volumes() {
  local VOLUME
  local VOLUMES

  if [ "$BACKUP_CLIENT_DATA" != "yes" ]; then
    return 0
  fi

  print_client_data_warning

  if ! docker_daemon_is_available; then
    echo "Error: Docker daemon is not reachable, client/runtime data cannot be backed up."
    exit 1
  fi

  if [ ! -f "$STACK_DIR/docker-compose.yml" ]; then
    echo "Error: Compose file not found, client/runtime data cannot be backed up."
    echo "Missing file: $STACK_DIR/docker-compose.yml"
    exit 1
  fi

  if ! docker compose -f "$STACK_DIR/docker-compose.yml" config --volumes >/dev/null 2>&1; then
    echo "Error: Docker Compose could not read the Wazuh stack."
    exit 1
  fi

  VOLUMES="$(docker_compose_declared_volumes)"

  if [ -z "$VOLUMES" ]; then
    echo "No Docker volumes declared in Compose file."
    echo ""
    return 0
  fi

  echo "Saving Wazuh Docker volumes for Compose project: $COMPOSE_PROJECT_NAME"
  while IFS= read -r VOLUME; do
    [ -n "$VOLUME" ] || continue
    backup_docker_volume "$VOLUME"
  done <<< "$VOLUMES"
  echo ""
}

restore_docker_volume() {
  local LOGICAL_VOLUME="$1"
  local VOLUME_NAME
  local MOUNTPOINT
  local SOURCE

  SOURCE="$RESTORE_DIR/docker-volumes/$LOGICAL_VOLUME.tar.gz"

  if [ ! -f "$SOURCE" ]; then
    echo "Skipped, volume archive not found: $SOURCE"
    return 0
  fi

  VOLUME_NAME="$(docker_volume_name_for_compose_volume "$LOGICAL_VOLUME")"

  if ! docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
    docker volume create "$VOLUME_NAME" >/dev/null
    echo "Created Docker volume: $VOLUME_NAME"
  fi

  MOUNTPOINT="$(docker volume inspect "$VOLUME_NAME" --format '{{.Mountpoint}}')"

  if [ -z "$MOUNTPOINT" ] || [ ! -d "$MOUNTPOINT" ]; then
    echo "Error: Docker volume mountpoint not found: $LOGICAL_VOLUME ($VOLUME_NAME)"
    exit 1
  fi

  validate_tar_archive_paths "$SOURCE"

  find "$MOUNTPOINT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  tar -C "$MOUNTPOINT" -xzf "$SOURCE"
  echo "Restored Docker volume: $LOGICAL_VOLUME ($VOLUME_NAME)"
}

restore_wazuh_docker_volumes() {
  local VOLUME
  local VOLUMES

  if [ "$RESTORE_CLIENT_DATA" != "yes" ]; then
    return 0
  fi

  print_client_data_restore_warning

  if ! docker_daemon_is_available; then
    echo "Error: Docker daemon is not reachable, client/runtime data cannot be restored."
    exit 1
  fi

  if [ ! -d "$RESTORE_DIR/docker-volumes" ]; then
    echo "Error: selected backup does not contain docker-volumes data:"
    echo "  $RESTORE_DIR/docker-volumes"
    exit 1
  fi

  if [ ! -f "$STACK_DIR/docker-compose.yml" ]; then
    echo "Error: Compose file not found after configuration restore:"
    echo "  $STACK_DIR/docker-compose.yml"
    exit 1
  fi

  if ! docker compose -f "$STACK_DIR/docker-compose.yml" config --volumes >/dev/null 2>&1; then
    echo "Error: Docker Compose could not read the restored Wazuh stack."
    exit 1
  fi

  VOLUMES="$(docker_compose_declared_volumes)"

  if [ -z "$VOLUMES" ]; then
    echo "No Docker volumes declared in Compose file."
    echo ""
    return 0
  fi

  confirm_or_exit "Overwrite matching Wazuh Docker volumes from backup"

  echo "Restoring Wazuh Docker volumes for Compose project: $COMPOSE_PROJECT_NAME"
  while IFS= read -r VOLUME; do
    [ -n "$VOLUME" ] || continue
    restore_docker_volume "$VOLUME"
  done <<< "$VOLUMES"
  echo ""
}

run_backup() {
  local BACKUP_STACK_DIR

  select_stack_type
  BACKUP_STACK_DIR="$BACKUP_DIR/wazuh-docker-$STACK_TYPE"

  ensure_private_directory "$BACKUP_ROOT"
  ensure_private_directory "$BACKUP_DIR"

  echo "Backup directory:"
  echo "  $BACKUP_DIR"
  echo ""
  echo "Selected stack type: $STACK_TYPE"
  echo "Stack directory:     $STACK_DIR"
  echo "Compose project:     $COMPOSE_PROJECT_NAME"
  echo ""

  {
    echo "STACK_TYPE=$STACK_TYPE"
    echo "STACK_DIR=$STACK_DIR"
    echo "COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME"
    echo "CREATED_AT=$TIMESTAMP"
  } > "$BACKUP_DIR/easy-wazuh-backup-metadata.env"

  select_backup_scope

  if [ "$BACKUP_CLIENT_DATA" = "yes" ]; then
    echo "Selected backup scope: Wazuh configuration and client/runtime data"
  else
    echo "Selected backup scope: Wazuh configuration only"
    print_config_only_warning
  fi

  echo "Saving Wazuh Docker configuration..."
  copy_if_exists "$STACK_DIR/docker-compose.yml" "$BACKUP_STACK_DIR/docker-compose.yml"
  copy_if_exists "$STACK_DIR/config" "$BACKUP_STACK_DIR/config"
  echo ""

  echo "Saving local Wazuh agent configuration, if present..."
  copy_if_exists "$LOCAL_AGENT_CONF" "$BACKUP_DIR/local-agent/ossec.conf"
  echo ""

  backup_wazuh_docker_volumes

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
}

run_restore() {
  local RESTORE_STACK_DIR

  select_restore_dir
  infer_stack_type_from_restore_dir
  RESTORE_STACK_DIR="$(restore_stack_backup_dir)"
  select_restore_scope

  echo "Restore directory:"
  echo "  $RESTORE_DIR"
  echo ""
  echo "Selected stack type: $STACK_TYPE"
  echo "Stack directory:     $STACK_DIR"
  echo "Compose project:     $COMPOSE_PROJECT_NAME"
  echo ""

  if [ "$RESTORE_CLIENT_DATA" = "yes" ]; then
    echo "Selected restore scope: Wazuh configuration and client/runtime data"
  else
    echo "Selected restore scope: Wazuh configuration only"
    print_config_only_restore_warning
  fi

  confirm_or_exit "Continue with restore"

  echo "Restoring Wazuh Docker configuration..."
  restore_if_exists "$RESTORE_STACK_DIR/docker-compose.yml" "$STACK_DIR/docker-compose.yml"
  restore_if_exists "$RESTORE_STACK_DIR/config" "$STACK_DIR/config"
  echo ""

  echo "Restoring local Wazuh agent configuration, if present..."
  restore_if_exists "$RESTORE_DIR/local-agent/ossec.conf" "$LOCAL_AGENT_CONF"
  echo ""

  restore_wazuh_docker_volumes

  echo ""
  echo "=================================================="
  echo " Restore completed"
  echo "=================================================="
  echo "Restore directory:"
  echo "  $RESTORE_DIR"
  echo ""
  echo "Start or restart Wazuh with:"
  echo "  docker compose -f $STACK_DIR/docker-compose.yml up -d"
}

select_action

case "$ACTION" in
  backup)
    run_backup
    ;;
  restore)
    run_restore
    ;;
esac
