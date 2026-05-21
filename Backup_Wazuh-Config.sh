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
ALLOW_PARTIAL_VOLUME_RESTORE="${ALLOW_PARTIAL_VOLUME_RESTORE:-no}"
STOPPED_RUNNING_SERVICES=""
RESTORED_VOLUME_COUNT=0
MISSING_VOLUME_ARCHIVE_COUNT=0

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
    if [ -d "$SOURCE" ] && [ ! -L "$SOURCE" ]; then
      rm -rf "$TARGET"
      mkdir -p "$TARGET"
      cp -a "$SOURCE"/. "$TARGET"/
    else
      rm -rf "$TARGET"
      cp -a "$SOURCE" "$TARGET"
    fi
    echo "Restored: $TARGET"
  else
    echo "Skipped, not found in backup: $SOURCE"
  fi
}

print_disk_space() {
  local PATH_TO_CHECK="$1"

  df -h "$PATH_TO_CHECK" 2>/dev/null | sed 's/^/  /' || true
}

docker_is_available() {
  command -v docker >/dev/null 2>&1
}

docker_daemon_is_available() {
  docker_is_available && docker info >/dev/null 2>&1
}

docker_compose_project_has_resources() {
  local PROJECT_NAME="$1"

  docker_daemon_is_available || return 1

  if docker ps -a \
    --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --format '{{.ID}}' | sed -n '1p' | grep -q .; then
    return 0
  fi

  if docker volume ls \
    --filter "label=com.docker.compose.project=$PROJECT_NAME" \
    --format '{{.Name}}' | sed -n '1p' | grep -q .; then
    return 0
  fi

  return 1
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

auto_detect_stack_type() {
  local SINGLE_STACK_DIR="$WAZUH_DIR/wazuh-docker/single-node"
  local MULTI_STACK_DIR="$WAZUH_DIR/wazuh-docker/multi-node"
  local SINGLE_HAS_DOCKER_RESOURCES="no"
  local MULTI_HAS_DOCKER_RESOURCES="no"
  local SINGLE_HAS_COMPOSE_FILE="no"
  local MULTI_HAS_COMPOSE_FILE="no"

  if docker_compose_project_has_resources "single-node"; then
    SINGLE_HAS_DOCKER_RESOURCES="yes"
  fi

  if docker_compose_project_has_resources "multi-node"; then
    MULTI_HAS_DOCKER_RESOURCES="yes"
  fi

  if [ "$SINGLE_HAS_DOCKER_RESOURCES" = "yes" ] && [ "$MULTI_HAS_DOCKER_RESOURCES" = "no" ]; then
    set_stack_type "single-node"
    echo "Detected Wazuh Docker stack type from Docker resources: $STACK_TYPE"
    echo ""
    return 0
  fi

  if [ "$MULTI_HAS_DOCKER_RESOURCES" = "yes" ] && [ "$SINGLE_HAS_DOCKER_RESOURCES" = "no" ]; then
    set_stack_type "multi-node"
    echo "Detected Wazuh Docker stack type from Docker resources: $STACK_TYPE"
    echo ""
    return 0
  fi

  if [ -f "$SINGLE_STACK_DIR/docker-compose.yml" ]; then
    SINGLE_HAS_COMPOSE_FILE="yes"
  fi

  if [ -f "$MULTI_STACK_DIR/docker-compose.yml" ]; then
    MULTI_HAS_COMPOSE_FILE="yes"
  fi

  if [ "$SINGLE_HAS_COMPOSE_FILE" = "yes" ] && [ "$MULTI_HAS_COMPOSE_FILE" = "no" ]; then
    set_stack_type "single-node"
    echo "Detected Wazuh Docker stack type from installed files: $STACK_TYPE"
    echo ""
    return 0
  fi

  if [ "$MULTI_HAS_COMPOSE_FILE" = "yes" ] && [ "$SINGLE_HAS_COMPOSE_FILE" = "no" ]; then
    set_stack_type "multi-node"
    echo "Detected Wazuh Docker stack type from installed files: $STACK_TYPE"
    echo ""
    return 0
  fi

  return 1
}

select_stack_type() {
  local SELECTED_STACK

  if [ -n "$STACK_TYPE" ]; then
    set_stack_type "$STACK_TYPE"
    return 0
  fi

  if auto_detect_stack_type; then
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
  local DEFAULT_RESTORE_DIR=""
  local BACKUP_COUNT=0
  local BACKUP_DIR_CANDIDATE

  if [ -n "$RESTORE_DIR" ]; then
    if [ ! -d "$RESTORE_DIR" ]; then
      echo "Error: restore directory not found: $RESTORE_DIR"
      exit 1
    fi
    return 0
  fi

  echo "Available backups:"
  if [ -d "$BACKUP_ROOT" ]; then
    while IFS= read -r BACKUP_DIR_CANDIDATE; do
      BACKUP_COUNT=$((BACKUP_COUNT + 1))
      DEFAULT_RESTORE_DIR="$BACKUP_DIR_CANDIDATE"
      echo "  $BACKUP_DIR_CANDIDATE"
    done < <(find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -name 'backup-*' -printf '%p\n' | sort)
  else
    echo "  No backup root found: $BACKUP_ROOT"
  fi
  echo ""

  while true; do
    if [ "$BACKUP_COUNT" -eq 1 ]; then
      read -r -p "Backup directory to restore [$DEFAULT_RESTORE_DIR]: " SELECTED_DIR
      if [ -z "$SELECTED_DIR" ]; then
        SELECTED_DIR="$DEFAULT_RESTORE_DIR"
      fi
    else
      read -r -p "Backup directory to restore: " SELECTED_DIR
    fi

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
  echo "The script will stop running Wazuh containers before archiving Docker"
  echo "volumes, then restart the services it stopped after the backup."
  echo ""
  echo "Make sure the backup destination has enough free disk space. The default"
  echo "BACKUP_ROOT is on this VM under /opt/easy-wazuh-backups, so a full client"
  echo "data backup can fill the same disk used by Wazuh and Docker."
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
  echo "The script will stop running Wazuh containers before restoring Docker"
  echo "volumes, then restart the services it stopped after the restore."
  echo "=================================================="
  echo ""
}

docker_compose_declared_volumes() {
  docker compose -f "$STACK_DIR/docker-compose.yml" config --volumes
}

docker_compose_declared_services() {
  docker compose -f "$STACK_DIR/docker-compose.yml" config --services
}

docker_compose_running_services() {
  local SERVICE
  local CONTAINER_ID
  local RUNNING

  while IFS= read -r SERVICE; do
    [ -n "$SERVICE" ] || continue

    CONTAINER_ID="$(docker compose -f "$STACK_DIR/docker-compose.yml" ps -q "$SERVICE" 2>/dev/null || true)"
    [ -n "$CONTAINER_ID" ] || continue

    RUNNING="$(docker inspect --format '{{.State.Running}}' "$CONTAINER_ID" 2>/dev/null || echo "false")"
    if [ "$RUNNING" = "true" ]; then
      echo "$SERVICE"
    fi
  done < <(docker_compose_declared_services)
}

restart_stopped_wazuh_containers() {
  local OPERATION_LABEL="$1"
  local SERVICES_TO_START

  if [ -z "$STOPPED_RUNNING_SERVICES" ]; then
    return 0
  fi

  SERVICES_TO_START="$STOPPED_RUNNING_SERVICES"
  STOPPED_RUNNING_SERVICES=""
  trap - EXIT

  echo "Restarting Wazuh containers that were stopped for $OPERATION_LABEL..."
  docker compose -f "$STACK_DIR/docker-compose.yml" start $SERVICES_TO_START
  echo ""
}

restart_stopped_wazuh_containers_after_backup() {
  restart_stopped_wazuh_containers "backup"
}

restart_stopped_wazuh_containers_after_restore() {
  restart_stopped_wazuh_containers "restore"
}

stop_wazuh_containers() {
  local OPERATION_LABEL="$1"

  STOPPED_RUNNING_SERVICES="$(docker_compose_running_services)"

  if [ -z "$STOPPED_RUNNING_SERVICES" ]; then
    echo "No running Wazuh containers found for this Compose stack."
    echo ""
    return 0
  fi

  echo "Stopping Wazuh containers before client/runtime data $OPERATION_LABEL..."
  while IFS= read -r SERVICE; do
    [ -n "$SERVICE" ] || continue
    echo "  $SERVICE"
  done <<< "$STOPPED_RUNNING_SERVICES"

  if [ "$OPERATION_LABEL" = "backup" ]; then
    trap restart_stopped_wazuh_containers_after_backup EXIT
  else
    trap restart_stopped_wazuh_containers_after_restore EXIT
  fi

  docker compose -f "$STACK_DIR/docker-compose.yml" stop $STOPPED_RUNNING_SERVICES
  echo ""
}

stop_wazuh_containers_before_backup() {
  stop_wazuh_containers "backup"
}

stop_wazuh_containers_before_restore() {
  stop_wazuh_containers "restore"
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

  stop_wazuh_containers_before_backup

  echo "Saving Wazuh Docker volumes for Compose project: $COMPOSE_PROJECT_NAME"
  while IFS= read -r VOLUME; do
    [ -n "$VOLUME" ] || continue
    backup_docker_volume "$VOLUME"
  done <<< "$VOLUMES"
  echo ""

  restart_stopped_wazuh_containers_after_backup
}

restore_docker_volume() {
  local LOGICAL_VOLUME="$1"
  local VOLUME_NAME
  local MOUNTPOINT
  local SOURCE

  SOURCE="$RESTORE_DIR/docker-volumes/$LOGICAL_VOLUME.tar.gz"

  if [ ! -f "$SOURCE" ]; then
    MISSING_VOLUME_ARCHIVE_COUNT=$((MISSING_VOLUME_ARCHIVE_COUNT + 1))
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
  RESTORED_VOLUME_COUNT=$((RESTORED_VOLUME_COUNT + 1))
  echo "Restored Docker volume: $LOGICAL_VOLUME ($VOLUME_NAME)"
}

assert_restore_has_all_volume_archives() {
  local VOLUMES="$1"
  local VOLUME
  local SOURCE
  local MISSING_ARCHIVES=""
  local MISSING_COUNT=0

  while IFS= read -r VOLUME; do
    [ -n "$VOLUME" ] || continue

    SOURCE="$RESTORE_DIR/docker-volumes/$VOLUME.tar.gz"
    if [ ! -f "$SOURCE" ]; then
      MISSING_COUNT=$((MISSING_COUNT + 1))
      MISSING_ARCHIVES="$MISSING_ARCHIVES
  $SOURCE"
    fi
  done <<< "$VOLUMES"

  if [ "$MISSING_COUNT" -eq 0 ]; then
    return 0
  fi

  echo "Error: selected backup is missing $MISSING_COUNT Docker volume archive(s):"
  echo "$MISSING_ARCHIVES"
  echo ""
  echo "Restore stopped to avoid a partial Wazuh runtime restore."
  echo "Use a complete backup, or set ALLOW_PARTIAL_VOLUME_RESTORE=yes if you"
  echo "intentionally want to restore only the archives that are present."

  if [ "$ALLOW_PARTIAL_VOLUME_RESTORE" = "yes" ]; then
    echo ""
    echo "ALLOW_PARTIAL_VOLUME_RESTORE=yes is set, continuing with partial restore."
    echo ""
    return 0
  fi

  exit 1
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

  assert_restore_has_all_volume_archives "$VOLUMES"

  confirm_or_exit "Overwrite matching Wazuh Docker volumes from backup"

  stop_wazuh_containers_before_restore

  echo "Restoring Wazuh Docker volumes for Compose project: $COMPOSE_PROJECT_NAME"
  while IFS= read -r VOLUME; do
    [ -n "$VOLUME" ] || continue
    restore_docker_volume "$VOLUME"
  done <<< "$VOLUMES"
  echo ""

  echo "Docker volume restore summary:"
  echo "  Restored archives: $RESTORED_VOLUME_COUNT"
  echo "  Missing archives:  $MISSING_VOLUME_ARCHIVE_COUNT"
  if [ "$MISSING_VOLUME_ARCHIVE_COUNT" -gt 0 ]; then
    echo "Warning: restore is partial because some declared Docker volumes were not present in the backup."
  fi
  echo ""

  restart_stopped_wazuh_containers_after_restore
}

run_backup() {
  local BACKUP_STACK_DIR

  select_stack_type
  BACKUP_STACK_DIR="$BACKUP_DIR/wazuh-docker-$STACK_TYPE"

  ensure_private_directory "$BACKUP_ROOT"
  ensure_private_directory "$BACKUP_DIR"

  echo "Backup directory:"
  echo "  $BACKUP_DIR"
  echo "Backup filesystem free space:"
  print_disk_space "$BACKUP_ROOT"
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
