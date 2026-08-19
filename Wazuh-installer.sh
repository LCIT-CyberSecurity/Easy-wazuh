#!/bin/bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

echo "Warning: Wazuh-installer.sh is deprecated."
echo "Use easy-wazuh-bootstrap.sh for new Easy-Wazuh installations."
echo ""

exec "$SCRIPT_DIR/easy-wazuh-bootstrap.sh" "$@"
