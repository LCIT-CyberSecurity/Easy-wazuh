#!/usr/bin/env python3
"""CLI for conservative Easy-Wazuh internal certificate preparation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wazuh_certificates.manager import CertificateManager, CertificateSafetyError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Easy-Wazuh certificate helper")
    parser.add_argument("--cert-dir", type=Path, default=Path("/opt/wazuh/wazuh-docker/multi-node/config/wazuh_indexer_ssl_certs"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("validate")
    prepare = sub.add_parser("prepare-worker")
    prepare.add_argument("--node-name", required=True)
    prepare.add_argument("--json", action="store_true")
    cleanup = sub.add_parser("cleanup-worker")
    cleanup.add_argument("--transaction-id", required=True)
    try:
        args = parser.parse_args(argv)
        manager = CertificateManager(args.cert_dir, Path(__file__).resolve().parent)
        if args.command == "status":
            print(json.dumps(manager.status(), sort_keys=True))
        elif args.command == "validate":
            print(json.dumps(manager.validate(), sort_keys=True))
        elif args.command == "prepare-worker":
            result = manager.prepare_worker(args.node_name)
            print(json.dumps(result, sort_keys=True) if args.json else result["status"])
        elif args.command == "cleanup-worker":
            print(json.dumps(manager.cleanup_worker(args.transaction_id), sort_keys=True))
        return 0
    except CertificateSafetyError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
