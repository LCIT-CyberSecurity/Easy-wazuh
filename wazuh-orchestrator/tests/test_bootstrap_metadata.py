from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_bootstrap_script_syntax_name_updated():
    text = (ROOT / "easy-wazuh-bootstrap.sh").read_text(encoding="utf-8")
    assert "write_deployment_metadata" in text
    assert "Wazuh-installer.sh" not in text


def test_metadata_fields_are_generated_by_bootstrap():
    text = (ROOT / "easy-wazuh-bootstrap.sh").read_text(encoding="utf-8")
    for expected in ("schema_version: 1", "stack_directory: $STACK_DIR", "baseline:", "workers: $BASELINE_WORKERS", "dashboard:", "scalable: false"):
        assert expected in text


def test_existing_metadata_not_silently_overwritten():
    text = (ROOT / "easy-wazuh-bootstrap.sh").read_text(encoding="utf-8")
    assert "Refusing to overwrite deployment identity silently" in text
    assert "cmp -s" in text
