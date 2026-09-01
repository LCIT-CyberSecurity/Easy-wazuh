from __future__ import annotations

import logging

from wazuh_orchestrator.logging_setup import configure_logging


def test_configure_logging_falls_back_to_stderr_when_file_logging_unavailable(monkeypatch, tmp_path):
    def fail_mkdir(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr("pathlib.Path.mkdir", fail_mkdir)

    configure_logging(tmp_path, "INFO")

    handlers = logging.getLogger().handlers
    assert handlers
    assert isinstance(handlers[0], logging.StreamHandler)
