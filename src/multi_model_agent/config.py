"""Configuration loader — YAML + env vars."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


class Config:
    """Typed wrapper around the YAML config dict."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, *path: str, default: Any = None) -> Any:
        node = self._data
        for key in path:
            if isinstance(node, dict):
                node = node.get(key)
            else:
                return default
            if node is None:
                return default
        return node

    @property
    def raw(self) -> dict[str, Any]:
        return self._data

    # --- Models ---
    @property
    def claude_model(self) -> str:
        return os.getenv("CLAUDE_MODEL", self.get("models", "claude", "model", default="claude-sonnet-4-6"))

    @property
    def gpt_model(self) -> str:
        return os.getenv("GPT_MODEL", self.get("models", "gpt", "model", default="gpt-4.1"))

    @property
    def claude_max_tokens(self) -> int:
        return self.get("models", "claude", "max_tokens", default=8192)

    @property
    def gpt_max_tokens(self) -> int:
        return self.get("models", "gpt", "max_tokens", default=8192)

    @property
    def claude_temperature(self) -> float:
        return self.get("models", "claude", "temperature", default=0.2)

    @property
    def gpt_temperature(self) -> float:
        return self.get("models", "gpt", "temperature", default=0.3)

    # --- Scanner ---
    @property
    def scanner_enabled(self) -> bool:
        return self.get("scanner", "enabled", default=True)

    @property
    def scanner_ignore_patterns(self) -> list[str]:
        return self.get("scanner", "ignore_patterns", default=[])

    @property
    def scanner_max_file_kb(self) -> int:
        return self.get("scanner", "max_file_size_kb", default=200)

    @property
    def scanner_severity_levels(self) -> list[str]:
        return self.get("scanner", "severity_levels", default=["critical", "high", "medium", "low"])

    @property
    def scanner_categories(self) -> list[str]:
        return self.get("scanner", "scan_categories", default=[])

    # --- Reviewer ---
    @property
    def reviewer_enabled(self) -> bool:
        return self.get("reviewer", "enabled", default=True)

    @property
    def reviewer_categories(self) -> list[str]:
        return self.get("reviewer", "review_categories", default=[])

    @property
    def reviewer_max_diff_kb(self) -> int:
        return self.get("reviewer", "max_diff_size_kb", default=500)

    # --- Test Runner ---
    @property
    def test_runner_enabled(self) -> bool:
        return self.get("test_runner", "enabled", default=True)

    @property
    def test_timeout(self) -> int:
        return self.get("test_runner", "timeout_seconds", default=600)

    @property
    def test_use_claude(self) -> bool:
        return self.get("test_runner", "use_claude_analysis", default=True)

    @property
    def test_frameworks(self) -> dict[str, list[str]]:
        return self.get("test_runner", "frameworks", default={})

    # --- Notifications ---
    @property
    def notify_enabled(self) -> bool:
        return self.get("notifications", "enabled", default=True)

    @property
    def notify_default_lang(self) -> str:
        return os.getenv("NOTIFY_LANG", self.get("notifications", "default_language", default="en"))

    @property
    def notify_supported_langs(self) -> list[str]:
        return self.get("notifications", "supported_languages", default=["en"])

    @property
    def notify_platforms(self) -> dict[str, dict]:
        return self.get("notifications", "platforms", default={})

    # --- Output ---
    @property
    def output_dir(self) -> str:
        return self.get("output", "report_dir", default="./reports")

    @property
    def output_formats(self) -> list[str]:
        return self.get("output", "format", default=["json", "markdown"])

    @property
    def output_include_snippets(self) -> bool:
        return self.get("output", "include_snippets", default=True)

    @property
    def output_snippet_lines(self) -> int:
        return self.get("output", "snippet_context_lines", default=5)


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from YAML file, merging with env vars."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if path.exists():
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {}

    return Config(data)
