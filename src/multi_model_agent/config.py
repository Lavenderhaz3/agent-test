"""Configuration loader — YAML + env vars.

配置加载器：从 YAML 文件和环境变量中读取所有配置项。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# 默认配置文件路径：项目根目录下 config/default.yaml
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    """深度合并两个字典，override 中的值会覆盖 base 中的同名键。"""
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


class Config:
    """配置封装类：提供类型安全的属性访问，优先读取环境变量（环境变量 > YAML 配置 > 默认值）。"""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, *path: str, default: Any = None) -> Any:
        """按路径获取嵌套配置值，如 config.get('models', 'claude', 'model')。"""
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
        """返回原始配置字典。"""
        return self._data

    # ========== 模型配置 ==========

    @property
    def claude_model(self) -> str:
        """Claude 模型名称，环境变量 CLAUDE_MODEL 可覆盖。"""
        return os.getenv("CLAUDE_MODEL", self.get("models", "claude", "model", default="claude-sonnet-4-6"))

    @property
    def gpt_model(self) -> str:
        """GPT 模型名称，环境变量 GPT_MODEL 可覆盖。"""
        return os.getenv("GPT_MODEL", self.get("models", "gpt", "model", default="gpt-4.1"))

    @property
    def claude_max_tokens(self) -> int:
        return self.get("models", "claude", "max_tokens", default=8192)

    @property
    def gpt_max_tokens(self) -> int:
        return self.get("models", "gpt", "max_tokens", default=8192)

    @property
    def claude_temperature(self) -> float:
        """Claude 生成温度（0~1，越低越确定性）。"""
        return self.get("models", "claude", "temperature", default=0.2)

    @property
    def gpt_temperature(self) -> float:
        """GPT 生成温度。"""
        return self.get("models", "gpt", "temperature", default=0.3)

    # ========== 扫描器配置 ==========

    @property
    def scanner_enabled(self) -> bool:
        """是否启用 Claude 安全扫描。"""
        return self.get("scanner", "enabled", default=True)

    @property
    def scanner_ignore_patterns(self) -> list[str]:
        """扫描时忽略的文件/目录匹配模式。"""
        return self.get("scanner", "ignore_patterns", default=[])

    @property
    def scanner_max_file_kb(self) -> int:
        """单文件最大扫描大小（KB）。"""
        return self.get("scanner", "max_file_size_kb", default=200)

    @property
    def scanner_severity_levels(self) -> list[str]:
        """需要报告的漏洞严重级别。"""
        return self.get("scanner", "severity_levels", default=["critical", "high", "medium", "low"])

    @property
    def scanner_categories(self) -> list[str]:
        """需要检测的漏洞类别（如 injection, xss, auth 等）。"""
        return self.get("scanner", "scan_categories", default=[])

    # ========== 评审器配置 ==========

    @property
    def reviewer_enabled(self) -> bool:
        """是否启用 GPT 代码评审。"""
        return self.get("reviewer", "enabled", default=True)

    @property
    def reviewer_categories(self) -> list[str]:
        """PR 评审关注类别（bugs, performance, security 等）。"""
        return self.get("reviewer", "review_categories", default=[])

    @property
    def reviewer_max_diff_kb(self) -> int:
        """单次评审最大 diff 大小（KB）。"""
        return self.get("reviewer", "max_diff_size_kb", default=500)

    # ========== 测试运行器配置 ==========

    @property
    def test_runner_enabled(self) -> bool:
        """是否启用测试自动运行。"""
        return self.get("test_runner", "enabled", default=True)

    @property
    def test_timeout(self) -> int:
        """测试执行超时（秒）。"""
        return self.get("test_runner", "timeout_seconds", default=600)

    @property
    def test_use_claude(self) -> bool:
        """测试失败时是否用 Claude Code 进行根因分析。"""
        return self.get("test_runner", "use_claude_analysis", default=True)

    @property
    def test_frameworks(self) -> dict[str, list[str]]:
        """各语言对应的测试框架命令映射。"""
        return self.get("test_runner", "frameworks", default={})

    # ========== 通知配置 ==========

    @property
    def notify_enabled(self) -> bool:
        """是否启用团队通知推送。"""
        return self.get("notifications", "enabled", default=True)

    @property
    def notify_default_lang(self) -> str:
        """默认报告语言（en/zh/ja/ko 等），环境变量 NOTIFY_LANG 可覆盖。"""
        return os.getenv("NOTIFY_LANG", self.get("notifications", "default_language", default="en"))

    @property
    def notify_supported_langs(self) -> list[str]:
        """支持的语言列表。"""
        return self.get("notifications", "supported_languages", default=["en"])

    @property
    def notify_platforms(self) -> dict[str, dict]:
        """各通知平台的配置（webhook URL 等）。"""
        return self.get("notifications", "platforms", default={})

    # ========== 输出配置 ==========

    @property
    def output_dir(self) -> str:
        """报告输出目录。"""
        return self.get("output", "report_dir", default="./reports")

    @property
    def output_formats(self) -> list[str]:
        """输出格式（json, markdown, html）。"""
        return self.get("output", "format", default=["json", "markdown"])

    @property
    def output_include_snippets(self) -> bool:
        """报告中是否包含问题代码片段。"""
        return self.get("output", "include_snippets", default=True)

    @property
    def output_snippet_lines(self) -> int:
        """代码片段上下文行数。"""
        return self.get("output", "snippet_context_lines", default=5)


def load_config(config_path: str | Path | None = None) -> Config:
    """从 YAML 文件加载配置，文件不存在时返回空配置。"""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if path.exists():
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {}

    return Config(data)
