"""Multi-platform notification delivery.

多平台通知推送模块：将聚合报告发送到 Slack、Microsoft Teams、飞书/Lark、钉钉等协作工具。
每种平台使用其原生消息格式（Slack Block Kit、Teams Adaptive Card、飞书交互卡片、钉钉 Markdown）。
支持根据报告语言自动切换文案。
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .aggregator import AggregatedReport
from .config import Config
from .i18n import get_strings


def _build_slack_payload(report: AggregatedReport) -> dict[str, Any]:
    """构建 Slack Block Kit 格式消息。
    包含：标题、仓库信息、安全扫描摘要（前 5 个高危漏洞）、PR 评审摘要、测试结果。
    """
    strings = get_strings(report.lang)
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"CodeSentinel Report"},
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*Repo:* `{report.repo}` | *Time:* {report.timestamp}"}
            ],
        },
        {"type": "divider"},
    ]

    # ===== 安全扫描区块 =====
    if report.scan:
        summary = report.scan.get("summary", {})
        findings = report.scan.get("findings", [])
        total = summary.get("total", 0)
        if total > 0:
            sev_text = (
                f"🔴 {summary.get('critical', 0)} critical | "
                f"🟠 {summary.get('high', 0)} high | "
                f"🟡 {summary.get('medium', 0)} medium | "
                f"🔵 {summary.get('low', 0)} low"
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Security Scan:* {total} issues found\n{sev_text}"},
            })
            # 展示前 5 个最严重问题
            for f in findings[:5]:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*[{f.get('severity', 'low').upper()}] {f.get('title', '')}*\n"
                            f"`{f.get('file', '')}:{f.get('line', 0)}` — {f.get('description', '')[:200]}"
                        ),
                    },
                })
        else:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Security Scan:* ✅ No issues found"},
            })
        blocks.append({"type": "divider"})

    # ===== PR 评审区块 =====
    if report.review:
        comments = report.review.get("comments", [])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*PR Review:* {len(comments)} comments | "
                    f"Risk: {report.review.get('risk_level', 'low').upper()}\n"
                    f"{report.review.get('summary', '')[:300]}"
                ),
            },
        })
        blocks.append({"type": "divider"})

    # ===== 测试结果区块 =====
    if report.tests:
        passed = report.tests.get("total_passed", 0)
        failed = report.tests.get("total_failed", 0)
        pass_rate = report.tests.get("pass_rate", 0)
        emoji = "✅" if failed == 0 else "⚠️" if pass_rate > 80 else "❌"
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Test Results {emoji}:* {passed} passed, {failed} failed | "
                    f"Pass rate: {pass_rate:.1f}%"
                ),
            },
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"_{strings['footer']}_"}],
    })

    return {"blocks": blocks}


def _build_teams_payload(report: AggregatedReport) -> dict[str, Any]:
    """构建 Microsoft Teams Adaptive Card 格式消息。
    使用 FactSet 展示关键指标。
    """
    strings = get_strings(report.lang)
    facts: list[dict] = []

    if report.scan:
        s = report.scan.get("summary", {})
        facts.append({"title": "Security Issues", "value": str(s.get("total", 0))})
        facts.append({"title": "Critical / High", "value": f"{s.get('critical', 0)} / {s.get('high', 0)}"})
    if report.review:
        facts.append({"title": "Review Comments", "value": str(len(report.review.get("comments", [])))})
    if report.tests:
        facts.append({"title": "Tests Passed/Failed", "value": f"{report.tests.get('total_passed', 0)} / {report.tests.get('total_failed', 0)}"})

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": "CodeSentinel Report", "weight": "bolder", "size": "large"},
                        {"type": "TextBlock", "text": f"Repo: {report.repo}", "isSubtle": True},
                        {"type": "FactSet", "facts": facts},
                    ],
                },
            }
        ],
    }


def _build_feishu_payload(report: AggregatedReport) -> dict[str, Any]:
    """构建飞书 / Lark 交互式卡片消息。
    使用 markdown 标签渲染各模块摘要。
    """
    strings = get_strings(report.lang)
    elements: list[dict] = []

    if report.scan:
        s = report.scan.get("summary", {})
        elements.append({
            "tag": "markdown",
            "content": f"**{strings['scan_header']}**  \n{strings['scan_summary'].format(files=str(report.scan.get('files_scanned', 0)), issues=str(s.get('total', 0)))}",
        })
    if report.review:
        elements.append({
            "tag": "markdown",
            "content": f"**{strings['review_header']}**  \n{report.review.get('summary', '')[:500]}",
        })
    if report.tests:
        elements.append({
            "tag": "markdown",
            "content": f"**{strings['test_header']}**  \n{strings['test_summary'].format(passed=str(report.tests.get('total_passed', 0)), failed=str(report.tests.get('total_failed', 0)), skipped=str(report.tests.get('total_skipped', 0)), errors=str(report.tests.get('total_errors', 0)))}",
        })

    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": "CodeSentinel Report"},
            },
            "elements": elements,
        },
    }


def _build_dingtalk_payload(report: AggregatedReport) -> dict[str, Any]:
    """构建钉钉 Markdown 消息。
    钉钉机器人仅支持 Markdown 和 Text 两种消息类型。
    """
    strings = get_strings(report.lang)
    md = [f"# CodeSentinel Report  ", f"Repo: {report.repo}  ", ""]

    if report.scan:
        s = report.scan.get("summary", {})
        md.append(f"## {strings['scan_header']}  ")
        md.append(f"{strings['scan_summary'].format(files=str(report.scan.get('files_scanned', 0)), issues=str(s.get('total', 0)))}  ")
    if report.review:
        md.append(f"## {strings['review_header']}  ")
        md.append(f"{report.review.get('summary', '')[:300]}  ")
    if report.tests:
        md.append(f"## {strings['test_header']}  ")
        md.append(f"{strings['test_summary'].format(passed=str(report.tests.get('total_passed', 0)), failed=str(report.tests.get('total_failed', 0)), skipped=str(report.tests.get('total_skipped', 0)), errors=str(report.tests.get('total_errors', 0)))}  ")

    return {
        "msgtype": "markdown",
        "markdown": {"title": "CodeSentinel Report", "text": "\n".join(md)},
    }


class MultiNotifier:
    """多平台通知器：遍历启用的平台，构建对应格式的消息并通过 webhook 发送。"""

    def __init__(self, config: Config) -> None:
        self.config = config

    def notify(self, report: AggregatedReport) -> dict[str, bool]:
        """向所有已启用的平台发送报告。返回各平台推送结果（True/False）。"""
        if not self.config.notify_enabled:
            return {}

        platforms = self.config.notify_platforms
        results: dict[str, bool] = {}

        for name, cfg in platforms.items():
            if not cfg.get("enabled", False):
                continue

            # 从环境变量读取 webhook URL
            env_key = cfg.get("webhook_url_env", "")
            webhook_url = os.getenv(env_key, "") if env_key else ""

            if not webhook_url:
                results[name] = False
                continue

            # 选择对应平台的消息构建函数
            builder = {
                "slack": _build_slack_payload,
                "teams": _build_teams_payload,
                "feishu": _build_feishu_payload,
                "dingtalk": _build_dingtalk_payload,
                "generic": _build_slack_payload,  # 通用 webhook 默认用 Slack 格式
            }.get(name, _build_slack_payload)

            payload = builder(report)
            results[name] = self._send(webhook_url, payload)

        return results

    def _send(self, url: str, payload: dict[str, Any]) -> bool:
        """通过 HTTP POST 发送 webhook 消息。"""
        try:
            resp = httpx.post(url, json=payload, timeout=15)
            return resp.is_success
        except Exception:
            return False


def notify(report: AggregatedReport, config: Config | None = None) -> dict[str, bool]:
    """便捷函数：一键发送通知到所有已配置平台。"""
    if config is None:
        from .config import load_config
        config = load_config()
    notifier = MultiNotifier(config)
    return notifier.notify(report)
