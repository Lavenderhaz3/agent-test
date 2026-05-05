"""Multi-platform notification delivery.

Sends aggregated reports to Slack, Microsoft Teams, Feishu/Lark,
DingTalk, and generic webhook endpoints with i18n-aware formatting.
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
    """Build a Slack Block Kit message."""
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

    # Security scan section
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
            # Top issues (max 5)
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

    # PR review section
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

    # Test results section
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
    """Build a Microsoft Teams Adaptive Card."""
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
    """Build a Feishu/Lark interactive card."""
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
    """Build a DingTalk markdown message."""
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
    """Delivers reports to multiple collaboration platforms."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def notify(self, report: AggregatedReport) -> dict[str, bool]:
        """Send report to all enabled platforms. Returns per-platform status."""
        if not self.config.notify_enabled:
            return {}

        platforms = self.config.notify_platforms
        results: dict[str, bool] = {}

        for name, cfg in platforms.items():
            if not cfg.get("enabled", False):
                continue

            env_key = cfg.get("webhook_url_env", "")
            webhook_url = os.getenv(env_key, "") if env_key else ""

            if not webhook_url:
                results[name] = False
                continue

            builder = {
                "slack": _build_slack_payload,
                "teams": _build_teams_payload,
                "feishu": _build_feishu_payload,
                "dingtalk": _build_dingtalk_payload,
                "generic": _build_slack_payload,
            }.get(name, _build_slack_payload)

            payload = builder(report)
            results[name] = self._send(webhook_url, payload)

        return results

    def _send(self, url: str, payload: dict[str, Any]) -> bool:
        try:
            resp = httpx.post(url, json=payload, timeout=15)
            return resp.is_success
        except Exception:
            return False


def notify(report: AggregatedReport, config: Config | None = None) -> dict[str, bool]:
    """Convenience function to send notifications."""
    if config is None:
        from .config import load_config
        config = load_config()
    notifier = MultiNotifier(config)
    return notifier.notify(report)
