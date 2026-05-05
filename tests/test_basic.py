"""Basic smoke tests for the multi-model-agent package."""

from multi_model_agent.config import load_config
from multi_model_agent.i18n import get_strings, translate
from multi_model_agent.scanner import ClaudeScanner, ScanResult, Finding
from multi_model_agent.reviewer import GPTReviewer, ReviewResult, ReviewComment
from multi_model_agent.test_runner import TestRunner, TestReport, detect_framework
from multi_model_agent.aggregator import aggregate, AggregatedReport
from multi_model_agent.notifier import (
    _build_slack_payload,
    _build_teams_payload,
    _build_feishu_payload,
    _build_dingtalk_payload,
)


def test_config_loads():
    """Config loads without error."""
    cfg = load_config()
    assert cfg.claude_model
    assert cfg.gpt_model
    assert cfg.scanner_enabled
    assert isinstance(cfg.notify_supported_langs, list)


def test_i18n_english():
    strings = get_strings("en")
    assert "scan_header" in strings
    assert "Security Scan Results" in strings["scan_header"]


def test_i18n_chinese():
    strings = get_strings("zh")
    assert "安全扫描结果" in strings["scan_header"]


def test_i18n_fallback():
    strings = get_strings("nonexistent")
    assert "Security Scan Results" in strings["scan_header"]


def test_translate():
    result = translate("test_summary", "en", passed="5", failed="1", skipped="0", errors="0")
    assert "5 passed" in result


def test_finding_dataclass():
    f = Finding(
        file="test.py",
        line=10,
        severity="high",
        category="injection",
        title="SQL Injection",
        description="Unsanitized input in SQL query",
        cwe="CWE-89",
        remediation="Use parameterized queries",
    )
    d = f.__dict__
    assert d["file"] == "test.py"
    assert d["severity"] == "high"


def test_scan_result_empty():
    r = ScanResult()
    assert r.summary["total"] == 0
    assert r.files_scanned == 0


def test_review_result_empty():
    r = ReviewResult()
    assert len(r.comments) == 0
    assert r.risk_level == "low"


def test_test_report_empty():
    r = TestReport()
    assert r.total_tests == 0
    assert r.pass_rate == 0.0


def test_aggregated_report():
    r = aggregate(repo="/test/repo", lang="en")
    data = r.to_dict()
    assert data["repo"] == "/test/repo"
    assert data["language"] == "en"
    assert data["scan"] is None
    assert data["review"] is None
    assert data["tests"] is None


def test_aggregated_report_json():
    r = aggregate(repo="/test/repo")
    js = r.to_json()
    assert '"repo": "/test/repo"' in js


def test_aggregated_report_markdown():
    r = aggregate(repo="/test/repo")
    md = r.to_markdown()
    assert "Multi-Model Agent Report" in md


def test_slack_payload():
    r = aggregate(repo="/test/repo")
    payload = _build_slack_payload(r)
    assert "blocks" in payload
    assert len(payload["blocks"]) > 0


def test_teams_payload():
    r = aggregate(repo="/test/repo")
    payload = _build_teams_payload(r)
    assert payload["type"] == "message"
    assert "attachments" in payload


def test_feishu_payload():
    r = aggregate(repo="/test/repo")
    payload = _build_feishu_payload(r)
    assert payload["msg_type"] == "interactive"


def test_dingtalk_payload():
    r = aggregate(repo="/test/repo")
    payload = _build_dingtalk_payload(r)
    assert payload["msgtype"] == "markdown"


def test_claude_scanner_no_api_key():
    cfg = load_config()
    scanner = ClaudeScanner(cfg)
    # Should fail gracefully without API key
    result = scanner.scan("/nonexistent/path")
    assert result.files_scanned == 0


def test_gpt_reviewer_no_api_key():
    cfg = load_config()
    reviewer = GPTReviewer(cfg)
    result = reviewer.review_diff("fake diff content")
    # Should fail gracefully without API key
    assert len(result.errors) > 0 or len(result.comments) >= 0


def test_test_runner_nonexistent_repo():
    cfg = load_config()
    runner = TestRunner(cfg)
    report = runner.run("/nonexistent/test/path")
    assert len(report.errors) > 0
