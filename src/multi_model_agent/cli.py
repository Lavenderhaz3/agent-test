"""CLI entry point for CodeSentinel.

Commands:
    run      Full workflow (scan + review + test + notify)
    scan     Run vulnerability scanner only
    review   Run PR review only
    test     Run tests only
    notify   Send an existing report to platforms
    config   Show current configuration
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from .config import load_config
from .scanner import scan_repository
from .reviewer import review_diff
from .test_runner import run_tests


@click.group()
@click.version_option(version="1.0.0", prog_name="codesentinel")
def main() -> None:
    """CodeSentinel — 基于 OpenClaw + Claude + GPT 的多模型协作代码审查智能体。

    Claude 负责漏洞扫描，GPT 负责 PR 评审与优化建议，
    OpenClaw 驱动测试执行，结果聚合推送至团队协作工具。
    """
    pass


@main.command()
@click.option("--repo", "-r", required=True, help="Path to the repository to analyze")
@click.option("--diff", "-d", default="", help="Path to git diff file or diff text for PR review")
@click.option("--pr-description", default="", help="PR description for context")
@click.option("--test-cmd", default="", help="Custom test command (auto-detected if omitted)")
@click.option("--skip-scan", is_flag=True, help="Skip vulnerability scanning")
@click.option("--skip-review", is_flag=True, help="Skip PR review")
@click.option("--skip-tests", is_flag=True, help="Skip test execution")
@click.option("--no-notify", is_flag=True, help="Skip notifications")
@click.option("--lang", default="", help="Report language (en, zh, ja, ko, etc.)")
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def run(
    repo: str,
    diff: str,
    pr_description: str,
    test_cmd: str,
    skip_scan: bool,
    skip_review: bool,
    skip_tests: bool,
    no_notify: bool,
    lang: str,
    config_path: str | None,
) -> None:
    """Run the full multi-model workflow."""
    cfg = load_config(config_path)

    from .orchestrator import Orchestrator

    orch = Orchestrator(cfg)
    orch.run(
        repo=repo,
        diff=diff,
        pr_description=pr_description,
        test_cmd=test_cmd,
        skip_scan=skip_scan,
        skip_review=skip_review,
        skip_tests=skip_tests,
        notify_enabled=not no_notify,
        lang=lang,
    )


@main.command()
@click.option("--repo", "-r", required=True, help="Path to the repository to scan")
@click.option("--output", "-o", default="", help="Output file for JSON results")
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def scan(repo: str, output: str, config_path: str | None) -> None:
    """Run the Claude vulnerability scanner on a repository."""
    cfg = load_config(config_path)
    result = scan_repository(repo, cfg)

    print(f"Files scanned: {result.files_scanned}")
    print(f"Issues found: {result.summary.get('total', 0)}")
    print(f"  Critical: {result.summary.get('critical', 0)}")
    print(f"  High:     {result.summary.get('high', 0)}")
    print(f"  Medium:   {result.summary.get('medium', 0)}")
    print(f"  Low:      {result.summary.get('low', 0)}")

    if result.errors:
        for e in result.errors:
            print(f"Error: {e}")

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved to {output}")
    elif result.findings:
        for f in result.findings:
            print(f"\n  [{f.severity.upper()}] {f.title}")
            print(f"  File: {f.file}:{f.line}")
            print(f"  CWE:  {f.cwe}")
            print(f"  {f.description}")
            print(f"  Fix: {f.remediation}")


@main.command()
@click.option("--diff", "-d", required=True, help="Git diff text or path to diff file")
@click.option("--pr-description", default="", help="PR description for context")
@click.option("--output", "-o", default="", help="Output file for JSON results")
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def review(diff: str, pr_description: str, output: str, config_path: str | None) -> None:
    """Run the GPT PR reviewer on a diff."""
    cfg = load_config(config_path)

    diff_content = diff
    diff_path = Path(diff)
    if diff_path.exists() and diff_path.is_file():
        diff_content = diff_path.read_text(encoding="utf-8")

    result = review_diff(diff_content, cfg)

    print(f"Comments: {len(result.comments)}")
    print(f"Risk:     {result.risk_level.upper()}")
    print(f"Summary:  {result.summary[:200]}")

    if result.errors:
        for e in result.errors:
            print(f"Error: {e}")

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved to {output}")
    elif result.comments:
        for c in result.comments:
            print(f"\n  [{c.severity.upper()}] [{c.category}] {c.title}")
            print(f"  File: {c.file}:{c.line}")
            print(f"  {c.comment}")
            if c.suggestion:
                print(f"  Suggestion: {c.suggestion}")


@main.command()
@click.option("--repo", "-r", required=True, help="Path to the repository")
@click.option("--command", "-c", default="", help="Custom test command (auto-detected if omitted)")
@click.option("--output", "-o", default="", help="Output file for JSON results")
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def test(repo: str, command: str, output: str, config_path: str | None) -> None:
    """Run tests with auto-detection and Claude analysis."""
    cfg = load_config(config_path)
    result = run_tests(repo, command, cfg)

    print(f"Framework:   {result.framework}")
    print(f"Total:       {result.total_tests}")
    print(f"Passed:      {result.total_passed}")
    print(f"Failed:      {result.total_failed}")
    print(f"Skipped:     {result.total_skipped}")
    print(f"Errors:      {result.total_errors}")
    print(f"Pass rate:   {result.pass_rate:.1f}%")
    print(f"Duration:    {result.total_duration_ms / 1000:.1f}s")

    if result.errors:
        for e in result.errors:
            print(f"Error: {e}")

    if result.claude_analysis:
        print(f"\n--- Claude Analysis ---\n{result.claude_analysis}")

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved to {output}")


@main.command()
@click.option("--report", "-r", required=True, help="Path to JSON report file to send")
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def notify(report: str, config_path: str | None) -> None:
    """Send an existing report JSON to configured notification platforms."""
    cfg = load_config(config_path)

    report_data = json.loads(Path(report).read_text(encoding="utf-8"))
    from .aggregator import AggregatedReport
    from .notifier import MultiNotifier

    aggregated = AggregatedReport(
        scan=report_data.get("scan"),
        review=report_data.get("review"),
        tests=report_data.get("tests"),
        repo=report_data.get("repo", ""),
        lang=report_data.get("language", "en"),
    )

    notifier = MultiNotifier(cfg)
    results = notifier.notify(aggregated)
    for platform, ok in results.items():
        print(f"{'Sent' if ok else 'Failed'}: {platform}")


@main.command()
@click.option("--config", "config_path", default=None, help="Path to config YAML")
def show_config(config_path: str | None) -> None:
    """Display the current configuration."""
    cfg = load_config(config_path)
    import yaml
    print(yaml.dump(cfg.raw, default_flow_style=False, allow_unicode=True))
    print(f"\nEnvironment:")
    print(f"  ANTHROPIC_API_KEY: {'set' if os.getenv('ANTHROPIC_API_KEY') else 'NOT SET'}")
    print(f"  OPENAI_API_KEY:    {'set' if os.getenv('OPENAI_API_KEY') else 'NOT SET'}")
    for name, pcfg in cfg.notify_platforms.items():
        env_key = pcfg.get("webhook_url_env", "")
        val = os.getenv(env_key, "") if env_key else ""
        print(f"  {env_key}: {'set' if val else 'NOT SET'} ({'enabled' if pcfg.get('enabled') else 'disabled'})")


if __name__ == "__main__":
    main()
