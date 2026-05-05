"""CLI entry point for CodeSentinel.

命令行入口：提供 run / scan / review / test / notify / show-config 六个子命令。
基于 Click 框架构建，支持丰富的参数和选项。
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
@click.option("--repo", "-r", required=True, help="要分析的仓库路径")
@click.option("--diff", "-d", default="", help="PR diff 文件路径或 diff 文本")
@click.option("--pr-description", default="", help="PR 描述（提供上下文）")
@click.option("--test-cmd", default="", help="自定义测试命令（省略则自动检测）")
@click.option("--skip-scan", is_flag=True, help="跳过漏洞扫描")
@click.option("--skip-review", is_flag=True, help="跳过 PR 评审")
@click.option("--skip-tests", is_flag=True, help="跳过测试执行")
@click.option("--no-notify", is_flag=True, help="跳过通知推送")
@click.option("--lang", default="", help="报告语言 (en, zh, ja, ko 等)")
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
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
    """执行完整工作流：扫描 + 评审 + 测试 + 通知。

    示例:
      codesentinel run --repo ./myproject --diff pr.patch
      codesentinel run --repo ./myproject --skip-review --lang zh --no-notify
    """
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
@click.option("--repo", "-r", required=True, help="要扫描的仓库路径")
@click.option("--output", "-o", default="", help="JSON 结果输出文件")
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
def scan(repo: str, output: str, config_path: str | None) -> None:
    """运行 Claude 漏洞扫描器（独立模式）。

    示例:
      codesentinel scan --repo ./myproject -o scan_results.json
    """
    cfg = load_config(config_path)
    result = scan_repository(repo, cfg)

    # 打印扫描汇总
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
        # 无输出文件时，在终端逐条打印漏洞详情
        for f in result.findings:
            print(f"\n  [{f.severity.upper()}] {f.title}")
            print(f"  File: {f.file}:{f.line}")
            print(f"  CWE:  {f.cwe}")
            print(f"  {f.description}")
            print(f"  Fix: {f.remediation}")


@main.command()
@click.option("--diff", "-d", required=True, help="Git diff 文本或 diff 文件路径")
@click.option("--pr-description", default="", help="PR 描述（提供评审上下文）")
@click.option("--output", "-o", default="", help="JSON 结果输出文件")
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
def review(diff: str, pr_description: str, output: str, config_path: str | None) -> None:
    """运行 GPT PR 评审器（独立模式）。

    示例:
      codesentinel review --diff pr.patch
      codesentinel review --diff "the diff content..." --pr-description "Add login feature"
    """
    cfg = load_config(config_path)

    # 支持传入文件路径或原始 diff 文本
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
@click.option("--repo", "-r", required=True, help="仓库路径")
@click.option("--command", "-c", default="", help="自定义测试命令（省略则自动检测框架）")
@click.option("--output", "-o", default="", help="JSON 结果输出文件")
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
def test(repo: str, command: str, output: str, config_path: str | None) -> None:
    """运行测试（自动检测框架 + Claude Code 失败分析）。

    示例:
      codesentinel test --repo ./myproject
      codesentinel test --repo ./myproject -c "pytest -x"
    """
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
@click.option("--report", "-r", required=True, help="JSON 报告文件路径")
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
def notify(report: str, config_path: str | None) -> None:
    """将已有的 JSON 报告推送到配置的通知平台。

    示例:
      codesentinel notify --report reports/report_20260506_120000.json
    """
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
@click.option("--config", "config_path", default=None, help="自定义 YAML 配置文件路径")
def show_config(config_path: str | None) -> None:
    """显示当前配置（YAML 内容 + 环境变量状态）。"""
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
