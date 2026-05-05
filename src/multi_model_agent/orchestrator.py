"""Main orchestrator — coordinates scanning, reviewing, testing, and notifications.

主编排器：协调 Claude 扫描 + GPT 评审 + 测试执行 + 报告聚合 + 通知推送的完整工作流。
第一阶段（扫描 + 评审）并行执行以节省时间，第二阶段（测试）串行执行，
最后聚合结果、保存报告、推送通知。
"""

from __future__ import annotations

import concurrent.futures
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.panel import Panel

from .config import Config, load_config
from .scanner import ClaudeScanner, ScanResult
from .reviewer import GPTReviewer, ReviewResult
from .test_runner import TestRunner, TestReport
from .aggregator import AggregatedReport, aggregate, save_report
from .notifier import MultiNotifier

console = Console()


def _run_scan(config: Config, repo: str) -> ScanResult | None:
    """执行 Claude 安全漏洞扫描（在线程池中运行）。"""
    if not config.scanner_enabled:
        console.print("[yellow]Scanner is disabled in config. Skipping.[/]")
        return None
    console.print("[bold]Scanning for vulnerabilities...[/]")
    scanner = ClaudeScanner(config)
    result = scanner.scan(repo)
    if result.errors:
        for e in result.errors:
            console.print(f"[red]Scan error:[/] {e}")
        return None
    return result


def _run_review(config: Config, diff_or_pr: str, pr_description: str = "") -> ReviewResult | None:
    """执行 GPT PR 评审（在线程池中运行）。"""
    if not config.reviewer_enabled:
        console.print("[yellow]Reviewer is disabled in config. Skipping.[/]")
        return None
    console.print("[bold]Reviewing changes...[/]")
    reviewer = GPTReviewer(config)

    # 支持传入 diff 文件路径或直接文本
    diff_path = Path(diff_or_pr)
    if diff_path.exists() and diff_path.is_file():
        diff_content = diff_path.read_text(encoding="utf-8")
    else:
        diff_content = diff_or_pr

    if pr_description:
        result = reviewer.review_pr(pr_description, diff_content)
    else:
        result = reviewer.review_diff(diff_content)

    if result.errors:
        for e in result.errors:
            console.print(f"[red]Review error:[/] {e}")
        return None
    return result


def _run_tests(config: Config, repo: str, command: str = "") -> TestReport | None:
    """执行测试（串行运行，可能调用 Claude Code CLI 分析失败）。"""
    if not config.test_runner_enabled:
        console.print("[yellow]Test runner is disabled in config. Skipping.[/]")
        return None
    console.print("[bold]Running tests...[/]")
    runner = TestRunner(config)
    result = runner.run(repo, command)
    if result.errors:
        for e in result.errors:
            console.print(f"[red]Test error:[/] {e}")
    return result


def _print_results(scan: ScanResult | None, review: ReviewResult | None, tests: TestReport | None) -> None:
    """在终端打印工作流结果汇总表（使用 Rich 表格）。"""
    console.print("")
    console.print(Panel.fit("[bold]Results Summary[/]", border_style="blue"))

    table = Table(title="Workflow Results")
    table.add_column("Stage", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # 安全扫描结果行
    if scan:
        s = scan.summary
        total = s.get("total", 0)
        if total == 0:
            table.add_row("Security Scan", "✅ Passed", f"{scan.files_scanned} files — no issues")
        else:
            table.add_row(
                "Security Scan",
                "⚠️ Issues Found",
                f"{total} issues ({s.get('critical', 0)} critical, {s.get('high', 0)} high)"
            )
    else:
        table.add_row("Security Scan", "⏭️ Skipped", "")

    # PR 评审结果行
    if review:
        table.add_row(
            "PR Review",
            f"{'✅' if review.risk_level == 'low' else '⚠️'} Reviewed",
            f"{len(review.comments)} comments — risk: {review.risk_level.upper()}"
        )
    else:
        table.add_row("PR Review", "⏭️ Skipped", "")

    # 测试结果行
    if tests:
        failed = tests.total_failed
        table.add_row(
            "Tests",
            "✅ Passed" if failed == 0 else f"❌ {failed} failures",
            f"{tests.total_passed}/{tests.total_tests} passed ({tests.pass_rate:.1f}%)"
        )
    else:
        table.add_row("Tests", "⏭️ Skipped", "")

    console.print(table)


class Orchestrator:
    """工作流编排器：将扫描、评审、测试、聚合、通知串联为完整流水线。

    执行顺序：
      第一阶段（并行）：Claude 漏洞扫描 + GPT PR 评审
      第二阶段（串行）：测试执行（可能调用 Claude Code CLI）
      第三阶段：结果聚合 + 报告保存
      第四阶段：多平台通知推送
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()

    def run(
        self,
        repo: str,
        diff: str = "",
        pr_description: str = "",
        test_cmd: str = "",
        skip_scan: bool = False,
        skip_review: bool = False,
        skip_tests: bool = False,
        notify_enabled: bool = True,
        lang: str = "",
    ) -> AggregatedReport:
        """执行完整工作流并返回聚合报告。"""
        start = time.time()
        repo_abs = str(Path(repo).resolve())

        if not lang:
            lang = self.config.notify_default_lang

        console.print(f"[bold blue]CodeSentinel[/] — analyzing [cyan]{repo_abs}[/]")
        console.print(f"Language: {lang}\n")

        scan_result: ScanResult | None = None
        review_result: ReviewResult | None = None

        # ===== 第一阶段：并行执行扫描 + 评审 =====
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures: dict[str, concurrent.futures.Future] = {}

            if not skip_scan:
                futures["scan"] = executor.submit(_run_scan, self.config, repo_abs)

            if not skip_review and diff:
                futures["review"] = executor.submit(_run_review, self.config, diff, pr_description)

            # 收集并行任务结果
            for name, future in futures.items():
                try:
                    if name == "scan":
                        scan_result = future.result(timeout=300)
                    elif name == "review":
                        review_result = future.result(timeout=300)
                except concurrent.futures.TimeoutError:
                    console.print(f"[red]{name} timed out after 5 minutes[/]")
                except Exception as e:
                    console.print(f"[red]{name} failed: {e}[/]")

        # ===== 第二阶段：串行执行测试 =====
        test_result: TestReport | None = None
        if not skip_tests:
            test_result = _run_tests(self.config, repo_abs, test_cmd)

        # ===== 第三阶段：聚合结果并保存报告 =====
        console.print("[bold]Aggregating results...[/]")
        report = aggregate(
            scan=scan_result,
            review=review_result,
            tests=test_result,
            repo=repo_abs,
            lang=lang,
        )

        saved = save_report(report, self.config.output_dir, self.config.output_formats)
        for p in saved:
            console.print(f"  Report saved: [dim]{p}[/]")

        # ===== 第四阶段：推送通知到团队协作工具 =====
        notify_results: dict[str, bool] = {}
        if notify_enabled:
            console.print("[bold]Sending notifications...[/]")
            notifier = MultiNotifier(self.config)
            notify_results = notifier.notify(report)
            for platform, ok in notify_results.items():
                icon = "✅" if ok else "❌"
                console.print(f"  {icon} {platform}")

        # 打印终端汇总表
        _print_results(scan_result, review_result, test_result)

        elapsed = time.time() - start
        console.print(f"\n[dim]Total time: {elapsed:.1f}s[/]")

        return report
