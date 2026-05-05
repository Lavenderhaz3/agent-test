"""Test runner with framework auto-detection and Claude Code integration.

测试运行器：自动检测语言和测试框架，执行测试，解析输出，可选调用 Claude Code（OpenClaw）分析失败原因。
支持 pytest、jest、vitest、go test、cargo test、gradle/mvn test 等主流框架。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .config import Config


@dataclass
class TestCase:
    """单条测试用例结果。"""
    name: str                        # 用例名称
    status: str                      # 结果状态：passed/failed/skipped/error
    duration_ms: float = 0.0         # 执行耗时（毫秒）
    message: str = ""                # 失败/错误信息
    file: str = ""                   # 所在文件
    line: int = 0                    # 所在行号


@dataclass
class TestSuite:
    """一个测试套件（包含多个用例）。"""
    name: str
    tests: list[TestCase] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    duration_ms: float = 0.0


@dataclass
class TestReport:
    """完整测试报告。"""
    suites: list[TestSuite] = field(default_factory=list)
    total_passed: int = 0
    total_failed: int = 0
    total_skipped: int = 0
    total_errors: int = 0
    total_duration_ms: float = 0.0
    framework: str = "unknown"       # 检测到的测试框架
    raw_output: str = ""             # 原始测试输出
    claude_analysis: str = ""        # Claude Code 失败分析结果
    errors: list[str] = field(default_factory=list)  # 运行过程中的错误

    @property
    def total_tests(self) -> int:
        """测试用例总数。"""
        return self.total_passed + self.total_failed + self.total_skipped + self.total_errors

    @property
    def pass_rate(self) -> float:
        """通过率（百分比）。"""
        total = self.total_tests
        if total == 0:
            return 0.0
        return self.total_passed / total * 100

    def to_dict(self) -> dict[str, Any]:
        """转为字典，用于 JSON 序列化。"""
        return {
            "suites": [
                {**asdict(s), "tests": [asdict(t) for t in s.tests]}
                for s in self.suites
            ],
            "total_passed": self.total_passed,
            "total_failed": self.total_failed,
            "total_skipped": self.total_skipped,
            "total_errors": self.total_errors,
            "total_tests": self.total_tests,
            "pass_rate": round(self.pass_rate, 1),
            "total_duration_ms": self.total_duration_ms,
            "framework": self.framework,
            "claude_analysis": self.claude_analysis,
            "errors": self.errors,
        }

    def to_markdown(self, strings: dict[str, str]) -> str:
        """生成 Markdown 格式测试报告。"""
        lines = [strings["test_header"], ""]
        lines.append(
            strings["test_summary"].format(
                passed=str(self.total_passed),
                failed=str(self.total_failed),
                skipped=str(self.total_skipped),
                errors=str(self.total_errors),
            )
        )
        lines.append("")
        lines.append(f"**Pass Rate:** {self.pass_rate:.1f}%  |  **Framework:** {self.framework}  |  **Duration:** {self.total_duration_ms / 1000:.1f}s")
        lines.append("")

        # 展开每个套件中的失败用例
        for suite in self.suites:
            lines.append(f"### {suite.name} — {suite.passed}/{len(suite.tests)} passed")
            for test in suite.tests:
                if test.status == "failed" or test.status == "error":
                    icon = "❌" if test.status == "failed" else "⚠️"
                    lines.append(f"- {icon} **{test.name}** — {test.message}")
                    if test.file:
                        lines.append(f"  `{test.file}:{test.line}`")
            lines.append("")

        # 附加 Claude Code 的 AI 分析
        if self.claude_analysis:
            lines.append("### AI Analysis (Claude)")
            lines.append(self.claude_analysis)
            lines.append("")

        return "\n".join(lines)


def detect_framework(repo_path: Path) -> tuple[str, str]:
    """检测项目的语言和测试框架。返回 (语言, 测试命令)。
    按顺序检查：Python(pyproject/setup) → JS/TS(package.json) → Go → Rust → Java
    """
    # Python 项目检测：优先 pyproject.toml，其次 setup.py/setup.cfg
    if (repo_path / "pyproject.toml").exists() or (repo_path / "setup.py").exists() or (repo_path / "setup.cfg").exists():
        if (repo_path / "tox.ini").exists():
            return "python", "tox"
        return "python", "pytest"
    if (repo_path / "Pipfile").exists() or (repo_path / "requirements.txt").exists():
        return "python", "pytest"

    # JavaScript / TypeScript 项目检测：解析 package.json 中的 scripts 和依赖
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            scripts = data.get("scripts", {})
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "vitest" in deps or "vitest" in scripts.get("test", ""):
                return "typescript" if "typescript" in deps else "javascript", "vitest"
            if "jest" in deps or "jest" in scripts.get("test", ""):
                return "typescript" if "typescript" in deps else "javascript", "jest"
            if "mocha" in deps:
                return "javascript", "mocha"
            if "test" in scripts:
                return "typescript" if "typescript" in deps else "javascript", "npm test"
        except Exception:
            pass

    # Go 项目检测
    if (repo_path / "go.mod").exists():
        return "go", "go test ./..."

    # Rust 项目检测
    if (repo_path / "Cargo.toml").exists():
        return "rust", "cargo test"

    # Java 项目检测（Gradle 优先级高于 Maven）
    if list(repo_path.glob("*.gradle")) or (repo_path / "gradlew").exists():
        return "java", "./gradlew test"
    if (repo_path / "pom.xml").exists():
        return "java", "mvn test"

    return "unknown", ""


def _parse_test_output(output: str, framework: str) -> list[TestSuite]:
    """根据框架类型将原始输出解析为结构化测试套件列表。"""
    suites: list[TestSuite] = []

    if framework == "pytest":
        suites = _parse_pytest(output)
    elif framework in ("jest", "vitest"):
        suites = _parse_jest(output)
    elif framework == "go test ./...":
        suites = _parse_go_test(output)
    else:
        suites = _parse_generic(output)  # 未知框架用通用解析

    return suites


def _parse_pytest(output: str) -> list[TestSuite]:
    """解析 pytest 输出。匹配格式：
    'test_file.py::test_name PASSED' 或 'FAILED test_file.py::test_name - message'
    """
    tests: list[TestCase] = []
    for line in output.split("\n"):
        m = re.match(r"(\S+::\S+)\s+(PASSED|FAILED|SKIPPED|ERROR)", line)
        if m:
            name, status = m.group(1), m.group(2).lower()
            tests.append(TestCase(name=name, status=status))
        m = re.match(r"FAILED\s+(\S+::\S+)\s*[-]\s*(.*)", line)
        if m:
            tests.append(TestCase(name=m.group(1), status="failed", message=m.group(2)))

    suite = TestSuite(name="pytest", tests=tests)
    for t in tests:
        setattr(suite, t.status, getattr(suite, t.status) + 1)
    return [suite] if tests else []


def _parse_jest(output: str) -> list[TestSuite]:
    """解析 Jest/Vitest 输出。匹配格式：
    '  Suite Name' 作为套件头，'    ✓ test name (5ms)' 作为用例子项。
    """
    suites: list[TestSuite] = []
    current_suite = None
    for line in output.split("\n"):
        # 套件名：以两个空格开头的大写字母开头行
        m = re.match(r"^\s{2}([A-Z].*?)(?:\s+\(.*\))?$", line)
        if m and "✓" not in line and "✗" not in line and "PASS" not in line and "FAIL" not in line:
            if current_suite:
                suites.append(current_suite)
            current_suite = TestSuite(name=m.group(1).strip())
        # 用例子项：四个空格 + 图标 + 名称 + 耗时
        m = re.match(r"^\s{4}([✓✓✗✕])\s+(.+?)\s+\((\d+)\s*ms\)", line)
        if m and current_suite is not None:
            icon = m.group(1)
            name = m.group(2)
            duration = int(m.group(3))
            status = "passed" if icon in ("✓", "✓") else "failed"
            current_suite.tests.append(TestCase(name=name, status=status, duration_ms=duration))
            setattr(current_suite, status, getattr(current_suite, status) + 1)

    if current_suite:
        suites.append(current_suite)
    return suites


def _parse_go_test(output: str) -> list[TestSuite]:
    """解析 go test 输出。匹配格式：
    '--- PASS: TestName (0.00s)' 和 'ok   package  0.123s'
    """
    tests: list[TestCase] = []
    for line in output.split("\n"):
        # 单个测试结果行
        m = re.match(r"---\s+(PASS|FAIL|SKIP):\s+(\S+)\s+\(([\d.]+)s\)", line)
        if m:
            status = m.group(1).lower()
            name = m.group(2)
            duration = float(m.group(3)) * 1000
            tests.append(TestCase(name=name, status=status, duration_ms=duration))
        # 包级别汇总行
        m = re.match(r"(ok|FAIL)\s+(\S+)\s+([\d.]+)s", line)
        if m:
            suite_name = m.group(2)
            passed = m.group(1) == "ok"
            suite = TestSuite(name=suite_name, tests=tests)
            suite.passed = len([t for t in tests if t.status == "passed"])
            suite.failed = len([t for t in tests if t.status == "failed"])
            suite.skipped = len([t for t in tests if t.status == "skip"])
            suite.duration_ms = float(m.group(3)) * 1000
            return [suite]
    test_suite = TestSuite(name="go-tests", tests=tests)
    test_suite.passed = len([t for t in tests if t.status == "passed"])
    test_suite.failed = len([t for t in tests if t.status == "failed"])
    test_suite.skipped = len([t for t in tests if t.status == "skip"])
    return [test_suite] if tests else []


def _parse_generic(output: str) -> list[TestSuite]:
    """通用解析器：对未知框架做最大努力的 PASS/FAIL 计数。"""
    passed = len(re.findall(r"(?i)\b(PASS|PASSED|ok|✓)\b", output))
    failed = len(re.findall(r"(?i)\b(FAIL|FAILED|FAILURE|✗)\b", output))
    if passed or failed:
        suite = TestSuite(name="tests")
        suite.passed = passed
        suite.failed = failed
        return [suite]
    return []


class TestRunner:
    """测试运行器：自动检测框架，执行测试，解析结果，可选 AI 失败分析。"""

    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self, repo_path: str | Path, command: str = "") -> TestReport:
        """在仓库中运行测试，返回结构化报告。"""
        import time
        start_time = time.time()

        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            report = TestReport(errors=[f"Repository path does not exist: {repo}"])
            report.total_duration_ms = (time.time() - start_time) * 1000
            return report

        # 第一步：检测语言和测试框架
        language, detected_cmd = detect_framework(repo)
        cmd = command or detected_cmd

        if not cmd:
            report = TestReport(
                framework=language,
                errors=["Could not detect test framework. Specify a command with --test-cmd."],
            )
            report.total_duration_ms = (time.time() - start_time) * 1000
            return report

        # 第二步：执行测试
        output, exit_code = self._execute(cmd, repo)

        # 第三步：解析输出
        suites = _parse_test_output(output, language)

        total_passed = sum(s.passed for s in suites)
        total_failed = sum(s.failed for s in suites)
        total_skipped = sum(s.skipped for s in suites)
        total_errors = sum(s.errors for s in suites)

        # 解析失败时使用通用解析兜底
        if not suites and output.strip():
            suites = _parse_generic(output)
            total_passed = sum(s.passed for s in suites)
            total_failed = sum(s.failed for s in suites)
            total_skipped = sum(s.skipped for s in suites)
            total_errors = sum(s.errors for s in suites)

        report = TestReport(
            suites=suites,
            total_passed=total_passed,
            total_failed=total_failed,
            total_skipped=total_skipped,
            total_errors=total_errors,
            framework=cmd,
            raw_output=output,
        )

        # 第四步：有失败时使用 Claude Code CLI 分析根因
        if self.config.test_use_claude and total_failed > 0 and output.strip():
            report.claude_analysis = self._analyze_with_claude(output, repo)

        report.total_duration_ms = (time.time() - start_time) * 1000
        return report

    def _execute(self, command: str, cwd: Path) -> tuple[str, int]:
        """通过子进程执行测试命令，捕获 stdout/stderr。"""
        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.config.test_timeout,
            )
            output = proc.stdout + "\n" + proc.stderr
            return output, proc.returncode
        except subprocess.TimeoutExpired:
            return f"Test execution timed out after {self.config.test_timeout}s", -1
        except Exception as e:
            return f"Failed to execute tests: {e}", -1

    def _analyze_with_claude(self, test_output: str, repo_path: Path) -> str:
        """调用 Claude Code CLI（OpenClaw）分析测试失败原因。
        将输出写入临时文件，由 Claude Code 读取并给出根因分析和修复建议。
        """
        try:
            # 写入临时文件避免命令行参数过长
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="test_output_"
            ) as f:
                f.write(test_output)
                tmp_path = f.name

            analysis_prompt = (
                "Analyze these test failures and provide: "
                "1) Root cause for each failure, "
                "2) Whether it's a test issue or a code issue, "
                "3) Specific fix recommendations. "
                f"Test output file: {tmp_path}"
            )

            # 调用 Claude Code CLI（非交互模式）
            proc = subprocess.run(
                ["claude", "--print", "--permission-mode", "bypassPermissions", analysis_prompt],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
            )

            # 清理临时文件
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

            if proc.returncode == 0:
                return proc.stdout.strip()
            return f"Claude analysis unavailable: {proc.stderr.strip()}"
        except FileNotFoundError:
            return "Claude Code CLI not installed. Install with: npm install -g @anthropic-ai/claude-code"
        except Exception as e:
            return f"Claude analysis error: {e}"


def run_tests(repo_path: str, command: str = "", config: Config | None = None) -> TestReport:
    """便捷函数：一行调用完成测试自动执行与分析。"""
    if config is None:
        from .config import load_config
        config = load_config()
    runner = TestRunner(config)
    return runner.run(repo_path, command)
