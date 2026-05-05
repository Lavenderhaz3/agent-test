"""Test runner with framework auto-detection and Claude Code integration.

Detects the language/framework, executes tests, parses results,
and optionally uses Claude Code (OpenClaw) for failure analysis.
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
    name: str
    status: str  # passed, failed, skipped, error
    duration_ms: float = 0.0
    message: str = ""
    file: str = ""
    line: int = 0


@dataclass
class TestSuite:
    name: str
    tests: list[TestCase] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    duration_ms: float = 0.0


@dataclass
class TestReport:
    suites: list[TestSuite] = field(default_factory=list)
    total_passed: int = 0
    total_failed: int = 0
    total_skipped: int = 0
    total_errors: int = 0
    total_duration_ms: float = 0.0
    framework: str = "unknown"
    raw_output: str = ""
    claude_analysis: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def total_tests(self) -> int:
        return self.total_passed + self.total_failed + self.total_skipped + self.total_errors

    @property
    def pass_rate(self) -> float:
        total = self.total_tests
        if total == 0:
            return 0.0
        return self.total_passed / total * 100

    def to_dict(self) -> dict[str, Any]:
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

        for suite in self.suites:
            lines.append(f"### {suite.name} — {suite.passed}/{len(suite.tests)} passed")
            for test in suite.tests:
                if test.status == "failed" or test.status == "error":
                    icon = "❌" if test.status == "failed" else "⚠️"
                    lines.append(f"- {icon} **{test.name}** — {test.message}")
                    if test.file:
                        lines.append(f"  `{test.file}:{test.line}`")
            lines.append("")

        if self.claude_analysis:
            lines.append("### AI Analysis (Claude)")
            lines.append(self.claude_analysis)
            lines.append("")

        return "\n".join(lines)


def detect_framework(repo_path: Path) -> tuple[str, str]:
    """Detect the language and test framework. Returns (language, command)."""
    # Python
    if (repo_path / "pyproject.toml").exists() or (repo_path / "setup.py").exists() or (repo_path / "setup.cfg").exists():
        if (repo_path / "tox.ini").exists():
            return "python", "tox"
        return "python", "pytest"
    if (repo_path / "Pipfile").exists() or (repo_path / "requirements.txt").exists():
        return "python", "pytest"

    # JavaScript/TypeScript
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

    # Go
    if (repo_path / "go.mod").exists():
        return "go", "go test ./..."

    # Rust
    if (repo_path / "Cargo.toml").exists():
        return "rust", "cargo test"

    # Java
    if list(repo_path.glob("*.gradle")) or (repo_path / "gradlew").exists():
        return "java", "./gradlew test"
    if (repo_path / "pom.xml").exists():
        return "java", "mvn test"

    return "unknown", ""


def _parse_test_output(output: str, framework: str) -> list[TestSuite]:
    """Parse test output into structured suites based on framework."""
    suites: list[TestSuite] = []

    if framework == "pytest":
        suites = _parse_pytest(output)
    elif framework in ("jest", "vitest"):
        suites = _parse_jest(output)
    elif framework == "go test ./...":
        suites = _parse_go_test(output)
    else:
        suites = _parse_generic(output)

    return suites


def _parse_pytest(output: str) -> list[TestSuite]:
    tests: list[TestCase] = []
    # pytest short summary line: PASSED / FAILED / SKIPPED / ERRORS
    for line in output.split("\n"):
        # Match: "test_file.py::test_name PASSED"
        m = re.match(r"(\S+::\S+)\s+(PASSED|FAILED|SKIPPED|ERROR)", line)
        if m:
            name, status = m.group(1), m.group(2).lower()
            tests.append(TestCase(name=name, status=status))
        # Match: "FAILED test_file.py::test_name - error message"
        m = re.match(r"FAILED\s+(\S+::\S+)\s*[-]\s*(.*)", line)
        if m:
            tests.append(TestCase(name=m.group(1), status="failed", message=m.group(2)))

    suite = TestSuite(name="pytest", tests=tests)
    for t in tests:
        setattr(suite, t.status, getattr(suite, t.status) + 1)
    return [suite] if tests else []


def _parse_jest(output: str) -> list[TestSuite]:
    suites: list[TestSuite] = []
    current_suite = None
    for line in output.split("\n"):
        # Suite header: "  Suite Name"
        m = re.match(r"^\s{2}([A-Z].*?)(?:\s+\(.*\))?$", line)
        if m and "✓" not in line and "✗" not in line and "PASS" not in line and "FAIL" not in line:
            if current_suite:
                suites.append(current_suite)
            current_suite = TestSuite(name=m.group(1).strip())
        # Test line: "    ✓ test name (5ms)" or "    ✗ test name (5ms)"
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
    tests: list[TestCase] = []
    for line in output.split("\n"):
        # "--- PASS: TestName (0.00s)" or "--- FAIL: TestName (0.00s)"
        m = re.match(r"---\s+(PASS|FAIL|SKIP):\s+(\S+)\s+\(([\d.]+)s\)", line)
        if m:
            status = m.group(1).lower()
            name = m.group(2)
            duration = float(m.group(3)) * 1000
            tests.append(TestCase(name=name, status=status, duration_ms=duration))
        # "ok   package  0.123s" or "FAIL  package  0.123s"
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
    """Best-effort parsing for unknown frameworks."""
    passed = len(re.findall(r"(?i)\b(PASS|PASSED|ok|✓)\b", output))
    failed = len(re.findall(r"(?i)\b(FAIL|FAILED|FAILURE|✗)\b", output))
    if passed or failed:
        suite = TestSuite(name="tests")
        suite.passed = passed
        suite.failed = failed
        return [suite]
    return []


class TestRunner:
    """Runs tests with auto-detection and Claude analysis."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self, repo_path: str | Path, command: str = "") -> TestReport:
        """Run tests in a repository and return a structured report."""
        import time
        start_time = time.time()

        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            report = TestReport(errors=[f"Repository path does not exist: {repo}"])
            report.total_duration_ms = (time.time() - start_time) * 1000
            return report

        language, detected_cmd = detect_framework(repo)
        cmd = command or detected_cmd

        if not cmd:
            report = TestReport(
                framework=language,
                errors=["Could not detect test framework. Specify a command with --test-cmd."],
            )
            report.total_duration_ms = (time.time() - start_time) * 1000
            return report

        output, exit_code = self._execute(cmd, repo)
        suites = _parse_test_output(output, language)

        total_passed = sum(s.passed for s in suites)
        total_failed = sum(s.failed for s in suites)
        total_skipped = sum(s.skipped for s in suites)
        total_errors = sum(s.errors for s in suites)

        # If parsing failed but we have output, do generic parse
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

        # Use Claude Code for failure analysis if enabled
        if self.config.test_use_claude and total_failed > 0 and output.strip():
            report.claude_analysis = self._analyze_with_claude(output, repo)

        report.total_duration_ms = (time.time() - start_time) * 1000
        return report

    def _execute(self, command: str, cwd: Path) -> tuple[str, int]:
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
        """Use Claude Code CLI to analyze test failures."""
        try:
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

            proc = subprocess.run(
                ["claude", "--print", "--permission-mode", "bypassPermissions", analysis_prompt],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=repo_path,
            )

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
    """Convenience function to run tests with auto-detection."""
    if config is None:
        from .config import load_config
        config = load_config()
    runner = TestRunner(config)
    return runner.run(repo_path, command)
