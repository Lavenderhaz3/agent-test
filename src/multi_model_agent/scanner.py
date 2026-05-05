"""Claude-based security vulnerability scanner.

Walks a codebase, batches source files, sends them to Claude for static
analysis, and returns structured vulnerability findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from anthropic import Anthropic

from .config import Config

SECURITY_AUDIT_PROMPT = """You are a senior security engineer performing a code security audit.
Analyze the following source code files and identify security vulnerabilities.

For each finding, classify by:
- severity: critical, high, medium, low
- category: injection, xss, auth, crypto, secrets, deserialization, ssrf, path_traversal, config, dependency

Report ONLY valid JSON with this exact structure:
{
  "findings": [
    {
      "file": "path/to/file",
      "line": 42,
      "severity": "high",
      "category": "injection",
      "title": "Short description",
      "description": "Detailed explanation of the vulnerability",
      "cwe": "CWE-89",
      "remediation": "How to fix this issue",
      "code_snippet": "relevant code line(s)"
    }
  ],
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}

Important rules:
- Only report REAL vulnerabilities, not theoretical ones
- Include the exact code snippet that shows the issue
- Reference CWE IDs where applicable
- Provide actionable, specific remediation steps
- If no vulnerabilities found, return an empty findings array
- Do NOT wrap the JSON in markdown code fences
"""


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    category: str
    title: str
    description: str
    cwe: str = ""
    remediation: str = ""
    code_snippet: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=lambda: {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
    })
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [asdict(f) for f in self.findings],
            "summary": self.summary,
            "files_scanned": self.files_scanned,
            "errors": self.errors,
            "scan_duration_ms": self.scan_duration_ms,
        }

    def to_markdown(self, strings: dict[str, str]) -> str:
        if not self.findings:
            return f"{strings['scan_header']}\n\n✅ No vulnerabilities detected.\n"

        lines = [strings["scan_header"], ""]
        lines.append(
            strings["scan_summary"].format(
                files=str(self.files_scanned), issues=str(self.summary["total"])
            )
        )
        lines.append("")

        # Group by severity
        grouped: dict[str, list[Finding]] = {"critical": [], "high": [], "medium": [], "low": []}
        for f in self.findings:
            grouped[f.severity].append(f)

        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}
        for sev in ["critical", "high", "medium", "low"]:
            if not grouped[sev]:
                continue
            lines.append(f"### {severity_emoji[sev]} {sev.upper()} ({len(grouped[sev])})")
            for f in grouped[sev]:
                lines.append(f"- **{f.title}** — `{f.file}:{f.line}`")
                lines.append(f"  - CWE: {f.cwe}")
                lines.append(f"  - {f.description}")
                lines.append(f"  - Fix: {f.remediation}")
                lines.append("")
        return "\n".join(lines)


def _should_ignore(file_path: str, ignore_patterns: list[str]) -> bool:
    for pattern in ignore_patterns:
        if pattern.endswith("/"):
            if f"/{pattern}" in file_path or file_path.startswith(pattern):
                return True
        elif pattern.startswith("*."):
            if file_path.endswith(pattern[1:]):
                return True
        elif pattern in file_path:
            return True
    return False


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _detect_language(path: Path) -> str:
    ext = path.suffix.lower()
    lang_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".jsx": "javascript", ".go": "go",
        ".rs": "rust", ".java": "java", ".kt": "kotlin", ".swift": "swift",
        ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
        ".rb": "ruby", ".php": "php", ".cs": "csharp", ".scala": "scala",
        ".sh": "bash", ".bash": "bash", ".zsh": "bash",
        ".yaml": "yaml", ".yml": "yaml", ".json": "json",
        ".tf": "terraform", ".sql": "sql", ".dockerfile": "dockerfile",
    }
    return lang_map.get(ext, "unknown")


def _collect_files(repo_path: Path, ignore_patterns: list[str], max_size_kb: int) -> list[Path]:
    files: list[Path] = []
    max_bytes = max_size_kb * 1024

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not _should_ignore(f"{root}/{d}/", ignore_patterns)]

        for fname in filenames:
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(repo_path))
            if _should_ignore(rel, ignore_patterns):
                continue
            if fpath.stat().st_size <= max_bytes:
                files.append(fpath.relative_to(repo_path))
    return files


class ClaudeScanner:
    """Scans codebases for vulnerabilities using the Claude API."""

    def __init__(self, config: Config) -> None:
        self.config = config
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.client = Anthropic(api_key=api_key) if api_key else None
        self._cache: dict[str, ScanResult] = {}

    def _build_file_batch(self, repo_path: Path, files: list[Path]) -> str:
        parts: list[str] = []
        total_chars = 0
        batch_max = self.config.get("scanner", "batch_max_tokens", default=80000) * 2

        for fpath in files:
            full_path = repo_path / fpath
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lang = _detect_language(full_path)
            header = f"\n--- FILE: {fpath} ({lang}) ---\n"
            if total_chars + len(header) + len(content) > batch_max:
                continue

            parts.append(f"{header}{content}")
            total_chars += len(header) + len(content)

        return "\n".join(parts)

    def scan(self, repo_path: str | Path) -> ScanResult:
        """Scan a repository for vulnerabilities."""
        import time
        start = time.time()

        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            result = ScanResult(errors=[f"Repository path does not exist: {repo}"])
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        ignore = self.config.scanner_ignore_patterns
        max_kb = self.config.scanner_max_file_kb
        files = _collect_files(repo, ignore, max_kb)

        if not files:
            result = ScanResult(files_scanned=0)
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        batch = self._build_file_batch(repo, files)
        if not batch.strip():
            result = ScanResult(files_scanned=len(files))
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        result = self._call_claude(batch)
        result.files_scanned = len(files)
        result.scan_duration_ms = (time.time() - start) * 1000
        return result

    def _call_claude(self, code_batch: str) -> ScanResult:
        if not self.client:
            return ScanResult(errors=["ANTHROPIC_API_KEY not set; cannot call Claude API"])

        try:
            response = self.client.messages.create(
                model=self.config.claude_model,
                max_tokens=self.config.claude_max_tokens,
                temperature=self.config.claude_temperature,
                system=SECURITY_AUDIT_PROMPT,
                messages=[{"role": "user", "content": code_batch}],
            )
            text = response.content[0].text

            # Parse JSON from response
            data = self._parse_json(text)
            findings = [
                Finding(
                    file=f.get("file", ""),
                    line=f.get("line", 0),
                    severity=f.get("severity", "low"),
                    category=f.get("category", "unknown"),
                    title=f.get("title", "Untitled"),
                    description=f.get("description", ""),
                    cwe=f.get("cwe", ""),
                    remediation=f.get("remediation", ""),
                    code_snippet=f.get("code_snippet", ""),
                )
                for f in data.get("findings", [])
            ]
            summary = data.get("summary", {})
            return ScanResult(findings=findings, summary=summary)
        except Exception as e:
            return ScanResult(errors=[f"Claude API error: {e}"])

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        # Strip markdown fences if present
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

        # Try to find JSON object bounds
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end + 1]

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"findings": [], "summary": {"total": 0}}


def scan_repository(repo_path: str, config: Config | None = None) -> ScanResult:
    """Convenience function to scan a repository."""
    if config is None:
        from .config import load_config
        config = load_config()
    scanner = ClaudeScanner(config)
    return scanner.scan(repo_path)
