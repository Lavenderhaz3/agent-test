"""Claude-based security vulnerability scanner.

基于 Claude API 的代码安全漏洞扫描器。
遍历代码库，将源文件分批发送给 Claude 进行静态分析，返回结构化漏洞报告。
覆盖 OWASP Top 10：注入、XSS、认证缺陷、加密弱点、硬编码密钥、反序列化、SSRF 等。
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

# Claude 安全审计系统提示词：定义输出 JSON 格式和审计规则
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
    """单条漏洞发现记录。"""
    file: str          # 文件路径
    line: int           # 行号
    severity: str       # 严重级别：critical/high/medium/low
    category: str       # 漏洞类别：injection/xss/auth/crypto/secrets/...
    title: str          # 问题简述
    description: str    # 详细说明
    cwe: str = ""       # CWE 编号（如 CWE-89）
    remediation: str = ""  # 修复建议
    code_snippet: str = ""  # 问题代码片段


@dataclass
class ScanResult:
    """一次扫描的完整结果。"""
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=lambda: {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
    })
    files_scanned: int = 0        # 扫描文件数
    errors: list[str] = field(default_factory=list)  # 扫描过程中的错误
    scan_duration_ms: float = 0.0  # 扫描耗时（毫秒）

    def to_dict(self) -> dict[str, Any]:
        """转为字典，用于 JSON 序列化。"""
        return {
            "findings": [asdict(f) for f in self.findings],
            "summary": self.summary,
            "files_scanned": self.files_scanned,
            "errors": self.errors,
            "scan_duration_ms": self.scan_duration_ms,
        }

    def to_markdown(self, strings: dict[str, str]) -> str:
        """生成 Markdown 格式报告，按严重级别分组展示。"""
        if not self.findings:
            return f"{strings['scan_header']}\n\n✅ No vulnerabilities detected.\n"

        lines = [strings["scan_header"], ""]
        lines.append(
            strings["scan_summary"].format(
                files=str(self.files_scanned), issues=str(self.summary["total"])
            )
        )
        lines.append("")

        # 按严重级别分组展示
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
    """根据忽略规则判断文件是否应跳过。
    支持目录模式（末尾带 /）、通配符扩展名（如 *.min.js）、子串匹配。
    """
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
    """计算文件 SHA256 摘要（前 16 位），用于缓存去重。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _detect_language(path: Path) -> str:
    """根据文件扩展名识别编程语言。"""
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
    """递归遍历代码目录，收集需要扫描的文件（过滤忽略项和超大文件）。"""
    files: list[Path] = []
    max_bytes = max_size_kb * 1024

    for root, dirs, filenames in os.walk(repo_path):
        # 跳过被忽略的目录
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
    """Claude 安全扫描器：将代码批量发送给 Claude API 进行漏洞检测。"""

    def __init__(self, config: Config) -> None:
        self.config = config
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        # API key 未设置时 client 为 None，调用时会返回友好错误
        self.client = Anthropic(api_key=api_key) if api_key else None

    def _build_file_batch(self, repo_path: Path, files: list[Path]) -> str:
        """将多个文件拼接为一个文本批次（控制总长度不超过 token 上限）。"""
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
        """扫描入口：收集文件 -> 构建批次 -> 调用 Claude -> 解析结果。"""
        import time
        start = time.time()

        repo = Path(repo_path).resolve()
        if not repo.is_dir():
            result = ScanResult(errors=[f"Repository path does not exist: {repo}"])
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        # 收集需要扫描的文件
        ignore = self.config.scanner_ignore_patterns
        max_kb = self.config.scanner_max_file_kb
        files = _collect_files(repo, ignore, max_kb)

        if not files:
            result = ScanResult(files_scanned=0)
            result.scan_duration_ms = (time.time() - start) * 1000
            return result

        # 构建文件批次并发送给 Claude
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
        """调用 Claude API 进行安全审计，解析返回的 JSON 结果。"""
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

            # 解析 Claude 返回的 JSON 响应
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
        """从 Claude 响应文本中提取 JSON 对象（处理 markdown 代码块包装）。"""
        # 去除可能的 markdown 代码块包装
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

        # 定位 JSON 对象的起止边界
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end + 1]

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"findings": [], "summary": {"total": 0}}


def scan_repository(repo_path: str, config: Config | None = None) -> ScanResult:
    """便捷函数：一行调用完成代码库安全扫描。"""
    if config is None:
        from .config import load_config
        config = load_config()
    scanner = ClaudeScanner(config)
    return scanner.scan(repo_path)
