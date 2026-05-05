"""Report aggregator — merges scanner, reviewer, and test runner results.

Produces unified JSON, Markdown, and HTML reports.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template

from .config import Config
from .scanner import ScanResult
from .reviewer import ReviewResult
from .test_runner import TestReport
from .i18n import get_strings

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
    <meta charset="utf-8">
    <title>CodeSentinel Report — {{ timestamp }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; max-width: 960px; margin: 0 auto; padding: 2em; background: #fff; color: #1a1a1a; }
        h1 { border-bottom: 2px solid #e5e5e5; padding-bottom: .5em; }
        h2 { margin-top: 2em; color: #333; }
        .summary { background: #f5f5f5; border-radius: 8px; padding: 1em; margin: 1em 0; }
        .finding, .comment { border-left: 4px solid #e5e5e5; padding: .5em 1em; margin: .5em 0; }
        .finding.critical { border-left-color: #d32f2f; }
        .finding.high { border-left-color: #f57c00; }
        .finding.medium { border-left-color: #fbc02d; }
        .finding.low { border-left-color: #1976d2; }
        .severity { font-size: .8em; padding: .1em .5em; border-radius: 3px; color: #fff; }
        .severity.critical { background: #d32f2f; }
        .severity.high { background: #f57c00; }
        .severity.medium { background: #fbc02d; color: #333; }
        .severity.low, .severity.suggestion { background: #1976d2; }
        pre { background: #f5f5f5; padding: .5em; border-radius: 4px; overflow-x: auto; }
        .test-pass { color: #2e7d32; }
        .test-fail { color: #d32f2f; }
        footer { margin-top: 3em; padding-top: 1em; border-top: 1px solid #e5e5e5; font-size: .85em; color: #666; }
    </style>
</head>
<body>
    <h1>CodeSentinel Report</h1>
    <p>Generated: {{ timestamp }}</p>
    <p>Repo: {{ repo }}</p>

    {% if scan %}
    <h2>Security Scan</h2>
    <div class="summary">
        <strong>{{ scan.summary.total }} issues found</strong>
        ({{ scan.summary.critical }} critical, {{ scan.summary.high }} high,
        {{ scan.summary.medium }} medium, {{ scan.summary.low }} low)
        in {{ scan.files_scanned }} files
    </div>
    {% for f in scan.findings %}
    <div class="finding {{ f.severity }}">
        <span class="severity {{ f.severity }}">{{ f.severity }}</span>
        <strong>{{ f.title }}</strong> — <code>{{ f.file }}:{{ f.line }}</code>
        <p>{{ f.description }}</p>
        {% if f.remediation %}<p><strong>Fix:</strong> {{ f.remediation }}</p>{% endif %}
    </div>
    {% endfor %}
    {% endif %}

    {% if review %}
    <h2>PR Review</h2>
    <div class="summary">
        <strong>{{ review.comments|length }} comments</strong>
        — Risk level: {{ review.risk_level.upper() }}
        <p>{{ review.summary }}</p>
    </div>
    {% for c in review.comments %}
    <div class="comment">
        <span class="severity {{ c.severity }}">{{ c.severity }}</span>
        <strong>{{ c.title }}</strong> — <code>{{ c.file }}:{{ c.line }}</code>
        <p>{{ c.comment }}</p>
        {% if c.suggestion %}<p><strong>Suggestion:</strong> {{ c.suggestion }}</p>{% endif %}
    </div>
    {% endfor %}
    {% endif %}

    {% if tests %}
    <h2>Test Results</h2>
    <div class="summary">
        <strong class="test-pass">{{ tests.total_passed }} passed</strong>,
        <strong class="test-fail">{{ tests.total_failed }} failed</strong>,
        {{ tests.total_skipped }} skipped, {{ tests.total_errors }} errors
        — Pass rate: {{ "%.1f" % tests.pass_rate }}%
    </div>
    {% if tests.claude_analysis %}
    <h3>AI Analysis</h3>
    <pre>{{ tests.claude_analysis }}</pre>
    {% endif %}
    {% endif %}

    <footer>{{ footer }}</footer>
</body>
</html>"""


@dataclass
class AggregatedReport:
    scan: dict[str, Any] | None = None
    review: dict[str, Any] | None = None
    tests: dict[str, Any] | None = None
    repo: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lang: str = "en"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "timestamp": self.timestamp,
            "language": self.lang,
            "scan": self.scan,
            "review": self.review,
            "tests": self.tests,
            "errors": self.errors if self.errors else None,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_markdown(self) -> str:
        strings = get_strings(self.lang)
        lines = [f"# CodeSentinel Report", "",
                 f"**Repository:** `{self.repo}`  ",
                 f"**Generated:** {self.timestamp}  ",
                 ""]

        if self.scan:
            # Reconstruct markdown from scan data
            findings = self.scan.get("findings", [])
            summary = self.scan.get("summary", {})
            files = self.scan.get("files_scanned", 0)
            lines.append(strings["scan_header"])
            lines.append("")
            if findings:
                lines.append(strings["scan_summary"].format(files=str(files), issues=str(summary.get("total", 0))))
            else:
                lines.append(":white_check_mark: No vulnerabilities detected.")
            lines.append("")
            for f in findings:
                sev = f.get("severity", "low")
                lines.append(f"- **[{sev.upper()}] {f.get('title', '')}** — `{f.get('file', '')}:{f.get('line', 0)}`")
                lines.append(f"  - {f.get('description', '')}")
                if f.get("remediation"):
                    lines.append(f"  - Fix: {f.get('remediation', '')}")
                lines.append("")

        if self.review:
            comments = self.review.get("comments", [])
            lines.append(strings["review_header"])
            lines.append("")
            lines.append(strings["review_summary"].format(comments=str(len(comments))))
            lines.append(f"**Risk Level:** {self.review.get('risk_level', 'low').upper()}")
            lines.append("")
            for c in comments:
                lines.append(f"- **[{c.get('severity', '').upper()}] {c.get('title', '')}** [{c.get('category', '')}] — `{c.get('file', '')}:{c.get('line', 0)}`")
                lines.append(f"  - {c.get('comment', '')}")
                if c.get("suggestion"):
                    lines.append(f"  - Suggestion: {c.get('suggestion', '')}")
                lines.append("")

        if self.tests:
            lines.append(strings["test_header"])
            lines.append("")
            lines.append(strings["test_summary"].format(
                passed=str(self.tests.get("total_passed", 0)),
                failed=str(self.tests.get("total_failed", 0)),
                skipped=str(self.tests.get("total_skipped", 0)),
                errors=str(self.tests.get("total_errors", 0)),
            ))
            lines.append("")

        lines.append(f"---  ")
        lines.append(f"*{strings['footer']}*")
        return "\n".join(lines)

    def to_html(self) -> str:
        strings = get_strings(self.lang)
        template = Template(REPORT_HTML_TEMPLATE)
        return template.render(
            repo=self.repo,
            timestamp=self.timestamp,
            lang=self.lang,
            scan=self.scan,
            review=self.review,
            tests=self.tests,
            footer=strings["footer"],
        )


def aggregate(
    scan: ScanResult | None = None,
    review: ReviewResult | None = None,
    tests: TestReport | None = None,
    repo: str = "",
    lang: str = "en",
) -> AggregatedReport:
    """Merge all results into a unified report."""
    return AggregatedReport(
        scan=scan.to_dict() if scan else None,
        review=review.to_dict() if review else None,
        tests=tests.to_dict() if tests else None,
        repo=repo,
        lang=lang,
    )


def save_report(report: AggregatedReport, output_dir: str, formats: list[str] | None = None) -> list[str]:
    """Save the report to disk in specified formats. Returns list of saved paths."""
    if formats is None:
        formats = ["json", "markdown", "html"]

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved: list[str] = []

    if "json" in formats:
        path = out / f"report_{ts}.json"
        path.write_text(report.to_json(), encoding="utf-8")
        saved.append(str(path))

    if "markdown" in formats:
        path = out / f"report_{ts}.md"
        path.write_text(report.to_markdown(), encoding="utf-8")
        saved.append(str(path))

    if "html" in formats:
        path = out / f"report_{ts}.html"
        path.write_text(report.to_html(), encoding="utf-8")
        saved.append(str(path))

    return saved
