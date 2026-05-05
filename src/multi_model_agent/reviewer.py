"""GPT-based PR review and optimization suggestion generator.

Accepts git diffs or PR metadata, sends to GPT for detailed review,
and returns structured comments with optimization suggestions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from openai import OpenAI

from .config import Config

REVIEW_SYSTEM_PROMPT = """You are an expert code reviewer. Review the following diff/PR changes and provide detailed,
actionable feedback. Focus on real issues, not style preferences.

Review for:
- bugs: Logic errors, edge cases, null handling
- performance: Inefficient algorithms, unnecessary allocations, N+1 queries
- security: Injection risks, exposed secrets, auth bypasses
- architecture: Design issues, coupling, missing abstractions
- testing: Missing or inadequate test coverage
- docs: Missing documentation for public APIs or complex logic
- optimization: Opportunities to simplify or improve the code

For each comment specify:
- file: relative path
- line: line number in the diff
- category: one of bugs, performance, security, architecture, testing, docs, optimization
- severity: critical, high, medium, low, suggestion
- title: short summary
- comment: detailed feedback
- suggestion: specific code change or approach improvement (optional)

Return ONLY valid JSON with this structure:
{
  "comments": [
    {
      "file": "src/foo.py",
      "line": 42,
      "category": "bugs",
      "severity": "high",
      "title": "Potential null dereference",
      "comment": "The variable may be None at this point...",
      "suggestion": "Add a null check before accessing the attribute."
    }
  ],
  "summary": "Overall assessment of the PR quality",
  "risk_level": "low|medium|high",
  "recommendations": ["Rec 1", "Rec 2"]
}
"""


@dataclass
class ReviewComment:
    file: str
    line: int
    category: str
    severity: str
    title: str
    comment: str
    suggestion: str = ""


@dataclass
class ReviewResult:
    comments: list[ReviewComment] = field(default_factory=list)
    summary: str = ""
    risk_level: str = "low"
    recommendations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    review_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "comments": [asdict(c) for c in self.comments],
            "summary": self.summary,
            "risk_level": self.risk_level,
            "recommendations": self.recommendations,
            "errors": self.errors,
            "review_duration_ms": self.review_duration_ms,
        }

    @property
    def comment_count(self) -> int:
        return len(self.comments)

    def to_markdown(self, strings: dict[str, str]) -> str:
        lines = [strings["review_header"], ""]
        lines.append(
            strings["review_summary"].format(comments=str(len(self.comments)))
        )
        lines.append("")
        lines.append(f"**Risk Level:** {self.risk_level.upper()}")
        lines.append("")
        lines.append(f"**Summary:** {self.summary}")
        lines.append("")

        if self.comments:
            grouped: dict[str, list[ReviewComment]] = {}
            for c in self.comments:
                grouped.setdefault(c.category, []).append(c)

            for cat, comments in sorted(grouped.items()):
                lines.append(f"### {cat.title()} ({len(comments)})")
                for c in comments:
                    lines.append(f"- **{c.title}** [{c.severity}] — `{c.file}:{c.line}`")
                    lines.append(f"  {c.comment}")
                    if c.suggestion:
                        lines.append(f"  > Suggestion: {c.suggestion}")
                    lines.append("")

        if self.recommendations:
            lines.append("### Recommendations")
            for r in self.recommendations:
                lines.append(f"- {r}")
            lines.append("")

        return "\n".join(lines)


class GPTReviewer:
    """Generates PR reviews and optimization suggestions using GPT."""

    def __init__(self, config: Config) -> None:
        self.config = config
        api_key = os.getenv("OPENAI_API_KEY", "")
        self.client = OpenAI(api_key=api_key) if api_key else None

    def review_diff(self, diff: str, context: str = "") -> ReviewResult:
        """Review a git diff and return structured feedback."""
        import time
        start = time.time()

        max_kb = self.config.reviewer_max_diff_kb
        if len(diff.encode()) > max_kb * 1024:
            diff = diff[: max_kb * 1024]

        result = self._call_gpt(diff, context)
        result.review_duration_ms = (time.time() - start) * 1000
        return result

    def review_pr(self, pr_description: str, diff: str, context: str = "") -> ReviewResult:
        """Review a full PR with description and diff."""
        combined = f"PR Description:\n{pr_description}\n\nDiff:\n{diff}"
        if context:
            combined = f"Context: {context}\n\n{combined}"
        return self.review_diff(combined)

    def _call_gpt(self, diff: str, context: str = "") -> ReviewResult:
        if not self.client:
            return ReviewResult(errors=["OPENAI_API_KEY not set; cannot call GPT API"])

        user_msg = diff
        if context:
            user_msg = f"Additional context: {context}\n\n{user_msg}"

        try:
            response = self.client.chat.completions.create(
                model=self.config.gpt_model,
                max_tokens=self.config.gpt_max_tokens,
                temperature=self.config.gpt_temperature,
                messages=[
                    {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
            )
            text = response.choices[0].message.content or ""

            data = self._parse_json(text)
            comments = [
                ReviewComment(
                    file=c.get("file", ""),
                    line=c.get("line", 0),
                    category=c.get("category", "bugs"),
                    severity=c.get("severity", "medium"),
                    title=c.get("title", ""),
                    comment=c.get("comment", ""),
                    suggestion=c.get("suggestion", ""),
                )
                for c in data.get("comments", [])
            ]
            return ReviewResult(
                comments=comments,
                summary=data.get("summary", ""),
                risk_level=data.get("risk_level", "low"),
                recommendations=data.get("recommendations", []),
            )
        except Exception as e:
            return ReviewResult(errors=[f"GPT API error: {e}"])

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end + 1]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"comments": [], "summary": "Failed to parse GPT response"}


def review_diff(diff_path_or_text: str, config: Config | None = None) -> ReviewResult:
    """Convenience function to review a diff file or text."""
    if config is None:
        from .config import load_config
        config = load_config()

    path = Path(diff_path_or_text)
    if path.exists() and path.is_file():
        diff = path.read_text(encoding="utf-8")
    else:
        diff = diff_path_or_text

    reviewer = GPTReviewer(config)
    return reviewer.review_diff(diff)
