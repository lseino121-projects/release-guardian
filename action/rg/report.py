from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Optional


@dataclass
class RDIReport:
    verdict: str               # go|conditional|no-go
    rdi_score: int             # 0..100
    summary: str
    context: dict[str, Any]
    notes: list[str]
    top_findings: list[dict[str, Any]]  # placeholder for v1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def render_pr_comment_md(report: RDIReport) -> str:
    marker = "<!-- release-guardian:rdi -->"

    verdict = report.verdict
    score = report.rdi_score

    if verdict == "go":
        header = f"✅ **Go** — RDI **{score}**"
    elif verdict == "conditional":
        header = f"⚠️ **Conditional** — RDI **{score}**"
    else:
        header = f"❌ **No-Go** — RDI **{score}**"

    why_lines = "\n".join([f"- {n}" for n in report.notes]) if report.notes else "- (No notes)"

    md = f"""{marker}
{header}

**Summary:** {report.summary}

### Why
{why_lines}

### Scanners (v1 scaffold)
- Trivy: _pending_
- Syft: _pending_
- Grype: _pending_
- Semgrep: _pending_

---
_Release Guardian (RDI) — decision intelligence at PR time._
"""
    return md
