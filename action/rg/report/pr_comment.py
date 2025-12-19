from __future__ import annotations

from typing import List

from rg.normalize.schema import Finding
from rg.models import RDIReport


def _md(s: str | None) -> str:
    return (s or "").replace("|", "\\|")


def _top_findings_table(findings: List[Finding], limit: int = 5) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get(f.severity, 99))[:limit]

    lines = [
        "| Severity | ID | Package | Installed | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in findings_sorted:
        lines.append(
            f"| {_md(f.severity).upper()} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(f.fixed_version)} |"
        )
    return "\n".join(lines)


def render_pr_comment_md(report: RDIReport, trivy_findings: List[Finding], grype_findings: List[Finding]) -> str:
    marker = "<!-- release-guardian:rdi -->"

    verdict = report.verdict
    score = report.rdi_score

    if verdict == "go":
        header = f"✅ **Go** — RDI **{score}**"
    elif verdict == "conditional":
        header = f"⚠️ **Conditional** — RDI **{score}**"
    else:
        header = f"❌ **No-Go** — RDI **{score}**"

    notes = (report.notes or [])[:6]
    why_lines = "\n".join([f"- {_md(n)}" for n in notes]) if notes else "- (No notes)"

    trivy_table = _top_findings_table(trivy_findings)
    grype_table = _top_findings_table(grype_findings)

    md = f"""{marker}
{header}

**Summary:** {_md(report.summary)}

### Why
{why_lines}

### Top findings (Trivy)
{trivy_table}

### Top findings (Grype)
{grype_table}

### Scanners
- Trivy: ✅ ({len(trivy_findings)} findings)
- Syft: ✅ (SBOM generated)
- Grype: ✅ ({len(grype_findings)} findings)
- Semgrep: _pending_

---
_Release Guardian (RDI) — decision intelligence at PR time._
"""
    return md
