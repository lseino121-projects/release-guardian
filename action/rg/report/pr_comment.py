from __future__ import annotations

from typing import List

from rg.normalize.schema import Finding
from rg.normalize.dedupe import unified_summary, unified_summary_for_clusters
from rg.models import RDIReport


def _md(s: str | None) -> str:
    return (s or "").replace("|", "\\|")

def _sev_badge(sev: str | None) -> str:
    """
    Small visual indicator for severity in GitHub Markdown tables.
    """
    s = (sev or "").strip().lower()
    if s == "critical":
        return "🟥"
    if s == "high":
        return "🟧"
    if s == "medium":
        return "🟨"
    if s == "low":
        return "🟩"
    return "⬜️"


def _sev_cell(sev: str | None) -> str:
    """
    Render a badge + uppercase severity label.
    Example: '🟥 CRITICAL'
    """
    s = (sev or "unknown").strip()
    return f"{_sev_badge(s)} {s.upper()}"


def _unified_table(unified: dict, limit: int = 5) -> str:
    rows = unified.get("unified_top") or []
    if not rows:
        return "_No vulnerabilities._"

    lines = [
        "| Worst | Package | Version | Advisories | Tools |",
        "|---|---|---|---|---|",
    ]
    for r in rows[:limit]:
        worst = _sev_cell(r.get("worst_severity"))
        lines.append(
            f"| {worst} | {_md(r.get('package'))} | {_md(r.get('installed_version'))} | "
            f"{_md(', '.join(r.get('advisories') or []))} | {_md(', '.join(r.get('tools') or []))} |"
        )
    return "\n".join(lines)


def _semgrep_table(findings: List[Finding], limit: int = 5) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get((f.severity or "").lower(), 99))[:limit]

    lines = [
        "| Severity | Rule | File | Line |",
        "|---|---|---|---|",
    ]
    for f in findings_sorted:
        sev = _sev_cell(f.severity)
        # Semgrep: package=path, installed_version=line (your chosen mapping)
        lines.append(
            f"| {sev} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} |"
        )
    return "\n".join(lines)


def _top_findings_table(findings: List[Finding], limit: int = 5) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get((f.severity or "").lower(), 99))[:limit]

    lines = [
        "| Severity | ID | Package | Installed | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in findings_sorted:
        sev = _sev_cell(f.severity)
        lines.append(
            f"| {sev} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(f.fixed_version)} |"
        )
    return "\n".join(lines)



def render_pr_comment_md(
    report: RDIReport,
    trivy_findings: List[Finding],
    grype_findings: List[Finding],
    semgrep_findings: List[Finding],
    introduced_semgrep_findings: List[Finding],
) -> str:
    marker = "<!-- release-guardian:rdi -->"

    deps_findings = trivy_findings + grype_findings
    unified_all = unified_summary(deps_findings)

    introduced_ct = int(report.context.get("introduced_clusters", 0) or 0)
    preexisting_ct = int(report.context.get("preexisting_clusters", 0) or 0)
    changed_pkgs_ct = int(report.context.get("changed_pkgs_count", 0) or 0)

    # Important: distinguish between "not provided" (None) vs "provided but empty" ([]).
    introduced_clusters_raw = report.context.get("introduced_clusters_list", None)

    introduced_deps_note = ""
    if introduced_clusters_raw is None:
        # Truly missing: we can't filter precisely.
        introduced_deps_table = "_(Introduced dependency clusters list not provided to renderer yet.)_"
        introduced_deps_note = (
            "Pass `introduced_clusters_list` in report.context to show exact introduced dependency clusters."
        )
    else:
        # Provided (could be empty list, which is a valid/normal case).
        introduced_clusters = introduced_clusters_raw or []
        if not introduced_clusters:
            introduced_deps_table = "_No introduced dependency vulnerabilities._"
        else:
            introduced_deps = unified_summary_for_clusters(deps_findings, introduced_clusters)
            introduced_deps_table = _unified_table(introduced_deps)

    introduced_semgrep_table = _semgrep_table(introduced_semgrep_findings)

    # Semgrep baseline counts (optional but helps explain "why GO even with findings on HEAD")
    semgrep_intro = int(report.context.get("semgrep_introduced_count", 0) or 0)
    semgrep_pre = int(report.context.get("semgrep_preexisting_count", 0) or 0)
    semgrep_baseline_line = f"_Baseline: introduced={semgrep_intro}, preexisting={semgrep_pre}_"

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

    # details sections
    trivy_table = _top_findings_table(trivy_findings)
    grype_table = _top_findings_table(grype_findings)
    semgrep_table = _semgrep_table(semgrep_findings)

    unified_all_table = _unified_table(unified_all)

    md = f"""{marker}
{header}

**Summary:** {_md(report.summary)}

### Why
{why_lines}

### Introduced risk (what this PR adds)
**Dependencies (introduced clusters):** {introduced_ct}  
{introduced_deps_note}
{introduced_deps_table}

**Code (Semgrep introduced):** {len(introduced_semgrep_findings)}
{introduced_semgrep_table}

<details>
<summary><b>Details: Top findings (Trivy)</b></summary>

{trivy_table}
</details>

<details>
<summary><b>Details: Top findings (Grype)</b></summary>

{grype_table}
</details>

<details>
<summary><b>Details: Semgrep findings on HEAD</b></summary>

{semgrep_baseline_line}

{semgrep_table}
</details>

### Dependency vulnerability snapshot (all tools)
- **Clusters (pkg@version):** {unified_all["clusters_count"]}
- **Total advisories (all tools):** {unified_all["advisories_count"]}
- **Worst severity:** {unified_all["worst_severity"].upper() if unified_all["worst_severity"] else "UNKNOWN"}
- **Introduced clusters:** {introduced_ct} | **Pre-existing clusters:** {preexisting_ct} | **Changed packages:** {changed_pkgs_ct}

{unified_all_table}

### Scanners
- Trivy: ✅ ({len(trivy_findings)} findings)
- Syft: ✅ (SBOM generated)
- Grype: ✅ ({len(grype_findings)} findings)
- Semgrep: ✅ ({len(semgrep_findings)} findings)

---
_Release Guardian (RDI) — decision intelligence at PR time._
"""
    return md
