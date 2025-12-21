from __future__ import annotations

from typing import List

from rg.normalize.schema import Finding
from rg.normalize.dedupe import unified_summary, unified_summary_for_clusters
from rg.models import RDIReport


def _md(s: str | None) -> str:
    return (s or "").replace("|", "\\|")


def _unified_table(unified: dict, limit: int = 5) -> str:
    rows = unified.get("unified_top") or []
    if not rows:
        return "_No vulnerabilities._"
    lines = [
        "| Worst | Package | Version | Advisories | Tools |",
        "|---|---|---|---|---|",
    ]
    for r in rows[:limit]:
        lines.append(
            f"| {_md((r.get('worst_severity') or '').upper())} | {_md(r.get('package'))} | {_md(r.get('installed_version'))} | "
            f"{_md(', '.join(r.get('advisories') or []))} | {_md(', '.join(r.get('tools') or []))} |"
        )
    return "\n".join(lines)


def _semgrep_table(findings: List[Finding], limit: int = 5) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get(f.severity, 99))[:limit]

    lines = [
        "| Severity | Rule | File | Line |",
        "|---|---|---|---|",
    ]
    for f in findings_sorted:
        # Semgrep: package=path, installed_version=line (your chosen mapping)
        lines.append(
            f"| {_md(f.severity).upper()} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} |"
        )
    return "\n".join(lines)


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

    # Prefer explicit list (best). If missing, we can't filter precisely, so display a hint.
    introduced_clusters = report.context.get("introduced_clusters_list") or []

    if introduced_clusters:
        introduced_deps = unified_summary_for_clusters(deps_findings, introduced_clusters)
        introduced_deps_table = _unified_table(introduced_deps)
        introduced_deps_note = ""
    else:
        introduced_deps_table = "_(Introduced dependency clusters list not provided to renderer yet.)_"
        introduced_deps_note = "Pass `introduced_clusters_list` in report.context to show exact introduced dependency clusters."

    introduced_semgrep_table = _semgrep_table(introduced_semgrep_findings)

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

    # “details” sections (keep the comment tight)
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
<summary><b>Details: Top findings (Semgrep)</b></summary>

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
