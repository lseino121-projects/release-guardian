from __future__ import annotations

from pathlib import Path
from typing import List
from rg.models import RDIReport
from rg.normalize.dedupe import unified_summary, unified_summary_for_clusters
from rg.normalize.schema import Finding
from rg.report.decision_block import render_decision_block
from rg.report.hints import hint_for_id


def _md(s: str | None) -> str:
    return (s or "").replace("|", "\\|")


def _sev_badge(sev: str | None) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "🟥"
    if s == "high":
        return "🟧"
    if s == "medium":
        return "🟨"
    if s == "low":
        return "🟦"
    return "⬜️"


def _detect_pkg_manager(workspace: str = "/github/workspace") -> str:
    p = Path(workspace)
    if (p / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (p / "yarn.lock").exists():
        return "yarn"
    if (p / "package-lock.json").exists():
        return "npm"
    return "npm"


def _dep_fix_commands(introduced_rows: list[dict], pkg_mgr: str) -> list[str]:
    # v1: simple, “works often enough” commands. Great for MVP.
    pkgs: list[str] = []
    for r in introduced_rows or []:
        pkg = (r.get("package") or "").strip()
        if pkg and pkg not in pkgs:
            pkgs.append(pkg)

    if not pkgs:
        return []

    if pkg_mgr == "pnpm":
        return [f"pnpm add {p}@latest" for p in pkgs] + ["pnpm install"]
    if pkg_mgr == "yarn":
        return [f"yarn add {p}@latest" for p in pkgs] + ["yarn install"]

    return [f"npm install {p}@latest" for p in pkgs] + ["npm install"]


def _code_fix_commands(introduced_semgrep: List[Finding]) -> list[str]:
    # v1: grep helpers + 1-line guidance
    rules = {(f.id or "").lower() for f in (introduced_semgrep or [])}
    cmds: list[str] = []

    if any("child-process-exec" in r or "child_process.exec" in r for r in rules):
        cmds += [
            "rg \"child_process\\.exec\\(\" -n",
            "# Prefer: execFile(...) or spawn(...) with args array; never pass user input to a shell",
        ]

    if any("subprocess-popen-shell-true" in r for r in rules):
        cmds += [
            "rg \"subprocess\\.(Popen|run|call)\\(\" -n",
            "rg \"shell\\s*=\\s*True\" -n",
            "# Prefer: subprocess.run([...], shell=False) and validate inputs",
        ]

    return cmds


def _unified_table(unified: dict, limit: int = 5, include_hint: bool = False) -> str:
    rows = unified.get("unified_top") or []
    if not rows:
        return "_No vulnerabilities._"

    if include_hint:
        lines = [
            "| Worst | Package | Version | Advisories | Tools | Hint |",
            "|---|---|---|---|---|---|",
        ]
    else:
        lines = [
            "| Worst | Package | Version | Advisories | Tools |",
            "|---|---|---|---|---|",
        ]

    for r in rows[:limit]:
        worst = (r.get("worst_severity") or "").lower()
        worst_cell = f"{_sev_badge(worst)} {_md(worst.upper())}".strip()

        advs = r.get("advisories") or []
        advs_str = ", ".join(advs)
        tools_str = ", ".join(r.get("tools") or [])

        if include_hint:
            # pick first advisory ID (CVE/GHSA) to lookup hint
            hint = hint_for_id(advs[0]) if advs else ""
            lines.append(
                f"| {worst_cell} | {_md(r.get('package'))} | {_md(r.get('installed_version'))} | "
                f"{_md(advs_str)} | {_md(tools_str)} | {_md(hint)} |"
            )
        else:
            lines.append(
                f"| {worst_cell} | {_md(r.get('package'))} | {_md(r.get('installed_version'))} | "
                f"{_md(advs_str)} | {_md(tools_str)} |"
            )

    return "\n".join(lines)


def _semgrep_table(findings: List[Finding], limit: int = 5, include_hint: bool = False) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get((f.severity or "").lower(), 99))[:limit]

    if include_hint:
        lines = [
            "| Severity | Rule | File | Line | Hint |",
            "|---|---|---|---|---|",
        ]
        for f in findings_sorted:
            sev = (f.severity or "").lower()
            sev_cell = f"{_sev_badge(sev)} {_md(sev.upper())}".strip()

            hint = (f.hint or "").strip() or hint_for_id(f.id)

            lines.append(
                f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(hint)} |"
            )
        return "\n".join(lines)

    lines = [
        "| Severity | Rule | File | Line |",
        "|---|---|---|---|",
    ]
    for f in findings_sorted:
        sev = (f.severity or "").lower()
        sev_cell = f"{_sev_badge(sev)} {_md(sev.upper())}".strip()
        lines.append(f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} |")

    return "\n".join(lines)


def _top_findings_table(findings: List[Finding], limit: int = 5, include_hint: bool = False) -> str:
    if not findings:
        return "_No findings._"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: order.get((f.severity or "").lower(), 99))[:limit]

    if include_hint:
        lines = [
            "| Severity | ID | Package | Installed | Fix | Hint |",
            "|---|---|---|---|---|---|",
        ]
        for f in findings_sorted:
            sev = (f.severity or "").lower()
            sev_cell = f"{_sev_badge(sev)} {_md(sev.upper())}".strip()
            hint = hint_for_id(f.id)
            lines.append(
                f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(f.fixed_version)} | {_md(hint)} |"
            )
        return "\n".join(lines)

    lines = [
        "| Severity | ID | Package | Installed | Fix |",
        "|---|---|---|---|---|",
    ]
    for f in findings_sorted:
        sev = (f.severity or "").lower()
        sev_cell = f"{_sev_badge(sev)} {_md(sev.upper())}".strip()
        lines.append(
            f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(f.fixed_version)} |"
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
    decision_block = render_decision_block(report)

    deps_findings = trivy_findings + grype_findings
    unified_all = unified_summary(deps_findings)

    introduced_ct = int(report.context.get("introduced_clusters", 0) or 0)
    preexisting_ct = int(report.context.get("preexisting_clusters", 0) or 0)
    changed_pkgs_ct = int(report.context.get("changed_pkgs_count", 0) or 0)

    introduced_clusters_raw = report.context.get("introduced_clusters_list", None)

    introduced_deps_note = ""
    introduced_rows: list[dict] = []
    if introduced_clusters_raw is None:
        introduced_deps_table = "_(Introduced dependency clusters list not provided to renderer yet.)_"
        introduced_deps_note = "Pass `introduced_clusters_list` in report.context to show exact introduced dependency clusters."
    else:
        introduced_clusters = introduced_clusters_raw or []
        if not introduced_clusters:
            introduced_deps_table = "_No introduced dependency vulnerabilities._"
        else:
            introduced_deps = unified_summary_for_clusters(deps_findings, introduced_clusters)
            introduced_rows = introduced_deps.get("unified_top") or []
            introduced_deps_table = _unified_table(introduced_deps, include_hint=True)

    introduced_semgrep_table = _semgrep_table(introduced_semgrep_findings, include_hint=True)

    # Quick fix block (copy/paste)
    pkg_mgr = _detect_pkg_manager()
    dep_cmds = _dep_fix_commands(introduced_rows, pkg_mgr)
    code_cmds = _code_fix_commands(introduced_semgrep_findings)

    fix_lines: list[str] = []
    if dep_cmds:
        fix_lines += [
            f"**Dependency fixes ({pkg_mgr}):**",
            "```bash",
            *dep_cmds[:8],
            "```",
        ]
    if code_cmds:
        fix_lines += [
            "**Code fixes (helpers):**",
            "```bash",
            *code_cmds[:10],
            "```",
        ]
    quick_fix_block = "\n".join(fix_lines) if fix_lines else "_No quick-fix commands available._"

    # Semgrep baseline counts (helps explain “why GO even with findings on HEAD”)
    semgrep_intro = int(report.context.get("semgrep_introduced_count", 0) or 0)
    semgrep_pre = int(report.context.get("semgrep_preexisting_count", 0) or 0)
    semgrep_baseline_line = f"_Baseline: introduced={semgrep_intro}, preexisting={semgrep_pre}_"

    notes = (report.notes or [])[:6]
    why_lines = "\n".join([f"- {_md(n)}" for n in notes]) if notes else "- (No notes)"

    # Details sections (keep tight; hints optional)
    trivy_table = _top_findings_table(trivy_findings, include_hint=False)
    grype_table = _top_findings_table(grype_findings, include_hint=False)
    semgrep_table = _semgrep_table(semgrep_findings, include_hint=False)

    unified_all_table = _unified_table(unified_all, include_hint=False)

    worst_all = "NONE" if unified_all.get("clusters_count") == 0 else (
        unified_all["worst_severity"].upper() if unified_all.get("worst_severity") else "UNKNOWN"
    )

    md = f"""{marker}
{decision_block}

---

### Why
{why_lines}

### Introduced risk (what this PR adds)
**Dependencies (introduced clusters):** {introduced_ct}  
{introduced_deps_note}
{introduced_deps_table}

**Code (Semgrep introduced):** {len(introduced_semgrep_findings)}
{introduced_semgrep_table}

### Quick fix (copy/paste)
{quick_fix_block}

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
- **Worst severity:** {worst_all}
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
