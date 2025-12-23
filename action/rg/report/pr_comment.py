from __future__ import annotations

from typing import List, Dict, Tuple, Optional
from pathlib import Path
from rg.normalize.schema import Finding
from rg.normalize.dedupe import unified_summary, unified_summary_for_clusters
from rg.models import RDIReport
from rg.report.decision_block import render_decision_block

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


def _collect_dep_fixes(
    deps_findings: List[Finding],
) -> Dict[Tuple[str, str], List[str]]:
    """
    Build (pkg, ver) -> unique list of fix versions observed across scanners.
    Assumes Finding.fixed_version is a string, sometimes comma-separated.
    """
    fixes: Dict[Tuple[str, str], List[str]] = {}

    for f in deps_findings:
        pkg = (f.package or "").strip()
        ver = (f.installed_version or "").strip()
        if not pkg or not ver:
            continue

        fv = (f.fixed_version or "").strip()
        if not fv:
            continue

        # Some scanners return "1.2.3, 1.2.4" (comma separated)
        parts = [p.strip() for p in fv.split(",") if p.strip()]
        if not parts:
            continue

        key = (pkg, ver)
        existing = fixes.get(key, [])
        for p in parts:
            if p not in existing:
                existing.append(p)
        fixes[key] = existing

    return fixes

def _detect_pkg_manager(workspace: str = "/github/workspace") -> str:
    """
    Best-effort detection. In Actions container, /github/workspace is mounted.
    """
    p = Path(workspace)
    if (p / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (p / "yarn.lock").exists():
        return "yarn"
    if (p / "package-lock.json").exists():
        return "npm"
    return "npm"

def _dep_fix_commands(introduced_rows: list[dict], pkg_mgr: str) -> list[str]:
    """
    introduced_rows are from unified_top rows: package, installed_version, etc.
    We'll emit safe, generic commands (v1). You can refine by lockfile type later.
    """
    pkgs = []
    for r in introduced_rows or []:
        pkg = (r.get("package") or "").strip()
        if pkg and pkg not in pkgs:
            pkgs.append(pkg)

    if not pkgs:
        return []

    if pkg_mgr == "pnpm":
        # pnpm: prefer explicit add for direct deps; dedupe/lock update for transitive is trickier.
        return [f"pnpm add {p}@latest" for p in pkgs] + ["pnpm install"]
    if pkg_mgr == "yarn":
        return [f"yarn add {p}@latest" for p in pkgs] + ["yarn install"]
    # npm default
    return [f"npm install {p}@latest" for p in pkgs] + ["npm install"]

def _code_fix_commands(introduced_semgrep: List[Finding]) -> list[str]:
    """
    v1: no magic. Provide grep-style helpers to locate occurrences and suggested safer APIs.
    """
    rules = {(f.id or "").lower() for f in (introduced_semgrep or [])}
    cmds: list[str] = []

    if any("child-process-exec" in r or "child_process.exec" in r for r in rules):
        cmds += [
            "rg \"child_process\\.exec\\(\" -n",
            "# Prefer: child_process.execFile(...) or spawn(...) with args array",
        ]

    if any("subprocess-popen-shell-true" in r for r in rules):
        cmds += [
            "rg \"subprocess\\.(Popen|run|call)\\(\" -n",
            "rg \"shell\\s*=\\s*True\" -n",
            "# Prefer: subprocess.run([...], shell=False) and validate inputs",
        ]

    return cmds

def _dep_hint(pkg: str | None, ver: str | None, fixes_map: Dict[Tuple[str, str], List[str]]) -> str:
    p = (pkg or "").strip()
    v = (ver or "").strip()
    if not p or not v:
        return ""

    fixes = fixes_map.get((p, v), [])
    if not fixes:
        return "No fix version listed."

    # Keep it short: show up to 2 versions
    show = fixes[:2]
    more = "" if len(fixes) <= 2 else f" (+{len(fixes) - 2} more)"
    return f"Upgrade to {', '.join(show)}{more}."


def _semgrep_hint(rule_id: str | None) -> str:
    """
    Lightweight MVP hints. Keep these 1-liners.
    Expand later via rule metadata if you want.
    """
    rid = (rule_id or "").lower()

    # Python
    if "subprocess-popen-shell-true" in rid:
        return "Avoid shell=True. Use subprocess.run([...], shell=False) and validate inputs."

    # JS
    if "child-process-exec" in rid or "child_process.exec" in rid:
        return "Avoid exec/shell. Use spawn/execFile with args array; never pass user input to shell."

    # Terraform / Docker (examples; tweak to your rule IDs)
    if "terraform" in rid and ("public" in rid or "0.0.0.0" in rid):
        return "Restrict ingress. Avoid 0.0.0.0/0 on sensitive ports."

    if "docker" in rid and ("latest" in rid):
        return "Pin image tags/digests for reproducible builds and safer rollbacks."

    return "Review and refactor to remove this risky pattern."

def _unified_table(unified: dict, limit: int = 5, fixes_map: Optional[Dict[Tuple[str, str], List[str]]] = None) -> str:
    rows = unified.get("unified_top") or []
    if not rows:
        return "_No vulnerabilities._"

    fixes_map = fixes_map or {}

    lines = [
        "| Worst | Package | Version | Advisories | Tools | Hint |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows[:limit]:
        worst = (r.get("worst_severity") or "").lower()
        badge = _sev_badge(worst)
        worst_cell = f"{badge} {_md(worst.upper())}".strip()

        pkg = r.get("package")
        ver = r.get("installed_version")
        hint = _dep_hint(pkg, ver, fixes_map)

        lines.append(
            f"| {worst_cell} | {_md(pkg)} | {_md(ver)} | "
            f"{_md(', '.join(r.get('advisories') or []))} | {_md(', '.join(r.get('tools') or []))} | {_md(hint)} |"
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
            hint = _semgrep_hint(f.id)

            lines.append(
                f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} | {_md(hint)} |"
            )
        return "\n".join(lines)

    # default (no hint column)
    lines = [
        "| Severity | Rule | File | Line |",
        "|---|---|---|---|",
    ]
    for f in findings_sorted:
        sev = (f.severity or "").lower()
        sev_cell = f"{_sev_badge(sev)} {_md(sev.upper())}".strip()

        lines.append(
            f"| {sev_cell} | {_md(f.id)} | {_md(f.package)} | {_md(f.installed_version)} |"
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
    fixes_map = _collect_dep_fixes(deps_findings)

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
            introduced_deps_table = _unified_table(introduced_deps, fixes_map=fixes_map)

    introduced_semgrep_table = _semgrep_table(introduced_semgrep_findings, include_hint=True)
    pkg_mgr = _detect_pkg_manager()
    introduced_rows = (introduced_deps.get("unified_top") or []) if introduced_clusters_raw is not None else []
    dep_cmds = _dep_fix_commands(introduced_rows, pkg_mgr)
    code_cmds = _code_fix_commands(introduced_semgrep_findings)

    fix_lines = []
    if dep_cmds:
        fix_lines.append(f"**Dependency fixes ({pkg_mgr}):**")
        fix_lines.append("```bash")
        fix_lines.extend(dep_cmds[:6])
        fix_lines.append("```")

    if code_cmds:
        fix_lines.append("**Code fixes (helpers):**")
        fix_lines.append("```bash")
        fix_lines.extend(code_cmds[:8])
        fix_lines.append("```")

    quick_fix_block = "\n".join(fix_lines) if fix_lines else "_No quick-fix commands available._"


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
{decision_block}

---

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
- **Worst severity:** {"NONE" if unified_all["clusters_count"] == 0 else (unified_all["worst_severity"].upper() if unified_all["worst_severity"] else "UNKNOWN")}
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
