from __future__ import annotations

from pathlib import Path
from typing import List

from rg.models import RDIReport
from rg.normalize.dedupe import unified_summary, unified_summary_for_clusters
from rg.normalize.schema import Finding
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


def _detect_pkg_manager(workspace: str = "/github/workspace") -> str:
    p = Path(workspace)
    if (p / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (p / "yarn.lock").exists():
        return "yarn"
    if (p / "package-lock.json").exists():
        return "npm"
    return "npm"


def _dep_fix_commands(
    introduced_rows: list[dict],
    pkg_mgr: str,
    fixes_map: dict[tuple[str, str], list[str]],
) -> list[str]:
    """
    Upgrade introduced dependency vulns with best-effort fix versions.
    If fix version is known, also emit override/resolution snippet for transitive deps.
    """
    def best_fix(versions: list[str]) -> str | None:
        if not versions:
            return None
        for v in versions:
            v = (v or "").strip()
            if v and v[0].isdigit():
                return v
        v0 = (versions[0] or "").strip()
        return v0 or None

    def override_snippet(pm: str, pkg: str, ver: str) -> list[str]:
        if pm == "yarn":
            return [
                "# If this is transitive, pin via package.json:",
                "# {",
                "#   \"resolutions\": {",
                f"#     \"{pkg}\": \"{ver}\"",
                "#   }",
                "# }",
                "yarn install",
            ]
        if pm == "pnpm":
            return [
                "# If this is transitive, pin via package.json:",
                "# {",
                "#   \"pnpm\": {",
                "#     \"overrides\": {",
                f"#       \"{pkg}\": \"{ver}\"",
                "#     }",
                "#   }",
                "# }",
                "pnpm install",
            ]
        return [
            "# If this is transitive, pin via package.json:",
            "# {",
            "#   \"overrides\": {",
            f"#     \"{pkg}\": \"{ver}\"",
            "#   }",
            "# }",
            "npm install",
        ]

    cmds: list[str] = []
    seen: set[tuple[str, str]] = set()

    for r in introduced_rows or []:
        pkg = (r.get("package") or "").strip()
        installed = (r.get("installed_version") or "").strip()
        if not pkg or not installed:
            continue

        key = (pkg, installed)
        if key in seen:
            continue
        seen.add(key)

        fixes = fixes_map.get(key, [])
        ver = best_fix(fixes)
        target = ver or "latest"

        if pkg_mgr == "pnpm":
            cmds.append(f"pnpm add {pkg}@{target}")
        elif pkg_mgr == "yarn":
            cmds.append(f"yarn add {pkg}@{target}")
        else:
            cmds.append(f"npm install {pkg}@{target}")

        if ver:
            cmds.extend(override_snippet(pkg_mgr, pkg, ver))

        cmds.append("")

    while cmds and cmds[-1] == "":
        cmds.pop()

    return cmds


def _code_fix_commands(introduced_semgrep: List[Finding]) -> list[str]:
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
            hint = "Upgrade the dependency (or bump the direct parent) to a non-vulnerable version."
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


def _collect_dep_fixes(deps_findings: List[Finding]) -> dict[tuple[str, str], list[str]]:
    """
    Build (pkg, installed_version) -> unique list of fix versions observed across scanners.
    """
    fixes: dict[tuple[str, str], list[str]] = {}
    for f in deps_findings:
        pkg = (f.package or "").strip()
        ver = (f.installed_version or "").strip()
        if not pkg or not ver:
            continue

        raw = (f.fixed_version or "")
        raw = raw.strip() if isinstance(raw, str) else ""
        if not raw:
            continue

        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            continue

        key = (pkg, ver)
        existing = fixes.get(key, [])
        for p in parts:
            if p not in existing:
                existing.append(p)
        fixes[key] = existing

    return fixes


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
            hint = (f.hint or "").strip() or "Review and refactor to remove this risky pattern."
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

    introduced_ct = int(report.context.get("introduced_clusters", 0) or 0)
    preexisting_ct = int(report.context.get("preexisting_clusters", 0) or 0)
    changed_pkgs_ct = int(report.context.get("changed_pkgs_count", 0) or 0)

    introduced_clusters_raw = report.context.get("introduced_clusters_list", None)

    introduced_deps_note = ""
    introduced_rows: list[dict] = []
    introduced_deps_table = "_No introduced dependency vulnerabilities._"

    if introduced_clusters_raw is None:
        introduced_deps_table = "_(Introduced dependency clusters list not provided to renderer yet.)_"
        introduced_deps_note = (
            "Pass `introduced_clusters_list` in report.context to show exact introduced dependency clusters."
        )
    else:
        introduced_clusters = introduced_clusters_raw or []
        if introduced_clusters:
            introduced_deps = unified_summary_for_clusters(deps_findings, introduced_clusters)
            introduced_rows = introduced_deps.get("unified_top") or []
            introduced_deps_table = _unified_table(introduced_deps, include_hint=True)

    introduced_semgrep_table = _semgrep_table(introduced_semgrep_findings, include_hint=True)

    pkg_mgr = _detect_pkg_manager()
    fixes_map = _collect_dep_fixes(deps_findings)
    dep_cmds = _dep_fix_commands(introduced_rows, pkg_mgr, fixes_map)
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

    quick_fix_block = "\n".join(fix_lines).strip() if fix_lines else "_No quick-fix commands available._"

    # Semgrep baseline counts (helps explain “GO even with findings on HEAD snapshot”)
    semgrep_intro = int(report.context.get("semgrep_introduced_count", 0) or 0)
    semgrep_pre = int(report.context.get("semgrep_preexisting_count", 0) or 0)
    semgrep_baseline_line = f"_Baseline: introduced={semgrep_intro}, preexisting={semgrep_pre}_"

    # ✅ Canonical WHY: show the gate narrative + gate decision (last 2 notes),
    # and optionally the baseline line (first note) if present.
    notes_all = report.notes or []
    why_notes: list[str] = []
    if notes_all:
        why_notes.append(notes_all[0])              # Baselines: ...
    if len(notes_all) >= 3:
        why_notes.extend(notes_all[-2:])            # gate narrative + decision
    elif len(notes_all) >= 2:
        why_notes.append(notes_all[-1])             # at least the decision line

    why_lines = "\n".join([f"- {_md(n)}" for n in why_notes]) if why_notes else "- (No notes)"

    # Details sections
    trivy_table = _top_findings_table(trivy_findings)
    grype_table = _top_findings_table(grype_findings)
    semgrep_table = _semgrep_table(semgrep_findings)

    unified_all_table = _unified_table(unified_all)

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
<summary><b>Details: Semgrep findings (HEAD snapshot)</b></summary>

{semgrep_baseline_line}

{semgrep_table}
</details>

### Dependency vulnerability snapshot (HEAD, includes pre-existing)
_This section is informational. Gating is based on **introduced** risk only._
- **Clusters (pkg@version):** {unified_all["clusters_count"]}
- **Introduced deps worst:** {(report.context.get("introduced_dep_worst_severity") or "NONE").upper()}
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
