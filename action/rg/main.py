# main.py
from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.models import RDIReport

from rg.normalize.dedupe import unified_summary

from rg.scanners.trivy import run_trivy_fs
from rg.normalize.trivy_norm import normalize_trivy

from rg.scanners.syft import run_syft_sbom
from rg.scanners.grype import run_grype_from_sbom
from rg.normalize.grype_norm import normalize_grype

from rg.scanners.semgrep import run_semgrep
from rg.normalize.semgrep_norm import normalize_semgrep

from rg.rdi.introduced_semgrep import introduced_semgrep_from_pr
from rg.rdi.policy_v1 import classify_clusters, gate_verdict

from rg.report.pr_comment import render_pr_comment_md
from rg.rdi.introduced_sbom import introduced_packages_from_sbom_pr


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_rank(sev: str | None) -> int:
    return _SEV_RANK.get((sev or "").lower(), 99)


def _baseline_penalty(status: str) -> int:
    """
    Must match policy_v1 philosophy so Confidence never disagrees with the score penalty model.
    """
    s = (status or "").upper().strip()

    if s == "OK":
        return 0

    # Lockfile introduced in this PR. Expected, still deterministic; do not penalize confidence.
    if s == "BASE_MISSING":
        return 0

    # Real confidence problems
    if s in ("REF_UNAVAILABLE", "SCAN_FAILED"):
        return 15

    # Unknown statuses → medium penalty
    return 8


def baseline_confidence(node_status: str, semgrep_status: str) -> str:
    pen = _baseline_penalty(node_status) + _baseline_penalty(semgrep_status)
    return "HIGH" if pen == 0 else ("MED" if pen <= 6 else "LOW")


def _unique_ids(findings_list) -> int:
    ids = set()
    for f in findings_list or []:
        fid = (getattr(f, "id", None) or "").strip()
        if fid:
            ids.add(fid)
    return len(ids)


def _best_fix_version(raw: str | None) -> str | None:
    """
    Trivy sometimes returns "1.2.6, 0.2.4" etc. Grype may be empty.
    v1 heuristic: first token that looks like a version (starts with digit).
    """
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return None
    for p in parts:
        if p and p[0].isdigit():
            return p
    return parts[0] or None


def _pick_blocking_dep(introduced_dep_findings) -> tuple[str, str]:
    """
    Deterministic "aha" line for deps:
      - choose worst severity finding, then pkg, then installed_version, then vuln id
      - include up to 3 advisory IDs
      - include best observed fix version if available
    """
    if not introduced_dep_findings:
        return "", ""

    f0 = sorted(
        introduced_dep_findings,
        key=lambda f: (
            _sev_rank(getattr(f, "severity", None)),
            str(getattr(f, "package", "") or ""),
            str(getattr(f, "installed_version", "") or ""),
            str(getattr(f, "id", "") or ""),
        ),
    )[0]

    pkg = (getattr(f0, "package", "") or "").strip()
    ver = (getattr(f0, "installed_version", "") or "").strip()
    sev = (getattr(f0, "severity", "") or "").strip().upper() or "UNKNOWN"

    ids = sorted(
        {
            (getattr(f, "id", "") or "").strip()
            for f in introduced_dep_findings
            if (getattr(f, "package", "") or "").strip() == pkg
            and (getattr(f, "installed_version", "") or "").strip() == ver
            and (getattr(f, "id", "") or "").strip()
        }
    )
    ids_str = ", ".join(ids[:3]) + ("…" if len(ids) > 3 else "")

    # Pick best fix version observed for this pkg@ver across findings
    fix_candidates: list[str] = []
    for f in introduced_dep_findings:
        if (getattr(f, "package", "") or "").strip() != pkg:
            continue
        if (getattr(f, "installed_version", "") or "").strip() != ver:
            continue
        fx = _best_fix_version(getattr(f, "fixed_version", None))
        if fx and fx not in fix_candidates:
            fix_candidates.append(fx)
    best_fix = fix_candidates[0] if fix_candidates else None

    summary = f"🟥 {sev} deps: {pkg}@{ver}" + (f" — {ids_str}" if ids_str else "")
    if best_fix:
        fix = f"Fix: upgrade {pkg} to {best_fix} (or bump the direct parent / pin a transitive override)."
    else:
        fix = "Fix: upgrade the dependency (or bump the direct parent / pin a transitive override) to a non-vulnerable version."
    return summary, fix


def _pick_blocking_code(introduced_code_findings) -> tuple[str, str]:
    """
    Deterministic "aha" line for code:
      - choose worst severity finding, then file, then line, then rule id
      - include rule id + location
      - include hint if present (already curated via rule metadata)
    """
    if not introduced_code_findings:
        return "", ""

    f0 = sorted(
        introduced_code_findings,
        key=lambda f: (
            _sev_rank(getattr(f, "severity", None)),
            str(getattr(f, "package", "") or ""),  # file path in your schema
            str(getattr(f, "installed_version", "") or ""),  # line in your schema
            str(getattr(f, "id", "") or ""),
        ),
    )[0]

    sev = (getattr(f0, "severity", "") or "").strip().upper() or "UNKNOWN"
    rule = (getattr(f0, "id", "") or "").strip()
    file_path = (getattr(f0, "package", "") or "").strip()
    line = (getattr(f0, "installed_version", "") or "").strip()

    hint = (getattr(f0, "hint", "") or "").strip()
    if not hint:
        hint = "Review and refactor to remove this risky pattern."

    summary = f"🟧 {sev} code: {rule} — {file_path}:{line}"
    fix = f"Fix: {hint}"
    return summary, fix


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--event-path", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--severity-threshold", required=True)
    ap.add_argument("--allow-conditional", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    ctx = load_context(args.event_path)

    workspace = "/github/workspace"
    out_dir = f"{workspace}/.rg/out"
    semgrep_config = "action/rg/rules"  # repo-local deterministic rules

    # -------------------------
    # 1) Dependency scanners
    # -------------------------
    trivy_path = run_trivy_fs(workspace=workspace, out_dir=out_dir, timeout=600)
    trivy_findings = normalize_trivy(str(trivy_path))

    sbom_path = run_syft_sbom(workspace=workspace, out_dir=out_dir, timeout=600)

    grype_path = run_grype_from_sbom(str(sbom_path), out_dir=out_dir, timeout=600)
    grype_findings = normalize_grype(str(grype_path))

    deps_findings = trivy_findings + grype_findings
    unified = unified_summary(deps_findings)

    # -------------------------
    # 2) Semgrep head scan (for HEAD snapshot table)
    # -------------------------
    semgrep_path = run_semgrep(
        workspace=workspace,
        out_dir=out_dir,
        timeout=900,
        config=semgrep_config,
    )
    semgrep_findings = normalize_semgrep(str(semgrep_path))

    # -------------------------
    # 3) Baselines: introduced vs preexisting
    # -------------------------
    base_sha = ctx.base_sha or ""
    head_sha = ctx.head_sha or ""

    # SBOM baseline is canonical for deps diff
    sbom_baseline = introduced_packages_from_sbom_pr(base_sha, head_sha, repo_dir=workspace)
    changed_pkgs = sbom_baseline.changed
    node_baseline_status = sbom_baseline.status
    diff_unavailable = node_baseline_status != "OK"

    classified = classify_clusters(deps_findings, changed_pkgs)

    semgrep_baseline = introduced_semgrep_from_pr(
        base_ref=base_sha,
        head_ref=head_sha,
        repo_dir=workspace,
        config=semgrep_config,
        timeout=900,
        excludes=["unsafe", "examples/unsafe"],
    )
    introduced_semgrep_findings = semgrep_baseline.introduced
    preexisting_semgrep_findings = semgrep_baseline.preexisting

    # -------------------------
    # 4) Gating (single source of truth)
    # -------------------------
    verdict, score, gate_notes, worst_sources, dep_worst, code_worst, overall_worst = gate_verdict(
        mode=args.mode,
        threshold=args.severity_threshold,
        allow_conditional=args.allow_conditional,
        findings=deps_findings,
        introduced_clusters=classified["introduced"],
        introduced_semgrep_findings=introduced_semgrep_findings,
        node_baseline_status=node_baseline_status,
        semgrep_baseline_status=semgrep_baseline.status,
    )

    # -------------------------
    # 5) Introduced counts + AHA culprit
    # -------------------------
    introduced_cluster_set = set(classified["introduced"])
    introduced_dep_findings = [
        f for f in deps_findings if (f.package, f.installed_version) in introduced_cluster_set
    ]
    introduced_dep_advisories_count = _unique_ids(introduced_dep_findings)

    introduced_sources: list[str] = []
    if introduced_dep_advisories_count > 0:
        introduced_sources.append("deps")
    if len(introduced_semgrep_findings) > 0:
        introduced_sources.append("code")

    blocking_summary = ""
    blocking_fix = ""
    if verdict != "go" and (overall_worst is not None):
        ws = worst_sources or []
        # Prefer deps if deps caused worst (ties include deps), else code
        if "deps" in ws and introduced_dep_findings:
            blocking_summary, blocking_fix = _pick_blocking_dep(introduced_dep_findings)
        elif "code" in ws and introduced_semgrep_findings:
            blocking_summary, blocking_fix = _pick_blocking_code(introduced_semgrep_findings)
        else:
            # fallback: pick whichever exists
            if introduced_dep_findings:
                blocking_summary, blocking_fix = _pick_blocking_dep(introduced_dep_findings)
            elif introduced_semgrep_findings:
                blocking_summary, blocking_fix = _pick_blocking_code(introduced_semgrep_findings)

    # Notes: baseline line + canonical gate notes (decision block + Why must align)
    notes = [
        f"Baselines: node={node_baseline_status}, semgrep={semgrep_baseline.status}.",
        *gate_notes,
    ]
    if diff_unavailable:
        notes.append(
            "Dependency baseline not OK (e.g., BASE_MISSING means lockfile introduced; expected). "
            "REF_UNAVAILABLE means the SHAs weren’t fetchable."
        )

    summary = f"{verdict.upper()} (RDI {score}) — v1 scaffold"

    report = RDIReport(
        verdict=verdict,
        rdi_score=score,
        summary=summary,
        context={
            "repo": args.repo,
            "sha": args.sha,
            "event_name": ctx.event_name,
            "pr_number": ctx.pr_number,
            "base_sha": ctx.base_sha,
            "head_sha": ctx.head_sha,

            # deps diff classification
            "introduced_clusters": len(classified["introduced"]),
            "preexisting_clusters": len(classified["preexisting"]),
            "changed_pkgs_count": len(changed_pkgs),
            "introduced_clusters_list": classified["introduced"],

            # AHA payload (decision block uses this; never recompute there)
            "blocking_summary": blocking_summary,
            "blocking_fix": blocking_fix,

            # baselines
            "node_baseline_status": node_baseline_status,
            "lockfile_diff_unavailable": diff_unavailable,
            "semgrep_baseline_status": semgrep_baseline.status,
            "semgrep_introduced_count": len(introduced_semgrep_findings),
            "semgrep_preexisting_count": len(preexisting_semgrep_findings),

            # direction
            "deps_direction": "↑" if len(classified["introduced"]) > 0 else "→",
            "code_direction": "↑" if len(introduced_semgrep_findings) > 0 else "→",
            "deps_preexisting_clusters": len(classified["preexisting"]),
            "code_preexisting_findings": len(preexisting_semgrep_findings),

            # canonical introduced-risk fields (from gate_verdict)
            "introduced_dep_advisories_count": introduced_dep_advisories_count,
            "introduced_code_findings_count": len(introduced_semgrep_findings),
            "introduced_dep_worst_severity": dep_worst,
            "introduced_code_worst_severity": code_worst,
            "introduced_worst_severity": overall_worst,
            "introduced_worst_sources": worst_sources,  # what CAUSED the worst severity
            "introduced_sources": introduced_sources,    # what was introduced at all

            "severity_threshold": args.severity_threshold,
            "baseline_confidence": baseline_confidence(node_baseline_status, semgrep_baseline.status),
        },
        notes=notes[:10],
        top_findings=unified.get("unified_top", [])[:10],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(
        render_pr_comment_md(
            report,
            trivy_findings,
            grype_findings,
            semgrep_findings,
            introduced_semgrep_findings,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
