from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple, Optional

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

    # SBOM baseline is canonical for deps diff (avoid double-baseline overwrite bugs)
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
    # 5) Counts ONLY (no recomputing "worst" here)
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

    # Notes: baseline line + canonical gate notes
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

            # baselines
            "node_baseline_status": node_baseline_status,
            "lockfile_diff_unavailable": diff_unavailable,
            "semgrep_baseline_status": semgrep_baseline.status,
            "semgrep_introduced_count": len(introduced_semgrep_findings),
            "semgrep_preexisting_count": len(preexisting_semgrep_findings),

            # direction (optional)
            "deps_direction": "↑" if len(classified["introduced"]) > 0 else "→",
            "code_direction": "↑" if len(introduced_semgrep_findings) > 0 else "→",
            "deps_preexisting_clusters": len(classified["preexisting"]),
            "code_preexisting_findings": len(preexisting_semgrep_findings),

            # canonical introduced-risk fields
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
