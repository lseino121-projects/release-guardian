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

from rg.rdi.introduced_node import introduced_packages_from_pr
from rg.rdi.introduced_semgrep import introduced_semgrep_from_pr
from rg.rdi.policy_v1 import classify_clusters, gate_verdict

from rg.report.pr_comment import render_pr_comment_md
from rg.rdi.introduced_sbom import introduced_packages_from_sbom_pr

def baseline_confidence(node_status: str, semgrep_status: str) -> str:
    def pen(s: str) -> int:
        s = (s or "").upper()
        if s == "OK":
            return 0
        if s == "BASE_MISSING":
            return 3
        return 15
    p = pen(node_status) + pen(semgrep_status)
    return "HIGH" if p == 0 else ("MED" if p <= 6 else "LOW")


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
    semgrep_config = "action/rg/rules"  # local deterministic rules inside repo

    # -------------------------
    # 1) Dependency scanners (v1 gating scope)
    # -------------------------
    trivy_path = run_trivy_fs(workspace=workspace, out_dir=out_dir, timeout=600)
    trivy_findings = normalize_trivy(str(trivy_path))

    sbom_path = run_syft_sbom(workspace=workspace, out_dir=out_dir, timeout=600)

    grype_path = run_grype_from_sbom(str(sbom_path), out_dir=out_dir, timeout=600)
    grype_findings = normalize_grype(str(grype_path))

    deps_findings = trivy_findings + grype_findings
    unified = unified_summary(deps_findings)

    # -------------------------
    # 2) Semgrep (head scan for reporting table)
    # -------------------------
    semgrep_path = run_semgrep(
        workspace=workspace,
        out_dir=out_dir,
        timeout=900,
        config=semgrep_config,
    )
    semgrep_findings = normalize_semgrep(str(semgrep_path))

    # -------------------------
    # 3) Introduced vs pre-existing baselines
    # -------------------------
    base_sha = ctx.base_sha or ""
    head_sha = ctx.head_sha or ""

    # Node baseline (for introduced deps)
    node_baseline = introduced_packages_from_pr(base_sha, head_sha, repo_dir=workspace)
    changed_pkgs = node_baseline.changed
    node_baseline_status = node_baseline.status
    diff_unavailable = node_baseline_status != "OK"

    classified = classify_clusters(deps_findings, changed_pkgs)

    # Semgrep baseline (introduced SAST)
    semgrep_baseline = introduced_semgrep_from_pr(
        base_ref=base_sha,
        head_ref=head_sha,
        repo_dir=workspace,
        config=semgrep_config,
        timeout=900,
    )
    introduced_semgrep_findings = semgrep_baseline.introduced
    preexisting_semgrep_findings = semgrep_baseline.preexisting  # not required yet, but useful later

    sbom_baseline = introduced_packages_from_sbom_pr(base_sha, head_sha, repo_dir=workspace)
    changed_pkgs = sbom_baseline.changed
    node_baseline_status = sbom_baseline.status  # reuse existing field name for now if you want
    diff_unavailable = sbom_baseline.status != "OK"

    # -------------------------
    # 4) Gating (introduced-only, deps + semgrep)
    # -------------------------
    verdict, score, gate_notes = gate_verdict(
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
    # 5) Introduced Risk summary (single narrative payload)
    # -------------------------
    SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _rank(sev: str | None) -> int:
        return SEV_RANK.get((sev or "").lower(), 99)

    def _worst(findings_list) -> str | None:
        worst_sev: str | None = None
        for f in findings_list:
            if worst_sev is None or _rank(getattr(f, "severity", None)) < _rank(worst_sev):
                worst_sev = getattr(f, "severity", None)
        return worst_sev

    introduced_cluster_set = set(classified["introduced"])
    introduced_dep_findings = [
        f for f in deps_findings if (f.package, f.installed_version) in introduced_cluster_set
    ]
    introduced_dep_worst = _worst(introduced_dep_findings)
    introduced_code_worst = _worst(introduced_semgrep_findings)

    introduced_any = bool(introduced_dep_findings) or bool(introduced_semgrep_findings)
    introduced_sources: list[str] = []
    if introduced_dep_findings:
        introduced_sources.append("deps")
    if introduced_semgrep_findings:
        introduced_sources.append("code")

    # overall worst across deps+code
    introduced_overall_worst: str | None = None
    for sev in [introduced_dep_worst, introduced_code_worst]:
        if sev and (introduced_overall_worst is None or _rank(sev) < _rank(introduced_overall_worst)):
            introduced_overall_worst = sev

    # -------------------------
    # 6) Notes ("Why") — tie to vision
    # -------------------------
    # Keep these tight; the comment renderer takes the first N lines.
    notes = [
        # Baseline health (short, factual)
        f"Baselines: node={node_baseline_status}, semgrep={semgrep_baseline.status}.",

        # Decision narrative (single source of truth)
        *gate_notes,
    ]

    # Optional debug-ish note (only when baseline is not OK)
    if diff_unavailable:
        notes.append(
            "Node baseline not OK (e.g., BASE_MISSING means lockfile introduced; expected). REF_UNAVAILABLE means the SHAs weren’t fetchable."
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

            # existing counters
            "introduced_clusters": len(classified["introduced"]),
            "preexisting_clusters": len(classified["preexisting"]),
            "changed_pkgs_count": len(changed_pkgs),
            "introduced_clusters_list": classified["introduced"],

            # baseline metadata
            "node_baseline_status": node_baseline_status,
            "lockfile_diff_unavailable": diff_unavailable,
            "semgrep_baseline_status": semgrep_baseline.status,
            "semgrep_introduced_count": len(introduced_semgrep_findings),
            "semgrep_preexisting_count": len(preexisting_semgrep_findings),

            # NEW: introduced-risk “policy plumbing” fields
            "introduced_dep_advisories_count": len(introduced_dep_findings),
            "introduced_code_findings_count": len(introduced_semgrep_findings),
            "introduced_worst_severity": introduced_overall_worst,
            "introduced_sources": introduced_sources,  # ["deps", "code"]
            "severity_threshold": args.severity_threshold,
            "baseline_confidence": baseline_confidence(
                node_baseline_status,
                semgrep_baseline.status,
            ),

        },
        notes=notes[:10],  # keep it crisp; pr_comment uses first ~6 anyway
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
