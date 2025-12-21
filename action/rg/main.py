from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.models import RDIReport

from rg.normalize.dedupe import unified_summary

from rg.rdi.introduced_node import introduced_packages_from_pr
from rg.rdi.policy_v1 import classify_clusters, gate_verdict

from rg.scanners.trivy import run_trivy_fs
from rg.normalize.trivy_norm import normalize_trivy

from rg.scanners.syft import run_syft_sbom
from rg.scanners.grype import run_grype_from_sbom
from rg.normalize.grype_norm import normalize_grype

from rg.report.pr_comment import render_pr_comment_md


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

    # --- Trivy ---
    trivy_path = run_trivy_fs(workspace=workspace, out_dir=out_dir, timeout=600)
    trivy_findings = normalize_trivy(str(trivy_path))

    # --- Syft -> SBOM ---
    sbom_path = run_syft_sbom(workspace=workspace, out_dir=out_dir, timeout=600)

    # --- Grype from SBOM ---
    grype_path = run_grype_from_sbom(str(sbom_path), out_dir=out_dir, timeout=600)
    grype_findings = normalize_grype(str(grype_path))

    all_findings = trivy_findings + grype_findings
    unified = unified_summary(all_findings)

    # --- Introduced vs pre-existing (Node-first) ---
    base_sha = ctx.base_sha or ""
    head_sha = ctx.head_sha or ""

    baseline = introduced_packages_from_pr(base_sha, head_sha, repo_dir=workspace)
    changed_pkgs = baseline.changed
    node_baseline_status = baseline.status

    classified = classify_clusters(all_findings, changed_pkgs)

    verdict, score, gate_notes = gate_verdict(
        mode=args.mode,
        threshold=args.severity_threshold,
        allow_conditional=args.allow_conditional,
        findings=all_findings,
        introduced_clusters=classified["introduced"],
    )

    # baseline not OK means we couldn't do a normal base-vs-head diff
    diff_unavailable = node_baseline_status != "OK"

    notes = [
        f"Node baseline status: {node_baseline_status}",
        f"Unified clusters (pkg@ver): {unified['clusters_count']} across {unified['advisories_count']} advisories.",
        f"Introduced clusters: {len(classified['introduced'])} | Pre-existing clusters: {len(classified['preexisting'])}",
        *gate_notes,
    ]

    if diff_unavailable:
        notes.append(
            "Baseline not OK for Node lockfile. If status=BASE_MISSING, all head deps are treated as introduced (expected). "
            "If status=REF_UNAVAILABLE, fix git checkout/fetch."
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
            "introduced_clusters": len(classified["introduced"]),
            "preexisting_clusters": len(classified["preexisting"]),
            "changed_pkgs_count": len(changed_pkgs),
            "node_baseline_status": node_baseline_status,
            "lockfile_diff_unavailable": diff_unavailable,
        },
        notes=notes[:15],  # tighten once stable
        top_findings=unified.get("unified_top", [])[:10],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(render_pr_comment_md(report, trivy_findings, grype_findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
