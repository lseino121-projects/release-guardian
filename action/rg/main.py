from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.models import RDIReport

from rg.scanners.trivy import run_trivy_fs
from rg.normalize.trivy_norm import normalize_trivy

from rg.scanners.syft import run_syft_sbom
from rg.scanners.grype import run_grype_from_sbom
from rg.normalize.grype_norm import normalize_grype

from rg.report.pr_comment import render_pr_comment_md


def decide_placeholder(mode: str) -> tuple[str, int]:
    # v1: always go
    return "go", 18


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

    verdict, score = decide_placeholder(args.mode)

    notes = [
        f"Trivy findings: {len(trivy_findings)} (not gating yet).",
        f"Grype findings: {len(grype_findings)} (not gating yet).",
        "Next: dedupe Trivy + Grype into a unified vulnerability set.",
        "Decision engine will block only *introduced* high-risk findings (v1 policy).",
    ]

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
        },
        notes=notes,
        top_findings=[f.__dict__ for f in (trivy_findings + grype_findings)[:10]],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(render_pr_comment_md(report, trivy_findings, grype_findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
