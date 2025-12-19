from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.models import RDIReport
from rg.scanners.trivy import run_trivy_fs
from rg.normalize.trivy_norm import normalize_trivy
from rg.report.pr_comment import render_pr_comment_md


def decide_placeholder(mode: str) -> tuple[str, int]:
    """
    Placeholder decision engine.
    Next step: replace with normalization + RDI scoring.
    """
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

    # Run Trivy FS + normalize
    trivy_path = run_trivy_fs(workspace=workspace, out_dir=out_dir, timeout=600)
    trivy_findings = normalize_trivy(str(trivy_path))

    verdict, score = decide_placeholder(args.mode)

    notes = [
        f"Trivy findings: {len(trivy_findings)} (not gating yet).",
        "Next: add Syft + Grype for SBOM-based vulnerability correlation.",
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
        top_findings=[f.__dict__ for f in trivy_findings[:10]],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(render_pr_comment_md(report, trivy_findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
