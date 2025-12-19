from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.report import RDIReport, render_pr_comment_md


def decide_placeholder(mode: str) -> tuple[str, int, list[str]]:
    """
    Placeholder decision engine.
    Next step: replace with scanner execution + normalization + RDI scoring.
    """
    # v1 scaffold logic: always Go, unless mode is enforce and we want to test paths later.
    verdict = "go"
    score = 18
    notes = [
        "Scaffold run: scanner integration not enabled yet.",
        "Next: run Trivy/Syft/Grype/Semgrep locally in the runner.",
        "Decision engine will block only *introduced* high-risk findings (v1 policy).",
    ]
    return verdict, score, notes


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

    verdict, score, notes = decide_placeholder(args.mode)

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
        top_findings=[],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(render_pr_comment_md(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
