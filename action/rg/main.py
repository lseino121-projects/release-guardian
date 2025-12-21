from __future__ import annotations

import argparse
import json
from pathlib import Path

from rg.github_context import load_context
from rg.models import RDIReport

from rg.rdi.introduced_node import introduced_packages_from_pr
from rg.rdi.policy_v1 import classify_clusters, gate_verdict

from rg.normalize.dedupe import unified_summary

from rg.scanners.trivy import run_trivy_fs
from rg.normalize.trivy_norm import normalize_trivy

from rg.scanners.syft import run_syft_sbom
from rg.scanners.grype import run_grype_from_sbom
from rg.normalize.grype_norm import normalize_grype

from rg.report.pr_comment import render_pr_comment_md
import subprocess

def _sh(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, cwd=workspace, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as e:
        return f"ERROR({e.returncode}): {e.output.strip()}"

notes.append(f"DEBUG git rev-parse HEAD: {_sh(['git','rev-parse','HEAD'])}")
notes.append(f"DEBUG base_sha: {ctx.base_sha} head_sha: {ctx.head_sha}")
notes.append(f"DEBUG has package-lock in workspace: {_sh(['bash','-lc','test -f package-lock.json && echo yes || echo no'])}")
notes.append(f"DEBUG git show base:pkg-lock: {_sh(['bash','-lc', f'git show {ctx.base_sha}:package-lock.json >/dev/null && echo ok || echo missing'])}")
notes.append(f"DEBUG git show head:pkg-lock: {_sh(['bash','-lc', f'git show {ctx.head_sha}:package-lock.json >/dev/null && echo ok || echo missing'])}")
notes.append(f"DEBUG remotes: {_sh(['git','remote','-v'])}")


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

    # --- Unified summary ---
    all_findings = trivy_findings + grype_findings
    unified = unified_summary(all_findings)

    # --- Introduced vs pre-existing (Node-first) ---
    base_sha = ctx.base_sha or ""
    head_sha = ctx.head_sha or ""

    changed_pkgs = {}
    diff_unavailable = False
    import subprocess

    def _sh(cmd: list[str]) -> str:
        try:
            return subprocess.check_output(cmd, cwd=workspace, text=True, stderr=subprocess.STDOUT).strip()
        except subprocess.CalledProcessError as e:
            return f"ERROR({e.returncode}): {e.output.strip()}"

    notes.append(f"DEBUG git rev-parse HEAD: {_sh(['git','rev-parse','HEAD'])}")
    notes.append(f"DEBUG base_sha: {ctx.base_sha} head_sha: {ctx.head_sha}")
    notes.append(f"DEBUG has package-lock in workspace: {_sh(['bash','-lc','test -f package-lock.json && echo yes || echo no'])}")
    notes.append(f"DEBUG git show base:pkg-lock: {_sh(['bash','-lc', f'git show {ctx.base_sha}:package-lock.json >/dev/null && echo ok || echo missing'])}")
    notes.append(f"DEBUG git show head:pkg-lock: {_sh(['bash','-lc', f'git show {ctx.head_sha}:package-lock.json >/dev/null && echo ok || echo missing'])}")
    notes.append(f"DEBUG remotes: {_sh(['git','remote','-v'])}")

    if base_sha and head_sha:
        changed_pkgs = introduced_packages_from_pr(ctx.base_sha, ctx.head_sha, repo_dir=workspace)

        # Optional sentinel support if you implemented it (won't break if not present)
        if "__RG_DIFF_UNAVAILABLE__" in changed_pkgs:
            diff_unavailable = True
            changed_pkgs.pop("__RG_DIFF_UNAVAILABLE__", None)
    else:
        diff_unavailable = True

    classified = classify_clusters(all_findings, changed_pkgs)

    verdict, score, gate_notes = gate_verdict(
        mode=args.mode,
        threshold=args.severity_threshold,
        allow_conditional=args.allow_conditional,
        findings=all_findings,
        introduced_clusters=classified["introduced"],
    )

    notes = [
        f"Unified clusters (pkg@ver): {unified['clusters_count']} across {unified['advisories_count']} advisories.",
        f"Introduced clusters: {len(classified['introduced'])} | Pre-existing clusters: {len(classified['preexisting'])}",
        *gate_notes,
    ]
    if diff_unavailable:
        notes.append(
            "Lockfile diff unavailable for base/head. If introduced detection looks wrong, set checkout ref to github.event.pull_request.head.sha or allow git fetch of SHAs."
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
            "lockfile_diff_unavailable": diff_unavailable,
        },
        notes=notes,
        top_findings=unified.get("unified_top", [])[:10],
    )

    Path(args.out_json).write_text(json.dumps(report.to_dict(), indent=2))
    Path(args.out_md).write_text(render_pr_comment_md(report, trivy_findings, grype_findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
