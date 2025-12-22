from __future__ import annotations
from typing import List

from rg.models import RDIReport


def render_decision_block(report: RDIReport) -> str:
    verdict = report.verdict
    score = report.rdi_score

    if verdict == "go":
        header = f"✅ Go — RDI {score}"
    elif verdict == "conditional":
        header = f"⚠️ Conditional — RDI {score}"
    else:
        header = f"❌ No-Go — RDI {score}"

    ctx = report.context or {}

    deps_clusters = ctx.get("introduced_clusters", 0)
    deps_advs = ctx.get("introduced_dep_advisories_count", "?")
    code_ct = ctx.get("introduced_code_findings_count", 0)
    worst = (ctx.get("introduced_worst_severity") or "none").upper()
    sources = ctx.get("introduced_sources") or []
    sources_str = " + ".join(sources) if sources else "none"

    threshold = ctx.get("severity_threshold", "HIGH").upper()
    confidence = ctx.get("baseline_confidence", "HIGH")
    node_status = ctx.get("node_baseline_status", "OK")
    semgrep_status = ctx.get("semgrep_baseline_status", "OK")

    lines = [
        header,
        "",
        f"Introduced risk: deps={deps_clusters} cluster / {deps_advs} advisories, code={code_ct} findings.",
        f"Worst severity: {worst} (sources: {sources_str}).",
        f"Decision: Introduced risk exceeds {threshold} threshold."
        if verdict != "go"
        else "Decision: No introduced risk above threshold.",
        f"Confidence: {confidence} (baseline: node={node_status}, semgrep={semgrep_status}).",
    ]

    return "\n".join(lines)
