from __future__ import annotations

from rg.models import RDIReport


def _confidence_badge(conf: str | None) -> str:
    c = (conf or "").strip().upper()
    if c == "HIGH":
        return "🟩"
    if c == "MED":
        return "🟨"
    if c == "LOW":
        return "🟥"
    return "⬜️"


def render_decision_block(report: RDIReport) -> str:
    verdict = (report.verdict or "").lower()
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

    threshold = (ctx.get("severity_threshold") or "high").upper()

    confidence = (ctx.get("baseline_confidence") or "HIGH").upper()
    node_status = (ctx.get("node_baseline_status") or "OK").upper()
    semgrep_status = (ctx.get("semgrep_baseline_status") or "OK").upper()

    conf_badge = _confidence_badge(confidence)

    if verdict == "go":
        decision_line = f"Decision: Introduced risk is below threshold ({threshold})."
    else:
        decision_line = f"Decision: Introduced risk meets/exceeds threshold ({threshold})."

    lines = [
        header,
        "",
        f"Introduced risk: deps={deps_clusters} cluster / {deps_advs} advisories, code={code_ct} findings.",
        f"Worst severity: {worst} (sources: {sources_str}).",
        decision_line,
        f"Confidence: {conf_badge} {confidence} (baseline: node={node_status}, semgrep={semgrep_status}).",
    ]

    # One extra line only when confidence isn't HIGH
    if confidence != "HIGH":
        lines.append("Baseline comparison imperfect → score penalized; decision may be conservative.")

    return "\n".join(lines)
