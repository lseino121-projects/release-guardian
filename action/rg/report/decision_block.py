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

    deps_clusters = int(ctx.get("introduced_clusters", 0) or 0)
    deps_advs = int(ctx.get("introduced_dep_advisories_count", 0) or 0)
    code_ct = int(ctx.get("introduced_code_findings_count", 0) or 0)

    overall_worst = (ctx.get("introduced_worst_severity") or "none").upper()
    dep_worst = (ctx.get("introduced_dep_worst_severity") or "none").upper()
    code_worst = (ctx.get("introduced_code_worst_severity") or "none").upper()

    worst_sources = ctx.get("introduced_worst_sources") or []
    worst_sources_str = " + ".join(worst_sources) if worst_sources else "none"

    threshold = (ctx.get("severity_threshold") or "high").upper()

    confidence = (ctx.get("baseline_confidence") or "HIGH").upper()
    node_status = (ctx.get("node_baseline_status") or "OK").upper()
    semgrep_status = (ctx.get("semgrep_baseline_status") or "OK").upper()
    conf_badge = _confidence_badge(confidence)

    deps_pre = int(ctx.get("deps_preexisting_clusters", ctx.get("preexisting_clusters", 0)) or 0)
    code_pre = int(ctx.get("code_preexisting_findings", ctx.get("semgrep_preexisting_count", 0)) or 0)

    deps_dir = (ctx.get("deps_direction") or ("↑" if deps_clusters else "→"))
    code_dir = (ctx.get("code_direction") or ("↑" if code_ct else "→"))

    if verdict == "go":
        decision_line = f"Decision: Introduced risk is below threshold ({threshold})."
    else:
        decision_line = f"Decision: Introduced risk meets/exceeds threshold ({threshold})."

    lines = [
        header,
        "",
        f"Introduced risk: deps={deps_clusters} cluster / {deps_advs} advisories, code={code_ct} findings.",
        f"Worst severity: {overall_worst} (source: {worst_sources_str}; deps={dep_worst}, code={code_worst}).",
        f"Direction: deps {deps_dir} (preexisting={deps_pre}), code {code_dir} (preexisting={code_pre}).",
        decision_line,
        f"Confidence: {conf_badge} {confidence} (baseline: node={node_status}, semgrep={semgrep_status}).",
    ]

    if confidence != "HIGH":
        lines.append("Baseline comparison imperfect → score penalized; decision may be conservative.")

    return "\n".join(lines)
