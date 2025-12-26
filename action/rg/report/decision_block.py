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

    # Introduced-only core counters
    deps_clusters = int(ctx.get("introduced_clusters", 0) or 0)
    deps_advs = int(ctx.get("introduced_dep_advisories_count", 0) or 0)
    code_ct = int(ctx.get("introduced_code_findings_count", 0) or 0)

    threshold = (ctx.get("severity_threshold") or "high").upper()

    confidence = (ctx.get("baseline_confidence") or "HIGH").upper()
    node_status = (ctx.get("node_baseline_status") or "OK").upper()
    semgrep_status = (ctx.get("semgrep_baseline_status") or "OK").upper()
    conf_badge = _confidence_badge(confidence)

    overall_worst = (ctx.get("introduced_worst_severity") or "none").upper()
    worst_sources = ctx.get("introduced_worst_sources") or []
    worst_sources_str = " + ".join(worst_sources) if worst_sources else "none"

    # -------------------------
    # AHA: show the blocker immediately
    # Expect these to be passed by main.py (recommended):
    #   blocking_summary: short string
    #   blocking_fix: short string
    # -------------------------
    blocking_summary = (ctx.get("blocking_summary") or "").strip()
    blocking_fix = (ctx.get("blocking_fix") or "").strip()

    # -------------------------
    # Optional: show pre-existing HEAD deps worst (NOT gating)
    # Pass these from main.py if you want minimist to appear at the top:
    #   head_preexisting_dep_summary: str
    # -------------------------
    preexisting_head_line = (ctx.get("head_preexisting_dep_summary") or "").strip()

    # -------------------------
    # Compact decision line (avoid repeating “why”)
    # -------------------------
    if verdict == "go":
        decision_line = f"Decision: Introduced risk is below threshold ({threshold})."
    else:
        decision_line = f"Decision: Introduced risk meets/exceeds threshold ({threshold})."

    # -------------------------
    # Render (keep very tight)
    # -------------------------
    lines: list[str] = [header, ""]

    if blocking_summary:
        lines.append(blocking_summary)
    if blocking_fix:
        lines.append(f"Fix: {blocking_fix}")

    if preexisting_head_line:
        lines += ["", preexisting_head_line]

    lines += [
        "",
        f"Introduced-only: deps={deps_clusters} clusters / {deps_advs} advisories, code={code_ct} findings.",
        f"Worst introduced severity: {overall_worst} (source: {worst_sources_str}).",
        decision_line,
        f"Confidence: {conf_badge} {confidence} (baseline: node={node_status}, semgrep={semgrep_status}).",
    ]

    if confidence != "HIGH":
        lines.append("Baseline comparison imperfect → score penalized; decision may be conservative.")

    return "\n".join(lines)
