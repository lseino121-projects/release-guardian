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

    # Core summary
    deps_clusters = int(ctx.get("introduced_clusters", 0) or 0)
    deps_advs = int(ctx.get("introduced_dep_advisories_count", 0) or 0)
    code_ct = int(ctx.get("introduced_code_findings_count", 0) or 0)

    overall_worst = (ctx.get("introduced_worst_severity") or "none").upper()
    dep_worst = (ctx.get("introduced_dep_worst_severity") or "none").upper()
    code_worst = (ctx.get("introduced_code_worst_severity") or "none").upper()

    worst_sources = ctx.get("introduced_worst_sources") or []
    sources_str = " + ".join(worst_sources) if worst_sources else "none"

    threshold = (ctx.get("severity_threshold") or "high").upper()

    confidence = (ctx.get("baseline_confidence") or "HIGH").upper()
    node_status = (ctx.get("node_baseline_status") or "OK").upper()
    semgrep_status = (ctx.get("semgrep_baseline_status") or "OK").upper()
    conf_badge = _confidence_badge(confidence)

    # Direction (short)
    deps_pre = int(ctx.get("deps_preexisting_clusters", ctx.get("preexisting_clusters", 0)) or 0)
    code_pre = int(ctx.get("code_preexisting_findings", ctx.get("semgrep_preexisting_count", 0)) or 0)
    deps_dir = (ctx.get("deps_direction") or ("↑" if deps_clusters else "→"))
    code_dir = (ctx.get("code_direction") or ("↑" if code_ct else "→"))

    # Canonical decision line: mirror gate_verdict (so "Why" never disagrees)
    gate_notes = (report.notes or [])[1:]  # skip "Baselines: ..."
    decision_line = gate_notes[1] if len(gate_notes) >= 2 else ""
    if not decision_line:
        decision_line = (
            f"Introduced risk is below threshold ({threshold})."
            if verdict == "go"
            else f"Introduced risk meets/exceeds threshold ({threshold})."
        )

    # ✅ AHA: blocking culprit + fix (computed in main; never recompute here)
    blocking_summary = (ctx.get("blocking_summary") or "").strip()
    blocking_fix = (ctx.get("blocking_fix") or "").strip()

    lines = [header, ""]

    if verdict != "go" and blocking_summary:
        lines.append(blocking_summary)
        if blocking_fix:
            lines.append(blocking_fix)
        lines.append("")

    lines += [
        f"Introduced risk: deps={deps_clusters} cluster / {deps_advs} advisories, code={code_ct} findings.",
        f"Worst severity: {overall_worst} (source: {sources_str}; deps={dep_worst}, code={code_worst}).",
        f"Direction: deps {deps_dir} (preexisting={deps_pre}), code {code_dir} (preexisting={code_pre}).",
        f"Decision: {decision_line}",
        f"Confidence: {conf_badge} {confidence} (baseline: node={node_status}, semgrep={semgrep_status}).",
    ]

    if confidence != "HIGH":
        lines.append("Baseline comparison imperfect → score penalized; decision may be conservative.")

    return "\n".join(lines)
