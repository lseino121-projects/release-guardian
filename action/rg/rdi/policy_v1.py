from __future__ import annotations

from typing import List, Dict, Tuple, Optional

from rg.normalize.schema import Finding
from rg.normalize.dedupe import cluster_findings


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _rank(sev: str | None) -> int:
    return _SEV_RANK.get((sev or "").lower(), 99)


def classify_clusters(
    findings: List[Finding],
    changed_pkgs: Dict[str, Tuple[Optional[str], Optional[str]]],
) -> dict:
    """
    Returns:
      introduced_clusters: list[(pkg, ver)]
      preexisting_clusters: list[(pkg, ver)]
      unknown_clusters: list[(pkg, ver)]
    """
    clusters = cluster_findings(findings)

    introduced: list[tuple[str, str]] = []
    preexisting: list[tuple[str, str]] = []
    unknown: list[tuple[str, str]] = []

    for (pkg, ver) in clusters.keys():
        if pkg in changed_pkgs:
            _, head_ver = changed_pkgs[pkg]
            if head_ver == ver:
                introduced.append((pkg, ver))
            else:
                preexisting.append((pkg, ver))
        else:
            preexisting.append((pkg, ver))

    return {"introduced": introduced, "preexisting": preexisting, "unknown": unknown}


def _worst_severity(findings: List[Finding]) -> Optional[str]:
    worst: Optional[str] = None
    for f in findings:
        if worst is None or _rank(f.severity) < _rank(worst):
            worst = f.severity
    return worst

def gate_verdict(
    mode: str,
    threshold: str,
    allow_conditional: bool,
    findings: List[Finding],
    introduced_clusters: list[tuple[str, str]],
    introduced_semgrep_findings: Optional[List[Finding]] = None,
) -> tuple[str, int, list[str]]:
    """
    v1 gating:
      - Only introduced deps clusters can block (Trivy/Grype normalized -> clusters).
      - Introduced Semgrep HIGH/CRITICAL can block (report-only unless mode=enforce).
      - "threshold" applies consistently across sources (high/critical/etc).
    """
    score = 18  # still placeholder
    allow_conditional_bool = str(allow_conditional).lower() in ("1", "true", "yes", "y")
    thr_rank = _rank(threshold)

    # -------------------------
    # Introduced deps
    # -------------------------
    introduced_set = set(introduced_clusters)
    introduced_dep_findings = [
        f for f in findings if (f.package, f.installed_version) in introduced_set
    ]
    dep_worst = _worst_severity(introduced_dep_findings)

    # -------------------------
    # Introduced Semgrep
    # -------------------------
    introduced_semgrep_findings = introduced_semgrep_findings or []
    semgrep_worst = _worst_severity(introduced_semgrep_findings)

    # Counts for a single compact summary line (optional but helpful)
    introduced_dep_clusters_ct = len(introduced_clusters)
    introduced_dep_advisories_ct = len(introduced_dep_findings)
    introduced_code_ct = len(introduced_semgrep_findings)

    # If nothing introduced anywhere -> GO
    if introduced_dep_advisories_ct == 0 and introduced_code_ct == 0:
        return "go", score, ["No introduced risk detected (deps or code)."]

    # Determine if either source meets/exceeds threshold
    dep_meets = dep_worst is not None and _rank(dep_worst) <= thr_rank
    semgrep_meets = semgrep_worst is not None and _rank(semgrep_worst) <= thr_rank

    # Worst overall + sources (for your “Why” line)
    worst = None
    sources: list[str] = []
    if dep_worst is not None:
        worst = dep_worst
        sources.append("deps")
    if semgrep_worst is not None:
        if worst is None or _rank(semgrep_worst) < _rank(worst):
            worst = semgrep_worst
        sources.append("code")

    worst_str = worst.upper() if worst else "UNKNOWN"
    sources_str = ", ".join(sources) if sources else "unknown"

    # 1) Compact risk summary line (this replaces the noisy counters)
    summary_line = (
        f"Introduced risk: deps={introduced_dep_clusters_ct} clusters/{introduced_dep_advisories_ct} advisories, "
        f"code={introduced_code_ct} findings. Worst={worst_str} (sources: {sources_str})."
    )

    # 2) Decision line (single narrative)
    if mode != "enforce":
        return "conditional", score, [summary_line, f"Reporting-only (mode={mode})."]

    if dep_meets or semgrep_meets:
        return_value = "conditional" if allow_conditional_bool else "no-go"
        return (
            return_value,
            score,
            [
                summary_line,
                f"Introduced risk meets/exceeds threshold ({threshold.upper()}).",
            ],
        )

    return "go", score, [summary_line, f"Introduced risk is below threshold ({threshold.upper()})."]
