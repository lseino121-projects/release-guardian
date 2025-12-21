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
def _worst_severity(findings: List[Finding]) -> Optional[str]:
    worst: Optional[str] = None
    for f in findings:
        if not f.severity:
            continue
        if worst is None or _rank(f.severity) < _rank(worst):
            worst = f.severity
    return worst


def _worst_of(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    return a if _rank(a) < _rank(b) else b


def _rdi_score_from_introduced(
    worst: Optional[str],
    dep_clusters: int,
    dep_advisories: int,
    code_findings: int,
) -> int:
    """
    RDI score: 0..100 (higher = safer)

    v1 mapping (simple + explainable):
      - Start at 95
      - Apply severity penalty based on worst introduced severity
      - If both deps + code introduced exist, apply small extra penalty
      - Small volume penalty (more introduced items -> slightly lower)
    """
    score = 95

    sev_penalty = {
        None: 0,
        "low": 10,
        "medium": 25,
        "high": 45,
        "critical": 70,
    }.get((worst or "").lower(), 15)

    score -= sev_penalty

    # both sources introduced → extra risk surface
    if dep_advisories > 0 and code_findings > 0:
        score -= 10

    # light volume penalty (keeps score stable but nudges down as volume increases)
    score -= min(dep_clusters, 5) * 2          # up to -10
    score -= min(code_findings, 5) * 2         # up to -10

    # clamp
    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return score


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
      - Introduced Semgrep findings can block.
      - threshold applies consistently across sources.
      - RDI score derived from introduced worst severity (0-100, higher=safer).
    """
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

    # -------------------------
    # Unified introduced view
    # -------------------------
    introduced_overall_worst = _worst_of(dep_worst, semgrep_worst)

    dep_clusters_ct = len(introduced_clusters)
    dep_advisories_ct = len(introduced_dep_findings)
    code_ct = len(introduced_semgrep_findings)

    introduced_sources: list[str] = []
    if dep_advisories_ct > 0:
        introduced_sources.append("deps")
    if code_ct > 0:
        introduced_sources.append("code")

    score = _rdi_score_from_introduced(
        worst=introduced_overall_worst,
        dep_clusters=dep_clusters_ct,
        dep_advisories=dep_advisories_ct,
        code_findings=code_ct,
    )

    # Notes: keep tight (1 narrative + 1 decision line)
    notes: list[str] = []
    notes.append(
        f"Introduced risk: deps={dep_clusters_ct} clusters/{dep_advisories_ct} advisories, code={code_ct} findings. "
        f"Worst={(introduced_overall_worst or 'none').upper()} (sources: {', '.join(introduced_sources) if introduced_sources else 'none'})."
    )

    # If nothing introduced anywhere -> GO
    if dep_advisories_ct == 0 and code_ct == 0:
        return "go", score, notes + ["No introduced risk detected."]

    # Determine if either source meets/exceeds threshold
    dep_meets = dep_worst is not None and _rank(dep_worst) <= thr_rank
    semgrep_meets = semgrep_worst is not None and _rank(semgrep_worst) <= thr_rank

    # If not enforce -> conditional when anything introduced exists
    if mode != "enforce":
        return "conditional", score, notes + ["Reporting only (mode is not enforce)."]

    # Enforce mode: block if introduced meets/exceeds threshold
    if dep_meets or semgrep_meets:
        return (
            ("conditional" if allow_conditional_bool else "no-go"),
            score,
            notes + [f"Introduced risk meets/exceeds threshold ({threshold.upper()})."],
        )

    return "go", score, notes + ["Introduced risk is below threshold."]
