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

    notes: list[str] = []

    # -------------------------
    # Introduced deps (existing)
    # -------------------------
    introduced_set = set(introduced_clusters)
    introduced_dep_findings = [
        f for f in findings if (f.package, f.installed_version) in introduced_set
    ]
    dep_worst = _worst_severity(introduced_dep_findings)

    notes.append(f"Introduced clusters: {len(introduced_clusters)}")
    notes.append(f"Introduced advisories: {len(introduced_dep_findings)}")

    # -------------------------
    # Introduced Semgrep (new)
    # -------------------------
    introduced_semgrep_findings = introduced_semgrep_findings or []
    semgrep_worst = _worst_severity(introduced_semgrep_findings)

    notes.append(f"Introduced Semgrep findings: {len(introduced_semgrep_findings)}")

    # If nothing introduced anywhere -> GO
    if not introduced_dep_findings and not introduced_semgrep_findings:
        return "go", score, notes + ["No introduced vulnerabilities or code findings detected."]

    # Determine if either source meets/exceeds threshold
    dep_meets = dep_worst is not None and _rank(dep_worst) <= thr_rank
    semgrep_meets = semgrep_worst is not None and _rank(semgrep_worst) <= thr_rank

    if dep_worst:
        notes.append(f"Worst introduced dependency severity: {dep_worst.upper()}")
    if semgrep_worst:
        notes.append(f"Worst introduced Semgrep severity: {semgrep_worst.upper()}")

    # If not enforce -> always conditional when anything introduced exists
    if mode != "enforce":
        return "conditional", score, notes + ["Mode is not enforce; reporting only."]

    # Enforce mode: block if introduced meets/exceeds threshold
    if dep_meets or semgrep_meets:
        reason_bits = []
        if dep_meets:
            reason_bits.append("dependencies")
        if semgrep_meets:
            reason_bits.append("code")
        reason = " & ".join(reason_bits)

        msg = f"Introduced {reason} findings meet/exceed threshold ({threshold.upper()})."
        if allow_conditional_bool:
            return "conditional", score, notes + [msg]
        return "no-go", score, notes + [msg]

    return "go", score, notes + ["Introduced findings are below threshold."]
