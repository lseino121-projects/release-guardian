from __future__ import annotations

from typing import List, Dict, Tuple, Optional

from rg.normalize.schema import Finding
from rg.normalize.dedupe import cluster_findings


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _rank(sev: str | None) -> int:
    return _SEV_RANK.get((sev or "").lower(), 99)


def classify_clusters(findings: List[Finding], changed_pkgs: Dict[str, Tuple[Optional[str], Optional[str]]]) -> dict:
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
            # If head version matches the vuln cluster version, it is introduced/changed in this PR
            if head_ver == ver:
                introduced.append((pkg, ver))
            else:
                preexisting.append((pkg, ver))
        else:
            preexisting.append((pkg, ver))

    return {
        "introduced": introduced,
        "preexisting": preexisting,
        "unknown": unknown,
    }


def gate_verdict(mode: str, threshold: str, allow_conditional: bool, findings: List[Finding], introduced_clusters: list[tuple[str, str]]) -> tuple[str, int, list[str]]:
    """
    v1 gating:
      - Only introduced clusters can block.
      - Block if any introduced finding severity >= threshold.
    """
    # score is placeholder still; we’ll upgrade later
    score = 18

    allow_conditional_bool = str(allow_conditional).lower() in ("1", "true", "yes", "y")

    # Extract findings for introduced clusters only
    introduced_set = set(introduced_clusters)
    introduced_findings = [f for f in findings if (f.package, f.installed_version) in introduced_set]

    worst = None
    for f in introduced_findings:
        if worst is None or _rank(f.severity) < _rank(worst):
            worst = f.severity

    # threshold rank
    thr_rank = _rank(threshold)

    notes: list[str] = []
    notes.append(f"Introduced clusters: {len(introduced_clusters)}")
    notes.append(f"Introduced advisories: {len(introduced_findings)}")

    if not introduced_findings:
        return "go", score, notes + ["No introduced vulnerabilities detected."]

    if worst is None:
        return "go", score, notes + ["Introduced vulnerabilities present but severity unknown."]

    worst_rank = _rank(worst)
    notes.append(f"Worst introduced severity: {worst.upper()}")

    if mode != "enforce":
        return "conditional", score, notes + ["Mode is not enforce; reporting only."]

    if worst_rank <= thr_rank:
        # at/above threshold
        if allow_conditional_bool:
            return "conditional", score, notes + [f"Introduced vulnerabilities meet/exceed threshold ({threshold.upper()})."]
        return "no-go", score, notes + [f"Introduced vulnerabilities meet/exceed threshold ({threshold.upper()})."]

    return "go", score, notes + ["Introduced vulnerabilities are below threshold."]
