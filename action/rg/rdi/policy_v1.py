from __future__ import annotations

from typing import List, Dict, Tuple, Optional

from rg.normalize.schema import Finding
from rg.normalize.dedupe import cluster_findings


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _rank(sev: str | None) -> int:
    return _SEV_RANK.get((sev or "").lower(), 99)


def _worst_severity(findings: List[Finding]) -> str | None:
    worst: str | None = None
    for f in findings:
        if worst is None or _rank(f.severity) < _rank(worst):
            worst = f.severity
    return worst


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


def gate_verdict(
    mode: str,
    threshold: str,
    allow_conditional: bool,
    findings: List[Finding],
    introduced_clusters: list[tuple[str, str]],
    introduced_semgrep_findings: List[Finding] | None = None,
) -> tuple[str, int, list[str]]:
    """
    v1 gating (introduced-only):
      - Deps/Vulns: introduced clusters can block if severity >= threshold.
      - Semgrep: introduced findings can block if severity >= threshold.
      - Combine both channels into one verdict.
    """
    score = 18  # still placeholder; upgrade later

    allow_conditional_bool = str(allow_conditional).lower() in ("1", "true", "yes", "y")
    introduced_semgrep_findings = introduced_semgrep_findings or []

    # -------------------------
    # 1) Dependency introduced findings
    # -------------------------
    introduced_set = set(introduced_clusters)
    introduced_dep_findings = [
        f for f in findings if (f.package, f.installed_version) in introduced_set
    ]
    worst_dep = _worst_severity(introduced_dep_findings)

    # -------------------------
    # 2) Semgrep introduced findings
    # -------------------------
    worst_sast = _worst_severity(introduced_semgrep_findings)

    thr_rank = _rank(threshold)

    notes: list[str] = []
    notes.append(f"Introduced clusters: {len(introduced_clusters)}")
    notes.append(f"Introduced advisories: {len(introduced_dep_findings)}")
    notes.append(f"Introduced Semgrep: {len(introduced_semgrep_findings)}")

    # If nothing introduced anywhere → GO
    if not introduced_dep_findings and not introduced_semgrep_findings:
        return "go", score, notes + ["No introduced vulnerabilities or SAST findings detected."]

    # Determine whether each channel meets/exceeds the threshold
    dep_hits_threshold = False
    sast_hits_threshold = False

    if worst_dep is not None and _rank(worst_dep) <= thr_rank:
        dep_hits_threshold = True
        notes.append(f"Worst introduced dependency severity: {worst_dep.upper()}")

    if worst_sast is not None and _rank(worst_sast) <= thr_rank:
        sast_hits_threshold = True
        notes.append(f"Worst introduced Semgrep severity: {worst_sast.upper()}")

    # If enforce is off → always conditional when there is any introduced signal
    if mode != "enforce":
        return "conditional", score, notes + ["Mode is not enforce; reporting only."]

    # If either channel meets/exceeds threshold → block/conditional depending on allow_conditional
    if dep_hits_threshold or sast_hits_threshold:
        reasons: list[str] = []
        if dep_hits_threshold:
            reasons.append(f"Deps meet/exceed threshold ({threshold.upper()})")
        if sast_hits_threshold:
            reasons.append(f"Semgrep meets/exceed threshold ({threshold.upper()})")
        msg = " & ".join(reasons) + "."

        if allow_conditional_bool:
            return "conditional", score, notes + [msg]
        return "no-go", score, notes + [msg]

    # Otherwise: introduced signals exist but are below threshold → GO
    return "go", score, notes + ["Introduced findings are below threshold."]
