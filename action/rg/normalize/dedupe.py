from __future__ import annotations

from collections import defaultdict
from typing import Iterable, List

from rg.normalize.schema import Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev_rank(sev: str | None) -> int:
    return _SEV_ORDER.get((sev or "").lower(), 99)

def unified_summary_for_clusters(findings: List[Finding], clusters: list[tuple[str, str]]) -> dict:
    """
    Like unified_summary(), but only for the provided (pkg, ver) clusters.
    """
    wanted = set((p or "", v or "") for (p, v) in clusters)
    filtered = [f for f in findings if (f.package or "", f.installed_version or "") in wanted]
    return unified_summary(filtered)

def cluster_findings(findings: Iterable[Finding]) -> dict[tuple[str, str], list[Finding]]:
    """
    Cluster findings by (package, installed_version).
    This is the most stable cross-tool join for v1.
    """
    clusters: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        pkg = (f.package or "").strip()
        ver = (f.installed_version or "").strip()
        if not pkg:
            continue
        clusters[(pkg, ver)].append(f)
    return clusters


def unified_summary(findings: List[Finding]) -> dict:
    """
    Returns:
      - clusters_count: number of pkg@ver clusters
      - advisories_count: total findings (all tools)
      - worst_severity: worst severity across clusters
      - unified_top: top clusters for reporting
    """
    clusters = cluster_findings(findings)

    unified_top: list[dict] = []
    worst_rank = 99
    worst_sev: str | None = None

    for (pkg, ver), items in clusters.items():
        rep = sorted(items, key=lambda x: _sev_rank(x.severity))[0]

        rep_rank = _sev_rank(rep.severity)
        if rep_rank < worst_rank:
            worst_rank = rep_rank
            worst_sev = rep.severity

        unified_top.append(
            {
                "package": pkg,
                "installed_version": ver,
                "worst_severity": rep.severity or "unknown",
                "advisories": sorted({i.id for i in items}),
                "tools": sorted({i.tool for i in items}),
            }
        )

    unified_top = sorted(unified_top, key=lambda x: _sev_rank(x.get("worst_severity")))[:10]

    return {
        "clusters_count": len(clusters),
        "advisories_count": len(findings),
        "worst_severity": (worst_sev or "unknown"),
        "unified_top": unified_top,
    }
