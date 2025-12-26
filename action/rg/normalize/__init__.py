from __future__ import annotations

# Keep package init lightweight.
# Do NOT import scanner-specific normalizers here, because it causes import-time failures
# when functions are renamed/removed (and dedupe should not depend on them).

from .schema import Finding
from .dedupe import unified_summary, unified_summary_for_clusters

__all__ = [
    "Finding",
    "unified_summary",
    "unified_summary_for_clusters",
]
