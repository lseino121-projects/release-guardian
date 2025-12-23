from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# -------------------------
# Exact-match hints (best)
# -------------------------
HINTS: Dict[str, str] = {
    # --- Semgrep rules ---
    "action.rg.rules.javascript.rg.js.child-process-exec":
        "Avoid exec/shell. Use spawn/execFile with args array; never pass user input to a shell.",
    "action.rg.rules.python.rg.python.subprocess-popen-shell-true":
        "Avoid shell=True. Use subprocess.run([...], shell=False) and validate inputs.",

    # --- Optional: advisory IDs (CVE/GHSA) ---
    # "cve-2021-44906": "Upgrade minimist to a fixed version (see Fix column).",
}

# -------------------------
# Pattern fallback (stable)
# -------------------------
# (needle, hint)
PATTERN_HINTS: Tuple[Tuple[str, str], ...] = (
    ("child-process-exec", "Avoid exec/shell. Use spawn/execFile with args array; never pass user input to a shell."),
    ("subprocess-popen-shell-true", "Avoid shell=True. Use subprocess.run([...], shell=False) and validate inputs."),
    # Terraform / Docker examples (only keep if you actually have these rules)
    ("0.0.0.0/0", "Restrict ingress. Avoid 0.0.0.0/0 on sensitive ports."),
    ("latest-tag", "Pin image tags/digests for reproducible builds and safer rollbacks."),
)

# -------------------------
# Advisory prefixes → generic hint
# -------------------------
ADVISORY_PREFIXES = ("cve-", "ghsa-")


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _is_advisory_id(fid: str) -> bool:
    fid = _norm(fid)
    return fid.startswith(ADVISORY_PREFIXES)


def _join_versions(versions: Sequence[str], limit: int = 2) -> str:
    vs = [v.strip() for v in versions if v and v.strip()]
    if not vs:
        return ""
    head = vs[:limit]
    more = "" if len(vs) <= limit else f" (+{len(vs) - limit} more)"
    return f"{', '.join(head)}{more}"


# -------------------------------------------------------------------
# Backward-compatible API (what you already call everywhere)
# -------------------------------------------------------------------
def hint_for_id(finding_id: str | None) -> str:
    """
    Returns a 1-line remediation hint for:
      - Semgrep rule IDs
      - Advisory IDs (CVE/GHSA)

    Backward compatible: callers only pass finding_id.
    """
    fid = _norm(finding_id)
    if not fid:
        return ""

    # 1) Exact match
    hit = HINTS.get(fid)
    if hit:
        return hit

    # 2) Pattern fallback
    for needle, hint in PATTERN_HINTS:
        if needle in fid:
            return hint

    # 3) Generic advisory fallback
    if _is_advisory_id(fid):
        return "Upgrade the affected dependency to a fixed version (see Fix column)."

    return ""


# -------------------------------------------------------------------
# Next-level API (optional): use context when available
# -------------------------------------------------------------------
@dataclass(frozen=True)
class HintContext:
    finding_id: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_versions: Optional[Sequence[str]] = None
    tool: Optional[str] = None  # e.g. "trivy", "grype", "semgrep"
    rule_id: Optional[str] = None  # alias of finding_id for semgrep


def hint_for(ctx: HintContext) -> str:
    """
    Next-level hinting that uses extra context when you have it.

    Use this if you want richer dependency hints like:
      "Upgrade minimist to 1.2.8 (+2 more)."
    """
    fid = _norm(ctx.rule_id or ctx.finding_id or "")
    pkg = (ctx.package or "").strip()
    fixed_versions = list(ctx.fixed_versions or [])

    # 1) Reuse the existing logic first (exact + pattern)
    base = hint_for_id(fid)
    if base:
        return base

    # 2) Dependency-aware generic hint (CVE/GHSA, or when fix versions exist)
    if fixed_versions or _is_advisory_id(fid):
        vtxt = _join_versions(fixed_versions, limit=2)
        if pkg and vtxt:
            return f"Upgrade {pkg} to {vtxt}."
        if pkg:
            return f"Upgrade {pkg} to a fixed version (see Fix column)."
        if vtxt:
            return f"Upgrade the dependency to {vtxt}."
        return "Upgrade the affected dependency to a fixed version (see Fix column)."

    # 3) No hint found
    return ""
