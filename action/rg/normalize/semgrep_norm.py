from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from rg.normalize.schema import Finding


def _first_line(s: str, max_len: int = 140) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    s = s.splitlines()[0].strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _norm_semgrep_id(check_id: str) -> str:
    """
    Semgrep sometimes prefixes IDs when loading configs from directories, e.g.
      action.rg.rules.python.<rule-id>
    or even duplicates like:
      action.rg.rules.python.action.rg.rules.python.rg.python.foo

    For Release Guardian, we want the canonical rule id (the last occurrence),
    so it matches hints and stays stable.
    """
    cid = (check_id or "").strip()
    if not cid:
        return ""

    marker = "action.rg.rules."
    if cid.count(marker) >= 2:
        # keep from the *last* occurrence
        return cid[cid.rfind(marker) :]

    # If it looks like "<prefix>.<canonical>", try to strip prefix when the canonical already contains marker
    if marker in cid:
        # If there's exactly one marker but it isn't at the start, trim everything before it.
        idx = cid.find(marker)
        if idx > 0:
            return cid[idx:]

    return cid


def _map_semgrep_severity(extra_sev: str) -> str:
    """
    Map Semgrep severities to RG severities.
    Semgrep typically: ERROR/WARNING/INFO (sometimes "CRITICAL"/"HIGH" depending on sources).
    """
    s = (extra_sev or "").strip().lower()

    # semgrep standard
    if s == "error":
        return "high"
    if s == "warning":
        return "medium"
    if s == "info":
        return "low"

    # if someone uses custom strings
    if s in {"critical", "high", "medium", "low"}:
        return s

    return "medium"


def _semgrep_hint(result: Dict[str, Any]) -> str:
    """
    v1 hint extraction priority:
      1) extra.metadata.rg.hint          (your rule metadata)
      2) extra.message                   (Semgrep message)
      3) extra.metadata.fix / extra.fix  (if present)
    """
    extra = result.get("extra")
    extra = extra if isinstance(extra, dict) else {}

    meta = extra.get("metadata")
    meta = meta if isinstance(meta, dict) else {}

    # ✅ New: metadata.rg.hint
    rg = meta.get("rg")
    rg = rg if isinstance(rg, dict) else {}
    rg_hint = rg.get("hint")
    if rg_hint:
        return _first_line(str(rg_hint))

    # (legacy fallbacks if you ever used them)
    legacy = meta.get("rg_hint") or meta.get("release_guardian_hint")
    if legacy:
        return _first_line(str(legacy))

    # Semgrep message (good default)
    msg = extra.get("message")
    if msg:
        return _first_line(str(msg))

    # Optional fix hint
    fix = meta.get("fix") or extra.get("fix")
    if fix:
        return _first_line(str(fix))

    return ""


def normalize_semgrep(path: str) -> List[Finding]:
    data = json.loads(Path(path).read_text())
    results = data.get("results") or []
    out: List[Finding] = []

    for r in results:
        if not isinstance(r, dict):
            continue

        raw_id = str(r.get("check_id") or "")
        check_id = _norm_semgrep_id(raw_id)

        extra = r.get("extra")
        extra = extra if isinstance(extra, dict) else {}

        sev_raw = str(extra.get("severity") or "")
        sev = _map_semgrep_severity(sev_raw)

        # path + line mapping (your convention)
        file_path = str(r.get("path") or "")
        start = r.get("start") or {}
        line = str(start.get("line") or "") if isinstance(start, dict) else ""

        hint = _semgrep_hint(r)

        out.append(
            Finding(
                tool="semgrep",
                severity=sev,
                id=check_id,
                package=file_path,       # file path
                installed_version=line,  # line number
                fixed_version="",
                hint=hint or None,
            )
        )

    return out
