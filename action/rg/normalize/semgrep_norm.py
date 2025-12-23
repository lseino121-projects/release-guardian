from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from rg.normalize.schema import Finding


def _first_line(s: str, max_len: int = 140) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    s = s.splitlines()[0].strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _semgrep_hint(result: Dict[str, Any]) -> str:
    """
    v1 hint extraction priority:
      1) extra.metadata.rg_hint (your custom field)
      2) extra.message
      3) extra.metadata.fix / extra.fix (if present)
    """
    extra = (result.get("extra") or {}) if isinstance(result.get("extra"), dict) else {}
    meta = (extra.get("metadata") or {}) if isinstance(extra.get("metadata"), dict) else {}

    # Your custom per-rule hint (preferred)
    rg_hint = meta.get("rg_hint") or meta.get("release_guardian_hint")
    if rg_hint:
        return _first_line(str(rg_hint))

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

        check_id = str(r.get("check_id") or "")
        sev = ""
        extra = r.get("extra") or {}
        if isinstance(extra, dict):
            sev = str(extra.get("severity") or "").lower()

        # path + line mapping (your convention)
        file_path = str(r.get("path") or "")
        start = r.get("start") or {}
        line = ""
        if isinstance(start, dict):
            line = str(start.get("line") or "")

        hint = _semgrep_hint(r)

        out.append(
            Finding(
                tool="semgrep",
                severity=sev or "medium",
                id=check_id,
                package=file_path,           # you map this as file path
                installed_version=line,      # you map this as line
                fixed_version="",
                hint=hint or None,           # NEW
            )
        )

    return out
