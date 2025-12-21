from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from rg.normalize.schema import Finding


def _map_severity(raw: Optional[str]) -> str:
    s = (raw or "").strip().lower()
    if s in {"critical", "high", "medium", "low"}:
        return s
    if s == "error":
        return "high"
    if s in {"warning", "warn"}:
        return "medium"
    if s == "info":
        return "low"
    return "low"


def normalize_semgrep(json_path: str) -> List[Finding]:
    p = Path(json_path)
    data = json.loads(p.read_text())

    out: List[Finding] = []
    for r in data.get("results", []) or []:
        rule_id = str(r.get("check_id") or "semgrep.rule")

        path = r.get("path") or ""
        start = r.get("start") or {}
        line = None
        if isinstance(start, dict):
            line = start.get("line")

        extra = r.get("extra") or {}
        sev = _map_severity(extra.get("severity"))

        msg = (extra.get("message") or "").strip()
        if len(msg) > 180:
            msg = msg[:177] + "..."

        out.append(
            Finding(
                tool="semgrep",
                type="vuln",
                id=rule_id,
                severity=sev,
                package=path or None,                          # file path
                installed_version=str(line) if line else None, # line number
                fixed_version=None,
                title=msg or None,
            )
        )

    return out
