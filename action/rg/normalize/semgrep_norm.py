from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from rg.normalize.schema import Finding


def _map_severity(raw: Optional[str]) -> str:
    """
    Semgrep severity varies by ruleset:
    - Often: ERROR/WARNING/INFO
    - Sometimes: critical/high/medium/low
    Normalize into: critical|high|medium|low
    """
    s = (raw or "").strip().lower()
    if s in {"critical", "high", "medium", "low"}:
        return s
    if s in {"error"}:
        return "high"
    if s in {"warning", "warn"}:
        return "medium"
    if s in {"info"}:
        return "low"
    return "low"


def normalize_semgrep(json_path: str) -> List[Finding]:
    p = Path(json_path)
    data = json.loads(p.read_text())

    findings: List[Finding] = []

    for r in data.get("results", []) or []:
        check_id = r.get("check_id") or "semgrep.rule"
        path = r.get("path") or ""
        start = (r.get("start") or {}) if isinstance(r.get("start"), dict) else {}
        line = start.get("line")

        extra = r.get("extra") or {}
        sev = _map_severity(extra.get("severity"))

        # message can be long; keep it short
        msg = (extra.get("message") or "").strip()
        if len(msg) > 160:
            msg = msg[:157] + "..."

        # We’ll reuse Finding fields:
        # - id: semgrep rule id
        # - package: file path
        # - installed_version: line (string)
        # - fixed_version: empty
        findings.append(
            Finding(
                tool="semgrep",
                id=str(check_id),
                severity=sev,
                package=str(path),
                installed_version=str(line) if line is not None else "",
                fixed_version="",
            )
        )

    return findings
