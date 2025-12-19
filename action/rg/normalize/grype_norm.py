from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .schema import Finding


def normalize_grype(grype_json_path: str) -> List[Finding]:
    data = json.loads(Path(grype_json_path).read_text())
    findings: list[Finding] = []

    matches = data.get("matches") or []
    for m in matches:
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}

        vuln_id = vuln.get("id") or "UNKNOWN"
        severity = (vuln.get("severity") or "UNKNOWN").lower()
        pkg = artifact.get("name")
        installed = artifact.get("version")

        findings.append(
            Finding(
                tool="grype",
                type="vuln",
                id=vuln_id,
                severity=severity,
                package=pkg,
                installed_version=installed,
                fixed_version=None,
                title=vuln.get("description"),
            )
        )
    return findings
