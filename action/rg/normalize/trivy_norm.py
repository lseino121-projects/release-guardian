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

        # Grype fix versions commonly live here:
        # vulnerability.fix.versions = ["1.2.3", ...]
        fix_obj = vuln.get("fix") or {}
        fix_versions = []
        if isinstance(fix_obj, dict):
            fix_versions = fix_obj.get("versions") or []
        if not isinstance(fix_versions, list):
            fix_versions = []

        fixed_version = ", ".join([str(v).strip() for v in fix_versions if str(v).strip()]) or None

        findings.append(
            Finding(
                tool="grype",
                type="vuln",
                id=vuln_id,
                severity=severity,
                package=pkg,
                installed_version=installed,
                fixed_version=fixed_version,
                title=vuln.get("description") or "",
            )
        )
    return findings
