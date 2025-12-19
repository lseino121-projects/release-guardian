from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .schema import Finding


def normalize_trivy(trivy_json_path: str) -> List[Finding]:
    data = json.loads(Path(trivy_json_path).read_text())
    findings: list[Finding] = []

    results = data.get("Results") or []
    for r in results:
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            vuln_id = v.get("VulnerabilityID") or "UNKNOWN"
            severity = (v.get("Severity") or "UNKNOWN").lower()
            pkg = v.get("PkgName")
            installed = v.get("InstalledVersion")
            fixed = v.get("FixedVersion")
            title = v.get("Title") or v.get("Description")

            findings.append(
                Finding(
                    tool="trivy",
                    type="vuln",
                    id=vuln_id,
                    severity=severity,
                    package=pkg,
                    installed_version=installed,
                    fixed_version=fixed,
                    title=title,
                )
            )
    return findings
