from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Finding:
    tool: str
    type: str                 # "vuln" for v1
    id: str                   # CVE or advisory ID
    severity: str             # low|medium|high|critical
    package: Optional[str]
    installed_version: Optional[str]
    fixed_version: Optional[str]
    title: Optional[str]
