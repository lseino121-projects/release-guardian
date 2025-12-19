from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class RDIReport:
    verdict: str               # go|conditional|no-go
    rdi_score: int             # 0..100
    summary: str
    context: dict[str, Any]
    notes: list[str]
    top_findings: list[dict[str, Any]]  # v1: store a small sample

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
