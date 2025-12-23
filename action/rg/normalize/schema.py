from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


def _first_line(s: str, max_len: int = 120) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    s = s.splitlines()[0].strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


@dataclass
class Finding:
    tool: str
    severity: str
    id: str
    package: str
    installed_version: str
    fixed_version: str = ""
    hint: Optional[str] = None

    # Backward-compatible fields (optional)
    type: str = ""   # "dep" or "code"
    title: str = ""  # short human-friendly summary

    def __post_init__(self) -> None:
        # Normalize severity
        self.severity = (self.severity or "").lower() or "medium"

        # Infer type if missing
        if not self.type:
            self.type = "code" if (self.tool or "").lower() == "semgrep" else "dep"

        # Infer title if missing
        if not self.title:
            if self.type == "code":
                self.title = (self.hint or self.id or "Code finding").strip()
            else:
                base = (self.id or "").strip()
                pkg = (self.package or "").strip()
                if base and pkg:
                    self.title = f"{base} in {pkg}"
                else:
                    self.title = base or pkg or "Dependency finding"

        # Keep titles tidy for PR comments
        self.title = _first_line(self.title)
