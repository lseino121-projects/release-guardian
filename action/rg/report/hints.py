from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

def _rule_files(rules_dir: Path) -> Iterable[Path]:
    if not rules_dir.exists():
        return []
    return [
        p for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
    ]


def _rules_from_data(data: object) -> List[Mapping[str, object]]:
    if not data:
        return []
    if isinstance(data, dict):
        if "rules" in data and isinstance(data["rules"], list):
            return [r for r in data["rules"] if isinstance(r, dict)]
        return [data]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _hint_from_rule(rule: Mapping[str, object]) -> str:
    metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
    rg_meta = metadata.get("rg") if isinstance(metadata.get("rg"), dict) else {}
    hint = rg_meta.get("hint") if isinstance(rg_meta.get("hint"), str) else ""
    if not hint:
        msg = rule.get("message")
        hint = msg if isinstance(msg, str) else ""
    return hint


def _find_repo_root(start: Path) -> Optional[Path]:
    """
    Walk upward looking for a directory that contains 'action/rg/rules'.
    """
    cur = start.resolve()
    for _ in range(10):
        candidate = cur / "action" / "rg" / "rules"
        if candidate.exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _rules_dir() -> Path:
    # In GitHub Actions / your action container, this is the most reliable.
    ws = os.environ.get("GITHUB_WORKSPACE")
    if ws:
        p = Path(ws) / "action" / "rg" / "rules"
        if p.exists():
            return p

    # Local dev: infer repo root from this file’s location.
    root = _find_repo_root(Path(__file__).parent)
    if root:
        return root / "action" / "rg" / "rules"

    # Final fallback (won’t find much, but avoids crashing)
    return Path("action/rg/rules")


@lru_cache(maxsize=1)
@lru_cache(maxsize=1)
def _hint_map() -> Dict[str, str]:
    # repo-local Semgrep rules live here:
    rules_dir = Path("/github/workspace") / "action" / "rg" / "rules"
    hints: Dict[str, str] = {}
    for path in _rule_files(rules_dir):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for rule in _rules_from_data(data):
            rule_id = rule.get("id")
            if not isinstance(rule_id, str):
                continue
            hint = _hint_from_rule(rule).strip()
            if hint:
                hints[rule_id.strip().lower()] = hint
    return hints


def hint_for_id(finding_id: str | None) -> str:
    fid = (finding_id or "").strip().lower()
    if not fid:
        return ""
    return _hint_map().get(fid, "")
