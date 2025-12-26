from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

# Optional dependency: never crash the action if missing.
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


def _rule_files(rules_dir: Path) -> Iterable[Path]:
    if not rules_dir.exists():
        return []
    return [
        p
        for p in rules_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
    ]


def _rules_from_data(data: object) -> List[Mapping[str, object]]:
    if not data:
        return []
    if isinstance(data, dict):
        if "rules" in data and isinstance(data.get("rules"), list):
            return [r for r in data["rules"] if isinstance(r, dict)]
        return [data]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _hint_from_rule(rule: Mapping[str, object]) -> str:
    # Prefer: metadata.rg.hint
    meta = rule.get("metadata")
    if isinstance(meta, dict):
        rg = meta.get("rg")
        if isinstance(rg, dict):
            hint = rg.get("hint")
            if isinstance(hint, str) and hint.strip():
                return hint.strip()

    # Fallback: message
    msg = rule.get("message")
    if isinstance(msg, str) and msg.strip():
        return msg.strip()

    return ""


def _find_repo_root(start: Path) -> Optional[Path]:
    """
    Walk upward looking for a directory that contains 'action/rg/rules'.
    """
    cur = start.resolve()
    for _ in range(12):
        candidate = cur / "action" / "rg" / "rules"
        if candidate.exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _rules_dir() -> Path:
    # GitHub Actions / container runtime
    ws = os.environ.get("GITHUB_WORKSPACE")
    if ws:
        p = Path(ws) / "action" / "rg" / "rules"
        if p.exists():
            return p

    # Local dev: infer repo root from this file’s location
    root = _find_repo_root(Path(__file__).parent)
    if root:
        return root / "action" / "rg" / "rules"

    # Fallback: relative
    return Path("action") / "rg" / "rules"


@lru_cache(maxsize=1)
def _hint_map() -> Dict[str, str]:
    # If PyYAML isn't installed, don't crash the action.
    if yaml is None:
        return {}

    rules_dir = _rules_dir()
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

            hint = _hint_from_rule(rule)
            if hint:
                hints[rule_id.strip().lower()] = hint

    return hints


def hint_for_id(finding_id: str | None) -> str:
    fid = (finding_id or "").strip().lower()
    if not fid:
        return ""
    return _hint_map().get(fid, "")
