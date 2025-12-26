from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional

from rg.scanners.common import run_cmd


DEFAULT_EXCLUDES = [
    ".git",
    ".rg",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    "examples/unsafe",  # test fixtures (intentionally insecure)
]


def run_semgrep(
    workspace: str,
    out_dir: str,
    timeout: int = 900,
    config: str = "action/rg/rules",
    excludes: Optional[Iterable[str]] = None,
) -> Path:
    """
    Run Semgrep on the repo and emit JSON output.

    Notes:
    - We exclude intentionally-unsafe fixtures and common noise dirs by default.
    - We consider the scan "successful enough" if semgrep.json was produced.
      (Semgrep sometimes exits non-zero while still writing JSON for findings.)
    """
    out_path = Path(out_dir) / "semgrep.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Validate local config path when a repo-local path is expected.
    cfg_path = Path(workspace) / config
    looks_like_local = "/" in config or config.startswith(".")
    if looks_like_local and not cfg_path.exists():
        raise RuntimeError(
            f"semgrep config path not found: {cfg_path}. "
            f"workspace={workspace}. Did you mean 'action/rg/rules'?"
        )

    # Merge excludes (caller overrides/adds to defaults)
    exclude_list: List[str] = list(DEFAULT_EXCLUDES)
    if excludes:
        for e in excludes:
            e = str(e).strip()
            if e and e not in exclude_list:
                exclude_list.append(e)

    cmd: List[str] = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--output",
        str(out_path),
        "--quiet",
    ]

    # Add exclude flags
    for e in exclude_list:
        cmd.extend(["--exclude", e])

    code, stdout, stderr = run_cmd(cmd, timeout=timeout, cwd=workspace)

    # We require the JSON artifact as the source of truth.
    if not out_path.exists():
        raise RuntimeError(
            f"semgrep failed (exit={code}). stderr:\n{(stderr or '').strip()[:4000]}"
        )

    # Optional: if you want to treat exit!=0 as warning, keep it silent here.
    # If you want to surface it later, log it in main.py notes instead.
    return out_path
