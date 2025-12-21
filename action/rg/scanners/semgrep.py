from __future__ import annotations

import subprocess
from pathlib import Path

from rg.scanners.common import run_cmd


def run_semgrep(
    workspace: str,
    out_dir: str,
    timeout: int = 900,
    config: str = "action/rg/rules",
) -> Path:
    """
    Run Semgrep on the repo and emit JSON output.
    v1: reporting-only (not gating yet).
    """
    out_path = Path(out_dir) / "semgrep.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Fail fast if someone passes a local path that doesn't exist
    cfg_path = Path(workspace) / config
    if ("/" in config or config.startswith(".")) and not cfg_path.exists():
        raise RuntimeError(
            f"semgrep config path not found: {cfg_path}. "
            f"workspace={workspace}. Did you mean 'action/rg/rules'?"
        )

    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--include",
        "*.py",
        "--json",
        "--output",
        str(out_path),
        "--quiet",
    ]

    code, stdout, stderr = run_cmd(cmd, timeout=timeout, cwd=workspace)

    if not out_path.exists():
        raise RuntimeError(
            f"semgrep failed (exit={code}). stderr={stderr.strip()[:2000]}"
        )

    return out_path
