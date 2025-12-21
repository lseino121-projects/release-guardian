from __future__ import annotations

from pathlib import Path

from rg.scanners.common import run_cmd


def run_semgrep(
    workspace: str,
    out_dir: str,
    timeout: int = 900,
    config: str = "p/security-audit",
) -> Path:
    """
    Run Semgrep on the repo and emit JSON output.
    v1: reporting-only (not gating yet).
    """
    out_path = Path(out_dir) / "semgrep.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--output",
        str(out_path),
        "--quiet",
    ]

    # semgrep returns non-zero for findings in some modes; `--json --output` typically still works.
    code, stdout, stderr = run_cmd(cmd, timeout=timeout, cwd=workspace)

    # If semgrep completely failed and output wasn't produced, surface the error
    if not out_path.exists():
        raise RuntimeError(
            f"semgrep failed (exit={code}). stderr={stderr.strip()[:2000]}"
        )

    return out_path
