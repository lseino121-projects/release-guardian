from __future__ import annotations

from pathlib import Path
import json
from rg.scanners.common import run_cmd


def run_semgrep(
    workspace: str,
    out_dir: str,
    timeout: int = 900,
    config: str = "action/rg/rule",
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
        "--include",
        "*.py",
        "--json",
        "--output",
        str(out_path),
        "--quiet",
    ]


    # semgrep returns non-zero for findings in some modes; `--json --output` typically still works.
    code, stdout, stderr = run_cmd(cmd, timeout=timeout, cwd=workspace)
    print(f"[RG] semgrep rules loaded from: {config}")

    # If semgrep completely failed and output wasn't produced, surface the error
    if not out_path.exists():
        raise RuntimeError(
            f"semgrep failed (exit={code}). stderr={stderr.strip()[:2000]}"
        )

    data = json.loads(out_path.read_text())
    errors = data.get("errors") or []
    if errors:
        # keep it short; semgrep can be verbose
        raise RuntimeError(f"semgrep returned {len(errors)} errors; first={str(errors[0])[:500]}")

    return out_path
