from __future__ import annotations

from pathlib import Path

from .common import run_cmd, ensure_dir


def run_trivy_fs(workspace: str, out_dir: str, timeout: int = 600) -> Path:
    """
    Trivy filesystem scan for vulnerabilities only (v1). JSON output.
    """
    ensure_dir(out_dir)
    out_path = Path(out_dir) / "trivy.json"

    cmd = [
        "trivy",
        "fs",
        "--scanners", "vuln",
        "--format", "json",
        "--output", str(out_path),
        "--quiet",
        workspace,
    ]

    code, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if code != 0:
        raise RuntimeError(f"Trivy fs failed (exit {code}). stderr:\n{stderr.strip()}")
    return out_path
