from __future__ import annotations

from pathlib import Path

from .common import run_cmd, ensure_dir


def run_syft_sbom(workspace: str, out_dir: str, timeout: int = 600) -> Path:
    ensure_dir(out_dir)
    out_path = Path(out_dir) / "syft.json"

    cmd = ["syft", f"dir:{workspace}", "-o", "json"]
    code, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if code != 0:
        raise RuntimeError(f"Syft failed (exit {code}). stderr:\n{stderr.strip()}")

    out_path.write_text(stdout)
    return out_path
