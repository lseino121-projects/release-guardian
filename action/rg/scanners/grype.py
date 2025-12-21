from __future__ import annotations

from pathlib import Path

from .common import run_cmd, ensure_dir


def run_grype_from_sbom(sbom_path: str, out_dir: str, timeout: int = 600) -> Path:
    ensure_dir(out_dir)
    out_path = Path(out_dir) / "grype.json"

    cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
    code, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if code != 0:
        raise RuntimeError(f"Grype failed (exit {code}). stderr:\n{stderr.strip()}")

    out_path.write_text(stdout)
    return out_path
