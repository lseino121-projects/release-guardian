from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence


def run_cmd(cmd: Sequence[str], cwd: str | None = None, timeout: int = 600) -> tuple[int, str, str]:
    p = subprocess.run(
        list(cmd),
        cwd=cwd,
        timeout=timeout,
        text=True,
        capture_output=True,
    )
    return p.returncode, p.stdout, p.stderr


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
