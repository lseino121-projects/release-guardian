from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set
from rg.normalize.schema import Finding
from rg.normalize.semgrep_norm import normalize_semgrep

OK = "OK"
REF_UNAVAILABLE = "REF_UNAVAILABLE"
SCAN_FAILED = "SCAN_FAILED"


@dataclass(frozen=True)
class SemgrepBaselineResult:
    status: str
    introduced: List[Finding]
    preexisting: List[Finding]
    base_count: int
    head_count: int


def _git_safe(repo_dir: str) -> None:
    try:
        subprocess.check_call(
            ["git", "config", "--global", "--add", "safe.directory", repo_dir],
            cwd=repo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _has_commit(repo_dir: str, ref: str) -> bool:
    try:
        subprocess.check_call(
            ["git", "cat-file", "-e", f"{ref}^{{commit}}"],
            cwd=repo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _fetch_commit(repo_dir: str, ref: str) -> bool:
    tmp_ref = f"refs/rg/{ref}"
    try:
        subprocess.check_call(
            ["git", "fetch", "--no-tags", "--prune", "origin", f"+{ref}:{tmp_ref}"],
            cwd=repo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _ensure_commit(repo_dir: str, ref: str) -> bool:
    return _has_commit(repo_dir, ref) or _fetch_commit(repo_dir, ref)


def _git_archive_to_dir(repo_dir: str, ref: str, out_dir: str) -> bool:
    if not _ensure_commit(repo_dir, ref):
        return False
    try:
        p1 = subprocess.Popen(
            ["git", "archive", ref],
            cwd=repo_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        p2 = subprocess.Popen(
            ["tar", "-x", "-C", out_dir],
            stdin=p1.stdout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert p1.stdout is not None
        p1.stdout.close()
        rc2 = p2.wait()
        rc1 = p1.wait()
        return rc1 == 0 and rc2 == 0
    except Exception:
        return False


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
    "examples/unsafe",
]


def _run_semgrep(
    target_dir: str,
    out_path: str,
    config: str,
    timeout: int,
    excludes: Optional[Iterable[str]] = None,
) -> bool:
    """
    Run semgrep and write JSON results to out_path.

    Success condition (MVP): out_path exists.
    Semgrep can return non-zero even when it writes output (findings, parse issues, etc).
    """
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
        out_path,
        "--quiet",
    ]

    for e in exclude_list:
        cmd.extend(["--exclude", e])

    try:
        p = subprocess.run(
            cmd,
            cwd=target_dir,
            timeout=timeout,
            text=True,
            capture_output=True,
        )

        # Source of truth: did we produce the JSON artifact?
        if Path(out_path).exists():
            return True

        # If no output, surface a helpful debug breadcrumb (caller can decide how to expose)
        # Keep it short to avoid huge logs.
        err = (p.stderr or "").strip()
        raise RuntimeError(f"semgrep produced no JSON (exit={p.returncode}). stderr={err[:2000]}")

    except Exception:
        return False


def _fp(f: Finding) -> str:
    # v1 fingerprint: rule + file + line
    return f"{f.id}|{f.package or ''}|{f.installed_version or ''}"


from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, Set, List

from rg.normalize.semgrep_norm import normalize_semgrep
from rg.rdi.semgrep_types import SemgrepBaselineResult, OK, REF_UNAVAILABLE, SCAN_FAILED  # adjust imports if different
# assumes _git_safe, _git_archive_to_dir, _run_semgrep, _fp already exist in this module


def introduced_semgrep_from_pr(
    base_ref: str,
    head_ref: str,
    repo_dir: str = "/github/workspace",
    config: str = "action/rg/rules",
    timeout: int = 900,
    excludes: Optional[List[str]] = None,
) -> SemgrepBaselineResult:
    """
    Compute introduced vs pre-existing Semgrep findings for a PR by scanning:
      - base snapshot (git archive)
      - head working tree

    Success condition for each scan: JSON artifact exists.
    """
    if not base_ref or not head_ref:
        return SemgrepBaselineResult(REF_UNAVAILABLE, [], [], 0, 0)

    _git_safe(repo_dir)

    with tempfile.TemporaryDirectory(prefix="rg-semgrep-") as tmp:
        base_dir = Path(tmp) / "base"
        base_dir.mkdir(parents=True, exist_ok=True)

        ok = _git_archive_to_dir(repo_dir, base_ref, str(base_dir))
        if not ok:
            return SemgrepBaselineResult(REF_UNAVAILABLE, [], [], 0, 0)

        base_json = str(Path(tmp) / "semgrep_base.json")
        head_json = str(Path(tmp) / "semgrep_head.json")

        ok_base = _run_semgrep(
            target_dir=str(base_dir),
            out_path=base_json,
            config=config,
            timeout=timeout,
            excludes=excludes,
        )
        ok_head = _run_semgrep(
            target_dir=repo_dir,
            out_path=head_json,
            config=config,
            timeout=timeout,
            excludes=excludes,
        )

        if not ok_base or not ok_head:
            return SemgrepBaselineResult(SCAN_FAILED, [], [], 0, 0)

        base_findings = normalize_semgrep(base_json)
        head_findings = normalize_semgrep(head_json)

        base_fps: Set[str] = {_fp(f) for f in base_findings}
        introduced = [f for f in head_findings if _fp(f) not in base_fps]
        preexisting = [f for f in head_findings if _fp(f) in base_fps]

        return SemgrepBaselineResult(
            OK,
            introduced,
            preexisting,
            len(base_findings),
            len(head_findings),
        )
