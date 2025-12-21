from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set

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


def _run_semgrep(target_dir: str, out_path: str, config: str, timeout: int) -> bool:
    cmd = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--output",
        out_path,
        "--quiet",
    ]
    try:
        subprocess.run(
            cmd,
            cwd=target_dir,
            timeout=timeout,
            text=True,
            capture_output=True,
        )
        return Path(out_path).exists()
    except Exception:
        return False


def _fp(f: Finding) -> str:
    # v1 fingerprint: rule + file + line
    return f"{f.id}|{f.package or ''}|{f.installed_version or ''}"


def introduced_semgrep_from_pr(
    base_ref: str,
    head_ref: str,
    repo_dir: str = "/github/workspace",
    config: str = "p/security-audit",
    timeout: int = 900,
) -> SemgrepBaselineResult:
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

        ok_base = _run_semgrep(str(base_dir), base_json, config=config, timeout=timeout)
        ok_head = _run_semgrep(repo_dir, head_json, config=config, timeout=timeout)

        if not ok_base or not ok_head:
            return SemgrepBaselineResult(SCAN_FAILED, [], [], 0, 0)

        base_findings = normalize_semgrep(base_json)
        head_findings = normalize_semgrep(head_json)

        base_fps: Set[str] = {_fp(f) for f in base_findings}
        introduced = [f for f in head_findings if _fp(f) not in base_fps]
        preexisting = [f for f in head_findings if _fp(f) in base_fps]

        return SemgrepBaselineResult(OK, introduced, preexisting, len(base_findings), len(head_findings))
