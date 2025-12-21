from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


OK = "OK"
REF_UNAVAILABLE = "REF_UNAVAILABLE"
SCAN_FAILED = "SCAN_FAILED"


@dataclass(frozen=True)
class SBOMBaselineResult:
    status: str
    changed: Dict[str, Tuple[Optional[str], Optional[str]]]  # name -> (base_ver, head_ver)
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


def _run_syft(target_dir: str, out_path: str, timeout: int) -> bool:
    # Use a local dir scan; do NOT use "dir:/github/workspace" inside the archived base tree.
    cmd = ["syft", "dir:.", "-o", "json"]
    try:
        p = subprocess.run(
            cmd,
            cwd=target_dir,
            timeout=timeout,
            text=True,
            capture_output=True,
        )
        if p.returncode != 0:
            return False
        Path(out_path).write_text(p.stdout)
        return True
    except Exception:
        return False


def _extract_syft_packages(sbom_json_text: str) -> Dict[str, str]:
    """
    Syft JSON has `artifacts`: [{name, version, purl, ...}, ...]
    We key primarily by purl when present (most stable), else by name.
    Returned mapping: key -> version
    """
    data = json.loads(sbom_json_text)
    artifacts = data.get("artifacts") or []
    out: Dict[str, str] = {}
    if not isinstance(artifacts, list):
        return out

    for a in artifacts:
        if not isinstance(a, dict):
            continue
        name = a.get("name")
        ver = a.get("version")
        purl = a.get("purl")
        if not isinstance(ver, str) or not ver.strip():
            continue

        key = None
        if isinstance(purl, str) and purl.strip():
            key = purl.strip()
        elif isinstance(name, str) and name.strip():
            key = name.strip()

        if key:
            out[key] = ver.strip()

    return out


def introduced_packages_from_sbom_pr(
    base_ref: str,
    head_ref: str,
    repo_dir: str = "/github/workspace",
    timeout: int = 600,
) -> SBOMBaselineResult:
    """
    Universal "introduced packages" diff based on Syft SBOMs.
    Returns: mapping of changed/added/removed packages: key -> (base_ver, head_ver)
    """
    if not base_ref or not head_ref:
        return SBOMBaselineResult(REF_UNAVAILABLE, {}, 0, 0)

    _git_safe(repo_dir)

    with tempfile.TemporaryDirectory(prefix="rg-sbom-") as tmp:
        base_dir = Path(tmp) / "base"
        base_dir.mkdir(parents=True, exist_ok=True)

        if not _git_archive_to_dir(repo_dir, base_ref, str(base_dir)):
            return SBOMBaselineResult(REF_UNAVAILABLE, {}, 0, 0)

        base_json_path = str(Path(tmp) / "syft_base.json")
        head_json_path = str(Path(tmp) / "syft_head.json")

        ok_base = _run_syft(str(base_dir), base_json_path, timeout=timeout)
        ok_head = _run_syft(repo_dir, head_json_path, timeout=timeout)

        if not ok_base or not ok_head:
            return SBOMBaselineResult(SCAN_FAILED, {}, 0, 0)

        base_txt = Path(base_json_path).read_text()
        head_txt = Path(head_json_path).read_text()

        base_pkgs = _extract_syft_packages(base_txt)
        head_pkgs = _extract_syft_packages(head_txt)

        changed: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
        keys = set(base_pkgs.keys()) | set(head_pkgs.keys())
        for k in keys:
            bv = base_pkgs.get(k)
            hv = head_pkgs.get(k)
            if bv != hv:
                changed[k] = (bv, hv)

        return SBOMBaselineResult(OK, changed, len(base_pkgs), len(head_pkgs))
