from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


BaselineStatus = str
# Allowed statuses (stringly-typed for v1 simplicity)
OK: BaselineStatus = "OK"
BASE_MISSING: BaselineStatus = "BASE_MISSING"
HEAD_MISSING: BaselineStatus = "HEAD_MISSING"
REF_UNAVAILABLE: BaselineStatus = "REF_UNAVAILABLE"
PARSE_ERROR: BaselineStatus = "PARSE_ERROR"


@dataclass(frozen=True)
class BaselineResult:
    status: BaselineStatus
    changed: Dict[str, Tuple[Optional[str], Optional[str]]]  # pkg -> (base_ver, head_ver)


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
    """
    Fetch commit object by SHA from origin into a temporary ref, so `git show <sha>:path` works.
    """
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


def _git_show(repo_dir: str, ref: str, path: str) -> Optional[str]:
    """
    Return file contents at git ref, or None if file doesn't exist or ref can't be loaded.
    """
    if not _has_commit(repo_dir, ref):
        if not _fetch_commit(repo_dir, ref):
            return None

    try:
        return subprocess.check_output(
            ["git", "show", f"{ref}:{path}"],
            cwd=repo_dir,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return None


def _load_lock_json(text: str) -> dict:
    return json.loads(text)


def _extract_packages(lock: dict) -> Dict[str, str]:
    """
    Returns {package_name: version} for direct + transitive.
    Supports lockfile v2/v3 "packages" field.
    """
    pkgs: dict[str, str] = {}

    packages = lock.get("packages")
    if isinstance(packages, dict):
        for k, meta in packages.items():
            if k == "" or not isinstance(meta, dict):
                continue
            if not k.startswith("node_modules/"):
                continue
            name = k[len("node_modules/") :]
            ver = meta.get("version")
            if name and isinstance(ver, str):
                pkgs[name] = ver
        return pkgs

    deps = lock.get("dependencies")
    if isinstance(deps, dict):

        def walk(d: dict):
            for name, meta in d.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str):
                    pkgs[name] = ver
                sub = meta.get("dependencies")
                if isinstance(sub, dict):
                    walk(sub)

        walk(deps)

    return pkgs


def introduced_packages_from_pr(
    base_ref: str,
    head_ref: str,
    lock_path: str = "package-lock.json",
    repo_dir: str = "/github/workspace",
) -> BaselineResult:
    """
    Computes dependency changes for Node by diffing lockfiles.

    General baseline rules (future-proof):
      - OK: base & head exist -> diff
      - BASE_MISSING: head exists, base missing -> treat all head pkgs as introduced
      - HEAD_MISSING: base exists, head missing -> treat all pkgs as removed (not introduced) -> changed empty is fine for v1
      - REF_UNAVAILABLE: cannot load refs/files (git/permissions/etc.)
      - PARSE_ERROR: invalid lockfile JSON

    Returns BaselineResult(status, changed).
    """
    if not base_ref or not head_ref:
        return BaselineResult(status=REF_UNAVAILABLE, changed={})

    base_txt = _git_show(repo_dir, base_ref, lock_path)
    head_txt = _git_show(repo_dir, head_ref, lock_path)

    # If we can't read head, we can't determine what's introduced.
    if head_txt is None:
        # If base exists but head doesn't, treat as HEAD_MISSING (rare)
        if base_txt is not None:
            return BaselineResult(status=HEAD_MISSING, changed={})
        return BaselineResult(status=REF_UNAVAILABLE, changed={})

    try:
        head_lock = _load_lock_json(head_txt)
        head_pkgs = _extract_packages(head_lock)
    except Exception:
        return BaselineResult(status=PARSE_ERROR, changed={})

    # If base lockfile is missing but head exists: treat everything in head as introduced.
    if base_txt is None:
        changed = {name: (None, ver) for name, ver in head_pkgs.items()}
        return BaselineResult(status=BASE_MISSING, changed=changed)

    try:
        base_lock = _load_lock_json(base_txt)
        base_pkgs = _extract_packages(base_lock)
    except Exception:
        return BaselineResult(status=PARSE_ERROR, changed={})

    changed: dict[str, tuple[Optional[str], Optional[str]]] = {}
    names = set(base_pkgs.keys()) | set(head_pkgs.keys())
    for n in names:
        bv = base_pkgs.get(n)
        hv = head_pkgs.get(n)
        if bv != hv:
            changed[n] = (bv, hv)

    return BaselineResult(status=OK, changed=changed)
