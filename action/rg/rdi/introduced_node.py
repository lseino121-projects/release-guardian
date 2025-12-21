from __future__ import annotations

import json
import subprocess
from typing import Dict, Tuple, Optional


def _has_commit(ref: str) -> bool:
    try:
        subprocess.check_call(
            ["git", "cat-file", "-e", f"{ref}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _fetch_commit(ref: str) -> bool:
    """
    Try to fetch the commit object by SHA from origin.
    This works even when checkout is a PR merge ref and base/head SHAs aren't present locally.
    """
    # Refspec: fetch <sha> into a temporary local ref
    tmp_ref = f"refs/rg/{ref}"
    try:
        subprocess.check_call(
            ["git", "fetch", "--no-tags", "--prune", "origin", f"+{ref}:{tmp_ref}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _git_show(ref: str, path: str) -> Optional[str]:
    """
    Return file contents at git ref, or None if file doesn't exist / ref unavailable.
    """
    # Ensure commit exists locally
    if not _has_commit(ref):
        if not _fetch_commit(ref):
            return None

    try:
        return subprocess.check_output(
            ["git", "show", f"{ref}:{path}"],
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
    base_ref: str, head_ref: str, lock_path: str = "package-lock.json"
) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """
    Return mapping: pkg -> (base_version, head_version)
    Only includes packages where version differs or is new/removed.

    If base/head cannot be read, returns a sentinel:
      {"__RG_DIFF_UNAVAILABLE__": (None, None)}
    """
    if not base_ref or not head_ref:
        return {"__RG_DIFF_UNAVAILABLE__": (None, None)}

    base_txt = _git_show(base_ref, lock_path)
    head_txt = _git_show(head_ref, lock_path)

    if not base_txt or not head_txt:
        return {"__RG_DIFF_UNAVAILABLE__": (None, None)}

    base_lock = _load_lock_json(base_txt)
    head_lock = _load_lock_json(head_txt)

    base_pkgs = _extract_packages(base_lock)
    head_pkgs = _extract_packages(head_lock)

    changed: dict[str, tuple[Optional[str], Optional[str]]] = {}

    names = set(base_pkgs.keys()) | set(head_pkgs.keys())
    for n in names:
        bv = base_pkgs.get(n)
        hv = head_pkgs.get(n)
        if bv != hv:
            changed[n] = (bv, hv)

    return changed
