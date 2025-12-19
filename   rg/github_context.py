from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class GitHubContext:
    event_name: str
    pr_number: Optional[int]
    base_sha: Optional[str]
    head_sha: Optional[str]


def load_context(event_path: str) -> GitHubContext:
    """
    Minimal PR context loader. v1 scaffold only.
    We'll expand this later to include changed files, repo metadata, etc.
    """
    p = Path(event_path)
    data: dict[str, Any] = json.loads(p.read_text())

    # Best-effort event name detection: some events include 'action' + payload structure.
    # We'll use presence of pull_request to determine PR.
    pr = data.get("pull_request")
    if pr:
        pr_number = int(data.get("number") or pr.get("number"))
        base_sha = pr.get("base", {}).get("sha")
        head_sha = pr.get("head", {}).get("sha")
        return GitHubContext(event_name="pull_request", pr_number=pr_number, base_sha=base_sha, head_sha=head_sha)

    return GitHubContext(event_name="non_pr_event", pr_number=None, base_sha=None, head_sha=None)
