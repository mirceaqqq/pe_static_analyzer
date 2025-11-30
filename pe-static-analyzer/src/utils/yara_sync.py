"""
Utility to sync YARA rules from GitHub (e.g., https://github.com/Yara-Rules/rules).
Downloads .yar/.yara files from a set of folders and stores them under yara_rules/remote.
"""

import os
from pathlib import Path
from typing import List
import requests

DEFAULT_OWNER = "Yara-Rules"
DEFAULT_REPO = "rules"
DEFAULT_BRANCH = "master"
DEFAULT_FOLDERS = ["malware", "exploit_kits", "antidebug_antivm", "email", "exploit"]


def _walk_repo(owner: str, repo: str, path: str, branch: str, headers: dict):
    """
    Recursiv fetch of GitHub folder contents; yields file entries.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    for entry in resp.json():
        etype = entry.get("type")
        if etype == "file":
            yield entry
        elif etype == "dir":
            yield from _walk_repo(owner, repo, entry["path"], branch, headers)


def _fetch_dir(owner: str, repo: str, path: str, branch: str, target_dir: Path, token: str = "") -> None:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    for entry in _walk_repo(owner, repo, path, branch, headers):
        if entry.get("type") == "file" and entry["name"].lower().endswith((".yar", ".yara")):
            data = requests.get(entry["download_url"], headers=headers, timeout=30).content
            out = target_dir / entry["name"]
            out.write_bytes(data)


def sync_yara_rules(
    owner: str = DEFAULT_OWNER,
    repo: str = DEFAULT_REPO,
    branch: str = DEFAULT_BRANCH,
    folders: List[str] = None,
    target_dir: Path = Path("yara_rules") / "remote",
    token: str = "",
) -> int:
    """Return number of files saved."""
    folders = folders or DEFAULT_FOLDERS
    target_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for folder in folders:
        try:
            before = len(list(target_dir.glob("*.yar"))) + len(list(target_dir.glob("*.yara")))
            _fetch_dir(owner, repo, folder, branch, target_dir, token)
            after = len(list(target_dir.glob("*.yar"))) + len(list(target_dir.glob("*.yara")))
            count += max(0, after - before)
        except Exception:
            continue
    return count
