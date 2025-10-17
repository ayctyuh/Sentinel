from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

FLOSS_ARGS = ("--no-progress", "--only", "stackstrings,static-strings,decoded-strings")


def run_floss(file_path: str, limit: int = 200) -> Dict[str, List[str]]:
    """
    Execute FLOSS against a file and return extracted strings.

    The FLOSS binary is optional. If it is unavailable, an explanatory
    message is returned so callers can surface it gracefully.
    """

    floss_binary = shutil.which("floss")
    if not floss_binary:
        return {
            "strings": [],
            "error": "FLOSS binary not found. Install FLOSS or adjust PATH.",
        }

    try:
        completed = subprocess.run(
            [floss_binary, *FLOSS_ARGS, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            timeout=90,
        )
    except subprocess.CalledProcessError as exc:
        return {
            "strings": [],
            "error": f"FLOSS failed: {exc.stderr.strip() or exc.stdout.strip() or exc}",
        }
    except subprocess.TimeoutExpired:
        return {
            "strings": [],
            "error": "FLOSS timed out after 90 seconds.",
        }

    strings = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and not line.startswith("[FLOSS]")
    ]

    if limit:
        strings = strings[:limit]

    return {
        "strings": strings,
        "truncated": limit is not None and len(strings) >= limit,
    }
