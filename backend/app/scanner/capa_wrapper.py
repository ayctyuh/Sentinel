from __future__ import annotations

import json
import shutil
import subprocess
from typing import Dict, List


def run_capa(file_path: str) -> Dict[str, List[Dict[str, str]]]:
    """Run capa and return ATT&CK/MBC matches if the binary is available."""

    capa_binary = shutil.which("capa")
    if not capa_binary:
        return {
            "rules": [],
            "error": "capa binary not found. Install capa or ensure it is on PATH.",
        }

    try:
        completed = subprocess.run(
            [capa_binary, "--format", "json", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as exc:
        return {
            "rules": [],
            "error": f"capa failed: {exc.stderr.strip() or exc.stdout.strip() or exc}",
        }
    except subprocess.TimeoutExpired:
        return {
            "rules": [],
            "error": "capa timed out after 120 seconds.",
        }

    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            "rules": [],
            "error": "Unable to parse capa output (expected JSON).",
        }

    results: List[Dict[str, str]] = []
    for rule in data.get("rules", []):
        meta = rule.get("meta", {})
        attack = meta.get("att&ck", [])
        mbc = meta.get("mbc", [])
        if attack or mbc:
            results.append(
                {
                    "rule": meta.get("name", "unknown"),
                    "namespace": meta.get("namespace", ""),
                    "attck": attack,
                    "mbc": mbc,
                    "severity": meta.get("severity", ""),
                }
            )

    return {
        "rules": results,
        "metadata": data.get("meta", {}),
    }
