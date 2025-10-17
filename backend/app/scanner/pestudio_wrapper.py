from __future__ import annotations

import os
from typing import Dict, List


def run_pestudio_like_analysis(file_path: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Provide lightweight PE metadata (sections/imports).

    This mirrors a subset of PEStudio's output using the `pefile` package.
    If `pefile` is unavailable or the file is not a PE, an explanatory
    payload is returned so the caller can decide how to display it.
    """

    try:
        import pefile  # type: ignore
    except ImportError:
        return {
            "sections": [],
            "imports": [],
            "error": "python-pefile is not installed. Install it to enable PE analysis.",
        }

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return {
            "sections": [],
            "imports": [],
            "error": "File is not a valid PE executable.",
        }

    sections: List[Dict[str, str]] = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").rstrip("\x00")
        sections.append(
            {
                "name": name or "<unnamed>",
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "entropy": round(section.get_entropy(), 2) if hasattr(section, "get_entropy") else None,
            }
        )

    imports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore") if entry.dll else ""
            if dll_name:
                imports.append(dll_name)

    return {
        "sections": sections,
        "imports": sorted(set(imports)),
    }
