"""Locate the Nmap system executable used by Vulnex.

Nmap is a system executable, not a Python/PyPI dependency. This resolver
supports normal PATH lookup plus common macOS Homebrew locations.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


COMMON_NMAP_PATHS = (
    "/opt/homebrew/bin/nmap",  # Apple Silicon Homebrew
    "/usr/local/bin/nmap",      # Intel macOS Homebrew / common Unix path
    "/usr/bin/nmap",
    "/bin/nmap",
)


def find_nmap() -> str | None:
    """Return the absolute path to Nmap, or None if it is unavailable."""
    found = shutil.which("nmap")
    if found:
        return found

    for candidate in COMMON_NMAP_PATHS:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)

    return None


def nmap_install_message() -> str:
    """Return platform-aware installation guidance."""
    if os.name == "nt":
        return (
            "Nmap is not installed. Install Nmap for Windows from the official "
            "Nmap installer and ensure nmap.exe is available in PATH."
        )

    # macOS and Linux both commonly use package managers, but avoid attempting
    # privileged system installation automatically from a security application.
    if os.uname().sysname == "Darwin":
        return (
            "Nmap is not installed. On macOS, install it with Homebrew: "
            "brew install nmap. Then restart Vulnex."
        )

    return (
        "Nmap is not installed. Install Nmap using your Linux distribution's "
        "package manager (for example: sudo apt install nmap), then restart Vulnex."
    )
