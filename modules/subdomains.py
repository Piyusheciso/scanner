"""
Web Recon Scanner - Subdomain Enumeration

Phase 3 responsibilities:

    - Detect Subfinder executable
    - Enumerate subdomains
    - Validate basic output
    - Deduplicate results
"""

import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional

from config import (
    SUBFINDER_COMMAND,
    SUBFINDER_TIMEOUT,
)


@dataclass
class SubdomainResult:
    """
    Structured subdomain enumeration result.
    """

    available: bool
    executed: bool

    command: List[str]

    subdomains: List[str]

    raw_output: str

    error: Optional[str]

    return_code: Optional[int]


def find_subfinder() -> Optional[str]:
    """
    Locate Subfinder executable.
    """

    return shutil.which(
        SUBFINDER_COMMAND
    )


def parse_subfinder_output(
    output: str,
) -> List[str]:
    """
    Parse Subfinder output.

    Subfinder with -silent normally returns one
    subdomain per line.
    """

    if not output:
        return []

    subdomains = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        # Ignore obvious informational lines.
        if line.startswith("["):
            continue

        subdomains.append(
            line.lower()
        )

    # Deduplicate and sort.
    subdomains = sorted(
        set(subdomains)
    )

    return subdomains


def run_subfinder(
    domain: str,
) -> SubdomainResult:
    """
    Run Subfinder against a domain.
    """

    executable = find_subfinder()

    command = [
        executable or SUBFINDER_COMMAND,
        "-d",
        domain,
        "-silent",
    ]

    # --------------------------------------------------------
    # Subfinder unavailable
    # --------------------------------------------------------

    if executable is None:

        return SubdomainResult(
            available=False,
            executed=False,
            command=command,
            subdomains=[],
            raw_output="",
            error=(
                "Subfinder executable was not found "
                "in PATH."
            ),
            return_code=None,
        )

    # --------------------------------------------------------
    # Execute Subfinder
    # --------------------------------------------------------

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SUBFINDER_TIMEOUT,
            shell=False,
        )

        stdout = process.stdout or ""

        stderr = process.stderr or ""

        subdomains = (
            parse_subfinder_output(
                stdout
            )
        )

        raw_output = stdout

        if stderr:

            raw_output += (
                "\n[stderr]\n"
                + stderr
            )

        return SubdomainResult(
            available=True,
            executed=True,
            command=command,
            subdomains=subdomains,
            raw_output=raw_output,
            error=(
                None
                if process.returncode == 0
                else stderr.strip()
            ),
            return_code=process.returncode,
        )

    except subprocess.TimeoutExpired:

        return SubdomainResult(
            available=True,
            executed=False,
            command=command,
            subdomains=[],
            raw_output="",
            error=(
                "Subfinder timed out after "
                f"{SUBFINDER_TIMEOUT} seconds."
            ),
            return_code=None,
        )

    except OSError as exc:

        return SubdomainResult(
            available=True,
            executed=False,
            command=command,
            subdomains=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )

    except Exception as exc:

        return SubdomainResult(
            available=True,
            executed=False,
            command=command,
            subdomains=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )


def subdomain_to_dict(
    result: SubdomainResult,
) -> dict:
    """
    Convert result to dictionary.
    """

    return asdict(result)