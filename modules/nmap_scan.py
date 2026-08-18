"""
Web Recon Scanner - Nmap Integration

Phase 3 responsibilities:

    - Detect Nmap executable
    - Run:
        nmap -sV -Pn -p 80,443 <target>

    - Parse open ports
    - Parse service information
    - Preserve raw Nmap output
"""

import re
import shutil
import subprocess

from dataclasses import dataclass, asdict
from typing import List, Optional

from config import (
    NMAP_COMMAND,
    NMAP_TIMEOUT,
)


@dataclass
class PortResult:
    """
    Information about one scanned port.
    """

    port: int
    protocol: str
    state: str
    service: str
    version: str


@dataclass
class NmapResult:
    """
    Structured Nmap result.
    """

    available: bool
    executed: bool

    command: List[str]

    ports: List[PortResult]

    raw_output: str

    error: Optional[str]

    return_code: Optional[int]


def find_nmap() -> Optional[str]:
    """
    Locate Nmap executable.
    """

    return shutil.which(
        NMAP_COMMAND
    )


def parse_nmap_output(
    output: str,
) -> List[PortResult]:
    """
    Parse the normal Nmap port table.

    Example:

        PORT    STATE SERVICE VERSION
        80/tcp  open  http    nginx
        443/tcp open  https   nginx

    This parser is intentionally conservative.
    """

    ports = []

    if not output:
        return ports

    # --------------------------------------------------------
    # Match:
    #
    # 80/tcp open http nginx
    #
    # 443/tcp open https nginx
    # --------------------------------------------------------

    pattern = re.compile(
        r"^(\d+)\/(\w+)\s+"
        r"(\S+)\s+"
        r"(\S+)"
        r"(?:\s+(.*))?$"
    )

    for line in output.splitlines():

        line = line.strip()

        match = pattern.match(line)

        if not match:
            continue

        port = int(
            match.group(1)
        )

        protocol = (
            match.group(2)
        )

        state = (
            match.group(3)
        )

        service = (
            match.group(4)
        )

        version = (
            match.group(5)
            or ""
        )

        ports.append(
            PortResult(
                port=port,
                protocol=protocol,
                state=state,
                service=service,
                version=version.strip(),
            )
        )

    return ports


def run_nmap(
    hostname: str,
) -> NmapResult:
    """
    Execute:

        nmap -sV -Pn -p 80,443 hostname
    """

    executable = find_nmap()

    command = [
        executable or NMAP_COMMAND,
        "-sV",
        "-Pn",
        "-p",
        "80,443",
        hostname,
    ]

    # --------------------------------------------------------
    # Nmap unavailable
    # --------------------------------------------------------

    if executable is None:

        return NmapResult(
            available=False,
            executed=False,
            command=command,
            ports=[],
            raw_output="",
            error=(
                "Nmap executable was not found "
                "in PATH."
            ),
            return_code=None,
        )

    # --------------------------------------------------------
    # Execute Nmap
    # --------------------------------------------------------

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
            shell=False,
        )

        stdout = process.stdout or ""

        stderr = process.stderr or ""

        ports = (
            parse_nmap_output(
                stdout
            )
        )

        raw_output = stdout

        if stderr:

            raw_output += (
                "\n[stderr]\n"
                + stderr
            )

        return NmapResult(
            available=True,
            executed=True,
            command=command,
            ports=ports,
            raw_output=raw_output,
            error=(
                None
                if process.returncode == 0
                else stderr.strip()
            ),
            return_code=process.returncode,
        )

    except subprocess.TimeoutExpired:

        return NmapResult(
            available=True,
            executed=False,
            command=command,
            ports=[],
            raw_output="",
            error=(
                "Nmap timed out after "
                f"{NMAP_TIMEOUT} seconds."
            ),
            return_code=None,
        )

    except OSError as exc:

        return NmapResult(
            available=True,
            executed=False,
            command=command,
            ports=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )

    except Exception as exc:

        return NmapResult(
            available=True,
            executed=False,
            command=command,
            ports=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )


def nmap_to_dict(
    result: NmapResult,
) -> dict:
    """
    Convert Nmap result to dictionary.
    """

    data = asdict(result)

    data["ports"] = [
        asdict(port)
        for port in result.ports
    ]

    return data