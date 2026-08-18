"""
Web Recon Scanner - WhatWeb Integration

Phase 3 responsibilities:

    - Detect WhatWeb executable
    - Execute WhatWeb
    - Capture stdout/stderr
    - Parse basic technology information
    - Return structured data
"""

import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional

from config import (
    WHATWEB_COMMAND,
    WHATWEB_TIMEOUT,
)


@dataclass
class WhatWebResult:
    """
    Structured WhatWeb result.
    """

    available: bool
    executed: bool

    command: List[str]

    technologies: List[str]

    raw_output: str

    error: Optional[str]

    return_code: Optional[int]


def find_whatweb() -> Optional[str]:
    """
    Locate WhatWeb executable.

    Returns:
        Executable path if found.
        None otherwise.
    """

    return shutil.which(
        WHATWEB_COMMAND
    )


def parse_whatweb_output(
    output: str,
) -> List[str]:
    """
    Perform basic WhatWeb output parsing.

    This parser intentionally remains conservative.

    The raw output is preserved so the parser can be
    improved later without rescanning the target.
    """

    technologies = []

    if not output:
        return technologies

    # --------------------------------------------------------
    # WhatWeb commonly produces output similar to:
    #
    # target.com [200 OK] Country[...],
    # HTML5, HTTPServer[nginx], JQuery[...],
    # Script, etc.
    # --------------------------------------------------------

    known_indicators = [
        "nginx",
        "apache",
        "iis",
        "cloudflare",
        "wordpress",
        "drupal",
        "joomla",
        "react",
        "angular",
        "vue",
        "jquery",
        "bootstrap",
        "php",
        "node.js",
        "express",
        "next.js",
        "nuxt.js",
        "typescript",
    ]

    output_lower = output.lower()

    for indicator in known_indicators:

        if indicator.lower() in output_lower:

            technologies.append(
                indicator
            )

    # Remove duplicates while maintaining order.
    technologies = list(
        dict.fromkeys(technologies)
    )

    return technologies


def run_whatweb(
    target_url: str,
) -> WhatWebResult:
    """
    Execute WhatWeb against target URL.
    """

    executable = find_whatweb()

    command = [
        executable or WHATWEB_COMMAND,
        target_url,
    ]

    # --------------------------------------------------------
    # WhatWeb unavailable
    # --------------------------------------------------------

    if executable is None:

        return WhatWebResult(
            available=False,
            executed=False,
            command=command,
            technologies=[],
            raw_output="",
            error=(
                "WhatWeb executable was not found "
                "in PATH."
            ),
            return_code=None,
        )

    # --------------------------------------------------------
    # Execute WhatWeb
    # --------------------------------------------------------

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=WHATWEB_TIMEOUT,
            shell=False,
        )

        stdout = process.stdout or ""

        stderr = process.stderr or ""

        raw_output = stdout

        if stderr:

            raw_output += (
                "\n[stderr]\n"
                + stderr
            )

        technologies = (
            parse_whatweb_output(
                stdout
            )
        )

        return WhatWebResult(
            available=True,
            executed=True,
            command=command,
            technologies=technologies,
            raw_output=raw_output,
            error=(
                None
                if process.returncode == 0
                else stderr.strip()
            ),
            return_code=process.returncode,
        )

    except subprocess.TimeoutExpired:

        return WhatWebResult(
            available=True,
            executed=False,
            command=command,
            technologies=[],
            raw_output="",
            error=(
                "WhatWeb timed out after "
                f"{WHATWEB_TIMEOUT} seconds."
            ),
            return_code=None,
        )

    except OSError as exc:

        return WhatWebResult(
            available=True,
            executed=False,
            command=command,
            technologies=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )

    except Exception as exc:

        return WhatWebResult(
            available=True,
            executed=False,
            command=command,
            technologies=[],
            raw_output="",
            error=str(exc),
            return_code=None,
        )


def whatweb_to_dict(
    result: WhatWebResult,
) -> dict:
    """
    Convert WhatWeb result to dictionary.
    """

    return asdict(result)