"""
JavaScript discovery and downloader.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import hashlib
import re

import requests


DEFAULT_TIMEOUT = 15


@dataclass
class JavaScriptFile:
    url: str
    local_file: Optional[str]
    status_code: Optional[int]
    content_length: Optional[int]
    downloaded: bool
    error: Optional[str]


@dataclass
class JavaScriptResult:
    urls: List[str]
    files: List[JavaScriptFile]


SCRIPT_SRC_PATTERN = re.compile(
    r"<script\b[^>]*?\bsrc\s*=\s*"
    r"""["']([^"']+)["']""",
    re.IGNORECASE,
)


def extract_js_urls(
    html: str,
    base_url: str,
) -> List[str]:
    """
    Extract and normalize JavaScript URLs.
    """

    matches = SCRIPT_SRC_PATTERN.findall(
        html
    )

    urls = []

    for src in matches:

        src = src.strip()

        if not src:
            continue

        if src.startswith(
            (
                "data:",
                "javascript:",
            )
        ):
            continue

        absolute_url = urljoin(
            base_url,
            src,
        )

        parsed = urlparse(
            absolute_url
        )

        if parsed.scheme not in (
            "http",
            "https",
        ):
            continue

        urls.append(
            absolute_url
        )

    return sorted(
        set(urls)
    )


def _safe_filename(
    url: str,
    index: int,
) -> str:
    """
    Generate a safe local filename.
    """

    parsed = urlparse(url)

    filename = Path(
        parsed.path
    ).name

    if not filename:
        filename = f"script_{index}.js"

    filename = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        filename,
    )

    if not filename.lower().endswith(
        ".js"
    ):
        filename += ".js"

    digest = hashlib.sha1(
        url.encode(
            "utf-8"
        )
    ).hexdigest()[:8]

    return (
        f"{Path(filename).stem}_"
        f"{digest}.js"
    )


def download_js_files(
    urls: List[str],
    output_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[JavaScriptFile]:
    """
    Download discovered JavaScript files.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = []

    for index, url in enumerate(
        urls,
        start=1,
    ):

        local_file = (
            output_dir
            / _safe_filename(
                url,
                index,
            )
        )

        try:

            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        "Web-Recon-Scanner/1.0"
                    )
                },
            )

            content = response.content

            local_file.write_bytes(
                content
            )

            results.append(
                JavaScriptFile(
                    url=url,
                    local_file=str(
                        local_file
                    ),
                    status_code=(
                        response.status_code
                    ),
                    content_length=len(
                        content
                    ),
                    downloaded=True,
                    error=None,
                )
            )

        except requests.RequestException as exc:

            results.append(
                JavaScriptFile(
                    url=url,
                    local_file=None,
                    status_code=None,
                    content_length=None,
                    downloaded=False,
                    error=str(exc),
                )
            )

        except OSError as exc:

            results.append(
                JavaScriptFile(
                    url=url,
                    local_file=None,
                    status_code=None,
                    content_length=None,
                    downloaded=False,
                    error=str(exc),
                )
            )

    return results


def run_javascript_discovery(
    homepage_html: str,
    base_url: str,
    output_dir: Path,
) -> JavaScriptResult:
    """
    Extract and download JavaScript files.
    """

    urls = extract_js_urls(
        homepage_html,
        base_url,
    )

    files = download_js_files(
        urls,
        output_dir,
    )

    return JavaScriptResult(
        urls=urls,
        files=files,
    )


def javascript_to_dict(
    result: JavaScriptResult,
) -> dict:
    """
    Convert JavaScript result to JSON-safe data.
    """

    return {
        "urls": result.urls,
        "files": [
            {
                "url": item.url,
                "local_file": item.local_file,
                "status_code": item.status_code,
                "content_length": item.content_length,
                "downloaded": item.downloaded,
                "error": item.error,
            }
            for item in result.files
        ],
    }