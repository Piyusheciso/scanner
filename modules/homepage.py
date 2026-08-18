"""
Homepage downloader.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests


DEFAULT_TIMEOUT = 15


@dataclass
class HomepageResult:
    url: str
    final_url: Optional[str]
    status_code: Optional[int]
    content_type: Optional[str]
    content_length: Optional[int]
    html_file: Optional[str]
    downloaded: bool
    error: Optional[str]


def download_homepage(
    url: str,
    output_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
) -> HomepageResult:
    """
    Download the target homepage.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    html_file = output_dir / "homepage.html"

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

        content_type = response.headers.get(
            "Content-Type"
        )

        content = response.content

        html_file.write_bytes(
            content
        )

        return HomepageResult(
            url=url,
            final_url=response.url,
            status_code=response.status_code,
            content_type=content_type,
            content_length=len(content),
            html_file=str(html_file),
            downloaded=True,
            error=None,
        )

    except requests.RequestException as exc:

        return HomepageResult(
            url=url,
            final_url=None,
            status_code=None,
            content_type=None,
            content_length=None,
            html_file=None,
            downloaded=False,
            error=str(exc),
        )

    except OSError as exc:

        return HomepageResult(
            url=url,
            final_url=None,
            status_code=None,
            content_type=None,
            content_length=None,
            html_file=None,
            downloaded=False,
            error=str(exc),
        )


def homepage_to_dict(
    result: HomepageResult,
) -> dict:
    """
    Convert homepage result to JSON-safe data.
    """

    return {
        "url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "html_file": result.html_file,
        "downloaded": result.downloaded,
        "error": result.error,
    }