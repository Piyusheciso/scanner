"""
Common sensitive-file checks.
"""

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin

import requests


DEFAULT_TIMEOUT = 15


SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]


@dataclass
class SensitiveFileResult:
    path: str
    url: str
    status_code: Optional[int]
    content_type: Optional[str]
    content_length: Optional[int]
    accessible: bool
    error: Optional[str]


def check_sensitive_file(
    base_url: str,
    path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> SensitiveFileResult:
    """
    Check one common file.
    """

    url = urljoin(
        base_url.rstrip("/") + "/",
        path.lstrip("/"),
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

        content_length = len(
            response.content
        )

        content_type = response.headers.get(
            "Content-Type"
        )

        accessible = (
            response.status_code == 200
        )

        return SensitiveFileResult(
            path=path,
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            content_length=content_length,
            accessible=accessible,
            error=None,
        )

    except requests.RequestException as exc:

        return SensitiveFileResult(
            path=path,
            url=url,
            status_code=None,
            content_type=None,
            content_length=None,
            accessible=False,
            error=str(exc),
        )


def check_sensitive_files(
    base_url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[SensitiveFileResult]:
    """
    Check all configured paths.
    """

    results = []

    for path in SENSITIVE_PATHS:

        result = check_sensitive_file(
            base_url,
            path,
            timeout,
        )

        results.append(
            result
        )

    return results


def sensitive_files_to_dict(
    results: List[SensitiveFileResult],
) -> list:
    """
    Convert results to JSON-safe data.
    """

    return [
        {
            "path": result.path,
            "url": result.url,
            "status_code": result.status_code,
            "content_type": result.content_type,
            "content_length": result.content_length,
            "accessible": result.accessible,
            "error": result.error,
        }
        for result in results
    ]