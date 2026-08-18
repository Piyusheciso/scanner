"""
Web Recon Scanner - HTTP Reconnaissance

Phase 2 responsibilities:
    - HTTP/HTTPS availability detection
    - HTTP response status
    - Redirect detection
    - Final URL
    - Response headers
    - Server identification
    - Content-Type
    - Cookies
    - Security header analysis
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import requests
from requests.exceptions import (
    ConnectionError,
    RequestException,
    SSLError,
    Timeout,
)

from config import DEFAULT_TIMEOUT, MAX_REDIRECTS, USER_AGENT


# ============================================================
# Security headers
# ============================================================

SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP helps control which resources a browser can load.",
    "Strict-Transport-Security": "HSTS forces browsers to use HTTPS.",
    "X-Frame-Options": "Helps prevent clickjacking through framing.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls how much referrer information browsers send.",
    "Permissions-Policy": "Controls access to browser features and APIs.",
}


# ============================================================
# Data classes
# ============================================================

@dataclass
class SecurityHeaderResult:
    """
    Result for an individual security header.
    """

    name: str
    present: bool
    value: Optional[str]
    description: str


@dataclass
class HTTPReconResult:
    """
    Structured HTTP reconnaissance result.
    """

    requested_url: str
    reachable: bool
    status_code: Optional[int]
    reason: Optional[str]
    final_url: Optional[str]
    redirect_detected: bool
    redirect_count: int

    headers: Dict[str, str]

    server: Optional[str]
    content_type: Optional[str]
    content_length: Optional[str]
    date: Optional[str]

    cookies: List[str]

    security_headers: List[SecurityHeaderResult]

    error: Optional[str]


# ============================================================
# HTTP request
# ============================================================

def perform_request(url: str) -> HTTPReconResult:
    """
    Perform an HTTP GET request.

    Redirects are followed so that we can determine the final URL.

    Args:
        url: Target URL.

    Returns:
        HTTPReconResult
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )

        # ----------------------------------------------------
        # Response headers
        # ----------------------------------------------------

        response_headers = {
            key: value
            for key, value in response.headers.items()
        }

        # ----------------------------------------------------
        # Redirect information
        # ----------------------------------------------------

        redirect_count = len(response.history)

        redirect_detected = redirect_count > 0

        # ----------------------------------------------------
        # Cookies
        # ----------------------------------------------------

        cookies = []

        for cookie in response.cookies:

            cookie_string = cookie.name

            if cookie.value:
                cookie_string += "=<redacted>"

            cookies.append(cookie_string)

        # ----------------------------------------------------
        # Security headers
        # ----------------------------------------------------

        security_headers = analyze_security_headers(
            response_headers
        )

        # ----------------------------------------------------
        # Standard headers
        # ----------------------------------------------------

        server = response_headers.get("Server")

        content_type = response_headers.get(
            "Content-Type"
        )

        content_length = response_headers.get(
            "Content-Length"
        )

        date = response_headers.get("Date")

        # ----------------------------------------------------
        # Build result
        # ----------------------------------------------------

        return HTTPReconResult(
            requested_url=url,
            reachable=True,
            status_code=response.status_code,
            reason=response.reason,
            final_url=response.url,
            redirect_detected=redirect_detected,
            redirect_count=redirect_count,
            headers=response_headers,
            server=server,
            content_type=content_type,
            content_length=content_length,
            date=date,
            cookies=cookies,
            security_headers=security_headers,
            error=None,
        )

    except SSLError as exc:

        return create_error_result(
            url,
            f"SSL error: {exc}",
        )

    except Timeout as exc:

        return create_error_result(
            url,
            f"Connection timeout: {exc}",
        )

    except ConnectionError as exc:

        return create_error_result(
            url,
            f"Connection error: {exc}",
        )

    except RequestException as exc:

        return create_error_result(
            url,
            f"HTTP request error: {exc}",
        )

    except Exception as exc:

        return create_error_result(
            url,
            f"Unexpected error: {exc}",
        )


# ============================================================
# Error result
# ============================================================

def create_error_result(
    url: str,
    error: str,
) -> HTTPReconResult:
    """
    Create a failed HTTP reconnaissance result.
    """

    return HTTPReconResult(
        requested_url=url,
        reachable=False,
        status_code=None,
        reason=None,
        final_url=None,
        redirect_detected=False,
        redirect_count=0,
        headers={},
        server=None,
        content_type=None,
        content_length=None,
        date=None,
        cookies=[],
        security_headers=analyze_security_headers({}),
        error=error,
    )


# ============================================================
# Security header analysis
# ============================================================

def analyze_security_headers(
    headers: Dict[str, str],
) -> List[SecurityHeaderResult]:
    """
    Analyze standard security headers.

    Header names are compared case-insensitively.
    """

    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    results = []

    for header_name, description in SECURITY_HEADERS.items():

        value = normalized_headers.get(
            header_name.lower()
        )

        results.append(
            SecurityHeaderResult(
                name=header_name,
                present=value is not None,
                value=value,
                description=description,
            )
        )

    return results


# ============================================================
# HTTP/HTTPS scanner
# ============================================================

def scan_http_https(
    hostname: str,
) -> Dict[str, HTTPReconResult]:
    """
    Test both HTTP and HTTPS for a hostname.

    Returns:

        {
            "http": HTTPReconResult,
            "https": HTTPReconResult
        }
    """

    urls = {
        "http": f"http://{hostname}",
        "https": f"https://{hostname}",
    }

    results = {}

    for protocol, url in urls.items():

        results[protocol] = perform_request(url)

    return results


# ============================================================
# Serialization helpers
# ============================================================

def security_header_to_dict(
    result: SecurityHeaderResult,
) -> dict:
    """
    Convert SecurityHeaderResult to dictionary.
    """

    return asdict(result)


def http_result_to_dict(
    result: HTTPReconResult,
) -> dict:
    """
    Convert HTTPReconResult into JSON-compatible dictionary.
    """

    data = asdict(result)

    data["security_headers"] = [
        security_header_to_dict(header)
        for header in result.security_headers
    ]

    return data