"""
Target validation and normalization module.

Phase 1 responsibilities:
    - Validate target URL
    - Normalize target URL
    - Extract hostname
    - Extract scheme
    - Determine port
    - Resolve DNS
"""

import socket
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlparse


@dataclass
class TargetInfo:
    """
    Structured information about the target.
    """

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    ip_address: Optional[str]
    dns_resolved: bool


class TargetValidationError(Exception):
    """
    Raised when the supplied target is invalid.
    """

    pass


def normalize_url(url: str) -> str:
    """
    Normalize a user-supplied URL.

    Examples:

        target.com
        -> https://target.com

        http://target.com
        -> http://target.com

        https://target.com/
        -> https://target.com/

    Returns:
        Normalized URL.

    Raises:
        TargetValidationError
    """

    if not url:
        raise TargetValidationError("Target URL cannot be empty.")

    url = url.strip()

    # If no scheme was provided, default to HTTPS.
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise TargetValidationError(
            f"Unsupported URL scheme: {parsed.scheme}"
        )

    if not parsed.hostname:
        raise TargetValidationError(
            "Unable to determine hostname from target URL."
        )

    hostname = parsed.hostname

    # Reject obvious malformed hostnames.
    if " " in hostname:
        raise TargetValidationError(
            "Hostname contains whitespace."
        )

    # Remove fragment because it is not sent to the server.
    normalized = parsed._replace(
        fragment=""
    ).geturl()

    return normalized


def get_default_port(scheme: str) -> int:
    """
    Return the default port for HTTP/HTTPS.
    """

    if scheme.lower() == "https":
        return 443

    return 80


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to an IPv4 address.

    Returns:
        IPv4 address if resolution succeeds.
        None if resolution fails.
    """

    try:
        return socket.gethostbyname(hostname)

    except socket.gaierror:
        return None

    except Exception:
        return None


def validate_target(url: str) -> TargetInfo:
    """
    Validate and process the supplied target.

    Returns:
        TargetInfo object.

    Raises:
        TargetValidationError
    """

    original_url = url.strip()

    normalized_url = normalize_url(original_url)

    parsed = urlparse(normalized_url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    if hostname is None:
        raise TargetValidationError(
            "Hostname could not be extracted."
        )

    # Determine port.
    try:
        port = parsed.port

    except ValueError:
        raise TargetValidationError(
            "Invalid port specified in URL."
        )

    if port is None:
        port = get_default_port(scheme)

    # DNS resolution.
    ip_address = resolve_hostname(hostname)

    dns_resolved = ip_address is not None

    return TargetInfo(
        original_url=original_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        ip_address=ip_address,
        dns_resolved=dns_resolved,
    )


def target_to_dict(target: TargetInfo) -> dict:
    """
    Convert TargetInfo into a dictionary.

    Useful later when generating report.json.
    """

    return asdict(target)