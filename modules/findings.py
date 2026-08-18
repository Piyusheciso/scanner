"""
Finding engine.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    description: str
    evidence: str
    impact: str
    remediation: str
    source: str


def _add_finding(
    findings: List[Finding],
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    source: str,
) -> None:
    """
    Add one finding.
    """

    findings.append(
        Finding(
            id=finding_id,
            title=title,
            severity=severity,
            category=category,
            cwe=cwe,
            description=description,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            source=source,
        )
    )


def _check_security_headers(
    findings: List[Finding],
    phase_results: Dict[str, Any],
) -> None:
    """
    Generate findings for missing security headers.
    """

    http_results = phase_results.get(
        "http"
    )

    if not http_results:
        return

    preferred = None

    https = http_results.get(
        "https"
    )

    http = http_results.get(
        "http"
    )

    if (
        isinstance(https, dict)
        and https.get("reachable")
    ):
        preferred = https

    elif (
        isinstance(http, dict)
        and http.get("reachable")
    ):
        preferred = http

    if not preferred:
        return

    security_headers = preferred.get(
        "security_headers",
        [],
    )

    if not isinstance(
        security_headers,
        list,
    ):
        return

    header_info = {
        item.get("name"): item
        for item in security_headers
        if isinstance(item, dict)
    }

    header_rules = {
        "Content-Security-Policy": (
            "CSP-001",
            "Missing Content-Security-Policy",
            "Medium",
            "Security Headers",
            "CWE-693",
            "The response does not include a Content-Security-Policy header.",
            "Content-Security-Policy: Missing",
            "A missing CSP can reduce protection against certain content injection and XSS scenarios.",
            "Define an appropriate Content-Security-Policy for the application.",
        ),
        "X-Frame-Options": (
            "HDR-001",
            "Missing X-Frame-Options",
            "Medium",
            "Security Headers",
            "CWE-1021",
            "The response does not include an X-Frame-Options header.",
            "X-Frame-Options: Missing",
            "The application may have reduced protection against clickjacking.",
            "Set X-Frame-Options or use the frame-ancestors CSP directive.",
        ),
        "X-Content-Type-Options": (
            "HDR-002",
            "Missing X-Content-Type-Options",
            "Low",
            "Security Headers",
            "CWE-693",
            "The response does not include X-Content-Type-Options.",
            "X-Content-Type-Options: Missing",
            "Browsers may perform MIME sniffing where it could otherwise be prevented.",
            "Set X-Content-Type-Options: nosniff.",
        ),
        "Strict-Transport-Security": (
            "HDR-003",
            "Missing Strict-Transport-Security",
            "Low",
            "Security Headers",
            "CWE-319",
            "The HTTPS response does not include Strict-Transport-Security.",
            "Strict-Transport-Security: Missing",
            "Users may have reduced protection against protocol downgrade and initial insecure connections.",
            "Configure HSTS after confirming HTTPS is correctly deployed.",
        ),
    }

    for header_name, rule in header_rules.items():

        header = header_info.get(
            header_name
        )

        if header is None:
            continue

        if header.get("present"):
            continue

        (
            finding_id,
            title,
            severity,
            category,
            cwe,
            description,
            evidence,
            impact,
            remediation,
        ) = rule

        _add_finding(
            findings,
            finding_id,
            title,
            severity,
            category,
            cwe,
            description,
            evidence,
            impact,
            remediation,
            "Phase 2",
        )


def _check_http_exposure(
    findings: List[Finding],
    phase_results: Dict[str, Any],
) -> None:
    """
    Check for HTTP exposure when HTTPS is available.
    """

    http_results = phase_results.get(
        "http"
    )

    if not isinstance(
        http_results,
        dict,
    ):
        return

    http = http_results.get(
        "http"
    )

    https = http_results.get(
        "https"
    )

    if not isinstance(http, dict):
        return

    if not isinstance(https, dict):
        return

    if (
        http.get("reachable")
        and https.get("reachable")
    ):

        _add_finding(
            findings,
            "WEB-001",
            "HTTP endpoint is reachable",
            "Informational",
            "Transport Security",
            "CWE-319",
            "The target is reachable over both HTTP and HTTPS.",
            (
                f"HTTP: {http.get('final_url')}; "
                f"HTTPS: {https.get('final_url')}"
            ),
            "Unencrypted HTTP access may expose traffic if users are not redirected to HTTPS.",
            "Redirect HTTP traffic to HTTPS and configure HSTS where appropriate.",
            "Phase 2",
        )


def _check_sensitive_files(
    findings: List[Finding],
    phase_results: Dict[str, Any],
) -> None:
    """
    Generate findings from sensitive-file checks.
    """

    phase_6 = phase_results.get(
        "phase_6"
    )

    if not isinstance(
        phase_6,
        dict,
    ):
        return

    files = phase_6.get(
        "files",
        [],
    )

    if not isinstance(
        files,
        list,
    ):
        return

    for item in files:

        if not isinstance(item, dict):
            continue

        path = item.get(
            "path"
        )

        status = item.get(
            "status_code"
        )

        if status != 200:
            continue

        if path == "/.env":

            _add_finding(
                findings,
                "SEN-001",
                "Potentially exposed .env file",
                "High",
                "Sensitive File Exposure",
                "CWE-200",
                "The .env path returned HTTP 200 and may expose application configuration or secrets.",
                f"{path} returned HTTP 200.",
                "Exposed environment files can disclose credentials, tokens, database settings, or application secrets.",
                "Remove the file from the web root and block access to environment files at the web server.",
                "Phase 6",
            )

        elif path == "/.git/HEAD":

            _add_finding(
                findings,
                "SEN-002",
                "Potentially exposed Git metadata",
                "High",
                "Sensitive File Exposure",
                "CWE-538",
                "The Git HEAD file is publicly accessible.",
                f"{path} returned HTTP 200.",
                "Exposed Git metadata can disclose source-code repository information and may facilitate source exposure.",
                "Remove the .git directory from the web root and deny web access to repository metadata.",
                "Phase 6",
            )

        elif path == "/robots.txt":

            _add_finding(
                findings,
                "INFO-001",
                "robots.txt is publicly accessible",
                "Informational",
                "Information Disclosure",
                "CWE-200",
                "The robots.txt file is publicly accessible.",
                f"{path} returned HTTP 200.",
                "robots.txt may disclose paths that the site owner does not want indexed.",
                "Review entries in robots.txt and avoid using it as an access-control mechanism.",
                "Phase 6",
            )

        elif path == "/sitemap.xml":

            _add_finding(
                findings,
                "INFO-002",
                "sitemap.xml is publicly accessible",
                "Informational",
                "Information Disclosure",
                "CWE-200",
                "The sitemap is publicly accessible.",
                f"{path} returned HTTP 200.",
                "The sitemap can reveal application URLs and site structure.",
                "Ensure that published URLs are intended to be publicly discoverable.",
                "Phase 6",
            )

        elif path == "/security.txt":

            _add_finding(
                findings,
                "INFO-003",
                "security.txt is publicly accessible",
                "Informational",
                "Security Contact",
                "CWE-200",
                "A security.txt file is publicly accessible.",
                f"{path} returned HTTP 200.",
                "This is normally expected and can provide security-contact information.",
                "Keep the security.txt information accurate and current.",
                "Phase 6",
            )


def _check_js_observations(
    findings: List[Finding],
    phase_results: Dict[str, Any],
) -> None:
    """
    Record notable JS observations.
    """

    phase_5 = phase_results.get(
        "phase_5"
    )

    if not isinstance(
        phase_5,
        dict,
    ):
        return

    analysis = phase_5.get(
        "analysis"
    )

    if not isinstance(
        analysis,
        dict,
    ):
        return

    totals = analysis.get(
        "totals",
        {},
    )

    if not isinstance(
        totals,
        dict,
    ):
        return

    # These are observations, not automatic vulnerabilities.

    if totals.get(
        "eval()",
        0,
    ) > 0:

        _add_finding(
            findings,
            "JS-OBS-001",
            "JavaScript uses eval()",
            "Informational",
            "JavaScript Observation",
            "CWE-95",
            "The downloaded JavaScript contains calls to eval().",
            (
                f"eval() occurrences: "
                f"{totals.get('eval()', 0)}"
            ),
            "eval() can increase risk when untrusted data reaches the evaluated expression.",
            "Review each usage and replace eval() with safer alternatives where possible.",
            "Phase 5",
        )

    if totals.get(
        "document.cookie",
        0,
    ) > 0:

        _add_finding(
            findings,
            "JS-OBS-002",
            "JavaScript accesses document.cookie",
            "Informational",
            "JavaScript Observation",
            "CWE-1004",
            "The downloaded JavaScript accesses document.cookie.",
            (
                f"document.cookie occurrences: "
                f"{totals.get('document.cookie', 0)}"
            ),
            "Client-side cookie access should be reviewed to ensure sensitive cookies use appropriate security attributes.",
            "Review cookie usage and apply Secure, HttpOnly, and SameSite attributes where appropriate.",
            "Phase 5",
        )


def generate_findings(
    target,
    phase_results: Dict[str, Any],
    logger,
) -> List[Finding]:
    """
    Generate findings from reconnaissance results.
    """

    findings: List[Finding] = []

    _check_security_headers(
        findings,
        phase_results,
    )

    _check_http_exposure(
        findings,
        phase_results,
    )

    _check_sensitive_files(
        findings,
        phase_results,
    )

    _check_js_observations(
        findings,
        phase_results,
    )

    logger.info(
        "Finding engine generated %d findings.",
        len(findings),
    )

    return findings


def findings_to_dict(
    findings: List[Finding],
) -> List[dict]:
    """
    Convert findings to JSON-safe data.
    """

    return [
        asdict(finding)
        for finding in findings
    ]


def count_findings(
    findings: List[Finding],
) -> Dict[str, int]:
    """
    Count findings by severity.
    """

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:

        if finding.severity in counts:

            counts[
                finding.severity
            ] += 1

    return counts