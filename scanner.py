#!/usr/bin/env python3

"""
============================================================
Web Recon Scanner
============================================================

Purpose:
    Automated VAPT reconnaissance scanner.

Current implementation:
    Phase 1 - Target validation
    Phase 2 - HTTP/HTTPS reconnaissance

Future implementation:
    Phase 3 - Technology / Network reconnaissance
    Phase 4 - Homepage / JavaScript discovery
    Phase 5 - JavaScript analysis
    Phase 6 - Sensitive file checks
    Phase 7 - Finding engine
    Phase 8 - JSON / HTML reporting

IMPORTANT:
    scanner.py is the main orchestration file.

    Future phases should be inserted only at the
    clearly marked PHASE INSERTION POINTS below.

Usage:
    python scanner.py -u https://example.com
"""

import argparse
import logging
import sys
from pathlib import Path


# ============================================================
# CONFIGURATION IMPORTS
# ============================================================

from config import (
    LOG_DIR,
    OUTPUT_DIR,
    SCANNER_NAME,
    SCANNER_VERSION,
)


# ============================================================
# PHASE 1 IMPORTS
# ============================================================

from modules.target import (
    TargetValidationError,
    target_to_dict,
    validate_target,
)


# ============================================================
# PHASE 2 IMPORTS
# ============================================================

from modules.http_recon import (
    scan_http_https,
)


# ============================================================
# FUTURE PHASE IMPORTS
# ============================================================

# ------------------------------------------------------------
# PHASE 3
# ------------------------------------------------------------
# ============================================================
# PHASE 3 IMPORTS
# ============================================================

from modules.whatweb import (
    run_whatweb,
    whatweb_to_dict,
)

from modules.subdomains import (
    run_subfinder,
    subdomain_to_dict,
)

from modules.nmap_scan import (
    run_nmap,
    nmap_to_dict,
)
# ------------------------------------------------------------

# ============================================================
# PHASE 4 IMPORTS
# ============================================================

from modules.homepage import (
    download_homepage,
    homepage_to_dict,
)

from modules.javascript import (
    run_javascript_discovery,
    javascript_to_dict,
)


# ------------------------------------------------------------
# PHASE 5
# ------------------------------------------------------------
# ============================================================
# PHASE 5 IMPORTS
# ============================================================

from modules.js_analysis import (
    analyze_javascript,
    js_analysis_to_dict,
)
# ------------------------------------------------------------


# ============================================================
# PHASE 6 IMPORTS
# ============================================================

from modules.sensitive_files import (
    check_sensitive_files,
    sensitive_files_to_dict,
)
# ------------------------------------------------------------


# ============================================================
# PHASE 7 IMPORTS
# ============================================================

from modules.findings import (
    generate_findings,
    findings_to_dict,
    count_findings,
)

# ============================================================
# PHASE 8 IMPORTS
# ============================================================

from reporting.json_report import (
    generate_json_report,
)

from reporting.html_report import (
    generate_html_report,
)

# ============================================================
# TERMINAL COLORS
# ============================================================

RESET = "\033[0m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


# ============================================================
# TERMINAL DISPLAY HELPERS
# ============================================================

def print_banner():
    """
    Display scanner banner.
    """

    print(
        f"""
{CYAN}╔════════════════════════════════════════════════════════════╗
║                    Web Recon Scanner                       ║
║                  VAPT Reconnaissance Tool                  ║
╚════════════════════════════════════════════════════════════╝{RESET}
"""
    )


def print_success(message: str):
    """
    Print success message.
    """

    print(
        f"{GREEN}[+] {message}{RESET}"
    )


def print_info(message: str):
    """
    Print informational message.
    """

    print(
        f"{CYAN}[*] {message}{RESET}"
    )


def print_warning(message: str):
    """
    Print warning message.
    """

    print(
        f"{YELLOW}[!] {message}{RESET}"
    )


def print_error(message: str):
    """
    Print error message.
    """

    print(
        f"{RED}[!] {message}{RESET}"
    )


# ============================================================
# LOGGING
# ============================================================

def setup_logging() -> logging.Logger:
    """
    Configure scanner logging.

    Log file:

        logs/scanner.log
    """

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = LOG_DIR / "scanner.log"

    logger = logging.getLogger(
        "web-recon-scanner"
    )

    logger.setLevel(
        logging.INFO
    )

    # Prevent duplicate handlers.
    if logger.handlers:
        return logger

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )

    file_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    return logger


# ============================================================
# OUTPUT DIRECTORY
# ============================================================

def create_target_output_directory(
    hostname: str,
) -> Path:
    """
    Create target-specific output directory.

    Example:

        output/
        └── target.com/
    """

    target_directory = (
        OUTPUT_DIR / hostname
    )

    target_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return target_directory


# ============================================================
# CLI ARGUMENTS
# ============================================================

def parse_arguments():
    """
    Parse command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Web Recon Scanner - "
            "VAPT Reconnaissance Tool"
        )
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help=(
            "Target URL, "
            "e.g. https://example.com"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"{SCANNER_NAME} "
            f"{SCANNER_VERSION}"
        ),
    )

    return parser.parse_args()


# ============================================================
# PHASE 1
# TARGET VALIDATION
# ============================================================

def run_phase_1(
    target_url: str,
    logger: logging.Logger,
):
    """
    Execute Phase 1.

    Responsibilities:
        - URL validation
        - URL normalization
        - hostname extraction
        - scheme extraction
        - port extraction
        - DNS resolution
    """

    print_info(
        "Step 1 - Target Validation"
    )

    print()

    try:

        target = validate_target(
            target_url
        )

    except TargetValidationError as exc:

        print_error(
            f"Invalid target: {exc}"
        )

        logger.error(
            "Target validation failed: %s",
            exc,
        )

        return None

    except Exception as exc:

        print_error(
            f"Unexpected validation error: {exc}"
        )

        logger.exception(
            "Unexpected target validation error."
        )

        return None

    # --------------------------------------------------------
    # Display target
    # --------------------------------------------------------

    print_success(
        f"URL              : "
        f"{target.normalized_url}"
    )

    print_success(
        f"Hostname         : "
        f"{target.hostname}"
    )

    print_success(
        f"Scheme           : "
        f"{target.scheme}"
    )

    print_success(
        f"Port             : "
        f"{target.port}"
    )

    # --------------------------------------------------------
    # DNS resolution
    # --------------------------------------------------------

    if target.dns_resolved:

        print_success(
            "DNS Resolution   : Successful"
        )

        print_success(
            f"IP Address       : "
            f"{target.ip_address}"
        )

    else:

        print_warning(
            "DNS Resolution   : Failed"
        )

        logger.warning(
            "DNS resolution failed for %s",
            target.hostname,
        )

    print()

    logger.info(
        "Step 1 completed: %s",
        target.normalized_url,
    )

    return target


# ============================================================
# PHASE 2
# HTTP / HTTPS RECONNAISSANCE
# ============================================================

def run_phase_2(
    target,
    logger: logging.Logger,
):
    """
    Execute Phase 2.

    Responsibilities:
        - HTTP detection
        - HTTPS detection
        - status code
        - redirects
        - final URL
        - response headers
        - server
        - content type
        - cookies
        - security headers
    """

    print(
        "============================================================"
    )

    print_info(
        "Step 2 - HTTP Reconnaissance"
    )

    print(
        "============================================================"
    )

    print()

    # --------------------------------------------------------
    # Start HTTP/HTTPS scan
    # --------------------------------------------------------

    print_info(
        "Testing HTTP and HTTPS..."
    )

    results = scan_http_https(
        target.hostname
    )

    # --------------------------------------------------------
    # HTTP / HTTPS results
    # --------------------------------------------------------

    print()

    print_info(
        "HTTP/HTTPS Detection"
    )

    print()

    for protocol in (
        "http",
        "https",
    ):

        result = results.get(
            protocol
        )

        if result is None:
            continue

        print(
            f"    {protocol.upper()}"
        )

        # ----------------------------------------------------
        # Connection failed
        # ----------------------------------------------------

        if not result.reachable:

            print_warning(
                "      Status       : "
                "Unreachable"
            )

            print_warning(
                f"      Error        : "
                f"{result.error}"
            )

            print()

            continue

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        print_success(
            f"      Status       : "
            f"{result.status_code} "
            f"({result.reason})"
        )

        # ----------------------------------------------------
        # Final URL
        # ----------------------------------------------------

        print_success(
            f"      Final URL    : "
            f"{result.final_url}"
        )

        # ----------------------------------------------------
        # Redirect
        # ----------------------------------------------------

        if result.redirect_detected:

            print_success(
                f"      Redirect      : "
                f"Yes "
                f"({result.redirect_count})"
            )

        else:

            print_success(
                "      Redirect      : No"
            )

        print()

        # ----------------------------------------------------
        # Logging
        # ----------------------------------------------------

        logger.info(
            "%s: reachable=%s "
            "status=%s "
            "final_url=%s "
            "redirects=%s",
            protocol,
            result.reachable,
            result.status_code,
            result.final_url,
            result.redirect_count,
        )

    # ========================================================
    # RESPONSE INFORMATION
    # ========================================================

    print(
        "------------------------------------------------------------"
    )

    print_info(
        "Response Information"
    )

    print()

    # Prefer HTTPS response.
    preferred_result = results.get(
        "https"
    )

    if (
        preferred_result is None
        or not preferred_result.reachable
    ):

        preferred_result = results.get(
            "http"
        )

    if (
        preferred_result is None
        or not preferred_result.reachable
    ):

        print_warning(
            "No reachable HTTP/HTTPS endpoint."
        )

    else:

        # ----------------------------------------------------
        # Server
        # ----------------------------------------------------








        # ----------------------------------------------------
        # Content type
        # ----------------------------------------------------

        print_success(
            f"    Content-Type   : "
            f"{preferred_result.content_type or 'Not disclosed'}"
        )

        # ----------------------------------------------------
        # Content length
        # ----------------------------------------------------

        print_success(
            f"    Content-Length : "
            f"{preferred_result.content_length or 'Not disclosed'}"
        )

        # ----------------------------------------------------
        # Date
        # ----------------------------------------------------

        print_success(
            f"    Date           : "
            f"{preferred_result.date or 'Not disclosed'}"
        )

        # ----------------------------------------------------
        # Cookies
        # ----------------------------------------------------

        if preferred_result.cookies:

            print_success(
                f"    Cookies        : "
                f"{len(preferred_result.cookies)} "
                f"detected"
            )

        else:

            print_success(
                "    Cookies        : "
                "None detected"
            )

    print()

    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    print_info(
        "Security Headers"
    )

    print()

    if (
        preferred_result is not None
        and preferred_result.reachable
    ):

        for header in (
            preferred_result.security_headers
        ):

            if header.present:

                print(
                    f"    "
                    f"{header.name:<30}"
                    f" "
                    f"{GREEN}✅ Present{RESET}"
                )

            else:

                print(
                    f"    "
                    f"{header.name:<30}"
                    f" "
                    f"{RED}❌ Missing{RESET}"
                )

    else:

        print_warning(
            "Unable to analyze security headers."
        )

    print()

    logger.info(
        "Step 2 completed."
    )

    return results


# ============================================================
# PHASE 3 INSERTION POINT
# TECHNOLOGY / NETWORK RECONNAISSANCE
# ============================================================
# ============================================================
# PHASE 3
# TECHNOLOGY / NETWORK RECONNAISSANCE
# ============================================================

def run_phase_3(
    target,
    logger: logging.Logger,
):
    """
    Execute Phase 3.

    Responsibilities:

        - WhatWeb technology detection
        - Subdomain enumeration
        - Nmap service detection

    External tools:

        - WhatWeb
        - Subfinder
        - Nmap
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 3 - Technology & Network Reconnaissance"
    )

    print(
        "============================================================"
    )

    print()

    phase_3_results = {}

    # ========================================================
    # 3.1 WHATWEB
    # ========================================================

    print_info(
        "Running WhatWeb..."
    )

    logger.info(
        "Starting WhatWeb scan."
    )

    whatweb_result = run_whatweb(
        target.normalized_url
    )

    phase_3_results["whatweb"] = (
        whatweb_to_dict(
            whatweb_result
        )
    )

    if not whatweb_result.available:

        print_warning(
            "WhatWeb not found."
        )

        print_warning(
            f"    {whatweb_result.error}"
        )

    elif not whatweb_result.executed:

        print_warning(
            "WhatWeb could not be executed."
        )

        if whatweb_result.error:

            print_warning(
                f"    {whatweb_result.error}"
            )

    else:

        if whatweb_result.technologies:

            print_success(
                "Technologies detected:"
            )

            for technology in (
                whatweb_result.technologies
            ):

                print(
                    f"    {technology}"
                )

        else:

            print_warning(
                "No technologies parsed from WhatWeb."
            )

        if whatweb_result.error:

            logger.warning(
                "WhatWeb returned an error: %s",
                whatweb_result.error,
            )

    print()

    # ========================================================
    # 3.2 SUBDOMAIN ENUMERATION
    # ========================================================

    print_info(
        "Running subdomain enumeration..."
    )

    logger.info(
        "Starting Subfinder scan."
    )

    subfinder_result = run_subfinder(
        target.hostname
    )

    phase_3_results["subdomains"] = (
        subdomain_to_dict(
            subfinder_result
        )
    )

    if not subfinder_result.available:

        print_warning(
            "Subfinder not found."
        )

        print_warning(
            f"    {subfinder_result.error}"
        )

    elif not subfinder_result.executed:

        print_warning(
            "Subfinder could not be executed."
        )

        if subfinder_result.error:

            print_warning(
                f"    {subfinder_result.error}"
            )

    else:

        print_success(
            f"Subdomains found: "
            f"{len(subfinder_result.subdomains)}"
        )

        if subfinder_result.subdomains:

            for subdomain in (
                subfinder_result.subdomains
            ):

                print(
                    f"    {subdomain}"
                )

        else:

            print(
                "    No subdomains returned."
            )

        if subfinder_result.error:

            logger.warning(
                "Subfinder returned an error: %s",
                subfinder_result.error,
            )

    print()

    # ========================================================
    # 3.3 NMAP
    # ========================================================

    print_info(
        "Running Nmap service detection..."
    )

    print_info(
        "Command: nmap -sV -Pn -p 80,443 "
        f"{target.hostname}"
    )

    logger.info(
        "Starting Nmap scan."
    )

    nmap_result = run_nmap(
        target.hostname
    )

    phase_3_results["nmap"] = (
        nmap_to_dict(
            nmap_result
        )
    )

    if not nmap_result.available:

        print_warning(
            "Nmap not found."
        )

        print_warning(
            f"    {nmap_result.error}"
        )

    elif not nmap_result.executed:

        print_warning(
            "Nmap could not be executed."
        )

        if nmap_result.error:

            print_warning(
                f"    {nmap_result.error}"
            )

    else:

        open_ports = [
            port
            for port in nmap_result.ports
            if port.state == "open"
        ]

        print_success(
            f"Open ports found: "
            f"{len(open_ports)}"
        )

        if open_ports:

            for port in open_ports:

                version_text = ""

                if port.version:

                    version_text = (
                        f" - {port.version}"
                    )

                print(
                    f"    "
                    f"{port.port}/{port.protocol}"
                    f"    "
                    f"{port.service}"
                    f"{version_text}"
                )

        else:

            print(
                "    No open ports detected."
            )

        if nmap_result.error:

            logger.warning(
                "Nmap returned an error: %s",
                nmap_result.error,
            )

    # ========================================================
    # PHASE 3 COMPLETE
    # ========================================================

    print()

    print(
        "------------------------------------------------------------"
    )

    print_success(
        "Step 3 completed."
    )

    print()

    logger.info(
        "Phase 3 completed successfully."
    )

    return phase_3_results


# ============================================================
# PHASE 4
# HOMEPAGE / JAVASCRIPT DISCOVERY
# ============================================================

def run_phase_4(
    target,
    target_output,
    logger,
):
    """
    Download homepage and discover JavaScript.
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 4 - Homepage & JavaScript Discovery"
    )

    print(
        "============================================================"
    )

    print()

    phase_4_results = {}

    # --------------------------------------------------------
    # Homepage
    # --------------------------------------------------------

    print_info(
        "Downloading homepage..."
    )

    homepage_dir = (
        target_output / "homepage"
    )

    homepage_result = download_homepage(
        target.normalized_url,
        homepage_dir,
    )

    phase_4_results["homepage"] = (
        homepage_to_dict(
            homepage_result
        )
    )

    if not homepage_result.downloaded:

        print_error(
            "Homepage download failed."
        )

        if homepage_result.error:

            print_warning(
                f"    {homepage_result.error}"
            )

        return phase_4_results

    print_success(
        f"Homepage Status : "
        f"{homepage_result.status_code}"
    )

    print_success(
        f"Homepage File   : "
        f"{homepage_result.html_file}"
    )

    print_success(
        f"Content Length  : "
        f"{homepage_result.content_length} bytes"
    )

    # --------------------------------------------------------
    # Read homepage
    # --------------------------------------------------------

    try:

        homepage_html = Path(
            homepage_result.html_file
        ).read_text(
            encoding="utf-8",
            errors="replace",
        )

    except OSError as exc:

        print_error(
            f"Unable to read homepage: {exc}"
        )

        logger.exception(
            "Homepage read failed."
        )

        return phase_4_results

    # --------------------------------------------------------
    # JavaScript discovery
    # --------------------------------------------------------

    print()

    print_info(
        "Extracting JavaScript files..."
    )

    js_dir = (
        target_output / "js"
    )

    javascript_result = (
        run_javascript_discovery(
            homepage_html,
            homepage_result.final_url
            or target.normalized_url,
            js_dir,
        )
    )

    phase_4_results["javascript"] = (
        javascript_to_dict(
            javascript_result
        )
    )

    print_success(
        f"JavaScript URLs : "
        f"{len(javascript_result.urls)}"
    )

    if javascript_result.urls:

        for url in javascript_result.urls:

            print(
                f"    {url}"
            )

    else:

        print(
            "    No JavaScript files found."
        )

    # --------------------------------------------------------
    # JS downloads
    # --------------------------------------------------------

    print()

    print_info(
        "Downloading JavaScript files..."
    )

    downloaded_count = sum(
        1
        for item in javascript_result.files
        if item.downloaded
    )

    failed_count = sum(
        1
        for item in javascript_result.files
        if not item.downloaded
    )

    print_success(
        f"Downloaded      : "
        f"{downloaded_count}"
    )

    if failed_count:

        print_warning(
            f"Failed          : "
            f"{failed_count}"
        )

    for item in javascript_result.files:

        if item.downloaded:

            print(
                f"    [+] {item.local_file}"
            )

        else:

            print(
                f"    [!] {item.url}"
            )

    print()

    print(
        "------------------------------------------------------------"
    )

    print_success(
        "Step 4 completed."
    )

    logger.info(
        "Phase 4 completed: JS URLs=%d downloaded=%d",
        len(javascript_result.urls),
        downloaded_count,
    )

    return phase_4_results


# ============================================================
# ============================================================
# PHASE 5
# JAVASCRIPT ANALYSIS
# ============================================================

def run_phase_5(
    target,
    target_output,
    logger,
):
    """
    Analyze downloaded JavaScript files.
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 5 - JavaScript Analysis"
    )

    print(
        "============================================================"
    )

    print()

    js_directory = (
        target_output / "js"
    )

    phase_5_results = {
        "javascript_directory": str(
            js_directory
        ),
        "analysis": None,
    }

    # --------------------------------------------------------
    # Check JS directory
    # --------------------------------------------------------

    if not js_directory.exists():

        print_warning(
            "JavaScript directory not found."
        )

        print_warning(
            f"    {js_directory}"
        )

        logger.warning(
            "Phase 5 JS directory does not exist: %s",
            js_directory,
        )

        return phase_5_results

    # --------------------------------------------------------
    # Analyze JavaScript
    # --------------------------------------------------------

    print_info(
        "Analyzing JavaScript files..."
    )

    result = analyze_javascript(
        js_directory
    )

    phase_5_results["analysis"] = (
        js_analysis_to_dict(
            result
        )
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()

    print_success(
        f"Files analyzed  : "
        f"{result.files_analyzed}"
    )

    if result.files_failed:

        print_warning(
            f"Files failed    : "
            f"{result.files_failed}"
        )

    print()

    print_info(
        "JS Pattern Results"
    )

    print()

    for name, count in (
        result.totals.items()
    ):

        print(
            f"    {name:<20}: "
            f"{count} occurrences"
        )

    # --------------------------------------------------------
    # File results
    # --------------------------------------------------------

    print()

    print_info(
        "Per-file Results"
    )

    print()

    for analysis in result.files:

        filename = Path(
            analysis.file
        ).name

        if analysis.error:

            print_warning(
                f"    {filename}: "
                f"{analysis.error}"
            )

            continue

        print(
            f"    {filename}"
        )

        for name, count in (
            analysis.patterns.items()
        ):

            if count:

                print(
                    f"        "
                    f"{name:<18}: "
                    f"{count}"
                )

    print()

    print(
        "------------------------------------------------------------"
    )

    print_success(
        "Step 5 completed."
    )

    logger.info(
        "Phase 5 completed: files=%d failed=%d",
        result.files_analyzed,
        result.files_failed,
    )

    return phase_5_results
# ============================================================
# PHASE 6 INSERTION POINT
# SENSITIVE FILE CHECKS
# ============================================================

# ============================================================
# PHASE 6
# SENSITIVE FILE CHECKS
# ============================================================

def run_phase_6(
    target,
    logger,
):
    """
    Check common sensitive and metadata files.
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 6 - Sensitive File Checks"
    )

    print(
        "============================================================"
    )

    print()

    print_info(
        "Checking common files..."
    )

    results = check_sensitive_files(
        target.normalized_url
    )

    phase_6_results = {
        "files": sensitive_files_to_dict(
            results
        )
    }

    print()

    print_info(
        "Sensitive File Results"
    )

    print()

    for result in results:

        if result.status_code is None:

            print(
                f"    {result.path:<20} "
                f": ERROR"
            )

            if result.error:

                print(
                    f"        {result.error}"
                )

            continue

        if result.status_code == 200:

            status_text = (
                f"{GREEN}200{RESET}"
            )

        elif result.status_code in (
            401,
            403,
        ):

            status_text = (
                f"{YELLOW}"
                f"{result.status_code}"
                f"{RESET}"
            )

        else:

            status_text = (
                f"{result.status_code}"
            )

        print(
            f"    {result.path:<20} "
            f": {status_text}"
        )

        if result.content_type:

            print(
                f"        Content-Type : "
                f"{result.content_type}"
            )

        print(
            f"        Size         : "
            f"{result.content_length} bytes"
        )

    print()

    print(
        "------------------------------------------------------------"
    )

    print_success(
        "Step 6 completed."
    )

    logger.info(
        "Phase 6 completed: checked=%d",
        len(results),
    )

    return phase_6_results


# ============================================================
# PHASE 7
# FINDING ENGINE
# ============================================================

def run_phase_7(
    target,
    phase_results,
    logger,
):
    """
    Generate findings from scan results.
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 7 - Finding Engine"
    )

    print(
        "============================================================"
    )

    print()

    print_info(
        "Analyzing reconnaissance results..."
    )

    findings = generate_findings(
        target,
        phase_results,
        logger,
    )

    finding_data = findings_to_dict(
        findings
    )

    severity_counts = count_findings(
        findings
    )

    phase_7_results = {
        "findings": finding_data,
        "counts": severity_counts,
        "total": len(findings),
    }

    print()

    print_info(
        "Finding Summary"
    )

    print()

    print(
        f"    Critical       : "
        f"{severity_counts['Critical']}"
    )

    print(
        f"    High           : "
        f"{severity_counts['High']}"
    )

    print(
        f"    Medium         : "
        f"{severity_counts['Medium']}"
    )

    print(
        f"    Low            : "
        f"{severity_counts['Low']}"
    )

    print(
        f"    Informational  : "
        f"{severity_counts['Informational']}"
    )

    print()

    if findings:

        print_info(
            "Findings"
        )

        print()

        for finding in findings:

            print(
                f"    [{finding.severity}] "
                f"{finding.id} - "
                f"{finding.title}"
            )

    else:

        print_success(
            "No findings generated."
        )

    print()

    print(
        "------------------------------------------------------------"
    )

    print_success(
        f"Step 7 completed. "
        f"Findings: {len(findings)}"
    )

    logger.info(
        "Phase 7 completed: findings=%d",
        len(findings),
    )

    return phase_7_results



# ============================================================
# PHASE 8 INSERTION POINT
# REPORTING
# ============================================================

# ============================================================
# PHASE 8
# REPORTING
# ============================================================

def run_phase_8(
    target,
    phase_results,
    findings,
    target_output,
    logger,
):
    """
    Generate JSON and HTML reports.
    """

    print()

    print(
        "============================================================"
    )

    print_info(
        "Step 8 - Report Generation"
    )

    print(
        "============================================================"
    )

    print()

    report_results = {}

    # --------------------------------------------------------
    # JSON report
    # --------------------------------------------------------

    print_info(
        "Generating JSON report..."
    )

    try:

        json_file = generate_json_report(
            target,
            phase_results,
            findings,
            target_output,
        )

        report_results["json"] = str(
            json_file
        )

        print_success(
            f"JSON Report     : "
            f"{json_file}"
        )

    except Exception as exc:

        print_error(
            f"JSON report failed: {exc}"
        )

        logger.exception(
            "JSON report generation failed."
        )

        report_results["json"] = None

    # --------------------------------------------------------
    # HTML report
    # --------------------------------------------------------

    print()

    print_info(
        "Generating HTML report..."
    )

    try:

        html_file = generate_html_report(
            target,
            phase_results,
            findings,
            target_output,
        )

        report_results["html"] = str(
            html_file
        )

        print_success(
            f"HTML Report     : "
            f"{html_file}"
        )

    except Exception as exc:

        print_error(
            f"HTML report failed: {exc}"
        )

        logger.exception(
            "HTML report generation failed."
        )

        report_results["html"] = None

    print()

    print(
        "------------------------------------------------------------"
    )

    if (
        report_results["json"]
        or report_results["html"]
    ):

        print_success(
            "Step 8 completed."
        )

    else:

        print_error(
            "Phase 8 failed."
        )

    logger.info(
        "Phase 8 completed."
    )

    return report_results

# ============================================================
# MAIN SCANNER ORCHESTRATOR
# ============================================================

def main():
    """
    Main scanner execution flow.

    Future phases are intentionally kept as separate
    insertion points so scanner.py remains organized.
    """

    print_banner()

    logger = setup_logging()

    logger.info(
        "%s %s started",
        SCANNER_NAME,
        SCANNER_VERSION,
    )

    # ========================================================
    # ARGUMENT PARSING
    # ========================================================

    try:

        args = parse_arguments()

    except SystemExit:

        raise

    except Exception as exc:

        print_error(
            f"Unable to parse arguments: {exc}"
        )

        logger.exception(
            "Argument parsing failed."
        )

        return 1

    target_url = args.url

    logger.info(
        "Target supplied: %s",
        target_url,
    )

    # ========================================================
    # PHASE 1
    # ========================================================

    target = run_phase_1(
        target_url,
        logger,
    )

    if target is None:

        return 1

    # ========================================================
    # OUTPUT DIRECTORY
    # ========================================================

    try:

        target_output = (
            create_target_output_directory(
                target.hostname
            )
        )

        print_success(
            f"Output Directory : "
            f"{target_output}"
        )

        logger.info(
            "Output directory: %s",
            target_output,
        )

    except OSError as exc:

        print_error(
            f"Unable to create output directory: "
            f"{exc}"
        )

        logger.exception(
            "Output directory creation failed."
        )

        return 1

    # ========================================================
    # LOG FILE
    # ========================================================

    log_file = (
        LOG_DIR / "scanner.log"
    )

    print_success(
        f"Log File         : {log_file}"
    )

    print()

    # ========================================================
    # PHASE RESULTS
    #
    # All phase results will eventually be stored here.
    #
    # This dictionary becomes the main data source for:
    #
    #     Phase 7 - Finding Engine
    #     Phase 8 - JSON Report
    #     Phase 8 - HTML Report
    #
    # ========================================================

    phase_results = {}

    # ========================================================
    # STORE PHASE 1 RESULT
    # ========================================================

    phase_results["target"] = (
        target_to_dict(target)
    )

    # ========================================================
    # PHASE 2
    # ========================================================

    try:

        http_results = run_phase_2(
            target,
            logger,
        )

        phase_results["http"] = (
            http_results
        )

    except Exception as exc:

        print_error(
            f"Phase 2 failed: {exc}"
        )

        logger.exception(
            "Phase 2 failed."
        )

        # Continue to future phases.
        #
        # A failed phase should not necessarily
        # terminate the entire reconnaissance scan.

        phase_results["http"] = None

    # ========================================================
    # PHASE 3 INSERTION POINT
    #
    # ========================================================
    # PHASE 3
    # ========================================================

    try:

        phase_results["phase_3"] = run_phase_3(
            target,
            logger,
        )

    except Exception as exc:

        print_error(
            f"Phase 3 failed: {exc}"
        )

        logger.exception(
            "Phase 3 failed."
        )

        phase_results["phase_3"] = None


        # ========================================================
    # PHASE 4
    # ========================================================

    try:

        phase_results["phase_4"] = run_phase_4(
            target,
            target_output,
            logger,
        )

    except Exception as exc:

        print_error(
            f"Phase 4 failed: {exc}"
        )

        logger.exception(
            "Phase 4 failed."
        )

        phase_results["phase_4"] = None


    # ========================================================
        # ========================================================
    # PHASE 5
    # ========================================================

    try:

        phase_results["phase_5"] = run_phase_5(
            target,
            target_output,
            logger,
        )

    except Exception as exc:

        print_error(
            f"Phase 5 failed: {exc}"
        )

        logger.exception(
            "Phase 5 failed."
        )

        phase_results["phase_5"] = None


       # ========================================================
    # PHASE 6
    # ========================================================

    try:

        phase_results["phase_6"] = run_phase_6(
            target,
            logger,
        )

    except Exception as exc:

        print_error(
            f"Phase 6 failed: {exc}"
        )

        logger.exception(
            "Phase 6 failed."
        )

        phase_results["phase_6"] = None


        # ========================================================
    # PHASE 7
    # ========================================================

    try:

        phase_7_results = run_phase_7(
            target,
            phase_results,
            logger,
        )

        phase_results["phase_7"] = (
            phase_7_results
        )

        findings = phase_7_results.get(
            "findings",
            [],
        )

    except Exception as exc:

        print_error(
            f"Phase 7 failed: {exc}"
        )

        logger.exception(
            "Phase 7 failed."
        )

        phase_results["phase_7"] = None

        findings = []


        # ========================================================
    # PHASE 8
    # ========================================================

    try:

        phase_results["phase_8"] = run_phase_8(
            target,
            phase_results,
            findings,
            target_output,
            logger,
        )

    except Exception as exc:

        print_error(
            f"Phase 8 failed: {exc}"
        )

        logger.exception(
            "Phase 8 failed."
        )

        phase_results["phase_8"] = None


    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print(
        "============================================================"
    )

    print_success(
        "Scan completed."
    )

    print_success(
        f"Target           : "
        f"{target.normalized_url}"
    )

    print_success(
        f"Output Directory : "
        f"{target_output}"
    )

    print(
        "============================================================"
    )

    print()

    logger.info(
        "Scanner completed successfully."
    )

    return 0


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        sys.exit(
            main()
        )

    except KeyboardInterrupt:

        print()

        print_warning(
            "Scan interrupted by user."
        )

        sys.exit(130)

    except Exception as exc:

        print_error(
            f"Unexpected scanner error: {exc}"
        )

        sys.exit(1)