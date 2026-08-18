"""
HTML report generation.
"""

import html
from pathlib import Path
from typing import Any


def esc(value: Any) -> str:
    """
    HTML escape helper.
    """

    if value is None:
        return ""

    return html.escape(
        str(value)
    )


def severity_class(
    severity: str,
) -> str:
    """
    Return CSS class for severity.
    """

    return {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Informational": "info",
    }.get(
        severity,
        "info",
    )


def render_findings(
    findings: list,
) -> str:
    """
    Render finding cards.
    """

    if not findings:

        return """
        <div class="empty">
            No findings generated.
        </div>
        """

    rows = []

    for finding in findings:

        severity = esc(
            finding.get(
                "severity",
                "Informational",
            )
        )

        rows.append(
            f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="badge {severity_class(severity)}">
                        {severity}
                    </span>

                    <strong>
                        {esc(finding.get("id"))}
                        -
                        {esc(finding.get("title"))}
                    </strong>
                </div>

                <div class="finding-grid">
                    <div>
                        <b>Category</b>
                        <p>{esc(finding.get("category"))}</p>
                    </div>

                    <div>
                        <b>CWE</b>
                        <p>{esc(finding.get("cwe"))}</p>
                    </div>

                    <div>
                        <b>Source</b>
                        <p>{esc(finding.get("source"))}</p>
                    </div>
                </div>

                <b>Description</b>
                <p>{esc(finding.get("description"))}</p>

                <b>Evidence</b>
                <pre>{esc(finding.get("evidence"))}</pre>

                <b>Impact</b>
                <p>{esc(finding.get("impact"))}</p>

                <b>Remediation</b>
                <p>{esc(finding.get("remediation"))}</p>
            </div>
            """
        )

    return "\n".join(rows)


def render_security_headers(
    http_data: dict,
) -> str:
    """
    Render security headers.
    """

    if not isinstance(
        http_data,
        dict,
    ):
        return "<p>No HTTP data.</p>"

    preferred = http_data.get(
        "https"
    )

    if not isinstance(
        preferred,
        dict,
    ) or not preferred.get(
        "reachable"
    ):

        preferred = http_data.get(
            "http"
        )

    if not isinstance(
        preferred,
        dict,
    ):
        return "<p>No reachable endpoint.</p>"

    headers = preferred.get(
        "security_headers",
        [],
    )

    if not headers:
        return "<p>No security-header data.</p>"

    rows = []

    for header in headers:

        if not isinstance(
            header,
            dict,
        ):
            continue

        present = header.get(
            "present",
            False,
        )

        status = (
            "Present"
            if present
            else "Missing"
        )

        symbol = (
            "&#9989;"
            if present
            else "&#10060;"
        )

        rows.append(
            f"""
            <tr>
                <td>{esc(header.get("name"))}</td>
                <td>{symbol} {status}</td>
            </tr>
            """
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Header</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def render_http(
    http_data: dict,
) -> str:
    """
    Render HTTP/HTTPS information.
    """

    if not isinstance(
        http_data,
        dict,
    ):
        return "<p>No HTTP data.</p>"

    rows = []

    for protocol in (
        "http",
        "https",
    ):

        result = http_data.get(
            protocol
        )

        if not isinstance(
            result,
            dict,
        ):
            continue

        rows.append(
            f"""
            <tr>
                <td>{esc(protocol.upper())}</td>
                <td>{esc(result.get("status_code"))}</td>
                <td>{esc(result.get("final_url"))}</td>
                <td>{esc(result.get("redirect_count"))}</td>
                <td>{esc(result.get("server"))}</td>
            </tr>
            """
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Protocol</th>
                <th>Status</th>
                <th>Final URL</th>
                <th>Redirects</th>
                <th>Server</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def render_phase3(
    phase3: dict,
) -> str:
    """
    Render WhatWeb, subdomains and Nmap.
    """

    if not isinstance(
        phase3,
        dict,
    ):
        return "<p>No Phase 3 data.</p>"

    sections = []

    whatweb = phase3.get(
        "whatweb",
        {},
    )

    technologies = (
        whatweb.get(
            "technologies",
            [],
        )
        if isinstance(
            whatweb,
            dict,
        )
        else []
    )

    sections.append(
        "<h3>Technologies</h3>"
        + (
            "<ul>"
            + "".join(
                f"<li>{esc(item)}</li>"
                for item in technologies
            )
            + "</ul>"
            if technologies
            else "<p>None detected.</p>"
        )
    )

    subdomains = phase3.get(
        "subdomains",
        {},
    )

    subdomain_list = (
        subdomains.get(
            "subdomains",
            [],
        )
        if isinstance(
            subdomains,
            dict,
        )
        else []
    )

    sections.append(
        "<h3>Subdomains</h3>"
        + (
            "<ul>"
            + "".join(
                f"<li>{esc(item)}</li>"
                for item in subdomain_list
            )
            + "</ul>"
            if subdomain_list
            else "<p>None found.</p>"
        )
    )

    nmap = phase3.get(
        "nmap",
        {},
    )

    ports = (
        nmap.get(
            "ports",
            [],
        )
        if isinstance(
            nmap,
            dict,
        )
        else []
    )

    port_rows = []

    for port in ports:

        if port.get("state") != "open":
            continue

        port_rows.append(
            f"""
            <tr>
                <td>{esc(port.get("port"))}</td>
                <td>{esc(port.get("protocol"))}</td>
                <td>{esc(port.get("service"))}</td>
                <td>{esc(port.get("version"))}</td>
            </tr>
            """
        )

    sections.append(
        "<h3>Open Ports</h3>"
        + (
            f"""
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(port_rows)}
                </tbody>
            </table>
            """
            if port_rows
            else "<p>No open ports detected.</p>"
        )
    )

    return "".join(sections)


def render_phase4(
    phase4: dict,
) -> str:
    """
    Render homepage and JavaScript discovery.
    """

    if not isinstance(
        phase4,
        dict,
    ):
        return "<p>No Phase 4 data.</p>"

    homepage = phase4.get(
        "homepage",
        {},
    )

    javascript = phase4.get(
        "javascript",
        {},
    )

    html_file = (
        homepage.get("html_file")
        if isinstance(
            homepage,
            dict,
        )
        else None
    )

    urls = (
        javascript.get(
            "urls",
            [],
        )
        if isinstance(
            javascript,
            dict,
        )
        else []
    )

    return f"""
    <h3>Homepage</h3>

    <table>
        <tr>
            <th>Status</th>
            <td>{esc(homepage.get("status_code"))}</td>
        </tr>
        <tr>
            <th>Final URL</th>
            <td>{esc(homepage.get("final_url"))}</td>
        </tr>
        <tr>
            <th>Local File</th>
            <td>{esc(html_file)}</td>
        </tr>
    </table>

    <h3>JavaScript Files</h3>

    {
        "<ul>"
        + "".join(
            f"<li>{esc(url)}</li>"
            for url in urls
        )
        + "</ul>"
        if urls
        else "<p>No JavaScript files found.</p>"
    }
    """


def render_phase5(
    phase5: dict,
) -> str:
    """
    Render JavaScript analysis.
    """

    if not isinstance(
        phase5,
        dict,
    ):
        return "<p>No Phase 5 data.</p>"

    analysis = phase5.get(
        "analysis",
        {},
    )

    if not isinstance(
        analysis,
        dict,
    ):
        return "<p>No JS analysis data.</p>"

    totals = analysis.get(
        "totals",
        {},
    )

    rows = []

    for name, count in totals.items():

        rows.append(
            f"""
            <tr>
                <td>{esc(name)}</td>
                <td>{esc(count)}</td>
            </tr>
            """
        )

    return f"""
    <p>
        Files analyzed:
        <strong>{esc(analysis.get("files_analyzed", 0))}</strong>
    </p>

    <table>
        <thead>
            <tr>
                <th>Pattern</th>
                <th>Occurrences</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def render_phase6(
    phase6: dict,
) -> str:
    """
    Render sensitive-file results.
    """

    if not isinstance(
        phase6,
        dict,
    ):
        return "<p>No Phase 6 data.</p>"

    files = phase6.get(
        "files",
        [],
    )

    rows = []

    for item in files:

        status = item.get(
            "status_code"
        )

        if status == 200:
            symbol = "&#9989;"
        elif status in (
            401,
            403,
        ):
            symbol = "&#9888;&#65039;"
        else:
            symbol = "&#10060;"

        rows.append(
            f"""
            <tr>
                <td>{esc(item.get("path"))}</td>
                <td>{symbol} {esc(status)}</td>
                <td>{esc(item.get("content_type"))}</td>
                <td>{esc(item.get("content_length"))}</td>
            </tr>
            """
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Path</th>
                <th>Status</th>
                <th>Content-Type</th>
                <th>Size</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def generate_html_report(
    target,
    phase_results: dict,
    findings,
    output_dir: Path,
) -> Path:
    """
    Generate report.html.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    target_data = phase_results.get(
        "target",
        {},
    )

    http_data = phase_results.get(
        "http",
        {},
    )

    phase3 = phase_results.get(
        "phase_3",
        {},
    )

    phase4 = phase_results.get(
        "phase_4",
        {},
    )

    phase5 = phase_results.get(
        "phase_5",
        {},
    )

    phase6 = phase_results.get(
        "phase_6",
        {},
    )

    phase7 = phase_results.get(
        "phase_7",
        {},
    ) or {}

    counts = phase7.get(
        "counts",
        {},
    )

    finding_total = phase7.get(
        "total",
        len(findings),
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>
    Web Recon Scanner - {esc(target.hostname)}
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background: #f4f6f8;
    color: #1f2937;
}}

.container {{
    width: 92%;
    max-width: 1250px;
    margin: 30px auto;
}}

.header {{
    background: #111827;
    color: white;
    padding: 28px;
    border-radius: 10px;
}}

.header h1 {{
    margin: 0 0 8px 0;
}}

.header p {{
    margin: 4px 0;
}}

.card {{
    background: white;
    margin-top: 20px;
    padding: 22px;
    border-radius: 10px;
    box-shadow:
        0 2px 8px rgba(0,0,0,0.06);
}}

.card h2 {{
    margin-top: 0;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 10px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th,
td {{
    padding: 10px;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}}

th {{
    background: #f9fafb;
}}

pre {{
    background: #111827;
    color: #e5e7eb;
    padding: 12px;
    border-radius: 6px;
    overflow-x: auto;
}}

.summary {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
}}

.stat {{
    background: #f9fafb;
    padding: 18px;
    border-radius: 8px;
    text-align: center;
}}

.stat .number {{
    display: block;
    font-size: 28px;
    font-weight: bold;
    margin-bottom: 5px;
}}

.critical {{
    color: #991b1b;
}}

.high {{
    color: #b91c1c;
}}

.medium {{
    color: #b45309;
}}

.low {{
    color: #0369a1;
}}

.info {{
    color: #374151;
}}

.badge {{
    display: inline-block;
    padding: 5px 9px;
    border-radius: 5px;
    font-size: 12px;
    font-weight: bold;
    margin-right: 8px;
    background: #e5e7eb;
}}

.finding {{
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 18px;
    margin-top: 15px;
}}

.finding-header {{
    margin-bottom: 15px;
}}

.finding-grid {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}}

.empty {{
    padding: 15px;
    background: #f9fafb;
    border-radius: 6px;
}}

.footer {{
    text-align: center;
    color: #6b7280;
    padding: 30px;
}}

</style>

</head>

<body>

<div class="container">

    <div class="header">

        <h1>
            Web Recon Scanner
        </h1>

        <p>
            VAPT Reconnaissance Report
        </p>

        <p>
            Target:
            <strong>
                {esc(target_data.get("normalized_url"))}
            </strong>
        </p>

        <p>
            Hostname:
            {esc(target_data.get("hostname"))}
        </p>

    </div>


    <div class="card">

        <h2>
            Finding Summary
        </h2>

        <div class="summary">

            <div class="stat">
                <span class="number">
                    {esc(finding_total)}
                </span>
                Total
            </div>

            <div class="stat critical">
                <span class="number">
                    {esc(counts.get("Critical", 0))}
                </span>
                Critical
            </div>

            <div class="stat high">
                <span class="number">
                    {esc(counts.get("High", 0))}
                </span>
                High
            </div>

            <div class="stat medium">
                <span class="number">
                    {esc(counts.get("Medium", 0))}
                </span>
                Medium
            </div>

            <div class="stat low">
                <span class="number">
                    {esc(counts.get("Low", 0))}
                </span>
                Low
            </div>

            <div class="stat info">
                <span class="number">
                    {esc(counts.get("Informational", 0))}
                </span>
                Informational
            </div>

        </div>

    </div>


    <div class="card">

        <h2>
            Target Information
        </h2>

        <table>

            <tr>
                <th>Normalized URL</th>
                <td>
                    {esc(target_data.get("normalized_url"))}
                </td>
            </tr>

            <tr>
                <th>Hostname</th>
                <td>
                    {esc(target_data.get("hostname"))}
                </td>
            </tr>

            <tr>
                <th>Scheme</th>
                <td>
                    {esc(target_data.get("scheme"))}
                </td>
            </tr>

            <tr>
                <th>Port</th>
                <td>
                    {esc(target_data.get("port"))}
                </td>
            </tr>

            <tr>
                <th>IP Address</th>
                <td>
                    {esc(target_data.get("ip_address"))}
                </td>
            </tr>

        </table>

    </div>


    <div class="card">

        <h2>
            HTTP / HTTPS Reconnaissance
        </h2>

        {render_http(http_data)}

    </div>


    <div class="card">

        <h2>
            Security Headers
        </h2>

        {render_security_headers(http_data)}

    </div>


    <div class="card">

        <h2>
            Technology & Network Reconnaissance
        </h2>

        {render_phase3(phase3)}

    </div>


    <div class="card">

        <h2>
            Homepage & JavaScript Discovery
        </h2>

        {render_phase4(phase4)}

    </div>


    <div class="card">

        <h2>
            JavaScript Analysis
        </h2>

        {render_phase5(phase5)}

    </div>


    <div class="card">

        <h2>
            Sensitive Files
        </h2>

        {render_phase6(phase6)}

    </div>


    <div class="card">

        <h2>
            Findings
        </h2>

        {render_findings(findings)}

    </div>


    <div class="footer">

        Generated by Web Recon Scanner

    </div>

</div>

</body>

</html>
"""

    report_file = (
        output_dir / "report.html"
    )

    report_file.write_text(
        html_content,
        encoding="utf-8",
    )

    return report_file