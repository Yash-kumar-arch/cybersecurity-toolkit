from html import escape
from datetime import datetime

def format_title(title):

    title_map = {
        "robots.txt": "Robots.txt",
        "Directory listing detection": "Directory Listing Detection",
        "Backup file discovery": "Backup File Discovery",
        "security_headers": "Security Headers",
        "server_fingerprinting": "Server Fingerprinting",
        "form_discovery": "Form Discovery",
        "technology_detection": "Technology Detection",
        "cookie_analysis": "Cookie Analysis",
        "Technology_Detection": "Technology Detection",
        "crawler": "Website Crawler"
    }

    return title_map.get(title, title.replace("_", " ").title())


def format_percentage(score):

    try:
        return f"{float(score) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def get_severity_class(severity):

    severity = str(severity).upper()

    if severity == "HIGH":
        return "high"

    elif severity == "MEDIUM":
        return "medium"

    elif severity == "LOW":
        return "low"

    elif severity == "INFO":
        return "info"

    else:
        return "neutral"


def get_status_class(status):

    status = str(status).upper()

    if status in ["HIGH", "WEAK", "MISSING", "INVALID"]:
        return "status-danger"

    elif status in ["MEDIUM", "ACCEPTABLE"]:
        return "status-warning"

    elif status in ["OK", "DETECTED"]:
        return "status-success"

    elif status in ["ERROR", "INCONCLUSIVE"]:
        return "status-neutral"

    else:
        return "status-neutral"


def calculate_summary(final_report):

    high = 0
    medium = 0
    low = 0
    info = 0
    total_findings = 0

    # Domain-level results
    for result in final_report.get("domain_results", []):

        severity = str(
            result.get("severity", "INFO")
        ).upper()

        if severity == "HIGH":
            high += 1

        elif severity == "MEDIUM":
            medium += 1

        elif severity == "LOW":
            low += 1

        else:
            info += 1

        if result.get("findings"):
            total_findings += len(result["findings"])

    # Page-level results
    for findings in final_report.get("page_results", {}).values():

        for result in findings:

            severity = str(
                result.get("severity", "INFO")
            ).upper()

            if severity == "HIGH":
                high += 1

            elif severity == "MEDIUM":
                medium += 1

            elif severity == "LOW":
                low += 1

            else:
                info += 1

            if result.get("findings"):
                total_findings += len(result["findings"])

    return {
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "total_findings": total_findings
    }


def generate_html_report(
        final_report,
        output_file="scan_report.html"
):

    target_url = escape(
        str(final_report.get("target_url", "Unknown"))
    )

    pages_scanned = final_report.get(
        "pages_scanned",
        0
    )

    overall_risk = str(
        final_report.get(
            "overall_risk_level",
            "UNKNOWN"
        )
    ).upper()

    total_score = final_report.get(
        "total_score",
        0
    )

    domain_results = final_report.get(
        "domain_results",
        []
    )

    page_results = final_report.get(
        "page_results",
        {}
    )

    page_scores = final_report.get(
        "page_scores",
        {}
    )

    affected_pages = final_report.get(
        "affected_pages",
        {}
    )

    summary = calculate_summary(
        final_report
    )

    scan_time = datetime.now().strftime(
        "%d %B %Y, %H:%M:%S"
    )

    overall_risk_class = get_severity_class(
        overall_risk
    )

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>Web Vulnerability Scan Report</title>


<style>

/* =========================
   GLOBAL
========================= */

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background: #f4f6f8;

    color: #1f2937;

}}

.container {{

    width: min(
        1400px,
        94%
    );

    margin: auto;

}}


/* =========================
   HEADER
========================= */

.header {{

    background:
        linear-gradient(
            135deg,
            #111827,
            #1f2937
        );

    color: white;

    padding: 38px 0;

}}

.header-content {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 30px;

    flex-wrap: wrap;

}}

.header h1 {{

    margin: 0 0 10px 0;

    font-size: 32px;

}}

.target-url {{

    color: #cbd5e1;

    word-break: break-all;

}}


/* =========================
   RISK BADGES
========================= */

.risk-badge {{

    padding: 14px 24px;

    border-radius: 12px;

    font-size: 18px;

    font-weight: 700;

    text-transform: uppercase;

    letter-spacing: 0.5px;

}}

.risk-badge.high {{

    background: #fee2e2;

    color: #991b1b;

}}

.risk-badge.medium {{

    background: #fef3c7;

    color: #92400e;

}}

.risk-badge.low {{

    background: #dcfce7;

    color: #166534;

}}

.risk-badge.info {{

    background: #dbeafe;

    color: #1e40af;

}}

.risk-badge.neutral {{

    background: #e5e7eb;

    color: #374151;

}}


/* =========================
   SUMMARY CARDS
========================= */

.summary-grid {{

    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                180px,
                1fr
            )
        );

    gap: 18px;

    margin: 30px 0;

}}

.summary-card {{

    background: white;

    border-radius: 14px;

    padding: 22px;

    box-shadow:
        0 4px 12px
        rgba(
            0,
            0,
            0,
            0.06
        );

}}

.summary-card h3 {{

    margin: 0;

    color: #6b7280;

    font-size: 14px;

    font-weight: 600;

}}

.summary-value {{

    font-size: 30px;

    font-weight: 750;

    margin-top: 10px;

}}


/* =========================
   SECTIONS
========================= */

.section {{

    margin: 34px 0;

}}

.section-title {{

    font-size: 24px;

    margin-bottom: 18px;

    font-weight: 750;

}}


/* =========================
   SUMMARY TABLE
========================= */

.table-wrapper {{

    background: white;

    border-radius: 14px;

    overflow-x: auto;

    box-shadow:
        0 4px 12px
        rgba(
            0,
            0,
            0,
            0.06
        );

}}

table {{

    width: 100%;

    border-collapse: collapse;

}}

th,
td {{

    padding: 15px 18px;

    text-align: left;

    border-bottom: 1px solid #e5e7eb;

}}

th {{

    background: #f9fafb;

    font-size: 13px;

    color: #6b7280;

    text-transform: uppercase;

    letter-spacing: 0.5px;

}}

tr:last-child td {{

    border-bottom: none;

}}


/* =========================
   STATUS
========================= */

.badge {{

    display: inline-block;

    padding: 5px 10px;

    border-radius: 999px;

    font-size: 12px;

    font-weight: 700;

}}

.status-danger {{

    background: #fee2e2;

    color: #991b1b;

}}

.status-warning {{

    background: #fef3c7;

    color: #92400e;

}}

.status-success {{

    background: #dcfce7;

    color: #166534;

}}

.status-neutral {{

    background: #e5e7eb;

    color: #374151;

}}


/* =========================
   FINDING CARDS
========================= */

.finding-card {{

    background: white;

    border-radius: 14px;

    padding: 22px;

    margin-bottom: 18px;

    box-shadow:
        0 4px 12px
        rgba(
            0,
            0,
            0,
            0.06
        );

}}

.finding-header {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 15px;

    flex-wrap: wrap;

}}

.finding-title {{

    font-size: 18px;

    font-weight: 700;

}}

.finding-meta {{

    margin-top: 14px;

    display: flex;

    gap: 10px;

    flex-wrap: wrap;

}}

.finding-list {{

    margin-top: 15px;

    padding-left: 20px;

}}

.finding-list li {{

    margin: 8px 0;

    line-height: 1.5;

}}


/* =========================
   AFFECTED PAGES
========================= */

details {{

    background: white;

    border-radius: 12px;

    margin-bottom: 12px;

    box-shadow:
        0 3px 10px
        rgba(
            0,
            0,
            0,
            0.05
        );

}}

summary {{

    cursor: pointer;

    padding: 17px 20px;

    font-weight: 700;

}}

.page-list {{

    padding: 0 20px 18px 38px;

}}

.page-list li {{

    margin: 7px 0;

    word-break: break-all;

    color: #374151;

}}


/* =========================
   PAGE FINDINGS
========================= */

.page-card {{

    margin-bottom: 18px;

}}

.page-url {{

    color: #2563eb;

    word-break: break-all;

    font-size: 14px;

}}


/* =========================
   TECHNOLOGIES
========================= */

.tech-list {{

    display: flex;

    gap: 10px;

    flex-wrap: wrap;

}}

.tech-tag {{

    padding: 8px 13px;

    border-radius: 999px;

    background: #e0f2fe;

    color: #075985;

    font-size: 13px;

    font-weight: 600;

}}


/* =========================
   FOOTER
========================= */

.footer {{

    margin-top: 60px;

    padding: 25px 0;

    border-top: 1px solid #d1d5db;

    color: #6b7280;

    font-size: 13px;

}}


/* =========================
   MOBILE
========================= */

@media (max-width: 700px) {{

    .header h1 {{

        font-size: 25px;

    }}

    .summary-value {{

        font-size: 25px;

    }}

}}

</style>

</head>


<body>


<header class="header">

<div class="container">

<div class="header-content">

<div>

<h1>Web Vulnerability Scan Report</h1>

<div class="target-url">

Target:
{target_url}

</div>

<div style="margin-top: 8px; color: #94a3b8;">

Scanned:
{scan_time}

</div>

</div>


<div class="risk-badge {overall_risk_class}">

Overall Risk:
{escape(overall_risk)}

</div>

</div>

</div>

</header>


<main class="container">


<!-- =========================
     EXECUTIVE SUMMARY
========================= -->


<section class="summary-grid">


<div class="summary-card">

<h3>Pages Scanned</h3>

<div class="summary-value">

{pages_scanned}

</div>

</div>


<div class="summary-card">

<h3>Total Findings</h3>

<div class="summary-value">

{summary["total_findings"]}

</div>

</div>


<div class="summary-card">

<h3>High Severity</h3>

<div class="summary-value">

{summary["high"]}

</div>

</div>


<div class="summary-card">

<h3>Medium Severity</h3>

<div class="summary-value">

{summary["medium"]}

</div>

</div>


<div class="summary-card">

<h3>Low Severity</h3>

<div class="summary-value">

{summary["low"]}

</div>

</div>


<div class="summary-card">

<h3>Informational</h3>

<div class="summary-value">

{summary["info"]}

</div>

</div>


</section>


<!-- =========================
     FINDINGS SUMMARY
========================= -->


<section class="section">

<h2 class="section-title">

Findings Summary

</h2>


<div class="table-wrapper">

<table>

<thead>

<tr>

<th>Plugin</th>

<th>Status</th>

<th>Severity</th>

<th>Risk Score</th>

<th>Findings</th>

</tr>

</thead>

<tbody>
"""


    # Domain-level summary rows

    for result in domain_results:

        plugin_name = (
            result.get(
                "plugin_name"
            )
            or result.get(
                "path_name",
                "Unknown"
            )
        )

        status = result.get(
            "status",
            "UNKNOWN"
        )

        severity = result.get(
            "severity",
            "INFO"
        )

        score = result.get(
            "normalized_score",
            0
        )

        finding_count = len(
            result.get(
                "findings",
                []
            )
        )

        html += f"""

<tr>

<td>
{escape(format_title(plugin_name))}
</td>

<td>

<span class="badge {get_status_class(status)}">

{escape(str(status).upper())}

</span>

</td>

<td>

<span class="badge {get_severity_class(severity)}">

{escape(str(severity).upper())}

</span>

</td>

<td>

{format_percentage(score)}

</td>

<td>

{finding_count}

</td>

</tr>

"""


    # Page-level summary rows

    for plugin_name, score in page_scores.items():

        if isinstance(
            plugin_name,
            tuple
        ):

            display_name = " - ".join(
                str(value)
                for value in plugin_name
            )

        else:

            display_name = str(
                plugin_name
            )

        affected_count = len(
            affected_pages.get(
                str(plugin_name),
                []
            )
        )

        html += f"""

<tr>

<td>

{escape(format_title(display_name))}

</td>

<td>

<span class="badge status-warning">

PAGE LEVEL

</span>

</td>

<td>

<span class="badge {get_severity_class('LOW')}">

ANALYZED

</span>

</td>

<td>

{format_percentage(score)}

</td>

<td>

{affected_count} affected pages

</td>

</tr>

"""


    html += """

</tbody>

</table>

</div>

</section>


<!-- =========================
     DOMAIN FINDINGS
========================= -->


<section class="section">

<h2 class="section-title">

Domain-Level Findings

</h2>

"""


    for result in domain_results:

        plugin_name = (
            result.get(
                "plugin_name"
            )
            or result.get(
                "path_name",
                "Unknown"
            )
        )

        status = result.get(
            "status",
            "UNKNOWN"
        )

        severity = result.get(
            "severity",
            "INFO"
        )

        score = result.get(
            "normalized_score",
            0
        )

        findings = result.get(
            "findings",
            []
        )

        html += f"""

<div class="finding-card">

<div class="finding-header">

<div class="finding-title">

{escape(format_title(plugin_name))}

</div>

<span class="badge {get_status_class(status)}">

{escape(str(status).upper())}

</span>

</div>


<div class="finding-meta">

<span class="badge {get_severity_class(severity)}">

Severity:
{escape(str(severity).upper())}

</span>

<span class="badge status-neutral">

Risk Score:
{format_percentage(score)}

</span>

</div>

"""


        if findings:

            html += """

<ul class="finding-list">

"""

            for finding in findings:

                html += f"""

<li>

{escape(str(finding))}

</li>

"""

            html += """

</ul>

"""

        else:

            html += """

<p>

No findings were reported.

</p>

"""


        html += """

</div>

"""


    html += """

</section>


<!-- =========================
     AFFECTED PAGES
========================= -->


<section class="section">

<h2 class="section-title">

Affected Pages

</h2>

"""


    if affected_pages:

        for plugin_name, urls in affected_pages.items():

            if isinstance(
                plugin_name,
                tuple
            ):

                display_name = " - ".join(
                    str(value)
                    for value in plugin_name
                )

            else:

                display_name = str(
                    plugin_name
                )

            html += f"""

<details>

<summary>

{escape(format_title(display_name))}

—

{len(urls)} affected page(s)

</summary>

<ul class="page-list">

"""


            for url in urls:

                html += f"""

<li>

{escape(str(url))}

</li>

"""


            html += """

</ul>

</details>

"""


    else:

        html += """

<div class="finding-card">

No affected pages were detected.

</div>

"""


    html += """

</section>


<!-- =========================
     PAGE-BY-PAGE RESULTS
========================= -->


<section class="section">

<h2 class="section-title">

Page-by-Page Analysis

</h2>

"""


    for url, findings in page_results.items():

        html += f"""

<details class="page-card">

<summary>

<span class="page-url">

{escape(str(url))}

</span>

</summary>

"""


        for result in findings:

            plugin_name = (
            result.get("plugin_name")
            or result.get("path_name", "Unknown")
        )

            if plugin_name == "security_headers":
                title = result.get(
                    "header_name",
                    "Security Headers"
                )
            else:
                title = plugin_name

            status = result.get(
                "status",
                "UNKNOWN"
            )

            severity = result.get(
                "severity",
                "INFO"
            )

            score = result.get(
                "normalized_score",
                0
            )

            result_findings = result.get(
                "findings",
                []
            )


            html += f"""

<div class="finding-card">

<div class="finding-header">

<div class="finding-title">
    {escape(format_title(title))}
</div>

<span class="badge {get_status_class(status)}">

{escape(str(status).upper())}

</span>

</div>


<div class="finding-meta">

<span class="badge {get_severity_class(severity)}">

Severity:
{escape(str(severity).upper())}

</span>

<span class="badge status-neutral">

Risk Score:
{format_percentage(score)}

</span>

</div>

"""


            if result_findings:

                html += """

<ul class="finding-list">

"""


                for finding in result_findings:

                    html += f"""

<li>

{escape(str(finding))}

</li>

"""


                html += """

</ul>

"""


            elif (
                plugin_name
                == "technology_detection"
            ):

                technologies = result_findings

                if technologies:

                    html += """

<div class="tech-list">

"""


                    for technology in technologies:

                        html += f"""

<span class="tech-tag">

{escape(str(technology))}

</span>

"""


                    html += """

</div>

"""

                else:

                    html += """

<p>

No technologies detected.

</p>

"""


            else:

                html += """

<p>

No findings reported.

</p>

"""


            html += """

</div>

"""


        html += """

</details>

"""


    html += """

</section>


</main>


<footer class="footer">

<div class="container">

Generated by Python Web Vulnerability Scanner

<br>

Educational security assessment tool for authorized testing only.

</div>

</footer>


</body>

</html>

"""


    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        f"HTML report generated: {output_file}"
    )