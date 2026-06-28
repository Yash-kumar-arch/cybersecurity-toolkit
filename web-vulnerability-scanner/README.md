# Python Web Vulnerability Scanner

A Python-based Web Vulnerability Scanner built as a long-term cybersecurity learning project. The goal is to understand how web security assessments work internally by implementing security checks from scratch rather than relying on existing tools.

## Current Features

### HTTP Security Header Analysis

* X-Frame-Options (XFO)
* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Content-Type-Options (XCTO)
* Referrer-Policy

### Server Fingerprinting

Detects information leaked through response headers:

* Server software and version disclosure
* Backend technology exposure (X-Powered-By, X-AspNet-Version, X-Generator)
* Version detection using regex patterns

### Technology Detection

* Signature-based technology fingerprinting
* Detects technologies using:

  * HTML content
  * HTTP response headers
  * Response cookies
  * JavaScript (`<script src>`)
  * Stylesheets (`<link href>`)
* Uses a configurable `TECH_SIGNATURES` database for extensibility
* Detects multiple technologies from a single HTTP response without issuing additional requests

### robots.txt Analysis

* Detects sensitive path disclosures in robots.txt
* Flags directories like `/admin`, `/backup`, `/.git` exposed to crawlers
* Handles missing `robots.txt` as a finding

### Directory Listing Detection

* Checks 31 common directories for enabled directory listing
* Flags any folder returning an Apache/Nginx file index page
* Multithreaded for fast scanning

### Backup File Discovery

* Checks 27 common backup filenames at the root directory
* Detects exposed database dumps, configuration backups, and archive files
* Multithreaded for fast scanning

### Form Discovery

* Parses HTML to extract all form elements
* Flags password fields submitted via GET requests
* Detects hidden input fields that may contain sensitive information
* Flags forms submitting over insecure HTTP
* Flags forms submitting to external/cross-origin domains

### Website Crawling

* BFS-based crawler using a queue, capped at 25 pages per scan
* Restricts crawling to the target domain
* Converts relative URLs to absolute using `urljoin`
* Automatically feeds discovered pages back into the Scanner for analysis

### Multithreaded Scanning

* Directory Listing, Backup File Discovery, Crawling, and per-page analysis execute concurrently using `ThreadPoolExecutor`
* Significantly reduces scan time for multi-page websites

---

## Architecture

Plugin-based architecture:

* `Plugin` base class
* Individual analyzer classes extending `Plugin`
* `Scanner` class responsible for coordinating scans and aggregating results
* Shared HTTP response object passed to page-level plugins (avoids duplicate requests)
* Signature-based detection engine for technology fingerprinting
* Normalized scoring system (0.0–1.0)
* Shared severity classifier
* Plugins divided into:

  * **Domain-level plugins** (run once per scan)

    * robots.txt Analysis
    * Directory Listing Detection
    * Backup File Discovery
  * **Page-level plugins** (run for every crawled page)

    * Security Header Analysis
    * Server Fingerprinting
    * Form Discovery
    * Technology Detection
* Exception handling around all network requests
* Concurrent execution using `concurrent.futures.ThreadPoolExecutor`

---

## Project Roadmap

### Completed

* HTTP Security Header Analysis
* Server Fingerprinting
* Technology Detection
* robots.txt Analysis
* Directory Listing Detection
* Backup File Discovery
* Form Discovery
* Website Crawling
* Multi-page Scanner Integration
* Multithreading

### Planned

* HTML/PDF Report Generation
* Additional Web Vulnerability Checks
* More Technology Signatures
* Authentication & Session Analysis
* SSL/TLS Security Checks
* API Endpoint Analysis

---

## Example Output

```python
{
    "target_url": "https://example.com",
    "pages_scanned": 25,
    "overall_risk_level": "MEDIUM",
    "domain_results": [...],
    "page_results": {
        "https://example.com": [
            {
                "path_name": "Technology_Detection",
                "status": "detected",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    "Nginx",
                    "WordPress"
                ]
            }
        ]
    }
}
```

---

## Requirements

* Python 3.x

```bash
pip install requests beautifulsoup4
```

---

## Libraries Used

* `requests` — HTTP requests and response handling
* `beautifulsoup4` — HTML parsing for forms, scripts, and links
* `re` — Regular expressions for version detection
* `collections.deque` — BFS crawling queue
* `urllib.parse` — URL parsing and normalization
* `concurrent.futures.ThreadPoolExecutor` — Concurrent scanning

---

## How to Run

```bash
python Web_Vulnerability_Scanner.py
```

---

## Disclaimer

This project is intended solely for educational purposes and authorized security testing. Only scan systems that you own or have explicit permission to assess.
