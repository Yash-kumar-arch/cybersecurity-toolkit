# Python Web Vulnerability Scanner

A Python-based web vulnerability scanner built as a long-term cybersecurity and software engineering learning project.

The project is being developed from scratch to understand how web security scanning tools work internally. Instead of relying entirely on existing scanning frameworks, the scanner implements its own crawling engine, plugin architecture, HTTP request handling, concurrent execution, security checks, risk scoring, and result aggregation.

The primary goal of this project is not to build a production-ready vulnerability scanner immediately. It is to learn software engineering concepts by building a real, continuously evolving system.

---

## Project Goals

This project is being developed to understand:

* How web crawlers work
* How HTTP responses can be analyzed for security weaknesses
* How plugin-based architectures are designed
* How concurrent I/O can improve performance
* How components can communicate through structured data
* How risk scores can be calculated and aggregated
* How failures can be handled without crashing an entire application
* How a project can evolve from a single Python file into a more maintainable system

The project is developed incrementally:

```text
Understand the concept
        ↓
Implement it
        ↓
Test it
        ↓
Improve it
        ↓
Commit it
        ↓
Continue building
```

---

# Current Features

## HTTP Security Header Analysis

The scanner currently analyzes:

* `X-Frame-Options`
* `Content-Security-Policy`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `Referrer-Policy`

The plugins analyze whether headers are:

* Missing
* Properly configured
* Weakly configured
* Invalid
* Inconclusive because the response could not be reliably analyzed

Each result returns structured information including:

```python
{
    "plugin_name": "...",
    "header_name": "...",
    "status": "...",
    "severity": "...",
    "normalized_score": 0.0,
    "findings": [...]
}
```

---

## Server Fingerprinting

Analyzes response headers for information disclosure.

Currently checks headers such as:

* `Server`
* `X-Powered-By`
* `X-AspNet-Version`
* `X-Generator`

The scanner can detect:

* Server software disclosure
* Server version disclosure
* Framework and backend technology exposure

Version information is detected using regular expressions.

---

## Technology Detection

The scanner includes a signature-based technology detection engine.

Technologies can be detected using evidence from:

* HTML content
* HTTP response headers
* Cookies
* JavaScript source URLs
* Stylesheet URLs

Technology signatures are stored separately in a configurable `TECH_SIGNATURES` database.

Conceptually:

```text
HTTP Response
      ↓
Evidence Extraction
      ↓
Signature Matching
      ↓
Detected Technologies
```

The detector can identify multiple technologies from a single response without issuing additional requests.

Detection is based on available evidence and signatures rather than claiming absolute certainty.

---

## Form Analysis

The form analysis plugin parses HTML forms and checks for potentially risky patterns.

Currently analyzes:

* Password fields submitted using `GET`
* Hidden fields with potentially sensitive names
* Forms submitting over insecure HTTP
* Forms submitting to external domains
* Cross-origin form destinations

HTML is parsed using `BeautifulSoup`.

---

## robots.txt Analysis

The scanner analyzes the target website's `robots.txt` file.

It can:

* Check whether `robots.txt` exists
* Extract disallowed paths
* Detect potentially sensitive path disclosures
* Identify paths such as:

  * `/admin`
  * `/backup`
  * `/database`
  * `/private`
  * `/.git`

The scanner treats `robots.txt` as an information source, not as an access-control mechanism.

---

## Directory Listing Detection

Checks common directories for publicly accessible directory listings.

The plugin:

* Requests common directory paths
* Detects directory index pages
* Performs checks concurrently
* Reports discovered directory listings as findings

---

## Backup File Discovery

Checks common filenames for exposed backup files.

Examples include:

* Database dumps
* Configuration backups
* Archive files
* Old configuration files
* Backup copies of application files

The checks are performed concurrently using a worker pool.

---

# Website Crawling

The scanner contains a breadth-first search crawler.

The crawler uses:

```python
collections.deque
```

to manage URLs waiting to be visited.

The crawling process is:

```text
Target URL
    ↓
Fetch Page
    ↓
Extract Links
    ↓
Convert Relative URLs
    ↓
Filter External Domains
    ↓
Track Visited URLs
    ↓
Add New URLs to Queue
    ↓
Repeat
```

The crawler currently:

* Uses breadth-first search
* Converts relative URLs to absolute URLs using `urljoin`
* Restricts crawling to the target domain
* Tracks visited URLs using a `set`
* Prevents duplicate URLs from being queued
* Limits the maximum number of scanned pages
* Returns structured page data

A crawled page contains:

```text
URL
HTTP Response
Discovered Links
```

---

# Concurrent Execution

The project uses:

```python
concurrent.futures.ThreadPoolExecutor
```

for I/O-bound operations.

Concurrency is currently used for:

* Crawling multiple pages
* Directory listing checks
* Backup file checks
* Running page-level analysis across crawled pages

The basic architecture is:

```text
                ┌──────────────┐
                │    Scanner   │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │    Crawler   │
                └──────┬───────┘
                       │
              Multiple Page Requests
                       │
                       ▼
                ┌──────────────┐
                │ Page Results │
                └──────┬───────┘
                       │
                       ▼
              Concurrent Plugin Analysis
```

The project uses concurrency primarily to improve I/O-bound execution rather than CPU computation.

---

# Architecture

The scanner uses a plugin-based architecture.

At a high level:

```text
                 Target URL
                     │
                     ▼
                ┌─────────┐
                │ Scanner │
                └────┬────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
      Crawler              Domain Plugins
          │                     │
          ▼                     │
   Crawled Page Data             │
          │                     │
          ▼                     │
     Page Plugins                │
          │                     │
          └──────────┬──────────┘
                     ▼
              Result Aggregation
                     │
                     ▼
                Risk Scoring
                     │
                     ▼
               Final Report
```

---

## Core Components

### `Plugin`

Base interface for scanner plugins.

Plugins implement:

```python
def analyze(self, response):
    ...
```

Some plugins also implement:

```python
def get_paths(self):
    ...
```

This allows different plugins to perform different types of analysis while following a common structure.

---

### `Scanner`

The main orchestration component.

Responsibilities currently include:

* Managing the shared HTTP session
* Managing scanner configuration
* Registering plugins
* Starting the crawl
* Running page-level plugins
* Running domain-level plugins
* Aggregating results
* Calculating scores
* Determining the overall risk level
* Returning the final report

---

### `Crawler`

Responsible for:

* Discovering pages
* Fetching pages
* Extracting links
* Restricting crawling to the target domain
* Tracking visited URLs
* Limiting crawl size

The crawler returns structured page data instead of directly performing security analysis.

This allows crawling and scanning to remain separate responsibilities.

---

### Domain-Level Plugins

These run once for the target website.

Current domain-level plugins include:

* `robots.txt` analysis
* Directory listing detection
* Backup file discovery

---

### Page-Level Plugins

These run against every successfully crawled page.

Current page-level plugins include:

* Security header analysis
* Server fingerprinting
* Form analysis
* Technology detection

---

# HTTP Request Architecture

The scanner owns a shared:

```python
requests.Session()
```

The session is passed to components that need to perform HTTP requests.

This allows:

* Shared HTTP configuration
* Consistent headers
* Connection reuse where supported
* Centralized session ownership
* Explicit dependency injection

The scanner also configures a custom user agent:

```text
VulnScanner/1.0
```

Page-level plugins analyze responses that have already been fetched by the crawler rather than independently requesting the same page again.

---

# Error Handling

The project uses multiple layers of error handling.

## Network Errors

Network-related exceptions are handled using:

```python
requests.exceptions.RequestException
```

Examples include:

* Connection failures
* Timeouts
* DNS failures
* Other request-related errors

---

## Plugin Failure Isolation

A failure inside one plugin should not crash the entire scan.

The scanner catches unexpected plugin exceptions and records an error result.

Conceptually:

```text
Plugin A
    ↓
Success

Plugin B
    ↓
Unexpected Error
    ↓
ERROR result recorded

Plugin C
    ↓
Still executes
```

This allows the scanner to degrade gracefully when an individual plugin fails.

The scanner also uses logging to record unexpected failures and their context.

---

# Risk Scoring

The scanner uses normalized scores between:

```text
0.0 → no detected risk
1.0 → maximum score for that issue
```

The score is calculated within individual plugins based on the findings detected.

The scanner then aggregates page-level results before calculating the overall risk.

One important scoring improvement was made to prevent the same issue from artificially inflating the total score simply because it appears on many pages.

For example:

```text
Page 1 → CSP score: 0.18
Page 2 → CSP score: 0.18
Page 3 → CSP score: 0.18
```

The scanner does not simply add the same issue score repeatedly for every page.

Instead, issue scores are aggregated by issue category while affected URLs are tracked separately.

This creates a distinction between:

```text
How severe is the issue?
```

and:

```text
How widespread is the issue?
```

The scanner also records which pages were affected by each issue.

For example:

```text
Content-Security-Policy
24 / 25 pages affected
```

This information is used for reporting and prevalence analysis without directly multiplying the same issue's severity score by the number of affected pages.

---

# Current Scan Flow

The current scan process is:

```text
Target URL
    ↓
Initial HTTP Request
    ↓
Crawler
    ↓
Breadth-First Page Discovery
    ↓
Concurrent Page Fetching
    ↓
Page-Level Plugin Analysis
    ↓
Plugin Error Isolation
    ↓
Result Collection
    ↓
Score Aggregation
    ↓
Affected Page Tracking
    ↓
Domain-Level Plugin Analysis
    ↓
Total Score Calculation
    ↓
Overall Risk Classification
    ↓
Final Structured Report
```

---

# Example Output

The scanner currently displays a summary of affected pages and aggregated scores.

Example:

```text
AFFECTED PAGES:

('security_headers', 'Content-Security-Policy') 24 / 25 pages affected

server_fingerprinting 24 / 25 pages affected

form_discovery 3 / 25 pages affected

Page scores:
{
    ('security_headers', 'Content-Security-Policy'): 0.18,
    'server_fingerprinting': 0.15,
    'form_discovery': 0.10
}

Total score: 0.43
```

The scanner returns a structured report:

```python
{
    "target_url": "https://example.com",
    "pages_scanned": 25,
    "overall_risk_level": "LOW",
    "domain_results": [...],
    "page_results": {
        "https://example.com": [
            {
                "plugin_name": "technology_detection",
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

# Engineering Concepts Practiced

This project has been used to learn and apply:

* Object-oriented programming
* Classes and inheritance
* Composition
* Dependency injection
* First-class functions and methods
* Breadth-first search
* Queues using `deque`
* Sets for state tracking and deduplication
* Concurrent I/O
* `ThreadPoolExecutor`
* HTTP requests using `requests`
* Shared `requests.Session`
* HTML parsing using BeautifulSoup
* URL joining using `urljoin`
* URL parsing using `urlparse`
* Domain restriction
* Structured result dictionaries
* Normalized scoring
* Maximum-score aggregation
* Affected-page tracking
* Exception handling
* Logging
* Plugin architecture
* Separation of crawling and analysis responsibilities
* Signature-based detection engines
* Graceful degradation
* Configuration using dataclasses

---

# Project Structure

The project currently exists as a single Python implementation while the architecture is being developed and understood.

As the system grows, components may eventually be separated into modules such as:

```text
project/
│
├── scanner.py
├── crawler.py
├── config.py
│
├── plugins/
│   ├── security_headers.py
│   ├── forms.py
│   ├── technology_detection.py
│   └── ...
│
├── reports/
│   ├── json_report.py
│   └── html_report.py
│
└── tests/
```

The project is intentionally being refactored gradually rather than splitting files prematurely.

---

# Roadmap

The immediate goal is to finish and stabilize the first complete version of the scanning engine.

## Near-Term Goals

* Improve technology detection
* Add cookie security analysis
* Improve plugin result consistency
* Improve crawler reliability
* Improve HTTP error handling
* Improve the final report structure
* Add JSON report generation
* Add HTML report generation
* Improve terminal output
* Add basic automated tests

---

## Future Improvements

Possible future improvements include:

* Better URL normalization
* More deliberate redirect handling
* Retry strategies
* Rate limiting
* Improved HTTP error classification
* More consistent plugin contracts
* Improved severity and prevalence modeling
* Unit testing with `pytest`
* Mock HTTP responses
* CLI arguments using `argparse`
* Configuration files
* Additional security plugins
* Historical scan comparison
* API integration
* Web dashboard

These features will be added only when they solve a real problem in the project.

The project will not add complexity merely for the sake of appearing more advanced.

---

# Requirements

* Python 3.x

Install the required dependencies:

```bash
pip install requests beautifulsoup4
```

---

# Libraries Used

* `requests` — HTTP requests and session management
* `beautifulsoup4` — HTML parsing
* `re` — Regular expressions for version detection
* `collections.deque` — BFS crawling queue
* `urllib.parse` — URL parsing and URL joining
* `concurrent.futures.ThreadPoolExecutor` — Concurrent I/O-bound execution
* `dataclasses` — Configuration management
* `logging` — Application logging

---

# How to Run

```bash
python Web_Vulnerability_Scanner.py
```

The scanner will prompt for a target URL:

```text
Enter the url:
```

Example:

```text
https://example.com
```

---

# Disclaimer

This project is intended solely for educational purposes and authorized security testing.

Only scan systems that you own or have explicit permission to assess.
