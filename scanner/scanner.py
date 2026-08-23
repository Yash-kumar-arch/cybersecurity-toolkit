import logging
import requests
from concurrent.futures import ThreadPoolExecutor

from scanner.config import ScannerConfig
from scanner.crawler import Crawler

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

class Scanner():
    def __init__ (self,target_url,config=None):
        self.target_url = target_url
        self.config = config or ScannerConfig()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.config.user_agent
        })
        self.crawler = Crawler(
            target_url,
            self.session,
            self.config.request_timeout,
            self.config.max_workers,
            self.config.max_pages
        )
        self.domain_plugins = []
        self.pages_plugins = []

    def add_domain_plugin(self,domain_plugin):
        self.domain_plugins.append(domain_plugin)

    def add_pages_plugin(self,page_plugin):
        self.pages_plugins.append(page_plugin)

    def scan_page(self, page_data):
        url = page_data["url"]
        response = page_data["response"]

        page_findings = []
        
        for plug in self.pages_plugins:
            try:
                result = plug.analyze(response)
                page_findings.append(result)
            except Exception as e:
                logger.exception(
                "Plugin %s failed while scanning %s",
                plug.__class__.__name__,
                url
            )

                error_result = {
                    "plugin_name": plug.__class__.__name__,
                    "status": "ERROR",
                    "severity": "INFO",
                    "normalized_score": 0.0,
                    "findings": [
                        "Unexpected plugin execution failure"
                    ]
                }

                page_findings.append(error_result)
        return (url, page_findings)

    def scan(self):
        try:
            response = self.session.get(self.target_url,timeout=self.config.request_timeout)
        except requests.exceptions.RequestException as e:
            logger.error("Request failed: %s", e)
            return None
        
        crawler_result = self.crawler.analyze(response)
        crawled_page_data = crawler_result["findings"]
        total_score = 0
        domain_results = []

        for domain in self.domain_plugins:
            results = domain.analyze(response)
            domain_results.append(results)  

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            results = list(executor.map(self.scan_page, crawled_page_data))
        
        valid_results = list(filter(None, results))

        page_results = {}
        for url, page_findings in valid_results:
            page_results[url] = page_findings

        page_scores = {}
        affected_pages = {}

        for url ,findings_list in page_results.items():
            for result in findings_list:

                if result["status"] == "INCONCLUSIVE":
                    continue

                if result["plugin_name"] == "security_headers":
                    score_key = (
                        result["plugin_name"],
                        result["header_name"]
                    )
                else:
                    score_key = result["plugin_name"]
    
                current_score = page_scores.get(score_key, 0)

                page_scores[score_key] = max(
                    current_score,
                    result["normalized_score"]
                )

                if result["normalized_score"] > 0:

                    if score_key not in affected_pages:
                        affected_pages[score_key] = set()

                    affected_pages[score_key].add(url)
        
        total_score += sum(page_scores.values())

        affected_page_summary = []

        for score_key, urls in affected_pages.items():

            if isinstance(score_key, tuple):
                plugin_name, finding_name = score_key
            else:
                plugin_name = score_key
                finding_name = None

            affected_page_summary.append({
                "plugin_name": plugin_name,
                "finding_name": finding_name,
                "affected_pages": list(urls),
                "affected_count": len(urls),
                "total_pages": len(page_results)
            })

        for result in domain_results:
            total_score += result["normalized_score"]

        if total_score <= 1.0:
            risk = "LOW"
        elif total_score <= 3.0:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        final_report = {
    "target_url": self.target_url,
    "pages_scanned": len(crawled_page_data),
    "overall_risk_level": risk,
    "domain_results": domain_results,
    "page_results": page_results,
    "page_scores": page_scores,
    "affected_pages": {
        str(score_key): list(urls)
        for score_key, urls in affected_pages.items()
    }
}

        return final_report