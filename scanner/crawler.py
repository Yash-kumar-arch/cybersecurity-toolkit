import requests
from bs4 import BeautifulSoup
from collections import deque
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from scanner.base_plugin import Plugin

class Crawler(Plugin):

    def __init__(
            self,
            target_url,
            session,
            request_timeout,
            max_workers,
            max_pages):
        self.request_timeout = request_timeout
        self.max_workers = max_workers 
        self.max_pages = max_pages
        self.target_url = target_url
        self.session = session

    def crawl_page(self, url):

        new_links = []
        
        try:
            response = self.session.get(url, timeout=self.request_timeout)
        except requests.exceptions.RequestException:
            return None
        
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.find_all("a")
        
        for link in links:
            href = link.get("href")
            if not href or href.startswith("#"):
                continue
            new_url = urljoin(url, href)
            if urlparse(new_url).netloc != urlparse(self.target_url).netloc:
                continue
            new_links.append(new_url)
        
        return {
    "url": url,
    "response": response,
    "links": new_links
}


    def analyze(self,response):
        
        to_visit = deque([self.target_url])
        visited = set()
        discovered_pages = []
        crawled_pages = []

        while to_visit and len(visited) < self.max_pages:
            remaining = self.max_pages - len(visited)

            current_batch = []

            for _ in range(min(len(to_visit), remaining)):
                current_batch.append(to_visit.popleft())
            
            # mark all as visited before processing
            for url in current_batch:
                visited.add(url)
                discovered_pages.append(url)

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                results = list(executor.map(self.crawl_page, current_batch))

            valid_results = [
            page
            for page in results
            if page is not None
        ]
            # flatten results and add new links to to_visit
            crawled_pages.extend(valid_results)

            new_links = [
                link
                for page in valid_results
                for link in page["links"]
            ]

            for url in new_links:
                if url not in visited and url not in to_visit:
                    to_visit.append(url)

        return {
            "path_name": "crawler",
            "status": "OK",
            "severity": "LOW",
            "normalized_score": 0.0,
            "findings": crawled_pages
        }