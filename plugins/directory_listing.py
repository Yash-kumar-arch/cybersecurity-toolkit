import requests
from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin
from concurrent.futures import ThreadPoolExecutor


class Direct_List(Plugin):

    def __init__(self,target_url,session,request_timeout,max_workers):
        self.target_url = target_url
        self.request_timeout = request_timeout
        self.max_workers = max_workers
        self.session = session

    def check_directory(self,directory):

        url = self.target_url + "/" + directory
        try:
            response = self.session.get(url,timeout=self.request_timeout)
            if response.status_code == 200 and "Index of" in response.text:
                return f"Directory listing is enabled in {url} and sensitive info might leak"
            else:
                return None

        except requests.exceptions.RequestException:
            return None
        
    def get_paths(self):
        return [
    "/uploads", "/backup", "/backups", "/images", "/img",
    "/files", "/documents", "/docs", "/assets", "/media",
    "/admin", "/dashboard", "/config", "/configs", "/data",
    "/database", "/db", "/logs", "/log", "/temp", "/tmp",
    "test", "dev", "old", "archive", "/private", "/secret",
    "/api", "/static", "/public", "/downloads", "/content"
]
        
        
    def analyze(self,response):

        findings = []
        score = 0
        max_score = 20

        dirs_to_check = [
    "uploads", "backup", "backups", "images", "img",
    "files", "documents", "docs", "assets", "media",
    "admin", "dashboard", "config", "configs", "data",
    "database", "db", "logs", "log", "temp", "tmp",
    "test", "dev", "old", "archive", "private", "secret",
    "api", "static", "public", "downloads", "content"
]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(self.check_directory, dirs_to_check))

        findings = list(filter(None, results))
        score = len(findings) * 3
        if findings:
            status = "WEAK"
        else:
            status = "OK"

        normalized_score = min(score / max_score, 1.0)
        severity = severity_classifer(normalized_score)

        return {
            "path_name":"Directory listing detection",
            "status":status,
            "severity":severity,
            "normalized_score":normalized_score,
            "findings":findings
        }