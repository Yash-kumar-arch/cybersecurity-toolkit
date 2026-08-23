import requests
from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin


class Robot_txt(Plugin):

    def __init__(self,target_url,session,request_timeout):
        self.target_url = target_url
        self.request_timeout = request_timeout
        self.session = session  

    def analyze(self,response):
        score = 0
        max_score = 50
        findings = []
        clean_list = []

        my_url = self.target_url + "/robots.txt"

        try:
            response = self.session.get(my_url, timeout=self.request_timeout)
        except requests.exceptions.RequestException:
            return {
                "path_name": "robots.txt",
                "status": "ERROR",
                "severity": "LOW",
                "normalized_score": 0.0,
                "findings": ["Could not connect to fetch robots.txt"]
            }

        if response.status_code == 404:
            findings.append("robots.txt not found. Search engines and crawlers are not provided with crawl directives.")
            score += 3
            status = "WEAK"

        else:
            data = response.text
            my_list = data.splitlines()
            for my in my_list:
                if my.startswith("Disallow"):
                    clean_list.append(my.split(":")[1].strip())


        sus_list = [
    "/admin", "/administrator", "/backup", "/config", "/database", "/db",
    "/api", "/internal", "/private", "/secret", "/password", "/credentials",
    "/logs", "/log", "/temp", "/tmp", "/test", "/dev", "/development", "/staging",
    "/phpmyadmin", "/wp-admin", "/cpanel", "/dashboard", "/manage", "/manager",
    "/upload", "/uploads", "/shell", "/console", "/debug", "/.git"
    ]
        flagged_paths = set()

        for path in clean_list:
            for sus in sus_list:
                if sus in path and path not in flagged_paths:
                    flagged_paths.add(path)
                    findings.append(f"The robot.txt has sensitive data visible: {sus} keyword found in {path} ")
                    score += 5
                    break  
        if findings:
            status = "WEAK"
        else:
            status = "OK"
        normalized_score = min(score / max_score, 1.0)
        severity = severity_classifer(normalized_score)

        return {
            "path_name":"robots.txt",
            "status":status,
            "severity":severity,
            "normalized_score":normalized_score,
            "findings":findings
        }