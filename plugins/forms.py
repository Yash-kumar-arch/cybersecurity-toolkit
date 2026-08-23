from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


class Forms(Plugin):

    def analyze(self,response):

        findings = []
        score = 0
        max_score = 30

        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        sensitive_keywords = [
                "password",
                "passwd",
                "secret",
                "api_key",
                "apikey",
                "private_key"
            ]

        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "").lower()
            inputs = form.find_all("input")

            if action:
                action_domain = urlparse(action).netloc
                page_domain = urlparse(response.url).netloc
                
                if action_domain and action_domain != page_domain:
                    findings.append(f"Form submits to external domain {action_domain}")
                    score += 3
            
            has_password = False
            for input_field in inputs:
                if input_field.get("type") == "password":
                    has_password = True
            
            if method == "get" and has_password:
                findings.append(f"Password field found in GET form submitting to {action}")
                score +=3
            
            for input_field in inputs:
                input_type = input_field.get("type")
                input_name = input_field.get("name")
                normalized_name = (input_name or "").lower()
                
                if input_type == "hidden":
                    if any(keyword in normalized_name for keyword in sensitive_keywords):
                        findings.append(f"The hidden input type has sensitive info {input_name}")
                        score += 3
            
            if action and action.startswith("http://"):
                findings.append(f"Form submits over insecure HTTP to {action}")
                score += 3

        if findings:
            status = "WEAK"

        else:
            status = "OK"

        normalized_value = min(score / max_score,1.0) 
        severity = severity_classifer(normalized_value)

        return {
            "plugin_name": "form_discovery",
            "path_name":"Forums",
            "status":status,
            "severity":severity,
            "normalized_score":normalized_value,
            "findings":findings
        }