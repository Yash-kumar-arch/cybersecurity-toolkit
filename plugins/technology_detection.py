from signatures.tech_signatures import TECH_SIGNATURES
from bs4 import BeautifulSoup


class TechDetection():

    def analyze(self,response):

        evidence = {
    "html": response.text.lower(),
    "headers": str(response.headers).lower(),
    "cookies": str(response.cookies).lower(),
    "scripts": [],
    "links": []
}
        
        soup = BeautifulSoup(response.text,"html.parser")
        evidence["scripts"] = [
        script.get("src", "").lower()
        for script in soup.find_all("script")
        if script.get("src")
    ]
        
        evidence["links"] = [
        link.get("href", "").lower()
        for link in soup.find_all("link")
        if link.get("href")
    ]
        
        detected = set()

        for technology, rules in TECH_SIGNATURES.items():
            found = False
            for rule_type, patterns in rules.items():
                if found:
                    break                          # skip remaining rule_types for THIS tech
                for pattern in patterns:
                    if self.match_pattern(rule_type, pattern, evidence):
                        found = True
                        detected.add(technology)
                        break                      # skip remaining patterns

        if detected:
            status = "detected"
        else:
            status = "not_detected"

        return {
            "plugin_name": "technology_detection",
            "path_name": "Technology_Detection",
            "status": status,
            "severity": "INFO",
            "normalized_score": 0.0,
            "findings":list(detected)
            }
         
    def match_pattern(self,rule_type,pattern, evidence):
        pattern = pattern.lower()

        source = evidence[rule_type]

        if isinstance(source, str):
            return pattern in source

        elif isinstance(source, list):
            return (any(pattern in s for s in source))
        
        else:
            return False