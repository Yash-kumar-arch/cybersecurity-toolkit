from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin
import re 


class Server_Fin(Plugin):

    def analyze(self,response):

        findings = []
        score = 0
        max_score = 26
        server_list = []

        fingerprint_headers = {
            "Server": {"check_version":True},
            "X-Powered-By":{"check_version":False},
            "X-AspNet-Version":{"check_version":True},
            "X-Generator":{"check_version":False}
        }
        for header_name, config in fingerprint_headers.items():
            value = response.headers.get(header_name)
            if value:
                score += 2
                server_list.append(header_name)
                
                if config["check_version"]:
                    if re.search(r'\d+\.\d+', value):
                        findings.append(f"The server version {value} is visible and has risks")
                        score += 5
                    else:
                        score += 2
                        findings.append(f"Version is not visible but server_name {value} is visible")
                else:
                    findings.append(f"The sensitive servers and framework names are listed {value} and are prior to risks")
                    score += 4

        if score == 0:
            status = "OK"
        elif score <= 15:
            status = "ACCEPTABLE"
        elif score <= 26:
            status = "WEAK"

        normalized_score = score / max_score
        severity = severity_classifer(normalized_score)

        return {
            "plugin_name": "server_fingerprinting",
            "headers_found": server_list,
            "status":status,
            "severity":severity,
            "normalized_score":normalized_score,
            "findings":findings
        }