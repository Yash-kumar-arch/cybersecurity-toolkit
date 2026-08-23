from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin

class Cookie_analysis(Plugin):

    def analyze(self,response):

        findings = []
        score = 0
        max_score = 30

        cookies = response.cookies

        for cookie in cookies:
            cookie_name = cookie.name
            secure = cookie.secure
            httponly = "HttpOnly" in cookie._rest
            samesite = cookie._rest.get("SameSite")

            if not secure:
                score += 3
                findings.append(f"Cookie {cookie_name} can be sent through unsecure protocol")

            if not httponly:
                score += 2
                findings.append(f"Cookie {cookie_name} has risk to javascript malware code")

            if samesite is None:
                score += 2
                findings.append(
                    f"Cookie '{cookie_name}' does not define a SameSite attribute"
                )

        if findings:
            status = "WEAK"
        else:
            status = "OK"

        normalized_score = min(score / max_score, 1.0)
        severity = severity_classifer(normalized_score)

        return {
            "plugin_name": "cookie_analysis",
            "status": status,
            "severity": severity,
            "normalized_score": normalized_score,
            "findings": findings
        }