from scanner.scoring import severity_classifer
from scanner.base_plugin import Plugin

class XFOPlugin(Plugin):

    def analyze(self,response):
        
        value = response.headers.get("X-Frame-Options") 
        header_name = "X-Frame-Options"
        findings = []
        score = 0
        max_score = 3

        if response.status_code in [403, 404, 429]:
            return {
                "plugin_name": "security_headers",
                "header_name": header_name,
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    f"Security header analysis skipped because response status was {response.status_code}"
                ]
            }

        if value is None:
            status = "MISSING"
            severity = "HIGH"
            findings.append("X-Frame-Options header is missing. Clickjacking protection is not enforced")
            normalized_score = 1.0

            return {
        "plugin_name": "security_headers",
        "header_name":header_name,
        "status": status,
        "severity": severity,
        "findings":findings,
        "normalized_score":normalized_score}
        
        value = value.strip().upper()   

        if  value == "DENY" or value == "SAMEORIGIN":

            status = "OK"
            findings.append("X-Frame-Options header is present. Clickjacking protection is enforced")
            score += 0
        
        else:

            status = "WEAK"
            findings.append("X-Frame-Options header is present but enforced weakly")
            score += 3

        normalized_score = score / max_score 
        severity = severity_classifer(normalized_score)
        
        return {
            "plugin_name": "security_headers",
            "header_name":header_name,
            "status":status,
            "severity":severity,
            "findings":findings,
            "normalized_score":normalized_score }


class CSPPlugin(Plugin):
    def analyze(self,response):
        value = response.headers.get("Content-Security-Policy")
        score = 0 
        header_name = "Content-Security-Policy"
        findings = []
        max_score = 11

        if response.status_code in [403, 404, 429]:
            return {
                "plugin_name": "security_headers",
                "header_name": header_name,
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    f"Security header analysis skipped because response status was {response.status_code}"
                ]
            }

        if value is None:
            status = "MISSING"
            severity = "HIGH"
            findings.append("The CSP header is missing and has a risk to XSS injection")
            normalized_score = 1.0
            return{
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status": status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score
            }
        
        value = value.lower()
        tokens = value.split(" ")
        status = "OK"

        if "unsafe-inline" in value:
            
            findings.append("The CSP header is present but has unsafe-inline as value")
            score += 2
            status = "ACCEPTABLE"
    
        if "unsafe-eval" in value:
            
            findings.append("The CSP header is present but has unsafe-eval as value")
            score += 3
            status = "WEAK"
            
        if "*" in tokens:
        
            findings.append("The CSP header is present but has wildcard * as value")
            score += 4
            status = "WEAK"
            
        if "script-src" in value and "unsafe-eval" not in value and "unsafe-inline" not in value and "*" not in tokens :
        
            findings.append("The CSP header is present and is well enforced")
            score += 0
            status = "OK"

        if "script-src" not in value:
        
            findings.append("The CSP header is present but script-src is missing.It still has risks to XSS injection")
            score += 2
            status = "WEAK"
        
        normalized_score = score / max_score
        severity = severity_classifer(normalized_score)
        
        return{
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status": status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score
            }

class HSTSPlugin(Plugin):
    def analyze(self,response):

        value = response.headers.get("Strict-Transport-Security")
        header_name = "Strict-Transport-Security"
        findings = []
        score = 0 
        max_score = 5

        if response.status_code in [403, 404, 429]:
            return {
                "plugin_name": "security_headers",
                "header_name": header_name,
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    f"Security header analysis skipped because response status was {response.status_code}"
                ]
            }

        if value is None:
            status = "MISSING"
            severity = "HIGH"
            normalized_score = 1.0
            findings.append("The Strict-Transport-Security header is missing risks are there")

            return{
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status":status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score
            }
            
        
        value = value.lower()
        value = value.split(";")
        clean_list = []
        directive = None
        max_number = None
        found_include_subdomains = False
        found_preload = False
        status = "OK"

        for directives in value:

            clean_list.append(directives.strip())
            if "max-age" in directives:
                directive = directives
                
        if directive is None:
            findings.append("The max-age directive is missing")
            score += 3
            status = "WEAK"

        elif directive is not None:
            try:
                max_number = int(directive.split("=")[1])

            except:
                max_number = None
                findings.append("The max_age value is not valid")
                score += 2 
                status = "WEAK"

        if max_number is not None:
            
                if max_number < 31536000:
                    score += 2
                    findings.append("The max_age value is very small")
                    status = "WEAK"
        

        for direct in clean_list:

            if "includesubdomains" in direct:
                found_include_subdomains = True
            if "preload" in direct:
                found_preload = True

        if not found_include_subdomains and status == "OK":  
                score += 1 
                findings.append("The includeSubDomains is not present")
                status = "ACCEPTABLE"

        if not found_preload and (status == "OK" or status == "ACCEPTABLE"):
                score += 1
                findings.append("The preload directive is not present")
                status = "ACCEPTABLE"

        normalized_score = score / max_score
        severity = severity_classifer(normalized_score)

        return{
            "plugin_name": "security_headers",
            "header_name":header_name,
            "status":status,
            "severity":severity,
            "findings":findings,
            "normalized_score":normalized_score

        }

class XCTOPlugin(Plugin):

    def analyze(self,response):
        value = response.headers.get("X-Content-Type-Options")
        header_name = "X-Content-Type-Options"
        score = 0
        findings = []
        max_score = 4

        if response.status_code in [403, 404, 429]:
            return {
                "plugin_name": "security_headers",
                "header_name": header_name,
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    f"Security header analysis skipped because response status was {response.status_code}"
                ]
            }

        if value is None:
            status = "MISSING"
            severity = "HIGH"
            normalized_score = 1.0
            findings.append("The X-Content-Type-Options is missing and risks are there")

            return {
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status":status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score

            }
        
        value = value.strip().lower()
        
        
        if "nosniff" == value:
            score += 0
            findings.append("The XCTO header is present and properly enforced")
            status = "OK"
        else:
            score += 4
            findings.append("The XCTO header is present but not properly enforced")
            status = "WEAK"
        
        normalized_score = score / max_score
        severity = severity_classifer(normalized_score)


        return {
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status":status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score

            }

class RefPolPlugin(Plugin):

    def analyze(self,response):

        value = response.headers.get("Referrer-Policy")
        findings = []
        header_name = "Referrer-Policy"
        score = 0
        max_score = 4
        clean_list = []

        if response.status_code in [403, 404, 429]:
            return {
                "plugin_name": "security_headers",
                "header_name": header_name,
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "normalized_score": 0.0,
                "findings": [
                    f"Security header analysis skipped because response status was {response.status_code}"
                ]
            }

        if value is None:
            status = "MISSING"
            severity = "HIGH"
            findings.append("The Referrer-Policy header is missing and risks are there")
            normalized_score = 1.0

            return {
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status":status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score
            }
        
        pol_class = {
            "no-referrer":"STRONG",
            "same-origin":"STRONG",
            "strict-origin":"STRONG",
            "strict-origin-when-cross-origin":"STRONG",
            "origin":"ACCEPTABLE",
            "origin-when-cross-origin":"ACCEPTABLE",
            "no-referrer-when-downgrade":"WEAK",
            "unsafe-url":"WEAK"
        }

        main_value = None

        value = value.lower().split(",")
        for v in value:
            clean_list.append(v.strip())

        for c_value in clean_list:
            if c_value in pol_class:
                main_value = c_value
            
        if main_value == None:
            status = "INVALID"
            severity = "HIGH"
            findings.append("The given value of header is invalid")
            normalized_score = 1.0
            return {
                "plugin_name": "security_headers",
                "header_name":header_name,
                "status":status,
                "severity":severity,
                "findings":findings,
                "normalized_score":normalized_score
                }

        else:
            classification = pol_class[main_value]

        if classification == "STRONG":
            status = "OK"
            score += 0
        
        elif classification == "ACCEPTABLE":
            status = "ACCEPTABLE"
            score += 2
            findings.append("The header is enforced but has some weaknesses")

        elif classification == "WEAK":
            status = "WEAK"
            findings.append("A weak Referrer-Policy is configured.")
            score += 4

        normalized_score = score / max_score 
        severity = severity_classifer(normalized_score)
    
        return {
            "plugin_name": "security_headers",
            "header_name":header_name,
            "status":status,
            "severity":severity,
            "findings":findings,
            "normalized_score":normalized_score

        }