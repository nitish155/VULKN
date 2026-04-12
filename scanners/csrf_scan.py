# scanners/csrf_scan.py
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Hide SSL warnings for targets with bad certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common names developers use for Anti-CSRF tokens
CSRF_TOKEN_KEYWORDS = ['csrf', 'xsrf', 'token', 'authenticity', '_csrf_token']

def run_csrf_scan(target_url: str) -> dict:
    details = []
    session = requests.Session()
    session.headers["User-Agent"] = "VULKN_CSRF_Scanner/1.0"
    
    try:
        response = session.get(target_url, timeout=5, verify=False)
        soup = BeautifulSoup(response.content, "lxml")
        forms = soup.find_all("form")
        
        for form in forms:
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            
            # CSRF attacks primarily target state-changing requests, which should use POST
            if method == "post":
                has_token = False
                
                # Scan every input inside the form for a hidden token
                for input_tag in form.find_all("input"):
                    input_name = input_tag.attrs.get("name", "").lower()
                    input_type = input_tag.attrs.get("type", "").lower()
                    
                    if input_type == "hidden" and any(keyword in input_name for keyword in CSRF_TOKEN_KEYWORDS):
                        has_token = True
                        break
                
                # If no token was found in a POST form, it's a massive red flag
                if not has_token:
                    form_url = urljoin(target_url, action)
                    details.append({
                        "type": "Missing Anti-CSRF Token",
                        "severity": "Medium",
                        "description": f"A state-changing POST form targeting '{form_url}' does not contain a recognized Anti-CSRF token."
                    })
                    
    except requests.RequestException:
        pass # Target unreachable or timed out

    # Deduplicate findings in case multiple identical forms exist
    unique_details = [dict(t) for t in {tuple(d.items()) for d in details}]

    return {
        "scanner_name": "Cross-Site Request Forgery (CSRF)",
        "target_url": target_url,
        "vulnerabilities_found": len(unique_details),
        "details": unique_details
    }

# Test it locally!
if __name__ == "__main__":
    import json
    # testphp is notorious for having forms with zero CSRF protection
    vulnerable_target = "http://testphp.vulnweb.com/login.php"
    
    print("Scanning for missing Anti-CSRF tokens...")
    result = run_csrf_scan(vulnerable_target)
    print(json.dumps(result, indent=4))