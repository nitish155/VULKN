# scanners/headers_scan.py
import requests
import urllib3

# Hide SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_headers_scan(target_url: str) -> dict:
    details = []
    
    try:
        # We only need to fetch the headers, so a 5-second timeout is plenty
        response = requests.get(target_url, timeout=5, verify=False)
        
        # Convert all headers to lowercase to make checking easy
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # 1. Clickjacking Defense (X-Frame-Options)
        if 'x-frame-options' not in headers:
            details.append({
                "type": "Missing Security Header (Clickjacking)",
                "severity": "Medium",
                "description": "The 'X-Frame-Options' header is missing. The website can be embedded in an attacker's iframe."
            })

        # 2. XSS Mitigation (Content-Security-Policy)
        if 'content-security-policy' not in headers:
            details.append({
                "type": "Missing Security Header (CSP)",
                "severity": "Medium",
                "description": "The 'Content-Security-Policy' header is missing, removing a major layer of defense against XSS."
            })

        # 3. Protocol Downgrade Defense (Strict-Transport-Security)
        if target_url.startswith('https') and 'strict-transport-security' not in headers:
            details.append({
                "type": "Missing Security Header (HSTS)",
                "severity": "Medium",
                "description": "The 'Strict-Transport-Security' (HSTS) header is missing. Users could be downgraded to insecure HTTP."
            })

        # 4. MIME Sniffing Defense
        if 'x-content-type-options' not in headers or headers.get('x-content-type-options') != 'nosniff':
            details.append({
                "type": "Missing Security Header (MIME Sniffing)",
                "severity": "Low",
                "description": "The 'X-Content-Type-Options' header is missing or improperly configured."
            })

        # 5. Information Disclosure (Leaking backend tech)
        if 'server' in headers:
            details.append({
                "type": "Information Disclosure",
                "severity": "Low",
                "description": f"The server is leaking its software version in the headers: {response.headers.get('Server')}"
            })
            
        if 'x-powered-by' in headers:
            details.append({
                "type": "Information Disclosure",
                "severity": "Low",
                "description": f"The server is leaking its backend framework: {response.headers.get('X-Powered-By')}"
            })

    except requests.RequestException:
        pass # If the site is down, we just return an empty scan

    return {
        "scanner_name": "Security Headers & Info Disclosure",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }

# Test it locally!
if __name__ == "__main__":
    import json
    # testphp is basically a sieve for security headers
    vulnerable_target = "http://testphp.vulnweb.com"
    
    print("Scanning HTTP headers...")
    result = run_headers_scan(vulnerable_target)
    print(json.dumps(result, indent=4))