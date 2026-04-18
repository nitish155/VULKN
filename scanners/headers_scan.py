import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_headers_scan(target_url: str, cookies: dict = None) -> dict:
    details = []
    
    try:
        response = requests.get(target_url, timeout=5, verify=False, cookies=cookies)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        if 'x-frame-options' not in headers:
            details.append({
                "type": "Missing Security Header (Clickjacking)",
                "severity": "Medium",
                "description": "The 'X-Frame-Options' header is missing."
            })

        if 'content-security-policy' not in headers:
            details.append({
                "type": "Missing Security Header (CSP)",
                "severity": "Medium",
                "description": "The 'Content-Security-Policy' header is missing."
            })

        if target_url.startswith('https') and 'strict-transport-security' not in headers:
            details.append({
                "type": "Missing Security Header (HSTS)",
                "severity": "Medium",
                "description": "The 'Strict-Transport-Security' (HSTS) header is missing."
            })

        if 'x-content-type-options' not in headers or headers.get('x-content-type-options') != 'nosniff':
            details.append({
                "type": "Missing Security Header (MIME Sniffing)",
                "severity": "Low",
                "description": "The 'X-Content-Type-Options' header is missing or improperly configured."
            })

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
        pass 

    return {
        "scanner_name": "Security Headers & Info Disclosure",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }