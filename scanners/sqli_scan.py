# scanners/sqli_scan.py
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Hide SSL warnings for targets with bad certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The Error Signatures: If any of these appear in the HTML, the database is vulnerable.
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_fetch_assoc()",
    # SQL Server
    "unclosed quotation mark after the character string",
    "microsoft sql native client error",
    "odbc sql server driver",
    # PostgreSQL
    "syntax error at or near",
    "valid postgresql error",
    # Oracle
    "ora-00933",
    "quoted string not properly terminated",
    "oracle error"
]

def run_sqli_scan(target_url: str) -> dict:
    # Characters that break SQL syntax
    payloads = ["'", "\"", "`", "')", "';", "\\"]
    
    details = []
    
    # Parse the URL to find query parameters (e.g., ?id=1)
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    # List of URLs to test. We always test the raw URL + dummy param just in case
    test_urls = []
    if not query_params:
        # If no params exist, append a dummy one to test
        for payload in payloads:
            test_urls.append(f"{target_url}?id={payload}")
    else:
        # If params exist (e.g., id=1), inject payload into each parameter
        for payload in payloads:
            for key, values in query_params.items():
                for value in values:
                    # Create a copy of the params and inject the payload
                    malicious_params = query_params.copy()
                    malicious_params[key] = [value + payload]
                    
                    # Rebuild the malicious URL
                    malicious_query = urlencode(malicious_params, doseq=True)
                    malicious_url = urlunparse(list(parsed_url[:4]) + [malicious_query] + list(parsed_url[5:]))
                    test_urls.append(malicious_url)

    # Execute the scan
    for test_url in test_urls:
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            response_text = response.text.lower()
            
            # Scan the HTML response for any known database errors
            for error in SQL_ERRORS:
                if error in response_text:
                    details.append({
                        "type": "Error-Based SQL Injection",
                        "payload_used": test_url,
                        "severity": "Critical",
                        "description": f"Database syntax error leaked in HTTP response. Matched signature: '{error}'"
                    })
                    break # Break inner loop so we don't duplicate logs for multiple matches
                    
            if details:
                break # If we confirmed SQLi, stop spamming the server with more payloads
                
        except requests.RequestException:
            continue

    return {
        "scanner_name": "SQL Injection (Error-Based)",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }

# Test it locally!
if __name__ == "__main__":
    import json
    # testphp.vulnweb.com is a legal, intentionally vulnerable site built for testing tools!
    vulnerable_target = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print("Scanning for SQLi...")
    result = run_sqli_scan(vulnerable_target)
    print(json.dumps(result, indent=4))