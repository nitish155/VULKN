import nmap
from urllib.parse import urlparse

TOP_PORTS = [
    "20","21","22","23","25","53","67","68","69",
    "80","88","110","111","119","123","135","137","138","139",
    "143","161","179","194","389","427","443","445","465","500",
    "512","513","514","515","520","548","554","587","623","631",
    "636","989","990","993","995","1433","1434","1521","1723",
    "2049","2082","2083","2086","2087","2181","2222","2375","2376",
    "2483","2484","3000","3128","3260","3306","3389","3690",
    "4444","5000","5001","5060","5061","5432","5601","5800","5900",
    "5985","5986","6379","6443","6667","7001","7002","7443","7777",
    "8000","8008","8009","8080","8081","8082","8088","8090","8091",
    "8181","8333","8443","8500","8888","9000","9042","9080","9090",
    "9091","9100","9200","9443","9999","10000","11211","27017"
]

# Nmap scans TCP ports, not HTTP sessions. We add cookies=None just so the signature matches.
def run_port_scan(target_url: str, cookies: dict = None) -> dict:
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    if ':' in domain:
        domain = domain.split(':')[0]

    port_string = ",".join(TOP_PORTS)
    details = []

    try:
        scanner = nmap.PortScanner()
        scanner.scan(domain, port_string, arguments='-sT -sC -sV -T4')
        
    except nmap.PortScannerError as e:
        details.append({
            "type": "Scanner Error",
            "payload_used": "Nmap",
            "severity": "Info",
            "description": f"Nmap scanning error: {str(e)}"
        })
        return _build_response(target_url, details)
    except Exception as e:
        details.append({
            "type": "Execution Error",
            "payload_used": "Nmap",
            "severity": "Info",
            "description": f"Failed to execute Nmap. Error: {str(e)}"
        })
        return _build_response(target_url, details)

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                data = scanner[host][proto][port]
                
                if data['state'] == "open":
                    name = data.get('name', 'unknown')
                    product = data.get('product', '')
                    version = data.get('version', '')
                    
                    service_info = f"{name} {product} {version}".strip()
                    description = f"Port {port}/{proto} is open. Identified service: {service_info if service_info else 'Unknown'}."
                    
                    if 'script' in data:
                        script_results = " | ".join([f"[{k}] {v}" for k, v in data['script'].items()])
                        description += f" Script output: {script_results}"

                    details.append({
                        "type": f"Exposed Port ({port}/{proto})",
                        "payload_used": "Nmap -sT -sC -sV",
                        "severity": "Medium",
                        "description": description
                    })

    return _build_response(target_url, details)

def _build_response(target_url: str, details: list) -> dict:
    return {
        "scanner_name": "Advanced Nmap Scanner",
        "target_url": target_url,
        "vulnerabilities_found": len(details),
        "details": details
    }