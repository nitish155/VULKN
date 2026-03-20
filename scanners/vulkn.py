def get_target():
    url = input("Enter target URL to scan: ")
    return url

def validate_url(url):
    if url.startswith("http://") or url.startswith("https://"):
        return True
    else:
        return False

def mock_scan(url):
    print(f"\n[VULKN] Starting scan on: {url}")
    print("[VULKN] Checking for SQL Injection...")
    print("[VULKN] Checking for XSS...")
    print("[VULKN] Checking for CSRF...")
    print("[VULKN] Checking open ports...")
    print("[VULKN] Checking for weak auth...")
    print("[VULKN] Checking directory traversal...")
    print(f"\n[VULKN] Scan complete. Report ready for: {url}")

def main():
    print("=" * 40)
    print("   VULKN — Web Security Scanner")
    print("=" * 40)

    url = get_target()

    if validate_url(url):
        mock_scan(url)
    else:
        print("[ERROR] Invalid URL. Must start with http:// or https://")

if __name__ == "__main__":
    main()