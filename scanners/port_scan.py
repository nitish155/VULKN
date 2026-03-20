import socket
import concurrent.futures
from datetime import datetime

def scan_port(host, port, timeout=1):
    """Try to connect to a single port. Returns port if open, else None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return port, service
    except socket.error:
        pass
    return None

def scan(host, start_port, end_port, max_threads=100):
    """Scan a range of ports on the given host."""
    print(f"\n{'='*50}")
    print(f"  Target   : {host}")
    print(f"  Port Range: {start_port} - {end_port}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in range(start_port, end_port + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port, service = result
                open_ports.append((port, service))
                print(f"  [OPEN] Port {port:5d}  -->  {service}")

    open_ports.sort()

    print(f"\n{'='*50}")
    print(f"  Scan complete. {len(open_ports)} open port(s) found.")
    print(f"{'='*50}\n")

    return open_ports


if __name__ == "__main__":
    target = input("Enter target host (e.g. localhost or 192.168.1.1): ").strip()
    start  = int(input("Start port: ").strip())
    end    = int(input("End port:   ").strip())

    scan(target, start, end)


