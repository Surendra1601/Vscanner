import nmap
import logging
import subprocess
import argparse
import sys
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_dependencies():
    """Ensure required tools are installed."""
    if shutil.which("nmap") is None:
        logging.error("Nmap is not installed. Please install it and try again.")
        sys.exit(1)
    if shutil.which("searchsploit") is None:
        logging.error("SearchSploit is not installed. Please install it and try again.")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python-based Vulnerability Scanner with Nmap and SearchSploit"
    )
    parser.add_argument("target", nargs="?", help="Target IP or domain to scan")
    parser.add_argument("--port", type=int, help="Open port number to analyze for vulnerabilities")
    return parser.parse_args()

def aggressive_scan(target):
    scanner = nmap.PortScanner()
    try:
        logging.info(f"Performing aggressive scan on {target}...")
        scanner.scan(target, arguments="-T4 -A -sV --version-intensity 9 --script=version -Pn")
    except nmap.PortScannerError as e:
        logging.error(f"Nmap scan failed: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error during scan: {e}")
        sys.exit(1)

    results = {}
    for host in scanner.all_hosts():
        logging.info(f"Results for {host}:")
        for proto in scanner[host].all_protocols():
            for port, port_data in scanner[host][proto].items():
                state = port_data['state']
                service = port_data.get('name', 'unknown')
                version = port_data.get('version', 'unknown')
                logging.info(f"Port {port} ({service}) - Version: {version} - State: {state}")
                if state == 'open':
                    results[port] = {"service": service, "version": version}
    return results

def search_exploits(service, version):
    search_query = f"{service} {version}" if version != 'unknown' else service
    try:
        result = subprocess.run(
            ["searchsploit", search_query],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout.strip()
        if output:
            logging.info(f"Exploits found for {service} {version}:\n{output}")
            return output
        else:
            logging.info(f"No known exploits found for {service} {version}")
            return "No known exploits found."
    except subprocess.CalledProcessError as e:
        logging.error(f"SearchSploit error: {e}")
        return "Error retrieving exploits."
    except Exception as e:
        logging.error(f"Unexpected error using searchsploit: {e}")
        return "Error retrieving exploits."

def select_port(scan_results, preselected_port=None):
    open_ports = list(scan_results.keys())
    if not open_ports:
        logging.info("No open ports found.")
        return None

    if preselected_port and preselected_port in open_ports:
        return preselected_port

    print(f"\nOpen Ports Detected: {open_ports}")
    while True:
        try:
            selected_port = int(input("Select a port to analyze for vulnerabilities: "))
            if selected_port in open_ports:
                return selected_port
            else:
                logging.error("Selected port is not open. Try again.")
        except ValueError:
            logging.error("Invalid input. Please enter a valid port number.")
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            sys.exit(0)

def save_report(target, port, service, version, exploits):
    report_content = (
        f"Target: {target}\n"
        f"Port: {port}\n"
        f"Service: {service}\n"
        f"Version: {version}\n\n"
        f"Exploits:\n{exploits}\n"
        f"{'-'*40}\n"
    )
    try:
        with open("scan_report.txt", "w") as f:
            f.write(report_content)
        logging.info("Scan completed! Report saved as scan_report.txt")
    except Exception as e:
        logging.error(f"Failed to write report: {e}")

def main():
    check_dependencies()
    args = parse_args()

    try:
        target = args.target or input("Enter target IP or domain: ").strip()
        if not target:
            logging.error("No target specified. Exiting.")
            sys.exit(1)

        scan_results = aggressive_scan(target)
        if not scan_results:
            logging.info("No open ports found.")
            return

        selected_port = select_port(scan_results, args.port)
        if selected_port is None:
            return

        service = scan_results[selected_port]['service']
        version = scan_results[selected_port]['version']
        exploits = search_exploits(service, version)
        save_report(target, selected_port, service, version, exploits)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
