import nmap
import logging
import subprocess
import argparse
import sys
import shutil
import os

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
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logging.error("This script must be run as root for aggressive scans (-A).")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Scanner (Nmap + SearchSploit)"
    )
    parser.add_argument("target", help="Target IP or domain to scan")
    return parser.parse_args()

def aggressive_scan(target):
    """Perform an aggressive Nmap scan."""
    scanner = nmap.PortScanner()
    try:
        logging.info(f"Performing aggressive scan on {target}...")
        scanner.scan(target, arguments="-T4 -A -sV --version-intensity 9 --script=vuln -Pn")
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
            ports = scanner[host].get(proto, {})

            for port, port_data in ports.items():

                state = port_data.get("state", "unknown")
                service = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                extrainfo = port_data.get("extrainfo", "")

                full_version = " ".join(filter(None, [product, version, extrainfo])) or "unknown"

                logging.info(f"Port {port} ({service}) - Version: {full_version} - State: {state}")

                if state == "open":
                    results[port] = {"service": service, "version": full_version}

    return results

def search_exploits(service, version):
    """Search exploits using SearchSploit."""
    search_query = f"{service} {version}" if version != 'unknown' else service

    try:
        result = subprocess.run(
            ["searchsploit", search_query],
            capture_output=True,
            text=True,
            check=False
        )
        output = result.stdout.strip()

        if output:
            logging.info(f"Exploits found for {service} {version}")
            return output
        else:
            return "No known exploits found."

    except Exception as e:
        logging.error(f"SearchSploit error: {e}")
        return "Error retrieving exploits."


def search_exploits(service, version):
    """Search exploits using SearchSploit."""
    search_query = f"{service} {version}".strip()

    try:
        result = subprocess.run(
            ["searchsploit", "-w", search_query],
            capture_output=True,
            text=True
        )

        if result.stdout.strip():
            return result.stdout.strip()
        elif result.stderr.strip():
            return result.stderr.strip()
        else:
            return "No known exploits found."

    except Exception as e:
        logging.error(f"SearchSploit error: {e}")
        return "Error retrieving exploits."

def save_full_report(target, scan_results):
    """Save results of all ports into one report."""
    
    output_path = "/output/scan_report.txt"
    report = f"Target: {target}\n\n"
    report += "===== OPEN PORTS =====\n"

    for port, data in scan_results.items():
        report += (
            f"\nPort {port} - Service: {data['service']} - Version: {data['version']}\n"
        )
        report += "Exploits:\n"
        report += search_exploits(data["service"], data["version"])
        report += "\n" + ("-" * 40) + "\n"

    os.makedirs("/output", exist_ok=True)

    with open(output_path, "w") as f:
        f.write(report)

    logging.info(f"Report saved to: {output_path}")


def main():
    args = parse_args()
    check_dependencies()
    scan_results = aggressive_scan(args.target)
    save_full_report(args.target, scan_results)

if __name__ == "__main__":
    main()