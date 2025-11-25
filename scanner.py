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
        description="Automated Vulnerability Scanner (Nmap + SearchSploit)"
    )
    parser.add_argument("target", help="Target IP or domain to scan")
    return parser.parse_args()

def aggressive_scan(target):
    """Perform an aggressive Nmap scan."""
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

def save_full_report(target, scan_results):
    """Save results of all ports into one report."""
    report = f"Target: {target}\n\n"
    report += "===== OPEN PORTS =====\
