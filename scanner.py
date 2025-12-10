import nmap
import logging
import subprocess
import sys
import shutil
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def check_dependencies():
    """Ensure required tools and permissions are available."""
    if shutil.which("nmap") is None:
        logging.error("Nmap is not installed. Please install it and try again.")
        sys.exit(1)

    if shutil.which("searchsploit") is None:
        logging.error("SearchSploit is not installed. Please install it and try again.")
        sys.exit(1)

    # Root permission check (Linux/macOS only)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logging.error("This script must be run as root for aggressive scans (-A).")
        sys.exit(1)


def aggressive_scan(target):
    """Perform aggressive full vuln scan on target."""
    scanner = nmap.PortScanner()

    try:
        logging.info(f"Performing aggressive vulnerability scan on {target}...")
        scanner.scan(
            target,
            arguments="-T4 -A -sV --version-intensity 9 --script=vuln -Pn"
        )
    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        sys.exit(1)

    results = {}

    for host in scanner.all_hosts():
        logging.info(f"Scan results for {host}:")
        for proto in scanner[host].all_protocols():
            for port, port_data in scanner[host][proto].items():

                state = port_data.get("state", "unknown")
                service = port_data.get("name", "unknown")
                product = port_data.get("product", "")
                version = port_data.get("version", "")
                extrainfo = port_data.get("extrainfo", "")

                full_version = " ".join(
                    x for x in [product, version, extrainfo] if x
                ) or "unknown"

                logging.info(
                    f"Port {port} ({service}) - Version: {full_version} - State: {state}"
                )

                if state == "open":
                    results[port] = {
                        "service": service,
                        "version": full_version
                    }

    return results


def search_exploits(service, version):
    """Search exploits using SearchSploit with web references."""
    query = f"{service} {version}".strip()

    try:
        result = subprocess.run(
            ["searchsploit", "-w", query],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip() or result.stderr.strip()

        return output if output else "No known exploits found."

    except Exception as e:
        logging.error(f"SearchSploit error: {e}")
        return "Error retrieving exploits."


def save_full_report(target, scan_results):
    """Save results of all ports into a single report file."""

    os.makedirs("output", exist_ok=True)
    output_path = "output/scan_report.txt"

    report = f"TARGET: {target}\n"
    report += "=" * 60 + "\n"
    report += "OPEN PORTS & EXPLOITS\n"
    report += "=" * 60 + "\n"

    for port, data in scan_results.items():
        service = data["service"]
        version = data["version"]

        report += (
            f"\nPort {port}\n"
            f"Service : {service}\n"
            f"Version : {version}\n"
            f"Exploits:\n"
            f"{search_exploits(service, version)}\n"
            + "-" * 60 + "\n"
        )

    with open(output_path, "w") as f:
        f.write(report)

    logging.info(f"Full report saved to: {output_path}")


def main():
    check_dependencies()

    target = input("Enter target IP or domain: ").strip()
    if not target:
        logging.error("No target entered. Exiting.")
        sys.exit(1)

    scan_results = aggressive_scan(target)
    if not scan_results:
        logging.info("No open ports found. Nothing to report.")
        return

    save_full_report(target, scan_results)


if __name__ == "__main__":
    main()
