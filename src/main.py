import nmap
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'  # Overwrite log file on each run.
)

def generate_report(results):
    report = {
        "timestamp": datetime.now().isoformat(),
        "results": results,
        "recommendations": []
    }

    if any(r['vulnerabilities'] for r in results):
        report["recommendations"].append("Close unnecessary ports and update vulnerable services.")

    with open('security_report.json', 'w') as f:
        json.dump(report, f, indent=4)

    logging.info("Report generated. See security_report.json for details.")

def main():
    subnet = "10.0.0.0/24"  # Scan the whole subnet ("Use your subnet here")
    ports_to_check = "22,80,443" #Can be modified to check other ports.
    nm = nmap.PortScanner()
    print(f"Starting scan on subnet: {subnet} for ports: {ports_to_check}")
    results = []
    

    try:
        nm.scan(hosts=subnet, ports=ports_to_check)
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()}) - State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', '')
                    banner = nm[host][proto][port].get('product', '')

                    vulnerabilities = port in [22, 80,443,]  # Example vulnerable ports
                    if vulnerabilities:
                        message = f"ALERT: {host} has vulnerable port {port} open!"
                        print(message)
                        logging.warning(message)

                    results.append({
                        "ip": host,
                        "port": port,
                        "service": service,
                        "state": state,
                        "banner": banner,
                        "vulnerabilities": vulnerabilities
                    })

        generate_report(results)
        print("Scan complete. Report generated as security_report.json and scanner.log.")

    except Exception as e:
        logging.error(f"Error scanning subnet: {e}")


if __name__ == "__main__":
    main()

# End of file