import xml.etree.ElementTree as ET
import asyncio
import argparse
import json
import requests
import time
from vuln_checkers import check_ftp, check_dns, check_smtp, check_smb,check_telnet,checkservice3
from time import sleep
from pathlib import Path
from vuln_checkers.vulnerability_scanner import MultiSourceVulnerabilityScanner


scanner = MultiSourceVulnerabilityScanner()
def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Error parsing {xml_file}: {e}")
        return []

    results = []
    for host in root.findall('host'):
        addr = host.find('address')
        ip = addr.attrib['addr'] if addr is not None else None
        if not ip:
            continue

        services = []
        for port in host.findall(".//port"):
            state = port.find("state")
            # if state is not None and state.attrib.get("state") == "open":
            if state is not None :
                service = port.find("service")
                port_info = {
                    "port": int(port.attrib['portid']),
                    "state": state.attrib.get("state"),
                    "protocol": port.attrib['protocol'],
                    "service": service.attrib.get("name") if service is not None else None,
                    "product": service.attrib.get("product") if service is not None else None,
                    "version": service.attrib.get("version") if service is not None else None
                }
                services.append(port_info)

        results.append({"ip": ip, "services": services})
    return results




async def check_services(hosts):

    
    results = []

    for host in hosts:
        ip = host["ip"]
        enriched_services = []
        
        for svc in host["services"]:
            name = (svc["service"] or "").lower()
            port = svc["port"]
            product = svc.get("product")
            version = svc.get("version")
            print(product)
            print(version)
            # Run service detection for this port (returns a list of dicts)
            misc_results = checkservice3.run_service_detection(ip, str(port))
            svc["Misc"] = misc_results
            
            # Find the result for the current port
            if misc_results:
                # Option 1: Use first result (if the function returns results for the specific port only)
                result = misc_results[0]
                
                # Handle product assignment
                if not product and result:
                    product = result.get("service", "")
                    if product:
                        svc.update({"product": product})
                
                if product == "Unknown":
                    product = svc.get("service", "")
                
                # Handle version assignment - check if version is already assigned or is "Unknown"
                if (not version or version == "Unknown") and result:
                    new_version = result.get("version", None)
                    if new_version:
                        version = new_version
                        svc.update({"version": version})
            
            print(product)
            print(version)
            
            # Check FTP
            if "ftp" in name or port in (21, 20):  # Fixed the condition here
                svc["ftp vulnerability check"] = check_ftp.run_ftp_vuln_scan(ip, port, timeout=10)
            
            # Check Telnet
            if "telnet" in name or port == 23:
                svc["telnet vulnerability check"] = check_telnet.run_telnet_vuln_scan(ip, port)
            
            # Check DNS
            if "domain" in name or port == 53 or port == 5353:
                svc["DNS vulnerability check"] = check_dns.run_dns_vuln_scan(ip)
            
            if "smtp" in name or port == 25:
                svc["SMTP vulnerability check"] = check_smtp.run_smtp_vuln_scan(ip, port, timeout=10)
            
            if any(x in name for x in ["smb", "netbios", "microsoft-ds", "samba"]) or port == 445:
                svc["SMB vulnerability check"] = check_smb.run_smb_vuln_scan(ip, port, timeout=10)
            
            # Query Vulners
            # if product and version:
            #     print(f"Querying Vulners for {product} {version} on {ip}:{port}")
            #     cves = query_vulners(product, version)
            #     sleep(1)
            #     svc.update({"cves": cves})
            # else:
            #     print(f"Skipping Vulners query for {ip}:{port} - missing product/version")
            
            if product:
                print(f"Scanning vulnerabilities for {product} {version} on {ip}:{port}")
                svc["vulns"] = scanner.scan_vulnerabilities(product, version, port)
          
                
            enriched_services.append(svc)
        
        results.append({
            "ip": ip,
            "services": enriched_services
        })

    return results

def load_all_xml_files(folder_path):
    xml_files = list(Path(folder_path).rglob("*.xml"))  # recursively get .xml files
    all_hosts = []
    for xml_file in xml_files:
        print(f"[+] Parsing: {xml_file}")
        hosts = parse_nmap_xml(xml_file)
        all_hosts.extend(hosts)
    return all_hosts

def runcvecollector(folder_project, outputfilename, scan_options=None):
    output = outputfilename

    all_hosts = load_all_xml_files(folder_project)
    print(all_hosts)
    findings = asyncio.run(check_services(all_hosts))

    # Create the final output structure
    output_data = {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_options": scan_options
        },
        "scan_results": findings
    }

    with open(output, "w") as f:
        json.dump(output_data, f, indent=4)

    print(f"\n[✓] Scan complete. Combined results saved to: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk Nmap XML Analyzer: FTP/Telnet Check & CVE Lookup")
    parser.add_argument("input_folder", help="Folder containing Nmap XML files")
    parser.add_argument("-o", "--output", default="nmap_bulk_report.json", help="Output JSON report file")
    args = parser.parse_args()

    all_hosts = load_all_xml_files(args.input_folder)
    print(all_hosts)
    findings = asyncio.run(check_services(all_hosts))

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=4)

    print(f"\n[✓] Scan complete. Combined results saved to: {args.output}")
