import xml.etree.ElementTree as ET
import ftplib
import asyncio
import argparse
import json
import requests
from time import sleep
from pathlib import Path

VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"

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
            if state is not None and state.attrib.get("state") == "open":
                service = port.find("service")
                port_info = {
                    "port": int(port.attrib['portid']),
                    "protocol": port.attrib['protocol'],
                    "service": service.attrib.get("name") if service is not None else None,
                    "product": service.attrib.get("product") if service is not None else None,
                    "version": service.attrib.get("version") if service is not None else None
                }
                services.append(port_info)

        results.append({"ip": ip, "services": services})
    return results

def check_ftp(ip, port, timeout=5):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        ftp.login()
        ftp.quit()
        return True
    except Exception:
        return False

async def check_telnet(ip, port, timeout=5):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def query_vulners(product, version):
    if not product or not version:
        return []
    params = {
        'software': f"{product} {version}"
    }
    try:
        response = requests.get(VULNERS_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            if data['result'] == 'OK':
                return [cve['id'] for cve in data['data']['search'] if 'id' in cve]
    except Exception as e:
        print(f"[!] Vulners API error for {product} {version}: {e}")
    return []

async def check_services(hosts):
    results = []

    for host in hosts:
        ip = host["ip"]
        ftp_result = None
        telnet_result = None
        enriched_services = []

        for svc in host["services"]:
            name = (svc["service"] or "").lower()
            port = svc["port"]
            product = svc.get("product")
            version = svc.get("version")

            # Check FTP
            if "ftp" in name:
                ftp_result = check_ftp(ip, port)

            # Check Telnet
            elif "telnet" in name:
                telnet_result = await check_telnet(ip, port)

            # Query Vulners
            cves = query_vulners(product, version)
            sleep(1) 
            svc.update({"cves": cves})
            enriched_services.append(svc)

        results.append({
            "ip": ip,
            "ftp_anonymous": ftp_result if ftp_result is not None else False,
            "telnet_guest": telnet_result if telnet_result is not None else False,
            "services": enriched_services
        })

    return results

from pathlib import Path

def load_all_xml_files(folder_path):
    xml_files = list(Path(folder_path).rglob("*.xml"))  # recursively get .xml files
    all_hosts = []
    for xml_file in xml_files:
        print(f"[+] Parsing: {xml_file}")
        hosts = parse_nmap_xml(xml_file)
        all_hosts.extend(hosts)
    return all_hosts

def runcvecollector(folder_project,outputfilename):
    output = outputfilename

    all_hosts = load_all_xml_files(folder_project)
    print(all_hosts)
    findings = asyncio.run(check_services(all_hosts))

    with open(output, "w") as f:
        json.dump(findings, f, indent=4)

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
