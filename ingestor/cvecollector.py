import xml.etree.ElementTree as ET
import ftplib
import asyncio
import argparse
import json
import requests
import dns.message
import dns.query
from vuln_checkers import check_ftp, check_dns, check_smtp, check_smb,check_telnet
from time import sleep
from pathlib import Path
import pprint

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


# async def check_telnet(ip, port, timeout=5):
#     default_creds = [
#         # Generic
#         ("admin", "admin"),
#         ("root", "root"),
#         ("admin", "password"),
#         ("user", "user"),
#         ("guest", "guest"),
#         ("root", "admin"),
#         ("root", "password"),
#         ("admin", ""),  # admin with blank password
#         ("", "admin"),   # blank username, admin password
#         # Cisco
#         ("cisco", "cisco"),
#         ("admin", "cisco"),
#         ("cisco", "admin"),
#         # Juniper
#         ("root", "Juniper"),
#         ("root", "Juniper123"),
#         # MikroTik
#         ("admin", ""),
#         ("admin", "admin"),
#         # D-Link
#         ("admin", ""),
#         ("admin", "admin"),
#         # Zyxel
#         ("admin", "1234"),
#         # Huawei
#         ("admin", "admin"),
#         ("root", "admin"),
#         # Netgear
#         ("admin", "password"),
#     ]
#     try:
#         reader, writer = await asyncio.wait_for(
#             asyncio.open_connection(ip, port), timeout=timeout
#         )
#         for username, password in default_creds:
#             try:
#                 # Wait for login prompt
#                 data = await asyncio.wait_for(reader.readuntil(b":"), timeout=2)
#                 writer.write((username + "\n").encode())
#                 await writer.drain()
#                 # Wait for password prompt
#                 data = await asyncio.wait_for(reader.readuntil(b":"), timeout=2)
#                 writer.write((password + "\n").encode())
#                 await writer.drain()
#                 # Read response after login attempt
#                 data = await asyncio.wait_for(reader.read(1024), timeout=2)
#                 if b"Last login" in data or b"#" in data or b"$" in data or b"Welcome" in data:
#                     writer.close()
#                     await writer.wait_closed()
#                     return (username, password)
#             except Exception:
#                 continue
#         writer.close()
#         await writer.wait_closed()
#         return None
#     except Exception:
#         return None


def check_Dns(ip,port, test_domain="example.com"):
    try:
        q = dns.message.make_query(test_domain, dns.rdatatype.A)
        r = dns.query.udp(q, ip, timeout=2,port=port)
        return bool(r.answer)
    except Exception:
        return False

def query_vulners(product, version):
    url = "https://vulners.com/api/v3/search/lucene/"
    query = f'{product} {version}'
    params = {'query': query, 'size': 10}
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pprint.pprint(data)
            cves = set()
            # Lucene endpoint
            if data.get('result') == 'OK' and 'documents' in data.get('data', {}):
                for doc in data['data']['documents']:
                    if 'cvelist' in doc and doc['cvelist']:
                        cves.update(doc['cvelist'])
                    elif 'id' in doc and doc['id'].startswith('CVE-'):
                        cves.add(doc['id'])
            # Burp/software or other endpoint
            elif data.get('result') == 'OK' and 'search' in data.get('data', {}):
                for doc in data['data']['search']:
                    cvelist = doc.get('_source', {}).get('cvelist', [])
                    cves.update(cvelist)
            return list(cves)
    except Exception as e:
        print(f"[!] Vulners API error for {product} {version}: {e}")
    return []

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
            print (product)
            print (version)
            # Check FTP
            if "ftp" in name or port == (21 or 20 ):
               svc["ftp vulnerability check"]  = check_ftp.run_ftp_vuln_scan(ip, port, timeout=10)

            # Check Telnet
            if "telnet" in name or port == 23:
                svc["telnet vulnerability check"] = check_telnet.run_telnet_vuln_scan(ip, port)
            # Check DNS
            if "domain" in name or port == 53:
                svc["DNS vulnerability check"] = check_dns.run_dns_vuln_scan(ip)
            if "smtp" in name or port == 25:
                svc["SMTP vulnerability check"] = check_smtp.run_smtp_vuln_scan(ip, port, timeout=10)   
            if "smb" in name or port == 445:
                svc["SMB vulnerability check"] = check_smb.run_smb_vuln_scan(ip, port, timeout=10)  
            # Query Vulners
            cves = query_vulners(product, version)
            sleep(1) 
            svc.update({"cves": cves})
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
