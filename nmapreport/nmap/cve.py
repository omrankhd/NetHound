#!/home/rootme47/Desktop/NetHounD/.venv/bin/python
import xmltodict
import json
import os
import hashlib
import re
import requests
import sys

VULNERS_API_KEY = os.getenv('VULNERS_API_KEY')  # Set as env var
print(os.environ.get('VULNERS_API_KEY'))
print(sys.executable)
VULNERS_URL = "https://vulners.com/api/v3/burp/software/"

def get_cpe_from_xml(xmlfile):
    cpe_data = {}

    with open(xmlfile, 'r', encoding='utf-8') as f:
        data = xmltodict.parse(f.read())

    hosts = data['nmaprun'].get('host', [])
    if not isinstance(hosts, list):
        hosts = [hosts]

    for host in hosts:
        address = None
        addr_info = host.get('address', {})
        if isinstance(addr_info, list):
            for a in addr_info:
                if a.get('@addrtype') == 'ipv4':
                    address = a.get('@addr')
        elif isinstance(addr_info, dict):
            address = addr_info.get('@addr')

        if not address:
            continue

        cpe_data[address] = []

        ports = host.get('ports', {}).get('port', [])
        if not isinstance(ports, list):
            ports = [ports]

        for port in ports:
            service = port.get('service', {})
            if isinstance(service, dict):
                service_cpe = service.get('cpe', [])
                if isinstance(service_cpe, str):
                    cpe_data[address].append(service_cpe)
                elif isinstance(service_cpe, list):
                    cpe_data[address].extend(service_cpe)

    return cpe_data

def query_vulners(cpe):
    headers = {'Content-Type': 'application/json'}
    payload = {
        "software": cpe,
        "apiKey": VULNERS_API_KEY
    }

    try:
        response = requests.post(VULNERS_URL, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] Failed to query Vulners for {cpe} - Status: {response.status_code}")
    except Exception as e:
        print(f"[!] Error querying Vulners for {cpe}: {e}")
    return None

def get_cves(xmlfile):
    if not VULNERS_API_KEY:
        print(os.environ['HOME'])
        
        print(VULNERS_API_KEY)
        print("[!] Please set your Vulners API key in the VULNERS_API_KEY environment variable.")
        return

    scanfile_md5 = hashlib.md5(xmlfile.encode()).hexdigest()
    cpe_dict = get_cpe_from_xml(xmlfile)
    output_dir = "/opt/notes"
    os.makedirs(output_dir, exist_ok=True)

    for host, cpes in cpe_dict.items():
        all_cves = []
        for cpe in cpes:
            vulners_data = query_vulners(cpe)
            if vulners_data and 'data' in vulners_data and 'search' in vulners_data['data']:
                vulns = vulners_data['data']['search']
                all_cves.extend(vulns)

        if all_cves:
            host_md5 = hashlib.md5(host.encode()).hexdigest()
            outpath = os.path.join(output_dir, f"{scanfile_md5}_{host_md5}.cve")
            with open(outpath, 'w') as f:
                f.write(json.dumps(all_cves, indent=4))
            print(f"[+] Saved {len(all_cves)} CVEs for {host} to {outpath}")
        else:
            print(f"[-] No CVEs found for host {host}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cve_ingestor.py <nmap_xml_file>")
        sys.exit(1)

    get_cves(sys.argv[1])
