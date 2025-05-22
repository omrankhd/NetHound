import asyncio
import subprocess
import xmltodict
import json
import argparse
import os
import aiofiles
import sys
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, ElementTree

# Create potential CVE entries
def generate_cve_entries(ip: str, ports: list):
    cve_entries = []
    for port in ports:
        product = port.get("product", "").strip()
        version = port.get("version", "").strip()
        service = port.get("service", "").strip()

        if product and version:
            cve_entries.append({
                "ip": ip,
                "port": port["port"],
                "service": service,
                "product": product,
                "version": version,
                "cve_query": f"{product} {version}"
            })
    return cve_entries

# Save CVEs to XML
async def save_cve_xml(cve_data, output_file):
    root = Element("cve_report")
    for entry in cve_data:
        cve_elem = SubElement(root, "entry")
        for key, value in entry.items():
            child = SubElement(cve_elem, key)
            child.text = str(value)
    tree = ElementTree(root)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)

# Save CVEs to JSON
async def save_cve_json(cve_data, output_file):
    async with aiofiles.open(output_file, "w") as f:
        await f.write(json.dumps(cve_data, indent=4))

async def parse_and_save(xml_file: str, json_file: str, cve_json_file: str, cve_xml_file: str):
    async with aiofiles.open(xml_file, mode='r') as f:
        xml_content = await f.read()
        data = xmltodict.parse(xml_content)

    hosts = data.get('nmaprun', {}).get('host', [])
    if not isinstance(hosts, list):
        hosts = [hosts]

    result = []
    all_cves = []
    for host in hosts:
        address_data = host.get('address', {})
        if isinstance(address_data, list):
            ip = next((a['@addr'] for a in address_data if a.get('@addrtype') == 'ipv4'), None)
        else:
            ip = address_data.get('@addr')
        ports = host.get('ports', {}).get('port', [])
        if not isinstance(ports, list):
            ports = [ports]

        open_ports = []
        for port in ports:
            if port.get('state', {}).get('@state') == 'open':
                service = port.get('service', {})
                open_ports.append({
                    "port": port.get('@portid'),
                    "protocol": port.get('@protocol'),
                    "service": service.get('@name', 'unknown'),
                    "product": service.get('@product', 'unknown'),
                    "version": service.get('@version', 'unknown'),
                })

        if open_ports:
            result.append({"ip": ip, "open_ports": open_ports})
            all_cves.extend(generate_cve_entries(ip, open_ports))

    async with aiofiles.open(json_file, "w") as f:
        await f.write(json.dumps(result, indent=4))
    await save_cve_json(all_cves, cve_json_file)
    await save_cve_xml(all_cves, cve_xml_file)
    print(f"[✓] Saved JSON: {json_file}")
    print(f"[✓] Saved CVEs to: {cve_json_file}, {cve_xml_file}")

async def scan_target(target: str, options: list, output_dir: str, timeout: int, sem: asyncio.Semaphore, top_ports: bool = False, ports: str = None):
    async with sem:
        print(f"[+] Scanning {target}")
        xml_filename = f"{target.replace('/', '_')}.xml"
        xml_path = os.path.join(output_dir, xml_filename)
        json_path = xml_path.replace(".xml", ".json")
        cve_json = os.path.join(output_dir, "cve_results.json")
        cve_xml = os.path.join(output_dir, "cve_results.xml")

        cmd = [
            "rustscan", "-a", target,
            "-b", "2000", "-t", "2000", "--ulimit", "5500"
        ]

        if top_ports:
            cmd.append("--top")
        if ports:
            cmd += ["-p", ports]

        cmd += ["--"] + options + ["-oX", xml_path]

        try:
            proc = await asyncio.create_subprocess_exec(*cmd)
            if timeout > 0:
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            else:
                await proc.communicate()

            if os.path.exists(xml_path):
                await parse_and_save(xml_path, json_path, cve_json, cve_xml)
        except asyncio.TimeoutError:
            print(f"[!] Timeout exceeded for {target}, skipping.")

async def main(targets, options, output_dir, concurrency, timeout, top_ports, ports):
    os.makedirs(output_dir, exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_target(t, options, output_dir, timeout, sem, top_ports, ports) for t in targets]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RustScan Ingestor + CVE Collector")
    parser.add_argument("targets", nargs="+", help="List of target IPs or CIDRs")
    parser.add_argument("-o", "--output-dir", default="scan_results", help="Directory to store output files")
    parser.add_argument("--options", nargs="+", default=["-sV"], help="RustScan/Nmap options")
    parser.add_argument("--concurrency", type=int, default=4, help="Concurrent scans")
    parser.add_argument("--timeout", type=int, default=0, help="Timeout in seconds per target (0 = unlimited)")
    parser.add_argument("--top", action="store_true", help="Use RustScan's --top ports")
    parser.add_argument("-p", "--ports", help="Specify ports manually")

    args = parser.parse_args()

    if args.top and args.ports:
        print("[!] Error: Cannot use --top and -p at the same time.")
        sys.exit(1)

    asyncio.run(main(args.targets, args.options, args.output_dir, args.concurrency, args.timeout, args.top, args.ports))
