import asyncio
import subprocess
import xmltodict
import json
import argparse
import os
import aiofiles
import sys
from ipaddress import ip_network
import re

async def run_rustscan(target: str, options: list, output_dir: str, timeout: int = 0, top_ports: bool = False, ports: str = None):
    print(f"[+] Scanning {target} with RustScan, timeout = {'unlimited' if timeout == 0 else f'{timeout}s'}")

    cmd = [
        "rustscan",
        "-a", target,
        "-b", "2000",
        "-t", "2000",
        "--ulimit", "5500"
    ]

    if top_ports:
        cmd.append("--top")
    if ports:
        cmd += ["-p", ports]

    
    # subnet_folder = os.path.join("/opt/xml/",output_dir)

    subnet_folder = output_dir
    os.makedirs(subnet_folder, exist_ok=True)
    output_template = os.path.join(subnet_folder, "{{ip}}.xml")

   
    cmd += ["--"] + options +["-Pn"]+ ["-oX", output_template]

    try:
        print(cmd)
        proc = await asyncio.create_subprocess_exec(*cmd)
        if timeout > 0:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        else:
            await proc.communicate()
        return output_template
    except asyncio.TimeoutError:
        print(f"[!] Timeout exceeded for {target}, skipping.")
        return None

async def parse_and_save(xml_file: str, json_file: str):
    async with aiofiles.open(xml_file, mode='r') as f:
        xml_content = await f.read()
        data = xmltodict.parse(xml_content)

    hosts = data.get('nmaprun', {}).get('host', [])
    if not isinstance(hosts, list):
        hosts = [hosts]

    result = []
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

    async with aiofiles.open(json_file, "w") as f:
        await f.write(json.dumps(result, indent=4))
    print(f"[✓] Saved JSON: {json_file}")

async def scan_target(target: str, options: list, output_dir: str, timeout: int, top_ports: bool = False, ports: str = None):
        xml_template = await run_rustscan(target, options, output_dir, timeout, top_ports, ports)
        if not xml_template:
            return

      
        try:
            net = ip_network(target, strict=False)
            for ip in net.hosts():
                # ip_path = os.path.join(output_dir, target.replace('/', '_'), f"{ip}.xml")
                ip_path = os.path.join(output_dir, f"{ip}.xml")
                if os.path.exists(ip_path):
                    json_file = ip_path.replace(".xml", ".json")
                    await parse_and_save(ip_path, json_file)
        except ValueError:
          
            ip_path = xml_template.replace("{{ip}}", target)
            if os.path.exists(ip_path):
                json_file = ip_path.replace(".xml", ".json")
                await parse_and_save(ip_path, json_file)

def discover_live_hosts_nmap(targets):
    live_hosts = set()
    for target in targets:
        print(f"[+] Running Nmap host discovery on {target}")
        try:
            result = subprocess.run(["nmap", "-sn", target], capture_output=True, text=True, check=True)
            found = re.findall(r"Nmap scan report for (?:.+? )?\(?(\d{1,3}(?:\.\d{1,3}){3})\)?", result.stdout)
            print(f"[+] Found {len(found)} live hosts in {target}")
            live_hosts.update(found)
        except subprocess.CalledProcessError as e:
            print(f"[-] Error scanning {target}: {e}")
    return list(live_hosts)


async def main(targets, options, output_dir,timeout, top_ports, ports):
    os.makedirs(output_dir, exist_ok=True)
    for target in targets:
        await scan_target(target, options, output_dir, timeout, top_ports, ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Native RustScan Ingestor with Optimized Batch Settings")
    parser.add_argument("targets", nargs="+", help="List of target IPs or CIDRs")
    parser.add_argument("-o", "--output-dir", default="rustscan_results", help="Directory to store output JSON files")
    parser.add_argument("--options", nargs="+", default=[""], help="RustScan/Nmap options passed after '--'")
    parser.add_argument("--timeout", type=int, default=0, help="Timeout per scan in seconds (0 = unlimited)")
    parser.add_argument("--top", action="store_true", help="Enable scanning top ports using RustScan's --top")
    parser.add_argument("-p", "--ports", help="Specify custom ports to scan, e.g., '22,80,443'")
    parser.add_argument("--nmap-host-discovery", action="store_true", help="Use Nmap -sn to discover live hosts before scanning")

    args = parser.parse_args()

    # Prevent user from using --top and -p at the same time
    if args.top and args.ports:
        print("[!] Error: You cannot use both --top and --ports (-p) at the same time.")
        sys.exit(1)
    final_targets = args.targets
    if args.nmap_host_discovery:
        for t in args.targets:
            if '/' not in t:
                print(f"[!] Error: --nmap-host-discovery requires CIDR notation, but '{t}' is not a CIDR (e.g., /24)")
                sys.exit(1)

    if args.nmap_host_discovery:
        final_targets = discover_live_hosts_nmap(args.targets)
        if not final_targets:
            print("[!] No live hosts found. Exiting.")
            sys.exit(1)
print(f"[+] Final targets: {final_targets}")
asyncio.run(main(final_targets, args.options, args.output_dir, args.timeout, args.top, args.ports))
