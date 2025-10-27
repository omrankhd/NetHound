import asyncio
import subprocess
import argparse
import os
import sys
from ipaddress import ip_network
import re

async def run_rustscan(target: str, options: list, output_dir: str, top_ports: bool = False, ports: str = None):
    print(f"[+] Scanning {target} with RustScan")

    cmd = [
        "rustscan",
        "-a", target,
        "-b", "2000",
        "-t", "2000",
        "--no-banner",  
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
        await proc.communicate()
        return output_template
    except Exception as e:
        print(f"[!] Error scanning {target}: {e}")
        return None


async def scan_target(target: str, options: list, output_dir: str, top_ports: bool = False, ports: str = None):
        xml_template = await run_rustscan(target, options, output_dir, top_ports, ports)
        if not xml_template:
            return

      
        try:
            net = ip_network(target, strict=False)
            for ip in net.hosts():
                # ip_path = os.path.join(output_dir, target.replace('/', '_'), f"{ip}.xml")
                ip_path = os.path.join(output_dir, f"{ip}.xml")
                # if os.path.exists(ip_path):
                #     json_file = ip_path.replace(".xml", ".json")
                #     await parse_and_save(ip_path, json_file)
        except ValueError:
          
            ip_path = xml_template.replace("{{ip}}", target)
            # if os.path.exists(ip_path):
            #     json_file = ip_path.replace(".xml", ".json")
            #     await parse_and_save(ip_path, json_file)

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


async def main(targets, options, output_dir, top_ports, ports):
    os.makedirs(output_dir, exist_ok=True)
    for target in targets:
        await scan_target(target, options, output_dir, top_ports, ports)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Native RustScan Ingestor with Optimized Batch Settings")
    parser.add_argument("targets", nargs="+", help="List of target IPs or CIDRs")
    parser.add_argument("-o", "--output-dir", default="rustscan_results", help="Directory to store output JSON files")
    parser.add_argument("--options", nargs="+", default=[""], help="RustScan/Nmap options passed after '--'")
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
asyncio.run(main(final_targets, args.options, args.output_dir, args.top, args.ports))
