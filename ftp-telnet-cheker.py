import xml.etree.ElementTree as ET
import ftplib
import asyncio
import argparse
import json

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

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
                    "service": service.attrib.get("name") if service is not None else None
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

async def check_services(hosts):
    results = []
    for host in hosts:
        ip = host["ip"]
        ftp_result = None
        telnet_result = None

        for svc in host["services"]:
            name = (svc["service"] or "").lower()
            port = svc["port"]

            if "ftp" in name:
                ftp_result = check_ftp(ip, port)

            elif "telnet" in name:
                telnet_result = await check_telnet(ip, port)

        # Only include if FTP or Telnet service was detected
        if ftp_result is not None or telnet_result is not None:
            results.append({
                "ip": ip,
                "ftp_anonymous": ftp_result if ftp_result is not None else False,
                "telnet_guest": telnet_result if telnet_result is not None else False
            })

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check FTP and Telnet anonymous access using Nmap XML service names")
    parser.add_argument("xml_file", help="Path to Nmap XML file")
    parser.add_argument("-o", "--output", default="ftp_telnet_service_report.json", help="Output JSON report")
    args = parser.parse_args()

    hosts = parse_nmap_xml(args.xml_file)
    findings = asyncio.run(check_services(hosts))

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=4)

    print(f"[✓] Scan complete. Results saved to {args.output}")
