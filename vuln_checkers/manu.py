import socket
import sys
import re

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        return False
    finally:
        sock.close()

def get_service_version(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Attempt to grab banner first (generic approach)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()

        # Implement protocol-specific detection here
        if port == 80 or port == 443:
            http_version = detect_http_version(ip, port, timeout)
            if http_version:
                return f"HTTP: {http_version}"
        elif port == 21:
            ftp_version = detect_ftp_version(ip, port, timeout)
            if ftp_version:
                return f"FTP: {ftp_version}"
        elif port == 22:
            ssh_version = detect_ssh_version(ip, port, timeout)
            if ssh_version:
                return f"SSH: {ssh_version}"
        elif port == 53:
            dns_version = detect_dns_version(ip, port, timeout)
            if dns_version:
                return f"DNS: {dns_version}"

        # If no specific protocol detection, try to identify from banner using fingerprints
        if banner:
            return identify_service_from_banner(banner, port)

        return "No specific version detected (generic banner grab failed)"

    except socket.timeout:
        return "Timeout during version detection"
    except ConnectionRefusedError:
        return "Connection refused during version detection"
    except Exception as e:
        return f"Error during version detection: {e}"
    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python port_scanner.py <IP_ADDRESS> <PORT_RANGE (e.g., 1-1024)>")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_range_str = sys.argv[2]

    try:
        start_port, end_port = map(int, port_range_str.split('-'))
    except ValueError:
        print("Invalid port range format. Use e.g., 1-1024")
        sys.exit(1)

    print(f"Scanning {target_ip} for open ports in range {start_port}-{end_port}...")

    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            print(f"Port {port} is open")
            service_info = get_service_version(target_ip, port)
            print(f"  Service/Version: {service_info}")
            open_ports.append((port, service_info))

    if open_ports:
        print("\nScan complete. Open ports and detected services/versions:")
        for port, service_info in open_ports:
            print(f"Port {port}: {service_info}")
    else:
        print("\nNo open ports found in the specified range.")





def detect_http_version(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        if response:
            first_line = response.split('\n')[0]
            if "HTTP/1." in first_line:
                return first_line.strip()
        return None
    except Exception:
        return None
    finally:
        sock.close()





def detect_ftp_version(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        response = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        if response.startswith("220"):
            return response
        return None
    except Exception:
        return None
    finally:
        sock.close()





def detect_ssh_version(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # SSH protocol starts with 'SSH-2.0-' or 'SSH-1.99-' followed by software version
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        if banner.startswith("SSH-"):
            return banner
        return None
    except Exception:
        return None
    finally:
        sock.close()





import dns.resolver
import dns.exception

def detect_dns_version(ip, port, timeout=1):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = timeout

        version_queries = ['version.bind', 'version.server']
        for query in version_queries:
            try:
                answer = resolver.resolve(query, 'TXT', dns.rdataclass.CH)
                for rdata in answer:
                    return rdata.strings[0].decode("utf-8")
            except dns.resolver.NXDOMAIN:
                continue
            except dns.exception.Timeout:
                continue
        return None
    except Exception:
        return None






service_fingerprints = {
    "HTTP": [
        (r"Server: (.*)", "Server"),
        (r"X-Powered-By: (.*)", "X-Powered-By"),
        (r"Apache/([\d\.]+)", "Apache"),
        (r"nginx/([\d\.]+)", "Nginx"),
    ],
    "FTP": [
        (r"220 (.*) FTP server", "FTP Server"),
        (r"vsFTPd ([\d\.]+)", "vsFTPd"),
        (r"Pure-FTPd ([\d\.]+)", "Pure-FTPd"),
    ],
    "SSH": [
        (r"OpenSSH_([\w\.]+)", "OpenSSH"),
        (r"SSH-2.0-([\w\.]+)", "SSH"),
    ],
    "DNS": [
        (r"dnsmasq-([\d\.]+)", "dnsmasq"),
        (r"BIND (\d+\.\d+\.\d+)", "BIND"),
    ],
    # Add more service fingerprints here
}

def identify_service_from_banner(banner, port):
    # Try to identify based on common port assignments first
    if port == 80 or port == 443:
        service_type = "HTTP"
    elif port == 21:
        service_type = "FTP"
    elif port == 22:
        service_type = "SSH"
    elif port == 23:
        service_type = "Telnet"
    elif port == 25:
        service_type = "SMTP"
    elif port == 53:
        service_type = "DNS"
    else:
        service_type = "Unknown"

    # Attempt to match against known fingerprints
    for service, patterns in service_fingerprints.items():
        for pattern, name in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if len(match.groups()) > 0 else "Unknown"
                return f"{name} {version}"

    # If no specific fingerprint matched, return generic info
    if service_type != "Unknown":
        return f"{service_type} (Banner: {banner})"
    else:
        return f"Unknown Service (Banner: {banner})"
