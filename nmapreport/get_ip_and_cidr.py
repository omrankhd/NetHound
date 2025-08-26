import subprocess
import platform
import re

def get_local_ip():
  
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            # Try ifconfig first
            try:
                output = subprocess.check_output(['ifconfig']).decode()
                # First try to find wireless or ethernet interfaces
                interfaces = re.finditer(r'(wlan\d|eth\d|enp\ds\d|wlp\ds\d)[: ]', output)
                for interface in interfaces:
                    interface_name = interface.group(1)
                    # Find IP address in the interface block
                    ip_match = re.search(
                        rf'{interface_name}.*?inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)',
                        output,
                        re.DOTALL
                    )
                    if ip_match:
                        ip = ip_match.group(1)
                        if not ip.startswith('127.'):
                            return ip
            except subprocess.CalledProcessError:
                # If ifconfig fails, try ip addr
                try:
                    output = subprocess.check_output(['ip', 'addr']).decode()
                    # Look specifically for wireless or ethernet interfaces
                    interfaces = re.finditer(r'\d+: (wlan\d|eth\d|enp\ds\d|wlp\ds\d):', output)
                    for interface in interfaces:
                        interface_name = interface.group(1)
                        # Find IP address in the interface block
                        ip_match = re.search(
                            rf'{interface_name}.*?inet (\d+\.\d+\.\d+\.\d+)',
                            output,
                            re.DOTALL
                        )
                        if ip_match:
                            ip = ip_match.group(1)
                            if not ip.startswith('127.'):
                                return ip
                except subprocess.CalledProcessError:
                    pass
                    
        elif system == 'windows':
            # Use ipconfig for Windows
            output = subprocess.check_output(['ipconfig']).decode('utf-8', errors='ignore')
            # First try to find Wireless or Ethernet adapter sections
            sections = re.split(r'\r?\n\r?\n', output)
            for section in sections:
                # Check if it's a wireless or ethernet adapter
                if ('Wireless' in section or 'Ethernet' in section) and 'adapter' in section:
                    # Look for IPv4 Address in this section
                    ip_match = re.search(r'IPv4 Address[^\n:]*:\s*(\d+\.\d+\.\d+\.\d+)', section)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not ip.startswith('127.'):
                            return ip
        
        return None
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

def get_local_cidr():
  
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            # Try ifconfig first
            try:
                output = subprocess.check_output(['ifconfig']).decode()
                # First try to find wireless or ethernet interfaces
                interfaces = re.finditer(r'(wlan\d|eth\d|enp\ds\d|wlp\ds\d)[: ]', output)
                for interface in interfaces:
                    interface_name = interface.group(1)
                    # Find IP and netmask in the interface block
                    ip_block = re.search(
                        rf'{interface_name}.*?inet (?:addr:)?(\d+\.\d+\.\d+\.\d+).*?(?:Mask:|netmask )(\d+\.\d+\.\d+\.\d+)',
                        output,
                        re.DOTALL
                    )
                    if ip_block:
                        ip = ip_block.group(1)
                        netmask = ip_block.group(2)
                        if not ip.startswith('127.'):
                            # Convert netmask to CIDR prefix
                            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                            # Get network address
                            network = '.'.join(str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4))
                            return f"{network}/{cidr}"

            except subprocess.CalledProcessError:
                # If ifconfig fails, try ip addr
                try:
                    output = subprocess.check_output(['ip', 'addr']).decode()
                    interfaces = re.finditer(r'\d+: (wlan\d|eth\d|enp\ds\d|wlp\ds\d):', output)
                    for interface in interfaces:
                        interface_name = interface.group(1)
                        # Find CIDR directly (ip addr shows it in CIDR format)
                        ip_match = re.search(
                            rf'{interface_name}.*?inet (\d+\.\d+\.\d+\.\d+)/(\d+)',
                            output,
                            re.DOTALL
                        )
                        if ip_match:
                            ip = ip_match.group(1)
                            cidr = ip_match.group(2)
                            if not ip.startswith('127.'):
                                # Calculate network address
                                mask_bits = '1' * int(cidr) + '0' * (32 - int(cidr))
                                netmask = '.'.join(str(int(mask_bits[i:i+8], 2)) for i in range(0, 32, 8))
                                network = '.'.join(str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4))
                                return f"{network}/{cidr}"

                except subprocess.CalledProcessError:
                    pass
                    
        elif system == 'windows':
            output = subprocess.check_output(['ipconfig']).decode('utf-8', errors='ignore')
            sections = re.split(r'\r?\n\r?\n', output)
            for section in sections:
                if ('Wireless' in section or 'Ethernet' in section) and 'adapter' in section:
                    # Look for both IPv4 Address and Subnet Mask
                    ip_match = re.search(r'IPv4 Address[^\n:]*:\s*(\d+\.\d+\.\d+\.\d+)', section)
                    mask_match = re.search(r'Subnet Mask[^\n:]*:\s*(\d+\.\d+\.\d+\.\d+)', section)
                    if ip_match and mask_match:
                        ip = ip_match.group(1)
                        netmask = mask_match.group(1)
                        if not ip.startswith('127.'):
                            # Convert netmask to CIDR prefix
                            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                            # Calculate network address
                            network = '.'.join(str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4))
                            return f"{network}/{cidr}"
        
        return None
    except Exception as e:
        print(f"Error getting CIDR: {e}")
        return None

def main():
    ip = get_local_ip()
    cidr = get_local_cidr()
    print(f"IP Address: {ip}")
    print(f"Network CIDR: {cidr}")

if __name__ == "__main__":
    main()
