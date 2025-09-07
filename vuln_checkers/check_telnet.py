#!/usr/bin/env python3


import socket
import time
import argparse
from typing import List, Dict, Tuple, Optional

class TelnetVulnScanner:
    def __init__(self, host: str, port: int = 23, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.vulnerabilities = []
        
    def check_connection(self) -> bool:
        """Check if telnet service is running on the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def get_banner(self) -> Optional[str]:
        """Retrieve the telnet banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Read initial banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except Exception as e:
            print(f"Banner retrieval error: {e}")
            return None
    
    def check_weak_credentials(self) -> List[Dict]:
        """Check for common weak credentials."""
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'admin'),
            ('root', ''),
            ('guest', 'guest'),
            ('guest', ''),
            ('user', 'user'),
            ('test', 'test')
        ]
        
        found_creds = []
        
        for username, password in common_creds:
            if self._try_login(username, password):
                found_creds.append({
                    'username': username,
                    'password': password,
                    'severity': 'HIGH'
                })
                print(f"[!] Weak credentials found: {username}:{password}")
        
        return found_creds
    
    def _try_login(self, username: str, password: str) -> bool:
        """Attempt to login with given credentials."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Read initial banner
            initial_data = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send username
            sock.send(f"{username}\r\n".encode())
            time.sleep(1)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send password
            sock.send(f"{password}\r\n".encode())
            time.sleep(2)
            final_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            
            # Check for successful login indicators
            success_indicators = ['$', '#', '>', 'welcome', 'logged in', 'shell']
            failure_indicators = ['incorrect', 'invalid', 'denied', 'failed', 'error']
            
            final_lower = final_response.lower()
            
            has_success = any(indicator in final_lower for indicator in success_indicators)
            has_failure = any(indicator in final_lower for indicator in failure_indicators)
            
            return has_success and not has_failure
            
        except Exception as e:
            return False
    
    def check_banner_disclosure(self, banner: str) -> List[Dict]:
        """Check for information disclosure in banner."""
        issues = []
        
        if not banner:
            return issues
        
        # Check for version disclosure
        version_keywords = ['version', 'v.', 'release', 'build']
        if any(keyword in banner.lower() for keyword in version_keywords):
            issues.append({
                'type': 'Version Disclosure',
                'description': 'Banner reveals version information',
                'banner': banner,
                'severity': 'MEDIUM'
            })
        
        # Check for system information
        system_keywords = ['linux', 'windows', 'unix', 'freebsd', 'solaris']
        if any(keyword in banner.lower() for keyword in system_keywords):
            issues.append({
                'type': 'System Information Disclosure',
                'description': 'Banner reveals system information',
                'banner': banner,
                'severity': 'LOW'
            })
        
        return issues
    
    def check_encryption_support(self) -> Dict:
        """Check if telnet supports encryption (unlikely but worth checking)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Telnet negotiation for encryption
            # This is a basic check - real telnet encryption is complex
            sock.send(b'\xff\xfd\x26')  # DO ENCRYPT
            time.sleep(1)
            response = sock.recv(1024)
            sock.close()
            
            # Check response for encryption support
            if b'\xff\xfb\x26' in response:  # WILL ENCRYPT
                return {
                    'encryption_supported': True,
                    'severity': 'INFO'
                }
            else:
                return {
                    'encryption_supported': False,
                    'severity': 'HIGH',
                    'description': 'Telnet traffic is unencrypted'
                }
        except Exception:
            return {
                'encryption_supported': False,
                'severity': 'HIGH',
                'description': 'Telnet traffic is unencrypted'
            }
    
    def check_dos_vulnerability(self) -> Dict:
        """Check for potential DoS vulnerabilities."""
        try:
            # Send oversized data to check for buffer overflow
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send large payload
            large_payload = "A" * 10000
            sock.send(large_payload.encode())
            time.sleep(2)
            
            # Try to send normal data
            sock.send(b"test\r\n")
            response = sock.recv(1024)
            sock.close()
            
            return {
                'dos_vulnerable': False,
                'severity': 'INFO',
                'description': 'No obvious DoS vulnerability detected'
            }
        except Exception as e:
            return {
                'dos_vulnerable': True,
                'severity': 'MEDIUM',
                'description': f'Potential DoS vulnerability: {str(e)}'
            }
    
    def scan(self) -> Dict:
        """Run comprehensive vulnerability scan."""
        print(f"[*] Starting telnet vulnerability scan on {self.host}:{self.port}")
        
        results = {
            'host': self.host,
            'port': self.port,
            'service_running': False,
            'banner': None,
            'vulnerabilities': []
        }
        
        # Check if service is running
        if not self.check_connection():
            print(f"[-] Telnet service not running on {self.host}:{self.port}")
            return results
        
        results['service_running'] = True
        print(f"[+] Telnet service detected on {self.host}:{self.port}")
        
        # Get banner
        banner = self.get_banner()
        results['banner'] = banner
        if banner:
            print(f"[*] Banner: {banner}")
        
        # Check for banner disclosure
        if banner:
            banner_issues = self.check_banner_disclosure(banner)
            results['vulnerabilities'].extend(banner_issues)
        
        # Check for weak credentials
        print("[*] Checking for weak credentials...")
        weak_creds = self.check_weak_credentials()
        results['vulnerabilities'].extend(weak_creds)
        
        # Check encryption support
        encryption_check = self.check_encryption_support()
        results['vulnerabilities'].append(encryption_check)
        
        # Check for DoS vulnerability
        dos_check = self.check_dos_vulnerability()
        results['vulnerabilities'].append(dos_check)
        
        # General security recommendations
        results['vulnerabilities'].append({
            'type': 'Protocol Security',
            'description': 'Telnet is inherently insecure - consider using SSH',
            'severity': 'HIGH'
        })
        
        return results
    
    def print_report(self, results: Dict):
        """Print formatted vulnerability report."""
        print("\n" + "="*60)
        print(f"TELNET VULNERABILITY REPORT")
        print("="*60)
        print(f"Host: {results['host']}")
        print(f"Port: {results['port']}")
        print(f"Service Running: {results['service_running']}")
        
        if results['banner']:
            print(f"Banner: {results['banner']}")
        
        print(f"\nVulnerabilities Found: {len(results['vulnerabilities'])}")
        print("-" * 60)
        
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for vuln in results['vulnerabilities']:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] += 1
            
            print(f"[{severity}] {vuln.get('type', 'Unknown')}")
            if 'description' in vuln:
                print(f"    Description: {vuln['description']}")
            if 'username' in vuln and 'password' in vuln:
                print(f"    Credentials: {vuln['username']}:{vuln['password']}")
            print()
        
        print("Summary:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print("\nRecommendations:")
        print("  1. Disable telnet service if not required")
        print("  2. Use SSH instead of telnet for remote access")
        print("  3. Implement strong authentication")
        print("  4. Use network segmentation and firewalls")
        print("  5. Monitor and log all telnet connections")

def run_telnet_vuln_scan(server: str, port: int = 23, timeout: int = 10) -> dict:
    """
    Externally callable function to run the full Telnet vulnerability scan.
    Returns the results as a dictionary.
    """
    scanner = TelnetVulnScanner(server, port, timeout)
    results = scanner.scan()
    return results

def main():
    parser = argparse.ArgumentParser(description='Telnet Vulnerability Scanner')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-p', '--port', type=int, default=23, help='Telnet port (default: 23)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = TelnetVulnScanner(args.host, args.port, args.timeout)
    results = scanner.scan()
    scanner.print_report(results)

if __name__ == "__main__":
    main()