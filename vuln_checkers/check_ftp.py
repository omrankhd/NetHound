#!/usr/bin/env python3
"""
FTP Security Vulnerability Scanner
A tool for testing FTP servers for common security vulnerabilities
"""

import ftplib
import socket
import ssl
import argparse
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string
import re

class FTPVulnerabilityScanner:
    def __init__(self, target_host, port=21, timeout=10):
        self.target_host = target_host
        self.port = port
        self.timeout = timeout
        self.results = {}
        self.banner = None
        
    def connect_ftp(self, use_ssl=False):
        """Establish FTP connection"""
        try:
            if use_ssl:
                ftp = ftplib.FTP_TLS()
            else:
                ftp = ftplib.FTP()
            
            ftp.connect(self.target_host, self.port, timeout=self.timeout)
            return ftp
        except Exception as e:
            return None
    
    def check_banner_grabbing(self):
        """Check FTP banner for version information"""
        print(f"[*] Checking FTP banner on {self.target_host}:{self.port}")
        
        try:
            ftp = self.connect_ftp()
            if ftp:
                self.banner = ftp.getwelcome()
                print(f"[+] Banner: {self.banner}")
                
                # Check for version disclosure
                version_indicators = ['version', 'vsftpd', 'proftpd', 'pureftpd', 'filezilla']
                for indicator in version_indicators:
                    if indicator.lower() in self.banner.lower():
                        print(f"[!] INFO DISCLOSURE: Potential version info in banner")
                        self.results['banner_disclosure'] = True
                        ftp.quit()
                        return True
                
                self.results['banner_disclosure'] = False
                ftp.quit()
                return False
            else:
                print("[!] Could not connect to FTP server")
                return False
                
        except Exception as e:
            print(f"[!] Error checking banner: {e}")
            self.results['banner_disclosure'] = None
            return False
    
    def check_anonymous_access(self):
        """Check for anonymous FTP access"""
        print(f"[*] Testing anonymous FTP access")
        
        try:
            ftp = self.connect_ftp()
            if ftp:
                try:
                    ftp.login('anonymous', 'anonymous@test.com')
                    print(f"[!] VULNERABILITY: Anonymous FTP access allowed")
                    
                    # Check if we can list directories
                    try:
                        files = ftp.nlst()
                        print(f"[!] Anonymous user can list {len(files)} files/directories")
                        self.results['anonymous_access'] = True
                        
                        # Check write permissions
                        try:
                            test_filename = 'test_write_' + ''.join(random.choices(string.ascii_letters, k=5))
                            ftp.storbinary(f'STOR {test_filename}', open('/dev/null', 'rb'))
                            print(f"[!] CRITICAL: Anonymous user has write access")
                            self.results['anonymous_write'] = True
                            # Try to clean up
                            try:
                                ftp.delete(test_filename)
                            except:
                                pass
                        except:
                            print(f"[+] Anonymous user cannot write files")
                            self.results['anonymous_write'] = False
                            
                    except:
                        print(f"[+] Anonymous user cannot list directories")
                        self.results['anonymous_access'] = True
                        
                    ftp.quit()
                    return True
                    
                except ftplib.error_perm as e:
                    print(f"[+] Anonymous access denied: {e}")
                    self.results['anonymous_access'] = False
                    ftp.quit()
                    return False
            else:
                return False
                
        except Exception as e:
            print(f"[!] Error testing anonymous access: {e}")
            self.results['anonymous_access'] = None
            return False
    
    def check_weak_credentials(self):
        """Test for common weak credentials"""
        print(f"[*] Testing common weak credentials")
        
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('root', 'password'),
            ('ftp', 'ftp'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('demo', 'demo'),
            ("anonymous", "anonymous@"),
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("user", "user"),
            ("ftp", "ftp"),
            ("", ""),
            # Cisco
            ("cisco", "cisco"),
            ("admin", "cisco"),
            ("cisco", "admin"),
            # D-Link
            ("admin", ""),
            ("admin", "admin"),
            # Zyxel
            ("admin", "1234"),
            # Huawei
            ("admin", "admin"),
            ("root", "admin"),
            # Netgear
            ("admin", "password"),
            ]
        
        for username, password in common_creds:
            try:
                ftp = self.connect_ftp()
                if ftp:
                    try:
                        ftp.login(username, password)
                        print(f"[!] VULNERABILITY: Weak credentials found - {username}:{password}")
                        self.results['weak_credentials'] = True
                        ftp.quit()
                        return True
                    except ftplib.error_perm:
                        pass
                    except Exception as e:
                        print(f"[!] Error testing {username}:{password} - {e}")
                    finally:
                        try:
                            ftp.quit()
                        except:
                            pass
                        
            except Exception as e:
                continue
                
        print("[+] No common weak credentials found")
        self.results['weak_credentials'] = False
        return False
    
    def check_ssl_support(self):
        """Check for SSL/TLS support (FTPS)"""
        print(f"[*] Testing SSL/TLS support")
        
        try:
            ftp = ftplib.FTP_TLS()
            ftp.connect(self.target_host, self.port, timeout=self.timeout)
            ftp.auth()
            print(f"[+] SSL/TLS support detected")
            self.results['ssl_support'] = True
            ftp.quit()
            return True
            
        except Exception as e:
            print(f"[!] No SSL/TLS support: {e}")
            self.results['ssl_support'] = False
            return False
    
    def check_bounce_attack(self):
        """Check for FTP bounce attack vulnerability"""
        print(f"[*] Testing FTP bounce attack vulnerability")
        
        try:
            ftp = self.connect_ftp()
            if ftp:
                try:
                    # Try to login anonymously first
                    ftp.login('anonymous', 'test@test.com')
                    
                    # Try to use PORT command to connect to a different host
                    # This is a simplified test - in reality this would be more complex
                    try:
                        # Try to make the server connect to itself on a different port
                        ftp.sendcmd('PORT 127,0,0,1,0,80')
                        print(f"[!] POTENTIAL VULNERABILITY: Server accepted PORT command to different host")
                        self.results['bounce_attack'] = True
                        ftp.quit()
                        return True
                    except ftplib.error_perm as e:
                        print(f"[+] PORT command properly restricted: {e}")
                        self.results['bounce_attack'] = False
                        ftp.quit()
                        return False
                        
                except ftplib.error_perm:
                    print(f"[+] Cannot test bounce attack - no anonymous access")
                    self.results['bounce_attack'] = None
                    ftp.quit()
                    return False
            else:
                return False
                
        except Exception as e:
            print(f"[!] Error testing bounce attack: {e}")
            self.results['bounce_attack'] = None
            return False
    
    def check_directory_traversal(self):
        """Check for directory traversal vulnerabilities"""
        print(f"[*] Testing directory traversal")
        
        try:
            ftp = self.connect_ftp()
            if ftp:
                try:
                    ftp.login('anonymous', 'test@test.com')
                    
                    # Try various directory traversal patterns
                    traversal_patterns = [
                        '../../../etc/passwd',
                        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                        '....//....//....//etc//passwd',
                        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                    ]
                    
                    for pattern in traversal_patterns:
                        try:
                            response = ftp.sendcmd(f'CWD {pattern}')
                            if '250' in response:
                                print(f"[!] VULNERABILITY: Directory traversal possible with pattern: {pattern}")
                                self.results['directory_traversal'] = True
                                ftp.quit()
                                return True
                        except:
                            continue
                    
                    print(f"[+] No directory traversal vulnerabilities detected")
                    self.results['directory_traversal'] = False
                    ftp.quit()
                    return False
                    
                except ftplib.error_perm:
                    print(f"[+] Cannot test directory traversal - no anonymous access")
                    self.results['directory_traversal'] = None
                    ftp.quit()
                    return False
            else:
                return False
                
        except Exception as e:
            print(f"[!] Error testing directory traversal: {e}")
            self.results['directory_traversal'] = None
            return False
    
    def check_brute_force_protection(self):
        """Test for brute force protection"""
        print(f"[*] Testing brute force protection")
        
        failed_attempts = 0
        max_attempts = 5
        
        for i in range(max_attempts):
            try:
                ftp = self.connect_ftp()
                if ftp:
                    try:
                        random_user = ''.join(random.choices(string.ascii_letters, k=8))
                        random_pass = ''.join(random.choices(string.ascii_letters, k=8))
                        ftp.login(random_user, random_pass)
                    except ftplib.error_perm:
                        failed_attempts += 1
                    except Exception as e:
                        if "too many" in str(e).lower() or "blocked" in str(e).lower():
                            print(f"[+] Brute force protection detected after {i+1} attempts")
                            self.results['brute_force_protection'] = True
                            return True
                    finally:
                        try:
                            ftp.quit()
                        except:
                            pass
                        
                time.sleep(1)  # Brief delay between attempts
                
            except Exception as e:
                if "too many" in str(e).lower() or "blocked" in str(e).lower():
                    print(f"[+] Brute force protection detected")
                    self.results['brute_force_protection'] = True
                    return True
                    
        if failed_attempts == max_attempts:
            print(f"[!] WEAKNESS: No brute force protection detected after {max_attempts} failed attempts")
            self.results['brute_force_protection'] = False
            return False
        else:
            print(f"[+] Brute force protection appears to be in place")
            self.results['brute_force_protection'] = True
            return True
    
    def check_passive_mode(self):
        """Check passive mode functionality"""
        print(f"[*] Testing passive mode")
        
        try:
            ftp = self.connect_ftp()
            if ftp:
                try:
                    ftp.login('anonymous', 'test@test.com')
                    ftp.set_pasv(True)
                    files = ftp.nlst()
                    print(f"[+] Passive mode works correctly")
                    self.results['passive_mode'] = True
                    ftp.quit()
                    return True
                except Exception as e:
                    print(f"[!] Passive mode issue: {e}")
                    self.results['passive_mode'] = False
                    ftp.quit()
                    return False
            else:
                return False
                
        except Exception as e:
            print(f"[!] Error testing passive mode: {e}")
            self.results['passive_mode'] = None
            return False
    
    def run_all_tests(self):
        """Run all vulnerability tests"""
        print(f"Starting FTP vulnerability scan on {self.target_host}:{self.port}")
        print("=" * 60)
        
        # Check if port is open first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, self.port))
            sock.close()
            
            if result != 0:
                print(f"[!] Port {self.port} is not open on {self.target_host}")
                return {}
        except Exception as e:
            print(f"[!] Error checking port: {e}")
            return {}
        
        tests = [
            self.check_banner_grabbing,
            self.check_anonymous_access,
            self.check_weak_credentials,
            self.check_ssl_support,
            self.check_bounce_attack,
            self.check_directory_traversal,
            self.check_brute_force_protection,
            self.check_passive_mode
        ]
        
        vulnerabilities_found = 0
        
        for test in tests:
            try:
                if test():
                    vulnerabilities_found += 1
                print("-" * 40)
                time.sleep(1)  # Brief pause between tests
            except Exception as e:
                print(f"[!] Error running test {test.__name__}: {e}")
                print("-" * 40)
        
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target_host}:{self.port}")
        print(f"Vulnerabilities found: {vulnerabilities_found}")
        
        if vulnerabilities_found > 0:
            print(f"[!] SECURITY ISSUES DETECTED")
        else:
            print(f"[+] No major vulnerabilities detected")
        
        return self.results

def run_ftp_vuln_scan(server, port=21, timeout=10):
    """
    Run all FTP vulnerability tests for the given server and port, return the results as a dict.
    """
    scanner = FTPVulnerabilityScanner(server, port, timeout)
    return scanner.run_all_tests()

def main():
    parser = argparse.ArgumentParser(description='FTP Security Vulnerability Scanner')
    parser.add_argument('host', help='Target FTP server hostname or IP')
    parser.add_argument('--port', type=int, default=21, help='FTP port (default: 21)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    scanner = FTPVulnerabilityScanner(args.host, args.port, args.timeout)
    results = scanner.run_all_tests()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"FTP Vulnerability Scan Results\n")
            f.write(f"Target: {args.host}:{args.port}\n")
            f.write(f"Timestamp: {time.ctime()}\n\n")
            
            for test, result in results.items():
                f.write(f"{test}: {result}\n")
        
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
