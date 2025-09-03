#!/usr/bin/env python3
"""
SMTP Vulnerability Assessment Script
For legitimate security testing of SMTP servers you own or have permission to test
"""

import smtplib
import socket
import ssl
import re
import sys
from typing import Dict, List, Tuple, Optional
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SMTPVulnerabilityChecker:
    def __init__(self, host: str, port: int = 25, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results = {}
        
    def check_connection(self) -> bool:
        """Test basic connectivity to SMTP server"""
        try:
            with socket.create_connection((self.host, self.port), self.timeout):
                logger.info(f"Successfully connected to {self.host}:{self.port}")
                return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def get_banner(self) -> Optional[str]:
        """Retrieve SMTP banner information"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            banner = server.getwelcome()
            server.quit()
            return banner.decode() if isinstance(banner, bytes) else str(banner)
        except Exception as e:
            logger.error(f"Failed to get banner: {e}")
            return None
    
    def check_open_relay(self) -> bool:
        """Check if server allows open relay"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            
            # Try to send from external domain to external domain
            try:
                server.mail("test@external.com")
                server.rcpt("recipient@another-external.com")
                server.quit()
                return True  # Open relay detected
            except smtplib.SMTPRecipientsRefused:
                server.quit()
                return False  # Properly configured
            except Exception:
                server.quit()
                return False
        except Exception as e:
            logger.error(f"Open relay check failed: {e}")
            return False
    
    def check_vrfy_command(self) -> Tuple[bool, List[str]]:
        """Check if VRFY command is enabled (user enumeration)"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            
            test_users = ['admin', 'root', 'test', 'user', 'postmaster']
            valid_users = []
            vrfy_enabled = False
            
            for user in test_users:
                try:
                    code, response = server.verify(user)
                    vrfy_enabled = True
                    if code == 250:
                        valid_users.append(user)
                except smtplib.SMTPException:
                    pass
            
            server.quit()
            return vrfy_enabled, valid_users
        except Exception as e:
            logger.error(f"VRFY check failed: {e}")
            return False, []
    
    def check_expn_command(self) -> bool:
        """Check if EXPN command is enabled (mailing list enumeration)"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            
            # Try EXPN command
            try:
                server.docmd("EXPN", "all")
                server.quit()
                return True
            except smtplib.SMTPException:
                server.quit()
                return False
        except Exception as e:
            logger.error(f"EXPN check failed: {e}")
            return False
    
    def check_supported_commands(self) -> List[str]:
        """Get list of supported SMTP commands"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            
            # Get HELP response
            try:
                help_response = server.help()
                server.quit()
                return help_response.decode().split('\n') if isinstance(help_response, bytes) else help_response.split('\n')
            except Exception:
                server.quit()
                return []
        except Exception as e:
            logger.error(f"Command enumeration failed: {e}")
            return []
    
    def check_tls_support(self) -> Dict[str, bool]:
        """Check TLS/SSL support and configuration"""
        tls_info = {
            'starttls_supported': False,
            'ssl_direct': False,
            'tls_version': None,
            'cipher_suite': None
        }
        
        # Check STARTTLS
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            if server.has_extn('STARTTLS'):
                tls_info['starttls_supported'] = True
                try:
                    server.starttls()
                    # Get TLS info if available
                    if hasattr(server.sock, 'version'):
                        tls_info['tls_version'] = server.sock.version()
                    if hasattr(server.sock, 'cipher'):
                        tls_info['cipher_suite'] = server.sock.cipher()
                except Exception as e:
                    logger.warning(f"STARTTLS failed: {e}")
            server.quit()
        except Exception as e:
            logger.error(f"STARTTLS check failed: {e}")
        
        # Check direct SSL (usually port 465)
        if self.port == 465:
            try:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)
                tls_info['ssl_direct'] = True
                server.quit()
            except Exception as e:
                logger.error(f"Direct SSL check failed: {e}")
        
        return tls_info
    
    def check_auth_methods(self) -> List[str]:
        """Check supported authentication methods"""
        try:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            server.helo("test.example.com")
            
            # Try to enable TLS first for auth check
            if server.has_extn('STARTTLS'):
                try:
                    server.starttls()
                except Exception:
                    pass
            
            auth_methods = []
            if server.has_extn('AUTH'):
                auth_line = server.esmtp_features.get('auth', '')
                auth_methods = auth_line.split()
            
            server.quit()
            return auth_methods
        except Exception as e:
            logger.error(f"Auth methods check failed: {e}")
            return []
    
    def run_full_assessment(self) -> Dict:
        """Run complete vulnerability assessment"""
        logger.info(f"Starting SMTP vulnerability assessment for {self.host}:{self.port}")
        
        # Basic connectivity
        if not self.check_connection():
            return {"error": "Cannot connect to SMTP server"}
        
        # Gather information
        self.results['banner'] = self.get_banner()
        self.results['open_relay'] = self.check_open_relay()
        self.results['vrfy_enabled'], self.results['valid_users'] = self.check_vrfy_command()
        self.results['expn_enabled'] = self.check_expn_command()
        self.results['supported_commands'] = self.check_supported_commands()
        self.results['tls_info'] = self.check_tls_support()
        self.results['auth_methods'] = self.check_auth_methods()
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate a formatted vulnerability report"""
        if not self.results:
            return "No assessment results available"
        
        report = f"\n{'='*60}\n"
        report += f"SMTP Vulnerability Assessment Report\n"
        report += f"Target: {self.host}:{self.port}\n"
        report += f"{'='*60}\n\n"
        
        # Banner information
        if self.results.get('banner'):
            report += f"Server Banner:\n{self.results['banner']}\n\n"
        
        # Critical vulnerabilities
        report += "CRITICAL VULNERABILITIES:\n"
        critical_found = False
        
        if self.results.get('open_relay'):
            report += " OPEN RELAY DETECTED - Server allows relaying emails from external domains\n"
            critical_found = True
        
        if not critical_found:
            report += " No critical vulnerabilities found\n"
        
        report += "\n"
        
        # Security issues
        report += "SECURITY CONCERNS:\n"
        
        if self.results.get('vrfy_enabled'):
            report += "  VRFY command enabled - Allows user enumeration\n"
            if self.results.get('valid_users'):
                report += f"   Valid users found: {', '.join(self.results['valid_users'])}\n"
        
        if self.results.get('expn_enabled'):
            report += " EXPN command enabled - Allows mailing list enumeration\n"
        
        # TLS/SSL configuration
        tls_info = self.results.get('tls_info', {})
        report += "\nTLS/SSL CONFIGURATION:\n"
        
        if tls_info.get('starttls_supported'):
            report += " STARTTLS supported\n"
        else:
            report += " STARTTLS not supported\n"
        
        if tls_info.get('ssl_direct'):
            report += " Direct SSL supported\n"
        
        if tls_info.get('tls_version'):
            report += f"   TLS Version: {tls_info['tls_version']}\n"
        
        # Authentication methods
        auth_methods = self.results.get('auth_methods', [])
        if auth_methods:
            report += f"\nAuthentication Methods: {', '.join(auth_methods)}\n"
        
        # Supported commands
        commands = self.results.get('supported_commands', [])
        if commands:
            report += f"\nSupported Commands:\n"
            for cmd in commands[:10]:  # Limit output
                report += f"  {cmd.strip()}\n"
        
        return report

def run_smtp_vuln_scan(server, port=25, timeout=10):
    """
    Run all SMTP vulnerability tests for the given server and port, return the results as a dict.
    """
    checker = SMTPVulnerabilityChecker(server, port, timeout)
    return checker.run_full_assessment()

def main():
    parser = argparse.ArgumentParser(description='SMTP Vulnerability Assessment Tool')
    parser.add_argument('host', help='SMTP server hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=25, help='SMTP port (default: 25)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create checker instance
    checker = SMTPVulnerabilityChecker(args.host, args.port, args.timeout)
    
    # Run assessment
    results = checker.run_full_assessment()
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Generate and display report
    report = checker.generate_report()
    print(report)
    
    # Return appropriate exit code
    if results.get('open_relay'):
        sys.exit(2)  # Critical vulnerability found
    elif results.get('vrfy_enabled') or results.get('expn_enabled'):
        sys.exit(1)  # Security concerns found
    else:
        sys.exit(0)  # No issues found

if __name__ == "__main__":
    main()
