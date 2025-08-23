#!/usr/bin/env python3
"""
SMB Vulnerability Assessment Script
For legitimate security testing of SMB servers you own or have permission to test
"""

import socket
import struct
import sys
import argparse
import logging
from typing import Dict, List, Tuple, Optional
import time
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SMBVulnerabilityChecker:
    def __init__(self, host: str, port: int = 445, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.results = {}
        
        # SMB protocol constants
        self.SMB1_HEADER = b'\xff\x53\x4d\x42'  # SMB1 signature
        self.SMB2_HEADER = b'\xfe\x53\x4d\x42'  # SMB2 signature
        
    def check_connection(self) -> bool:
        """Test basic connectivity to SMB server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            if result == 0:
                logger.info(f"Successfully connected to {self.host}:{self.port}")
                return True
            else:
                logger.error(f"Connection failed to {self.host}:{self.port}")
                return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def send_smb_packet(self, packet: bytes) -> Optional[bytes]:
        """Send SMB packet and receive response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send NetBIOS session request first
            netbios_header = struct.pack('>I', len(packet))
            sock.send(netbios_header + packet)
            
            # Receive response
            response_length = struct.unpack('>I', sock.recv(4))[0]
            response = sock.recv(response_length)
            
            sock.close()
            return response
        except Exception as e:
            logger.debug(f"SMB packet send error: {e}")
            return None
    
    def check_smb_versions(self) -> Dict[str, bool]:
        """Check which SMB protocol versions are supported"""
        versions = {
            'SMB1': False,
            'SMB2': False,
            'SMB3': False
        }
        
        # SMB1 Negotiate Request
        smb1_negotiate = (
            b'\xff\x53\x4d\x42'  # SMB1 signature
            b'\x72'              # SMB_COM_NEGOTIATE
            b'\x00\x00\x00\x00' # Flags
            b'\x00\x00'         # Flags2
            b'\x00\x00'         # Process ID High
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x00\x00'         # Reserved
            b'\x00\x00'         # Tree ID
            b'\x00\x00'         # Process ID
            b'\x00\x00'         # User ID
            b'\x00\x00'         # Multiplex ID
            b'\x00'             # Word Count
            b'\x02\x00'         # Byte Count
            b'\x00\x00'         # Dialect strings (empty)
        )
        
        response = self.send_smb_packet(smb1_negotiate)
        if response and response.startswith(self.SMB1_HEADER):
            versions['SMB1'] = True
            logger.info("SMB1 protocol detected")
        
        # SMB2 Negotiate Request
        smb2_negotiate = (
            b'\xfe\x53\x4d\x42'     # SMB2 signature
            b'\x40\x00'             # Structure size
            b'\x00\x00'             # Credit charge
            b'\x00\x00'             # Channel sequence
            b'\x00\x00'             # Reserved
            b'\x00\x00'             # Command (negotiate)
            b'\x00\x00\x00\x00'     # Credits
            b'\x00\x00\x00\x00'     # Flags
            b'\x00\x00\x00\x00'     # Next command
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Message ID
            b'\x00\x00\x00\x00'     # Process ID
            b'\x00\x00\x00\x00'     # Tree ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Session ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x24\x00'             # Structure size
            b'\x02\x00'             # Dialect count
            b'\x00\x00'             # Security mode
            b'\x00\x00'             # Reserved
            b'\x00\x00\x00\x00'     # Capabilities
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Client GUID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Negotiate context
            b'\x02\x02'             # SMB 2.0.2
            b'\x10\x02'             # SMB 2.1
        )
        
        response = self.send_smb_packet(smb2_negotiate)
        if response and response.startswith(self.SMB2_HEADER):
            versions['SMB2'] = True
            logger.info("SMB2 protocol detected")
            
            # Check for SMB3 in the response
            if b'\x00\x03' in response or b'\x02\x03' in response or b'\x11\x03' in response:
                versions['SMB3'] = True
                logger.info("SMB3 protocol detected")
        
        return versions
    
    def check_smb_signing(self) -> Dict[str, bool]:
        """Check SMB signing configuration"""
        signing_info = {
            'signing_enabled': False,
            'signing_required': False
        }
        
        # This is a simplified check - in practice, you'd need to parse the negotiate response
        smb2_negotiate = (
            b'\xfe\x53\x4d\x42'     # SMB2 signature
            b'\x40\x00'             # Structure size
            b'\x00\x00'             # Credit charge
            b'\x00\x00'             # Channel sequence
            b'\x00\x00'             # Reserved
            b'\x00\x00'             # Command (negotiate)
            b'\x00\x00\x00\x00'     # Credits
            b'\x00\x00\x00\x00'     # Flags
            b'\x00\x00\x00\x00'     # Next command
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Message ID
            b'\x00\x00\x00\x00'     # Process ID
            b'\x00\x00\x00\x00'     # Tree ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Session ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x24\x00'             # Structure size
            b'\x02\x00'             # Dialect count
            b'\x00\x00'             # Security mode
            b'\x00\x00'             # Reserved
            b'\x00\x00\x00\x00'     # Capabilities
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Client GUID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Negotiate context
            b'\x02\x02'             # SMB 2.0.2
            b'\x10\x02'             # SMB 2.1
        )
        
        response = self.send_smb_packet(smb2_negotiate)
        if response and len(response) > 70:
            # Parse security mode from negotiate response
            try:
                security_mode = struct.unpack('<H', response[70:72])[0]
                signing_info['signing_enabled'] = bool(security_mode & 0x01)
                signing_info['signing_required'] = bool(security_mode & 0x02)
            except:
                logger.debug("Could not parse security mode from response")
        
        return signing_info
    
    def check_null_session(self) -> bool:
        """Check if null session authentication is allowed"""
        try:
            # This is a simplified check - real implementation would need full SMB session setup
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send a simple SMB1 session setup with null credentials
            null_session_packet = (
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x73'              # SMB_COM_SESSION_SETUP_ANDX
                b'\x00\x00\x00\x00' # Flags
                b'\x00\x00'         # Flags2
                b'\x00\x00'         # Process ID High
                b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
                b'\x00\x00'         # Reserved
                b'\x00\x00'         # Tree ID
                b'\x00\x00'         # Process ID
                b'\x00\x00'         # User ID
                b'\x00\x00'         # Multiplex ID
                b'\x0c'             # Word Count
                b'\xff'             # AndX Command
                b'\x00'             # Reserved
                b'\x00\x00'         # AndX Offset
                b'\x00\x00'         # Max Buffer Size
                b'\x00\x00'         # Max Mpx Count
                b'\x00\x00'         # VC Number
                b'\x00\x00\x00\x00' # Session Key
                b'\x00\x00'         # ANSI Password Length
                b'\x00\x00'         # Unicode Password Length
                b'\x00\x00\x00\x00' # Reserved
                b'\x00\x00\x00\x00' # Capabilities
                b'\x00\x00'         # Byte Count
            )
            
            netbios_header = struct.pack('>I', len(null_session_packet))
            sock.send(netbios_header + null_session_packet)
            
            response_length = struct.unpack('>I', sock.recv(4))[0]
            response = sock.recv(response_length)
            
            sock.close()
            
            # Check if session setup was successful (simplified)
            if response and len(response) > 32:
                status = struct.unpack('<I', response[5:9])[0]
                return status == 0  # STATUS_SUCCESS
            
            return False
        except Exception as e:
            logger.debug(f"Null session check error: {e}")
            return False
    
    
    
    def check_guest_access(self) -> bool:
        """Check if guest account access is enabled"""
        try:
            # Simplified guest access check
            # Real implementation would require full SMB session establishment
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send negotiate request first
            negotiate_packet = (
                b'\x00\x00\x00\x54'  # NetBIOS Session Service
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x72'              # SMB_COM_NEGOTIATE
                b'\x00\x00\x00\x00' # Flags
                b'\x18\x53\xc0\x00' # Flags2
                b'\x00\x00'         # Process ID High
                b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
                b'\x00\x00'         # Reserved
                b'\x00\x00'         # Tree ID
                b'\xff\xfe'         # Process ID
                b'\x00\x00'         # User ID
                b'\x00\x00'         # Multiplex ID
                b'\x00'             # Word Count
                b'\x35\x00'         # Byte Count
                b'\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00'
                b'\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00'
                b'\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00'
                b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
            )
            
            sock.send(negotiate_packet)
            response = sock.recv(1024)
            
            if response and len(response) > 36:
                # Try guest session setup
                guest_session = (
                    b'\x00\x00\x00\x48'  # NetBIOS Session Service
                    b'\xff\x53\x4d\x42'  # SMB1 signature
                    b'\x73'              # SMB_COM_SESSION_SETUP_ANDX
                    b'\x00\x00\x00\x00' # Flags
                    b'\x18\x07\xc0\x00' # Flags2
                    b'\x00\x00'         # Process ID High
                    b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
                    b'\x00\x00'         # Reserved
                    b'\x00\x00'         # Tree ID
                    b'\xff\xfe'         # Process ID
                    b'\x00\x00'         # User ID
                    b'\x00\x00'         # Multiplex ID
                    b'\x0c'             # Word Count
                    b'\xff'             # AndX Command
                    b'\x00'             # Reserved
                    b'\x00\x00'         # AndX Offset
                    b'\x00\x00'         # Max Buffer Size
                    b'\x00\x00'         # Max Mpx Count
                    b'\x00\x00'         # VC Number
                    b'\x00\x00\x00\x00' # Session Key
                    b'\x01\x00'         # ANSI Password Length
                    b'\x00\x00'         # Unicode Password Length
                    b'\x00\x00\x00\x00' # Reserved
                    b'\x00\x00\x00\x00' # Capabilities
                    b'\x07\x00'         # Byte Count
                    b'\x00'             # Password
                    b'\x67\x75\x65\x73\x74\x00' # Username: "guest"
                )
                
                sock.send(guest_session)
                guest_response = sock.recv(1024)
                
                sock.close()
                
                if guest_response and len(guest_response) > 8:
                    status = struct.unpack('<I', guest_response[5:9])[0]
                    return status == 0  # STATUS_SUCCESS
            
            sock.close()
            return False
        except Exception as e:
            logger.debug(f"Guest access check error: {e}")
            return False
    
    def enumerate_shares(self) -> List[str]:
        """Attempt to enumerate available shares"""
        # This would require establishing an authenticated session
        # For now, return common share names to check
        common_shares = ['C$', 'ADMIN$', 'IPC$', 'print$', 'fax$', 'shared', 'public']
        logger.info("Share enumeration requires authentication - checking common shares")
        return common_shares
    
    def run_full_assessment(self) -> Dict:
        """Run complete SMB vulnerability assessment"""
        logger.info(f"Starting SMB vulnerability assessment for {self.host}:{self.port}")
        
        # Basic connectivity
        if not self.check_connection():
            return {"error": "Cannot connect to SMB server"}
        
        # Gather information
        self.results['smb_versions'] = self.check_smb_versions()
        self.results['smb_signing'] = self.check_smb_signing()
        self.results['null_session'] = self.check_null_session()
        self.results['guest_access'] = self.check_guest_access()
        self.results['common_shares'] = self.enumerate_shares()
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate a formatted vulnerability report"""
        if not self.results:
            return "No assessment results available"
        
        report = f"\n{'='*60}\n"
        report += f"SMB Vulnerability Assessment Report\n"
        report += f"Target: {self.host}:{self.port}\n"
        report += f"{'='*60}\n\n"
        
        # SMB Version Information
        versions = self.results.get('smb_versions', {})
        report += "SMB PROTOCOL VERSIONS:\n"
        for version, supported in versions.items():
            status = "✅ Supported" if supported else "❌ Not Supported"
            report += f"  {version}: {status}\n"
        
        if versions.get('SMB1'):
            report += "  ⚠️  SMB1 is deprecated and should be disabled\n"
        
        report += "\n"
        
        # Critical Vulnerabilities
        report += "CRITICAL VULNERABILITIES:\n"
        critical_found = False
        
        
        if self.results.get('null_session'):
            report += "❌ NULL SESSION AUTHENTICATION ALLOWED\n"
            report += "   Anonymous access may be possible\n"
            critical_found = True
        
        if not critical_found:
            report += "✅ No critical vulnerabilities detected\n"
        
        report += "\n"
        
        # Security Configuration
        report += "SECURITY CONFIGURATION:\n"
        
        signing = self.results.get('smb_signing', {})
        if signing.get('signing_required'):
            report += "✅ SMB signing is required\n"
        elif signing.get('signing_enabled'):
            report += "⚠️  SMB signing is enabled but not required\n"
        else:
            report += "❌ SMB signing is disabled\n"
        
        if self.results.get('guest_access'):
            report += "⚠️  Guest account access is enabled\n"
        else:
            report += "✅ Guest account access is disabled\n"
        
        # Common Shares
        shares = self.results.get('common_shares', [])
        if shares:
            report += f"\nCOMMON SHARES TO INVESTIGATE:\n"
            for share in shares:
                report += f"  {share}\n"
        
        # Recommendations
        report += "\nRECOMMENDATIONS:\n"
        
        if versions.get('SMB1'):
            report += "• Disable SMB1 protocol\n"
        
        if not signing.get('signing_required'):
            report += "• Enable and require SMB signing\n"
        
        if self.results.get('guest_access'):
            report += "• Disable guest account access\n"
        
        
        
        if self.results.get('null_session'):
            report += "• Disable anonymous/null session access\n"
        
        return report

def run_smb_vuln_scan(server: str, port: int = 445, timeout: int = 10) -> dict:
    """
    Externally callable function to run the full SMB vulnerability assessment.
    Returns the results as a dictionary.
    """
    checker = SMBVulnerabilityChecker(server, port, timeout)
    results = checker.run_full_assessment()
    return results

def main():
    parser = argparse.ArgumentParser(description='SMB Vulnerability Assessment Tool')
    parser.add_argument('host', help='SMB server hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=445, help='SMB port (default: 445)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create checker instance
    checker = SMBVulnerabilityChecker(args.host, args.port, args.timeout)
    
    # Run assessment
    results = checker.run_full_assessment()
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Generate and display report
    report = checker.generate_report()
    print(report)
    
    # Return appropriate exit code based on findings
    if  results.get('null_session'):
        sys.exit(2)  # Critical vulnerability found
    elif results.get('smb_versions', {}).get('SMB1') or results.get('guest_access'):
        sys.exit(1)  # Security concerns found
    else:
        sys.exit(0)  # No major issues found

if __name__ == "__main__":
    main()
