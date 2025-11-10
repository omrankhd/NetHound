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
from typing import Dict, Optional


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
            
            # Send NetBIOS session request with proper header
            netbios_header = struct.pack('>I', len(packet))
            sock.send(netbios_header + packet)
            
            # Receive response with proper error handling
            try:
                response_header = sock.recv(4)
                if len(response_header) < 4:
                    sock.close()
                    return None
                    
                response_length = struct.unpack('>I', response_header)[0]
                # Mask off the NetBIOS message type bits (top byte)
                response_length = response_length & 0x00FFFFFF
                
                response = b''
                while len(response) < response_length:
                    chunk = sock.recv(min(4096, response_length - len(response)))
                    if not chunk:
                        break
                    response += chunk
                
                sock.close()
                return response
            except socket.timeout:
                sock.close()
                return None
                
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
        
        # SMB1 Negotiate Request with proper dialect strings
        dialect_strings = b'\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02Windows for Workgroups 3.1a\x00\x02LM1.2X002\x00\x02LANMAN2.1\x00\x02NT LM 0.12\x00'
        
        smb1_negotiate = (
            b'\xff\x53\x4d\x42'  # SMB1 signature
            b'\x72'              # SMB_COM_NEGOTIATE
            b'\x00\x00\x00\x00' # NT Status
            b'\x18'             # Flags
            b'\x53\xc8'         # Flags2
            b'\x00\x00'         # Process ID High
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x00\x00'         # Reserved
            b'\x00\x00'         # Tree ID
            b'\xff\xfe'         # Process ID
            b'\x00\x00'         # User ID
            b'\x00\x00'         # Multiplex ID
            b'\x00'             # Word Count
            + struct.pack('<H', len(dialect_strings))  # Byte Count
            + dialect_strings
        )
        
        response = self.send_smb_packet(smb1_negotiate)
        if response and len(response) >= 4 and response.startswith(self.SMB1_HEADER):
            versions['SMB1'] = True
            logger.info("SMB1 protocol detected")
        
        # SMB2/3 Negotiate Request
        smb2_negotiate = (
            b'\xfe\x53\x4d\x42'     # SMB2 signature
            b'\x40\x00'             # Header structure size (64)
            b'\x00\x00'             # Credit charge
            b'\x00\x00\x00\x00'     # Status
            b'\x00\x00'             # Command (negotiate = 0)
            b'\x00\x00'             # Credit request
            b'\x00\x00\x00\x00'     # Flags
            b'\x00\x00\x00\x00'     # Next command
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Message ID
            b'\x00\x00\x00\x00'     # Reserved (Process ID)
            b'\x00\x00\x00\x00'     # Tree ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Session ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x24\x00'             # Negotiate structure size (36)
            b'\x05\x00'             # Dialect count (5)
            b'\x01\x00'             # Security mode (signing enabled)
            b'\x00\x00'             # Reserved
            b'\x00\x00\x00\x00'     # Capabilities
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Client GUID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Negotiate context offset/count
            b'\x02\x02'             # SMB 2.0.2
            b'\x10\x02'             # SMB 2.1
            b'\x00\x03'             # SMB 3.0
            b'\x02\x03'             # SMB 3.0.2
            b'\x11\x03'             # SMB 3.1.1
        )
        
        response = self.send_smb_packet(smb2_negotiate)
        if response and len(response) >= 4 and response.startswith(self.SMB2_HEADER):
            versions['SMB2'] = True
            logger.info("SMB2 protocol detected")
            
            # Check for SMB3 in the response (dialect revision at offset 72-73)
            if len(response) >= 74:
                try:
                    dialect = struct.unpack('<H', response[72:74])[0]
                    if dialect >= 0x0300:  # SMB 3.0 or higher
                        versions['SMB3'] = True
                        logger.info(f"SMB3 protocol detected (dialect: 0x{dialect:04x})")
                except:
                    pass
        
        return versions
    
    def check_smb_signing(self) -> Dict[str, bool]:
        """Check SMB signing configuration"""
        signing_info = {
            'signing_enabled': False,
            'signing_required': False
        }
        
        smb2_negotiate = (
            b'\xfe\x53\x4d\x42'     # SMB2 signature
            b'\x40\x00'             # Header structure size
            b'\x00\x00'             # Credit charge
            b'\x00\x00\x00\x00'     # Status
            b'\x00\x00'             # Command (negotiate)
            b'\x00\x00'             # Credit request
            b'\x00\x00\x00\x00'     # Flags
            b'\x00\x00\x00\x00'     # Next command
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Message ID
            b'\x00\x00\x00\x00'     # Reserved
            b'\x00\x00\x00\x00'     # Tree ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Session ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x24\x00'             # Negotiate structure size
            b'\x02\x00'             # Dialect count
            b'\x01\x00'             # Security mode (signing enabled)
            b'\x00\x00'             # Reserved
            b'\x00\x00\x00\x00'     # Capabilities
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # Client GUID
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Negotiate context
            b'\x02\x02'             # SMB 2.0.2
            b'\x10\x02'             # SMB 2.1
        )
        
        response = self.send_smb_packet(smb2_negotiate)
        if response and len(response) > 70:
            try:
                # Security mode is at offset 66-67 in SMB2 negotiate response
                security_mode = struct.unpack('<H', response[66:68])[0]
                signing_info['signing_enabled'] = bool(security_mode & 0x01)
                signing_info['signing_required'] = bool(security_mode & 0x02)
                logger.debug(f"Security mode: 0x{security_mode:04x}")
            except Exception as e:
                logger.debug(f"Could not parse security mode: {e}")
        
        return signing_info
    
    def check_null_session(self) -> bool:
        """Check if null session authentication is allowed"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send SMB1 negotiate first
            dialect_strings = b'\x02NT LM 0.12\x00'
            negotiate = (
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x72'              # SMB_COM_NEGOTIATE
                b'\x00\x00\x00\x00' # NT Status
                b'\x18'             # Flags
                b'\x53\xc8'         # Flags2
                b'\x00\x00'         # Process ID High
                b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
                b'\x00\x00'         # Reserved
                b'\x00\x00'         # Tree ID
                b'\xff\xfe'         # Process ID
                b'\x00\x00'         # User ID
                b'\x00\x00'         # Multiplex ID
                b'\x00'             # Word Count
                + struct.pack('<H', len(dialect_strings))
                + dialect_strings
            )
            
            netbios_header = struct.pack('>I', len(negotiate))
            sock.send(netbios_header + negotiate)
            
            # Receive negotiate response
            resp_header = sock.recv(4)
            if len(resp_header) < 4:
                sock.close()
                return False
                
            resp_len = struct.unpack('>I', resp_header)[0] & 0x00FFFFFF
            negotiate_resp = sock.recv(resp_len)
            
            if not negotiate_resp or len(negotiate_resp) < 37:
                sock.close()
                return False
            
            # Send null session setup
            null_session = (
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x73'              # SMB_COM_SESSION_SETUP_ANDX
                b'\x00\x00\x00\x00' # NT Status
                b'\x18'             # Flags
                b'\x07\xc8'         # Flags2 (unicode, long names, NT status)
                b'\x00\x00'         # Process ID High
                b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
                b'\x00\x00'         # Reserved
                b'\x00\x00'         # Tree ID
                b'\xff\xfe'         # Process ID
                b'\x00\x00'         # User ID
                b'\x00\x00'         # Multiplex ID
                b'\x0d'             # Word Count (13)
                b'\xff'             # AndX Command (none)
                b'\x00'             # Reserved
                b'\x00\x00'         # AndX Offset
                b'\xff\xff'         # Max Buffer Size
                b'\x02\x00'         # Max Mpx Count
                b'\x01\x00'         # VC Number
                b'\x00\x00\x00\x00' # Session Key
                b'\x00\x00'         # ANSI Password Length (0 = null)
                b'\x00\x00'         # Unicode Password Length (0 = null)
                b'\x00\x00\x00\x00' # Reserved
                b'\x00\x00\x00\x00' # Capabilities
                b'\x00\x00'         # Byte Count (empty username/password)
            )
            
            netbios_header = struct.pack('>I', len(null_session))
            sock.send(netbios_header + null_session)
            
            # Receive session setup response
            resp_header = sock.recv(4)
            if len(resp_header) < 4:
                sock.close()
                return False
                
            resp_len = struct.unpack('>I', resp_header)[0] & 0x00FFFFFF
            session_resp = sock.recv(resp_len)
            
            sock.close()
            
            if session_resp and len(session_resp) >= 9:
                # Check NT Status at offset 5-8
                status = struct.unpack('<I', session_resp[5:9])[0]
                logger.debug(f"Null session status: 0x{status:08x}")
                return status == 0x00000000  # STATUS_SUCCESS
            
            return False
        except Exception as e:
            logger.debug(f"Null session check error: {e}")
            return False
    
    def check_guest_access(self) -> bool:
        """Check if guest account access is enabled"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Send negotiate
            dialect_strings = b'\x02NT LM 0.12\x00'
            negotiate = (
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x72'              # SMB_COM_NEGOTIATE
                b'\x00\x00\x00\x00'
                b'\x18'
                b'\x53\xc8'
                b'\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00'
                b'\x00\x00'
                b'\xff\xfe'
                b'\x00\x00'
                b'\x00\x00'
                b'\x00'
                + struct.pack('<H', len(dialect_strings))
                + dialect_strings
            )
            
            netbios_header = struct.pack('>I', len(negotiate))
            sock.send(netbios_header + negotiate)
            resp_header = sock.recv(4)
            if len(resp_header) < 4:
                sock.close()
                return False
            resp_len = struct.unpack('>I', resp_header)[0] & 0x00FFFFFF
            negotiate_resp = sock.recv(resp_len)
            
            if not negotiate_resp or len(negotiate_resp) < 37:
                sock.close()
                return False
            
            # Try guest session with username "guest" and empty password
            guest_user = b'guest\x00'
            
            guest_session = (
                b'\xff\x53\x4d\x42'  # SMB1 signature
                b'\x73'              # SMB_COM_SESSION_SETUP_ANDX
                b'\x00\x00\x00\x00'
                b'\x18'
                b'\x07\xc8'
                b'\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00'
                b'\x00\x00'
                b'\xff\xfe'
                b'\x00\x00'
                b'\x00\x00'
                b'\x0d'
                b'\xff'
                b'\x00'
                b'\x00\x00'
                b'\xff\xff'
                b'\x02\x00'
                b'\x01\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00'         # ANSI Password Length
                b'\x00\x00'         # Unicode Password Length
                b'\x00\x00\x00\x00'
                b'\x00\x00\x00\x00'
                + struct.pack('<H', len(guest_user))
                + guest_user
            )
            
            netbios_header = struct.pack('>I', len(guest_session))
            sock.send(netbios_header + guest_session)
            
            resp_header = sock.recv(4)
            if len(resp_header) < 4:
                sock.close()
                return False
            resp_len = struct.unpack('>I', resp_header)[0] & 0x00FFFFFF
            guest_resp = sock.recv(resp_len)
            
            sock.close()
            
            if guest_resp and len(guest_resp) >= 9:
                status = struct.unpack('<I', guest_resp[5:9])[0]
                logger.debug(f"Guest access status: 0x{status:08x}")
                return status == 0x00000000  # STATUS_SUCCESS
            
            return False
        except Exception as e:
            logger.debug(f"Guest access check error: {e}")
            return False
    
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
            report += "  ⚠️  NULL SESSION AUTHENTICATION ALLOWED\n"
            report += "      Anonymous access may be possible\n"
            critical_found = True
        
        if not critical_found:
            report += "  ✅ No critical vulnerabilities detected\n"
        
        report += "\n"
        
        # Security Configuration
        report += "SECURITY CONFIGURATION:\n"
        
        signing = self.results.get('smb_signing', {})
        if signing.get('signing_required'):
            report += "  ✅ SMB signing is required\n"
        elif signing.get('signing_enabled'):
            report += "  ⚠️  SMB signing is enabled but not required\n"
        else:
            report += "  ❌ SMB signing is disabled\n"
        
        if self.results.get('guest_access'):
            report += "  ⚠️  Guest account access is enabled\n"
        else:
            report += "  ✅ Guest account access is disabled\n"
        
        # Recommendations
        report += "\nRECOMMENDATIONS:\n"
        recommendations = []
        
        if versions.get('SMB1'):
            recommendations.append("• Disable SMB1 protocol")
        
        if not signing.get('signing_required'):
            recommendations.append("• Enable and require SMB signing")
        
        if self.results.get('guest_access'):
            recommendations.append("• Disable guest account access")
        
        if self.results.get('null_session'):
            recommendations.append("• Disable anonymous/null session access")
        
        if recommendations:
            report += "\n".join(recommendations) + "\n"
        else:
            report += "  ✅ No major security issues found\n"
        
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
    if results.get('null_session'):
        sys.exit(2)  # Critical vulnerability found
    elif results.get('smb_versions', {}).get('SMB1') or results.get('guest_access'):
        sys.exit(1)  # Security concerns found
    else:
        sys.exit(0)  # No major issues found

if __name__ == "__main__":
    main()