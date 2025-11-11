import socket
import ssl
import re
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import sys
from typing import List, Dict, Any, Optional, Tuple, Union
from . import scrapper

class EnhancedServiceDetector:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            27017: 'MongoDB', 11211: 'Memcached', 161: 'SNMP', 389: 'LDAP'
        }

    def scan_port(self, ip, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _update_service_info_from_scrapper(self, port: int, service_info: dict) -> dict:
        """Update service information from scrapper data"""
        try:
            port_info = scrapper.get_port_info(port)
            
            if port_info and isinstance(port_info, dict):
                # Update service info from dictionary
                if 'Service' in port_info:
                    service_info['service'] = port_info['Service']
                if 'Details' in port_info:
                    service_info['details']['description'] = port_info['Details']
                if 'Protocol' in port_info:
                    service_info['details']['protocol'] = port_info['Protocol']
                service_info['confidence'] = 'High'
        except Exception as e:
            service_info['details']['scrapper_error'] = str(e)
        return service_info

    def detect_service_version(self, ip, port):
        """Main service version detection function"""
        print(f"Analyzing port {port}...")
        
        service_info = {
            'port': port,
            'service': self.common_ports.get(port, 'Unknown'),
            'version': 'Unknown',
            'details': {},
            'confidence': 'Low'
        }
        
        # Update service info from scrapper
        service_info = self._update_service_info_from_scrapper(port, service_info)

        
        if port == 80 or port == 8080:
            return self._detect_http_version(ip, port, service_info)
        elif port == 443 or port == 8443 or port == 8443:
            return self._detect_https_version(ip, port, service_info)
        elif port == 22:
            return self._detect_ssh_version(ip, port, service_info)
        elif port == 21:
            return self._detect_ftp_version(ip, port, service_info)
        elif port == 25 or port == 587 or port == 465  or port == 8825 :
            return self._detect_smtp_version(ip, port, service_info)
        elif port == 110 or port == 995:
            return self._detect_pop3_version(ip, port, service_info)
        elif port == 143 or port == 993:
            return self._detect_imap_version(ip, port, service_info)
        elif port == 53:
            return self._detect_dns_version(ip, port, service_info)
        elif port == 3306 or port == 3307:
            return self._detect_mysql_version(ip, port, service_info)
        elif port == 5432:
            return self._detect_postgresql_version(ip, port, service_info)
        elif port == 6379:
            return self._detect_redis_version(ip, port, service_info)
        elif port == 1433 or port == 1434:
            return self._detect_mssql_version(ip, port, service_info)
        elif port == 27017:
            return self._detect_mongodb_version(ip, port, service_info)
        elif port == 11211:
            return self._detect_memcached_version(ip, port, service_info)
        elif port == 5900:
            return self._detect_vnc_version(ip, port, service_info)
        elif port == 161:
            return self._detect_snmp_version(ip, port, service_info)
        elif port == 389 or port == 636:
            return self._detect_ldap_version(ip, port, service_info)
        else:
            # Generic banner grabbing for unknown services
            return self._generic_banner_grab(ip, port, service_info)

    def _detect_http_version(self, ip, port, service_info):
        """Enhanced HTTP version detection with multiple methods"""
        try:
            # Method 1: Standard HTTP request with detailed headers
            responses = []
            
            # Try multiple HTTP methods and paths
            test_requests = [
                ('GET', '/', {'User-Agent': 'ServiceDetector/2.0', 'Accept': '*/*'}),
                ('HEAD', '/', {'User-Agent': 'ServiceDetector/2.0'}),
                ('OPTIONS', '*', {'User-Agent': 'ServiceDetector/2.0'}),
                ('GET', '/server-status', {'User-Agent': 'ServiceDetector/2.0'}),
                ('GET', '/server-info', {'User-Agent': 'ServiceDetector/2.0'}),
                ('TRACE', '/', {'User-Agent': 'ServiceDetector/2.0'}),
                ('GET', '/.htaccess', {'User-Agent': 'ServiceDetector/2.0'}),
                ('GET', '/robots.txt', {'User-Agent': 'ServiceDetector/2.0'}),
            ]
            
            for method, path, headers in test_requests:
                try:
                    url = f"http://{ip}:{port}{path}"
                    req = urllib.request.Request(url)
                    for header, value in headers.items():
                        req.add_header(header, value)
                    req.get_method = lambda: method
                    
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        response_headers = dict(response.headers)
                        content = response.read(2048).decode('utf-8', errors='ignore')
                        
                        responses.append({
                            'method': method,
                            'path': path,
                            'status': response.status,
                            'headers': response_headers,
                            'content': content[:500]
                        })
                        
                except urllib.error.HTTPError as e:
                    # Even errors can give us useful header information
                    if hasattr(e, 'headers'):
                        responses.append({
                            'method': method,
                            'path': path,
                            'status': e.code,
                            'headers': dict(e.headers) if e.headers else {},
                            'error': str(e)
                        })
                except:
                    continue
            
            # Method 2: Raw socket HTTP request for more control
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                
                # Send crafted HTTP request
                request = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: ServiceDetector/2.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                
                raw_response = b""
                while True:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            break
                        raw_response += data
                        if len(raw_response) > 8192:  # Limit response size
                            break
                    except socket.timeout:
                        break
                
                sock.close()
                raw_response_str = raw_response.decode('utf-8', errors='ignore')
                responses.append({
                    'method': 'RAW',
                    'raw_response': raw_response_str[:1000]
                })
                
            except:
                pass
            
            # Analyze all responses
            service_info['details']['http_responses'] = responses
            service_info['confidence'] = 'High' if responses else 'Low'
            
            # Extract server information
            for response in responses:
                if 'headers' in response:
                    headers = response['headers']
                    
                    # Check for Server header
                    for header_name in ['Server', 'server']:
                        if header_name in headers:
                            service_info['service'] = 'HTTP Server'
                            service_info['version'] = headers[header_name]
                            service_info['confidence'] = 'High'
                            break
                    
                    # Check for other identifying headers
                    if 'X-Powered-By' in headers:
                        service_info['details']['powered_by'] = headers['X-Powered-By']
                    
                    if 'X-AspNet-Version' in headers:
                        service_info['details']['aspnet_version'] = headers['X-AspNet-Version']
                
                # Analyze response content for server signatures
                if 'content' in response:
                    content = response['content'].lower()
                    if 'apache' in content:
                        if 'apache' not in service_info['version'].lower():
                            service_info['details']['content_signature'] = 'Apache detected in content'
                    elif 'nginx' in content:
                        if 'nginx' not in service_info['version'].lower():
                            service_info['details']['content_signature'] = 'nginx detected in content'
                    elif 'iis' in content:
                        if 'iis' not in service_info['version'].lower():
                            service_info['details']['content_signature'] = 'IIS detected in content'
                
                # Check raw response for additional info
                if 'raw_response' in response:
                    raw = response['raw_response']
                    # Look for server signature in raw response
                    server_match = re.search(r'Server:\s*([^\r\n]+)', raw, re.IGNORECASE)
                    if server_match and service_info['version'] == 'Unknown':
                        service_info['version'] = server_match.group(1).strip()
                        service_info['confidence'] = 'High'
            
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_https_version(self, ip, port, service_info):
        """HTTPS version detection with SSL analysis"""
        try:
            # First, get SSL information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    # Get SSL/TLS information
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert': ssock.getpeercert() if ssock.getpeercert() else None
                    }
                    service_info['details']['ssl'] = ssl_info
                    
                    # Try HTTP over SSL
                    try:
                        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: ServiceDetector/2.0\r\nConnection: close\r\n\r\n"
                        ssock.send(request.encode())
                        response = ssock.recv(4096).decode('utf-8', errors='ignore')
                        
                        # Parse HTTP response
                        if response:
                            service_info['details']['https_response'] = response[:1000]
                            
                            # Extract server header
                            server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
                            if server_match:
                                service_info['service'] = 'HTTPS Server'
                                service_info['version'] = server_match.group(1).strip()
                                service_info['confidence'] = 'High'
                    except:
                        pass
            
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_ssh_version(self, ip, port, service_info):
        """Enhanced SSH version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # SSH sends version string immediately
            version_banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if version_banner:
                service_info['service'] = 'SSH'
                service_info['version'] = version_banner
                service_info['confidence'] = 'High'
                service_info['details']['banner'] = version_banner
                
                # Try to get more information by sending our version string
                try:
                    our_version = "SSH-2.0-ServiceDetector_2.0\r\n"
                    sock.send(our_version.encode())
                    
                    # Read algorithm negotiation
                    sock.settimeout(3)
                    kex_response = sock.recv(2048)
                    if kex_response:
                        service_info['details']['kex_length'] = len(kex_response)
                        # Parse SSH packet if possible
                        if len(kex_response) > 6:
                            packet_length = struct.unpack('>I', kex_response[:4])[0]
                            service_info['details']['kex_packet_length'] = packet_length
                except:
                    pass
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_ftp_version(self, ip, port, service_info):
        """Enhanced FTP version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Get welcome banner
            welcome = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['welcome'] = welcome
            
            # Send SYST command to get system information
            sock.send(b'status\r\n')
            syst_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['syst'] = syst_response
            
            # Send FEAT command to get feature list
            sock.send(b'FEAT\r\n')
            feat_response = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            service_info['details']['feat'] = feat_response
            
            # Send HELP command
            sock.send(b'HELP\r\n')
            help_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['help'] = help_response[:200]
            
            # Analyze responses for version information
            responses = [welcome, syst_response, feat_response, help_response]
            for response in responses:
                if response and any(x in response.lower() for x in ['vsftpd', 'filezilla', 'proftpd', 'pure-ftpd']):
                    service_info['service'] = 'FTP'
                    service_info['version'] = response.split('\r\n')[0] if response else 'FTP Server'
                    service_info['confidence'] = 'High'
                    break
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_smtp_version(self, ip, port, service_info):
        """Enhanced SMTP version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Get greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['greeting'] = greeting
            
            # Send EHLO to get extended information
            sock.send(b'EHLO servicedetector.local\r\n')
            ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            service_info['details']['ehlo'] = ehlo_response
            
            # Send HELP command
            sock.send(b'HELP\r\n')
            help_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['help'] = help_response
            
            # Try VRFY command
            sock.send(b'VRFY root\r\n')
            vrfy_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['vrfy'] = vrfy_response
            
            # Analyze responses
            responses = [greeting, ehlo_response]
            for response in responses:
                if response:
                    service_info['service'] = 'SMTP'
                    service_info['version'] = response.split('\r\n')[0] if response else 'SMTP Server'
                    service_info['confidence'] = 'High'
                    break
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_dns_version(self, ip, port, service_info):
        """DNS version detection using version queries"""
        try:
            version_queries = [
                ('version.bind', 'TXT', 'CH'),
                ('version.server', 'TXT', 'CH'),
                ('hostname.bind', 'TXT', 'CH'),
                ('id.server', 'TXT', 'CH'),
                ('authors.bind', 'TXT', 'CH')
            ]
            
            for query_name, query_type, query_class in version_queries:
                try:
                    # Create DNS query packet
                    query_id = 0x1234
                    flags = 0x0100  # Standard query
                    questions = 1
                    
                    # Build query
                    query = struct.pack('>HHHHHH', query_id, flags, questions, 0, 0, 0)
                    
                    # Encode domain name
                    domain_parts = query_name.split('.')
                    for part in domain_parts:
                        query += struct.pack('B', len(part)) + part.encode()
                    query += b'\x00'  # End of domain name
                    
                    # Query type and class
                    if query_type == 'TXT':
                        qtype = 16
                    else:
                        qtype = 1  # A record
                    
                    if query_class == 'CH':
                        qclass = 3  # Chaos class
                    else:
                        qclass = 1  # Internet class
                    
                    query += struct.pack('>HH', qtype, qclass)
                    
                    # Send query
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    sock.sendto(query, (ip, port))
                    
                    # Receive response
                    response, addr = sock.recvfrom(1024)
                    sock.close()
                    
                    if len(response) > 12:  # Basic DNS header is 12 bytes
                        service_info['service'] = 'DNS'
                        service_info['confidence'] = 'High'
                        
                        # Try to parse the response for version information
                        try:
                            # Skip header and question section
                            offset = 12
                            
                            # Skip question section
                            while offset < len(response) and response[offset] != 0:
                                label_len = response[offset]
                                if label_len == 0:
                                    break
                                offset += label_len + 1
                            offset += 5  # Skip null terminator and qtype/qclass
                            
                            # Parse answer section
                            if offset + 10 < len(response):
                                # Skip name (assuming compression)
                                offset += 2
                                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                                offset += 10
                                
                                if rtype == 16 and offset + rdlength <= len(response):  # TXT record
                                    txt_data = response[offset:offset+rdlength]
                                    if len(txt_data) > 1:
                                        txt_length = txt_data[0]
                                        if txt_length > 0 and len(txt_data) > txt_length:
                                            version_info = txt_data[1:1+txt_length].decode('utf-8', errors='ignore')
                                            service_info['version'] = f"DNS Server - {version_info}"
                                            service_info['details'][f'{query_name}_response'] = version_info
                                            break
                        except:
                            service_info['version'] = 'DNS Server (version query responded)'
                            break
                
                except:
                    continue
            
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_mysql_version(self, ip, port, service_info):
        """Enhanced MySQL version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # MySQL sends handshake packet immediately
            handshake = sock.recv(1024)
            
            if len(handshake) > 5:
                # Parse handshake packet
                packet_length = struct.unpack('<I', handshake[:3] + b'\x00')[0]
                packet_number = handshake[3]
                protocol_version = handshake[4]
                
                # Find server version string (null-terminated)
                version_end = handshake.find(b'\x00', 5)
                if version_end > 5:
                    server_version = handshake[5:version_end].decode('utf-8', errors='ignore')
                    
                    service_info['service'] = 'MySQL'
                    service_info['version'] = f"MySQL {server_version}"
                    service_info['confidence'] = 'High'
                    service_info['details']['protocol_version'] = protocol_version
                    service_info['details']['packet_length'] = packet_length
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_postgresql_version(self, ip, port, service_info):
        """Enhanced PostgreSQL version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Send SSL request
            ssl_request = struct.pack('>I', 8) + struct.pack('>I', 80877103)
            sock.send(ssl_request)
            ssl_response = sock.recv(1)
            
            service_info['details']['ssl_support'] = 'Yes' if ssl_response == b'S' else 'No'
            
            if ssl_response == b'N':  # SSL not supported, try regular connection
                # Send startup message
                startup_msg = b'user\x00postgres\x00database\x00postgres\x00\x00'
                startup_packet = struct.pack('>I', len(startup_msg) + 8) + struct.pack('>I', 196608) + startup_msg
                sock.send(startup_packet)
                
                # Read response
                try:
                    response = sock.recv(1024)
                    if len(response) > 5:
                        msg_type = response[0:1]
                        if msg_type == b'E':  # Error response
                            # Parse error message for version info
                            error_msg = response[5:].decode('utf-8', errors='ignore')
                            service_info['details']['error_response'] = error_msg[:200]
                            
                            # Look for version in error message
                            version_match = re.search(r'PostgreSQL ([\d.]+)', error_msg)
                            if version_match:
                                service_info['version'] = f"PostgreSQL {version_match.group(1)}"
                                service_info['confidence'] = 'High'
                
                except:
                    pass
            
            service_info['service'] = 'PostgreSQL'
            if service_info['version'] == 'Unknown':
                service_info['version'] = 'PostgreSQL (version not determined)'
                service_info['confidence'] = 'Medium'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_redis_version(self, ip, port, service_info):
        """Enhanced Redis version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Send INFO command
            sock.send(b'INFO\r\n')
            info_response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if 'redis_version' in info_response.lower():
                # Parse INFO response
                lines = info_response.split('\n')
                redis_info = {}
                
                for line in lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        redis_info[key.strip()] = value.strip()
                
                if 'redis_version' in redis_info:
                    service_info['version'] = f"Redis {redis_info['redis_version']}"
                    service_info['confidence'] = 'High'
                
                service_info['details']['redis_info'] = redis_info
                service_info['service'] = 'Redis'
            else:
                # Try PING command
                sock.send(b'PING\r\n')
                ping_response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'PONG' in ping_response:
                    service_info['service'] = 'Redis'
                    service_info['version'] = 'Redis (INFO command failed)'
                    service_info['confidence'] = 'Medium'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_mongodb_version(self, ip, port, service_info):
        """MongoDB version detection using isMaster command"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Build isMaster command
            command = {
                "isMaster": 1,
                "client": {
                    "driver": {"name": "ServiceDetector", "version": "2.0"},
                    "os": {"type": "unknown"},
                    "platform": "Python"
                }
            }
            
            command_bson = self._dict_to_bson(command)
            
            # MongoDB wire protocol message
            request_id = 1234
            response_to = 0
            opcode = 2004  # OP_QUERY
            flags = 0
            collection = "admin.$cmd"
            skip = 0
            limit = -1
            
            # Build message
            message = struct.pack('<i', flags)
            message += collection.encode() + b'\x00'
            message += struct.pack('<ii', skip, limit)
            message += command_bson
            
            # Add header
            header = struct.pack('<iiii', 16 + len(message), request_id, response_to, opcode)
            
            sock.send(header + message)
            
            # Read response
            response_header = sock.recv(16)
            if len(response_header) == 16:
                msg_length, resp_id, resp_to, resp_opcode = struct.unpack('<iiii', response_header)
                
                if msg_length > 16:
                    response_body = sock.recv(msg_length - 16)
                    
                    # Parse response (simplified)
                    if len(response_body) > 20:
                        service_info['service'] = 'MongoDB'
                        service_info['version'] = 'MongoDB (isMaster responded)'
                        service_info['confidence'] = 'Medium'
                        
                        # Try to extract version if possible (would need full BSON parsing)
                        if b'version' in response_body:
                            service_info['confidence'] = 'High'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _dict_to_bson(self, obj):
        """Simple BSON encoding for basic objects"""
        try:
            bson = b''
            for key, value in obj.items():
                if isinstance(value, str):
                    bson += b'\x02'  # String type
                    bson += key.encode() + b'\x00'
                    bson += struct.pack('<i', len(value) + 1)
                    bson += value.encode() + b'\x00'
                elif isinstance(value, int):
                    bson += b'\x10'  # Int32 type
                    bson += key.encode() + b'\x00'
                    bson += struct.pack('<i', value)
                elif isinstance(value, dict):
                    bson += b'\x03'  # Document type
                    bson += key.encode() + b'\x00'
                    sub_bson = self._dict_to_bson(value)
                    bson += struct.pack('<i', len(sub_bson) + 5) + sub_bson + b'\x00'
            
            return struct.pack('<i', len(bson) + 5) + bson + b'\x00'
        except:
            return b'\x05\x00\x00\x00\x00'  # Minimal BSON document

    def _detect_memcached_version(self, ip, port, service_info):
        """Enhanced Memcached version detection using multiple commands"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Memcached binary protocol - version command
            # Binary protocol header: magic(1) + opcode(1) + key_length(2) + extras_length(1) + data_type(1) + status(2) + body_length(4) + opaque(4) + cas(8)
            version_cmd = b'\x80\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            sock.send(version_cmd)
            
            response = sock.recv(1024)
            if len(response) >= 24:  # Minimum binary response header
                magic = response[0]
                if magic == 0x81:  # Binary response magic
                    body_length = struct.unpack('>I', response[8:12])[0]
                    if body_length > 0 and len(response) >= 24 + body_length:
                        version_info = response[24:24+body_length].decode('utf-8', errors='ignore')
                        service_info['service'] = 'Memcached'
                        service_info['version'] = f"Memcached {version_info}"
                        service_info['confidence'] = 'High'
                        service_info['details']['version_response'] = version_info
                        sock.close()
                        return service_info
            
            # Try text protocol if binary fails
            sock.send(b'version\r\n')
            text_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if text_response.startswith('VERSION'):
                version_parts = text_response.split()
                if len(version_parts) >= 2:
                    service_info['service'] = 'Memcached'
                    service_info['version'] = f"Memcached {version_parts[1]}"
                    service_info['confidence'] = 'High'
                    service_info['details']['text_response'] = text_response
                    
                    # Try to get additional stats
                    sock.send(b'stats\r\n')
                    stats_response = sock.recv(2048).decode('utf-8', errors='ignore')
                    if 'STAT version' in stats_response:
                        service_info['details']['stats'] = stats_response[:500]
            
            # Try basic commands to confirm it's memcached
            elif not text_response:
                sock.send(b'stats\r\n')
                stats_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if stats_response.startswith('STAT') and 'version' in stats_response:
                    service_info['service'] = 'Memcached'
                    service_info['version'] = 'Memcached (stats command responded)'
                    service_info['confidence'] = 'Medium'
                    service_info['details']['stats_response'] = stats_response[:200]
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_vnc_version(self, ip, port, service_info):
        """Enhanced VNC version detection using RFB protocol"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # VNC servers send protocol version immediately
            protocol_version = sock.recv(12).decode('utf-8', errors='ignore').strip()
            
            if protocol_version.startswith('RFB'):
                service_info['service'] = 'VNC'
                service_info['version'] = f"VNC {protocol_version}"
                service_info['confidence'] = 'High'
                service_info['details']['protocol_version'] = protocol_version
                
                # Send our protocol version back to get more info
                if 'RFB 003.008' in protocol_version:
                    sock.send(b'RFB 003.008\n')
                elif 'RFB 003.007' in protocol_version:
                    sock.send(b'RFB 003.007\n')
                elif 'RFB 003.003' in protocol_version:
                    sock.send(b'RFB 003.003\n')
                else:
                    sock.send(b'RFB 003.008\n')  # Default to newest
                
                # Read security types
                try:
                    sock.settimeout(3)
                    security_response = sock.recv(256)
                    if security_response:
                        service_info['details']['security_handshake'] = len(security_response)
                        if len(security_response) > 0:
                            num_security_types = security_response[0]
                            service_info['details']['security_types_count'] = num_security_types
                except:
                    pass
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_snmp_version(self, ip, port, service_info):
        """Enhanced SNMP version detection using multiple approaches"""
        try:
            # SNMP v1/v2c detection
            community_strings = ['public', 'private', 'community']
            
            for community in community_strings:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    
                    # Build SNMP Get Request for sysDescr (1.3.6.1.2.1.1.1.0)
                    request_id = 1234
                    
                    # ASN.1 BER encoding for SNMP packet
                    # OID for sysDescr: 1.3.6.1.2.1.1.1.0
                    oid = b'\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'  # sysDescr OID + NULL
                    
                    # Variable bindings
                    varbinds = b'\x30' + bytes([len(oid)]) + oid
                    
                    # PDU (GetRequest)
                    pdu_content = (struct.pack('>I', request_id)[1:] +  # Request ID (3 bytes, skip first)
                                   b'\x02\x01\x00' +  # Error status
                                   b'\x02\x01\x00' +  # Error index
                                   b'\x30' + bytes([len(varbinds)]) + varbinds)
                    
                    pdu = b'\xa0' + bytes([len(pdu_content)]) + pdu_content
                    
                    # Community string
                    community_bytes = community.encode()
                    community_field = b'\x04' + bytes([len(community_bytes)]) + community_bytes
                    
                    # Version (0 for SNMPv1, 1 for SNMPv2c)
                    for version in [b'\x02\x01\x00', b'\x02\x01\x01']:  # Try both v1 and v2c
                        # Complete message
                        message_content = version + community_field + pdu
                        message = b'\x30' + bytes([len(message_content)]) + message_content
                        
                        sock.sendto(message, (ip, port))
                        
                        try:
                            response, addr = sock.recvfrom(1500)
                            if len(response) > 10:
                                service_info['service'] = 'SNMP'
                                service_info['confidence'] = 'High'
                                
                                # Try to parse response for system description
                                try:
                                    # Look for response PDU and extract sysDescr
                                    if b'\xa2' in response:  # GetResponse PDU
                                        # Find the string value in response
                                        pos = response.find(b'\x04')  # OCTET STRING
                                        if pos != -1 and pos + 1 < len(response):
                                            str_len = response[pos + 1]
                                            if pos + 2 + str_len <= len(response):
                                                sys_descr = response[pos + 2:pos + 2 + str_len].decode('utf-8', errors='ignore')
                                                service_info['version'] = f"SNMP - {sys_descr[:100]}"
                                                service_info['details']['system_description'] = sys_descr
                                                service_info['details']['community'] = community
                                                service_info['details']['snmp_version'] = 'v1' if version == b'\x02\x01\x00' else 'v2c'
                                                sock.close()
                                                return service_info
                                except:
                                    pass
                                
                                service_info['version'] = 'SNMP Server'
                                service_info['details']['community'] = community
                                service_info['details']['snmp_version'] = 'v1' if version == b'\x02\x01\x00' else 'v2c'
                                sock.close()
                                return service_info
                        except socket.timeout:
                            continue
                    
                    sock.close()
                    
                except Exception:
                    continue
            
            # Try SNMPv3 detection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # SNMPv3 discovery message
                v3_message = (
                    b'\x30\x3a'  # Message wrapper
                    b'\x02\x01\x03'  # Version 3
                    b'\x30\x0f'  # Global data
                    b'\x02\x04\x00\x00\x00\x01'  # Message ID
                    b'\x02\x01\x00'  # Max size
                    b'\x04\x01\x04'  # Message flags (reportable)
                    b'\x02\x01\x03'  # Security model
                    b'\x04\x00'  # Security parameters
                    b'\xa0\x24'  # Scoped PDU
                    b'\x02\x01\x00'  # Context engine ID
                    b'\x04\x00'  # Context name
                    b'\xa0\x1d'  # PDU
                    b'\x02\x04\x00\x00\x00\x01'  # Request ID
                    b'\x02\x01\x00'  # Error status
                    b'\x02\x01\x00'  # Error index
                    b'\x30\x0f'  # Variable bindings
                    b'\x30\x0d'  # Variable binding
                    b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'  # sysDescr OID
                    b'\x05\x00'  # NULL value
                )
                
                sock.sendto(v3_message, (ip, port))
                response, addr = sock.recvfrom(1500)
                
                if len(response) > 10:
                    service_info['service'] = 'SNMP'
                    service_info['version'] = 'SNMP v3'
                    service_info['confidence'] = 'High'
                    service_info['details']['snmp_version'] = 'v3'
                
                sock.close()
                
            except:
                pass
            
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_ldap_version(self, ip, port, service_info):
        """Enhanced LDAP version detection using LDAP bind and search operations"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # LDAP Bind Request (anonymous)
            # Message ID
            message_id = b'\x02\x01\x01'
            
            # Bind Request
            bind_request = (
                b'\x60\x07'  # Bind request tag and length
                b'\x02\x01\x03'  # LDAP version 3
                b'\x04\x00'  # Empty bind DN
                b'\x80\x00'  # Simple authentication, empty password
            )
            
            # Complete message
            message_length = len(message_id) + len(bind_request)
            bind_message = b'\x30' + bytes([message_length]) + message_id + bind_request
            
            sock.send(bind_message)
            
            # Read response
            response = sock.recv(1024)
            
            if len(response) > 7:
                service_info['service'] = 'LDAP'
                service_info['confidence'] = 'High'
                
                # Parse bind response
                try:
                    if b'\x61' in response:  # Bind response tag
                        # Look for result code
                        pos = response.find(b'\x61')
                        if pos != -1 and pos + 5 < len(response):
                            result_code = response[pos + 4]  # Simplified parsing
                            service_info['details']['bind_result_code'] = result_code
                            
                            if result_code == 0:  # Success
                                service_info['version'] = 'LDAP Server (anonymous bind successful)'
                            else:
                                service_info['version'] = 'LDAP Server (anonymous bind failed)'
                except:
                    service_info['version'] = 'LDAP Server'
                
                # Try RootDSE search to get more information
                try:
                    # Search Request for RootDSE
                    search_message_id = b'\x02\x01\x02'
                    search_request = (
                        b'\x63\x26'  # Search request tag and length
                        b'\x04\x00'  # Base DN (empty for RootDSE)
                        b'\x0a\x01\x00'  # Scope: base
                        b'\x0a\x01\x00'  # Deref aliases: never
                        b'\x02\x01\x00'  # Size limit: no limit
                        b'\x02\x01\x00'  # Time limit: no limit
                        b'\x01\x01\x00'  # Types only: false
                        b'\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73'  # Filter: (objectClass=*)
                        b'\x30\x00'  # Attributes: all
                    )
                    
                    search_length = len(search_message_id) + len(search_request)
                    search_message = b'\x30' + bytes([search_length]) + search_message_id + search_request
                    
                    sock.send(search_message)
                    
                    # Read search response
                    search_response = sock.recv(2048)
                    if b'supportedLDAPVersion' in search_response or b'namingContexts' in search_response:
                        service_info['details']['rootdse_available'] = True
                        service_info['version'] = 'LDAP Server (RootDSE available)'
                        service_info['confidence'] = 'High'
                        
                        # Try to extract version information
                        if b'supportedLDAPVersion' in search_response:
                            service_info['details']['supported_versions'] = 'detected'
                
                except:
                    pass
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_pop3_version(self, ip, port, service_info):
        """Enhanced POP3 version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Get greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['greeting'] = greeting
            
            # Send CAPA command to get capabilities
            sock.send(b'CAPA\r\n')
            capa_response = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            service_info['details']['capabilities'] = capa_response
            
            # Send HELP command
            sock.send(b'HELP\r\n')
            help_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['help'] = help_response
            
            # Try IMPLEMENTATION command (some servers support this)
            sock.send(b'IMPLEMENTATION\r\n')
            impl_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['implementation'] = impl_response
            
            # Analyze responses for version information
            all_responses = [greeting, capa_response, help_response, impl_response]
            
            for response in all_responses:
                if response and '+OK' in response:
                    service_info['service'] = 'POP3'
                    service_info['confidence'] = 'High'
                    
                    # Look for server identification in greeting
                    if response == greeting and any(x in response.lower() for x in ['dovecot', 'courier', 'qpopper', 'microsoft']):
                        service_info['version'] = response.replace('+OK', '').strip()[:100]
                        break
                    elif 'IMPLEMENTATION' in response and '+OK' in response:
                        service_info['version'] = response.replace('+OK', '').strip()[:100]
                        break
            
            if service_info['version'] == 'Unknown':
                service_info['version'] = 'POP3 Server'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_imap_version(self, ip, port, service_info):
        """Enhanced IMAP version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Get greeting
            greeting = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['greeting'] = greeting
            
            # Send CAPABILITY command
            sock.send(b'A001 CAPABILITY\r\n')
            capability_response = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            service_info['details']['capabilities'] = capability_response
            
            # Send ID command (RFC 2971) to get server identification
            sock.send(b'A002 ID ("name" "ServiceDetector" "version" "2.0")\r\n')
            id_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['id_response'] = id_response
            
            # Send NAMESPACE command
            sock.send(b'A003 NAMESPACE\r\n')
            namespace_response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service_info['details']['namespace'] = namespace_response
            
            # Analyze responses
            all_responses = [greeting, capability_response, id_response, namespace_response]
            
            for response in all_responses:
                if response and ('* OK' in response or '* CAPABILITY' in response):
                    service_info['service'] = 'IMAP'
                    service_info['confidence'] = 'High'
                    
                    # Look for server identification
                    if '* OK' in response and any(x in response.lower() for x in ['dovecot', 'courier', 'cyrus', 'microsoft']):
                        # Extract server info from greeting
                        server_line = [line for line in response.split('\n') if '* OK' in line]
                        if server_line:
                            service_info['version'] = server_line[0].replace('* OK', '').strip()[:100]
                            break
                    elif '* ID' in response:
                        # Parse ID response for server information
                        service_info['version'] = 'IMAP Server (ID command responded)'
                        service_info['details']['server_supports_id'] = True
                        break
            
            if service_info['version'] == 'Unknown':
                service_info['version'] = 'IMAP Server'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _detect_mssql_version(self, ip, port, service_info):
        """Enhanced Microsoft SQL Server version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # TDS (Tabular Data Stream) pre-login packet
            # This is sent before authentication to negotiate protocol version
            prelogin_packet = (
                b'\x12\x01\x00\x34\x00\x00\x00\x00'  # TDS Header (pre-login)
                b'\x00\x00\x1a\x00\x06\x01\x00\x20'  # Pre-login data
                b'\x00\x01\x02\x00\x21\x00\x01\x03'
                b'\x00\x22\x00\x04\x04\x00\x26\x00'
                b'\x01\xff\x09\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00'
            )
            
            sock.send(prelogin_packet)
            response = sock.recv(1024)
            
            if len(response) >= 8:
                # Parse TDS response
                if response[0] == 0x04:  # Pre-login response
                    service_info['service'] = 'Microsoft SQL Server'
                    service_info['confidence'] = 'High'
                    service_info['details']['tds_response_length'] = len(response)
                    
                    # Try to extract version information from pre-login response
                    if len(response) > 20:
                        # Look for version token (token type 0x00)
                        pos = 8  # Skip header
                        while pos < len(response) - 5:
                            if response[pos] == 0x00:  # Version token
                                if pos + 6 <= len(response):
                                    major = response[pos + 2]
                                    minor = response[pos + 3]
                                    build = struct.unpack('<H', response[pos + 4:pos + 6])[0]
                                    service_info['version'] = f"Microsoft SQL Server {major}.{minor}.{build}"
                                    break
                            pos += 1
                    
                    if service_info['version'] == 'Unknown':
                        service_info['version'] = 'Microsoft SQL Server (version not parsed)'
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def _generic_banner_grab(self, ip, port, service_info):
        """Enhanced generic banner grabbing with multiple techniques"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Wait for any initial banner
            sock.settimeout(3)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    service_info['details']['initial_banner'] = banner[:200]
                    service_info['version'] = banner[:100]
                    service_info['confidence'] = 'Medium'
            except socket.timeout:
                pass
            
            # Try sending common protocol initiators
            test_strings = [
                b'GET / HTTP/1.0\r\n\r\n',
                b'HEAD / HTTP/1.0\r\n\r\n',
                b'OPTIONS / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n',
                b'HELP\r\n',
                b'QUIT\r\n',
                b'VERSION\r\n',
                b'STATUS\r\n',
                b'\r\n',
                b'\n',
                b'GET\r\n',
                b'HELO localhost\r\n',
                b'EHLO localhost\r\n',
            ]
            
            responses = {}
            for test_string in test_strings:
                try:
                    sock.send(test_string)
                    sock.settimeout(2)
                    response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if response and response not in responses.values():
                        responses[test_string.decode('utf-8', errors='ignore')[:20]] = response[:200]
                        
                        # Look for service identification in response
                        response_lower = response.lower()
                        if any(x in response_lower for x in ['server', 'version', 'welcome', 'hello']):
                            service_info['version'] = response[:100]
                            service_info['confidence'] = 'Medium'
                except:
                    continue
            
            service_info['details']['test_responses'] = responses
            
            # If we got any meaningful response, mark as identified
            if responses:
                service_info['confidence'] = 'Low' if service_info['confidence'] == 'Low' else service_info['confidence']
            
            sock.close()
            return service_info
            
        except Exception as e:
            service_info['details']['error'] = str(e)
            return service_info

    def scan_target(self, target_ip, port_range=None, specific_ports=None):
        """Main scanning function"""
        print(f"Starting enhanced service detection on {target_ip}")
        
        if specific_ports:
            ports_to_scan = specific_ports
        elif port_range:
            start, end = port_range
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = list(self.common_ports.keys())
        
        results = []
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            # First, check which ports are open
            future_to_port = {executor.submit(self.scan_port, target_ip, port): port for port in ports_to_scan}
            open_ports = []
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        print(f"Port {port} is open")
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")
            
            print(f"Found {len(open_ports)} open ports. Starting service detection...")
            
            # Then detect services on open ports
            future_to_port = {executor.submit(self.detect_service_version, target_ip, port): port for port in open_ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_info = future.result()
                    results.append(service_info)
                    print(f"Port {port}: {service_info['service']} - {service_info['version']} (Confidence: {service_info['confidence']})")
                except Exception as e:
                    print(f"Error detecting service on port {port}: {e}")
        
        return results

def main():
    
    
    if len(sys.argv) < 2:
        print("Usage: python3 checkservice3.py <target_ip> [port1,port2,port3] or [start_port-end_port]")
        print("Examples:")
        print("  python3 checkservice3.py 192.168.1.1")
        print("  python3 checkservice3.py 192.168.1.1 80,443,22,21")
        print("  python3 checkservice3.py 192.168.1.1 1-1000")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    detector = EnhancedServiceDetector(timeout=10)
    
    if len(sys.argv) > 2:
        port_arg = sys.argv[2]
        
        if '-' in port_arg:
            # Port range
            start, end = map(int, port_arg.split('-'))
            results = detector.scan_target(target_ip, port_range=(start, end))
        else:
            # Specific ports
            specific_ports = [int(p.strip()) for p in port_arg.split(',')]
            results = detector.scan_target(target_ip, specific_ports=specific_ports)
    else:
        # Default common ports
        results = detector.scan_target(target_ip)
    
    # Print detailed results
    print("\n" + "="*80)
    print("DETAILED SCAN RESULTS")
    print("="*80)
    
    for result in results:
        print(f"\nPort {result['port']} ({result['service']}):")
        print(f"  Version: {result['version']}")
        print(f"  Confidence: {result['confidence']}")
        
        if result['details']:
            print("  Additional Details:")
            for key, value in result['details'].items():
                if isinstance(value, dict):
                    print(f"    {key}:")
                    for sub_key, sub_value in value.items():
                        print(f"      {sub_key}: {sub_value}")
                else:
                    print(f"    {key}: {value}")
    
    print("="*80)
    

    
def run_service_detection(
    target_ip: str,
    ports: Optional[Union[List[int], Tuple[int, int], str]] = None,
    timeout: int = 10,
) -> List[Dict[str, Any]]:
  
    # Initialize the detector (assuming EnhancedServiceDetector exists)
    detector = EnhancedServiceDetector(timeout=timeout)
    
    # Input validation and type conversion
    if not isinstance(target_ip, str):
        raise TypeError(f"target_ip must be a string, got {type(target_ip)}")
    
    if not isinstance(timeout, int):
        timeout = int(timeout)

    # Parse ports parameter with better error handling
    try:
        if ports is None:
            # Default common ports scan
            results = detector.scan_target(target_ip)
        elif isinstance(ports, list):
            # Validate list contains only integers
            ports = [int(p) for p in ports]  # Convert to int in case they're strings
            results = detector.scan_target(target_ip, specific_ports=ports)
        elif isinstance(ports, tuple) and len(ports) == 2:
            # Port range as tuple - ensure both are integers
            start_port, end_port = int(ports[0]), int(ports[1])
            results = detector.scan_target(target_ip, port_range=(start_port, end_port))
        elif isinstance(ports, str):
            # Handle string input from command line arguments
            ports_str = ports.strip()
            if '-' in ports_str and ',' not in ports_str:
                # Port range as string "1-1000"
                try:
                    parts = ports_str.split('-', 1)
                    if len(parts) != 2:
                        raise ValueError("Invalid range format")
                    start, end = int(parts[0].strip()), int(parts[1].strip())
                    if start <= 0 or end <= 0 or start > end:
                        raise ValueError("Invalid port range values")
                    results = detector.scan_target(target_ip, port_range=(start, end))
                except ValueError as e:
                    raise ValueError(f"Invalid port range format '{ports_str}'. Use 'start-end' format with valid port numbers.") from e
            elif ',' in ports_str: 
                try:
                    port_list = []
                    for p in ports_str.split(','):
                        p = p.strip()
                        if not p:  # Skip empty strings
                            continue
                        port_num = int(p)
                        if port_num <= 0 or port_num > 65535:
                            raise ValueError(f"Port {port_num} out of valid range (1-65535)")
                        port_list.append(port_num)
                    
                    if not port_list:
                        raise ValueError("No valid ports found in list")
                    
                    results = detector.scan_target(target_ip, specific_ports=port_list)
                except ValueError as e:
                    raise ValueError(f"Invalid port list format '{ports_str}'. Ensure all values are valid integers (1-65535).") from e
            else:
                # Single port as string
                try:
                    single_port = int(ports_str)
                    if single_port <= 0 or single_port > 65535:
                        raise ValueError(f"Port {single_port} out of valid range (1-65535)")
                    results = detector.scan_target(target_ip, specific_ports=[single_port])
                except ValueError as e:
                    raise ValueError(f"Invalid port value '{ports_str}'. Must be a valid integer (1-65535).") from e
        elif isinstance(ports, int):
            # Handle single integer port
            if ports <= 0 or ports > 65535:
                raise ValueError(f"Port {ports} out of valid range (1-65535)")
            results = detector.scan_target(target_ip, specific_ports=[ports])
        else:
            raise TypeError(f"Invalid ports parameter type: {type(ports)}. Use list, tuple, string, int, or None.")
    
    except AttributeError as e:
        raise AttributeError(f"EnhancedServiceDetector method not found. Ensure the detector class is properly imported: {e}")
    except Exception as e:
        raise RuntimeError(f"Error during port scanning: {e}")
    
    # Validate results format
    if not isinstance(results, list):
        raise RuntimeError("Scanner returned invalid results format. Expected list of dictionaries.")
    
    # Print detailed results if verbose
   
    return results

if __name__ == "__main__":
    main()