#!/usr/bin/env python3

import socket
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string

class DNSVulnerabilityScanner:
    def __init__(self, target_server, timeout=5):
        self.target_server = target_server
        self.timeout = timeout
        self.results = {}
        
    def check_dns_response(self, query_type, domain):
        """Basic DNS query with error handling"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.target_server]
            resolver.timeout = self.timeout
            
            answer = resolver.resolve(domain, query_type)
            return True, answer
        except Exception as e:
            return False, str(e)
    
    def check_open_recursion(self):
        """Check if DNS server allows recursive queries from external sources"""
        print(f"[*] Testing for open recursion on {self.target_server}")
        
        # Test with external domain
        external_domains = ['google.com', 'facebook.com', 'github.com']
        
        for domain in external_domains:
            success, result = self.check_dns_response('A', domain)
            if success:
                print(f"[!] VULNERABILITY: Open recursion detected - resolved {domain}")
                self.results['open_recursion'] = True
                return True
        
        print("[+] No open recursion detected")
        self.results['open_recursion'] = False
        return False
    
    def check_dns_amplification(self):
        """Check for DNS amplification vulnerability"""
        print(f"[*] Testing for DNS amplification vulnerability")
        
        try:
            # Create a DNS query for a domain that typically has large responses
            query = dns.message.make_query('isc.org', dns.rdatatype.TXT)
            
            # Send query and measure response size
            response = dns.query.udp(query, self.target_server, timeout=self.timeout)
            
            query_size = len(query.to_wire())
            response_size = len(response.to_wire())
            amplification_factor = response_size / query_size
            
            print(f"[*] Query size: {query_size} bytes")
            print(f"[*] Response size: {response_size} bytes")
            print(f"[*] Amplification factor: {amplification_factor:.2f}")
            
            if amplification_factor > 2:
                print(f"[!] POTENTIAL VULNERABILITY: High amplification factor detected")
                self.results['amplification_risk'] = True
                return True
            else:
                print("[+] Low amplification risk")
                self.results['amplification_risk'] = False
                return False
                
        except Exception as e:
            print(f"[!] Error testing amplification: {e}")
            self.results['amplification_risk'] = None
            return False
    
    def check_zone_transfer(self):
        """Check for unauthorized zone transfers (AXFR)"""
        print(f"[*] Testing for unauthorized zone transfer")
        
        # Common domains to test zone transfer against
        test_domains = ['example.com', 'test.com', 'localhost']
        
        for domain in test_domains:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(self.target_server, domain, timeout=self.timeout))
                if zone:
                    print(f"[!] VULNERABILITY: Zone transfer allowed for {domain}")
                    self.results['zone_transfer'] = True
                    return True
            except Exception:
                continue
        
        print("[+] No unauthorized zone transfers detected")
        self.results['zone_transfer'] = False
        return False
    
    def check_dns_cache_poisoning(self):
        """Check for potential DNS cache poisoning vulnerability"""
        print(f"[*] Testing for DNS cache poisoning resistance")
        
        try:
            # Generate random subdomain
            random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_domain = f"{random_subdomain}.nonexistent-domain-for-testing.com"
            
            # Query for non-existent domain
            success, result = self.check_dns_response('A', test_domain)
            
            if success:
                print(f"[!] SUSPICIOUS: DNS server returned result for non-existent domain")
                self.results['cache_poisoning_risk'] = True
                return True
            else:
                print("[+] DNS server properly handles non-existent domains")
                self.results['cache_poisoning_risk'] = False
                return False
                
        except Exception as e:
            print(f"[!] Error testing cache poisoning: {e}")
            self.results['cache_poisoning_risk'] = None
            return False
    
    def check_dns_version(self):
        """Check DNS server version disclosure"""
        print(f"[*] Testing for DNS version disclosure")
        
        try:
            # Query for version.bind or version.server
            version_queries = ['version.bind', 'version.server']
            
            for version_query in version_queries:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [self.target_server]
                    resolver.timeout = self.timeout
                    
                    answer = resolver.resolve(version_query, 'TXT', dns.rdataclass.CH)
                    
                    for record in answer:
                        version_info = record.to_text().strip('"')
                        print(f"[!] INFO DISCLOSURE: DNS version revealed: {version_info}")
                        self.results['version_disclosure'] = version_info
                        return True
                        
                except Exception:
                    continue
            
            print("[+] No version information disclosed")
            self.results['version_disclosure'] = False
            return False
            
        except Exception as e:
            print(f"[!] Error checking version: {e}")
            self.results['version_disclosure'] = None
            return False
    
    def check_dns_flooding_resistance(self):
        """Test basic DNS flooding resistance"""
        print(f"[*] Testing DNS flooding resistance (basic)")
        
        def send_query():
            try:
                random_domain = ''.join(random.choices(string.ascii_lowercase, k=8)) + '.com'
                success, _ = self.check_dns_response('A', random_domain)
                return success
            except:
                return False
        
        # Send multiple concurrent queries
        successful_queries = 0
        total_queries = 10
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_query) for _ in range(total_queries)]
            
            for future in as_completed(futures):
                if future.result():
                    successful_queries += 1
        
        success_rate = successful_queries / total_queries
        print(f"[*] Query success rate: {success_rate:.2f}")
        
        if success_rate < 0.8:
            print("[!] POTENTIAL ISSUE: DNS server may be overwhelmed by concurrent queries")
            self.results['flooding_resistance'] = False
        else:
            print("[+] DNS server handles concurrent queries well")
            self.results['flooding_resistance'] = True
        
        return success_rate > 0.8
    
    def run_all_tests(self):
        """Run all vulnerability tests"""
        print(f"Starting DNS vulnerability scan on {self.target_server}")
        print("=" * 60)
        
        tests = [
            self.check_open_recursion,
            self.check_dns_amplification,
            self.check_zone_transfer,
            self.check_dns_cache_poisoning,
            self.check_dns_version,
            self.check_dns_flooding_resistance
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
        print(f"Target: {self.target_server}")
        print(f"Vulnerabilities found: {vulnerabilities_found}")
        
        if vulnerabilities_found > 0:
            print(f"[!] SECURITY ISSUES DETECTED")
        else:
            print(f"[+] No major vulnerabilities detected")
        
        return self.results

def run_dns_vuln_scan(server, timeout=5):
    print(sys.executable)
    scanner = DNSVulnerabilityScanner(server, timeout)
    return scanner.run_all_tests()

def main():
    parser = argparse.ArgumentParser(description='DNS Security Vulnerability Scanner')
    parser.add_argument('server', help='Target DNS server IP address')
    parser.add_argument('--timeout', type=int, default=5, help='Query timeout in seconds')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Validate IP address
    try:
        socket.inet_aton(args.server)
    except socket.error:
        print(f"[!] Invalid IP address: {args.server}")
        sys.exit(1)
    
    scanner = DNSVulnerabilityScanner(args.server, args.timeout)
    results = scanner.run_all_tests()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"DNS Vulnerability Scan Results\n")
            f.write(f"Target: {args.server}\n")
            f.write(f"Timestamp: {time.ctime()}\n\n")
            
            for test, result in results.items():
                f.write(f"{test}: {result}\n")
        
        print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
