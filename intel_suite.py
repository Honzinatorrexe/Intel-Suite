#!/usr/bin/env python3

import socket
import struct
import threading
import queue
import time
import ipaddress
import ssl
import dns.resolver
import requests
from datetime import datetime
import json
import sys
import argparse
import subprocess
import concurrent.futures
import whois
from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, sr1

class NetIntelSuite:
    def __init__(self):
        self.version = "2.0"
        self.author = "Honzinatorr"
        self.results = {}
        self.start_time = None
        
    def banner(self):
        banner_text = f"""

╔══════════════════════════════════════════════════════════════════╗
║                          NETINTEL SUITE                          ║
║              Professional Network Intelligence Toolkit           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

"""
        print(banner_text)

    def show_menu(self):
        menu_text = f"""

┌─────────────────────────────────────────────────────────────┐
│                      MAIN MENU                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [1]  Fast Port Scanner (1-1024 ports)                            │
│  [2]  Advanced Port Scanner with Service Detection                │
│  [3]  Network Range Scanner (ARP/ICMP)                            │
│  [4]  OS Fingerprinting (TCP/IP Stack Analysis)                   │
│  [5]  Service Banner Grabbing                                     │
│  [6]  DNS Enumeration (Records: A, AAAA, MX, TXT, NS, SOA)       │
│  [7]  Subdomain Discovery (Dictionary/DNS Brute)                 │
│  [8]  WHOIS Lookup + Domain Intelligence                         │
│  [9]  SSL/TLS Certificate Analyzer                                │
│  [10] HTTP/HTTPS Security Headers Checker                         │
│  [11] Common Vulnerability Scanner (CVE Checks)                  │
│  [12] Network Latency & Packet Loss Test                          │
│  [13] Reverse DNS Lookup                                          │
│  [14] GeoIP Location Tracker                                      │
│  [15] BGP Route Information                                      │
│  [16] Export Results (JSON/HTML/CSV)                             │
│  [17] Run Full Security Audit                                     │
│  [0] Exit                                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

"""
        print(menu_text)

    def fast_port_scan(self, target, ports=1024):
        print(f"[*] Starting fast scan on {target}...")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"[+] Port {port} is OPEN")
                sock.close()
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            executor.map(scan_port, range(1, ports + 1))
        
        return open_ports

    def advanced_service_scan(self, target, ports=None):
        print(f"[*] Starting advanced service scan on {target}...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        if ports:
            common_ports = ports
        
        services = {}
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    service_name = socket.getservbyport(port, 'tcp')
                    banner = self.grab_banner(target, port)
                    
                    services[port] = {
                        'service': service_name,
                        'banner': banner[:200] if banner else 'No banner',
                        'status': 'open'
                    }
                    print(f"[+] Port {port} ({service_name}) - Banner: {banner[:80] if banner else 'N/A'}")
                sock.close()
            except:
                pass
        
        return services

    def grab_banner(self, target, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            if port == 80:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except:
            return None

    def network_range_scan(self, network):
        print(f"[*] Scanning network: {network}")
        
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                print(f"[+] Device: {received.psrc} - MAC: {received.hwsrc}")
            
            return devices
        except Exception as e:
            print(f"[-] Error: {e}")
            return []

    def ping_sweep(self, network):
        print(f"[*] Performing ICMP ping sweep on {network}")
        
        alive_hosts = []
        network_obj = ipaddress.ip_network(network, strict=False)
        
        def ping_host(ip):
            try:
                packet = IP(dst=str(ip))/ICMP()
                response = sr1(packet, timeout=1, verbose=0)
                if response:
                    alive_hosts.append(str(ip))
                    print(f"[+] Host {ip} is alive")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(ping_host, network_obj.hosts())
        
        return alive_hosts

    def os_fingerprint(self, target):
        print(f"[*] Fingerprinting OS for {target}...")
        
        results = {}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 80))
            window_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            sock.close()
            results['tcp_window'] = window_size
        except:
            pass
        
        try:
            packet = IP(dst=target)/ICMP()
            response = sr1(packet, timeout=2, verbose=0)
            if response:
                ttl = response.ttl
                results['ttl'] = ttl
                
                if ttl <= 64:
                    results['os_guess'] = 'Linux / Unix / macOS'
                elif ttl <= 128:
                    results['os_guess'] = 'Windows'
                elif ttl <= 255:
                    results['os_guess'] = 'Cisco / Solaris / AIX'
                else:
                    results['os_guess'] = 'Unknown'
        except:
            pass
        
        print(f"[+] TTL: {results.get('ttl', 'N/A')} - OS Guess: {results.get('os_guess', 'Unknown')}")
        return results

    def dns_enumeration(self, domain):
        print(f"[*] Enumerating DNS records for {domain}...")
        
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'SOA': None,
            'CNAME': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    records[record_type].append(str(answer))
                    print(f"[+] {record_type} Record: {answer}")
            except:
                pass
        
        try:
            soa = dns.resolver.resolve(domain, 'SOA')
            records['SOA'] = str(soa[0])
            print(f"[+] SOA Record: {soa[0]}")
        except:
            pass
        
        return records

    def subdomain_discovery(self, domain, wordlist=None):
        print(f"[*] Discovering subdomains for {domain}...")
        
        default_wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 
                            'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 
                            'autoconfig', 'api', 'blog', 'admin', 'dev', 'test', 'stage',
                            'secure', 'vpn', 'remote', 'support', 'portal', 'shop', 'store']
        
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    subdomains = [line.strip() for line in f]
            except:
                subdomains = default_wordlist
        else:
            subdomains = default_wordlist
        
        found_subdomains = []
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                found_subdomains.append(full_domain)
                print(f"[+] Found subdomain: {full_domain}")
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, subdomains)
        
        return found_subdomains

    def whois_lookup(self, domain):
        print(f"[*] Performing WHOIS lookup for {domain}...")
        
        try:
            w = whois.whois(domain)
            
            info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails
            }
            
            print(f"[+] Registrar: {w.registrar}")
            print(f"[+] Created: {w.creation_date}")
            print(f"[+] Expires: {w.expiration_date}")
            print(f"[+] Name Servers: {w.name_servers}")
            
            return info
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")
            return None

    def geoip_tracker(self, target):
        print(f"[*] Tracking GeoIP for {target}...")
        
        try:
            response = requests.get(f'http://ip-api.com/json/{target}')
            data = response.json()
            
            if data['status'] == 'success':
                location = {
                    'ip': data['query'],
                    'country': data['country'],
                    'city': data['city'],
                    'region': data['regionName'],
                    'latitude': data['lat'],
                    'longitude': data['lon'],
                    'isp': data['isp'],
                    'organization': data['org']
                }
                
                print(f"[+] Country: {location['country']}")
                print(f"[+] City: {location['city']}")
                print(f"[+] ISP: {location['isp']}")
                print(f"[+] Coordinates: {location['latitude']}, {location['longitude']}")
                
                return location
            else:
                print(f"[-] GeoIP lookup failed")
                return None
        except Exception as e:
            print(f"[-] Error: {e}")
            return None

    def ssl_analyzer(self, hostname, port=443):
        print(f"[*] Analyzing SSL certificate for {hostname}:{port}...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_name': cert['subjectAltName']
                    }
                    
                    print(f"[+] Issuer: {info['issuer'].get('organizationName', 'N/A')}")
                    print(f"[+] Expires: {info['not_after']}")
                    print(f"[+] Common Name: {info['subject'].get('commonName', 'N/A')}")
                    
                    return info
        except Exception as e:
            print(f"[-] SSL analysis failed: {e}")
            return None

    def security_headers(self, url):
        print(f"[*] Checking security headers for {url}...")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            security_checks = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'MISSING'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'MISSING'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'MISSING'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'MISSING'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'MISSING')
            }
            
            for header, value in security_checks.items():
                if value != 'MISSING':
                    print(f"[+] {header}: {value}")
                else:
                    print(f"[-] {header}: {value}")
            
            return security_checks
        except Exception as e:
            print(f"[-] Header check failed: {e}")
            return None

    def vulnerability_scanner(self, target, ports=None):
        print(f"[*] Scanning for common vulnerabilities on {target}...")
        
        vulnerabilities = []
        
        vulnerable_ports = {
            21: 'FTP - Anonymous login possible?',
            22: 'SSH - Weak encryption?',
            23: 'Telnet - Unencrypted protocol',
            80: 'HTTP - Missing security headers',
            443: 'HTTPS - SSL/TLS vulnerabilities',
            3306: 'MySQL - Default credentials?',
            3389: 'RDP - BlueKeep vulnerability?',
            5900: 'VNC - Weak authentication?'
        }
        
        check_ports = ports if ports else vulnerable_ports.keys()
        
        for port in check_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    vuln_desc = vulnerable_ports.get(port, f'Port {port} open - Further investigation needed')
                    vulnerabilities.append({
                        'port': port,
                        'vulnerability': vuln_desc
                    })
                    print(f"[!] Port {port} open: {vuln_desc}")
                sock.close()
            except:
                pass
        
        return vulnerabilities

    def reverse_dns(self, ip_address):
        print(f"[*] Reverse DNS lookup for {ip_address}...")
        
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            print(f"[+] Hostname: {hostname}")
            return hostname
        except:
            print(f"[-] No reverse DNS record found")
            return None

    def latency_test(self, target, count=10):
        print(f"[*] Testing latency to {target}...")
        
        latencies = []
        lost_packets = 0
        
        for i in range(count):
            try:
                start = time.time()
                packet = IP(dst=target)/ICMP()
                response = sr1(packet, timeout=2, verbose=0)
                end = time.time()
                
                if response:
                    latency = (end - start) * 1000
                    latencies.append(latency)
                    print(f"[+] Ping {i+1}: {latency:.2f} ms")
                else:
                    lost_packets += 1
                    print(f"[-] Ping {i+1}: Request timed out")
            except:
                lost_packets += 1
        
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            packet_loss = (lost_packets / count) * 100
            
            print(f"\n[+] Statistics:")
            print(f"    Average Latency: {avg_latency:.2f} ms")
            print(f"    Min Latency: {min(latencies):.2f} ms")
            print(f"    Max Latency: {max(latencies):.2f} ms")
            print(f"    Packet Loss: {packet_loss:.1f}%")
            
            return {'avg': avg_latency, 'min': min(latencies), 'max': max(latencies), 'loss': packet_loss}
        
        return None

    def bgp_route_info(self, ip_address):
        print(f"[*] Fetching BGP info for {ip_address}...")
        
        try:
            response = requests.get(f'https://stat.ripe.net/data/whois/data.json?resource={ip_address}')
            data = response.json()
            print(f"[+] ASN Lookup completed")
            return data
        except:
            print(f"[-] BGP lookup failed")
            return None

    def export_results(self, results, filename, format='json'):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'json':
            output_file = f"{filename}_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"[+] Results exported to {output_file}")
        
        elif format == 'html':
            output_file = f"{filename}_{timestamp}.html"
            html_content = f"""
            <html>
            <head><title>NetIntel Suite Report</title></head>
            <body>
            <h1>Network Intelligence Report</h1>
            <pre>{json.dumps(results, indent=2, default=str)}</pre>
            </body>
            </html>
            """
            with open(output_file, 'w') as f:
                f.write(html_content)
            print(f"[+] Results exported to {output_file}")

    def full_security_audit(self, target, network=None):
        print(f"\n[*] Starting Full Security Audit on {target}")
        self.start_time = time.time()
        
        full_results = {
            'target': target,
            'timestamp': str(datetime.now()),
            'scans': {}
        }
        
        print(f"\n=== PORT SCANNING ===")
        full_results['scans']['ports'] = self.advanced_service_scan(target)
        
        print(f"\n=== OS FINGERPRINTING ===")
        full_results['scans']['os'] = self.os_fingerprint(target)
        
        print(f"\n=== VULNERABILITY SCAN ===")
        full_results['scans']['vulnerabilities'] = self.vulnerability_scanner(target)
        
        print(f"\n=== LATENCY TEST ===")
        full_results['scans']['latency'] = self.latency_test(target)
        
        try:
            self.ssl_analyzer(target)
        except:
            pass
        
        if network:
            print(f"\n=== NETWORK SCAN ===")
            full_results['scans']['network'] = self.network_range_scan(network)
        
        elapsed = time.time() - self.start_time
        print(f"\n[+] Audit completed in {elapsed:.2f} seconds")
        print(f"[+] Open ports found: {len(full_results['scans'].get('ports', {}))}")
        print(f"[+] Vulnerabilities found: {len(full_results['scans'].get('vulnerabilities', []))}")
        
        return full_results

    def run(self):
        self.banner()
        
        while True:
            self.show_menu()
            
            choice = input(f"\nNetIntel> ").strip()
            
            if choice == '1':
                target = input("Enter target IP or domain: ")
                ports = input("Number of ports to scan (default 1024): ") or 1024
                self.fast_port_scan(target, int(ports))
            
            elif choice == '2':
                target = input("Enter target IP or domain: ")
                self.advanced_service_scan(target)
            
            elif choice == '3':
                network = input("Enter network (e.g., 192.168.1.0/24): ")
                self.network_range_scan(network)
            
            elif choice == '4':
                target = input("Enter target IP: ")
                self.os_fingerprint(target)
            
            elif choice == '5':
                target = input("Enter target IP: ")
                port = int(input("Enter port number: "))
                banner = self.grab_banner(target, port)
                if banner:
                    print(f"[+] Banner: {banner}")
            
            elif choice == '6':
                domain = input("Enter domain: ")
                self.dns_enumeration(domain)
            
            elif choice == '7':
                domain = input("Enter domain: ")
                self.subdomain_discovery(domain)
            
            elif choice == '8':
                domain = input("Enter domain: ")
                self.whois_lookup(domain)
            
            elif choice == '9':
                hostname = input("Enter hostname: ")
                self.ssl_analyzer(hostname)
            
            elif choice == '10':
                url = input("Enter URL (http:// or https://): ")
                self.security_headers(url)
            
            elif choice == '11':
                target = input("Enter target IP: ")
                self.vulnerability_scanner(target)
            
            elif choice == '12':
                target = input("Enter target IP or hostname: ")
                self.latency_test(target)
            
            elif choice == '13':
                ip = input("Enter IP address: ")
                self.reverse_dns(ip)
            
            elif choice == '14':
                target = input("Enter IP or domain: ")
                self.geoip_tracker(target)
            
            elif choice == '15':
                ip = input("Enter IP address: ")
                self.bgp_route_info(ip)
            
            elif choice == '16':
                print("Export results from full audit option 17")
            
            elif choice == '17':
                target = input("Enter target IP or domain: ")
                network = input("Enter network for local scan (optional, press Enter to skip): ")
                results = self.full_security_audit(target, network if network else None)
                self.export_results(results, f"audit_{target}", 'json')
            
            elif choice == '0':
                print(f"[+] Exiting NetIntel Suite. Stay secure!")
                break
            
            else:
                print(f"[-] Invalid option")
            
            if choice != '0':
                input(f"\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        suite = NetIntelSuite()
        suite.run()
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")