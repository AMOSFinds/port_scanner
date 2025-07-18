#!/usr/bin/env python3
"""
Advanced Port Scanner - Professional Network Reconnaissance Tool
Author: Amos Mashele
Description: Multi-threaded port scanner with service detection and vulnerability identification
"""

import socket
import threading
import argparse
import sys
import time
from datetime import datetime
import json
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import subprocess
import re

# Initialize colorama for cross-platform colored output
init()

class PortScanner:
    def __init__(self, target, ports=None, threads=100, timeout=1, scan_type='tcp'):
        self.target = target
        self.ports = ports or range(1, 1025)  # Default to well-known ports
        self.threads = threads
        self.timeout = timeout
        self.scan_type = scan_type.lower()
        self.open_ports = []
        self.services = {}
        self.scan_results = {
            'target': target,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'open_ports': [],
            'services': {},
            'vulnerabilities': []
        }
        
        # Common service detection patterns
        self.service_patterns = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Vulnerability patterns (basic checks)
        self.vuln_patterns = {
            21: ['anonymous ftp', 'vsftpd 2.3.4'],
            22: ['ssh-1.99', 'openssh 4.3'],
            23: ['telnet'],
            80: ['server: apache/2.2', 'server: nginx/1.0'],
            443: ['ssl-3.0', 'tls-1.0']
        }

    def print_banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                          ADVANCED PORT SCANNER                                                        ║
║                                        Professional Network Tool                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}
{Fore.YELLOW}Ports: {len(self.ports)} ports{Style.RESET_ALL}
{Fore.YELLOW}Threads: {self.threads}{Style.RESET_ALL}
{Fore.YELLOW}Scan Type: {self.scan_type.upper()}{Style.RESET_ALL}
{Fore.YELLOW}Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
        print(banner)

    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            if ip != self.target:
                print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Cannot resolve hostname: {self.target}")
            return None

    def tcp_scan(self, port):
        """TCP Connect Scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                self.open_ports.append(port)
                service = self.detect_service(port)
                self.services[port] = service
                self.check_vulnerabilities(port, service)
                print(f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} Port {port}: {service}")
                return True
        except Exception as e:
            pass
        return False

    def udp_scan(self, port):
        """UDP Scan (basic implementation)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'', (self.target, port))
            
            # UDP is connectionless, so we'll just assume it's open if no error
            self.open_ports.append(port)
            service = self.service_patterns.get(port, 'Unknown')
            self.services[port] = service
            print(f"{Fore.YELLOW}[OPEN|FILTERED]{Style.RESET_ALL} UDP Port {port}: {service}")
            return True
        except Exception:
            pass
        return False

    def detect_service(self, port):
        """Detect service running on port"""
        # First check common ports
        if port in self.service_patterns:
            return self.service_patterns[port]
        
        # Try to grab banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + self.target.encode() + b'\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse banner for service information
            if 'HTTP' in banner:
                if 'Server:' in banner:
                    server = re.search(r'Server: ([^\r\n]+)', banner)
                    if server:
                        return f"HTTP ({server.group(1)})"
                return "HTTP"
            elif 'SSH' in banner:
                return f"SSH ({banner.split()[0]})"
            elif 'FTP' in banner:
                return f"FTP ({banner.split()[0]})"
            elif banner:
                return f"Unknown ({banner[:50]})"
        except:
            pass
        
        return "Unknown"

    def check_vulnerabilities(self, port, service):
        """Basic vulnerability checks"""
        if port in self.vuln_patterns:
            for pattern in self.vuln_patterns[port]:
                if pattern.lower() in service.lower():
                    vuln = {
                        'port': port,
                        'service': service,
                        'vulnerability': f"Potentially vulnerable service: {pattern}",
                        'severity': 'Medium'
                    }
                    self.scan_results['vulnerabilities'].append(vuln)
                    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} Port {port}: {pattern} detected")

    def scan_port(self, port):
        """Scan a single port"""
        if self.scan_type == 'tcp':
            return self.tcp_scan(port)
        elif self.scan_type == 'udp':
            return self.udp_scan(port)

    def run_scan(self):
        """Execute the port scan"""
        print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Starting {self.scan_type.upper()} scan...")
        
        # Resolve target
        resolved_ip = self.resolve_target()
        if not resolved_ip:
            return
        
        self.target = resolved_ip
        
        # Start scanning
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_port, self.ports)
        
        scan_time = time.time() - start_time
        
        # Generate results
        self.generate_results(scan_time)

    def generate_results(self, scan_time):
        """Generate and display scan results"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                                                SCAN RESULTS                                                        ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Scan completed in: {scan_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Open ports found: {len(self.open_ports)}{Style.RESET_ALL}")
        
        if self.open_ports:
            print(f"\n{Fore.GREEN}OPEN PORTS:{Style.RESET_ALL}")
            print("-" * 60)
            for port in sorted(self.open_ports):
                service = self.services.get(port, 'Unknown')
                print(f"{Fore.GREEN}{port:6d}/tcp{Style.RESET_ALL}  {service}")
        
        if self.scan_results['vulnerabilities']:
            print(f"\n{Fore.RED}POTENTIAL VULNERABILITIES:{Style.RESET_ALL}")
            print("-" * 60)
            for vuln in self.scan_results['vulnerabilities']:
                print(f"{Fore.RED}Port {vuln['port']}: {vuln['vulnerability']}{Style.RESET_ALL}")
        
        # Update scan results
        self.scan_results['open_ports'] = self.open_ports
        self.scan_results['services'] = self.services
        self.scan_results['scan_duration'] = scan_time
        
        # Save results to file
        self.save_results()

    def save_results(self):
        """Save scan results to JSON file"""
        filename = f"scan_results_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            print(f"\n{Fore.GREEN}[INFO]{Style.RESET_ALL} Results saved to: {filename}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not save results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner - Professional Network Reconnaissance Tool')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000, 80,443,8080)', default='1-1024')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads (default: 100)', default=100)
    parser.add_argument('--timeout', type=float, help='Socket timeout in seconds (default: 1)', default=1)
    parser.add_argument('--scan-type', choices=['tcp', 'udp'], help='Scan type (default: tcp)', default='tcp')
    parser.add_argument('--top-ports', type=int, help='Scan top N most common ports')
    
    args = parser.parse_args()
    
    # Parse port range
    ports = []
    if args.top_ports:
        # Top common ports
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 25565]
        ports = top_ports[:args.top_ports]
    else:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        elif ',' in args.ports:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        else:
            ports = [int(args.ports)]
    
    # Initialize and run scanner
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        scan_type=args.scan_type
    )
    
    scanner.print_banner()
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[INFO]{Style.RESET_ALL} Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
