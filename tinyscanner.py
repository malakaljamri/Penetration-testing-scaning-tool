"""
TinyScanner - Simple Port Scanner
Checks for open, closed, or filtered ports on a target host
"""

import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


class TinyScanner:
    """Simple TCP port scanner"""
    
    # Common service ports mapping
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt'
    }
    
    def __init__(self, target, ports, output_file=None):
        """
        Initialize TinyScanner
        
        Args:
            target: Target IP address or hostname
            ports: Ports to scan (comma-separated or range, e.g., "22,80,443" or "1-1000")
            output_file: Optional output file to save results
        """
        self.target = target
        self.ports = self._parse_ports(ports)
        self.output_file = output_file
        self.results = []
        self.timeout = 1  # Connection timeout in seconds
    
    def _parse_ports(self, ports_str):
        """
        Parse port specification
        
        Args:
            ports_str: Port specification string (e.g., "22,80,443" or "1-1000")
        
        Returns:
            List of port numbers to scan
        """
        ports = []
        
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                # Handle range (e.g., "1-1000")
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                ports.extend(range(start, end + 1))
            else:
                # Handle single port
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def _scan_port(self, port):
        """
        Scan a single port
        
        Args:
            port: Port number to scan
        
        Returns:
            Tuple of (port, status, service)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                sock.close()
                service = self.COMMON_PORTS.get(port, 'Unknown')
                return (port, 'open', service)
            else:
                sock.close()
                return (port, 'closed', '')
        
        except socket.timeout:
            return (port, 'filtered', '')
        except Exception as e:
            return (port, 'error', str(e))
    
    def scan(self):
        """Perform port scan"""
        print(f"Scanning {self.target} for {len(self.ports)} ports...")
        print()
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(self._scan_port, port): port 
                            for port in self.ports}
            
            for future in as_completed(future_to_port):
                port, status, service = future.result()
                
                if status == 'open':
                    print(f"Port {port} is open ({service})")
                    self.results.append(f"Port {port} is open ({service})")
                elif status == 'closed':
                    print(f"Port {port} is closed")
                    self.results.append(f"Port {port} is closed")
                elif status == 'filtered':
                    print(f"Port {port} is filtered")
                    self.results.append(f"Port {port} is filtered")
                else:
                    print(f"Port {port}: Error - {service}")
                    self.results.append(f"Port {port}: Error - {service}")
        
        # Save results to file if specified
        if self.output_file:
            self._save_results()
            print(f"\nData Saved in {self.output_file}")
    
    def _save_results(self):
        """Save scan results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"TinyScanner Results for {self.target}\n")
                f.write("=" * 50 + "\n\n")
                for result in self.results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"Error saving results: {e}")
