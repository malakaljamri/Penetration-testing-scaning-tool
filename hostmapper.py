"""
HostMapper - Network Host Mapper
Performs ping sweep to identify live hosts on a subnet
"""

import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class HostMapper:
    """Ping sweep tool to identify live hosts on a subnet"""
    
    def __init__(self, subnet, output_file=None):
        """
        Initialize HostMapper
        
        Args:
            subnet: Subnet in CIDR notation (e.g., 192.168.1.0/24)
            output_file: Optional output file to save results
        """
        self.subnet = subnet
        self.output_file = output_file
        self.results = []
        self.timeout = 1  # Timeout in seconds
    
    def _parse_subnet(self, subnet):
        """
        Parse subnet in CIDR notation and generate list of IP addresses
        
        Args:
            subnet: Subnet in CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            List of IP addresses to scan
        """
        if '/' not in subnet:
            raise ValueError("Subnet must be in CIDR notation (e.g., 192.168.1.0/24)")
        
        ip_str, prefix_str = subnet.split('/')
        prefix = int(prefix_str)
        
        # Convert IP to integer
        ip_parts = ip_str.split('.')
        if len(ip_parts) != 4:
            raise ValueError("Invalid IP address format")
        
        ip_int = 0
        for part in ip_parts:
            ip_int = (ip_int << 8) + int(part)
        
        # Calculate network address and broadcast address
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        network_int = ip_int & mask
        broadcast_int = network_int | (~mask & 0xFFFFFFFF)
        
        # Generate list of IP addresses (excluding network and broadcast)
        ip_list = []
        for i in range(network_int + 1, broadcast_int):
            ip = socket.inet_ntoa(struct.pack('!I', i))
            ip_list.append(ip)
        
        return ip_list
    
    def _ping_host(self, ip):
        """
        Ping a host to check if it's alive
        
        Args:
            ip: IP address to ping
        
        Returns:
            Tuple of (ip, is_alive, latency) or (ip, False, None) if error
        """
        try:
            # Create ICMP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            # Create ICMP echo request packet
            packet_id = id(time.time()) & 0xFFFF
            header = struct.pack('!BBHHH', 8, 0, 0, packet_id, 1)
            data = b'PentestKit Ping'
            checksum = self._calculate_checksum(header + data)
            header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, 1)
            packet = header + data
            
            # Send packet and measure time
            start_time = time.time()
            sock.sendto(packet, (ip, 0))
            
            try:
                # Wait for reply
                sock.recvfrom(1024)
                latency = (time.time() - start_time) * 1000  # Convert to milliseconds
                sock.close()
                return (ip, True, latency)
            except socket.timeout:
                sock.close()
                return (ip, False, None)
        
        except PermissionError:
            # If raw socket permission is denied, use TCP ping as fallback
            return self._tcp_ping(ip)
        
        except Exception:
            return (ip, False, None)
    
    def _tcp_ping(self, ip):
        """
        TCP ping as fallback when raw sockets are not available
        
        Args:
            ip: IP address to ping
        
        Returns:
            Tuple of (ip, is_alive, latency)
        """
        common_ports = [80, 443, 22, 21, 23, 25, 53]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                start_time = time.time()
                result = sock.connect_ex((ip, port))
                latency = (time.time() - start_time) * 1000
                sock.close()
                
                if result == 0:
                    return (ip, True, latency)
            except:
                continue
        
        return (ip, False, None)
    
    def _calculate_checksum(self, data):
        """
        Calculate ICMP checksum
        
        Args:
            data: Data to checksum
        
        Returns:
            Checksum value
        """
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = struct.unpack('!H', data[i:i+2])[0]
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    def scan(self):
        """Perform ping sweep on subnet"""
        try:
            ip_list = self._parse_subnet(self.subnet)
        except ValueError as e:
            print(f"Error: {e}")
            return
        
        print(f"Scanning subnet {self.subnet} ({len(ip_list)} hosts)...")
        print()
        
        # Use thread pool for concurrent pinging
        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self._ping_host, ip): ip 
                               for ip in ip_list}
                
                live_hosts = []
                for future in as_completed(future_to_ip):
                    ip, is_alive, latency = future.result()
                    
                    if is_alive:
                        latency_str = f"({latency:.2f}ms)" if latency else ""
                        print(f"{ip} {latency_str}")
                        live_hosts.append(ip)
                        self.results.append(f"{ip} {latency_str}")
        except KeyboardInterrupt:
            print("\n\nScan interrupted by user")
            return
        
        print()
        print(f"Live hosts found: {len(live_hosts)}")
        for host in live_hosts:
            print(host)
        
        # Save results to file if specified
        if self.output_file:
            self._save_results()
            print(f"\nData Saved in {self.output_file}")
    
    def _save_results(self):
        """Save scan results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"HostMapper Results for {self.subnet}\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Live hosts found: {len(self.results)}\n\n")
                for result in self.results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"Error saving results: {e}")
