"""
DirFinder - Small Dirsearch
Discovers hidden directories and files on a web server by brute-forcing common paths
"""

import socket
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


class DirFinder:
    """Directory brute-forcer for web servers"""
    
    def __init__(self, target_url, wordlist_path, output_file=None):
        """
        Initialize DirFinder
        
        Args:
            target_url: Target URL (e.g., http://example.com)
            wordlist_path: Path to wordlist file
            output_file: Optional output file to save results
        """
        self.target_url = self._normalize_url(target_url)
        self.wordlist_path = wordlist_path
        self.output_file = output_file
        self.results = []
        self.timeout = 3  # Request timeout in seconds
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        # Create SSL context that doesn't verify certificates (for testing purposes)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _normalize_url(self, url):
        """
        Normalize URL to ensure it has proper format
        
        Args:
            url: Input URL
        
        Returns:
            Normalized URL
        """
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if url.endswith('/'):
            url = url[:-1]
        return url
    
    def _load_wordlist(self):
        """
        Load wordlist from file
        
        Returns:
            List of paths to test
        """
        paths = []
        try:
            with open(self.wordlist_path, 'r') as f:
                for line in f:
                    path = line.strip()
                    if path and not path.startswith('#'):  # Skip empty lines and comments
                        paths.append(path)
        except FileNotFoundError:
            print(f"Error: Wordlist file not found: {self.wordlist_path}")
            raise
        return paths
    
    def _check_path(self, path):
        """
        Check if a path exists on the target server
        
        Args:
            path: Path to check (e.g., /admin, /login.php)
        
        Returns:
            Tuple of (path, status_code, content_length) or (path, None, None) if error
        """
        full_url = self.target_url + path
        
        try:
            request = urllib.request.Request(full_url)
            request.add_header('User-Agent', self.user_agent)
            
            response = urllib.request.urlopen(request, timeout=self.timeout, 
                                            context=self.ssl_context)
            status_code = response.getcode()
            content_length = response.getheader('Content-Length', '0')
            
            return (path, status_code, content_length)
        
        except urllib.error.HTTPError as e:
            # HTTPError means we got a response (even if it's 404, 403, etc.)
            return (path, e.code, '0')
        
        except urllib.error.URLError as e:
            # URLError means connection failed
            return (path, None, None)
        
        except socket.timeout:
            return (path, None, None)
        
        except Exception as e:
            return (path, None, None)
    
    def scan(self):
        """Perform directory brute-force scan"""
        print(f"Loading wordlist from {self.wordlist_path}...")
        
        try:
            paths = self._load_wordlist()
        except Exception:
            return
        
        print(f"Loaded {len(paths)} paths")
        print(f"Scanning {self.target_url}...")
        print()
        
        # Use thread pool for concurrent requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_path = {executor.submit(self._check_path, path): path 
                             for path in paths}
            
            for future in as_completed(future_to_path):
                path, status_code, content_length = future.result()
                
                if status_code is not None:
                    # Only show interesting status codes (not 404)
                    if status_code != 404:
                        status_msg = f"[Status: {status_code}]"
                        if content_length and content_length != '0':
                            status_msg += f" [Size: {content_length}]"
                        
                        print(f"{path:<20} {status_msg}")
                        self.results.append(f"{path:<20} {status_msg}")
        
        # Save results to file if specified
        if self.output_file:
            self._save_results()
            print(f"\nData Saved in {self.output_file}")
    
    def _save_results(self):
        """Save scan results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"DirFinder Results for {self.target_url}\n")
                f.write("=" * 50 + "\n\n")
                for result in self.results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"Error saving results: {e}")
