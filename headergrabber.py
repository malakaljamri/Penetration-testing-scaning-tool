"""
HeaderGrabber - HTTP Header Analyzer
Retrieves and analyzes HTTP headers from a web server
"""

import urllib.request
import urllib.error
import ssl


class HeaderGrabber:
    """HTTP header analyzer for web servers"""
    
    # Security headers that should be present
    SECURITY_HEADERS = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'Permissions-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
        'Cross-Origin-Embedder-Policy'
    ]
    
    # Information disclosure headers
    INFO_DISCLOSURE_HEADERS = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-Pingback'
    ]
    
    def __init__(self, target_url, output_file=None):
        """
        Initialize HeaderGrabber
        
        Args:
            target_url: Target URL (e.g., http://example.com)
            output_file: Optional output file to save results
        """
        self.target_url = self._normalize_url(target_url)
        self.output_file = output_file
        self.results = []
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
    
    def analyze(self):
        """Retrieve and analyze HTTP headers"""
        print(f"Analyzing headers for {self.target_url}...")
        print()
        
        try:
            request = urllib.request.Request(self.target_url)
            request.add_header('User-Agent', self.user_agent)
            
            response = urllib.request.urlopen(request, timeout=5, 
                                            context=self.ssl_context)
            
            # Get response headers
            headers = dict(response.headers)
            
            # Print status line
            status_line = f"HTTP/1.1 {response.getcode()} OK"
            print(status_line)
            self.results.append(status_line)
            
            # Print all headers
            for header, value in headers.items():
                header_line = f"{header}: {value}"
                print(header_line)
                self.results.append(header_line)
            
            print()
            
            # Analyze security headers
            self._analyze_security_headers(headers)
            
            # Analyze information disclosure
            self._analyze_info_disclosure(headers)
            
            # Save results to file if specified
            if self.output_file:
                self._save_results()
                print(f"\nData saved in {self.output_file}")
        
        except urllib.error.URLError as e:
            print(f"Error connecting to {self.target_url}: {e}")
        
        except Exception as e:
            print(f"Error: {e}")
    
    def _analyze_security_headers(self, headers):
        """Analyze security headers"""
        print("Security Headers Analysis:")
        print("-" * 50)
        
        missing_headers = []
        present_headers = []
        
        for header in self.SECURITY_HEADERS:
            if header in headers:
                present_headers.append(header)
                print(f"✓ {header}: {headers[header]}")
            else:
                missing_headers.append(header)
                print(f"✗ {header}: MISSING")
        
        if missing_headers:
            print()
            print(f"Warning: Missing {len(missing_headers)} Security Headers:")
            for header in missing_headers:
                print(f"  - {header}")
            self.results.append(f"\nWarning: Missing Security Headers - {', '.join(missing_headers)}")
        
        print()
        self.results.append("\nSecurity Headers Analysis:")
        self.results.append("-" * 50)
        self.results.extend(present_headers)
        if missing_headers:
            self.results.append(f"\nMissing Security Headers: {', '.join(missing_headers)}")
    
    def _analyze_info_disclosure(self, headers):
        """Analyze information disclosure headers"""
        print("Information Disclosure:")
        print("-" * 50)
        
        found_info = []
        
        for header in self.INFO_DISCLOSURE_HEADERS:
            if header in headers:
                found_info.append(f"{header}: {headers[header]}")
                print(f"⚠ {header}: {headers[header]}")
        
        if not found_info:
            print("No information disclosure headers detected")
        
        print()
        self.results.append("\nInformation Disclosure:")
        self.results.append("-" * 50)
        if found_info:
            self.results.extend(found_info)
        else:
            self.results.append("No information disclosure headers detected")
    
    def _save_results(self):
        """Save analysis results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"HeaderGrabber Results for {self.target_url}\n")
                f.write("=" * 50 + "\n\n")
                for result in self.results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"Error saving results: {e}")
