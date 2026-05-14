# PentestKit Test Commands

This document contains test commands for all PentestKit tools.

## View Help

```bash
python3 pentestkit.py --help
```

## 1. TinyScanner - Port Scanner

### Scan specific ports on localhost
```bash
python3 pentestkit.py -t 127.0.0.1 -p 22,80,443,8080,3000 -o scanner_result.txt
```

### Scan a range of ports
```bash
python3 pentestkit.py -t 127.0.0.1 -p 1-100 -o scanner_result.txt
```

### Scan common ports on a remote host
```bash
python3 pentestkit.py -t 192.168.1.1 -p 21,22,23,25,53,80,110,143,443,445,3306,3389 -o scanner_result.txt
```

## 2. DirFinder - Directory Brute-Forcer

### Test on example.com
```bash
python3 pentestkit.py -d http://example.com -w wordlist.txt -o dirfinder_result.txt
```

### Test on reboot01.com
```bash
python3 pentestkit.py -d https://reboot01.com -w wordlist.txt -o dirfinder_result.txt
```

### Test on localhost (if you have a web server running)
```bash
python3 pentestkit.py -d http://127.0.0.1:3000 -w wordlist.txt -o dirfinder_result.txt
```

## 3. HostMapper - Ping Sweep

### Scan your local subnet (172.20.10.0/24)
```bash
python3 pentestkit.py -m 172.20.10.0/24 -o hostmapper_result.txt
```

### Scan a different subnet (192.168.1.0/24)
```bash
python3 pentestkit.py -m 192.168.1.0/24 -o hostmapper_result.txt
```

### Scan a smaller subnet (/29 = 6 hosts)
```bash
python3 pentestkit.py -m 192.168.1.0/29 -o hostmapper_result.txt
```

## 4. HeaderGrabber - HTTP Header Analyzer

### Analyze headers of example.com
```bash
python3 pentestkit.py -g http://example.com -o header_result.txt
```

### Analyze headers of reboot01.com
```bash
python3 pentestkit.py -g https://reboot01.com -o header_result.txt
```

### Analyze headers of localhost
```bash
python3 pentestkit.py -g http://127.0.0.1:3000 -o header_result.txt
```

## Viewing Results

After running any test, you can view the results in the output files:

```bash
# View scanner results
cat scanner_result.txt

# View dirfinder results
cat dirfinder_result.txt

# View hostmapper results
cat hostmapper_result.txt

# View header analysis results
cat header_result.txt
```

## Notes

- **HostMapper**: If you don't have root/sudo access, it will automatically fall back to TCP ping on common ports
- **DirFinder**: The server may return 429 (Too Many Requests) if it has rate limiting enabled
- **TinyScanner**: Adjust the timeout in `tinyscanner.py` if scanning over high-latency networks
- **HeaderGrabber**: For HTTPS targets with self-signed certificates, it will accept all certificates by default

## Important

Always ensure you have permission to scan the targets you're testing. Use these tools responsibly and ethically.
