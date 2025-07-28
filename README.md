# Advanced Port Scanner

Professional network reconnaissance tool demonstrating cybersecurity fundamentals and Python development skills. Built as part of ethical hacking toolkit development.

## Features
- **Multi-threaded scanning** - Concurrent TCP/UDP port scanning for performance
- **Service detection** - Banner grabbing and service fingerprinting
- **Vulnerability identification** - Basic security flaw detection
- **Professional output** - Colored terminal interface with structured results
- **JSON export** - Machine-readable results for further analysis
- **Configurable parameters** - Flexible scanning options

## Technical Skills Demonstrated
- Network programming with Python sockets
- Multi-threading and concurrent programming
- Regular expressions for pattern matching
- Command-line interface development
- JSON data handling and file I/O
- Error handling and exception management

## Usage
```bash
# Basic scan
python port_scanner.py 192.168.1.1

# Custom port range
python port_scanner.py target.com -p 1-1000 -t 200

# Top common ports
python port_scanner.py 10.0.0.1 --top-ports 20
