# Python Port Scanner
A custom network utility designed to scan hosts for open ports using multiple scanning techniques. This project was developed to understand the fundamental mechanisms of the TCP/IP protocol and network security testing techniques.

## Features
- **Multiple Scanning Methods**: Supports four distinct scanning techniques:
  - TCP: Full three-way handshake.
  - SYN: Stealth scanning (half-open handshake)
  - UDP: Scanning for connectionless services.
  - FIN: Sending FIN packets to bypass certain firewall rules.
- **Flexible Target Specification**: Supports scanning single IPs, comma-separated lists, or IP ranges
- **Flexible Port Specification**: Allows scanning specific ports, lists of ports, or port ranges.
- **Colored Output**: Features intuitive, color-coded results for better readability (Green for "open", Red for "closed" or "filtered").
- **Hostname Resolution**: Automatically resolves domain names to IP addresses before scanning.

## Technical Stack
- Language: Python 3.10<br>
- Core Libraries:
  - *socket*: Used for implementing the full TCP handshake
  - *scapy*: Used for advanced packet manipulation in SYN, UDP, and FIN scans

## Project Structure
The application is modularized into four main components:
- ***scanner.py***: The entry point of the application.
- ***presentation.py***: Handles CLI arguments, user input configuration, and manages the application flow.
- ***engine.py***: Contains the core logic and functions for each scanning method.
- ***ColoredPortStatus.py***: A utility script for color-formatting the terminal output.

## Installation & Usage
### Prerequisites
- Python 3.10 or higher.
- Scapy library installed (`pip install scapy`).
- **Note**: Root/Administrator privileges are required for SYN, UDP, and FIN scans due to raw packet manipulation.

### Running the Scanner
To run the application, navigate to the source directory and use the following command structure:<br>
```
python scanner.py -t <TARGET> -p <PORTS> -m <METHOD>
```

**Example:**<br>
```
sudo python scanner.py -t 10.0.2.15 -p 20-80 -m syn
```

**Command Line Arguments:**
- `-t`, `--target`: Target IP address(es) or range.
- `-p`, `--ports`: Port(s) or port range to scan.
- `-m`, `--method`: Scanning method (`tcp`, `syn`, `udp`, `fin`)
- `-h`, `--help`: Display the help message and available flags.
