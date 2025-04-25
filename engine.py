import socket
from asyncio import timeout
from sys import flags

from scapy.layers.inet import IP, TCP, sr1
import time
import ColoredPortStatus


def tcp_full_handshake_scan(target_host, ports):
    """
    Scan ports of target host with full handshake method. Print results of scan in CLI.

    Args:
        target_host (str): IP address of target host
        ports (list): list of ports for scan

    Returns:
        dict: Dictionary with results of scanning in format {port: status}
    """

    open_ports = {}

    # Translate a host name to IPv4 address format if necessary
    try:
        ip = socket.gethostbyname(target_host)
        print(f"Start scanning host: {target_host} ({ip})")
    except socket.gaierror:
        print(f"Can't resolve hostname: {target_host}")
        return open_ports

    # Scan every port
    for port in ports:
        try:
            # Create TCP socket (AF_INTER - address family IPv4, SOCK_STREAM - connection type TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Timeout set for 1 second

            # Attempt to establish a connection (full TCP handshake)
            start_time = time.time()
            result = s.connect_ex((ip, port))
            end_time = time.time()

            # Calculate response time in ms
            response_time = round((end_time - start_time) * 1000, 2)

            # Result interpretation
            if result == 0:
                print(f"- {port}: {ColoredPortStatus.opened()} (response time: {response_time} ms)")
                open_ports[port] = "open"
            else:
                print(f"- {port}: {ColoredPortStatus.closed_or_filtered()}")
                open_ports[port] = "closed or filtered"

            # Close socket
            s.close()

        except socket.timeout:
            print(f"- {port}: filtered (timeout)")
            open_ports[port] = "filtered (timeout)"
        except socket.error as e:
            print(f"- {port}: error - {e}")
            open_ports[port] = f"error - {e}"

    return open_ports


def syn_scan(target_host, ports):
    """
    Scan ports of target host with not full handshake method (SYN). Print results of scan in CLI.

    Args:
        target_host (str): IP address of target host
        ports (list): list of ports for scan

    Returns:
        dict: Dictionary with results of scanning in format {port: status}

    """

    open_ports = {}

    # Translate a host name to IPv4 address format if necessary
    try:
        ip = socket.gethostbyname(target_host)
        print(f"Start scanning host: {target_host} ({ip})")
    except socket.gaierror:
        print(f"Can't resolve hostname: {target_host}")
        return open_ports

    # Scan every port
    for port in ports:
        # Build TCP packet with SYN flag
        ip_layer = IP(dst=ip)
        tcp_layer = TCP(dport=port, flags="S")
        packet = ip_layer/tcp_layer

        try:

            # Send packet and return for response
            start_time = time.time()
            response = sr1(packet, timeout=1, verbose=False)
            end_time = time.time()

            # Calculate response time in ms
            response_time = round((end_time - start_time) * 1000, 2)

            # Result interpretation
            if response is None:
                open_ports[port] = "filtered"
            elif response.haslayer(TCP): # If response contains TCP layer

                # Check if response flag is SYN-ACK
                if response[TCP].flags == 0x12:
                    # Sending RST flag
                    rst_packet = ip_layer/TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=1, verbose=False)

                    print(f"- {port}: {ColoredPortStatus.opened()} (response time: {response_time} ms)")
                    open_ports[port] = "open"

                # Check if response flag is RST-ACK
                elif response[TCP].flags == 0x14:
                    print(f"- {port}: {ColoredPortStatus.closed()} (response time: {response_time} ms)")
                    open_ports[port] = "closed"

                # If none of above was executed, it means that is probably filtered
                else:
                    print(f"- {port}: {ColoredPortStatus.filtered()} (response time: {response_time} ms)")
                    open_ports[port] = "filtered"

            # Another TCP flags
            else:
                print(f"- {port}: {ColoredPortStatus.filtered()} (response time: {response_time} ms)")
                open_ports[port] = "filtered"

        except Exception as e:
            open_ports[port] = f"error - {e}"