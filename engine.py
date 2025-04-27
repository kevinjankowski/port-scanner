import socket
from scapy.layers.inet import IP, TCP, sr1, UDP, ICMP
import time
import ColoredPortStatus

def resolve_hostname(hostname):
    """
    Translate a host name to IPv4 address format if necessary

    Args:
        hostname (str): address of target host

    Returns:
        str: Resolved hostname in numeric format (fe. localhost -> 127.0.0.1)
    """

    try:
        ip = socket.gethostbyname(hostname)
        print(f"Start scanning host: {hostname} ({ip})")
        return ip
    except socket.gaierror:
        print(f"Can't resolve hostname: {hostname}")
        return None


def tcp_scan(target_host, ports):
    """
    Scan ports of target host with full handshake method. Print results of scan in CLI.

    Args:
        target_host (list): address of target host
        ports (list): list of ports for scan
    """

    for host in target_host:

        # Translate a host name to IPv4 address format if necessary
        ip = resolve_hostname(host)

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
                    print(f"- {host}:{port} = {ColoredPortStatus.opened()} (response time: {response_time} ms)")

                else:
                    print(f"- {host}:{port} = {ColoredPortStatus.closed_or_filtered()}")

                # Close socket
                s.close()

            except socket.timeout:
                print(f"- {host}:{port} = filtered (timeout)")

            except socket.error as e:
                print(f"- {host}:{port} = error - {e}")


def syn_scan(target_host, ports):
    """
    Scan ports of target host with not full handshake method (SYN). Print results of scan in CLI.

    Args:
        target_host (list): address of target host
        ports (list): list of ports for scan
    """
    for host in target_host:

        # Translate a host name to IPv4 address format if necessary
        ip = resolve_hostname(host)

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
                    print(f"- {host}:{port} = {ColoredPortStatus.filtered()}")
                elif response.haslayer(TCP): # If response contains TCP layer

                    # Check if response flag is SYN-ACK. If it is - opened
                    if response[TCP].flags == 0x12:
                        # Sending RST flag
                        rst_packet = ip_layer/TCP(dport=port, flags="R")
                        sr1(rst_packet, timeout=1, verbose=False)

                        print(f"- {host}:{port} = {ColoredPortStatus.opened()} (response time: {response_time} ms)")

                    # Check if response flag is RST-ACK. If it is - closed
                    elif response[TCP].flags == 0x14:
                        print(f"- {host}:{port} = {ColoredPortStatus.closed()}")

                    # If none of above was executed, it means that is probably filtered
                    else:
                        print(f"- {host}:{port} = {ColoredPortStatus.filtered()}")

            except Exception as e:
                print(f"Error has occurred - {e}")


def udp_scan(target_host, ports):
    """
    Scan ports of target host with UDP method. Print results of scan in CLI.

    Args:
        target_host (list): address of target host
        ports (list): list of ports for scan
    """

    for host in target_host:

        # Translate a host name to IPv4 address format if necessary
        ip = resolve_hostname(host)

        for port in ports:

            try:
                # Build UDP packet
                ip_layer = IP(dst=ip)
                udp_layer = UDP(dport=port)
                packet = ip_layer / udp_layer

                # Send packet and return for response
                start_time = time.time()
                response = sr1(packet, timeout=1, verbose=False)
                end_time = time.time()

                # Calculate response time in ms
                response_time = round((end_time - start_time) * 1000, 2)

                # Result interpretation
                if response is None:
                    print(f"- {host}:{port} = {ColoredPortStatus.opened()}|{ColoredPortStatus.filtered()}")

                elif response.haslayer(UDP):
                    print(f"- {host}:{port} = {ColoredPortStatus.opened()} (response time: {response_time} ms)")

                elif response.haslayer(ICMP):
                    icmp_code = response.getlayer(ICMP).code
                    icmp_type = response.getlayer(ICMP).type


                    # if icmp type=3 and code=3 it means, that we received ICMP Host unreachable = closed
                    if icmp_code == 3 and icmp_type == 3:
                        print(f"- {host}:{port} = {ColoredPortStatus.closed()}")
                    else:
                        print(f"- {host}:{port} = {ColoredPortStatus.filtered()}")

            except PermissionError:
                print("Operation not permitted!")

            except Exception as e:
                print(f"Error has occurred - {e}")


def fin_scan(target_host, ports):
    """
    Scan ports of target host with FIN method. Print results of scan in CLI.

    Args:
        target_host (list): address of target host
        ports (list): list of ports for scan
    """

    for host in target_host:

        # Translate a host name to IPv4 address format if necessary
        ip = resolve_hostname(host)

        for port in ports:

            try:
                # Build TCP packet with SYN flag
                ip_layer = IP(dst=ip)
                tcp_layer = TCP(dport=port, flags="F")
                packet = ip_layer / tcp_layer

                # Send packet and return for response
                start_time = time.time()
                response = sr1(packet, timeout=1, verbose=False)
                end_time = time.time()

                # Calculate response time in ms
                response_time = round((end_time - start_time) * 1000, 2)

                # Results interpretation
                if response is None:
                    print(f"- {host}:{port} = {ColoredPortStatus.opened()} (response time: {response_time} ms)")

                elif response[TCP].flags == 0x14:
                    print(f'- {host}:{port} = {ColoredPortStatus.closed()}')

            except PermissionError:
                print("Operation not permitted!")

            except Exception as e:
                print(f"Error has occurred - {e}")