import socket
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
                print(f"- {port}: {ColoredPortStatus.closed()}")
                open_ports[port] = "closed or filtered"

            # Close socket
            s.close()

        except socket.timeout:
            print(f"- {port}: Filtered (timeout)")
            open_ports[port] = "Filtered (timeout)"
        except socket.error as e:
            print(f"- {port}: Error - {e}")
            open_ports[port] = f"Error - {e}"

    return open_ports

