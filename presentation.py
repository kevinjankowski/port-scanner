import argparse
import engine
import ipaddress


def setup_cli():
    """
    Set flags. Read arguments from CLI and turn them into Python's variable

    Returns:
        namespace: The parser.parse_args() method runs the parser and
                    places the extracted data in an argparse.Namespace object
    """

    parser = argparse.ArgumentParser(
        description='This is port scanner application. Don\'t use it without target host permission!'
    )
    parser.add_argument('-t', '--target', required=True,
                        help='IP address for scanning target (fe. 10.0.2.15).')
    parser.add_argument('-p', '--ports', type=str, default='1-1024',
                        help='Port range for scan (fe. 80,443 or 1-65535).')
    parser.add_argument('-m', '--method', choices=['tcp', 'syn', 'udp', 'fin'],
                        default='tcp', help='Scanning method. Default is "tcp".')

    return parser.parse_args()


def get_ports(s_ports):
    """
    Turn string that represents ports into list of integers

    Args:
        s_ports (str): port, ports or port range for scan (fe. "80" or "80,443" or "1-65535")

    Returns:
        list: List of integers that represents ports for scan (fe. [80] or [80,443] or [1,2,3, ..., 65535]

    """

    # if string contains "-" sign, that means, that it is a range of port numbers (fe. "11-222")
    if "-" in s_ports:
        # separate string to array of two strings.
        s_ports = s_ports.split('-')

        # first and last number of range
        first_num = int(s_ports[0])
        last_num = int(s_ports[1])

        # return an array of numbers (port numbers)
        return list(range(first_num, last_num + 1))

    elif "," in s_ports:
        return list(map(int, s_ports.split(',')))

    else:
        return [int(s_ports)]


def get_targets(s_targets):
    """
    Turn string that represents hosts into list of strings

    Args:
        s_targets (str): host, hosts or host range for scan (fe. "10.0.2.15" or "10.0.2.15,10.0.2.16" or "10.0.2.15-10.0.2.20")

    Returns:
        list: List of strings that represents hosts for scan (fe. [10.0.2.15] or [10.0.2.15,10.0.2.16] or [10.0.2.15-10.0.2.20]

    """

    targets = []

    if "-" in s_targets:
        # separate string to array of two strings.
        start_ip, end_ip = s_targets.split("-")

        # first and last number of range
        start_ip = ipaddress.IPv4Address(start_ip.strip())
        end_ip = ipaddress.IPv4Address(end_ip.strip())

        # appends host to a targets list
        for ip_int in range(int(start_ip), int(end_ip) + 1):
            targets.append(str(ipaddress.IPv4Address(ip_int)))

    elif "," in s_targets:
        parts = s_targets.split(",")
        for part in parts:
            targets.append(part.strip())

    else:
        targets.append(s_targets.strip())

    return targets


def run_application():
    """
    Runs chosen scan method with user's parameters.
    """

    # save parameters from namespace to single variable
    args = setup_cli()

    # extract basic parameters of scan into separate variables
    target = get_targets(args.target)
    ports = get_ports(args.ports)
    method = args.method

    # run chosen method
    match method:
        case 'tcp':
            engine.tcp_scan(target, ports)
        case 'syn':
            engine.syn_scan(target, ports)
        case 'udp':
            engine.udp_scan(target, ports)
        case 'fin':
            engine.fin_scan(target, ports)
