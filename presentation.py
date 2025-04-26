import argparse
import engine


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


def run_application():
    """
    Runs chosen scan method with user's parameters.
    """

    # save parameters from namespace to single variable
    args = setup_cli()

    # extract basic parameters of scan into separate variables
    target = args.target
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
