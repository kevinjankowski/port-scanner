import argparse
import engine


def setup_cli():
    parser = argparse.ArgumentParser(
        description='Skaner portów z wsparciem dla metod TCP/UDP'
    )
    parser.add_argument('-t', '--target', required=True,
                        help='Cel skanowania (IP lub zakres CIDR)')
    parser.add_argument('-p', '--ports', type=str, default='1-1024',
                        help='Zakres portów (np. 80,443 lub 1-65535)')
    parser.add_argument('-m', '--method', choices=['tcp', 'syn', 'udp', 'fin'],
                        default='tcp', help='Metoda skanowania')
    return parser.parse_args()


def get_ports(s_ports):
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


def run_application():
    # save parameters from cli to single variable
    args = setup_cli()

    # basic parameters of scan
    target = args.target
    ports = get_ports(args.ports)  # get_ports(s_ports) method returns array of port numbers
    method = args.method

    # run chosen method
    match method:
        case 'tcp':
            engine.tcp_full_handshake_scan(target, ports)
        case 'syn':
            print("syn method")
        case 'udp':
            print("udp method")
        case 'fin':
            print("fin method")
