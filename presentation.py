import argparse


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


def run_application():
    args = setup_cli()
    # to get some specific argument you can type: args.<name_of_arg>, fe.: args.target.


