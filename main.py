import argparse
import os
import sys

from net.utils import get_local_ip, parse_ports
from scanners.tcp import tcp_connect_scan
from scanners.syn import syn_scan
from scanners.udp import udp_scan
from report import print_banner, print_results, print_json


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pymap",
        description="Let's Hack The Planet",
    )
    parser.add_argument("target", help="your target's ip")
    parser.add_argument("-p", "--ports", type=str, default="80,443,22,23,21,3305",
                        help="ports to scan: 80,443 or 1-1024 or - for all")
    parser.add_argument("-sS", action="store_true", help="SYN scan (needs root)")
    parser.add_argument("-sT", action="store_true", help="TCP connect scan")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (args.sS or args.sT or args.sU):
        parser.print_help()
        return 1

    if args.sS and os.geteuid() != 0:
        print("[!] -sS needs root: raw sockets are not for everyone")
        return 1

    if not args.json:
        print_banner()

    ports = parse_ports(args.ports)

    if args.sT:
        results = tcp_connect_scan(args.target, ports)
    elif args.sU:
        results = udp_scan(args.target, ports)
    else:
        results = syn_scan(args.target, ports, get_local_ip())

    if args.json:
        print_json(results)
    else:
        print_results(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
