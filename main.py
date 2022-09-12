#!/usr/bin/python3
import argparse
from socket import socket, AF_PACKET, SOCK_RAW, ntohs

from protocols import Protocols


def dumpclean(obj) -> None:
    '''
    Pretty print the decode result

    Args:
        obj (Dict): decode result
    '''
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, dict):
                print(f"    [+]{key}")
                dumpclean(value)
            else:
                print(f"\t{key}: {value}")
    else:
        print(obj)


def main() -> None:
    '''
    Main
    '''
    soc = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ETH_P_ALL = 0x0003

    parser = argparse.ArgumentParser()
    parser.add_argument('-w',
                        dest='wlist',
                        nargs='+',
                        help="Whitelist protocols for display",
                        choices=['ETH', 'ARP', 'IPv6', 'IPv4', 'ICMP', 'TCP', 'UDP', 'DNS'])
    display = parser.parse_args().wlist[0]
    i = 0
    while True:
        packet, _ = soc.recvfrom(4096)
        eth_header = Protocols.decode_eth(packet, display)

        if eth_header:
            print(f"[>] Frame #{i}")
            dumpclean({"ETH": eth_header})
            print()

        i += 1


if __name__ == "__main__":
    main()
