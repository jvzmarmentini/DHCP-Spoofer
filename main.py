#!/usr/bin/python3
import argparse
import json
from socket import socket, AF_PACKET, SOCK_RAW, ntohs

from protocols import Protocols


def dumpclean(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                print(f"    [+]{k}")
                dumpclean(v)
            else:
                print(f"\t{k}: {v}")
    else:
        print(obj)


def main():
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
        # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096.
        packet, _ = soc.recvfrom(4096)
        eth_header = Protocols.decode_eth(packet, display)

        if eth_header:
            print(f"[>] Frame #{i}")
            dumpclean({"ETH": eth_header})
            print()

        i += 1


if __name__ == "__main__":
    main()
