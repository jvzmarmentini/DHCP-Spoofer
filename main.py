#!/usr/bin/python3
import argparse
import json
from socket import socket, AF_PACKET, SOCK_RAW, ntohs

from protocols import Protocols


def main():
    soc = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ETH_P_ALL = 0x0003

    parser = argparse.ArgumentParser()
    parser.add_argument('-d',
                        '--display',
                        dest='display',
                        nargs='+',
                        help='Whitelist protocols for display')
    display = parser.parse_args().display[0]

    while True:
        # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096.
        packet = soc.recvfrom(4096)[0]
        eth_header = Protocols.decode_eth(packet, display)
        if eth_header:
            print("ETH", json.dumps(eth_header, indent=4))


if __name__ == "__main__":
    main()
