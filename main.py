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
                        choices=['ETH', 'ARP', 'IPv6', 'IPv4', 'ICMP', 'TCP', 'UDP', 'DNS', 'DHCP'])
    display = parser.parse_args().wlist[0]
    i = 0

    try:
        while True:
            packet, _ = soc.recvfrom(4096)
            eth_header = Protocols.decode_eth(packet, display)

            if eth_header:
                print(f"[>] Frame #{i}")
                dumpclean({"ETH": eth_header})
                print()

            i += 1
    except KeyboardInterrupt:
        total = Protocols.network_access_layer
        print(f"\nTotal captured packets: {total}")

        print("Internet layer:")
        for protocol_name, calls in Protocols.perf_internet_layer.items():
            print(f"    {protocol_name} represents {calls/total * 100:.2f}%")

        print("Transport layer:")
        for protocol_name, calls in Protocols.perf_transport_layer.items():
            print(f"    {protocol_name} represents {calls/total * 100:.2f}%")

        print("Application layer:")
        for protocol_name, calls in Protocols.perf_application_layer.items():
            if calls != 0:
                print(
                    f"    {protocol_name} represents {calls/total * 100:.2f}%")


if __name__ == "__main__":
    main()
