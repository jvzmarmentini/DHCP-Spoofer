#!/usr/bin/python3

import json
from socket import *
from struct import *

from protocols import Protocols


def format_mac(mac_addr):
    return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))


s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ETH_P_ALL = 0x0003
eth_len = 14
ipv4_len = 20
ipv6_len = 40
icmp_len = 8
tcp_len = 20
udp_len = 8
dns_len = 12

while True:
    base_len = 0
    # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096.
    recv = s.recvfrom(4096)
    packet = recv[0]

    # print(packet, end="\n\n")
    eth = packet[base_len:eth_len]
    base_len += eth_len

    eth_header = unpack('!6s6sH', eth)
    network_proto = eth_header[2]
#    print('Destination MAC: ' + format_mac(eth[0]) + ' Source MAC: ' + format_mac(eth[1]) + ' Protocol: network_proto))

    if network_proto == 2048:
        ipv4 = packet[base_len:base_len+ipv4_len]
        base_len += ipv4_len

        ipv4_header = unpack("!2B3H2BH4s4s", ipv4)

        version_ihl = ipv4_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        header_full_lenght = ihl * 4

        ToS = ipv4_header[1]
        total_lenght = ipv4_header[2]
        identifier = ipv4_header[3]

        flags_offset = ipv4_header[4]
        flags = flags_offset >> 13
        offset = flags_offset & 0x7FF

        ttl = ipv4_header[5]
        protocol = ipv4_header[6]
        checksum = ipv4_header[7]
        source_addr = inet_ntoa(ipv4_header[8])
        dest_addr = inet_ntoa(ipv4_header[9])

#        print(f'Version: {version} IP Header Length: {ihl} ToS: {ToS} Total Lenght: {total_lenght} Identifier: {identifier} Flags: {bin(flags)} Offset: {bin(offset)} TTL: {ttl} Protocol: {protocol} Checksum: {checksum} Source Address: {source_addr} Destination Address: {dest_addr}')

        if protocol == 1:
            icmp = packet[base_len:base_len+icmp_len]
            base_len += icmp_len
            icmp_header = unpack("!BBH4s", icmp)

            type = icmp_header[0]
            code = icmp_header[1]
            checksum = icmp_header[2]

            #print(f'Type: {type} Code: {code} Checksum: {checksum}')

        elif protocol == 6:
            tcp = packet[base_len:base_len+tcp_len]
            base_len += tcp_len
            tcp_header = unpack("!HHIIBBHHH", tcp)

            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            seq = tcp_header[2]
            ack = tcp_header[3]
            header_len = tcp_header[4] >> 4
            flags = tcp_header[5]
            window = tcp_header[6]
            checksum = tcp_header[7]
            urgent_pointer = tcp_header[8]

#            print(f'sPort: {source_port} dPort: {dest_port} SEQ: {seq} ACK: {ack} Header Len: {header_len} Flags: {flags} Window: {window} Checksum: {checksum} Urgent Pointer: {urgent_pointer}')

        elif protocol == 17:
            udp = packet[base_len:]
            udp_header = Protocols.decode_udp(udp)
            print("UDP", json.dumps(udp_header, indent=4))

    elif network_proto == 34525:
        ipv6_header = packet[base_len:base_len+ipv6_len]
        base_len += ipv6_len

        ipv6 = unpack("!4sHBB16s16s", ipv6_header)
        version = ipv6[0] >> 28
        traffic_class = (ipv6[0] >> 21) & 0x7F
        flow_label = ipv6[0] & 0x1FFFFF
        payload_len = ipv6[1]
        next_header = ipv6[2]
        hop_limit = ipv6[3]
        source_address = ipv6[4]
        destination_address = ipv6[5]

        print(f'Version: {version} Traffic class: {traffic_class} Flow label: {flow_label} Payload length: {payload_len} Next header: {next_header} Hop limit: {hop_limit} Source address: {source_address} Destination address: {destination_address}')
