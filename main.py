#!/usr/bin/python3

from socket import *
from struct import *

def format_mac(mac_addr):
    return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))


s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))  # ETH_P_ALL = 0x0003

while True:
    # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096.
    packet = s.recvfrom(4096)
#    print(packet, end="\n\n")

    eth_header = packet[0][0:14]
    eth = unpack('!6s6sH', eth_header)
    network_proto = eth[2]
#    print('Destination MAC: ' + format_mac(eth[0]) + ' Source MAC: ' + format_mac(eth[1]) + ' Protocol: ' + str(network_proto))

    if network_proto == 2048:
        ipv4_header = packet[0][14:34]
        ipv4 = unpack("!BBHHHBBH4s4s", ipv4_header)

        version_ihl = ipv4[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        header_full_lenght = ihl * 4

        ToS = ipv4[1]
        total_lenght = ipv4[2]
        identifier = ipv4[3]

        flags_offset = ipv4[4]
        flags = flags_offset >> 13
        offset = flags_offset & 0x7FF

        ttl = ipv4[5]
        protocol = ipv4[6]
        checksum = ipv4[7]
        source_addr = inet_ntoa(ipv4[8])
        dest_addr = inet_ntoa(ipv4[9])

#        print(f'Version: {version} IP Header Length: {ihl} ToS: {ToS} Total Lenght: {total_lenght} Identifier: {identifier} Flags: {bin(flags)} Offset: {bin(offset)} TTL: {ttl} Protocol: {protocol} Checksum: {checksum} Source Address: {source_addr} Destination Address: {dest_addr}')

        if protocol == 1:
            icmp_header = packet[0][34:42]
            icmp = unpack("!BBH4s", icmp_header)

            type = icmp[0]
            code = icmp[1]
            checksum = icmp[2]

            print(f'Type: {type} Code: {code} Checksum: {checksum}')

        if protocol == 6:
            tcp_header = packet[0][42:62]
            tcp = unpack("!HHIIBBHHH", tcp_header)

            source_port = tcp[0]
            dest_port = tcp[1]
            seq = tcp[2]
            ack = tcp[3]
            header_len = tcp[4] >> 4
            flags = tcp[5]
            window = tcp[6]
            checksum = tcp[7]
            urgent_pointer = tcp[8]

            print(f'sPort: {source_port} dPort: {dest_port} SEQ: {seq} ACK: {ack} Header Len: {header_len} Flags: {flags} Window: {window} Checksum: {checksum} Urgent Pointer: {urgent_pointer}')
